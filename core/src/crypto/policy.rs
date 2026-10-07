//! Policy language and access-tree representation for CP-ABE.
//!
//! Supported syntax (case-insensitive keywords):
//!   clearance>=N            N in 1..=10
//!   department=<value>      also: role, project, organization
//!   AND / OR
//!   parentheses
//!
//! Values are limited to `[a-z0-9._-]` (1..=64 chars). Mixing AND and OR at the
//! same nesting level requires parentheses. Every attribute may appear at most
//! once in a policy (the underlying scheme assigns one ciphertext component per
//! attribute).
//!
//! Examples:
//!   clearance>=4 AND department=intelligence
//!   (clearance>=3 OR role=admin) AND department=ops
//!
//! The parser enforces hard limits on input length, nesting depth and leaf
//! count so that untrusted policy strings cannot exhaust the stack or CPU.

use crate::error::{Result, VeyraError};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashSet};
use std::fmt;

pub const MAX_POLICY_CHARS: usize = 1024;
pub const MAX_POLICY_DEPTH: usize = 8;
pub const MAX_POLICY_LEAVES: usize = 32;
pub const MAX_VALUE_LEN: usize = 64;
pub const MAX_CLEARANCE: u32 = 10;

const ALLOWED_NAMES: [&str; 4] = ["department", "role", "project", "organization"];

/// Leaf attribute in the access tree.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Attribute {
    pub name: String,
    pub value: Option<String>, // None for pure presence attributes
}

impl Attribute {
    pub fn new(name: impl Into<String>, value: Option<String>) -> Self {
        Self {
            name: name.into().to_lowercase(),
            value: value.map(|v| v.to_lowercase()),
        }
    }

    pub fn clearance_ge(n: u32) -> Self {
        Self::new(format!("clearance>={}", n), None)
    }

    pub fn department(dept: &str) -> Self {
        Self::new("department", Some(dept.to_string()))
    }

    pub fn role(role: &str) -> Self {
        Self::new("role", Some(role.to_string()))
    }

    /// Canonical string form used as attribute identifier in the scheme.
    pub fn id(&self) -> String {
        match &self.value {
            Some(v) => format!("{}={}", self.name, v),
            None => self.name.clone(),
        }
    }
}

impl fmt::Display for Attribute {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.id())
    }
}

/// Access structure node (threshold tree).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum AccessNode {
    /// Leaf: single attribute
    Leaf(Attribute),
    /// Internal: threshold-k of children (k == children.len() -> AND, k == 1 -> OR)
    Threshold {
        threshold: usize,
        children: Vec<AccessNode>,
    },
}

impl AccessNode {
    pub fn and(children: Vec<AccessNode>) -> Self {
        let k = children.len();
        AccessNode::Threshold { threshold: k, children }
    }

    pub fn or(children: Vec<AccessNode>) -> Self {
        AccessNode::Threshold { threshold: 1, children }
    }

    pub fn leaf(attr: Attribute) -> Self {
        AccessNode::Leaf(attr)
    }

    /// Number of leaves in the tree (duplicates counted separately).
    pub fn leaf_count(&self) -> usize {
        match self {
            AccessNode::Leaf(_) => 1,
            AccessNode::Threshold { children, .. } => {
                children.iter().map(|c| c.leaf_count()).sum()
            }
        }
    }

    /// Collect all distinct leaf attributes that appear in the tree.
    pub fn collect_attributes(&self) -> HashSet<Attribute> {
        let mut set = HashSet::new();
        self.collect_into(&mut set);
        set
    }

    fn collect_into(&self, set: &mut HashSet<Attribute>) {
        match self {
            AccessNode::Leaf(a) => {
                set.insert(a.clone());
            }
            AccessNode::Threshold { children, .. } => {
                for c in children {
                    c.collect_into(set);
                }
            }
        }
    }

    /// Evaluate whether a set of attribute IDs satisfies the tree.
    pub fn satisfied_by(&self, attrs: &HashSet<String>) -> bool {
        match self {
            AccessNode::Leaf(a) => attrs.contains(&a.id()),
            AccessNode::Threshold { threshold, children } => {
                let satisfied = children.iter().filter(|c| c.satisfied_by(attrs)).count();
                satisfied >= *threshold
            }
        }
    }
}

impl fmt::Display for AccessNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AccessNode::Leaf(a) => write!(f, "{}", a),
            AccessNode::Threshold { threshold, children } => {
                let joiner = if *threshold == children.len() {
                    " AND "
                } else if *threshold == 1 {
                    " OR "
                } else {
                    // General k-of-n nodes cannot be produced by the parser.
                    return write!(f, "(threshold {} of {} children)", threshold, children.len());
                };
                write!(f, "(")?;
                for (i, c) in children.iter().enumerate() {
                    if i > 0 {
                        write!(f, "{}", joiner)?;
                    }
                    write!(f, "{}", c)?;
                }
                write!(f, ")")
            }
        }
    }
}

/// Parse a human-readable policy string into an AccessNode.
pub fn parse_policy(input: &str) -> Result<AccessNode> {
    if input.len() > MAX_POLICY_CHARS {
        return Err(VeyraError::InvalidPolicy("policy is too long".into()));
    }
    let tokens = tokenize(input);
    if tokens.is_empty() {
        return Err(VeyraError::InvalidPolicy("empty policy".into()));
    }
    let (node, rest) = parse_expr(&tokens, 0)?;
    if !rest.is_empty() {
        return Err(VeyraError::InvalidPolicy("unexpected trailing tokens".into()));
    }
    let leaves = node.leaf_count();
    if leaves > MAX_POLICY_LEAVES {
        return Err(VeyraError::InvalidPolicy(format!(
            "policy has more than {} attributes",
            MAX_POLICY_LEAVES
        )));
    }
    if node.collect_attributes().len() != leaves {
        return Err(VeyraError::InvalidPolicy(
            "each attribute may appear only once in a policy".into(),
        ));
    }
    Ok(node)
}

/// Validate a single attribute string and return its canonical identifier.
pub fn normalize_attribute(raw: &str) -> Result<String> {
    Ok(parse_attribute(raw)?.id())
}

/// Expand a numeric clearance into the set of attributes it implies.
/// clearance 4 -> clearance>=1, clearance>=2, clearance>=3, clearance>=4
pub fn expand_clearance(level: u32) -> Vec<Attribute> {
    (1..=level.min(MAX_CLEARANCE)).map(Attribute::clearance_ge).collect()
}

/// Normalize a user's stored attributes into the effective attribute set used
/// for key issuance: invalid entries are dropped and `clearance>=N` implies all
/// lower clearance levels.
pub fn effective_attributes(raw: &[String]) -> Vec<String> {
    let mut out: BTreeSet<String> = BTreeSet::new();
    for item in raw {
        if let Ok(id) = normalize_attribute(item) {
            if let Some(level) = id
                .strip_prefix("clearance>=")
                .and_then(|v| v.parse::<u32>().ok())
            {
                for lower in expand_clearance(level) {
                    out.insert(lower.id());
                }
            }
            out.insert(id);
        }
    }
    out.into_iter().collect()
}

#[derive(Debug, Clone, PartialEq)]
enum Token {
    Attr(String),
    And,
    Or,
    LParen,
    RParen,
}

fn tokenize(input: &str) -> Vec<Token> {
    let mut tokens = Vec::new();
    let mut chars = input.chars().peekable();
    while let Some(&c) = chars.peek() {
        if c.is_whitespace() {
            chars.next();
            continue;
        }
        if c == '(' {
            tokens.push(Token::LParen);
            chars.next();
            continue;
        }
        if c == ')' {
            tokens.push(Token::RParen);
            chars.next();
            continue;
        }
        let mut word = String::new();
        while let Some(&ch) = chars.peek() {
            if ch.is_whitespace() || ch == '(' || ch == ')' {
                break;
            }
            word.push(ch);
            chars.next();
        }
        match word.to_lowercase().as_str() {
            "and" => tokens.push(Token::And),
            "or" => tokens.push(Token::Or),
            _ => tokens.push(Token::Attr(word)),
        }
    }
    tokens
}

fn parse_expr(tokens: &[Token], depth: usize) -> Result<(AccessNode, &[Token])> {
    let (left, mut rest) = parse_term(tokens, depth)?;
    let mut nodes = vec![left];
    let mut is_and: Option<bool> = None;

    while let Some(token) = rest.first() {
        let this_is_and = match token {
            Token::And => true,
            Token::Or => false,
            _ => break,
        };
        if is_and == Some(!this_is_and) {
            return Err(VeyraError::InvalidPolicy(
                "mixed AND/OR without parentheses".into(),
            ));
        }
        is_and = Some(this_is_and);
        let (n, r) = parse_term(&rest[1..], depth)?;
        nodes.push(n);
        rest = r;
    }

    let node = if nodes.len() == 1 {
        nodes.remove(0)
    } else if is_and == Some(true) {
        AccessNode::and(nodes)
    } else {
        AccessNode::or(nodes)
    };
    Ok((node, rest))
}

fn parse_term(tokens: &[Token], depth: usize) -> Result<(AccessNode, &[Token])> {
    let first = tokens
        .first()
        .ok_or_else(|| VeyraError::InvalidPolicy("unexpected end of policy".into()))?;
    match first {
        Token::LParen => {
            if depth + 1 > MAX_POLICY_DEPTH {
                return Err(VeyraError::InvalidPolicy(format!(
                    "policy nesting is deeper than {} levels",
                    MAX_POLICY_DEPTH
                )));
            }
            let (node, rest) = parse_expr(&tokens[1..], depth + 1)?;
            match rest.first() {
                Some(Token::RParen) => Ok((node, &rest[1..])),
                _ => Err(VeyraError::InvalidPolicy("missing closing parenthesis".into())),
            }
        }
        Token::Attr(s) => {
            let attr = parse_attribute(s)?;
            Ok((AccessNode::leaf(attr), &tokens[1..]))
        }
        _ => Err(VeyraError::InvalidPolicy("unexpected token".into())),
    }
}

fn validate_value(value: &str) -> Result<()> {
    let ok = !value.is_empty()
        && value.len() <= MAX_VALUE_LEN
        && value
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-'));
    if ok {
        Ok(())
    } else {
        Err(VeyraError::InvalidPolicy(
            "attribute values may only contain a-z, 0-9, '.', '_' and '-' (max 64 chars)".into(),
        ))
    }
}

fn parse_attribute(s: &str) -> Result<Attribute> {
    let lower = s.trim().to_lowercase();
    if lower.is_empty() || lower.len() > 96 {
        return Err(VeyraError::InvalidPolicy("malformed attribute".into()));
    }
    if let Some(rest) = lower.strip_prefix("clearance>=") {
        let n: u32 = rest
            .parse()
            .map_err(|_| VeyraError::InvalidPolicy("invalid clearance value".into()))?;
        if !(1..=MAX_CLEARANCE).contains(&n) {
            return Err(VeyraError::InvalidPolicy(
                "clearance must be between 1 and 10".into(),
            ));
        }
        return Ok(Attribute::clearance_ge(n));
    }
    match lower.split_once('=') {
        Some((name, value)) => {
            let name = name.trim();
            let value = value.trim();
            if !ALLOWED_NAMES.contains(&name) {
                return Err(VeyraError::UnknownAttribute(name.to_string()));
            }
            validate_value(value)?;
            Ok(Attribute::new(name, Some(value.to_string())))
        }
        None => Err(VeyraError::UnknownAttribute(lower)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(items: &[&str]) -> HashSet<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parse_simple_and() {
        let tree = parse_policy("clearance>=4 AND department=intelligence").unwrap();
        assert!(tree.satisfied_by(&set(&["clearance>=4", "department=intelligence"])));
        assert!(!tree.satisfied_by(&set(&["clearance>=3", "department=intelligence"])));
    }

    #[test]
    fn parse_or_with_parens() {
        let tree = parse_policy("(clearance>=3 OR role=admin) AND department=ops").unwrap();
        assert!(tree.satisfied_by(&set(&["clearance>=3", "department=ops"])));
        assert!(tree.satisfied_by(&set(&["role=admin", "department=ops"])));
        assert!(!tree.satisfied_by(&set(&["role=admin"])));
    }

    #[test]
    fn mixed_and_or_requires_parentheses() {
        assert!(parse_policy("role=admin AND role=auditor OR department=hr").is_err());
    }

    #[test]
    fn rejects_unknown_and_bare_attributes() {
        assert!(parse_policy("foo").is_err());
        assert!(parse_policy("color=blue").is_err());
        assert!(parse_policy("department=").is_err());
        assert!(parse_policy("clearance>=0").is_err());
        assert!(parse_policy("clearance>=11").is_err());
    }

    #[test]
    fn rejects_bad_values() {
        assert!(parse_policy("department=a/b").is_err());
        let long = format!("department={}", "a".repeat(MAX_VALUE_LEN + 1));
        assert!(parse_policy(&long).is_err());
    }

    #[test]
    fn rejects_duplicate_attributes() {
        assert!(parse_policy("(role=admin OR role=auditor) AND (role=admin OR department=hr)")
            .is_err());
    }

    #[test]
    fn rejects_deep_nesting_without_overflowing() {
        let deep = format!("{}role=admin{}", "(".repeat(5000), ")".repeat(5000));
        assert!(parse_policy(&deep).is_err());
        let ok = format!("{}role=admin{}", "(".repeat(MAX_POLICY_DEPTH), ")".repeat(MAX_POLICY_DEPTH));
        assert!(parse_policy(&ok).is_ok());
        let too_deep = format!(
            "{}role=admin{}",
            "(".repeat(MAX_POLICY_DEPTH + 1),
            ")".repeat(MAX_POLICY_DEPTH + 1)
        );
        assert!(parse_policy(&too_deep).is_err());
    }

    #[test]
    fn rejects_oversized_policies() {
        let many: Vec<String> = (0..=MAX_POLICY_LEAVES).map(|i| format!("project=p{}", i)).collect();
        assert!(parse_policy(&many.join(" OR ")).is_err());
        assert!(parse_policy(&"a".repeat(MAX_POLICY_CHARS + 1)).is_err());
    }

    #[test]
    fn canonical_form_round_trips() {
        let tree = parse_policy("(CLEARANCE>=3 or Role=Admin) and Department=OPS").unwrap();
        let canonical = tree.to_string();
        let again = parse_policy(&canonical).unwrap();
        assert_eq!(canonical, again.to_string());
        assert!(canonical.contains("role=admin"));
    }

    #[test]
    fn effective_attributes_expand_clearance_and_drop_invalid() {
        let eff = effective_attributes(&[
            "clearance>=3".to_string(),
            "Department=Eng".to_string(),
            "bogus".to_string(),
        ]);
        assert!(eff.contains(&"clearance>=1".to_string()));
        assert!(eff.contains(&"clearance>=2".to_string()));
        assert!(eff.contains(&"clearance>=3".to_string()));
        assert!(!eff.contains(&"clearance>=4".to_string()));
        assert!(eff.contains(&"department=eng".to_string()));
        assert!(!eff.iter().any(|a| a == "bogus"));
    }

    #[test]
    fn normalize_attribute_is_canonical() {
        assert_eq!(normalize_attribute(" Role = Admin ").unwrap(), "role=admin");
        assert_eq!(normalize_attribute("clearance>=04").unwrap(), "clearance>=4");
        assert!(normalize_attribute("nope").is_err());
    }
}
