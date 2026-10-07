const TYPES = [
  { value: "department", label: "Department" },
  { value: "role", label: "Role" },
  { value: "clearance", label: "Minimum clearance (1-10)" },
  { value: "project", label: "Project" },
  { value: "organization", label: "Organization" },
];
const VALUE_PATTERN = /^[a-z0-9._-]{1,64}$/;
const MAX_REQUIREMENTS = 16;

function parse(value) {
  const clearance = value.match(/^clearance>=(\d+)$/);
  if (clearance) return { type: "clearance", value: clearance[1] };
  const equality = value.match(/^(department|role|project|organization)=(.+)$/);
  if (equality) return { type: equality[1], value: equality[2] };
  return { type: "department", value };
}

function build(type, raw) {
  const value = raw.trim().toLowerCase();
  return type === "clearance" ? `clearance>=${value}` : `${type}=${value}`;
}

function problemWith(requirement) {
  const parsed = parse(requirement);
  if (parsed.type === "clearance") {
    const level = Number(parsed.value);
    return Number.isInteger(level) && level >= 1 && level <= 10
      ? null
      : "Clearance must be a whole number between 1 and 10.";
  }
  return VALUE_PATTERN.test(parsed.value)
    ? null
    : "Values may only use lowercase letters, digits, '.', '_' and '-' (max 64 characters).";
}

export function createPolicyBuilder(initial = []) {
  const root = document.createElement("div");
  root.className = "policy-builder";

  const requirements = Array.isArray(initial) && initial.length ? [...initial] : ["department=engineering"];

  function render() {
    root.innerHTML = `
      <div class="policy-header">
        <div>
          <strong>Access requirements</strong>
          <small>The recipient must satisfy all of them (and have a Veyra account).</small>
        </div>
        <button type="button" class="button button-small" id="addRequirement">Add requirement</button>
      </div>
      <div class="policy-rows"></div>
      <div class="form-error" id="policyError" role="alert"></div>
    `;

    const rows = root.querySelector(".policy-rows");

    requirements.forEach((raw, index) => {
      const parsed = parse(raw);
      const row = document.createElement("div");
      row.className = "policy-row";

      const select = document.createElement("select");
      select.setAttribute("aria-label", "Requirement type");
      for (const t of TYPES) {
        const option = document.createElement("option");
        option.value = t.value;
        option.textContent = t.label;
        option.selected = t.value === parsed.type;
        select.appendChild(option);
      }

      const input = document.createElement("input");
      input.value = parsed.value;
      input.setAttribute("aria-label", "Requirement value");
      input.autocomplete = "off";
      input.maxLength = 64;

      const remove = document.createElement("button");
      remove.type = "button";
      remove.className = "icon-button remove";
      remove.setAttribute("aria-label", "Remove requirement");
      remove.textContent = "×";

      const sync = () => {
        requirements[index] = build(select.value, input.value);
        input.setAttribute("aria-invalid", problemWith(requirements[index]) ? "true" : "false");
      };
      select.addEventListener("change", sync);
      input.addEventListener("input", sync);
      remove.addEventListener("click", () => {
        requirements.splice(index, 1);
        if (!requirements.length) requirements.push("department=engineering");
        render();
      });

      row.append(select, input, remove);
      rows.appendChild(row);
    });

    root.querySelector("#addRequirement").addEventListener("click", () => {
      if (requirements.length >= MAX_REQUIREMENTS) return;
      requirements.push("role=member");
      render();
    });
  }

  render();

  return {
    element: root,
    getRequirements() {
      return [...requirements];
    },
    getExpression() {
      return requirements.join(" AND ");
    },
    /** Returns a human readable problem, or null when the requirements are valid. */
    validate() {
      const message = root.querySelector("#policyError");
      let problem = null;
      for (const r of requirements) {
        problem = problemWith(r);
        if (problem) break;
      }
      if (!problem && new Set(requirements).size !== requirements.length) {
        problem = "Each requirement can only be used once.";
      }
      if (message) message.textContent = problem || "";
      return problem;
    },
  };
}
