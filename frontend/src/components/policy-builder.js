export function createPolicyBuilder(initial = []) {
  const root = document.createElement("div");
  root.className = "policy-builder";

  const requirements = Array.isArray(initial) && initial.length
    ? initial
    : ["clearance>=1"];

  function parse(value) {
    const clearance = value.match(/^clearance\s*>=\s*(\d+)$/i);
    if (clearance) return { type: "clearance", value: clearance[1] };

    const equality = value.match(/^(department|role|project|organization)\s*=\s*(.+)$/i);
    if (equality) return { type: equality[1].toLowerCase(), value: equality[2] };

    return { type: "custom", value };
  }

  function render() {
    root.innerHTML = `
      <div class="policy-header">
        <div>
          <strong>Access requirements</strong>
          <small>Veyra will enforce these requirements during download.</small>
        </div>
        <button type="button" class="button button-small" id="addRequirement">Add requirement</button>
      </div>
      <div class="policy-rows"></div>
    `;

    const rows = root.querySelector(".policy-rows");

    requirements.forEach((raw, index) => {
      const parsed = parse(raw);
      const row = document.createElement("div");
      row.className = "policy-row";

      row.innerHTML = `
        <select aria-label="Requirement type">
          <option value="department" ${parsed.type === "department" ? "selected" : ""}>Department</option>
          <option value="role" ${parsed.type === "role" ? "selected" : ""}>Role</option>
          <option value="clearance" ${parsed.type === "clearance" ? "selected" : ""}>Minimum clearance</option>
          <option value="project" ${parsed.type === "project" ? "selected" : ""}>Project</option>
          <option value="organization" ${parsed.type === "organization" ? "selected" : ""}>Organization</option>
        </select>
        <input value="${String(parsed.value).replace(/"/g, "&quot;")}" aria-label="Requirement value" />
        <button type="button" class="icon-button remove" aria-label="Remove requirement">×</button>
      `;

      const select = row.querySelector("select");
      const input = row.querySelector("input");

      const sync = () => {
        const type = select.value;
        requirements[index] = type === "clearance"
          ? `clearance>=${Math.max(0, Number.parseInt(input.value, 10) || 0)}`
          : `${type}=${input.value.trim() || "any"}`;
      };

      select.addEventListener("change", sync);
      input.addEventListener("input", sync);

      row.querySelector(".remove").addEventListener("click", () => {
        requirements.splice(index, 1);
        if (!requirements.length) requirements.push("clearance>=1");
        render();
      });

      rows.appendChild(row);
    });

    root.querySelector("#addRequirement").addEventListener("click", () => {
      requirements.push("department=engineering");
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
      return requirements.length ? requirements.join(" AND ") : "true";
    },
  };
}
