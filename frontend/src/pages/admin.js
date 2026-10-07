import { api } from "../services/api.js";
import { renderLayout } from "../components/layout.js";
import { buttonSpinner, toast } from "../components/ui.js";
import { escapeHtml } from "../utils/format.js";

export async function adminPage(user) {
  let users;
  try {
    users = await api.get("/admin/users");
  } catch (err) {
    renderLayout(`
      <section class="center-card">
        <h1>Couldn't load users.</h1>
        <p>${escapeHtml(err.message)}</p>
      </section>
    `, { user, title: "Admin" });
    return;
  }

  const rows = users.map((u) => `
    <form class="admin-row" data-user="${escapeHtml(u.id)}">
      <div class="admin-user">
        <strong>${escapeHtml(u.display_name)}</strong>
        <small>${escapeHtml(u.email)} · ${escapeHtml(u.role)}</small>
      </div>
      <textarea name="attributes" rows="3" aria-label="Attributes for ${escapeHtml(u.email)}" spellcheck="false">${escapeHtml((Array.isArray(u.attributes) ? u.attributes : []).join("\n"))}</textarea>
      <button class="button button-small" type="submit">Save</button>
    </form>
  `).join("");

  renderLayout(`
    <section class="page-head">
      <div>
        <div class="eyebrow">ADMIN</div>
        <h1>User attributes</h1>
        <p>Attributes decide who can open restricted transfers. One per line.</p>
      </div>
    </section>

    <section class="panel">
      <p class="muted">
        Allowed forms: <code>clearance&gt;=N</code> (1-10, implies all lower levels),
        <code>department=x</code>, <code>role=x</code>, <code>project=x</code>, <code>organization=x</code>.
        Values use lowercase letters, digits, dots, dashes and underscores.
      </p>
      <div class="admin-list">${rows}</div>
    </section>
  `, { user, title: "Admin" });

  document.querySelectorAll(".admin-row").forEach((form) => {
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      const button = form.querySelector("button");
      const attributes = form
        .querySelector("textarea")
        .value.split("\n")
        .map((line) => line.trim())
        .filter(Boolean);
      buttonSpinner(button, true, "Saving…");
      try {
        const updated = await api.post(`/admin/users/${encodeURIComponent(form.dataset.user)}/attributes`, { attributes });
        form.querySelector("textarea").value = (updated.attributes || []).join("\n");
        toast("Attributes saved.", "success");
      } catch (err) {
        toast(err.message, "error");
      } finally {
        buttonSpinner(button, false);
      }
    });
  });
}
