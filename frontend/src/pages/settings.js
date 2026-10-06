import { renderLayout } from "../components/layout.js";
import { escapeHtml } from "../utils/format.js";

export function settingsPage(user) {
  renderLayout(`
    <section class="page-head">
      <div>
        <div class="eyebrow">SETTINGS</div>
        <h1>Account settings</h1>
        <p>Review your Veyra account information.</p>
      </div>
    </section>

    <div class="detail-grid">
      <section class="panel">
        <h2>Profile</h2>
        <dl>
          <dt>Name</dt>
          <dd>${escapeHtml(user.display_name)}</dd>
          <dt>Email</dt>
          <dd>${escapeHtml(user.email)}</dd>
          <dt>Account role</dt>
          <dd>${escapeHtml(user.role)}</dd>
        </dl>
      </section>

      <section class="panel">
        <h2>Security</h2>
        <p class="muted">
          Veyra uses secure sessions and password hashing. Sensitive cryptographic
          material is never placed in browser storage.
        </p>
        <div class="security-note">Session cookies are protected with HttpOnly and SameSite controls.</div>
      </section>
    </div>
  `, { user, title: "Settings" });
}
