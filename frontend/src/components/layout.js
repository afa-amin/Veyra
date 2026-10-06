import { escapeHtml } from "../utils/format.js";
import { api } from "../services/api.js";

export function renderLayout(content, { user = null, title = "Veyra" } = {}) {
  document.title = `${title} — Veyra`;
  const app = document.querySelector("#app");

  app.innerHTML = `
    <div class="shell">
      <header class="topbar">
        <a class="brand" href="#/">
          <span class="brand-mark">V</span>
          <span>
            <strong>Veyra</strong>
            <small>Secure File Transfer</small>
          </span>
        </a>

        <nav class="nav">
          ${
            user
              ? `
                <a href="#/dashboard">Dashboard</a>
                <a href="#/send">Send</a>
                <a href="#/settings">Settings</a>
                <button class="link-button" id="logoutButton">Log out</button>
              `
              : `
                <a href="#/login">Log in</a>
                <a class="button button-small primary" href="#/register">Create account</a>
              `
          }
        </nav>
      </header>

      <main class="page-shell">${content}</main>

      <footer class="footer">
        <span>Veyra — Send sensitive files. Stay in control.</span>
        <span>
          <a href="#/security">Security</a>
          <a href="#/privacy">Privacy</a>
          <a href="#/terms">Terms</a>
        </span>
      </footer>
    </div>
  `;

  document.querySelector("#logoutButton")?.addEventListener("click", async () => {
    try {
      await api.post("/auth/logout", {});
    } finally {
      location.hash = "#/";
      window.dispatchEvent(new HashChangeEvent("hashchange"));
    }
  });
}

export function renderLoading() {
  document.querySelector("#app").innerHTML = `
    <div class="loading-screen" role="status" aria-live="polite">
      <div class="spinner"></div>
      <span>Loading Veyra…</span>
    </div>
  `;
}

export function renderErrorPage(message = "Something went wrong.") {
  renderLayout(`
    <section class="center-card">
      <div class="eyebrow">VEYRA</div>
      <h1>We couldn't load this page.</h1>
      <p>${escapeHtml(message)}</p>
      <a class="button primary" href="#/">Back to home</a>
    </section>
  `);
}
