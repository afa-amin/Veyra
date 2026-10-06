import { api } from "../services/api.js";
import { renderLayout } from "../components/layout.js";
import { buttonSpinner, toast } from "../components/ui.js";

export function authPage(mode) {
  const login = mode === "login";

  renderLayout(`
    <section class="center-card auth-card">
      <div class="eyebrow">VEYRA</div>
      <h1>${login ? "Welcome back." : "Create your account."}</h1>
      <p>${login ? "Access your secure transfers." : "Start sending sensitive files securely."}</p>

      <form id="authForm" class="form-stack">
        ${login ? "" : `
          <label>
            Name
            <input name="display_name" autocomplete="name" required />
          </label>
        `}
        <label>
          Email
          <input type="email" name="email" autocomplete="email" required />
        </label>
        <label>
          Password
          <input type="password" name="password" autocomplete="${login ? "current-password" : "new-password"}" minlength="12" required />
          <small>Use at least 12 characters.</small>
        </label>

        <div class="form-error" id="formError" role="alert"></div>

        <button class="button primary wide" id="submitButton" type="submit">
          ${login ? "Log in" : "Create account"}
        </button>
      </form>

      <p class="auth-switch">
        ${login
          ? 'New to Veyra? <a href="#/register">Create an account</a>'
          : 'Already have an account? <a href="#/login">Log in</a>'}
      </p>
    </section>
  `, { title: login ? "Log in" : "Create account" });

  document.querySelector("#authForm").addEventListener("submit", async (event) => {
    event.preventDefault();

    const button = document.querySelector("#submitButton");
    const error = document.querySelector("#formError");
    const data = Object.fromEntries(new FormData(event.currentTarget));

    error.textContent = "";
    buttonSpinner(button, true, login ? "Signing in…" : "Creating account…");

    try {
      await api.post(login ? "/auth/login" : "/auth/register", data);
      toast(login ? "Welcome back." : "Your Veyra account is ready.", "success");
      location.hash = "#/dashboard";
    } catch (err) {
      error.textContent = err.message;
      buttonSpinner(button, false);
    }
  });
}
