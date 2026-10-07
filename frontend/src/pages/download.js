import { api } from "../services/api.js";
import { escapeHtml, formatBytes } from "../utils/format.js";
import { buttonSpinner, toast } from "../components/ui.js";

const CODE_LENGTH = 8;

export async function downloadPage(token) {
  const encoded = encodeURIComponent(token);
  let transfer;

  try {
    transfer = await api.get(`/download/${encoded}`);
  } catch (err) {
    document.querySelector("#app").innerHTML = `
      <main class="page-shell">
        <section class="center-card download-card">
          <div class="eyebrow">SECURE FILE</div>
          <h1>This link isn't available.</h1>
          <p>It may have expired, been revoked, or already been used.</p>
        </section>
      </main>
    `;
    return;
  }

  document.querySelector("#app").innerHTML = `
    <main class="page-shell public-shell">
      <section class="center-card download-card">
        <div class="eyebrow">SECURE FILE</div>
        <h1>You've received a secure file.</h1>

        <div class="file-summary public">
          <strong>${escapeHtml(transfer.original_filename)}</strong>
          <span>${formatBytes(transfer.size_bytes)} · Expires ${escapeHtml(new Date(transfer.expires_at).toLocaleString())}</span>
        </div>

        <p>Confirm your email address to receive a one-time verification code.</p>

        <form id="verifyRequest" class="form-stack">
          <label>
            Recipient email
            <input type="email" id="email" autocomplete="email" required />
          </label>
          <button class="button primary wide" id="requestButton">Send verification code</button>
          <div class="form-error" id="downloadError" role="alert"></div>
        </form>

        <form id="verifyForm" class="form-stack hidden">
          <label>
            Verification code
            <input id="code" inputmode="numeric" pattern="[0-9]{${CODE_LENGTH}}" maxlength="${CODE_LENGTH}" autocomplete="one-time-code" required />
          </label>
          <button class="button primary wide" id="verifyButton">Verify</button>
        </form>

        <div id="downloadState" class="download-state hidden"></div>
      </section>
    </main>
  `;

  const requestForm = document.querySelector("#verifyRequest");
  const verifyForm = document.querySelector("#verifyForm");
  const requestButton = document.querySelector("#requestButton");
  const verifyButton = document.querySelector("#verifyButton");
  const error = document.querySelector("#downloadError");
  const emailInput = document.querySelector("#email");
  const codeInput = document.querySelector("#code");

  requestForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    error.textContent = "";
    buttonSpinner(requestButton, true, "Sending…");

    try {
      const result = await api.post(`/download/${encoded}/request-verification`, {
        email: emailInput.value.trim(),
      });
      buttonSpinner(requestButton, false);
      requestButton.textContent = "Send a new code";
      verifyForm.classList.remove("hidden");
      codeInput.focus();
      toast(result.message || "If the address matches, a code has been sent.", "success");
    } catch (err) {
      error.textContent = err.message;
      buttonSpinner(requestButton, false);
    }
  });

  verifyForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    error.textContent = "";
    buttonSpinner(verifyButton, true, "Verifying…");

    try {
      // The server answers with an HttpOnly cookie scoped to this link. No secret is
      // exposed to page scripts and the browser streams the file straight to disk.
      await api.post(`/download/${encoded}/verify`, {
        email: emailInput.value.trim(),
        code: codeInput.value.trim(),
      });
      requestForm.classList.add("hidden");
      verifyForm.classList.add("hidden");
      await showReady();
    } catch (err) {
      error.textContent = err.message;
      buttonSpinner(verifyButton, false);
    }
  });

  async function showReady() {
    const state = document.querySelector("#downloadState");
    state.classList.remove("hidden");

    let status = { ready: true, remaining: null };
    try {
      status = await api.get(`/download/${encoded}/status`);
    } catch {
      // Fall through: the download endpoint enforces the real limits.
    }

    const remaining =
      status.remaining === null || status.remaining === undefined
        ? ""
        : `<small>${status.remaining} download${status.remaining === 1 ? "" : "s"} remaining</small>`;

    state.innerHTML = `
      <div class="success-mark">✓</div>
      <strong>Access granted.</strong>
      <span>Your file is decrypted on the fly while it downloads.</span>
      ${remaining}
      ${
        status.ready
          ? `<a class="button primary" id="downloadButton" href="/api/v1/download/${encoded}/file" download>Download file</a>`
          : `<span class="form-error">No downloads remain for this link.</span>`
      }
    `;

    document.querySelector("#downloadButton")?.addEventListener("click", () => {
      setTimeout(showReadyQuietly, 2500);
    });
  }

  async function showReadyQuietly() {
    try {
      const status = await api.get(`/download/${encoded}/status`);
      if (!status.ready) {
        document.querySelector("#downloadState").innerHTML = `
          <div class="success-mark">✓</div>
          <strong>Download started.</strong>
          <span>No further downloads are available for this link.</span>
        `;
      }
    } catch {
      document.querySelector("#downloadState").innerHTML = `
        <div class="success-mark">✓</div>
        <strong>Download started.</strong>
        <span>This link is no longer available.</span>
      `;
    }
  }
}
