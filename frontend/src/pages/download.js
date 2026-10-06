import { api, downloadBlob } from "../services/api.js";
import { escapeHtml, formatBytes } from "../utils/format.js";
import { buttonSpinner, toast } from "../components/ui.js";

export async function downloadPage(token) {
  let transfer;

  try {
    transfer = await api.get(`/download/${encodeURIComponent(token)}`);
  } catch (err) {
    document.querySelector("#app").innerHTML = `
      <main class="page-shell">
        <section class="center-card download-card">
          <div class="eyebrow">SECURE FILE</div>
          <h1>This link isn't available.</h1>
          <p>${escapeHtml(err.message)}</p>
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
          <span>${formatBytes(transfer.size_bytes)} · Expires ${escapeHtml(transfer.expires_at)}</span>
        </div>

        <p>Enter the verification code sent to the recipient email.</p>

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
            <input id="code" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" autocomplete="one-time-code" required />
          </label>
          <button class="button primary wide" id="verifyButton">Verify & Download</button>
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
      await api.post(`/download/${encodeURIComponent(token)}/request-verification`, {
        email: emailInput.value.trim(),
      });

      requestButton.disabled = true;
      verifyForm.classList.remove("hidden");
      toast("Verification code sent.", "success");
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
      await api.post(`/download/${encodeURIComponent(token)}/verify`, {
        email: emailInput.value.trim(),
        code: codeInput.value.trim(),
      });

      const state = document.querySelector("#downloadState");
      state.classList.remove("hidden");
      state.innerHTML = `
        <div class="success-mark">✓</div>
        <strong>Access granted.</strong>
        <span>Your file is ready to download.</span>
        <button class="button primary" id="downloadButton">Download file</button>
      `;

      document.querySelector("#downloadButton").addEventListener("click", async () => {
        const downloadButton = document.querySelector("#downloadButton");
        buttonSpinner(downloadButton, true, "Preparing file…");

        try {
          const blob = await downloadBlob(`/download/${encodeURIComponent(token)}/file`);
          const url = URL.createObjectURL(blob);
          const anchor = document.createElement("a");
          anchor.href = url;
          anchor.download = transfer.original_filename;
          document.body.appendChild(anchor);
          anchor.click();
          anchor.remove();
          setTimeout(() => URL.revokeObjectURL(url), 1000);
        } catch (err) {
          toast(err.message, "error");
        } finally {
          buttonSpinner(downloadButton, false);
        }
      });

      requestForm.classList.add("hidden");
      verifyForm.classList.add("hidden");
    } catch (err) {
      error.textContent = err.message;
      buttonSpinner(verifyButton, false);
    }
  });
}
