import { api } from "../services/api.js";
import { renderLayout } from "../components/layout.js";
import { createDropzone } from "../components/dropzone.js";
import { createPolicyBuilder } from "../components/policy-builder.js";
import { buttonSpinner, toast } from "../components/ui.js";
import { escapeHtml, formatBytes } from "../utils/format.js";

export function sendPage(user) {
  renderLayout(`
    <section class="page-head">
      <div>
        <div class="eyebrow">NEW TRANSFER</div>
        <h1>Send a secure file.</h1>
        <p>Choose the recipient and how long access should remain available.</p>
      </div>
    </section>

    <div class="send-grid">
      <section class="panel upload-panel">
        <div id="dropzoneHost"></div>
        <div id="filePreview"></div>
      </section>

      <section class="panel">
        <form id="sendForm" class="form-stack">
          <label>
            Recipient
            <input type="email" name="recipient_email" placeholder="recipient@example.com" required />
          </label>

          <label>
            Access
            <select name="access_mode" id="accessMode">
              <option value="simple">Anyone with secure verification</option>
              <option value="restricted">Restricted access</option>
            </select>
          </label>

          <div id="policyHost" class="hidden"></div>

          <label>
            Expires
            <select name="expires_hours">
              <option value="1">1 hour</option>
              <option value="24">24 hours</option>
              <option value="72" selected>72 hours</option>
              <option value="168">7 days</option>
              <option value="720">30 days</option>
            </select>
          </label>

          <label>
            Downloads
            <select name="download_limit">
              <option value="1">1 download</option>
              <option value="5">5 downloads</option>
              <option value="10">10 downloads</option>
              <option value="unlimited">Unlimited</option>
            </select>
          </label>

          <label class="checkbox">
            <input type="checkbox" name="destroy_after_first" />
            <span>Destroy after first successful download</span>
          </label>

          <div class="form-error" id="sendError" role="alert"></div>

          <div class="upload-progress hidden" id="uploadProgress">
            <div class="progress-label"><span>Uploading and protecting…</span><strong id="progressValue">0%</strong></div>
            <div class="progress"><span id="progressBar"></span></div>
          </div>

          <button class="button primary wide" id="createButton" type="submit" disabled>
            Create Secure Link
          </button>
        </form>
      </section>
    </div>
  `, { user, title: "Send a secure file" });

  let selectedFile = null;
  const dropHost = document.querySelector("#dropzoneHost");
  const preview = document.querySelector("#filePreview");
  const button = document.querySelector("#createButton");
  const policyHost = document.querySelector("#policyHost");
  let policyBuilder = null;

  const setFile = (files) => {
    selectedFile = files[0] || null;
    if (!selectedFile) {
      preview.innerHTML = "";
      button.disabled = true;
      return;
    }

    preview.innerHTML = `
      <div class="selected-file">
        <div>
          <strong>${escapeHtml(selectedFile.name)}</strong>
          <small>${formatBytes(selectedFile.size)} · ${escapeHtml(selectedFile.type || "Unknown type")}</small>
        </div>
        <button type="button" class="icon-button" id="removeFile" aria-label="Remove file">×</button>
      </div>
    `;
    button.disabled = false;
    document.querySelector("#removeFile").onclick = () => {
      selectedFile = null;
      preview.innerHTML = "";
      button.disabled = true;
    };
  };

  dropHost.appendChild(createDropzone({ onFiles: setFile }));

  document.querySelector("#accessMode").addEventListener("change", (event) => {
    const restricted = event.target.value === "restricted";
    policyHost.classList.toggle("hidden", !restricted);

    if (restricted && !policyBuilder) {
      policyBuilder = createPolicyBuilder();
      policyHost.appendChild(policyBuilder.element);
    }
  });

  document.querySelector("#sendForm").addEventListener("submit", async (event) => {
    event.preventDefault();

    if (!selectedFile) return;

    const form = new FormData(event.currentTarget);
    form.set("file", selectedFile);
    form.set("destroy_after_first", String(form.has("destroy_after_first")));

    const error = document.querySelector("#sendError");
    if (form.get("access_mode") === "restricted") {
      const problem = policyBuilder?.validate();
      if (problem) {
        error.textContent = problem;
        return;
      }
      form.set("policy_expression", policyBuilder.getExpression());
    } else {
      form.delete("policy_expression");
    }

    const progress = document.querySelector("#uploadProgress");
    const progressBar = document.querySelector("#progressBar");
    const progressValue = document.querySelector("#progressValue");

    error.textContent = "";
    progress.classList.remove("hidden");
    buttonSpinner(button, true, "Creating secure link…");

    try {
      const result = await api.upload("/transfers", form, (percent) => {
        progressBar.style.width = `${percent}%`;
        progressValue.textContent = `${percent}%`;
      });

      renderSuccess(user, result);
    } catch (err) {
      error.textContent = err.message;
      progress.classList.add("hidden");
      buttonSpinner(button, false);
    }
  });
}

function renderSuccess(user, result) {
  renderLayout(`
    <section class="center-card success-card">
      <div class="success-mark">✓</div>
      <div class="eyebrow">SECURE TRANSFER READY</div>
      <h1>Your file is ready.</h1>
      <div class="file-summary">
        <strong>${escapeHtml(result.original_filename)}</strong>
        <span>Protected · Expires ${escapeHtml(result.expires_at)}</span>
      </div>

      <label class="link-field">
        Secure link
        <div>
          <input id="secureLink" value="${escapeHtml(result.secure_link)}" readonly />
          <button class="button" id="copyLink" type="button">Copy</button>
        </div>
      </label>

      <div class="success-actions">
        <a class="button primary" href="#/dashboard">View dashboard</a>
        <a class="button" href="#/send">Send another</a>
      </div>
      <p class="muted">Share this link only with the intended recipient.</p>
    </section>
  `, { user, title: "Secure link ready" });

  document.querySelector("#copyLink").addEventListener("click", async () => {
    const input = document.querySelector("#secureLink");
    await navigator.clipboard.writeText(input.value);
    toast("Secure link copied.", "success");
  });
}
