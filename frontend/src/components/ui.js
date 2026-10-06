import { escapeHtml } from "../utils/format.js";

export function toast(message, type = "info") {
  let host = document.querySelector("#toastHost");
  if (!host) {
    host = document.createElement("div");
    host.id = "toastHost";
    host.className = "toast-host";
    document.body.appendChild(host);
  }

  const item = document.createElement("div");
  item.className = `toast toast-${type}`;
  item.textContent = message;
  host.appendChild(item);

  requestAnimationFrame(() => item.classList.add("visible"));
  setTimeout(() => {
    item.classList.remove("visible");
    setTimeout(() => item.remove(), 180);
  }, 3500);
}

export function buttonSpinner(button, loading, loadingText = "Working…") {
  if (!button) return;

  if (loading) {
    button.dataset.originalText = button.textContent;
    button.disabled = true;
    button.innerHTML = `<span class="button-spinner"></span>${escapeHtml(loadingText)}`;
  } else {
    button.disabled = false;
    button.textContent = button.dataset.originalText || button.textContent;
  }
}

export function emptyState({ title, text, actionText, actionHref }) {
  return `
    <div class="empty-state">
      <div class="empty-icon">↗</div>
      <h3>${escapeHtml(title)}</h3>
      <p>${escapeHtml(text)}</p>
      ${actionText ? `<a class="button primary" href="${actionHref}">${escapeHtml(actionText)}</a>` : ""}
    </div>
  `;
}
