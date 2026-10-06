import { api } from "../services/api.js";
import { renderLayout } from "../components/layout.js";
import { emptyState } from "../components/ui.js";
import { escapeHtml, formatBytes, formatDate, statusClass, humanStatus } from "../utils/format.js";

export async function transfersPage(user) {
  try {
    const transfers = await api.get("/transfers");

    const content = transfers.length
      ? `<div class="transfer-list full-list">${transfers.map((item) => `
          <a class="transfer-row" href="#/transfers/${item.id}">
            <div>
              <strong>${escapeHtml(item.original_filename)}</strong>
              <small>${escapeHtml(item.recipient_email)} · ${formatBytes(item.size_bytes)}</small>
            </div>
            <div class="transfer-meta">
              <span class="${statusClass(item.status)}">${humanStatus(item.status)}</span>
              <small>Created ${formatDate(item.created_at)}</small>
            </div>
          </a>
        `).join("")}</div>`
      : emptyState({
          title: "No transfers yet.",
          text: "Create your first secure transfer.",
          actionText: "Send a file",
          actionHref: "#/send",
        });

    renderLayout(`
      <section class="page-head">
        <div>
          <div class="eyebrow">TRANSFERS</div>
          <h1>All transfers</h1>
          <p>Review and control files you've sent.</p>
        </div>
        <a class="button primary" href="#/send">Send a file</a>
      </section>
      <section class="panel">${content}</section>
    `, { user, title: "Transfers" });
  } catch (err) {
    renderLayout(`
      <section class="center-card">
        <h1>Couldn't load transfers.</h1>
        <p>${escapeHtml(err.message)}</p>
      </section>
    `, { user, title: "Transfers" });
  }
}
