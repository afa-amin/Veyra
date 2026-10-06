import { api } from "../services/api.js";
import { renderLayout } from "../components/layout.js";
import { emptyState } from "../components/ui.js";
import { escapeHtml, formatBytes, formatDate, statusClass, humanStatus } from "../utils/format.js";

export async function dashboardPage(user) {
  let transfers = [];

  try {
    transfers = await api.get("/transfers");
  } catch (err) {
    renderLayout(`
      <section class="center-card">
        <div class="eyebrow">DASHBOARD</div>
        <h1>Unable to load transfers.</h1>
        <p>${escapeHtml(err.message)}</p>
        <a class="button primary" href="#/dashboard">Try again</a>
      </section>
    `, { user, title: "Dashboard" });
    return;
  }

  const active = transfers.filter((x) => x.status === "active").length;
  const downloaded = transfers.filter((x) => x.status === "downloaded").length;
  const expiring = transfers.filter((x) => {
    const hours = (new Date(x.expires_at) - Date.now()) / 36e5;
    return x.status === "active" && hours > 0 && hours <= 24;
  }).length;

  const rows = transfers.length
    ? transfers.map((item) => `
      <a class="transfer-row" href="#/transfers/${item.id}">
        <div>
          <strong>${escapeHtml(item.original_filename)}</strong>
          <small>${escapeHtml(item.recipient_email)} · ${formatBytes(item.size_bytes)}</small>
        </div>
        <div class="transfer-meta">
          <span class="${statusClass(item.status)}">${humanStatus(item.status)}</span>
          <small>Expires ${formatDate(item.expires_at)}</small>
        </div>
      </a>
    `).join("")
    : emptyState({
        title: "No transfers yet.",
        text: "Send your first secure file.",
        actionText: "Send a file",
        actionHref: "#/send",
      });

  renderLayout(`
    <section class="page-head">
      <div>
        <div class="eyebrow">OVERVIEW</div>
        <h1>Good to see you, ${escapeHtml(user.display_name)}.</h1>
        <p>Keep track of your secure file transfers.</p>
      </div>
      <a class="button primary" href="#/send">Send a file</a>
    </section>

    <section class="stats-grid">
      <article><strong>${active}</strong><span>Active transfers</span></article>
      <article><strong>${transfers.length}</strong><span>Files sent</span></article>
      <article><strong>${downloaded}</strong><span>Completed</span></article>
      <article><strong>${expiring}</strong><span>Expiring soon</span></article>
    </section>

    <section class="panel">
      <div class="panel-heading">
        <div>
          <h2>Recent transfers</h2>
          <p>Your latest secure links.</p>
        </div>
        <a href="#/transfers">View all</a>
      </div>
      <div class="transfer-list">${rows}</div>
    </section>
  `, { user, title: "Dashboard" });
}
