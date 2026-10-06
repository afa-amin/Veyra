import { api } from "../services/api.js";
import { renderLayout } from "../components/layout.js";
import { buttonSpinner, toast } from "../components/ui.js";
import { escapeHtml, formatBytes, formatDate, statusClass, humanStatus } from "../utils/format.js";

export async function transferPage(user, id) {
  // The current API exposes the transfer collection but not a single-transfer GET.
  // Keep this page useful without inventing an unsupported endpoint.
  try {
    const transfers = await api.get("/transfers");
    const transfer = transfers.find((item) => item.id === id);

    if (!transfer) throw new Error("Transfer not found.");

    renderLayout(`
      <section class="page-head">
        <div>
          <div class="eyebrow">TRANSFER</div>
          <h1>${escapeHtml(transfer.original_filename)}</h1>
          <p>${formatBytes(transfer.size_bytes)} · ${escapeHtml(transfer.recipient_email)}</p>
        </div>
        <span class="${statusClass(transfer.status)} large">${humanStatus(transfer.status)}</span>
      </section>

      <div class="detail-grid">
        <section class="panel">
          <h2>Transfer details</h2>
          <dl>
            <dt>Recipient</dt><dd>${escapeHtml(transfer.recipient_email)}</dd>
            <dt>Created</dt><dd>${formatDate(transfer.created_at)}</dd>
            <dt>Expires</dt><dd>${formatDate(transfer.expires_at)}</dd>
            <dt>Downloads</dt><dd>${transfer.download_count} / ${transfer.download_limit ?? "Unlimited"}</dd>
            <dt>Access</dt><dd>${escapeHtml(transfer.access_mode)}</dd>
          </dl>
        </section>

        <section class="panel">
          <h2>Actions</h2>
          <p class="muted">Revoking access immediately prevents further authorization.</p>
          <button class="button danger wide" id="revokeButton" ${transfer.status !== "active" ? "disabled" : ""}>
            Revoke access
          </button>
        </section>
      </div>
    `, { user, title: transfer.original_filename });

    document.querySelector("#revokeButton")?.addEventListener("click", async () => {
      const button = document.querySelector("#revokeButton");
      if (!confirm("Revoke access to this transfer?")) return;

      buttonSpinner(button, true, "Revoking…");
      try {
        await api.post(`/transfers/${encodeURIComponent(id)}/revoke`, {});
        toast("Access revoked.", "success");
        await transferPage(user, id);
      } catch (err) {
        buttonSpinner(button, false);
        toast(err.message, "error");
      }
    });
  } catch (err) {
    renderLayout(`
      <section class="center-card">
        <div class="eyebrow">TRANSFER</div>
        <h1>Transfer unavailable.</h1>
        <p>${escapeHtml(err.message)}</p>
        <a class="button primary" href="#/transfers">Back to transfers</a>
      </section>
    `, { user, title: "Transfer" });
  }
}
