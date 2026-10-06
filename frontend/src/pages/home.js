import { renderLayout } from "../components/layout.js";

export function homePage(user) {
  renderLayout(`
    <section class="hero">
      <div class="eyebrow">PRIVATE FILE TRANSFER</div>
      <h1>Send sensitive files securely.</h1>
      <p class="hero-copy">
        Encrypted file transfers with access controls you can trust.
      </p>

      <a class="button primary button-large" href="${user ? "#/send" : "#/register"}">
        Send a file
      </a>

      <div class="hero-drop">
        <div class="upload-icon">↑</div>
        <strong>Drop your files here</strong>
        <span>or <a href="${user ? "#/send" : "#/login"}">Browse files</a></span>
      </div>

      <div class="trust-grid">
        <span>✓ Encrypted at rest and in transit</span>
        <span>✓ Expiring links</span>
        <span>✓ Access controls</span>
        <span>✓ No plaintext persistent storage</span>
      </div>
    </section>

    <section class="feature-grid">
      <article>
        <span class="feature-number">01</span>
        <h2>Simple by design</h2>
        <p>Select a file, choose who can access it, and create a secure link.</p>
      </article>
      <article>
        <span class="feature-number">02</span>
        <h2>Controlled access</h2>
        <p>Use verification and organization requirements without writing policies yourself.</p>
      </article>
      <article>
        <span class="feature-number">03</span>
        <h2>Built for sensitive data</h2>
        <p>Encrypted objects, expiring links, revocation, download limits, and audit events.</p>
      </article>
    </section>
  `, { user, title: "Send sensitive files securely" });
}
