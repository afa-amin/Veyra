import { renderLayout } from "../components/layout.js";

const pages = {
  privacy: {
    title: "Privacy",
    heading: "Privacy by design.",
    paragraphs: [
      "Veyra stores the metadata needed to operate secure transfers, authentication, authorization, auditing, and expiration.",
      "Persistent object storage contains encrypted file objects rather than plaintext files.",
      "Veyra does not intentionally place passwords, session tokens, OTP codes, private keys, or plaintext file contents into application logs.",
    ],
  },
  security: {
    title: "Security",
    heading: "Security is part of the product.",
    paragraphs: [
      "Veyra combines authenticated encryption, controlled access, expiring links, recipient verification, revocation, download limits, and audit events.",
      "The service does not claim true end-to-end encryption when the server participates in encryption or decryption.",
      "Production deployments should use TLS, protected secrets, hardened PostgreSQL, restricted object-storage credentials, and an independent security review.",
    ],
  },
  terms: {
    title: "Terms",
    heading: "Responsible use.",
    paragraphs: [
      "Use Veyra only for files and activity you are authorized to handle.",
      "Do not use the service to distribute unlawful content or to bypass access controls.",
      "Organizations deploying Veyra are responsible for their own retention, compliance, and access policies.",
    ],
  },
};

export function legalPage(type) {
  const page = pages[type] || pages.security;

  renderLayout(`
    <section class="legal-page">
      <div class="eyebrow">VEYRA</div>
      <h1>${page.heading}</h1>
      ${page.paragraphs.map((paragraph) => `<p>${paragraph}</p>`).join("")}
    </section>
  `, { title: page.title });
}
