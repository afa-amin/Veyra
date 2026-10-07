//! Verification-code delivery.

use crate::config::{Config, SmtpTls};
use anyhow::{bail, Result};
use lettre::{
    message::Mailbox, transport::smtp::authentication::Credentials, AsyncSmtpTransport, AsyncTransport, Message,
    Tokio1Executor,
};
use std::time::Duration;

pub async fn send_otp(cfg: &Config, to: &str, code: &str, ttl_minutes: i64) -> Result<()> {
    let host = match cfg.smtp_host.as_deref() {
        Some(h) => h,
        None => {
            if cfg.is_development() {
                // Development convenience only: production refuses to start without SMTP.
                tracing::warn!(recipient = %to, code = %code, "DEVELOPMENT MODE: SMTP is not configured, printing the verification code");
                return Ok(());
            }
            bail!("SMTP is not configured");
        }
    };

    let from: Mailbox = cfg.smtp_from.parse()?;
    let recipient: Mailbox = to.parse()?;
    let message = Message::builder()
        .from(from)
        .to(recipient)
        .subject("Your Veyra verification code")
        .body(format!(
            "Your Veyra verification code is:\n\n    {code}\n\n\
             It expires in {ttl_minutes} minutes and can be used once.\n\
             If you did not request this code, you can ignore this message. \
             Nobody can download the file without it.\n"
        ))?;

    let builder = match cfg.smtp_tls {
        SmtpTls::Wrapper => AsyncSmtpTransport::<Tokio1Executor>::relay(host)?,
        SmtpTls::StartTls => AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(host)?,
        SmtpTls::None => AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(host),
    };
    let mut builder = builder.port(cfg.smtp_port).timeout(Some(Duration::from_secs(20)));
    if let (Some(user), Some(password)) = (&cfg.smtp_user, &cfg.smtp_password) {
        builder = builder.credentials(Credentials::new(user.clone(), password.clone()));
    }
    builder.build().send(message).await?;
    Ok(())
}
