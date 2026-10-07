# Veyra Installer

Production-oriented installer for Ubuntu 24.04.

## Test installation

```bash
sudo ./installer/install.sh --dev-mode   # codes are printed to the service log (journalctl -u veyra-api); never for production
```

Development mode uses the development OTP mailbox and does not require SMTP.

## Production installation

Configure SMTP before running the installer:

```bash
export VEYRA_SMTP_HOST="smtp.example.com"
export VEYRA_SMTP_PORT="587"
export VEYRA_SMTP_USER="user@example.com"
export VEYRA_SMTP_PASSWORD="your-password"
export VEYRA_SMTP_FROM="Veyra <noreply@example.com>"

sudo -E ./installer/install.sh
```

## Package manager safety

The installer detects apt/dpkg/unattended-upgrades activity and waits for it. It never removes apt/dpkg lock files and never kills an active package manager automatically.

Default wait timeout is 900 seconds:

```bash
sudo VEYRA_APT_WAIT_TIMEOUT=1800 ./installer/install.sh --dev-mode
```

If the package manager remains busy beyond the timeout, the installer exits safely and can be rerun later.

## Public and API ports

A fresh installation scans TCP and UDP listeners on IPv4 and IPv6, then selects two different random non-privileged ports for Nginx/public traffic and the localhost API. Ports 80 and 443 are never selected randomly.

An explicit public port may be supplied: 

```bash
sudo ./installer/install.sh --dev-mode --port 8080
```

`veyractl update` preserves the existing public and API ports, TLS certificate/key configuration, and public URL instead of selecting new ports.

## Management

```bash
sudo veyractl status
sudo veyractl health
sudo veyractl logs
sudo veyractl restart
```


## Build compatibility fixes

The installer installs/updates the Rust stable toolchain before building Veyra. The cryptographic core explicitly declares its `serde_json` dependency, and the installer invokes Cargo through the stable toolchain instead of trusting an arbitrary system Cargo version. It also waits for active apt/dpkg/unattended-upgrades operations without deleting lock files.
