# TLS Deployment Evidence Scaffold

This directory prepares Lab 4 TLS deployment evidence without claiming a public trusted-root deployment yet.

## Lab Requirement

The final TLS evidence should show an Apache or Nginx deployment using TLS 1.2 or TLS 1.3. A trusted-root certificate is preferred, for example a CA-issued certificate from ZeroSSL, but only when an owned domain is available and the certificate can be validated for that domain. An ECDSA certificate is preferred when the CA and server platform support it.

Current status:

- Local self-signed TLS configuration is provided for parser and configuration practice.
- Trusted-root deployment is pending.
- This repository does not claim trusted-root browser/OS validation until real owned-domain evidence and a CA-issued certificate chain are added.
- Self-signed local TLS is not equivalent to public trusted-root TLS.

## Trust Chain

A trusted public TLS deployment normally includes:

- Leaf certificate: issued for the site hostname, with a matching SAN.
- Intermediate CA certificate: signs the leaf and chains toward a root.
- Root CA certificate: trusted by the operating system or browser trust store.

The browser or client validates that the leaf certificate chains through intermediates to a trusted root. A self-signed local certificate signs itself, so it does not prove public trust. It can be useful for local OpenSSL, Nginx, or Apache configuration practice, but it does not satisfy the trusted-root requirement.

## Certificate Validation Items

TLS evidence should check:

- Hostname/SAN matches the requested DNS name.
- Certificate validity period is current.
- Signature chain verifies from leaf to intermediate to trusted root.
- Key usage and extended key usage allow TLS server authentication.
- Weak signature algorithms such as MD5 and SHA-1 are not used.

## Ethics

Do not test against third-party targets. Use only a local server or an owned domain. Do not scan public websites, copy third-party certificates as claimed evidence, or submit traffic to systems you do not control.

## Files

- `nginx_or_apache_config_snippet.conf`: compact reference snippets for either server.
- `cert_chain_info.txt`: placeholder now; overwritten by local scripts with OpenSSL certificate text for practice certificates.
- `tls_test_log.txt`: placeholder now; overwritten by local scripts with a clear local self-signed limitation notice.
- `screenshots_placeholder.md`: checklist for screenshots to add later if a real owned-domain deployment is performed.

## Local Self-Signed Practice

Windows:

```powershell
powershell -ExecutionPolicy Bypass -File lab4_hash_pki\scripts\tls_local_self_signed_demo_windows.ps1
```

Linux:

```bash
bash lab4_hash_pki/scripts/tls_local_self_signed_demo_linux.sh
```

These scripts generate a local ECDSA key and self-signed certificate with `DNS:localhost` under `demos/tls/local/`. They do not require admin privileges and do not claim public trust.

