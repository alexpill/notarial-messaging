# notarial-messaging

A secure instant messaging prototype for French notarial practice, built on the
**LocalPKI** paradigm (Dumas, Lafourcade, Melemedjian, Orfila, Thoniel, 2019).

Built as part of subject **S001 — Astéroïde 2026**.

---

## Background

French notarial practice currently relies on centralized communication
infrastructure where party identities are guaranteed by distant PKIX certificate
authorities. **LocalPKI** proposes that certificates be self-signed by users
themselves, with the notary acting as a local trust authority — storing only a
hash of each certificate, never its content.

This project builds an instant messaging system on that foundation, with
client-side encryption and a Merkle transparency log for archiving purposes.

---

## Tech stack

| Component | Technology |
|---|---|
| Backend | Rust — Axum, SQLite |
| Frontend | SvelteKit + TypeScript |

---

## Requirements

- Rust stable ≥ 1.75
- Node.js ≥ 20

---

## Quick start

```bash
cp .env.example .env
# Fill in HSM_MASTER_KEY_HEX and EN_SIGNING_KEY_HEX (see .env.example)

cargo run -p server
```

---

## References

- Dumas et al. *LocalPKI: An Interoperable and IoT Friendly PKI*. 2019.
- RFC 5869 — HKDF
- RFC 6962 — Certificate Transparency
