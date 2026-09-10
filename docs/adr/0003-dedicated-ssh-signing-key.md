# 3. Dedicated SSH signing key, separate from the authentication key

## Status
Accepted

## Context
The threat model this controller defends against explicitly includes "stolen SSH authentication keys." If a single SSH key is used for both Git transport authentication and commit signing, a stolen key lets an attacker both push *and* forge GitHub-verified signatures — the signed-commit control would provide no additional protection in exactly the scenario it exists to cover.

## Decision
Generate a second, dedicated SSH keypair used only for commit signing (`~/.ssh/id_ed25519_signing`), registered on GitHub specifically via `POST /user/ssh_signing_keys` (the "signing key" slot, distinct from `POST /user/keys` which registers an "authentication key"). Git is configured globally: `gpg.format=ssh`, `user.signingkey=~/.ssh/id_ed25519_signing.pub`, `commit.gpgsign=true`, `gpg.ssh.allowedSignersFile=~/.ssh/allowed_signers`.

Per explicit user preference, the signing key has no passphrase, matching the existing convention for the authentication key.

## Consequences
- A stolen authentication key no longer compromises the signed-commit control — it grants push access but not the ability to forge a verified signature.
- Two operationally significant, non-obvious GitHub behaviors were discovered applying this decision (see SESSION.md "Gotchas" for the concrete incident):
  1. **GitHub does not retroactively verify commits made before a signing key was registered.** Only commits created after registration verify. The controller's own bootstrap commit on `main` (`5a8279a`) predates key registration and will show "Unverified" permanently; it was left as-is rather than rewriting protected trunk history without separate approval.
  2. **Commit signature verification requires the commit author's email to match a verified email on the GitHub account that owns the signing key** — not just a syntactically valid signature from a registered key. A mismatch here surfaces as `reason: unknown_key`, which reads like a key-registration problem but is actually an identity problem.
