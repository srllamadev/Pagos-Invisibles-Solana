# GhostPay Solana

Security-oriented implementation of a private-note payment flow on Solana using Anchor, SPL Token vaults, commitment/reveal semantics, nullifiers, and PDA-authorized vault spending.

This document is written for security reviewers and auditors.

## 1. Executive Summary

GhostPay Solana implements a privacy-preserving note model where:

1. Sender commits to recipient and amount using hash commitments.
2. Commitments are bound to an off-chain ECDH-derived shared secret hash.
3. Funds can be deposited into an SPL vault during note creation.
4. Spending requires a private ownership opening proof and a unique nullifier.
5. Vault withdrawals are authorized by a program-derived PDA signer.

The design goal is practical privacy hardening in a transparent ledger while maintaining explicit anti-double-spend constraints and strict account binding checks.

## 2. Repository Scope

Core on-chain program:

- [src/lib.rs](src/lib.rs)

Client and UI prototypes:

- [client/client.ts](client/client.ts)
- [frontend/index.html](frontend/index.html)
- [frontend/styles.css](frontend/styles.css)
- [frontend/app.js](frontend/app.js)

Program tests:

- [tests/anchor.test.ts](tests/anchor.test.ts)

## 3. Security Goals

Primary goals:

1. Confidentiality of recipient linkage and amount prior to reveal.
2. Anti-replay and anti-double-spend through nullifier uniqueness.
3. Authorization of spend through knowledge proof, not plain identity.
4. Controlled vault movement through PDA signer seeds and account constraints.
5. Deterministic, auditable spend path.

Secondary goals:

1. Support selective reveal for audit/compliance workflows.
2. Keep protocol state compact and explicit.

Non-goals (current version):

1. Full zero-knowledge anonymity set guarantees.
2. Mempool-level privacy.
3. Network-layer unlinkability.
4. Production hardening against all side-channel classes.

## 4. High-Level Architecture

System components:

1. On-chain Anchor program
: Stores notes, verifies reveal openings, enforces nullifier uniqueness, and controls vault spends.
2. Off-chain cryptographic derivation
: Derives shared secret hash (ECDH-style) and commitment inputs.
3. SPL Token vault
: Holds committed funds until valid spend execution.
4. Frontend and client
: Generates commitments, computes nullifiers, performs local scan matching, and submits transactions.

Trust boundaries:

1. Program state and SPL balances are trusted on-chain truth.
2. Off-chain derivation logic is trusted only as input producer; all critical checks are revalidated on-chain where applicable.
3. Wallet signing environment must be trusted by the user.

## 5. Protocol Overview

### 5.1 Create Note (Commit)

Inputs:

1. hashed_recipient (32 bytes)
2. amount_commitment (32 bytes)
3. ephemeral_pubkey (32 bytes)
4. scan_tag (32 bytes)
5. spend_auth_commitment (32 bytes)
6. nonce (u64)

Optional vault path:

1. SPL transfer from signer token account to vault token account.
2. Persist vault account, vault authority PDA, and mint binding in note state.

### 5.2 Reveal

Inputs:

1. recipient
2. recipient_blinding
3. shared_secret_hash
4. amount
5. amount_blinding

On-chain checks:

1. Recompute recipient commitment and match stored hashed_recipient.
2. Recompute amount commitment and match stored amount_commitment.
3. Recompute scan_tag from ephemeral_pubkey and shared_secret_hash.

### 5.3 Nullifier Consumption

Inputs:

1. nullifier
2. spend_auth_opening

On-chain checks:

1. Note is not yet spent.
2. ownership_commitment == hash(note_pubkey || spend_auth_opening).
3. nullifier == hash(note_pubkey || spend_auth_opening || "nullifier").
4. nullifier PDA is initialized exactly once.

### 5.4 Secure Vault Spend

Inputs:

1. nullifier
2. spend_auth_opening
3. withdraw_amount

On-chain checks:

1. Note is unspent.
2. vault_token_account matches note state.
3. vault_authority PDA matches note state.
4. token_mint matches note state.
5. withdraw_amount must equal full note vault amount (current rule).
6. ownership proof and nullifier derivation checks pass.

Execution:

1. Initialize nullifier record.
2. Transfer SPL from vault token account to recipient token account using PDA signer seeds.
3. Mark note spent and zero out vault_deposit_amount.

## 6. Cryptographic Design

### 6.1 Shared Secret Binding

Off-chain ECDH (X25519-style in client/test prototype) derives shared secret, then:

$$
shared\_secret\_hash = H(shared\_secret || nonce)
$$

This hash binds reveal and scan calculations to sender/receiver key agreement context.

### 6.2 Recipient Commitment

$$
hashed\_recipient = H(recipient || recipient\_blinding || shared\_secret\_hash)
$$

### 6.3 Amount Commitment

$$
amount\_commitment = H(amount\_{le\_u64} || amount\_blinding || shared\_secret\_hash)
$$

### 6.4 Scan Tag

$$
scan\_tag = H(ephemeral\_pubkey || shared\_secret\_hash)
$$

### 6.5 Spend Authorization Commitment

$$
spend\_auth\_commitment = H(note\_pubkey || spend\_auth\_opening)
$$

### 6.6 Nullifier

$$
nullifier = H(note\_pubkey || spend\_auth\_opening || "nullifier")
$$

Nullifier uniqueness is enforced by PDA initialization under seed prefix nullifier.

## 7. State Model

Primary account: GhostPayment

1. payer
2. hashed_recipient
3. amount_commitment
4. ephemeral_pubkey
5. scan_tag
6. spend_auth_commitment
7. nonce
8. reveal fields
9. vault_token_account
10. vault_authority
11. token_mint
12. vault_deposit_amount
13. spent

Auxiliary account: NullifierRecord

1. nullifier
2. ghost_payment
3. owner
4. created_at_slot

## 8. Security Controls and Invariants

### 8.1 Anti-Double-Spend

Control:

1. spent flag on note.
2. NullifierRecord PDA init-once semantics.

Invariant:

1. A nullifier can be consumed only once.
2. A note marked spent cannot be spent again.

### 8.2 Vault Integrity

Control:

1. Mint binding checks.
2. Vault account ownership checks.
3. Vault authority binding to note state.
4. PDA signer seeds for token transfer authorization.

Invariant:

1. Program only spends from the exact vault and mint recorded in note state.

### 8.3 Spend Authorization Privacy

Control:

1. Spend path validates opening proof against spend_auth_commitment.

Invariant:

1. Possession of signer identity alone does not authorize spending.

### 8.4 Reveal Integrity

Control:

1. Recipient and amount opening checks.
2. shared_secret_hash consistency check via scan_tag.

Invariant:

1. Invalid opening values are rejected.

## 9. Threat Model

### In-Scope Threats

1. Double-spend attempts via replayed nullifier.
2. Unauthorized vault withdrawals via forged account routing.
3. Invalid reveal data intended to forge commitment opening.
4. Cross-note replay of spend authorizations.

### Out-of-Scope or Partially Mitigated

1. Full anonymity against global traffic analysis.
2. Endpoint compromise of wallet/browser/device.
3. Side-channel leakage in off-chain cryptographic libraries.
4. Metadata leakage from transaction timing and fee behavior.

## 10. Instruction-Level Security Notes

On-chain API in [src/lib.rs](src/lib.rs):

1. create_ghost_payment
: Commits note fields without token movement.
2. create_ghost_payment_with_vault
: Commits note and deposits SPL into vault.
3. reveal_payment
: Verifies commitment openings and shared secret binding.
4. consume_nullifier
: Consumes nullifier with private opening proof.
5. spend_from_vault
: Performs secure vault withdrawal with PDA signer seeds.

## 11. Testing and Verification

Reference tests in [tests/anchor.test.ts](tests/anchor.test.ts):

1. Commit and reveal path using ECDH-style shared secret derivation.
2. Nullifier consumption and spent-state transition.
3. Vault deposit using SPL mint and ATAs.
4. Vault spend from PDA-controlled account to recipient ATA.

Recommended additional tests for formal audit readiness:

1. Negative spend with incorrect spend_auth_opening.
2. Nullifier replay attack attempt.
3. Mint mismatch and vault account mismatch rejection tests.
4. Fuzzing for malformed 32-byte arrays and boundary u64 values.
5. Property tests ensuring nullifier uniqueness across random openings.

## 12. Operational Security Checklist

Before production deployment:

1. Freeze and version cryptographic domain separators.
2. Add explicit domain tags to all hashes to reduce cross-context collision risk.
3. Introduce circuit-based or proof-based spend authorization for stronger privacy.
4. Add rate-limited monitoring for suspicious nullifier failures.
5. Run external audit and differential testing against a reference model.
6. Review compute budget behavior under adversarial transaction packing.
7. Lock dependency versions and verify reproducible builds.

## 13. Current Limitations

1. Full-note spend rule is currently enforced for vault spends.
2. No zk-proof system is integrated yet.
3. UI frontend includes local demo paths and is not a production custody interface.
4. Privacy remains probabilistic under public-ledger metadata analysis.

## 14. Frontend Security Notes

Prototype UI lives in:

1. [frontend/index.html](frontend/index.html)
2. [frontend/styles.css](frontend/styles.css)
3. [frontend/app.js](frontend/app.js)

The frontend currently demonstrates local commitment logic and workflow UX. Security-critical acceptance checks remain on-chain.

## 15. Build and Local Run

Static frontend preview:

```bash
python3 -m http.server 8080
```

Open:

```url
http://localhost:8080/frontend/
```

Program and test execution depend on Anchor/Solana Playground environment and project setup.

## 16. Audit Contact and Disclosure Policy

Suggested policy for this repository:

1. Report vulnerabilities privately to maintainers first.
2. Include proof-of-concept, impact, and affected instruction(s).
3. Allow coordinated disclosure window before public report.

Until a formal policy file is added, treat findings as confidential by default.
