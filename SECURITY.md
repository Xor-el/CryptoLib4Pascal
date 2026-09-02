# Security policy

CryptoLib4Pascal is a cryptographic library — symmetric and AEAD ciphers, RSA/DSA/ECDSA/EdDSA/Schnorr/
MuSig2, post-quantum algorithms (ML-KEM, ML-DSA, SLH-DSA), KDFs and password hashing, MACs, X.509
certificate generation/parsing, ASN.1, PEM, and RNG wrappers. This is security-critical code. We take
vulnerability reports seriously and are grateful to researchers who report them responsibly.

## Supported versions

`master` is the actively maintained branch and the source for all releases. Fixes land on `master`
first and ship in the next tagged release, so `master` may already contain a fix that hasn't been
released yet — please check against `master` before reporting an issue. Older tagged releases are not
backported to.

## Reporting a vulnerability

**Please report security vulnerabilities privately — do not open a public issue, pull request, or
discussion for a suspected vulnerability.**

Preferred channel: **GitHub private vulnerability reporting.** On this repository, go to the
**Security** tab → **Report a vulnerability**.

A good report includes:

- the affected primitive or component (e.g. `TGcmBlockCipher`, `TEcDsaSigner`, `TMlKemGenerator`,
  the X.509/ASN.1 parser, a specific padding scheme or KDF) and version or commit;
- a clear description of the issue and its security impact (what an attacker can achieve);
- a minimal reproduction — a test case, sample key/ciphertext/certificate, or a short program — and
  the affected toolchain (Delphi or FreePascal, version, OS, architecture) where relevant;
- any suggested remediation, if you have one.

You do not need a working exploit — a credible analysis of a broken invariant (e.g. nonce reuse, a
non-constant-time comparison on secret data, a parser that can be driven out of bounds) is enough.

## What to expect

This is a solo-maintained open-source project, so responses are best-effort rather than covered by a
formal SLA. In general you can expect:

- **Acknowledgement** of your report, typically within a few days.
- An initial **assessment** (is it a vulnerability, likely severity, affected versions) once it's
  been reviewed.
- **Coordinated disclosure.** We aim to develop and release a fix before public disclosure, and to
  coordinate timing with you. Our default embargo target is **90 days** from the initial report,
  shorter for issues under active exploitation and extendable by mutual agreement for complex fixes.
- **Credit** in the release notes, if you'd like it. Let us know if you'd prefer to remain anonymous.

## Scope

**In scope** — vulnerabilities in the implementations this repository ships:

- symmetric and AEAD ciphers — key/IV/nonce handling, block mode implementations, padding-oracle
  conditions, and non-constant-time or otherwise unsafe authentication-tag verification (GCM,
  GCM-SIV, CCM, EAX, OCB, ChaCha20-Poly1305);
- asymmetric cryptography — RSA padding (PKCS#1 v1.5, OAEP, PSS, ISO 9796) implementation flaws
  (e.g. a Bleichenbacher-style oracle), predictable or reused nonces in DSA/ECDSA/ECNR, and
  implementation bugs in EdDSA, Schnorr (Bip340), or MuSig2 (Bip327);
- the post-quantum implementations (ML-KEM, ML-DSA, SLH-DSA) — spec non-conformance, a verification
  or decapsulation bypass, or a side channel on secret data;
- KDFs and password hashing (HKDF, KDF1/KDF2, Argon2, Scrypt, PBKDF2) — parameters not applied
  correctly, silently weakening the derived key;
- MACs (HMAC, CMAC, KMAC, GMac, Poly1305, SipHash) — non-constant-time verification or other timing
  side-channels;
- the ASN.1 parser, X.509 certificate generation/parsing, and PEM reader/writer — memory-safety bugs
  (out-of-bounds read/write on malformed input), a certificate signature that verifies when it
  shouldn't, or unbounded resource use on malformed/adversarial input;
- the system RNG wrappers — predictable or weak output, or incorrect seeding;
- secret material (keys, RNG state, intermediate values) not cleared from memory where the API
  documents that it is.

**Out of scope / report elsewhere:**

- **Hash function primitive flaws** — this library depends on
  [HashLib4Pascal](https://github.com/Xor-el/HashLib4Pascal) for hash implementations; please report
  those there. A misuse of a correct hash by CryptoLib4Pascal (e.g. in an HMAC or KDF construction) is
  in scope here.
- **Base-encoding flaws** (Hex, Base64, etc.) — this library depends on
  [SimpleBaseLib4Pascal](https://github.com/Xor-el/SimpleBaseLib4Pascal) for those; please report
  issues there.
- The known cryptographic weaknesses of algorithms included for **legacy/compatibility** reasons
  (MD2/MD4/MD5, SHA-1, ECB mode, etc.) — offering them is documented and intentional. An
  implementation bug that makes one of them behave *incorrectly relative to its own spec* is still in
  scope.
- Full certificate **path validation / trust-store decisions** — this library generates and parses
  X.509 certificates but does not itself decide trust; that logic belongs in the consuming
  application (e.g. a TLS stack built on top of this library).
- General bugs, incorrect documentation, or feature requests with no security impact — please use the
  normal [issue tracker](https://github.com/Xor-el/CryptoLib4Pascal/issues) for those.
- Issues in third-party code that merely uses this library.
