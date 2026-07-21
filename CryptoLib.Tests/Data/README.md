# CryptoLib Test Data

External test vectors for CryptoLib4Pascal unit tests.

Cryptographic test corpora — especially post-quantum known-answer files, ACVP
vectors, and large certificate or PKCS fixtures — are kept here as data files
rather than embedded in Pascal source. Vector sets have grown substantially with
PQC and will continue to as more algorithms and standards land; keeping them
outside the codebase keeps the library and test sources readable, avoids bloating
builds with megabytes of string literals, and lets fixtures be updated or extended
without recompiling test code.

This folder holds the files the test suite loads at runtime (NIST `.rsp` and
`.txt` corpora, CSV manifests, JSON vectors, PEM/DER samples, and related
fixtures). Layout and formats are documented below.

## Layout

All folders and files prefer **PascalCase** names where possible.

```
Data/
├── Crypto/     Algorithm vectors (CSV, JSON, RSP, TXT)
├── Cert/       X.509 certificates, CRLs, PKCS#7, delta certs, PQC credentials
├── Pkcs/       PKCS#12 stores and EncryptedPrivateKeyInfo DER keys
├── Pem/        PEM reader fixtures
└── OpenSsl/    OpenSSL-style encrypted PEM private keys
```

### `Crypto/` subfolders

| Folder | Contents |
|--------|----------|
| `Aes`, `Speck`, `ChaCha`, `Gcm`, `GcmSiv` | Block/stream cipher and AEAD vectors |
| `Scrypt`, `Argon2` | Password-based KDF vectors |
| `Digest`, `Hmac`, `Poly1305` | Digest and MAC vectors |
| `Ed25519`, `Ed448` | RFC 8032 regression vectors |
| `Bip340`, `Bip327` | BIP-340 Schnorr and BIP-327 MuSig2 vectors |
| `Rsa`, `Dsa`, `Ecdsa` | Asymmetric algorithm vectors |
| `Drbg/` | SP 800-90A DRBG vectors (Hash, HMAC, CTR-AES) |
| `Pqc/` | Post-quantum vectors (`MlKem`, `MlDsa`, `SlhDsa`) |

### Other roots

| Root | Typical subfolders |
|------|-------------------|
| `Cert/` | `Chains/`, `Crl/`, `Delta/`, `Extensions/`, `Legacy/`, `Ocsp/`, `Pkcs7/`, `Pkits/`, `Pkix/`, `Pqc/` |
| `Pkcs/` | `Pkcs12Store/Stores/`, `EncryptedPrivateKeyInfo/Keys/` |
| `Pem/` | `Reader/` |
| `OpenSsl/` | `Reader/Keys/` |

## Catalog manifests

Several test areas iterate a `Manifest.csv` index. The `File` column holds paths
**relative to `Data/`** (for example `Cert/Chains/Connect4Server.pem`, not
`Data/Cert/...`).

| Manifest | Columns (summary) | Used by (examples) |
|----------|-------------------|-------------------|
| `Cert/Manifest.csv` | `CertId`, `File`, `Encoding`, `Category`, … | `CertTests`, `CertificateTests`, `DeltaCertificateTests`, `PqcCertCredentialsTests`, `PkixFoundationTests`, `CertPathTests`, `CertPathValidatorTests`, `OcspTests` |
| `Pkcs/Pkcs12Store/Manifest.csv` | `FixtureId`, `File`, `Password`, `Description` | `Pkcs12StoreTests` |
| `Pkcs/EncryptedPrivateKeyInfo/Manifest.csv` | `VectorId`, `File`, `Password`, `AlgorithmLabel` | `PkcsEncryptedPrivateKeyInfoTests` |
| `Pem/Reader/Manifest.csv` | `VectorId`, `File`, `Notes` | `PemReaderTests` |
| `OpenSsl/Reader/Manifest.csv` | `VectorId`, `File`, `Password`, `KeyKind`, `Notes` | `OpenSslReaderTests` |
| `Crypto/Rsa/Oaep/Manifest.csv` | `VectorId`, `KeySetId`, `VectorNo`, `SeedHex`, `SeedSource`, `InputHex`, `OutputHex`, `OaepDigest`, `OaepMgf` | `OaepTests` (with `KeySets.csv`) |
| `Crypto/Rsa/Pss/Manifest.csv` | `ExampleId`, CRT key columns, `MsgHex`, `SaltHex`, `SigHex` | `PssTests` |

### NIST PKITS (`Cert/Pkits/`)

The NIST Public Key Interoperability Test Suite corpus is **not** manifest-indexed. It is loaded by
path convention from `Cert/Pkits/Certs/<name>.crt` and `Cert/Pkits/Crls/<name>.crl`, where `<name>`
is the PKITS object name with spaces and hyphens removed (`PkitsVectors`).

The corpus is a fixed external conformance set published by NIST
(<https://csrc.nist.gov/projects/pki-testing>, "Public Key Interoperability Test Suite (PKITS)
Certification Path Validation"): 405 certificates under `Certs/` and 173 CRLs under `Crls/`, all
DER-encoded, exercising RFC 5280 path validation. The file set is defined upstream and is not edited
here — hence the path convention rather than a hand-maintained index, which cannot drift from the
folder. Source and edition are recorded in `Cert/Pkits/README`.

## Vector formats

### Symmetric ciphers and AEAD

| Path | Format |
|------|--------|
| `Crypto/Aes/NistSp80038a.csv` | NIST SP 800-38A: `Mode,Key,IV,Input,Output` |
| `Crypto/Speck/Speck.csv` | Speck: `Mode,Key,IV,Input,Output` |
| `Crypto/ChaCha/EstreamKeystream.csv` | ChaCha20-Poly1305 RFC 7539 keystream |
| `Crypto/ChaCha/Rfc7539Poly1305.csv` | RFC 7539 AEAD |
| `Crypto/ChaCha/XChaCha20.csv` | XChaCha20 |
| `Crypto/ChaCha/XChaCha20Poly1305.csv` | XChaCha20-Poly1305 AEAD |
| `Crypto/Gcm/NistGmac.csv` | NIST GMAC vectors |
| `Crypto/Gcm/McGrewViega.csv` | McGrew–Viega GCM vectors |
| `Crypto/GcmSiv/Rfc8452.csv` | RFC 8452 GCM-SIV vectors |

### KDF, digest, and MAC

| Path | Format |
|------|--------|
| `Crypto/Scrypt/TestVectors.csv` | RFC 7914: `Enabled,Password,Salt,Cost,BlockSize,Parallelism,OutputLenBytes,ExpectedHex` |
| `Crypto/Argon2/TestVectors.csv` | Argon2 test vectors |
| `Crypto/Digest/AbcVectors.csv` | Digest ABC: `Algorithm,Digest` |
| `Crypto/Hmac/Rfc2202.csv` | RFC 2202 HMAC vectors |
| `Crypto/Hmac/CrossAlgorithm.csv` | Cross-algorithm HMAC smoke vectors |
| `Crypto/Poly1305/Rfc7539.csv` | RFC 7539 Poly1305 |
| `Crypto/Poly1305/NaCl.csv` | NaCl Poly1305 vectors |

### EdDSA regression

| Path | Format |
|------|--------|
| `Crypto/Ed25519/Regression.csv` | `PubB64,PrivB64,MsgB64,SigB64,Comment` |
| `Crypto/Ed448/Regression.csv` | `PubB64,PrivB64,MsgB64,SigB64,Comment` |

### Asymmetric (classical)

| Path | Format |
|------|--------|
| `Crypto/Bip340/TestVectors.csv` | BIP-340 Schnorr test vector CSV |
| `Crypto/Bip327/*.json` | BIP-327 MuSig2 vector sets (`KeyAggVectors.json`, `SignVerifyVectors.json`, …) |
| `Crypto/Rsa/Iso9796.csv` | ISO 9796-1: `TestId,ModulusHex,PubExpHex,PriExpHex,MessageHex,SignatureHex,…` |
| `Crypto/Rsa/Oaep/KeySets.csv` | OAEP key sets: `KeySetId,KeyType,Modulus,…,PubDerHex,PrivDerHex` |
| `Crypto/Rsa/Oaep/Manifest.csv` | OAEP encrypt/decrypt vectors (see manifest table above) |
| `Crypto/Rsa/Pss/Manifest.csv` | RFC 3447 PSS examples (see manifest table above) |
| `Crypto/Dsa/Fips1863Sha3.csv` | FIPS 186-3 SHA-3 DSA: `DigestSize,P,Q,G,X,Y,KBigInt,KPadHex,MessageHex,ExpectedR,ExpectedS` |
| `Crypto/Dsa/Fips1862Golden.json` | FIPS 186-2 appendix golden cases: `{"cases":[{testId,paramGen,keyGen,sign},…]}` |
| `Crypto/Ecdsa/Curves.json` | X9.62 curves: `{"curves":[{curveId,curveType,…}]}` |
| `Crypto/Ecdsa/Vectors.json` | ECDSA vectors: `{"vectors":[{vectorId,curveId,algorithm,…}]}` |

### SP 800-90A DRBG (`Crypto/Drbg/`)

| Path | Format |
|------|--------|
| `Crypto/Drbg/EntropyProviders.json` | Deterministic entropy streams: `{"providers":[{id,predictionResistant,hex},…]}` |
| `Crypto/Drbg/HashDrbgVectors.json` | Hash_DRBG KAT: `{"vectors":[{id,digest,entropyProvider,entropyBits,predictionResistant,nonceHex,securityStrength,personalizationHex,additionalInputsHex,expectedHex},…]}` |
| `Crypto/Drbg/HMacDrbgVectors.json` | HMAC_DRBG KAT: `{"vectors":[{id,mac,digest,entropyProvider,…,expectedHex},…]}` |
| `Crypto/Drbg/CtrDrbgAesVectors.json` | CTR_DRBG (AES) KAT: `{"vectors":[{id,cipher,keySizeBits,entropyProvider,…,expectedHex},…]}` |

### Post-quantum (`Crypto/Pqc/`)

Vectors are grouped by algorithm. File naming follows NIST / ACVP conventions rather
than a single shared CSV schema.

**MlKem** (`Crypto/Pqc/MlKem/`)

- `*.rsp` — NIST `.rsp` keyGen / encapDecap vectors (`mlkem512.rsp`, …)
- `ML-KEM-*.txt` — consolidated NIST text corpora
- `Acvp/*.txt` — ACVP keyGen and encapDecap vectors per parameter set
- `Keys/*.hex` — hex-encoded key material for edge-case tests
- `Modulus/ML-KEM-*.txt` — modulus sanity vectors

**MlDsa** (`Crypto/Pqc/MlDsa/`)

- `*.rsp` — NIST `.rsp` vectors per parameter set
- `ML-DSA-*.txt` — consolidated NIST text corpora
- `Acvp/*.txt` — ACVP keyGen and signature vectors
- `Kat/*.txt` — known-answer tests (including context and hash variants)

**SlhDsa** (`Crypto/Pqc/SlhDsa/`)

- `*.rsp` — NIST `.rsp` vectors per parameter set and hash profile
- `SLH-DSA-*.txt` — consolidated NIST text corpora
- `Acvp/*.txt` — ACVP keyGen and signature vectors
- `Kat/*.txt` — known-answer tests (including context and hash variants)
