<p align="center">
  <h1 align="center">CryptoLib4Pascal</h1>
  <p align="center">
    <strong>Comprehensive cryptographic library for modern Object Pascal</strong>
  </p>
  <p align="center">
    <a href="https://github.com/Xor-el/CryptoLib4Pascal/actions/workflows/make.yml"><img src="https://github.com/Xor-el/CryptoLib4Pascal/actions/workflows/make.yml/badge.svg" alt="Build Status"></a>
    <a href="https://github.com/Xor-el/CryptoLib4Pascal/blob/master/LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License: MIT"></a>
    <a href="https://www.embarcadero.com/products/delphi"><img src="https://img.shields.io/badge/Delphi-Syndey%2B-red.svg" alt="Delphi Syndey+"></a>
    <a href="https://www.freepascal.org/"><img src="https://img.shields.io/badge/FreePascal-3.2.4%2B-blue.svg" alt="FreePascal 3.2.4+"></a>
  </p>
</p>

---

**CryptoLib4Pascal** brings production-grade cryptography to Delphi and FreePascal. From AES-GCM and ChaCha20-Poly1305 to ECDSA, EdDSA, RSA, Argon2, and X.509 certificates -- everything you need to build secure applications in Object Pascal, released under the permissive [MIT License](LICENSE).

## Table of Contents

- [Features](#features)
- [Available Algorithms](#available-algorithms)
- [Getting Started](#getting-started)
- [Quick Examples](#quick-examples)
- [Supported Platforms](#supported-platforms)
- [Running Tests](#running-tests)
- [Dependencies](#dependencies)
- [Contributing](#contributing)
- [Acknowledgements](#acknowledgements)
- [Tip Jar](#tip-jar)
- [License](#license)

## Features

- **Symmetric encryption** -- AES, Rijndael, Blowfish, Speck, ChaCha, (X)Salsa20
- **Authenticated encryption (AEAD)** -- GCM, GCM-SIV, CCM, EAX, OCB, ChaCha20-Poly1305
- **Asymmetric cryptography** -- RSA, DSA, ECDSA, EdDSA (Ed25519, Ed448), ECNR, Schnorr (Bip340), MuSig2 (Bip327)
- **Key exchange** -- DH, ECDH, X25519, X448
- **Hashing** -- SHA-2, SHA-3, Blake2, Keccak, RIPEMD, and more
- **Password hashing** -- Argon2 (2i/2d/2id), Scrypt, PBKDF2
- **MACs** -- HMAC, CMAC, KMAC, GMac, Poly1305, SipHash
- **X.509 certificates** -- generation and parsing
- **PEM encoding** -- OpenSSL-compatible import/export
- **Cross-platform** -- Windows, Linux, macOS, iOS, Android, Solaris, and BSDs

## Available Algorithms

<details>
<summary><strong>Symmetric Encryption</strong></summary>

#### Block Ciphers
`AES (128, 192, 256)` | `Rijndael` | `Blowfish` | `Speck`

#### Stream Ciphers
`ChaCha` | `(X)Salsa20`

</details>

<details>
<summary><strong>AEAD Ciphers</strong></summary>

`AES-GCM` | `AES-GCM-SIV` | `AES-CCM` | `AES-EAX` | `AES-OCB` | `ChaCha20-Poly1305`

</details>

<details>
<summary><strong>Block Cipher Modes</strong></summary>

`ECB` | `CBC` | `CFB` | `CTR` | `CTS` | `OFB` | `SIC`

</details>

<details>
<summary><strong>Block Cipher Padding Schemes</strong></summary>

`PKCS#5` | `PKCS#7` | `ISO 10126-2` | `ISO 7816-4` | `ISO/IEC 9797-1 (Bit)` | `ANSI X9.23` | `TBC` | `Zero`

</details>

<details>
<summary><strong>Asymmetric Cryptography</strong></summary>

- **RSA** -- PKCS#1, OAEP, PSS, ISO 9796
- **DSA** / **Deterministic DSA**
- **ECDSA** -- NIST, X9.62, SEC2, Brainpool curves
- **ECNR**
- **EdDSA** -- Ed25519, Ed448
- **Schnorr** -- Bip340
- **MuSig2** -- Bip327

</details>

<details>
<summary><strong>Key Agreement / Exchange</strong></summary>

`DH` | `ECDH` | `ECDHC` | `X25519` | `X448`

</details>

<details>
<summary><strong>Key Derivation Functions</strong></summary>

`HKDF` | `KDF1` | `KDF2`

#### Password Hashing
`Argon2 (2i, 2d, 2id)` | `Scrypt` | `PBKDF2`

</details>

<details>
<summary><strong>MACs</strong></summary>

`HMAC (all supported hashes)` | `CMAC` | `KMAC (128, 256)` | `GMac` | `Poly1305` | `SipHash`

</details>

<details>
<summary><strong>Hash Functions</strong></summary>

| Family | Variants |
|---|---|
| MD | MD2, MD4, MD5 |
| SHA-1 | SHA-1 |
| SHA-2 | 224, 256, 384, 512, 512-224, 512-256 |
| SHA-3 | 224, 256, 384, 512 |
| Keccak | 224, 256, 288, 384, 512 |
| Blake2B | 160, 256, 384, 512 |
| Blake2S | 128, 160, 224, 256 |
| RIPEMD | 128, 160, 256, 320 |
| GOST | 3411, 3411-2012 (256, 512) |
| Others | Tiger, WhirlPool |

</details>

<details>
<summary><strong>XOF (Extendable Output Functions)</strong></summary>

`Shake-128` | `Shake-256`

</details>

<details>
<summary><strong>Utilities</strong></summary>

- System RNG wrappers
- ASN.1 parsing
- Base encoding/decoding (Hex, Base64, etc.)
- X.509 certificate generation and parsing
- OpenSSL-compatible PEM reader/writer

</details>

## Getting Started

### Prerequisites

| Compiler | Minimum Version |
|---|---|
| Delphi | Sydney (10.4) or later |
| FreePascal | 3.2.4 or later |

### Installation

**1. Clone the repository:**

```bash
git clone https://github.com/Xor-el/CryptoLib4Pascal.git
```

**2a. Delphi**

- Open and install the package: `CryptoLib/src/Packages/Delphi/CryptoLib4PascalPackage.dpk`
- Also install the required dependency packages: [HashLib4Pascal](https://github.com/Xor-el/HashLib4Pascal) and [SimpleBaseLib4Pascal](https://github.com/Xor-el/SimpleBaseLib4Pascal)
- Add the `CryptoLib/src` subdirectories to your project's search path

**2b. FreePascal / Lazarus**

- Open and install the package: `CryptoLib/src/Packages/FPC/CryptoLib4PascalPackage.lpk`
- Also install the required dependency packages: [HashLib4Pascal](https://github.com/Xor-el/HashLib4Pascal) and [SimpleBaseLib4Pascal](https://github.com/Xor-el/SimpleBaseLib4Pascal)

## Quick Examples

### AES-CBC Encrypt / Decrypt

```pascal
uses
  ClpIBufferedCipher, ClpCipherUtilities, ClpParameterUtilities,
  ClpParametersWithIV, ClpConverters, ClpSecureRandom, ClpISecureRandom,
  ClpICipherParameters;

var
  LCipher: IBufferedCipher;
  LRandom: ISecureRandom;
  LKey, LIV, LPlain, LCipherText, LDecrypted: TBytes;
  LParams: ICipherParameters;
begin
  LRandom := TSecureRandom.Create();

  // Generate a random 256-bit key and 128-bit IV
  SetLength(LKey, 32);
  SetLength(LIV, 16);
  LRandom.NextBytes(LKey);
  LRandom.NextBytes(LIV);

  LParams := TParametersWithIV.Create(
    TParameterUtilities.CreateKeyParameter('AES', LKey), LIV);

  LPlain := TConverters.ConvertStringToBytes('Secret message', TEncoding.UTF8);

  // Encrypt
  LCipher := TCipherUtilities.GetCipher('AES/CBC/PKCS7PADDING');
  LCipher.Init(True, LParams);
  LCipherText := LCipher.DoFinal(LPlain);

  // Decrypt
  LCipher.Init(False, LParams);
  LDecrypted := LCipher.DoFinal(LCipherText);
end;
```

### SHA-256 Hashing

```pascal
uses
  ClpIDigest, ClpDigestUtilities, ClpConverters, ClpEncoders;

var
  LDigest: IDigest;
  LInput, LHash: TBytes;
begin
  LInput := TConverters.ConvertStringToBytes('Hello CryptoLib', TEncoding.UTF8);

  LDigest := TDigestUtilities.GetDigest('SHA-256');
  SetLength(LHash, LDigest.GetDigestSize);
  LDigest.BlockUpdate(LInput, 0, Length(LInput));
  LDigest.DoFinal(LHash, 0);

  WriteLn('SHA-256: ', THexEncoder.Encode(LHash, False));
end;
```

### ECDSA Sign / Verify

```pascal
uses
  ClpECUtilities, ClpIX9ECParametersHolder, ClpECParameters, ClpIECParameters,
  ClpSignerUtilities, ClpISigner, ClpConverters, ClpGeneratorUtilities,
  ClpSecureRandom, ClpISecureRandom, ClpECGenerators, ClpIECGenerators,
  ClpIAsymmetricCipherKeyPair, ClpIAsymmetricCipherKeyPairGenerator;

var
  LCurve: IX9ECParameters;
  LDomain: IECDomainParameters;
  LKpg: IAsymmetricCipherKeyPairGenerator;
  LKp: IAsymmetricCipherKeyPair;
  LSigner: ISigner;
  LMsg, LSig: TBytes;
begin
  // Set up the secp256k1 curve
  LCurve := TECUtilities.FindECCurveByName('secp256k1');
  LDomain := TECDomainParameters.Create(LCurve.Curve, LCurve.G,
    LCurve.N, LCurve.H, LCurve.GetSeed);

  // Generate a key pair
  LKpg := TGeneratorUtilities.GetKeyPairGenerator('ECDSA');
  LKpg.Init(TECKeyGenerationParameters.Create(LDomain,
    TSecureRandom.Create() as ISecureRandom));
  LKp := LKpg.GenerateKeyPair();

  LMsg := TConverters.ConvertStringToBytes('Sign me', TEncoding.UTF8);

  // Sign
  LSigner := TSignerUtilities.GetSigner('SHA-256withECDSA');
  LSigner.Init(True, LKp.Private);
  LSigner.BlockUpdate(LMsg, 0, Length(LMsg));
  LSig := LSigner.GenerateSignature();

  // Verify
  LSigner.Init(False, LKp.Public);
  LSigner.BlockUpdate(LMsg, 0, Length(LMsg));
  Assert(LSigner.VerifySignature(LSig));
end;
```

More examples (RSA, certificates, password hashing, etc.) are available in the [`CryptoLib.Examples`](CryptoLib.Examples/src/Examples/) directory.

## Supported Platforms

| OS | Delphi | FreePascal |
|---|:---:|:---:|
| Windows (XP and later) | ✅ | ✅ |
| Linux | ❓ | ✅ |
| macOS | ❓ | ❓ |
| Oracle Solaris | ➖ | ❓ |
| BSD | ➖ | ❓ |
| Android | ❓ | ❓ |
| iOS 2.0+ | ❓ | ❓ |

> ✅ Tested and passing · ❓ Untested · ➖ Not applicable

**Architectures:** x86, x86_64, ARM32, AArch64

## Running Tests

Tests use **DUnit** (Delphi) and **FPCUnit** (FreePascal).

**Delphi:** Open `CryptoLib.Tests/Delphi.Tests/CryptoLib.Tests.dpr` in the IDE and run.

**FreePascal / Lazarus:** Open `CryptoLib.Tests/FreePascal.Tests/CryptoLib.Tests.lpi` in the IDE and run.

## Dependencies

CryptoLib4Pascal requires two companion libraries that must be installed separately:

| Dependency | Purpose |
|---|---|
| [HashLib4Pascal](https://github.com/Xor-el/HashLib4Pascal) | Hash function implementations |
| [SimpleBaseLib4Pascal](https://github.com/Xor-el/SimpleBaseLib4Pascal) | Base encoding/decoding |

## Contributing

Contributions are welcome. Please open an [issue](https://github.com/Xor-el/CryptoLib4Pascal/issues) for bug reports or feature requests, and submit pull requests.

## Acknowledgements

- Thanks to [Sphere 10 Software](http://www.sphere10.com/) for sponsoring the development of this library.

## Tip Jar

If you find this library useful and would like to support its continued development, tips are greatly appreciated! 🙏

| Cryptocurrency | Wallet Address |
|---|---|
| <img src="https://raw.githubusercontent.com/spothq/cryptocurrency-icons/master/32/icon/btc.png" width="20" alt="Bitcoin" /> **Bitcoin (BTC)** | `bc1quqhe342vw4ml909g334w9ygade64szqupqulmu` |
| <img src="https://raw.githubusercontent.com/spothq/cryptocurrency-icons/master/32/icon/eth.png" width="20" alt="Ethereum" /> **Ethereum (ETH)** | `0x53651185b7467c27facab542da5868bfebe2bb69` |
| <img src="https://raw.githubusercontent.com/spothq/cryptocurrency-icons/master/32/icon/sol.png" width="20" alt="Solana" /> **Solana (SOL)** | `BPZHjY1eYCdQjLecumvrTJRi5TXj3Yz1vAWcmyEB9Miu` |

## License

CryptoLib4Pascal is released under the [MIT License](LICENSE).
