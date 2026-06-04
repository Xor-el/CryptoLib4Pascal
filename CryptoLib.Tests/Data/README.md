# CryptoLib Test Data

External test vectors for CryptoLib4Pascal unit tests.

## Layout

Vectors are grouped under `Crypto/`, `Cert/`, `Pkcs/`, and `OpenSsl/` using PascalCase folder and file names.

## Formats

| Path | Spec / format |
|------|----------------|
| `Crypto/Aes/NistSp80038a.csv` | NIST SP 800-38A: `Mode,Key,IV,Input,Output` |
| `Crypto/Speck/Speck.csv` | Speck: `Mode,Key,IV,Input,Output` |
| `Crypto/Scrypt/TestVectors.csv` | RFC 7914: `Enabled,Password,Salt,Cost,BlockSize,Parallelism,OutputLenBytes,ExpectedHex` |
| `Crypto/Digest/AbcVectors.csv` | Digest ABC: `Algorithm,Digest` |
| `Crypto/Bip340/TestVectors.csv` | BIP-340 test vector CSV |
| `Crypto/Rsa/RsaEngine.csv` | RSA engine smoke CRT key: `KeyId,Modulus,PubExp,PrivExp,P,Q,DP,DQ,QInv` |
| `Crypto/Rsa/Oaep/KeySets.csv` | OAEP key sets: `KeySetId,KeyType,Modulus,...,PubDerFile,PrivDerFile` |
| `Crypto/Rsa/Oaep/Manifest.csv` | OAEP vectors: `VectorId,KeySetId,VectorNo,SeedHex,SeedSource,InputHex,OutputHex,OaepDigest,OaepMgf` |
| `Crypto/Rsa/Oaep/Keys/*.der` | ASN.1 DER public/private keys referenced by KeySets |
| `Crypto/Rsa/Pss/Manifest.csv` | RFC 3447 PSS examples: CRT columns + `MsgHex,SaltHex,SigHex` |
| `Crypto/Rsa/Iso9796.csv` | ISO 9796-1: `TestId,ModulusHex,...` |
| `Crypto/Dsa/Fips1863Sha3.csv` | FIPS 186-3 SHA-3 DSA sign/verify: `DigestSize,P,Q,G,X,Y,KBigInt,KPadHex,MessageHex,ExpectedR,ExpectedS` |
| `Crypto/Dsa/Fips1862Golden.json` | FIPS 186-2 appendix golden cases: `{"cases":[{testId,paramGen,keyGen,sign},...]}` |
| `Crypto/Dsa/TestDsa512Gen.json` | TestDSA 512-bit param-gen block |
| `Crypto/Dsa/Dsa2Parameters.json` | TestDsa2Parameters golden path |
| `Crypto/Dsa/ParametersSmoke.json` | TestParameters fixed random chunks |
| `Crypto/Ecdsa/Curves.json` | X9.62 239-bit curves: `{"curves":[{curveId,curveType,...}]}` |
| `Crypto/Ecdsa/Vectors.json` | ECDSA/NONEwithECDSA vectors: `{"vectors":[{vectorId,curveId,algorithm,...}]}` |

## Resolution

Tests locate this folder by walking up from the test executable and the current
working directory for `CryptoLib.Tests/Data`.
