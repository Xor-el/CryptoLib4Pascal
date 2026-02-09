{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                Copyright (c) 2018 - 20XX Ugochukwu Mmaduekwe                    * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }

{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }

{ *                              Acknowledgements:                                  * }
{ *                                                                                 * }
{ *      Thanks to Sphere 10 Software (http://www.sphere10.com/) for sponsoring     * }
{ *                           development of this library                           * }

{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit ClpPkcsObjectIdentifiers;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpAsn1Objects,
  ClpIAsn1Objects;

type
  TPkcsObjectIdentifiers = class abstract(TObject)

  strict private

  const
    //
    // pkcs-1 OBJECT IDENTIFIER ::= {
    //       iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) 1 }
    //
    Pkcs1: String = '1.2.840.113549.1.1';

    //
    // pkcs-3 OBJECT IDENTIFIER ::= {
    // iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) 3 }
    //
    Pkcs3: String = '1.2.840.113549.1.3';

    //
    // pkcs-5 OBJECT IDENTIFIER ::= {
    // iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) 5 }
    //
    Pkcs5: String = '1.2.840.113549.1.5';

    //
    // object identifiers for digests
    //
    DigestAlgorithm: String = '1.2.840.113549.2';

    //
    // pkcs-7 OBJECT IDENTIFIER ::= {
    //       iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) 7 }
    //
    Pkcs7: String = '1.2.840.113549.1.7';

    //
    // pkcs-9 OBJECT IDENTIFIER ::= {
    //       iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) 9 }
    //
    Pkcs9: String = '1.2.840.113549.1.9';

    //
    // encryptionAlgorithm OBJECT IDENTIFIER ::= {
    //       iso(1) member-body(2) us(840) rsadsi(113549) 3 }
    //
    EncryptionAlgorithm: String = '1.2.840.113549.3';

    //
    // pkcs-12 OBJECT IDENTIFIER ::= {
    //       iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) 12 }
    //
    Pkcs12: String = '1.2.840.113549.1.12';
    BagTypes: String = '1.2.840.113549.1.12.10.1';
    Pkcs12PbeIds: String = '1.2.840.113549.1.12.1';

    //
    // id-ct OBJECT IDENTIFIER ::= {iso(1) member-body(2) usa(840) rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) ct(1)}
    //
    IdCT: String = '1.2.840.113549.1.9.16.1';
    //
    // id-cti OBJECT IDENTIFIER ::= {iso(1) member-body(2) usa(840) rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) cti(6)}
    //
    IdCti: String = '1.2.840.113549.1.9.16.6';
    //
    // id-aa OBJECT IDENTIFIER ::= {iso(1) member-body(2) usa(840) rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) attributes(2)}
    //
    IdAA: String = '1.2.840.113549.1.9.16.2';
    //
    // id-spq OBJECT IDENTIFIER ::= {iso(1) member-body(2) usa(840) rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) id-spq(5)}
    //
    IdSpq: String = '1.2.840.113549.1.9.16.5';

    CertTypes: String = '1.2.840.113549.1.9.22';
    CrlTypes: String = '1.2.840.113549.1.9.23';

  class var

    FIsBooted: Boolean;

    // PKCS#1 RSA OIDs
    FRsaEncryption,
    FMD2WithRsaEncryption,
    FMD4WithRsaEncryption,
    FMD5WithRsaEncryption,
    FSha1WithRsaEncryption,
    FSrsaOaepEncryptionSet,
    FIdRsaesOaep,
    FIdMgf1,
    FIdPSpecified,
    FIdRsassaPss,
    FSha256WithRsaEncryption,
    FSha384WithRsaEncryption,
    FSha512WithRsaEncryption,
    FSha224WithRsaEncryption,
    FSha512_224WithRsaEncryption,
    FSha512_256WithRsaEncryption,

    // PKCS#3
    FDhKeyAgreement,

    // PKCS#5
    FIdPbkdf2,
    FPbeWithMD2AndDesCbc, FPbeWithMD2AndRC2Cbc, FPbeWithMD5AndDesCbc, FPbeWithMD5AndRC2Cbc,
    FPbeWithSha1AndDesCbc, FPbeWithSha1AndRC2Cbc,
    FIdPbeS2, FIdPbmac1,

    // EncryptionAlgorithm (rsadsi 3)
    FDesEde3Cbc, FRC2Cbc, Frc4,

    // PKCS#7
    FData, FSignedData, FEnvelopedData, FSignedAndEnvelopedData, FDigestedData, FEncryptedData,

    // Digest algorithms
    FMD2, FMD4, FMD5,
    FIdHmacWithSha1, FIdHmacWithSha224, FIdHmacWithSha256,
    FIdHmacWithSha384, FIdHmacWithSha512,
    FIdHmacWithSha512_224, FIdHmacWithSha512_256,

    // PKCS#9
    FPkcs9AtEmailAddress,
    FPkcs9AtChallengePassword,
    FPkcs9AtUnstructuredName,
    FPkcs9AtUnstructuredAddress,
    FPkcs9AtExtensionRequest,
    FPkcs9AtContentType, FPkcs9AtMessageDigest, FPkcs9AtSigningTime, FPkcs9AtCounterSignature,
    FPkcs9AtExtendedCertificateAttributes, FPkcs9AtSigningDescription, FPkcs9AtSmimeCapabilities,
    FIdSmime,
    FPkcs9AtFriendlyName, FPkcs9AtLocalKeyID,
    FX509Certificate, FSdsiCertificate,
    FX509Crl,
    FSmimeAlg, FIdAlg,
    FIdAlgEsdh, FIdAlgCms3DesWrap, FIdAlgCmsRC2Wrap, FIdAlgZlibCompress, FIdAlgPwriKek, FIdAlgSsdh,
    FId_aa_cmsAlgorithmProtect,
    FIdRsaKem, FIdAlgHssLmsHashsig, FIdAlgAeadChaCha20Poly1305,
    FIdAlgHkdfWithSha256, FIdAlgHkdfWithSha384, FIdAlgHkdfWithSha512,
    FPreferSignedData, FCannotDecryptAny, FSmimeCapabilitiesVersions,
    FId_ct,
    FIdCTAuthData, FIdCTTstInfo, FIdCTCompressedData, FIdCTAuthEnvelopedData, FIdCTTimestampedData,
    FId_cti,
    FIdCtiEtsProofOfOrigin, FIdCtiEtsProofOfReceipt, FIdCtiEtsProofOfDelivery,
    FIdCtiEtsProofOfSender, FIdCtiEtsProofOfApproval, FIdCtiEtsProofOfCreation,
    FId_aa, FIdAAOid,
    FPkcs9AtBinarySigningTime,
    FIdAAReceiptRequest, FIdAAContentHint, FIdAAMsgSigDigest, FIdAAContentReference,
    FIdAAEncrypKeyPref, FIdAASigningCertificate, FIdAASigningCertificateV2, FIdAAContentIdentifier,
    FIdAASignatureTimeStampToken,
    FIdAAEtsSigPolicyID, FIdAAEtsCommitmentType, FIdAAEtsSignerLocation, FIdAAEtsSignerAttr,
    FIdAAEtsOtherSigCert, FIdAAEtsContentTimestamp, FIdAAEtsCertificateRefs, FIdAAEtsRevocationRefs,
    FIdAAEtsCertValues, FIdAAEtsRevocationValues, FIdAAEtsEscTimeStamp, FIdAAEtsCertCrlTimestamp,
    FIdAAEtsArchiveTimestamp,
    FIdAADecryptKeyID, FIdAAImplCryptoAlgs, FIdAAAsymmDecryptKeyID, FIdAAImplCompressAlgs, FIdAACommunityIdentifiers,
    FIdAAEtsArchiveTimestampV2,
    FId_spq,
    FIdSpqEtsUri, FIdSpqEtsUNotice,
    // PKCS#12
    FKeyBag, FPkcs8ShroudedKeyBag, FCertBag, FCrlBag, FSecretBag, FSafeContentsBag,
    FPbeWithShaAnd128BitRC4, FPbeWithShaAnd40BitRC4, FPbeWithShaAnd3KeyTripleDesCbc,
    FPbeWithShaAnd2KeyTripleDesCbc, FPbeWithShaAnd128BitRC2Cbc, FPbewithShaAnd40BitRC2Cbc
      : IDerObjectIdentifier;

    // PKCS#1 RSA getters
    class function GetRsaEncryption: IDerObjectIdentifier; static; inline;
    class function GetMD2WithRsaEncryption: IDerObjectIdentifier; static; inline;
    class function GetMD4WithRsaEncryption: IDerObjectIdentifier; static; inline;
    class function GetMD5WithRsaEncryption: IDerObjectIdentifier; static; inline;
    class function GetSha1WithRsaEncryption: IDerObjectIdentifier; static; inline;
    class function GetSrsaOaepEncryptionSet: IDerObjectIdentifier; static; inline;
    class function GetIdRsaesOaep: IDerObjectIdentifier; static; inline;
    class function GetIdMgf1: IDerObjectIdentifier; static; inline;
    class function GetIdPSpecified: IDerObjectIdentifier; static; inline;
    class function GetIdRsassaPss: IDerObjectIdentifier; static; inline;
    class function GetSha256WithRsaEncryption: IDerObjectIdentifier; static; inline;
    class function GetSha384WithRsaEncryption: IDerObjectIdentifier; static; inline;
    class function GetSha512WithRsaEncryption: IDerObjectIdentifier; static; inline;
    class function GetSha224WithRsaEncryption: IDerObjectIdentifier; static; inline;
    class function GetSha512_224WithRsaEncryption: IDerObjectIdentifier; static; inline;
    class function GetSha512_256WithRsaEncryption: IDerObjectIdentifier; static; inline;

    // PKCS#3
    class function GetDhKeyAgreement: IDerObjectIdentifier; static; inline;

    // PKCS#5
    class function GetIdPbkdf2: IDerObjectIdentifier; static; inline;
    class function GetPbeWithMD2AndDesCbc: IDerObjectIdentifier; static; inline;
    class function GetPbeWithMD2AndRC2Cbc: IDerObjectIdentifier; static; inline;
    class function GetPbeWithMD5AndDesCbc: IDerObjectIdentifier; static; inline;
    class function GetPbeWithMD5AndRC2Cbc: IDerObjectIdentifier; static; inline;
    class function GetPbeWithSha1AndDesCbc: IDerObjectIdentifier; static; inline;
    class function GetPbeWithSha1AndRC2Cbc: IDerObjectIdentifier; static; inline;
    class function GetIdPbeS2: IDerObjectIdentifier; static; inline;
    class function GetIdPbmac1: IDerObjectIdentifier; static; inline;

    // EncryptionAlgorithm
    class function GetDesEde3Cbc: IDerObjectIdentifier; static; inline;
    class function GetRC2Cbc: IDerObjectIdentifier; static; inline;
    class function GetRc4: IDerObjectIdentifier; static; inline;

    // PKCS#7 getters
    class function GetData: IDerObjectIdentifier; static; inline;
    class function GetSignedData: IDerObjectIdentifier; static; inline;
    class function GetEnvelopedData: IDerObjectIdentifier; static; inline;
    class function GetSignedAndEnvelopedData: IDerObjectIdentifier; static; inline;
    class function GetDigestedData: IDerObjectIdentifier; static; inline;
    class function GetEncryptedData: IDerObjectIdentifier; static; inline;

    // Digest algorithm getters
    class function GetMD2: IDerObjectIdentifier; static; inline;
    class function GetMD4: IDerObjectIdentifier; static; inline;
    class function GetMD5: IDerObjectIdentifier; static; inline;
    class function GetIdHmacWithSha1: IDerObjectIdentifier; static; inline;
    class function GetIdHmacWithSha224: IDerObjectIdentifier; static; inline;
    class function GetIdHmacWithSha256: IDerObjectIdentifier; static; inline;
    class function GetIdHmacWithSha384: IDerObjectIdentifier; static; inline;
    class function GetIdHmacWithSha512: IDerObjectIdentifier; static; inline;
    class function GetIdHmacWithSha512_224: IDerObjectIdentifier; static; inline;
    class function GetIdHmacWithSha512_256: IDerObjectIdentifier; static; inline;

    // PKCS#9 getters
    class function GetPkcs9AtEmailAddress: IDerObjectIdentifier; static; inline;
    class function GetPkcs9AtChallengePassword: IDerObjectIdentifier; static; inline;
    class function GetPkcs9AtUnstructuredName: IDerObjectIdentifier; static; inline;
    class function GetPkcs9AtUnstructuredAddress: IDerObjectIdentifier; static; inline;
    class function GetPkcs9AtExtensionRequest: IDerObjectIdentifier; static; inline;
    class function GetPkcs9AtContentType: IDerObjectIdentifier; static; inline;
    class function GetPkcs9AtMessageDigest: IDerObjectIdentifier; static; inline;
    class function GetPkcs9AtSigningTime: IDerObjectIdentifier; static; inline;
    class function GetPkcs9AtCounterSignature: IDerObjectIdentifier; static; inline;
    class function GetPkcs9AtExtendedCertificateAttributes: IDerObjectIdentifier; static; inline;
    class function GetPkcs9AtSigningDescription: IDerObjectIdentifier; static; inline;
    class function GetPkcs9AtSmimeCapabilities: IDerObjectIdentifier; static; inline;
    class function GetIdSmime: IDerObjectIdentifier; static; inline;
    class function GetPkcs9AtFriendlyName: IDerObjectIdentifier; static; inline;
    class function GetPkcs9AtLocalKeyID: IDerObjectIdentifier; static; inline;
    class function GetX509Certificate: IDerObjectIdentifier; static; inline;
    class function GetSdsiCertificate: IDerObjectIdentifier; static; inline;
    class function GetX509Crl: IDerObjectIdentifier; static; inline;
    class function GetSmimeAlg: IDerObjectIdentifier; static; inline;
    class function GetIdAlg: IDerObjectIdentifier; static; inline;
    class function GetIdAlgEsdh: IDerObjectIdentifier; static; inline;
    class function GetIdAlgCms3DesWrap: IDerObjectIdentifier; static; inline;
    class function GetIdAlgCmsRC2Wrap: IDerObjectIdentifier; static; inline;
    class function GetIdAlgZlibCompress: IDerObjectIdentifier; static; inline;
    class function GetIdAlgPwriKek: IDerObjectIdentifier; static; inline;
    class function GetIdAlgSsdh: IDerObjectIdentifier; static; inline;
    class function GetId_aa_cmsAlgorithmProtect: IDerObjectIdentifier; static; inline;
    class function GetIdRsaKem: IDerObjectIdentifier; static; inline;
    class function GetIdAlgHssLmsHashsig: IDerObjectIdentifier; static; inline;
    class function GetIdAlgAeadChaCha20Poly1305: IDerObjectIdentifier; static; inline;
    class function GetIdAlgHkdfWithSha256: IDerObjectIdentifier; static; inline;
    class function GetIdAlgHkdfWithSha384: IDerObjectIdentifier; static; inline;
    class function GetIdAlgHkdfWithSha512: IDerObjectIdentifier; static; inline;
    class function GetPreferSignedData: IDerObjectIdentifier; static; inline;
    class function GetCannotDecryptAny: IDerObjectIdentifier; static; inline;
    class function GetSmimeCapabilitiesVersions: IDerObjectIdentifier; static; inline;
    class function GetId_ct: IDerObjectIdentifier; static; inline;
    class function GetIdCTAuthData: IDerObjectIdentifier; static; inline;
    class function GetIdCTTstInfo: IDerObjectIdentifier; static; inline;
    class function GetIdCTCompressedData: IDerObjectIdentifier; static; inline;
    class function GetIdCTAuthEnvelopedData: IDerObjectIdentifier; static; inline;
    class function GetIdCTTimestampedData: IDerObjectIdentifier; static; inline;
    class function GetId_cti: IDerObjectIdentifier; static; inline;
    class function GetIdCtiEtsProofOfOrigin: IDerObjectIdentifier; static; inline;
    class function GetIdCtiEtsProofOfReceipt: IDerObjectIdentifier; static; inline;
    class function GetIdCtiEtsProofOfDelivery: IDerObjectIdentifier; static; inline;
    class function GetIdCtiEtsProofOfSender: IDerObjectIdentifier; static; inline;
    class function GetIdCtiEtsProofOfApproval: IDerObjectIdentifier; static; inline;
    class function GetIdCtiEtsProofOfCreation: IDerObjectIdentifier; static; inline;
    class function GetId_aa: IDerObjectIdentifier; static; inline;
    class function GetIdAAOid: IDerObjectIdentifier; static; inline;
    class function GetPkcs9AtBinarySigningTime: IDerObjectIdentifier; static; inline;
    class function GetIdAAReceiptRequest: IDerObjectIdentifier; static; inline;
    class function GetIdAAContentHint: IDerObjectIdentifier; static; inline;
    class function GetIdAAMsgSigDigest: IDerObjectIdentifier; static; inline;
    class function GetIdAAContentReference: IDerObjectIdentifier; static; inline;
    class function GetIdAAEncrypKeyPref: IDerObjectIdentifier; static; inline;
    class function GetIdAASigningCertificate: IDerObjectIdentifier; static; inline;
    class function GetIdAASigningCertificateV2: IDerObjectIdentifier; static; inline;
    class function GetIdAAContentIdentifier: IDerObjectIdentifier; static; inline;
    class function GetIdAASignatureTimeStampToken: IDerObjectIdentifier; static; inline;
    class function GetIdAAEtsSigPolicyID: IDerObjectIdentifier; static; inline;
    class function GetIdAAEtsCommitmentType: IDerObjectIdentifier; static; inline;
    class function GetIdAAEtsSignerLocation: IDerObjectIdentifier; static; inline;
    class function GetIdAAEtsSignerAttr: IDerObjectIdentifier; static; inline;
    class function GetIdAAEtsOtherSigCert: IDerObjectIdentifier; static; inline;
    class function GetIdAAEtsContentTimestamp: IDerObjectIdentifier; static; inline;
    class function GetIdAAEtsCertificateRefs: IDerObjectIdentifier; static; inline;
    class function GetIdAAEtsRevocationRefs: IDerObjectIdentifier; static; inline;
    class function GetIdAAEtsCertValues: IDerObjectIdentifier; static; inline;
    class function GetIdAAEtsRevocationValues: IDerObjectIdentifier; static; inline;
    class function GetIdAAEtsEscTimeStamp: IDerObjectIdentifier; static; inline;
    class function GetIdAAEtsCertCrlTimestamp: IDerObjectIdentifier; static; inline;
    class function GetIdAAEtsArchiveTimestamp: IDerObjectIdentifier; static; inline;
    class function GetIdAADecryptKeyID: IDerObjectIdentifier; static; inline;
    class function GetIdAAImplCryptoAlgs: IDerObjectIdentifier; static; inline;
    class function GetIdAAAsymmDecryptKeyID: IDerObjectIdentifier; static; inline;
    class function GetIdAAImplCompressAlgs: IDerObjectIdentifier; static; inline;
    class function GetIdAACommunityIdentifiers: IDerObjectIdentifier; static; inline;
    class function GetIdAAEtsArchiveTimestampV2: IDerObjectIdentifier; static; inline;
    class function GetId_spq: IDerObjectIdentifier; static; inline;
    class function GetIdSpqEtsUri: IDerObjectIdentifier; static; inline;
    class function GetIdSpqEtsUNotice: IDerObjectIdentifier; static; inline;
    // PKCS#12
    class function GetKeyBag: IDerObjectIdentifier; static; inline;
    class function GetPkcs8ShroudedKeyBag: IDerObjectIdentifier; static; inline;
    class function GetCertBag: IDerObjectIdentifier; static; inline;
    class function GetCrlBag: IDerObjectIdentifier; static; inline;
    class function GetSecretBag: IDerObjectIdentifier; static; inline;
    class function GetSafeContentsBag: IDerObjectIdentifier; static; inline;
    class function GetPbeWithShaAnd128BitRC4: IDerObjectIdentifier; static; inline;
    class function GetPbeWithShaAnd40BitRC4: IDerObjectIdentifier; static; inline;
    class function GetPbeWithShaAnd3KeyTripleDesCbc: IDerObjectIdentifier; static; inline;
    class function GetPbeWithShaAnd2KeyTripleDesCbc: IDerObjectIdentifier; static; inline;
    class function GetPbeWithShaAnd128BitRC2Cbc: IDerObjectIdentifier; static; inline;
    class function GetPbewithShaAnd40BitRC2Cbc: IDerObjectIdentifier; static; inline;

    class constructor PkcsObjectIdentifiers();

  public

    //
    // PKCS#1 RSA OIDs
    //
    class property RsaEncryption: IDerObjectIdentifier read GetRsaEncryption;
    class property MD2WithRsaEncryption: IDerObjectIdentifier read GetMD2WithRsaEncryption;
    class property MD4WithRsaEncryption: IDerObjectIdentifier read GetMD4WithRsaEncryption;
    class property MD5WithRsaEncryption: IDerObjectIdentifier read GetMD5WithRsaEncryption;
    class property Sha1WithRsaEncryption: IDerObjectIdentifier read GetSha1WithRsaEncryption;
    class property SrsaOaepEncryptionSet: IDerObjectIdentifier read GetSrsaOaepEncryptionSet;
    class property IdRsaesOaep: IDerObjectIdentifier read GetIdRsaesOaep;
    class property IdMgf1: IDerObjectIdentifier read GetIdMgf1;
    class property IdPSpecified: IDerObjectIdentifier read GetIdPSpecified;
    class property IdRsassaPss: IDerObjectIdentifier read GetIdRsassaPss;
    class property Sha256WithRsaEncryption: IDerObjectIdentifier read GetSha256WithRsaEncryption;
    class property Sha384WithRsaEncryption: IDerObjectIdentifier read GetSha384WithRsaEncryption;
    class property Sha512WithRsaEncryption: IDerObjectIdentifier read GetSha512WithRsaEncryption;
    class property Sha224WithRsaEncryption: IDerObjectIdentifier read GetSha224WithRsaEncryption;
    class property Sha512_224WithRsaEncryption: IDerObjectIdentifier read GetSha512_224WithRsaEncryption;
    class property Sha512_256WithRsaEncryption: IDerObjectIdentifier read GetSha512_256WithRsaEncryption;

    //
    // PKCS#3
    //
    class property DhKeyAgreement: IDerObjectIdentifier read GetDhKeyAgreement;

    //
    // PKCS#5
    //
    class property IdPbkdf2: IDerObjectIdentifier read GetIdPbkdf2;
    class property PbeWithMD2AndDesCbc: IDerObjectIdentifier read GetPbeWithMD2AndDesCbc;
    class property PbeWithMD2AndRC2Cbc: IDerObjectIdentifier read GetPbeWithMD2AndRC2Cbc;
    class property PbeWithMD5AndDesCbc: IDerObjectIdentifier read GetPbeWithMD5AndDesCbc;
    class property PbeWithMD5AndRC2Cbc: IDerObjectIdentifier read GetPbeWithMD5AndRC2Cbc;
    class property PbeWithSha1AndDesCbc: IDerObjectIdentifier read GetPbeWithSha1AndDesCbc;
    class property PbeWithSha1AndRC2Cbc: IDerObjectIdentifier read GetPbeWithSha1AndRC2Cbc;
    class property IdPbeS2: IDerObjectIdentifier read GetIdPbeS2;
    class property IdPbmac1: IDerObjectIdentifier read GetIdPbmac1;

    //
    // EncryptionAlgorithm
    //
    class property DesEde3Cbc: IDerObjectIdentifier read GetDesEde3Cbc;
    class property RC2Cbc: IDerObjectIdentifier read GetRC2Cbc;
    class property Rc4: IDerObjectIdentifier read GetRc4;

    //
    // PKCS#7
    //
    class property Data: IDerObjectIdentifier read GetData;
    class property SignedData: IDerObjectIdentifier read GetSignedData;
    class property EnvelopedData: IDerObjectIdentifier read GetEnvelopedData;
    class property SignedAndEnvelopedData: IDerObjectIdentifier read GetSignedAndEnvelopedData;
    class property DigestedData: IDerObjectIdentifier read GetDigestedData;
    class property EncryptedData: IDerObjectIdentifier read GetEncryptedData;

    //
    // Digest algorithms
    //
    class property MD2: IDerObjectIdentifier read GetMD2;
    class property MD4: IDerObjectIdentifier read GetMD4;
    class property MD5: IDerObjectIdentifier read GetMD5;

    class property IdHmacWithSha1: IDerObjectIdentifier read GetIdHmacWithSha1;
    class property IdHmacWithSha224: IDerObjectIdentifier read GetIdHmacWithSha224;
    class property IdHmacWithSha256: IDerObjectIdentifier read GetIdHmacWithSha256;
    class property IdHmacWithSha384: IDerObjectIdentifier read GetIdHmacWithSha384;
    class property IdHmacWithSha512: IDerObjectIdentifier read GetIdHmacWithSha512;
    class property IdHmacWithSha512_224: IDerObjectIdentifier read GetIdHmacWithSha512_224;
    class property IdHmacWithSha512_256: IDerObjectIdentifier read GetIdHmacWithSha512_256;

    //
    // PKCS#9
    //
    class property Pkcs9AtEmailAddress: IDerObjectIdentifier read GetPkcs9AtEmailAddress;
    class property Pkcs9AtChallengePassword: IDerObjectIdentifier read GetPkcs9AtChallengePassword;
    class property Pkcs9AtUnstructuredName: IDerObjectIdentifier read GetPkcs9AtUnstructuredName;
    class property Pkcs9AtUnstructuredAddress: IDerObjectIdentifier read GetPkcs9AtUnstructuredAddress;
    class property Pkcs9AtExtensionRequest: IDerObjectIdentifier read GetPkcs9AtExtensionRequest;
    class property Pkcs9AtContentType: IDerObjectIdentifier read GetPkcs9AtContentType;
    class property Pkcs9AtMessageDigest: IDerObjectIdentifier read GetPkcs9AtMessageDigest;
    class property Pkcs9AtSigningTime: IDerObjectIdentifier read GetPkcs9AtSigningTime;
    class property Pkcs9AtCounterSignature: IDerObjectIdentifier read GetPkcs9AtCounterSignature;
    class property Pkcs9AtExtendedCertificateAttributes: IDerObjectIdentifier read GetPkcs9AtExtendedCertificateAttributes;
    class property Pkcs9AtSigningDescription: IDerObjectIdentifier read GetPkcs9AtSigningDescription;
    class property Pkcs9AtSmimeCapabilities: IDerObjectIdentifier read GetPkcs9AtSmimeCapabilities;
    class property IdSmime: IDerObjectIdentifier read GetIdSmime;
    class property Pkcs9AtFriendlyName: IDerObjectIdentifier read GetPkcs9AtFriendlyName;
    class property Pkcs9AtLocalKeyID: IDerObjectIdentifier read GetPkcs9AtLocalKeyID;
    class property X509Certificate: IDerObjectIdentifier read GetX509Certificate;
    class property SdsiCertificate: IDerObjectIdentifier read GetSdsiCertificate;
    class property X509Crl: IDerObjectIdentifier read GetX509Crl;
    class property SmimeAlg: IDerObjectIdentifier read GetSmimeAlg;
    class property IdAlg: IDerObjectIdentifier read GetIdAlg;
    class property IdAlgEsdh: IDerObjectIdentifier read GetIdAlgEsdh;
    class property IdAlgCms3DesWrap: IDerObjectIdentifier read GetIdAlgCms3DesWrap;
    class property IdAlgCmsRC2Wrap: IDerObjectIdentifier read GetIdAlgCmsRC2Wrap;
    class property IdAlgZlibCompress: IDerObjectIdentifier read GetIdAlgZlibCompress;
    class property IdAlgPwriKek: IDerObjectIdentifier read GetIdAlgPwriKek;
    class property IdAlgSsdh: IDerObjectIdentifier read GetIdAlgSsdh;
    class property Id_aa_cmsAlgorithmProtect: IDerObjectIdentifier read GetId_aa_cmsAlgorithmProtect;
    class property IdRsaKem: IDerObjectIdentifier read GetIdRsaKem;
    class property IdAlgHssLmsHashsig: IDerObjectIdentifier read GetIdAlgHssLmsHashsig;
    class property IdAlgAeadChaCha20Poly1305: IDerObjectIdentifier read GetIdAlgAeadChaCha20Poly1305;
    class property IdAlgHkdfWithSha256: IDerObjectIdentifier read GetIdAlgHkdfWithSha256;
    class property IdAlgHkdfWithSha384: IDerObjectIdentifier read GetIdAlgHkdfWithSha384;
    class property IdAlgHkdfWithSha512: IDerObjectIdentifier read GetIdAlgHkdfWithSha512;
    class property PreferSignedData: IDerObjectIdentifier read GetPreferSignedData;
    class property CannotDecryptAny: IDerObjectIdentifier read GetCannotDecryptAny;
    class property SmimeCapabilitiesVersions: IDerObjectIdentifier read GetSmimeCapabilitiesVersions;
    class property Id_ct: IDerObjectIdentifier read GetId_ct;
    class property IdCTAuthData: IDerObjectIdentifier read GetIdCTAuthData;
    class property IdCTTstInfo: IDerObjectIdentifier read GetIdCTTstInfo;
    class property IdCTCompressedData: IDerObjectIdentifier read GetIdCTCompressedData;
    class property IdCTAuthEnvelopedData: IDerObjectIdentifier read GetIdCTAuthEnvelopedData;
    class property IdCTTimestampedData: IDerObjectIdentifier read GetIdCTTimestampedData;
    class property Id_cti: IDerObjectIdentifier read GetId_cti;
    class property IdCtiEtsProofOfOrigin: IDerObjectIdentifier read GetIdCtiEtsProofOfOrigin;
    class property IdCtiEtsProofOfReceipt: IDerObjectIdentifier read GetIdCtiEtsProofOfReceipt;
    class property IdCtiEtsProofOfDelivery: IDerObjectIdentifier read GetIdCtiEtsProofOfDelivery;
    class property IdCtiEtsProofOfSender: IDerObjectIdentifier read GetIdCtiEtsProofOfSender;
    class property IdCtiEtsProofOfApproval: IDerObjectIdentifier read GetIdCtiEtsProofOfApproval;
    class property IdCtiEtsProofOfCreation: IDerObjectIdentifier read GetIdCtiEtsProofOfCreation;
    class property Id_aa: IDerObjectIdentifier read GetId_aa;
    class property IdAAOid: IDerObjectIdentifier read GetIdAAOid;
    class property Pkcs9AtBinarySigningTime: IDerObjectIdentifier read GetPkcs9AtBinarySigningTime;
    class property IdAAReceiptRequest: IDerObjectIdentifier read GetIdAAReceiptRequest;
    class property IdAAContentHint: IDerObjectIdentifier read GetIdAAContentHint;
    class property IdAAMsgSigDigest: IDerObjectIdentifier read GetIdAAMsgSigDigest;
    class property IdAAContentReference: IDerObjectIdentifier read GetIdAAContentReference;
    class property IdAAEncrypKeyPref: IDerObjectIdentifier read GetIdAAEncrypKeyPref;
    class property IdAASigningCertificate: IDerObjectIdentifier read GetIdAASigningCertificate;
    class property IdAASigningCertificateV2: IDerObjectIdentifier read GetIdAASigningCertificateV2;
    class property IdAAContentIdentifier: IDerObjectIdentifier read GetIdAAContentIdentifier;
    class property IdAASignatureTimeStampToken: IDerObjectIdentifier read GetIdAASignatureTimeStampToken;
    class property IdAAEtsSigPolicyID: IDerObjectIdentifier read GetIdAAEtsSigPolicyID;
    class property IdAAEtsCommitmentType: IDerObjectIdentifier read GetIdAAEtsCommitmentType;
    class property IdAAEtsSignerLocation: IDerObjectIdentifier read GetIdAAEtsSignerLocation;
    class property IdAAEtsSignerAttr: IDerObjectIdentifier read GetIdAAEtsSignerAttr;
    class property IdAAEtsOtherSigCert: IDerObjectIdentifier read GetIdAAEtsOtherSigCert;
    class property IdAAEtsContentTimestamp: IDerObjectIdentifier read GetIdAAEtsContentTimestamp;
    class property IdAAEtsCertificateRefs: IDerObjectIdentifier read GetIdAAEtsCertificateRefs;
    class property IdAAEtsRevocationRefs: IDerObjectIdentifier read GetIdAAEtsRevocationRefs;
    class property IdAAEtsCertValues: IDerObjectIdentifier read GetIdAAEtsCertValues;
    class property IdAAEtsRevocationValues: IDerObjectIdentifier read GetIdAAEtsRevocationValues;
    class property IdAAEtsEscTimeStamp: IDerObjectIdentifier read GetIdAAEtsEscTimeStamp;
    class property IdAAEtsCertCrlTimestamp: IDerObjectIdentifier read GetIdAAEtsCertCrlTimestamp;
    class property IdAAEtsArchiveTimestamp: IDerObjectIdentifier read GetIdAAEtsArchiveTimestamp;
    class property IdAADecryptKeyID: IDerObjectIdentifier read GetIdAADecryptKeyID;
    class property IdAAImplCryptoAlgs: IDerObjectIdentifier read GetIdAAImplCryptoAlgs;
    class property IdAAAsymmDecryptKeyID: IDerObjectIdentifier read GetIdAAAsymmDecryptKeyID;
    class property IdAAImplCompressAlgs: IDerObjectIdentifier read GetIdAAImplCompressAlgs;
    class property IdAACommunityIdentifiers: IDerObjectIdentifier read GetIdAACommunityIdentifiers;
    class property IdAAEtsArchiveTimestampV2: IDerObjectIdentifier read GetIdAAEtsArchiveTimestampV2;
    class property Id_spq: IDerObjectIdentifier read GetId_spq;
    class property IdSpqEtsUri: IDerObjectIdentifier read GetIdSpqEtsUri;
    class property IdSpqEtsUNotice: IDerObjectIdentifier read GetIdSpqEtsUNotice;
    //
    // PKCS#12
    //
    class property KeyBag: IDerObjectIdentifier read GetKeyBag;
    class property Pkcs8ShroudedKeyBag: IDerObjectIdentifier read GetPkcs8ShroudedKeyBag;
    class property CertBag: IDerObjectIdentifier read GetCertBag;
    class property CrlBag: IDerObjectIdentifier read GetCrlBag;
    class property SecretBag: IDerObjectIdentifier read GetSecretBag;
    class property SafeContentsBag: IDerObjectIdentifier read GetSafeContentsBag;
    class property PbeWithShaAnd128BitRC4: IDerObjectIdentifier read GetPbeWithShaAnd128BitRC4;
    class property PbeWithShaAnd40BitRC4: IDerObjectIdentifier read GetPbeWithShaAnd40BitRC4;
    class property PbeWithShaAnd3KeyTripleDesCbc: IDerObjectIdentifier read GetPbeWithShaAnd3KeyTripleDesCbc;
    class property PbeWithShaAnd2KeyTripleDesCbc: IDerObjectIdentifier read GetPbeWithShaAnd2KeyTripleDesCbc;
    class property PbeWithShaAnd128BitRC2Cbc: IDerObjectIdentifier read GetPbeWithShaAnd128BitRC2Cbc;
    class property PbewithShaAnd40BitRC2Cbc: IDerObjectIdentifier read GetPbewithShaAnd40BitRC2Cbc;

    class procedure Boot(); static;

  end;

implementation

{ TPkcsObjectIdentifiers }

class procedure TPkcsObjectIdentifiers.Boot;
begin
  if not FIsBooted then
  begin
    // PKCS#1 RSA
    FRsaEncryption := TDerObjectIdentifier.Create(Pkcs1 + '.1');
    FMD2WithRsaEncryption := TDerObjectIdentifier.Create(Pkcs1 + '.2');
    FMD4WithRsaEncryption := TDerObjectIdentifier.Create(Pkcs1 + '.3');
    FMD5WithRsaEncryption := TDerObjectIdentifier.Create(Pkcs1 + '.4');
    FSha1WithRsaEncryption := TDerObjectIdentifier.Create(Pkcs1 + '.5');
    FSrsaOaepEncryptionSet := TDerObjectIdentifier.Create(Pkcs1 + '.6');
    FIdRsaesOaep := TDerObjectIdentifier.Create(Pkcs1 + '.7');
    FIdMgf1 := TDerObjectIdentifier.Create(Pkcs1 + '.8');
    FIdPSpecified := TDerObjectIdentifier.Create(Pkcs1 + '.9');
    FIdRsassaPss := TDerObjectIdentifier.Create(Pkcs1 + '.10');
    FSha256WithRsaEncryption := TDerObjectIdentifier.Create(Pkcs1 + '.11');
    FSha384WithRsaEncryption := TDerObjectIdentifier.Create(Pkcs1 + '.12');
    FSha512WithRsaEncryption := TDerObjectIdentifier.Create(Pkcs1 + '.13');
    FSha224WithRsaEncryption := TDerObjectIdentifier.Create(Pkcs1 + '.14');
    FSha512_224WithRsaEncryption := TDerObjectIdentifier.Create(Pkcs1 + '.15');
    FSha512_256WithRsaEncryption := TDerObjectIdentifier.Create(Pkcs1 + '.16');

    // PKCS#3
    FDhKeyAgreement := TDerObjectIdentifier.Create(Pkcs3 + '.1');

    // PKCS#5
    FIdPbkdf2 := TDerObjectIdentifier.Create(Pkcs5 + '.12');
    FPbeWithMD2AndDesCbc := TDerObjectIdentifier.Create(Pkcs5 + '.1');
    FPbeWithMD2AndRC2Cbc := TDerObjectIdentifier.Create(Pkcs5 + '.4');
    FPbeWithMD5AndDesCbc := TDerObjectIdentifier.Create(Pkcs5 + '.3');
    FPbeWithMD5AndRC2Cbc := TDerObjectIdentifier.Create(Pkcs5 + '.6');
    FPbeWithSha1AndDesCbc := TDerObjectIdentifier.Create(Pkcs5 + '.10');
    FPbeWithSha1AndRC2Cbc := TDerObjectIdentifier.Create(Pkcs5 + '.11');
    FIdPbeS2 := TDerObjectIdentifier.Create(Pkcs5 + '.13');
    FIdPbmac1 := TDerObjectIdentifier.Create(Pkcs5 + '.14');

    // EncryptionAlgorithm
    FDesEde3Cbc := TDerObjectIdentifier.Create(EncryptionAlgorithm + '.7');
    FRC2Cbc := TDerObjectIdentifier.Create(EncryptionAlgorithm + '.2');
    Frc4 := TDerObjectIdentifier.Create(EncryptionAlgorithm + '.4');

    // PKCS#7
    FData := TDerObjectIdentifier.Create(Pkcs7 + '.1');
    FSignedData := TDerObjectIdentifier.Create(Pkcs7 + '.2');
    FEnvelopedData := TDerObjectIdentifier.Create(Pkcs7 + '.3');
    FSignedAndEnvelopedData := TDerObjectIdentifier.Create(Pkcs7 + '.4');
    FDigestedData := TDerObjectIdentifier.Create(Pkcs7 + '.5');
    FEncryptedData := TDerObjectIdentifier.Create(Pkcs7 + '.6');

    // Digest algorithms
    FMD2 := TDerObjectIdentifier.Create(DigestAlgorithm + '.2');
    FMD4 := TDerObjectIdentifier.Create(DigestAlgorithm + '.4');
    FMD5 := TDerObjectIdentifier.Create(DigestAlgorithm + '.5');
    FIdHmacWithSha1 := TDerObjectIdentifier.Create(DigestAlgorithm + '.7');
    FIdHmacWithSha224 := TDerObjectIdentifier.Create(DigestAlgorithm + '.8');
    FIdHmacWithSha256 := TDerObjectIdentifier.Create(DigestAlgorithm + '.9');
    FIdHmacWithSha384 := TDerObjectIdentifier.Create(DigestAlgorithm + '.10');
    FIdHmacWithSha512 := TDerObjectIdentifier.Create(DigestAlgorithm + '.11');
    FIdHmacWithSha512_224 := TDerObjectIdentifier.Create(DigestAlgorithm + '.12');
    FIdHmacWithSha512_256 := TDerObjectIdentifier.Create(DigestAlgorithm + '.13');

    // PKCS#9
    FPkcs9AtEmailAddress := TDerObjectIdentifier.Create(Pkcs9 + '.1');
    FPkcs9AtUnstructuredName := TDerObjectIdentifier.Create(Pkcs9 + '.2');
    FPkcs9AtContentType := TDerObjectIdentifier.Create(Pkcs9 + '.3');
    FPkcs9AtMessageDigest := TDerObjectIdentifier.Create(Pkcs9 + '.4');
    FPkcs9AtSigningTime := TDerObjectIdentifier.Create(Pkcs9 + '.5');
    FPkcs9AtCounterSignature := TDerObjectIdentifier.Create(Pkcs9 + '.6');
    FPkcs9AtChallengePassword := TDerObjectIdentifier.Create(Pkcs9 + '.7');
    FPkcs9AtUnstructuredAddress := TDerObjectIdentifier.Create(Pkcs9 + '.8');
    FPkcs9AtExtendedCertificateAttributes := TDerObjectIdentifier.Create(Pkcs9 + '.9');
    FPkcs9AtSigningDescription := TDerObjectIdentifier.Create(Pkcs9 + '.13');
    FPkcs9AtExtensionRequest := TDerObjectIdentifier.Create(Pkcs9 + '.14');
    FPkcs9AtSmimeCapabilities := TDerObjectIdentifier.Create(Pkcs9 + '.15');
    FIdSmime := TDerObjectIdentifier.Create(Pkcs9 + '.16');
    FPkcs9AtFriendlyName := TDerObjectIdentifier.Create(Pkcs9 + '.20');
    FPkcs9AtLocalKeyID := TDerObjectIdentifier.Create(Pkcs9 + '.21');
    FX509Certificate := TDerObjectIdentifier.Create(CertTypes + '.1');
    FSdsiCertificate := TDerObjectIdentifier.Create(CertTypes + '.2');
    FX509Crl := TDerObjectIdentifier.Create(CrlTypes + '.1');
    FSmimeAlg := FIdSmime.Branch('3');
    FIdAlg := FSmimeAlg;
    FIdAlgEsdh := FSmimeAlg.Branch('5');
    FIdAlgCms3DesWrap := FSmimeAlg.Branch('6');
    FIdAlgCmsRC2Wrap := FSmimeAlg.Branch('7');
    FIdAlgZlibCompress := FSmimeAlg.Branch('8');
    FIdAlgPwriKek := FSmimeAlg.Branch('9');
    FIdAlgSsdh := FSmimeAlg.Branch('10');
    FId_aa_cmsAlgorithmProtect := TDerObjectIdentifier.Create(Pkcs9 + '.52');
    FIdRsaKem := FSmimeAlg.Branch('14');
    FIdAlgHssLmsHashsig := FSmimeAlg.Branch('17');
    FIdAlgAeadChaCha20Poly1305 := FSmimeAlg.Branch('18');
    FIdAlgHkdfWithSha256 := FSmimeAlg.Branch('28');
    FIdAlgHkdfWithSha384 := FSmimeAlg.Branch('29');
    FIdAlgHkdfWithSha512 := FSmimeAlg.Branch('30');
    FPreferSignedData := FPkcs9AtSmimeCapabilities.Branch('1');
    FCannotDecryptAny := FPkcs9AtSmimeCapabilities.Branch('2');
    FSmimeCapabilitiesVersions := FPkcs9AtSmimeCapabilities.Branch('3');
    FId_ct := FIdSmime.Branch('1');
    FIdCTAuthData := FId_ct.Branch('2');
    FIdCTTstInfo := FId_ct.Branch('4');
    FIdCTCompressedData := FId_ct.Branch('9');
    FIdCTAuthEnvelopedData := FId_ct.Branch('23');
    FIdCTTimestampedData := FId_ct.Branch('31');
    FId_cti := FIdSmime.Branch('6');
    FIdCtiEtsProofOfOrigin := FId_cti.Branch('1');
    FIdCtiEtsProofOfReceipt := FId_cti.Branch('2');
    FIdCtiEtsProofOfDelivery := FId_cti.Branch('3');
    FIdCtiEtsProofOfSender := FId_cti.Branch('4');
    FIdCtiEtsProofOfApproval := FId_cti.Branch('5');
    FIdCtiEtsProofOfCreation := FId_cti.Branch('6');
    FId_aa := FIdSmime.Branch('2');
    FIdAAOid := FId_aa;
    FPkcs9AtBinarySigningTime := FId_aa.Branch('46');
    FIdAAReceiptRequest := FId_aa.Branch('1');
    FIdAAContentHint := FId_aa.Branch('4');
    FIdAAMsgSigDigest := FId_aa.Branch('5');
    FIdAAContentReference := FId_aa.Branch('10');
    FIdAAEncrypKeyPref := FId_aa.Branch('11');
    FIdAASigningCertificate := FId_aa.Branch('12');
    FIdAAContentIdentifier := FId_aa.Branch('7');
    FIdAASignatureTimeStampToken := FId_aa.Branch('14');
    FIdAAEtsSigPolicyID := FId_aa.Branch('15');
    FIdAAEtsCommitmentType := FId_aa.Branch('16');
    FIdAAEtsSignerLocation := FId_aa.Branch('17');
    FIdAAEtsSignerAttr := FId_aa.Branch('18');
    FIdAAEtsOtherSigCert := FId_aa.Branch('19');
    FIdAAEtsContentTimestamp := FId_aa.Branch('20');
    FIdAAEtsCertificateRefs := FId_aa.Branch('21');
    FIdAAEtsRevocationRefs := FId_aa.Branch('22');
    FIdAAEtsCertValues := FId_aa.Branch('23');
    FIdAAEtsRevocationValues := FId_aa.Branch('24');
    FIdAAEtsEscTimeStamp := FId_aa.Branch('25');
    FIdAAEtsCertCrlTimestamp := FId_aa.Branch('26');
    FIdAAEtsArchiveTimestamp := FId_aa.Branch('27');
    FIdAADecryptKeyID := FId_aa.Branch('37');
    FIdAAImplCryptoAlgs := FId_aa.Branch('38');
    FIdAAAsymmDecryptKeyID := FId_aa.Branch('54');
    FIdAAImplCompressAlgs := FId_aa.Branch('43');
    FIdAACommunityIdentifiers := FId_aa.Branch('40');
    FIdAASigningCertificateV2 := FId_aa.Branch('47');
    FIdAAEtsArchiveTimestampV2 := FId_aa.Branch('48');
    FId_spq := FIdSmime.Branch('5');
    FIdSpqEtsUri := FId_spq.Branch('1');
    FIdSpqEtsUNotice := FId_spq.Branch('2');
    // PKCS#12
    FKeyBag := TDerObjectIdentifier.Create(BagTypes + '.1');
    FPkcs8ShroudedKeyBag := TDerObjectIdentifier.Create(BagTypes + '.2');
    FCertBag := TDerObjectIdentifier.Create(BagTypes + '.3');
    FCrlBag := TDerObjectIdentifier.Create(BagTypes + '.4');
    FSecretBag := TDerObjectIdentifier.Create(BagTypes + '.5');
    FSafeContentsBag := TDerObjectIdentifier.Create(BagTypes + '.6');
    FPbeWithShaAnd128BitRC4 := TDerObjectIdentifier.Create(Pkcs12PbeIds + '.1');
    FPbeWithShaAnd40BitRC4 := TDerObjectIdentifier.Create(Pkcs12PbeIds + '.2');
    FPbeWithShaAnd3KeyTripleDesCbc := TDerObjectIdentifier.Create(Pkcs12PbeIds + '.3');
    FPbeWithShaAnd2KeyTripleDesCbc := TDerObjectIdentifier.Create(Pkcs12PbeIds + '.4');
    FPbeWithShaAnd128BitRC2Cbc := TDerObjectIdentifier.Create(Pkcs12PbeIds + '.5');
    FPbewithShaAnd40BitRC2Cbc := TDerObjectIdentifier.Create(Pkcs12PbeIds + '.6');

    FIsBooted := True;
  end;
end;

// PKCS#1 RSA getters

class function TPkcsObjectIdentifiers.GetRsaEncryption: IDerObjectIdentifier;
begin
  Result := FRsaEncryption;
end;

class function TPkcsObjectIdentifiers.GetMD2WithRsaEncryption: IDerObjectIdentifier;
begin
  Result := FMD2WithRsaEncryption;
end;

class function TPkcsObjectIdentifiers.GetMD4WithRsaEncryption: IDerObjectIdentifier;
begin
  Result := FMD4WithRsaEncryption;
end;

class function TPkcsObjectIdentifiers.GetMD5WithRsaEncryption: IDerObjectIdentifier;
begin
  Result := FMD5WithRsaEncryption;
end;

class function TPkcsObjectIdentifiers.GetSha1WithRsaEncryption: IDerObjectIdentifier;
begin
  Result := FSha1WithRsaEncryption;
end;

class function TPkcsObjectIdentifiers.GetSrsaOaepEncryptionSet: IDerObjectIdentifier;
begin
  Result := FSrsaOaepEncryptionSet;
end;

class function TPkcsObjectIdentifiers.GetIdRsaesOaep: IDerObjectIdentifier;
begin
  Result := FIdRsaesOaep;
end;

class function TPkcsObjectIdentifiers.GetIdMgf1: IDerObjectIdentifier;
begin
  Result := FIdMgf1;
end;

class function TPkcsObjectIdentifiers.GetIdPSpecified: IDerObjectIdentifier;
begin
  Result := FIdPSpecified;
end;

class function TPkcsObjectIdentifiers.GetIdRsassaPss: IDerObjectIdentifier;
begin
  Result := FIdRsassaPss;
end;

class function TPkcsObjectIdentifiers.GetSha256WithRsaEncryption: IDerObjectIdentifier;
begin
  Result := FSha256WithRsaEncryption;
end;

class function TPkcsObjectIdentifiers.GetSha384WithRsaEncryption: IDerObjectIdentifier;
begin
  Result := FSha384WithRsaEncryption;
end;

class function TPkcsObjectIdentifiers.GetSha512WithRsaEncryption: IDerObjectIdentifier;
begin
  Result := FSha512WithRsaEncryption;
end;

class function TPkcsObjectIdentifiers.GetSha224WithRsaEncryption: IDerObjectIdentifier;
begin
  Result := FSha224WithRsaEncryption;
end;

class function TPkcsObjectIdentifiers.GetSha512_224WithRsaEncryption: IDerObjectIdentifier;
begin
  Result := FSha512_224WithRsaEncryption;
end;

class function TPkcsObjectIdentifiers.GetSha512_256WithRsaEncryption: IDerObjectIdentifier;
begin
  Result := FSha512_256WithRsaEncryption;
end;

// PKCS#3

class function TPkcsObjectIdentifiers.GetDhKeyAgreement: IDerObjectIdentifier;
begin
  Result := FDhKeyAgreement;
end;

// PKCS#5

class function TPkcsObjectIdentifiers.GetIdPbkdf2: IDerObjectIdentifier;
begin
  Result := FIdPbkdf2;
end;

class function TPkcsObjectIdentifiers.GetPbeWithMD2AndDesCbc: IDerObjectIdentifier;
begin
  Result := FPbeWithMD2AndDesCbc;
end;

class function TPkcsObjectIdentifiers.GetPbeWithMD2AndRC2Cbc: IDerObjectIdentifier;
begin
  Result := FPbeWithMD2AndRC2Cbc;
end;

class function TPkcsObjectIdentifiers.GetPbeWithMD5AndDesCbc: IDerObjectIdentifier;
begin
  Result := FPbeWithMD5AndDesCbc;
end;

class function TPkcsObjectIdentifiers.GetPbeWithMD5AndRC2Cbc: IDerObjectIdentifier;
begin
  Result := FPbeWithMD5AndRC2Cbc;
end;

class function TPkcsObjectIdentifiers.GetPbeWithSha1AndDesCbc: IDerObjectIdentifier;
begin
  Result := FPbeWithSha1AndDesCbc;
end;

class function TPkcsObjectIdentifiers.GetPbeWithSha1AndRC2Cbc: IDerObjectIdentifier;
begin
  Result := FPbeWithSha1AndRC2Cbc;
end;

class function TPkcsObjectIdentifiers.GetIdPbeS2: IDerObjectIdentifier;
begin
  Result := FIdPbeS2;
end;

class function TPkcsObjectIdentifiers.GetIdPbmac1: IDerObjectIdentifier;
begin
  Result := FIdPbmac1;
end;

// EncryptionAlgorithm

class function TPkcsObjectIdentifiers.GetDesEde3Cbc: IDerObjectIdentifier;
begin
  Result := FDesEde3Cbc;
end;

class function TPkcsObjectIdentifiers.GetRC2Cbc: IDerObjectIdentifier;
begin
  Result := FRC2Cbc;
end;

class function TPkcsObjectIdentifiers.GetRc4: IDerObjectIdentifier;
begin
  Result := Frc4;
end;

// PKCS#7

class function TPkcsObjectIdentifiers.GetData: IDerObjectIdentifier;
begin
  Result := FData;
end;

class function TPkcsObjectIdentifiers.GetSignedData: IDerObjectIdentifier;
begin
  Result := FSignedData;
end;

class function TPkcsObjectIdentifiers.GetEnvelopedData: IDerObjectIdentifier;
begin
  Result := FEnvelopedData;
end;

class function TPkcsObjectIdentifiers.GetSignedAndEnvelopedData: IDerObjectIdentifier;
begin
  Result := FSignedAndEnvelopedData;
end;

class function TPkcsObjectIdentifiers.GetDigestedData: IDerObjectIdentifier;
begin
  Result := FDigestedData;
end;

class function TPkcsObjectIdentifiers.GetEncryptedData: IDerObjectIdentifier;
begin
  Result := FEncryptedData;
end;

// Digest algorithms

class function TPkcsObjectIdentifiers.GetMD2: IDerObjectIdentifier;
begin
  Result := FMD2;
end;

class function TPkcsObjectIdentifiers.GetMD4: IDerObjectIdentifier;
begin
  Result := FMD4;
end;

class function TPkcsObjectIdentifiers.GetMD5: IDerObjectIdentifier;
begin
  Result := FMD5;
end;

class function TPkcsObjectIdentifiers.GetIdHmacWithSha1: IDerObjectIdentifier;
begin
  Result := FIdHmacWithSha1;
end;

class function TPkcsObjectIdentifiers.GetIdHmacWithSha224: IDerObjectIdentifier;
begin
  Result := FIdHmacWithSha224;
end;

class function TPkcsObjectIdentifiers.GetIdHmacWithSha256: IDerObjectIdentifier;
begin
  Result := FIdHmacWithSha256;
end;

class function TPkcsObjectIdentifiers.GetIdHmacWithSha384: IDerObjectIdentifier;
begin
  Result := FIdHmacWithSha384;
end;

class function TPkcsObjectIdentifiers.GetIdHmacWithSha512: IDerObjectIdentifier;
begin
  Result := FIdHmacWithSha512;
end;

class function TPkcsObjectIdentifiers.GetIdHmacWithSha512_224: IDerObjectIdentifier;
begin
  Result := FIdHmacWithSha512_224;
end;

class function TPkcsObjectIdentifiers.GetIdHmacWithSha512_256: IDerObjectIdentifier;
begin
  Result := FIdHmacWithSha512_256;
end;

// PKCS#9 getters

class function TPkcsObjectIdentifiers.GetPkcs9AtEmailAddress: IDerObjectIdentifier;
begin
  Result := FPkcs9AtEmailAddress;
end;

class function TPkcsObjectIdentifiers.GetPkcs9AtChallengePassword: IDerObjectIdentifier;
begin
  Result := FPkcs9AtChallengePassword;
end;

class function TPkcsObjectIdentifiers.GetPkcs9AtUnstructuredName: IDerObjectIdentifier;
begin
  Result := FPkcs9AtUnstructuredName;
end;

class function TPkcsObjectIdentifiers.GetPkcs9AtUnstructuredAddress: IDerObjectIdentifier;
begin
  Result := FPkcs9AtUnstructuredAddress;
end;

class function TPkcsObjectIdentifiers.GetPkcs9AtExtensionRequest: IDerObjectIdentifier;
begin
  Result := FPkcs9AtExtensionRequest;
end;

class function TPkcsObjectIdentifiers.GetPkcs9AtContentType: IDerObjectIdentifier;
begin
  Result := FPkcs9AtContentType;
end;

class function TPkcsObjectIdentifiers.GetPkcs9AtMessageDigest: IDerObjectIdentifier;
begin
  Result := FPkcs9AtMessageDigest;
end;

class function TPkcsObjectIdentifiers.GetPkcs9AtSigningTime: IDerObjectIdentifier;
begin
  Result := FPkcs9AtSigningTime;
end;

class function TPkcsObjectIdentifiers.GetPkcs9AtCounterSignature: IDerObjectIdentifier;
begin
  Result := FPkcs9AtCounterSignature;
end;

class function TPkcsObjectIdentifiers.GetPkcs9AtExtendedCertificateAttributes: IDerObjectIdentifier;
begin
  Result := FPkcs9AtExtendedCertificateAttributes;
end;

class function TPkcsObjectIdentifiers.GetPkcs9AtSigningDescription: IDerObjectIdentifier;
begin
  Result := FPkcs9AtSigningDescription;
end;

class function TPkcsObjectIdentifiers.GetPkcs9AtSmimeCapabilities: IDerObjectIdentifier;
begin
  Result := FPkcs9AtSmimeCapabilities;
end;

class function TPkcsObjectIdentifiers.GetIdSmime: IDerObjectIdentifier;
begin
  Result := FIdSmime;
end;

class function TPkcsObjectIdentifiers.GetPkcs9AtFriendlyName: IDerObjectIdentifier;
begin
  Result := FPkcs9AtFriendlyName;
end;

class function TPkcsObjectIdentifiers.GetPkcs9AtLocalKeyID: IDerObjectIdentifier;
begin
  Result := FPkcs9AtLocalKeyID;
end;

class function TPkcsObjectIdentifiers.GetX509Certificate: IDerObjectIdentifier;
begin
  Result := FX509Certificate;
end;

class function TPkcsObjectIdentifiers.GetSdsiCertificate: IDerObjectIdentifier;
begin
  Result := FSdsiCertificate;
end;

class function TPkcsObjectIdentifiers.GetX509Crl: IDerObjectIdentifier;
begin
  Result := FX509Crl;
end;

class function TPkcsObjectIdentifiers.GetSmimeAlg: IDerObjectIdentifier;
begin
  Result := FSmimeAlg;
end;

class function TPkcsObjectIdentifiers.GetIdAlg: IDerObjectIdentifier;
begin
  Result := FIdAlg;
end;

class function TPkcsObjectIdentifiers.GetIdAlgEsdh: IDerObjectIdentifier;
begin
  Result := FIdAlgEsdh;
end;

class function TPkcsObjectIdentifiers.GetIdAlgCms3DesWrap: IDerObjectIdentifier;
begin
  Result := FIdAlgCms3DesWrap;
end;

class function TPkcsObjectIdentifiers.GetIdAlgCmsRC2Wrap: IDerObjectIdentifier;
begin
  Result := FIdAlgCmsRC2Wrap;
end;

class function TPkcsObjectIdentifiers.GetIdAlgZlibCompress: IDerObjectIdentifier;
begin
  Result := FIdAlgZlibCompress;
end;

class function TPkcsObjectIdentifiers.GetIdAlgPwriKek: IDerObjectIdentifier;
begin
  Result := FIdAlgPwriKek;
end;

class function TPkcsObjectIdentifiers.GetIdAlgSsdh: IDerObjectIdentifier;
begin
  Result := FIdAlgSsdh;
end;

class function TPkcsObjectIdentifiers.GetId_aa_cmsAlgorithmProtect: IDerObjectIdentifier;
begin
  Result := FId_aa_cmsAlgorithmProtect;
end;

class function TPkcsObjectIdentifiers.GetIdRsaKem: IDerObjectIdentifier;
begin
  Result := FIdRsaKem;
end;

class function TPkcsObjectIdentifiers.GetIdAlgHssLmsHashsig: IDerObjectIdentifier;
begin
  Result := FIdAlgHssLmsHashsig;
end;

class function TPkcsObjectIdentifiers.GetIdAlgAeadChaCha20Poly1305: IDerObjectIdentifier;
begin
  Result := FIdAlgAeadChaCha20Poly1305;
end;

class function TPkcsObjectIdentifiers.GetIdAlgHkdfWithSha256: IDerObjectIdentifier;
begin
  Result := FIdAlgHkdfWithSha256;
end;

class function TPkcsObjectIdentifiers.GetIdAlgHkdfWithSha384: IDerObjectIdentifier;
begin
  Result := FIdAlgHkdfWithSha384;
end;

class function TPkcsObjectIdentifiers.GetIdAlgHkdfWithSha512: IDerObjectIdentifier;
begin
  Result := FIdAlgHkdfWithSha512;
end;

class function TPkcsObjectIdentifiers.GetPreferSignedData: IDerObjectIdentifier;
begin
  Result := FPreferSignedData;
end;

class function TPkcsObjectIdentifiers.GetCannotDecryptAny: IDerObjectIdentifier;
begin
  Result := FCannotDecryptAny;
end;

class function TPkcsObjectIdentifiers.GetSmimeCapabilitiesVersions: IDerObjectIdentifier;
begin
  Result := FSmimeCapabilitiesVersions;
end;

class function TPkcsObjectIdentifiers.GetId_ct: IDerObjectIdentifier;
begin
  Result := FId_ct;
end;

class function TPkcsObjectIdentifiers.GetIdCTAuthData: IDerObjectIdentifier;
begin
  Result := FIdCTAuthData;
end;

class function TPkcsObjectIdentifiers.GetIdCTTstInfo: IDerObjectIdentifier;
begin
  Result := FIdCTTstInfo;
end;

class function TPkcsObjectIdentifiers.GetIdCTCompressedData: IDerObjectIdentifier;
begin
  Result := FIdCTCompressedData;
end;

class function TPkcsObjectIdentifiers.GetIdCTAuthEnvelopedData: IDerObjectIdentifier;
begin
  Result := FIdCTAuthEnvelopedData;
end;

class function TPkcsObjectIdentifiers.GetIdCTTimestampedData: IDerObjectIdentifier;
begin
  Result := FIdCTTimestampedData;
end;

class function TPkcsObjectIdentifiers.GetId_cti: IDerObjectIdentifier;
begin
  Result := FId_cti;
end;

class function TPkcsObjectIdentifiers.GetIdCtiEtsProofOfOrigin: IDerObjectIdentifier;
begin
  Result := FIdCtiEtsProofOfOrigin;
end;

class function TPkcsObjectIdentifiers.GetIdCtiEtsProofOfReceipt: IDerObjectIdentifier;
begin
  Result := FIdCtiEtsProofOfReceipt;
end;

class function TPkcsObjectIdentifiers.GetIdCtiEtsProofOfDelivery: IDerObjectIdentifier;
begin
  Result := FIdCtiEtsProofOfDelivery;
end;

class function TPkcsObjectIdentifiers.GetIdCtiEtsProofOfSender: IDerObjectIdentifier;
begin
  Result := FIdCtiEtsProofOfSender;
end;

class function TPkcsObjectIdentifiers.GetIdCtiEtsProofOfApproval: IDerObjectIdentifier;
begin
  Result := FIdCtiEtsProofOfApproval;
end;

class function TPkcsObjectIdentifiers.GetIdCtiEtsProofOfCreation: IDerObjectIdentifier;
begin
  Result := FIdCtiEtsProofOfCreation;
end;

class function TPkcsObjectIdentifiers.GetId_aa: IDerObjectIdentifier;
begin
  Result := FId_aa;
end;

class function TPkcsObjectIdentifiers.GetIdAAOid: IDerObjectIdentifier;
begin
  Result := FIdAAOid;
end;

class function TPkcsObjectIdentifiers.GetPkcs9AtBinarySigningTime: IDerObjectIdentifier;
begin
  Result := FPkcs9AtBinarySigningTime;
end;

class function TPkcsObjectIdentifiers.GetIdAAReceiptRequest: IDerObjectIdentifier;
begin
  Result := FIdAAReceiptRequest;
end;

class function TPkcsObjectIdentifiers.GetIdAAContentHint: IDerObjectIdentifier;
begin
  Result := FIdAAContentHint;
end;

class function TPkcsObjectIdentifiers.GetIdAAMsgSigDigest: IDerObjectIdentifier;
begin
  Result := FIdAAMsgSigDigest;
end;

class function TPkcsObjectIdentifiers.GetIdAAContentReference: IDerObjectIdentifier;
begin
  Result := FIdAAContentReference;
end;

class function TPkcsObjectIdentifiers.GetIdAAEncrypKeyPref: IDerObjectIdentifier;
begin
  Result := FIdAAEncrypKeyPref;
end;

class function TPkcsObjectIdentifiers.GetIdAASigningCertificate: IDerObjectIdentifier;
begin
  Result := FIdAASigningCertificate;
end;

class function TPkcsObjectIdentifiers.GetIdAASigningCertificateV2: IDerObjectIdentifier;
begin
  Result := FIdAASigningCertificateV2;
end;

class function TPkcsObjectIdentifiers.GetIdAAContentIdentifier: IDerObjectIdentifier;
begin
  Result := FIdAAContentIdentifier;
end;

class function TPkcsObjectIdentifiers.GetIdAASignatureTimeStampToken: IDerObjectIdentifier;
begin
  Result := FIdAASignatureTimeStampToken;
end;

class function TPkcsObjectIdentifiers.GetIdAAEtsSigPolicyID: IDerObjectIdentifier;
begin
  Result := FIdAAEtsSigPolicyID;
end;

class function TPkcsObjectIdentifiers.GetIdAAEtsCommitmentType: IDerObjectIdentifier;
begin
  Result := FIdAAEtsCommitmentType;
end;

class function TPkcsObjectIdentifiers.GetIdAAEtsSignerLocation: IDerObjectIdentifier;
begin
  Result := FIdAAEtsSignerLocation;
end;

class function TPkcsObjectIdentifiers.GetIdAAEtsSignerAttr: IDerObjectIdentifier;
begin
  Result := FIdAAEtsSignerAttr;
end;

class function TPkcsObjectIdentifiers.GetIdAAEtsOtherSigCert: IDerObjectIdentifier;
begin
  Result := FIdAAEtsOtherSigCert;
end;

class function TPkcsObjectIdentifiers.GetIdAAEtsContentTimestamp: IDerObjectIdentifier;
begin
  Result := FIdAAEtsContentTimestamp;
end;

class function TPkcsObjectIdentifiers.GetIdAAEtsCertificateRefs: IDerObjectIdentifier;
begin
  Result := FIdAAEtsCertificateRefs;
end;

class function TPkcsObjectIdentifiers.GetIdAAEtsRevocationRefs: IDerObjectIdentifier;
begin
  Result := FIdAAEtsRevocationRefs;
end;

class function TPkcsObjectIdentifiers.GetIdAAEtsCertValues: IDerObjectIdentifier;
begin
  Result := FIdAAEtsCertValues;
end;

class function TPkcsObjectIdentifiers.GetIdAAEtsRevocationValues: IDerObjectIdentifier;
begin
  Result := FIdAAEtsRevocationValues;
end;

class function TPkcsObjectIdentifiers.GetIdAAEtsEscTimeStamp: IDerObjectIdentifier;
begin
  Result := FIdAAEtsEscTimeStamp;
end;

class function TPkcsObjectIdentifiers.GetIdAAEtsCertCrlTimestamp: IDerObjectIdentifier;
begin
  Result := FIdAAEtsCertCrlTimestamp;
end;

class function TPkcsObjectIdentifiers.GetIdAAEtsArchiveTimestamp: IDerObjectIdentifier;
begin
  Result := FIdAAEtsArchiveTimestamp;
end;

class function TPkcsObjectIdentifiers.GetIdAADecryptKeyID: IDerObjectIdentifier;
begin
  Result := FIdAADecryptKeyID;
end;

class function TPkcsObjectIdentifiers.GetIdAAImplCryptoAlgs: IDerObjectIdentifier;
begin
  Result := FIdAAImplCryptoAlgs;
end;

class function TPkcsObjectIdentifiers.GetIdAAAsymmDecryptKeyID: IDerObjectIdentifier;
begin
  Result := FIdAAAsymmDecryptKeyID;
end;

class function TPkcsObjectIdentifiers.GetIdAAImplCompressAlgs: IDerObjectIdentifier;
begin
  Result := FIdAAImplCompressAlgs;
end;

class function TPkcsObjectIdentifiers.GetIdAACommunityIdentifiers: IDerObjectIdentifier;
begin
  Result := FIdAACommunityIdentifiers;
end;

class function TPkcsObjectIdentifiers.GetIdAAEtsArchiveTimestampV2: IDerObjectIdentifier;
begin
  Result := FIdAAEtsArchiveTimestampV2;
end;

class function TPkcsObjectIdentifiers.GetId_spq: IDerObjectIdentifier;
begin
  Result := FId_spq;
end;

class function TPkcsObjectIdentifiers.GetIdSpqEtsUri: IDerObjectIdentifier;
begin
  Result := FIdSpqEtsUri;
end;

class function TPkcsObjectIdentifiers.GetIdSpqEtsUNotice: IDerObjectIdentifier;
begin
  Result := FIdSpqEtsUNotice;
end;

class function TPkcsObjectIdentifiers.GetKeyBag: IDerObjectIdentifier;
begin
  Result := FKeyBag;
end;

class function TPkcsObjectIdentifiers.GetPkcs8ShroudedKeyBag: IDerObjectIdentifier;
begin
  Result := FPkcs8ShroudedKeyBag;
end;

class function TPkcsObjectIdentifiers.GetCertBag: IDerObjectIdentifier;
begin
  Result := FCertBag;
end;

class function TPkcsObjectIdentifiers.GetCrlBag: IDerObjectIdentifier;
begin
  Result := FCrlBag;
end;

class function TPkcsObjectIdentifiers.GetSecretBag: IDerObjectIdentifier;
begin
  Result := FSecretBag;
end;

class function TPkcsObjectIdentifiers.GetSafeContentsBag: IDerObjectIdentifier;
begin
  Result := FSafeContentsBag;
end;

class function TPkcsObjectIdentifiers.GetPbeWithShaAnd128BitRC4: IDerObjectIdentifier;
begin
  Result := FPbeWithShaAnd128BitRC4;
end;

class function TPkcsObjectIdentifiers.GetPbeWithShaAnd40BitRC4: IDerObjectIdentifier;
begin
  Result := FPbeWithShaAnd40BitRC4;
end;

class function TPkcsObjectIdentifiers.GetPbeWithShaAnd3KeyTripleDesCbc: IDerObjectIdentifier;
begin
  Result := FPbeWithShaAnd3KeyTripleDesCbc;
end;

class function TPkcsObjectIdentifiers.GetPbeWithShaAnd2KeyTripleDesCbc: IDerObjectIdentifier;
begin
  Result := FPbeWithShaAnd2KeyTripleDesCbc;
end;

class function TPkcsObjectIdentifiers.GetPbeWithShaAnd128BitRC2Cbc: IDerObjectIdentifier;
begin
  Result := FPbeWithShaAnd128BitRC2Cbc;
end;

class function TPkcsObjectIdentifiers.GetPbewithShaAnd40BitRC2Cbc: IDerObjectIdentifier;
begin
  Result := FPbewithShaAnd40BitRC2Cbc;
end;

class constructor TPkcsObjectIdentifiers.PkcsObjectIdentifiers;
begin
  TPkcsObjectIdentifiers.Boot;
end;

end.


