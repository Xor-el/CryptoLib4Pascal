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

unit ClpSignerUtilities;

{$I ..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  Generics.Collections,
  ClpECNRSigner,
  ClpIECNRSigner,
  ClpIDigest,
  ClpDigestUtilities,
  ClpDsaDigestSigner,
  ClpX9ObjectIdentifiers,
  ClpEacObjectIdentifiers,
  ClpBsiObjectIdentifiers,
  ClpTeleTrusTObjectIdentifiers,
  ClpOiwObjectIdentifiers,
  ClpNistObjectIdentifiers,
  ClpCryptoProObjectIdentifiers,
  ClpEdECObjectIdentifiers,
  ClpParameterUtilities,
  ClpIAsymmetricKeyParameter,
  ClpEd25519,
  ClpIEd25519,
  ClpDsaSigner,
  ClpIDsaSigner,
  ClpECDsaSigner,
  ClpIECDsaSigner,
  ClpEd25519Signer,
  ClpIEd25519Signer,
  ClpEd25519CtxSigner,
  ClpIEd25519CtxSigner,
  ClpEd25519PhSigner,
  ClpIEd25519PhSigner,
  ClpISigner,
  ClpISecureRandom,
  ClpIAsn1Objects,
  ClpSignersEncodings,
  ClpSchnorrDigestSigner,
  ClpECSchnorrSipaSigner,
  ClpIECSchnorrSipaSigner,
  ClpRsaDigestSigner,
  ClpIRsaDigestSigner,
  ClpPssSigner,
  ClpIPssSigner,
  ClpGenericSigner,
  ClpIGenericSigner,
  ClpRsaBlindedEngine,
  ClpPkcs1Encoding,
  ClpIPkcs1Encoding,
  ClpPkcsObjectIdentifiers,
  ClpStringUtils,
  ClpCryptoLibTypes;

resourcestring
  SMechanismNil = 'Mechanism Cannot be Nil';
  SAlgorithmNil = 'Algorithm Cannot be Nil';
  SUnRecognizedAlgorithm = 'Signer " %s " not recognised.';

type

  /// <summary>
  /// Signer Utility class contains methods that can not be specifically
  /// grouped into other classes.
  /// </summary>
  TSignerUtilities = class sealed(TObject)

  strict private

  class var

    Falgorithms: TDictionary<String, String>;
    Foids: TDictionary<String, IDerObjectIdentifier>;

    class function GetAlgorithms: TCryptoLibStringArray; static; inline;

    class procedure Boot(); static;
    class constructor CreateSignerUtilities();
    class destructor DestroySignerUtilities();

  public

    /// <summary>
    /// Returns an ObjectIdentifier for a given encoding.
    /// </summary>
    /// <param name="mechanism">A string representation of the encoding.</param>
    /// <returns>A DerObjectIdentifier, null if the OID is not available.</returns>
    // TODO Don't really want to support this
    class function GetObjectIdentifier(mechanism: String): IDerObjectIdentifier;
      static; inline;

    class function GetEncodingName(const oid: IDerObjectIdentifier): String;
      static; inline;

    class function GetSigner(const id: IDerObjectIdentifier): ISigner; overload;
      static; inline;

    class function GetSigner(algorithm: String): ISigner; overload; static;

    class function InitSigner(const algorithm: String; forSigning: Boolean;
      const privateKey: IAsymmetricKeyParameter; const random: ISecureRandom)
      : ISigner; overload; static; inline;

    class function InitSigner(const algorithmOid: IDerObjectIdentifier;
      forSigning: Boolean; const privateKey: IAsymmetricKeyParameter;
      const random: ISecureRandom): ISigner; overload; static; inline;

    class property Algorithms: TCryptoLibStringArray read GetAlgorithms;

  end;

implementation

{ TSignerUtilities }

class procedure TSignerUtilities.Boot;
begin

  Falgorithms := TDictionary<String, String>.Create();
  Foids := TDictionary<String, IDerObjectIdentifier>.Create();

  TX9ObjectIdentifiers.Boot;
  TOiwObjectIdentifiers.Boot;
  TNistObjectIdentifiers.Boot;
  TTeleTrusTObjectIdentifiers.Boot;
  TCryptoProObjectIdentifiers.Boot;
  TEacObjectIdentifiers.Boot;
  TBsiObjectIdentifiers.Boot;
  TEdECObjectIdentifiers.Boot;

  Falgorithms.Add('NONEWITHDSA', 'NONEwithDSA');
  Falgorithms.Add('DSAWITHNONE', 'NONEwithDSA');
  Falgorithms.Add('RAWDSA', 'NONEwithDSA');

  Falgorithms.Add('DSA', 'SHA-1withDSA');
  Falgorithms.Add('DSAWITHSHA1', 'SHA-1withDSA');
  Falgorithms.Add('DSAWITHSHA-1', 'SHA-1withDSA');
  Falgorithms.Add('SHA/DSA', 'SHA-1withDSA');
  Falgorithms.Add('SHA1/DSA', 'SHA-1withDSA');
  Falgorithms.Add('SHA-1/DSA', 'SHA-1withDSA');
  Falgorithms.Add('SHA1WITHDSA', 'SHA-1withDSA');
  Falgorithms.Add('SHA-1WITHDSA', 'SHA-1withDSA');
  Falgorithms.Add(TX9ObjectIdentifiers.IdDsaWithSha1.id, 'SHA-1withDSA');
  Falgorithms.Add(TOiwObjectIdentifiers.DsaWithSha1.id, 'SHA-1withDSA');

  Falgorithms.Add('DSAWITHSHA224', 'SHA-224withDSA');
  Falgorithms.Add('DSAWITHSHA-224', 'SHA-224withDSA');
  Falgorithms.Add('SHA224/DSA', 'SHA-224withDSA');
  Falgorithms.Add('SHA-224/DSA', 'SHA-224withDSA');
  Falgorithms.Add('SHA224WITHDSA', 'SHA-224withDSA');
  Falgorithms.Add('SHA-224WITHDSA', 'SHA-224withDSA');
  Falgorithms.Add(TNistObjectIdentifiers.DsaWithSha224.id, 'SHA-224withDSA');

  Falgorithms.Add('DSAWITHSHA256', 'SHA-256withDSA');
  Falgorithms.Add('DSAWITHSHA-256', 'SHA-256withDSA');
  Falgorithms.Add('SHA256/DSA', 'SHA-256withDSA');
  Falgorithms.Add('SHA-256/DSA', 'SHA-256withDSA');
  Falgorithms.Add('SHA256WITHDSA', 'SHA-256withDSA');
  Falgorithms.Add('SHA-256WITHDSA', 'SHA-256withDSA');
  Falgorithms.Add(TNistObjectIdentifiers.DsaWithSha256.id, 'SHA-256withDSA');

  Falgorithms.Add('DSAWITHSHA384', 'SHA-384withDSA');
  Falgorithms.Add('DSAWITHSHA-384', 'SHA-384withDSA');
  Falgorithms.Add('SHA384/DSA', 'SHA-384withDSA');
  Falgorithms.Add('SHA-384/DSA', 'SHA-384withDSA');
  Falgorithms.Add('SHA384WITHDSA', 'SHA-384withDSA');
  Falgorithms.Add('SHA-384WITHDSA', 'SHA-384withDSA');
  Falgorithms.Add(TNistObjectIdentifiers.DsaWithSha384.id, 'SHA-384withDSA');

  Falgorithms.Add('DSAWITHSHA512', 'SHA-512withDSA');
  Falgorithms.Add('DSAWITHSHA-512', 'SHA-512withDSA');
  Falgorithms.Add('SHA512/DSA', 'SHA-512withDSA');
  Falgorithms.Add('SHA-512/DSA', 'SHA-512withDSA');
  Falgorithms.Add('SHA512WITHDSA', 'SHA-512withDSA');
  Falgorithms.Add('SHA-512WITHDSA', 'SHA-512withDSA');
  Falgorithms.Add(TNistObjectIdentifiers.DsaWithSha512.id, 'SHA-512withDSA');

  Falgorithms.Add('NONEWITHECDSA', 'NONEwithECDSA');
  Falgorithms.Add('ECDSAWITHNONE', 'NONEwithECDSA');

  Falgorithms.Add('ECDSA', 'SHA-1withECDSA');
  Falgorithms.Add('SHA1/ECDSA', 'SHA-1withECDSA');
  Falgorithms.Add('SHA-1/ECDSA', 'SHA-1withECDSA');
  Falgorithms.Add('ECDSAWITHSHA1', 'SHA-1withECDSA');
  Falgorithms.Add('ECDSAWITHSHA-1', 'SHA-1withECDSA');
  Falgorithms.Add('SHA1WITHECDSA', 'SHA-1withECDSA');
  Falgorithms.Add('SHA-1WITHECDSA', 'SHA-1withECDSA');
  Falgorithms.Add(TX9ObjectIdentifiers.ECDsaWithSha1.id, 'SHA-1withECDSA');
  Falgorithms.Add(TTeleTrusTObjectIdentifiers.ECSignWithSha1.id,
    'SHA-1withECDSA');

  Falgorithms.Add('SHA224/ECDSA', 'SHA-224withECDSA');
  Falgorithms.Add('SHA-224/ECDSA', 'SHA-224withECDSA');
  Falgorithms.Add('ECDSAWITHSHA224', 'SHA-224withECDSA');
  Falgorithms.Add('ECDSAWITHSHA-224', 'SHA-224withECDSA');
  Falgorithms.Add('SHA224WITHECDSA', 'SHA-224withECDSA');
  Falgorithms.Add('SHA-224WITHECDSA', 'SHA-224withECDSA');
  Falgorithms.Add(TX9ObjectIdentifiers.ECDsaWithSha224.id, 'SHA-224withECDSA');

  Falgorithms.Add('SHA256/ECDSA', 'SHA-256withECDSA');
  Falgorithms.Add('SHA-256/ECDSA', 'SHA-256withECDSA');
  Falgorithms.Add('ECDSAWITHSHA256', 'SHA-256withECDSA');
  Falgorithms.Add('ECDSAWITHSHA-256', 'SHA-256withECDSA');
  Falgorithms.Add('SHA256WITHECDSA', 'SHA-256withECDSA');
  Falgorithms.Add('SHA-256WITHECDSA', 'SHA-256withECDSA');
  Falgorithms.Add(TX9ObjectIdentifiers.ECDsaWithSha256.id, 'SHA-256withECDSA');

  Falgorithms.Add('SHA384/ECDSA', 'SHA-384withECDSA');
  Falgorithms.Add('SHA-384/ECDSA', 'SHA-384withECDSA');
  Falgorithms.Add('ECDSAWITHSHA384', 'SHA-384withECDSA');
  Falgorithms.Add('ECDSAWITHSHA-384', 'SHA-384withECDSA');
  Falgorithms.Add('SHA384WITHECDSA', 'SHA-384withECDSA');
  Falgorithms.Add('SHA-384WITHECDSA', 'SHA-384withECDSA');
  Falgorithms.Add(TX9ObjectIdentifiers.ECDsaWithSha384.id, 'SHA-384withECDSA');

  Falgorithms.Add('SHA512/ECDSA', 'SHA-512withECDSA');
  Falgorithms.Add('SHA-512/ECDSA', 'SHA-512withECDSA');
  Falgorithms.Add('ECDSAWITHSHA512', 'SHA-512withECDSA');
  Falgorithms.Add('ECDSAWITHSHA-512', 'SHA-512withECDSA');
  Falgorithms.Add('SHA512WITHECDSA', 'SHA-512withECDSA');
  Falgorithms.Add('SHA-512WITHECDSA', 'SHA-512withECDSA');
  Falgorithms.Add(TX9ObjectIdentifiers.ECDsaWithSha512.id, 'SHA-512withECDSA');

  Falgorithms.Add('RIPEMD160/ECDSA', 'RIPEMD160withECDSA');
  Falgorithms.Add('ECDSAWITHRIPEMD160', 'RIPEMD160withECDSA');
  Falgorithms.Add('RIPEMD160WITHECDSA', 'RIPEMD160withECDSA');
  Falgorithms.Add(TTeleTrusTObjectIdentifiers.ECSignWithRipeMD160.id,
    'RIPEMD160withECDSA');

  Falgorithms.Add('NONEWITHCVC-ECDSA', 'NONEwithCVC-ECDSA');
  Falgorithms.Add('CVC-ECDSAWITHNONE', 'NONEwithCVC-ECDSA');
  Falgorithms.Add('SHA1/CVC-ECDSA', 'SHA-1withCVC-ECDSA');
  Falgorithms.Add('SHA-1/CVC-ECDSA', 'SHA-1withCVC-ECDSA');
  Falgorithms.Add('CVC-ECDSAWITHSHA1', 'SHA-1withCVC-ECDSA');
  Falgorithms.Add('CVC-ECDSAWITHSHA-1', 'SHA-1withCVC-ECDSA');
  Falgorithms.Add('SHA1WITHCVC-ECDSA', 'SHA-1withCVC-ECDSA');
  Falgorithms.Add('SHA-1WITHCVC-ECDSA', 'SHA-1withCVC-ECDSA');
  Falgorithms.Add(TEacObjectIdentifiers.id_TA_ECDSA_SHA_1.id,
    'SHA-1withCVC-ECDSA');
  Falgorithms.Add('SHA224/CVC-ECDSA', 'SHA-224withCVC-ECDSA');
  Falgorithms.Add('SHA-224/CVC-ECDSA', 'SHA-224withCVC-ECDSA');
  Falgorithms.Add('CVC-ECDSAWITHSHA224', 'SHA-224withCVC-ECDSA');
  Falgorithms.Add('CVC-ECDSAWITHSHA-224', 'SHA-224withCVC-ECDSA');
  Falgorithms.Add('SHA224WITHCVC-ECDSA', 'SHA-224withCVC-ECDSA');
  Falgorithms.Add('SHA-224WITHCVC-ECDSA', 'SHA-224withCVC-ECDSA');
  Falgorithms.Add(TEacObjectIdentifiers.id_TA_ECDSA_SHA_224.id,
    'SHA-224withCVC-ECDSA');
  Falgorithms.Add('SHA256/CVC-ECDSA', 'SHA-256withCVC-ECDSA');
  Falgorithms.Add('SHA-256/CVC-ECDSA', 'SHA-256withCVC-ECDSA');
  Falgorithms.Add('CVC-ECDSAWITHSHA256', 'SHA-256withCVC-ECDSA');
  Falgorithms.Add('CVC-ECDSAWITHSHA-256', 'SHA-256withCVC-ECDSA');
  Falgorithms.Add('SHA256WITHCVC-ECDSA', 'SHA-256withCVC-ECDSA');
  Falgorithms.Add('SHA-256WITHCVC-ECDSA', 'SHA-256withCVC-ECDSA');
  Falgorithms.Add(TEacObjectIdentifiers.id_TA_ECDSA_SHA_256.id,
    'SHA-256withCVC-ECDSA');
  Falgorithms.Add('SHA384/CVC-ECDSA', 'SHA-384withCVC-ECDSA');
  Falgorithms.Add('SHA-384/CVC-ECDSA', 'SHA-384withCVC-ECDSA');
  Falgorithms.Add('CVC-ECDSAWITHSHA384', 'SHA-384withCVC-ECDSA');
  Falgorithms.Add('CVC-ECDSAWITHSHA-384', 'SHA-384withCVC-ECDSA');
  Falgorithms.Add('SHA384WITHCVC-ECDSA', 'SHA-384withCVC-ECDSA');
  Falgorithms.Add('SHA-384WITHCVC-ECDSA', 'SHA-384withCVC-ECDSA');
  Falgorithms.Add(TEacObjectIdentifiers.id_TA_ECDSA_SHA_384.id,
    'SHA-384withCVC-ECDSA');
  Falgorithms.Add('SHA512/CVC-ECDSA', 'SHA-512withCVC-ECDSA');
  Falgorithms.Add('SHA-512/CVC-ECDSA', 'SHA-512withCVC-ECDSA');
  Falgorithms.Add('CVC-ECDSAWITHSHA512', 'SHA-512withCVC-ECDSA');
  Falgorithms.Add('CVC-ECDSAWITHSHA-512', 'SHA-512withCVC-ECDSA');
  Falgorithms.Add('SHA512WITHCVC-ECDSA', 'SHA-512withCVC-ECDSA');
  Falgorithms.Add('SHA-512WITHCVC-ECDSA', 'SHA-512withCVC-ECDSA');
  Falgorithms.Add(TEacObjectIdentifiers.id_TA_ECDSA_SHA_512.id,
    'SHA-512withCVC-ECDSA');
  Falgorithms.Add('NONEWITHPLAIN-ECDSA', 'NONEwithPLAIN-ECDSA');
  Falgorithms.Add('PLAIN-ECDSAWITHNONE', 'NONEwithPLAIN-ECDSA');
  Falgorithms.Add('SHA1/PLAIN-ECDSA', 'SHA-1withPLAIN-ECDSA');
  Falgorithms.Add('SHA-1/PLAIN-ECDSA', 'SHA-1withPLAIN-ECDSA');
  Falgorithms.Add('PLAIN-ECDSAWITHSHA1', 'SHA-1withPLAIN-ECDSA');
  Falgorithms.Add('PLAIN-ECDSAWITHSHA-1', 'SHA-1withPLAIN-ECDSA');
  Falgorithms.Add('SHA1WITHPLAIN-ECDSA', 'SHA-1withPLAIN-ECDSA');
  Falgorithms.Add('SHA-1WITHPLAIN-ECDSA', 'SHA-1withPLAIN-ECDSA');
  Falgorithms.Add(TBsiObjectIdentifiers.ecdsa_plain_SHA1.id,
    'SHA-1withPLAIN-ECDSA');
  Falgorithms.Add('SHA224/PLAIN-ECDSA', 'SHA-224withPLAIN-ECDSA');
  Falgorithms.Add('SHA-224/PLAIN-ECDSA', 'SHA-224withPLAIN-ECDSA');
  Falgorithms.Add('PLAIN-ECDSAWITHSHA224', 'SHA-224withPLAIN-ECDSA');
  Falgorithms.Add('PLAIN-ECDSAWITHSHA-224', 'SHA-224withPLAIN-ECDSA');
  Falgorithms.Add('SHA224WITHPLAIN-ECDSA', 'SHA-224withPLAIN-ECDSA');
  Falgorithms.Add('SHA-224WITHPLAIN-ECDSA', 'SHA-224withPLAIN-ECDSA');
  Falgorithms.Add(TBsiObjectIdentifiers.ecdsa_plain_SHA224.id,
    'SHA-224withPLAIN-ECDSA');
  Falgorithms.Add('SHA256/PLAIN-ECDSA', 'SHA-256withPLAIN-ECDSA');
  Falgorithms.Add('SHA-256/PLAIN-ECDSA', 'SHA-256withPLAIN-ECDSA');
  Falgorithms.Add('PLAIN-ECDSAWITHSHA256', 'SHA-256withPLAIN-ECDSA');
  Falgorithms.Add('PLAIN-ECDSAWITHSHA-256', 'SHA-256withPLAIN-ECDSA');
  Falgorithms.Add('SHA256WITHPLAIN-ECDSA', 'SHA-256withPLAIN-ECDSA');
  Falgorithms.Add('SHA-256WITHPLAIN-ECDSA', 'SHA-256withPLAIN-ECDSA');
  Falgorithms.Add(TBsiObjectIdentifiers.ecdsa_plain_SHA256.id,
    'SHA-256withPLAIN-ECDSA');
  Falgorithms.Add('SHA384/PLAIN-ECDSA', 'SHA-384withPLAIN-ECDSA');
  Falgorithms.Add('SHA-384/PLAIN-ECDSA', 'SHA-384withPLAIN-ECDSA');
  Falgorithms.Add('PLAIN-ECDSAWITHSHA384', 'SHA-384withPLAIN-ECDSA');
  Falgorithms.Add('PLAIN-ECDSAWITHSHA-384', 'SHA-384withPLAIN-ECDSA');
  Falgorithms.Add('SHA384WITHPLAIN-ECDSA', 'SHA-384withPLAIN-ECDSA');
  Falgorithms.Add('SHA-384WITHPLAIN-ECDSA', 'SHA-384withPLAIN-ECDSA');
  Falgorithms.Add(TBsiObjectIdentifiers.ecdsa_plain_SHA384.id,
    'SHA-384withPLAIN-ECDSA');
  Falgorithms.Add('SHA512/PLAIN-ECDSA', 'SHA-512withPLAIN-ECDSA');
  Falgorithms.Add('SHA-512/PLAIN-ECDSA', 'SHA-512withPLAIN-ECDSA');
  Falgorithms.Add('PLAIN-ECDSAWITHSHA512', 'SHA-512withPLAIN-ECDSA');
  Falgorithms.Add('PLAIN-ECDSAWITHSHA-512', 'SHA-512withPLAIN-ECDSA');
  Falgorithms.Add('SHA512WITHPLAIN-ECDSA', 'SHA-512withPLAIN-ECDSA');
  Falgorithms.Add('SHA-512WITHPLAIN-ECDSA', 'SHA-512withPLAIN-ECDSA');
  Falgorithms.Add(TBsiObjectIdentifiers.ecdsa_plain_SHA512.id,
    'SHA-512withPLAIN-ECDSA');
  Falgorithms.Add('RIPEMD160/PLAIN-ECDSA', 'RIPEMD160withPLAIN-ECDSA');
  Falgorithms.Add('PLAIN-ECDSAWITHRIPEMD160', 'RIPEMD160withPLAIN-ECDSA');
  Falgorithms.Add('RIPEMD160WITHPLAIN-ECDSA', 'RIPEMD160withPLAIN-ECDSA');
  Falgorithms.Add(TBsiObjectIdentifiers.ecdsa_plain_RIPEMD160.id,
    'RIPEMD160withPLAIN-ECDSA');
  Falgorithms.Add('SHA1WITHECNR', 'SHA-1withECNR');
  Falgorithms.Add('SHA-1WITHECNR', 'SHA-1withECNR');
  Falgorithms.Add('SHA224WITHECNR', 'SHA-224withECNR');
  Falgorithms.Add('SHA-224WITHECNR', 'SHA-224withECNR');
  Falgorithms.Add('SHA256WITHECNR', 'SHA-256withECNR');
  Falgorithms.Add('SHA-256WITHECNR', 'SHA-256withECNR');
  Falgorithms.Add('SHA384WITHECNR', 'SHA-384withECNR');
  Falgorithms.Add('SHA-384WITHECNR', 'SHA-384withECNR');
  Falgorithms.Add('SHA512WITHECNR', 'SHA-512withECNR');
  Falgorithms.Add('SHA-512WITHECNR', 'SHA-512withECNR');



  // Falgorithms.Add('GOST-3410', 'GOST3410');
  // Falgorithms.Add('GOST-3410-94', 'GOST3410');
  // Falgorithms.Add('GOST3411WITHGOST3410', 'GOST3410');
  // Falgorithms.Add(TCryptoProObjectIdentifiers.GostR3411x94WithGostR3410x94.id,
  // 'GOST3410');

  // Falgorithms.Add('ECGOST-3410', 'ECGOST3410');
  // Falgorithms.Add('ECGOST-3410-2001', 'ECGOST3410');
  // Falgorithms.Add('GOST3411WITHECGOST3410', 'ECGOST3410');
  // Falgorithms.Add(TCryptoProObjectIdentifiers.GostR3411x94WithGostR3410x2001.id,
  // 'ECGOST3410');

  // ED25519
  Falgorithms.Add('ED25519', 'Ed25519');
  Falgorithms.Add(TEdECObjectIdentifiers.id_Ed25519.id, 'Ed25519');
  Falgorithms.Add('ED25519CTX', 'Ed25519ctx');
  Falgorithms.Add('ED25519PH', 'Ed25519ph');

  // ED25519Blake2B
  Falgorithms.Add('ED25519BLAKE2B', 'Ed25519Blake2B');
  Falgorithms.Add('ED25519BLAKE2BCTX', 'Ed25519Blake2Bctx');
  Falgorithms.Add('ED25519BLAKE2BPH', 'Ed25519Blake2Bph');

  // RSA
  TPkcsObjectIdentifiers.Boot;
  Falgorithms.Add('RSA', 'SHA-1withRSA');
  Falgorithms.Add('RSAWITHSHA1', 'SHA-1withRSA');
  Falgorithms.Add('RSAWITHSHA-1', 'SHA-1withRSA');
  Falgorithms.Add('SHA1/RSA', 'SHA-1withRSA');
  Falgorithms.Add('SHA-1/RSA', 'SHA-1withRSA');
  Falgorithms.Add('SHA1WITHRSA', 'SHA-1withRSA');
  Falgorithms.Add('SHA-1WITHRSA', 'SHA-1withRSA');
  Falgorithms.Add(TPkcsObjectIdentifiers.Sha1WithRsaEncryption.id, 'SHA-1withRSA');

  Falgorithms.Add('SHA224/RSA', 'SHA-224withRSA');
  Falgorithms.Add('SHA-224/RSA', 'SHA-224withRSA');
  Falgorithms.Add('SHA224WITHRSA', 'SHA-224withRSA');
  Falgorithms.Add('SHA-224WITHRSA', 'SHA-224withRSA');
  Falgorithms.Add(TPkcsObjectIdentifiers.Sha224WithRsaEncryption.id, 'SHA-224withRSA');

  Falgorithms.Add('SHA256/RSA', 'SHA-256withRSA');
  Falgorithms.Add('SHA-256/RSA', 'SHA-256withRSA');
  Falgorithms.Add('SHA256WITHRSA', 'SHA-256withRSA');
  Falgorithms.Add('SHA-256WITHRSA', 'SHA-256withRSA');
  Falgorithms.Add(TPkcsObjectIdentifiers.Sha256WithRsaEncryption.id, 'SHA-256withRSA');

  Falgorithms.Add('SHA384/RSA', 'SHA-384withRSA');
  Falgorithms.Add('SHA-384/RSA', 'SHA-384withRSA');
  Falgorithms.Add('SHA384WITHRSA', 'SHA-384withRSA');
  Falgorithms.Add('SHA-384WITHRSA', 'SHA-384withRSA');
  Falgorithms.Add(TPkcsObjectIdentifiers.Sha384WithRsaEncryption.id, 'SHA-384withRSA');

  Falgorithms.Add('SHA512/RSA', 'SHA-512withRSA');
  Falgorithms.Add('SHA-512/RSA', 'SHA-512withRSA');
  Falgorithms.Add('SHA512WITHRSA', 'SHA-512withRSA');
  Falgorithms.Add('SHA-512WITHRSA', 'SHA-512withRSA');
  Falgorithms.Add(TPkcsObjectIdentifiers.Sha512WithRsaEncryption.id, 'SHA-512withRSA');

  Falgorithms.Add('MD5/RSA', 'MD5withRSA');
  Falgorithms.Add('MD5WITHRSA', 'MD5withRSA');
  Falgorithms.Add(TPkcsObjectIdentifiers.MD5WithRsaEncryption.id, 'MD5withRSA');

  Falgorithms.Add('RIPEMD160/RSA', 'RIPEMD160withRSA');
  Falgorithms.Add('RIPEMD160WITHRSA', 'RIPEMD160withRSA');
  Falgorithms.Add('RIPEMD160WITHRSAENCRYPTION', 'RIPEMD160withRSA');
  Falgorithms.Add(TTeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD160.id, 'RIPEMD160withRSA');

  Falgorithms.Add('RIPEMD128WITHRSA', 'RIPEMD128withRSA');
  Falgorithms.Add('RIPEMD128WITHRSAENCRYPTION', 'RIPEMD128withRSA');
  Falgorithms.Add(TTeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD128.id, 'RIPEMD128withRSA');

  Falgorithms.Add('RIPEMD256WITHRSA', 'RIPEMD256withRSA');
  Falgorithms.Add('RIPEMD256WITHRSAENCRYPTION', 'RIPEMD256withRSA');
  Falgorithms.Add(TTeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD256.id, 'RIPEMD256withRSA');

  // MD2/MD4 with RSA
  Falgorithms.Add('MD2WITHRSA', 'MD2withRSA');
  Falgorithms.Add('MD2WITHRSAENCRYPTION', 'MD2withRSA');
  Falgorithms.Add(TPkcsObjectIdentifiers.MD2WithRsaEncryption.id, 'MD2withRSA');

  Falgorithms.Add('MD4WITHRSA', 'MD4withRSA');
  Falgorithms.Add('MD4WITHRSAENCRYPTION', 'MD4withRSA');
  Falgorithms.Add(TPkcsObjectIdentifiers.MD4WithRsaEncryption.id, 'MD4withRSA');

  // Extended MD5 with RSA aliases
  Falgorithms.Add('MD5WITHRSAENCRYPTION', 'MD5withRSA');

  // Extended SHA with RSA aliases
  Falgorithms.Add('SHA1WITHRSAENCRYPTION', 'SHA-1withRSA');
  Falgorithms.Add('SHA-1WITHRSAENCRYPTION', 'SHA-1withRSA');
  Falgorithms.Add('SHA224WITHRSAENCRYPTION', 'SHA-224withRSA');
  Falgorithms.Add('SHA-224WITHRSAENCRYPTION', 'SHA-224withRSA');
  Falgorithms.Add('SHA256WITHRSAENCRYPTION', 'SHA-256withRSA');
  Falgorithms.Add('SHA-256WITHRSAENCRYPTION', 'SHA-256withRSA');
  Falgorithms.Add('SHA384WITHRSAENCRYPTION', 'SHA-384withRSA');
  Falgorithms.Add('SHA-384WITHRSAENCRYPTION', 'SHA-384withRSA');
  Falgorithms.Add('SHA512WITHRSAENCRYPTION', 'SHA-512withRSA');
  Falgorithms.Add('SHA-512WITHRSAENCRYPTION', 'SHA-512withRSA');

  // SHA-512/224 and SHA-512/256 with RSA
  Falgorithms.Add('SHA512(224)WITHRSA', 'SHA-512(224)withRSA');
  Falgorithms.Add('SHA-512(224)WITHRSA', 'SHA-512(224)withRSA');
  Falgorithms.Add('SHA512(224)WITHRSAENCRYPTION', 'SHA-512(224)withRSA');
  Falgorithms.Add('SHA-512(224)WITHRSAENCRYPTION', 'SHA-512(224)withRSA');
  Falgorithms.Add(TPkcsObjectIdentifiers.Sha512_224WithRSAEncryption.id, 'SHA-512(224)withRSA');

  Falgorithms.Add('SHA512(256)WITHRSA', 'SHA-512(256)withRSA');
  Falgorithms.Add('SHA-512(256)WITHRSA', 'SHA-512(256)withRSA');
  Falgorithms.Add('SHA512(256)WITHRSAENCRYPTION', 'SHA-512(256)withRSA');
  Falgorithms.Add('SHA-512(256)WITHRSAENCRYPTION', 'SHA-512(256)withRSA');
  Falgorithms.Add(TPkcsObjectIdentifiers.Sha512_256WithRSAEncryption.id, 'SHA-512(256)withRSA');

  // PSS / RSA-OAEP signatures
  Falgorithms.Add('PSSWITHRSA', 'PSSwithRSA');
  Falgorithms.Add('RSASSA-PSS', 'PSSwithRSA');
  Falgorithms.Add('RSAPSS', 'PSSwithRSA');
  Falgorithms.Add(TPkcsObjectIdentifiers.IdRsassaPss.id, 'PSSwithRSA');

  Falgorithms.Add('SHA1WITHRSAANDMGF1', 'SHA-1withRSAandMGF1');
  Falgorithms.Add('SHA-1WITHRSAANDMGF1', 'SHA-1withRSAandMGF1');
  Falgorithms.Add('SHA1WITHRSA/PSS', 'SHA-1withRSAandMGF1');
  Falgorithms.Add('SHA-1WITHRSA/PSS', 'SHA-1withRSAandMGF1');
  Falgorithms.Add('SHA1WITHRSASSA-PSS', 'SHA-1withRSAandMGF1');
  Falgorithms.Add('SHA-1WITHRSASSA-PSS', 'SHA-1withRSAandMGF1');

  Falgorithms.Add('SHA224WITHRSAANDMGF1', 'SHA-224withRSAandMGF1');
  Falgorithms.Add('SHA-224WITHRSAANDMGF1', 'SHA-224withRSAandMGF1');
  Falgorithms.Add('SHA224WITHRSA/PSS', 'SHA-224withRSAandMGF1');
  Falgorithms.Add('SHA-224WITHRSA/PSS', 'SHA-224withRSAandMGF1');
  Falgorithms.Add('SHA224WITHRSASSA-PSS', 'SHA-224withRSAandMGF1');
  Falgorithms.Add('SHA-224WITHRSASSA-PSS', 'SHA-224withRSAandMGF1');

  Falgorithms.Add('SHA256WITHRSAANDMGF1', 'SHA-256withRSAandMGF1');
  Falgorithms.Add('SHA-256WITHRSAANDMGF1', 'SHA-256withRSAandMGF1');
  Falgorithms.Add('SHA256WITHRSA/PSS', 'SHA-256withRSAandMGF1');
  Falgorithms.Add('SHA-256WITHRSA/PSS', 'SHA-256withRSAandMGF1');
  Falgorithms.Add('SHA256WITHRSASSA-PSS', 'SHA-256withRSAandMGF1');
  Falgorithms.Add('SHA-256WITHRSASSA-PSS', 'SHA-256withRSAandMGF1');

  Falgorithms.Add('SHA384WITHRSAANDMGF1', 'SHA-384withRSAandMGF1');
  Falgorithms.Add('SHA-384WITHRSAANDMGF1', 'SHA-384withRSAandMGF1');
  Falgorithms.Add('SHA384WITHRSA/PSS', 'SHA-384withRSAandMGF1');
  Falgorithms.Add('SHA-384WITHRSA/PSS', 'SHA-384withRSAandMGF1');
  Falgorithms.Add('SHA384WITHRSASSA-PSS', 'SHA-384withRSAandMGF1');
  Falgorithms.Add('SHA-384WITHRSASSA-PSS', 'SHA-384withRSAandMGF1');

  Falgorithms.Add('SHA512WITHRSAANDMGF1', 'SHA-512withRSAandMGF1');
  Falgorithms.Add('SHA-512WITHRSAANDMGF1', 'SHA-512withRSAandMGF1');
  Falgorithms.Add('SHA512WITHRSA/PSS', 'SHA-512withRSAandMGF1');
  Falgorithms.Add('SHA-512WITHRSA/PSS', 'SHA-512withRSAandMGF1');
  Falgorithms.Add('SHA512WITHRSASSA-PSS', 'SHA-512withRSAandMGF1');
  Falgorithms.Add('SHA-512WITHRSASSA-PSS', 'SHA-512withRSAandMGF1');

  // Raw RSA (NONEWITHRSA) and raw PSS
  Falgorithms.Add('NONEWITHRSA', 'RSA');
  Falgorithms.Add('RSAWITHNONE', 'RSA');
  Falgorithms.Add('RAWRSA', 'RSA');

  Falgorithms.Add('RAWRSAPSS', 'RAWRSASSA-PSS');
  Falgorithms.Add('NONEWITHRSAPSS', 'RAWRSASSA-PSS');
  Falgorithms.Add('NONEWITHRSASSA-PSS', 'RAWRSASSA-PSS');

  // ECSCHNORR SIPA

  Falgorithms.Add('SHA1/ECSCHNORR/SIPA', 'SHA-1withECSCHNORRSIPA');
  Falgorithms.Add('SHA-1/ECSCHNORR/SIPA', 'SHA-1withECSCHNORRSIPA');
  Falgorithms.Add('ECSCHNORRSIPAWITHSHA1', 'SHA-1withECSCHNORRSIPA');
  Falgorithms.Add('ECSCHNORRSIPAWITHSHA-1', 'SHA-1withECSCHNORRSIPA');
  Falgorithms.Add('SHA1WITHECSCHNORRSIPA', 'SHA-1withECSCHNORRSIPA');
  Falgorithms.Add('SHA-1WITHECSCHNORRSIPA', 'SHA-1withECSCHNORRSIPA');

  Falgorithms.Add('SHA224/ECSCHNORR/SIPA', 'SHA-224withECSCHNORRSIPA');
  Falgorithms.Add('SHA-224/ECSCHNORR/SIPA', 'SHA-224withECSCHNORRSIPA');
  Falgorithms.Add('ECSCHNORRSIPAWITHSHA224', 'SHA-224withECSCHNORRSIPA');
  Falgorithms.Add('ECSCHNORRSIPAWITHSHA-224', 'SHA-224withECSCHNORRSIPA');
  Falgorithms.Add('SHA224WITHECSCHNORRSIPA', 'SHA-224withECSCHNORRSIPA');
  Falgorithms.Add('SHA-224WITHECSCHNORRSIPA', 'SHA-224withECSCHNORRSIPA');

  Falgorithms.Add('SHA256/ECSCHNORR/SIPA', 'SHA-256withECSCHNORRSIPA');
  Falgorithms.Add('SHA-256/ECSCHNORR/SIPA', 'SHA-256withECSCHNORRSIPA');
  Falgorithms.Add('ECSCHNORRSIPAWITHSHA256', 'SHA-256withECSCHNORRSIPA');
  Falgorithms.Add('ECSCHNORRSIPAWITHSHA-256', 'SHA-256withECSCHNORRSIPA');
  Falgorithms.Add('SHA256WITHECSCHNORRSIPA', 'SHA-256withECSCHNORRSIPA');
  Falgorithms.Add('SHA-256WITHECSCHNORRSIPA', 'SHA-256withECSCHNORRSIPA');

  Falgorithms.Add('SHA384/ECSCHNORR/SIPA', 'SHA-384withECSCHNORRSIPA');
  Falgorithms.Add('SHA-384/ECSCHNORR/SIPA', 'SHA-384withECSCHNORRSIPA');
  Falgorithms.Add('ECSCHNORRSIPAWITHSHA384', 'SHA-384withECSCHNORRSIPA');
  Falgorithms.Add('ECSCHNORRSIPAWITHSHA-384', 'SHA-384withECSCHNORRSIPA');
  Falgorithms.Add('SHA384WITHECSCHNORRSIPA', 'SHA-384withECSCHNORRSIPA');
  Falgorithms.Add('SHA-384WITHECSCHNORRSIPA', 'SHA-384withECSCHNORRSIPA');

  Falgorithms.Add('SHA512/ECSCHNORR/SIPA', 'SHA-512withECSCHNORRSIPA');
  Falgorithms.Add('SHA-512/ECSCHNORR/SIPA', 'SHA-512withECSCHNORRSIPA');
  Falgorithms.Add('ECSCHNORRSIPAWITHSHA512', 'SHA-512withECSCHNORRSIPA');
  Falgorithms.Add('ECSCHNORRSIPAWITHSHA-512', 'SHA-512withECSCHNORRSIPA');
  Falgorithms.Add('SHA512WITHECSCHNORRSIPA', 'SHA-512withECSCHNORRSIPA');
  Falgorithms.Add('SHA-512WITHECSCHNORRSIPA', 'SHA-512withECSCHNORRSIPA');

  Falgorithms.Add('RIPEMD160/ECSCHNORR/SIPA', 'RIPEMD160withECSCHNORRSIPA');
  Falgorithms.Add('ECSCHNORRSIPAWITHRIPEMD160', 'RIPEMD160withECSCHNORRSIPA');
  Falgorithms.Add('RIPEMD160WITHECSCHNORRSIPA', 'RIPEMD160withECSCHNORRSIPA');

  Foids.Add('SHA-1withDSA', TX9ObjectIdentifiers.IdDsaWithSha1);

  Foids.Add('SHA-1withECDSA', TX9ObjectIdentifiers.ECDsaWithSha1);
  Foids.Add('SHA-224withECDSA', TX9ObjectIdentifiers.ECDsaWithSha224);
  Foids.Add('SHA-256withECDSA', TX9ObjectIdentifiers.ECDsaWithSha256);
  Foids.Add('SHA-384withECDSA', TX9ObjectIdentifiers.ECDsaWithSha384);
  Foids.Add('SHA-512withECDSA', TX9ObjectIdentifiers.ECDsaWithSha512);

  Foids.Add('RIPEMD160withECDSA',
    TTeleTrusTObjectIdentifiers.ECSignWithRipeMD160);
  Foids.Add('SHA-1withCVC-ECDSA', TEacObjectIdentifiers.id_TA_ECDSA_SHA_1);
  Foids.Add('SHA-224withCVC-ECDSA', TEacObjectIdentifiers.id_TA_ECDSA_SHA_224);
  Foids.Add('SHA-256withCVC-ECDSA', TEacObjectIdentifiers.id_TA_ECDSA_SHA_256);
  Foids.Add('SHA-384withCVC-ECDSA', TEacObjectIdentifiers.id_TA_ECDSA_SHA_384);
  Foids.Add('SHA-512withCVC-ECDSA', TEacObjectIdentifiers.id_TA_ECDSA_SHA_512);
  Foids.Add('SHA-1withPLAIN-ECDSA', TBsiObjectIdentifiers.ecdsa_plain_SHA1);
  Foids.Add('SHA-224withPLAIN-ECDSA', TBsiObjectIdentifiers.ecdsa_plain_SHA224);
  Foids.Add('SHA-256withPLAIN-ECDSA', TBsiObjectIdentifiers.ecdsa_plain_SHA256);
  Foids.Add('SHA-384withPLAIN-ECDSA', TBsiObjectIdentifiers.ecdsa_plain_SHA384);
  Foids.Add('SHA-512withPLAIN-ECDSA', TBsiObjectIdentifiers.ecdsa_plain_SHA512);
  Foids.Add('RIPEMD160withPLAIN-ECDSA',
    TBsiObjectIdentifiers.ecdsa_plain_RIPEMD160);

  // Foids.Add('GOST3410',
  // TCryptoProObjectIdentifiers.GostR3411x94WithGostR3410x94);
  //
  // Foids.Add('ECGOST3410',
  // TCryptoProObjectIdentifiers.GostR3411x94WithGostR3410x2001);

  Foids.Add('Ed25519', TEdECObjectIdentifiers.id_Ed25519);

  // RSA signature OIDs
  Foids.Add('MD2withRSA', TPkcsObjectIdentifiers.MD2WithRsaEncryption);
  Foids.Add('MD4withRSA', TPkcsObjectIdentifiers.MD4WithRsaEncryption);
  Foids.Add('MD5withRSA', TPkcsObjectIdentifiers.MD5WithRsaEncryption);
  Foids.Add('SHA-1withRSA', TPkcsObjectIdentifiers.Sha1WithRsaEncryption);
  Foids.Add('SHA-224withRSA', TPkcsObjectIdentifiers.Sha224WithRsaEncryption);
  Foids.Add('SHA-256withRSA', TPkcsObjectIdentifiers.Sha256WithRsaEncryption);
  Foids.Add('SHA-384withRSA', TPkcsObjectIdentifiers.Sha384WithRsaEncryption);
  Foids.Add('SHA-512withRSA', TPkcsObjectIdentifiers.Sha512WithRsaEncryption);
  Foids.Add('SHA-512(224)withRSA', TPkcsObjectIdentifiers.Sha512_224WithRSAEncryption);
  Foids.Add('SHA-512(256)withRSA', TPkcsObjectIdentifiers.Sha512_256WithRSAEncryption);

  Foids.Add('RIPEMD128withRSA', TTeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD128);
  Foids.Add('RIPEMD160withRSA', TTeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD160);
  Foids.Add('RIPEMD256withRSA', TTeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD256);
end;

class constructor TSignerUtilities.CreateSignerUtilities;
begin
  TSignerUtilities.Boot;
end;

class destructor TSignerUtilities.DestroySignerUtilities;
begin
  Falgorithms.Free;
  Foids.Free;
end;

class function TSignerUtilities.GetAlgorithms: TCryptoLibStringArray;
begin
  Result := Foids.Keys.ToArray;
end;

class function TSignerUtilities.GetEncodingName
  (const oid: IDerObjectIdentifier): String;
begin
  Falgorithms.TryGetValue(oid.id, Result);
end;

class function TSignerUtilities.GetObjectIdentifier(mechanism: String)
  : IDerObjectIdentifier;
var
  aliased: string;
begin
  if (mechanism = '') then
  begin
    raise EArgumentNilCryptoLibException.CreateRes(@SMechanismNil);
  end;

  mechanism := UpperCase(mechanism);
  if (Falgorithms.TryGetValue(mechanism, aliased)) then
  begin
    mechanism := aliased;
  end;

  Foids.TryGetValue(mechanism, Result);
end;

class function TSignerUtilities.GetSigner
  (const id: IDerObjectIdentifier): ISigner;
begin
  Result := GetSigner(id.id);
end;

class function TSignerUtilities.GetSigner(algorithm: String): ISigner;
var
  mechanism, DigestName: string;
  DigestInstance: IDigest;
begin
  if (algorithm = '') then
  begin
    raise EArgumentNilCryptoLibException.CreateRes(@SAlgorithmNil);
  end;

  algorithm := UpperCase(algorithm);

  if (not Falgorithms.TryGetValue(algorithm, mechanism)) then
  begin
    mechanism := algorithm;
  end;

  if (TStringUtils.BeginsWith(mechanism, 'Ed25519', True)) then
  begin
    if TStringUtils.EndsWith(mechanism, 'Blake2B', True) then
    begin
      if (mechanism = 'Ed25519Blake2B') then
      begin
        Result := TEd25519Signer.Create(TEd25519Blake2B.Create()
          as IEd25519Blake2B) as IEd25519Signer;
        Exit;
      end;
      if (mechanism = 'Ed25519ctxBlake2B') then
      begin
        Result := TEd25519ctxSigner.Create(TEd25519Blake2B.Create()
          as IEd25519Blake2B, Nil) as IEd25519ctxSigner;
        Exit;
      end;
      if (mechanism = 'Ed25519phBlake2B') then
      begin
        Result := TEd25519phSigner.Create(TEd25519Blake2B.Create()
          as IEd25519Blake2B, Nil) as IEd25519phSigner;
        Exit;
      end;
    end
    else
    begin
      if (mechanism = 'Ed25519') then
      begin
        Result := TEd25519Signer.Create(TEd25519.Create() as IEd25519)
          as IEd25519Signer;
        Exit;
      end;
      if (mechanism = 'Ed25519ctx') then
      begin
        Result := TEd25519ctxSigner.Create(TEd25519.Create() as IEd25519, Nil)
          as IEd25519ctxSigner;
        Exit;
      end;
      if (mechanism = 'Ed25519ph') then
      begin
        Result := TEd25519phSigner.Create(TEd25519.Create() as IEd25519, Nil)
          as IEd25519phSigner;
        Exit;
      end;
    end;
  end;

  if TStringUtils.EndsWith(mechanism, 'withDSA', True) then
  begin
    DigestName := System.Copy(mechanism, 1, TStringUtils.LastIndexOf(mechanism,
      'with', True));

    DigestInstance := TDigestUtilities.GetDigest(DigestName);
    Result := (TDsaDigestSigner.Create(TDsaSigner.Create() as IDsaSigner,
      DigestInstance));
    Exit;
  end;

  if TStringUtils.EndsWith(mechanism, 'withECDSA', false) then
  begin
    DigestName := System.Copy(mechanism, 1, TStringUtils.LastIndexOf(mechanism,
      'with', True));

    DigestInstance := TDigestUtilities.GetDigest(DigestName);
    Result := (TDsaDigestSigner.Create(TECDsaSigner.Create() as IECDsaSigner,
      DigestInstance));
    Exit;
  end;

  if (TStringUtils.EndsWith(mechanism, 'withCVC-ECDSA', True) or
    TStringUtils.EndsWith(mechanism, 'withPLAIN-ECDSA', True)) then
  begin
    DigestName := System.Copy(mechanism, 1, TStringUtils.LastIndexOf(mechanism,
      'with', True));

    DigestInstance := TDigestUtilities.GetDigest(DigestName);
    Result := (TDsaDigestSigner.Create(TECDsaSigner.Create() as IECDsaSigner,
      DigestInstance, TPlainDsaEncoding.Instance));
    Exit;
  end;

  if TStringUtils.EndsWith(mechanism, 'withECNR', True) then
  begin
    DigestName := System.Copy(mechanism, 1, TStringUtils.LastIndexOf(mechanism,
      'with', True));

    DigestInstance := TDigestUtilities.GetDigest(DigestName);
    Result := (TDsaDigestSigner.Create(TECNRSigner.Create() as IECNRSigner,
      DigestInstance));
    Exit;
  end;

  if TStringUtils.EndsWith(mechanism, 'withECSCHNORRSIPA', True) then
  begin
    DigestName := System.Copy(mechanism, 1, TStringUtils.LastIndexOf(mechanism,
      'with', True));

    DigestInstance := TDigestUtilities.GetDigest(DigestName);
    Result := TSchnorrDigestSigner.Create(TECSchnorrSipaSigner.Create()
      as IECSchnorrSipaSigner, DigestInstance, TPlainSchnorrEncoding.Instance);
    Exit;
  end;

  if TStringUtils.EndsWith(mechanism, 'withRSAandMGF1', True) then
  begin
    DigestName := System.Copy(mechanism, 1, TStringUtils.LastIndexOf(mechanism,
      'with', True));
    DigestInstance := TDigestUtilities.GetDigest(DigestName);
    Result := TPssSigner.Create(TRsaBlindedEngine.Create(), DigestInstance);
    Exit;
  end;

  // TODO: PSSwithRSA - The Sha1Digest here is a default.
  // if (mechanism = 'PSSwithRSA') then
  // begin
  //   Result := TPssSigner.Create(TRsaBlindedEngine.Create(),
  //     TDigestUtilities.GetDigest('SHA-1'));
  //   Exit;
  // end;

  if TStringUtils.EndsWith(mechanism, 'withRSA', True) then
  begin
    DigestName := System.Copy(mechanism, 1, TStringUtils.LastIndexOf(mechanism,
      'with', True));

    DigestInstance := TDigestUtilities.GetDigest(DigestName);
    Result := TRsaDigestSigner.Create(DigestInstance) as IRsaDigestSigner;
    Exit;
  end;

  if (mechanism = 'RSA') then
  begin
    Result := TGenericSigner.Create(
      TPkcs1Encoding.Create(TRsaBlindedEngine.Create()),
      TDigestUtilities.GetDigest('NONE'));
    Exit;
  end;

  // TODO: RAWRSASSA-PSS - Add support for other parameter settings
  // if (mechanism = 'RAWRSASSA-PSS') then
  // begin
  //   Result := TPssSigner.CreateRawSigner(TRsaBlindedEngine.Create(),
  //     TDigestUtilities.GetDigest('SHA-1'));
  //   Exit;
  // end;

  raise ESecurityUtilityCryptoLibException.CreateResFmt(@SUnRecognizedAlgorithm,
    [algorithm]);

end;

class function TSignerUtilities.InitSigner(const algorithm: String;
  forSigning: Boolean; const privateKey: IAsymmetricKeyParameter;
  const random: ISecureRandom): ISigner;
begin
  Result := TSignerUtilities.GetSigner(algorithm);
  Result.Init(forSigning, TParameterUtilities.WithRandom(privateKey, random));
end;

class function TSignerUtilities.InitSigner(const algorithmOid
  : IDerObjectIdentifier; forSigning: Boolean;
  const privateKey: IAsymmetricKeyParameter;
  const random: ISecureRandom): ISigner;
begin
  Result := InitSigner(algorithmOid.id, forSigning, privateKey, random);
end;

end.
