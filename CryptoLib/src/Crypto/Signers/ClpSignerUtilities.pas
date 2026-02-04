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

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  Generics.Collections,
  ClpIAsn1Core,
  ClpAsn1Objects,
  ClpIX509Asn1Objects,
  ClpCollectionUtilities,
  ClpAsn1Comparers,
  ClpCryptoLibComparers,
  ClpECNRSigner,
  ClpICipherParameters,
  ClpIAsymmetricBlockCipher,
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
  ClpRsaDigestSigner,
  ClpPssSigner,
  ClpGenericSigner,
  ClpX931Signer,
  ClpRsaBlindedEngine,
  ClpIRsaBlindedEngine,
  ClpPkcs1Encoding,
  ClpIPkcs1Encoding,
  ClpPkcsObjectIdentifiers,
  ClpStringUtilities,
  ClpCryptoLibTypes,
  ClpPkcsAsn1Objects,
  ClpPkcsRsaAsn1Objects,
  ClpX509Asn1Objects;

resourcestring
  SMechanismNil = 'Mechanism Cannot be Nil';
  SAlgorithmNil = 'Algorithm Cannot be Nil';
  SUnRecognizedAlgorithm = 'Signer " %s " not recognised.';

type
  /// <summary>
  ///  Signer Utility class contains methods that can not be specifically grouped into other classes.
  /// </summary>
  TSignerUtilities = class sealed(TObject)

  strict private
    class var
      FAlgorithmMap: TDictionary<String, String>;
      FAlgorithmOidMap: TDictionary<IDerObjectIdentifier, String>;
      FNoRandom: TDictionary<String, Byte>;
      FOids: TDictionary<String, IDerObjectIdentifier>;

    class function GetMechanism(const AAlgorithm: String): String; static;
    class function GetAlgorithms: TCryptoLibStringArray; static;

    class function GetSignerForMechanism(const AMechanism: String): ISigner; static;
    class function GetDefaultX509ParametersForMechanism(const AMechanism: String): IAsn1Encodable; static;
    class function GetPssX509Parameters(const ADigestName: String): IAsn1Encodable; static;
    class function InitSignerForMechanism(const AMechanism: String; AForSigning: Boolean;
      const AKey: IAsymmetricKeyParameter; const ARandom: ISecureRandom): ISigner; static;
    class procedure AddAlgorithm(const AName: String; const AOid: IDerObjectIdentifier; AIsNoRandom: Boolean); static;
    class procedure Boot; static;
    class constructor Create;
    class destructor Destroy;

  public

   /// <summary>
   /// Returns an ObjectIdentifier for a given signature mechanism.
   /// </summary>
   /// <param name="mechanism">A string representation of the signature mechanism.</param>
   /// <returns>A DerObjectIdentifier, null if the OID is not available.</returns>
    class function GetObjectIdentifier(const AMechanism: String): IDerObjectIdentifier;
      static; inline;

    class function GetEncodingName(const AOid: IDerObjectIdentifier): String;
      static; inline;

    /// <summary>
    /// Returns a Signer for a given signature mechanism OID.
    /// </summary>
    /// <param name="AOid">A DerObjectIdentifier representing the signature mechanism.</param>
    /// <returns>An ISigner instance.</returns>
    class function GetSigner(const AOid: IDerObjectIdentifier): ISigner; overload;
      static;

    /// <summary>
    /// Returns a Signer for a given signature mechanism name.
    /// </summary>
    /// <param name="AAlgorithm">A string representation of the signature mechanism.</param>
    /// <returns>An ISigner instance.</returns>
    class function GetSigner(const AAlgorithm: String): ISigner; overload;
      static;

    /// <summary>
    /// Returns default X.509 parameters for a given signature mechanism OID.
    /// </summary>
    /// <param name="AOid">A DerObjectIdentifier representing the signature mechanism.</param>
    /// <returns>An IAsn1Encodable instance (typically DerNull or RsassaPssParameters).</returns>
    class function GetDefaultX509Parameters(const AOid: IDerObjectIdentifier): IAsn1Encodable; overload;
      static;

    /// <summary>
    /// Returns default X.509 parameters for a given signature mechanism name.
    /// </summary>
    /// <param name="AAlgorithm">A string representation of the signature mechanism.</param>
    /// <returns>An IAsn1Encodable instance (typically DerNull or RsassaPssParameters).</returns>
    class function GetDefaultX509Parameters(const AAlgorithm: String): IAsn1Encodable; overload;
      static;

    /// <summary>
    /// Initializes a Signer for signing or verification with the given key and random.
    /// </summary>
    /// <param name="AAlgorithmOid">A DerObjectIdentifier representing the signature mechanism.</param>
    /// <param name="AForSigning">True for signing, False for verification.</param>
    /// <param name="APrivateKey">The key to use (private for signing, public for verification).</param>
    /// <param name="ARandom">Secure random instance (can be nil for verification or deterministic algorithms).</param>
    /// <returns>An initialized ISigner instance.</returns>
    class function InitSigner(const AAlgorithmOid: IDerObjectIdentifier; AForSigning: Boolean;
      const APrivateKey: IAsymmetricKeyParameter; const ARandom: ISecureRandom): ISigner; overload;
      static;

    /// <summary>
    /// Initializes a Signer for signing or verification with the given key and random.
    /// </summary>
    /// <param name="AAlgorithm">A string representation of the signature mechanism.</param>
    /// <param name="AForSigning">True for signing, False for verification.</param>
    /// <param name="APrivateKey">The key to use (private for signing, public for verification).</param>
    /// <param name="ARandom">Secure random instance (can be nil for verification or deterministic algorithms).</param>
    /// <returns>An initialized ISigner instance.</returns>
    class function InitSigner(const AAlgorithm: String; AForSigning: Boolean;
      const APrivateKey: IAsymmetricKeyParameter; const ARandom: ISecureRandom): ISigner; overload;
      static;

    class property Algorithms: TCryptoLibStringArray read GetAlgorithms;

  end;

implementation

{ TSignerUtilities }

class procedure TSignerUtilities.AddAlgorithm(const AName: String;
  const AOid: IDerObjectIdentifier; AIsNoRandom: Boolean);
begin
  if AName = '' then
    raise EArgumentNilCryptoLibException.CreateRes(@SAlgorithmNil);

  if UpperCase(AName) <> AName then
    FAlgorithmMap.Add(AName, AName);
  if AOid <> nil then
  begin
    FAlgorithmOidMap.Add(AOid, AName);
    FOids.Add(AName, AOid);
  end;
  if AIsNoRandom then
    FNoRandom.Add(AName, 0);
end;

class procedure TSignerUtilities.Boot;
begin
  FAlgorithmMap := TDictionary<String, String>.Create(TCryptoLibComparers.OrdinalIgnoreCaseEqualityComparer);
  FAlgorithmOidMap := TDictionary<IDerObjectIdentifier, String>.Create(TAsn1Comparers.OidEqualityComparer);
  FNoRandom := TDictionary<String, Byte>.Create(TCryptoLibComparers.OrdinalIgnoreCaseEqualityComparer);
  FOids := TDictionary<String, IDerObjectIdentifier>.Create(TCryptoLibComparers.OrdinalIgnoreCaseEqualityComparer);

  TPkcsObjectIdentifiers.Boot;
  TX9ObjectIdentifiers.Boot;
  TOiwObjectIdentifiers.Boot;
  TNistObjectIdentifiers.Boot;
  TTeleTrusTObjectIdentifiers.Boot;
  TCryptoProObjectIdentifiers.Boot;
  TBsiObjectIdentifiers.Boot;
  TEdECObjectIdentifiers.Boot;

  FAlgorithmMap.AddOrSetValue('MD2WITHRSA', 'MD2withRSA');
  FAlgorithmMap.AddOrSetValue('MD2WITHRSAENCRYPTION', 'MD2withRSA');
  FAlgorithmOidMap.AddOrSetValue(TPkcsObjectIdentifiers.MD2WithRsaEncryption, 'MD2withRSA');

  FAlgorithmMap.AddOrSetValue('MD4WITHRSA', 'MD4withRSA');
  FAlgorithmMap.AddOrSetValue('MD4WITHRSAENCRYPTION', 'MD4withRSA');
  FAlgorithmOidMap.AddOrSetValue(TPkcsObjectIdentifiers.MD4WithRsaEncryption, 'MD4withRSA');
  FAlgorithmOidMap.AddOrSetValue(TOiwObjectIdentifiers.MD4WithRsa, 'MD4withRSA');
  FAlgorithmOidMap.AddOrSetValue(TOiwObjectIdentifiers.MD4WithRsaEncryption, 'MD4withRSA');

  FAlgorithmMap.AddOrSetValue('MD5WITHRSA', 'MD5withRSA');
  FAlgorithmMap.AddOrSetValue('MD5WITHRSAENCRYPTION', 'MD5withRSA');
  FAlgorithmOidMap.AddOrSetValue(TPkcsObjectIdentifiers.MD5WithRsaEncryption, 'MD5withRSA');
  FAlgorithmOidMap.AddOrSetValue(TOiwObjectIdentifiers.MD5WithRsa, 'MD5withRSA');

  FAlgorithmMap.AddOrSetValue('SHA1WITHRSA', 'SHA-1withRSA');
  FAlgorithmMap.AddOrSetValue('SHA-1WITHRSA', 'SHA-1withRSA');
  FAlgorithmMap.AddOrSetValue('SHA1WITHRSAENCRYPTION', 'SHA-1withRSA');
  FAlgorithmMap.AddOrSetValue('SHA-1WITHRSAENCRYPTION', 'SHA-1withRSA');
  FAlgorithmOidMap.AddOrSetValue(TPkcsObjectIdentifiers.Sha1WithRsaEncryption, 'SHA-1withRSA');
  FAlgorithmOidMap.AddOrSetValue(TOiwObjectIdentifiers.Sha1WithRsa, 'SHA-1withRSA');

  FAlgorithmMap.AddOrSetValue('SHA224WITHRSA', 'SHA-224withRSA');
  FAlgorithmMap.AddOrSetValue('SHA-224WITHRSA', 'SHA-224withRSA');
  FAlgorithmMap.AddOrSetValue('SHA224WITHRSAENCRYPTION', 'SHA-224withRSA');
  FAlgorithmMap.AddOrSetValue('SHA-224WITHRSAENCRYPTION', 'SHA-224withRSA');
  FAlgorithmOidMap.AddOrSetValue(TPkcsObjectIdentifiers.Sha224WithRsaEncryption, 'SHA-224withRSA');

  FAlgorithmMap.AddOrSetValue('SHA256WITHRSA', 'SHA-256withRSA');
  FAlgorithmMap.AddOrSetValue('SHA-256WITHRSA', 'SHA-256withRSA');
  FAlgorithmMap.AddOrSetValue('SHA256WITHRSAENCRYPTION', 'SHA-256withRSA');
  FAlgorithmMap.AddOrSetValue('SHA-256WITHRSAENCRYPTION', 'SHA-256withRSA');
  FAlgorithmOidMap.AddOrSetValue(TPkcsObjectIdentifiers.Sha256WithRsaEncryption, 'SHA-256withRSA');

  FAlgorithmMap.AddOrSetValue('SHA384WITHRSA', 'SHA-384withRSA');
  FAlgorithmMap.AddOrSetValue('SHA-384WITHRSA', 'SHA-384withRSA');
  FAlgorithmMap.AddOrSetValue('SHA384WITHRSAENCRYPTION', 'SHA-384withRSA');
  FAlgorithmMap.AddOrSetValue('SHA-384WITHRSAENCRYPTION', 'SHA-384withRSA');
  FAlgorithmOidMap.AddOrSetValue(TPkcsObjectIdentifiers.Sha384WithRsaEncryption, 'SHA-384withRSA');

  FAlgorithmMap.AddOrSetValue('SHA512WITHRSA', 'SHA-512withRSA');
  FAlgorithmMap.AddOrSetValue('SHA-512WITHRSA', 'SHA-512withRSA');
  FAlgorithmMap.AddOrSetValue('SHA512WITHRSAENCRYPTION', 'SHA-512withRSA');
  FAlgorithmMap.AddOrSetValue('SHA-512WITHRSAENCRYPTION', 'SHA-512withRSA');
  FAlgorithmOidMap.AddOrSetValue(TPkcsObjectIdentifiers.Sha512WithRsaEncryption, 'SHA-512withRSA');

  FAlgorithmMap.AddOrSetValue('SHA512(224)WITHRSA', 'SHA-512(224)withRSA');
  FAlgorithmMap.AddOrSetValue('SHA-512(224)WITHRSA', 'SHA-512(224)withRSA');
  FAlgorithmMap.AddOrSetValue('SHA512(224)WITHRSAENCRYPTION', 'SHA-512(224)withRSA');
  FAlgorithmMap.AddOrSetValue('SHA-512(224)WITHRSAENCRYPTION', 'SHA-512(224)withRSA');
  FAlgorithmOidMap.AddOrSetValue(TPkcsObjectIdentifiers.Sha512_224WithRSAEncryption, 'SHA-512(224)withRSA');

  FAlgorithmMap.AddOrSetValue('SHA512(256)WITHRSA', 'SHA-512(256)withRSA');
  FAlgorithmMap.AddOrSetValue('SHA-512(256)WITHRSA', 'SHA-512(256)withRSA');
  FAlgorithmMap.AddOrSetValue('SHA512(256)WITHRSAENCRYPTION', 'SHA-512(256)withRSA');
  FAlgorithmMap.AddOrSetValue('SHA-512(256)WITHRSAENCRYPTION', 'SHA-512(256)withRSA');
  FAlgorithmOidMap.AddOrSetValue(TPkcsObjectIdentifiers.Sha512_256WithRSAEncryption, 'SHA-512(256)withRSA');

  FAlgorithmMap.AddOrSetValue('SHA3-224WITHRSA', 'SHA3-224withRSA');
  FAlgorithmMap.AddOrSetValue('SHA3-224WITHRSAENCRYPTION', 'SHA3-224withRSA');
  FAlgorithmOidMap.AddOrSetValue(TNistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_224, 'SHA3-224withRSA');
  FAlgorithmMap.AddOrSetValue('SHA3-256WITHRSA', 'SHA3-256withRSA');
  FAlgorithmMap.AddOrSetValue('SHA3-256WITHRSAENCRYPTION', 'SHA3-256withRSA');
  FAlgorithmOidMap.AddOrSetValue(TNistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_256, 'SHA3-256withRSA');
  FAlgorithmMap.AddOrSetValue('SHA3-384WITHRSA', 'SHA3-384withRSA');
  FAlgorithmMap.AddOrSetValue('SHA3-384WITHRSAENCRYPTION', 'SHA3-384withRSA');
  FAlgorithmOidMap.AddOrSetValue(TNistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_384, 'SHA3-384withRSA');
  FAlgorithmMap.AddOrSetValue('SHA3-512WITHRSA', 'SHA3-512withRSA');
  FAlgorithmMap.AddOrSetValue('SHA3-512WITHRSAENCRYPTION', 'SHA3-512withRSA');
  FAlgorithmOidMap.AddOrSetValue(TNistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_512, 'SHA3-512withRSA');

  FAlgorithmMap.AddOrSetValue('PSSWITHRSA', 'PSSwithRSA');
  FAlgorithmMap.AddOrSetValue('RSASSA-PSS', 'PSSwithRSA');
  FAlgorithmOidMap.AddOrSetValue(TPkcsObjectIdentifiers.IdRsassaPss, 'PSSwithRSA');
  FAlgorithmMap.AddOrSetValue('RSAPSS', 'PSSwithRSA');

  FAlgorithmMap.AddOrSetValue('SHA1WITHRSAANDMGF1', 'SHA-1withRSAandMGF1');
  FAlgorithmMap.AddOrSetValue('SHA-1WITHRSAANDMGF1', 'SHA-1withRSAandMGF1');
  FAlgorithmMap.AddOrSetValue('SHA1WITHRSA/PSS', 'SHA-1withRSAandMGF1');
  FAlgorithmMap.AddOrSetValue('SHA-1WITHRSA/PSS', 'SHA-1withRSAandMGF1');
  FAlgorithmMap.AddOrSetValue('SHA1WITHRSASSA-PSS', 'SHA-1withRSAandMGF1');
  FAlgorithmMap.AddOrSetValue('SHA-1WITHRSASSA-PSS', 'SHA-1withRSAandMGF1');

  FAlgorithmMap.AddOrSetValue('SHA224WITHRSAANDMGF1', 'SHA-224withRSAandMGF1');
  FAlgorithmMap.AddOrSetValue('SHA-224WITHRSAANDMGF1', 'SHA-224withRSAandMGF1');
  FAlgorithmMap.AddOrSetValue('SHA224WITHRSA/PSS', 'SHA-224withRSAandMGF1');
  FAlgorithmMap.AddOrSetValue('SHA-224WITHRSA/PSS', 'SHA-224withRSAandMGF1');
  FAlgorithmMap.AddOrSetValue('SHA224WITHRSASSA-PSS', 'SHA-224withRSAandMGF1');
  FAlgorithmMap.AddOrSetValue('SHA-224WITHRSASSA-PSS', 'SHA-224withRSAandMGF1');

  FAlgorithmMap.AddOrSetValue('SHA256WITHRSAANDMGF1', 'SHA-256withRSAandMGF1');
  FAlgorithmMap.AddOrSetValue('SHA-256WITHRSAANDMGF1', 'SHA-256withRSAandMGF1');
  FAlgorithmMap.AddOrSetValue('SHA256WITHRSA/PSS', 'SHA-256withRSAandMGF1');
  FAlgorithmMap.AddOrSetValue('SHA-256WITHRSA/PSS', 'SHA-256withRSAandMGF1');
  FAlgorithmMap.AddOrSetValue('SHA256WITHRSASSA-PSS', 'SHA-256withRSAandMGF1');
  FAlgorithmMap.AddOrSetValue('SHA-256WITHRSASSA-PSS', 'SHA-256withRSAandMGF1');

  FAlgorithmMap.AddOrSetValue('SHA384WITHRSAANDMGF1', 'SHA-384withRSAandMGF1');
  FAlgorithmMap.AddOrSetValue('SHA-384WITHRSAANDMGF1', 'SHA-384withRSAandMGF1');
  FAlgorithmMap.AddOrSetValue('SHA384WITHRSA/PSS', 'SHA-384withRSAandMGF1');
  FAlgorithmMap.AddOrSetValue('SHA-384WITHRSA/PSS', 'SHA-384withRSAandMGF1');
  FAlgorithmMap.AddOrSetValue('SHA384WITHRSASSA-PSS', 'SHA-384withRSAandMGF1');
  FAlgorithmMap.AddOrSetValue('SHA-384WITHRSASSA-PSS', 'SHA-384withRSAandMGF1');

  FAlgorithmMap.AddOrSetValue('SHA512WITHRSAANDMGF1', 'SHA-512withRSAandMGF1');
  FAlgorithmMap.AddOrSetValue('SHA-512WITHRSAANDMGF1', 'SHA-512withRSAandMGF1');
  FAlgorithmMap.AddOrSetValue('SHA512WITHRSA/PSS', 'SHA-512withRSAandMGF1');
  FAlgorithmMap.AddOrSetValue('SHA-512WITHRSA/PSS', 'SHA-512withRSAandMGF1');
  FAlgorithmMap.AddOrSetValue('SHA512WITHRSASSA-PSS', 'SHA-512withRSAandMGF1');
  FAlgorithmMap.AddOrSetValue('SHA-512WITHRSASSA-PSS', 'SHA-512withRSAandMGF1');

  FAlgorithmMap.AddOrSetValue('RIPEMD128WITHRSA', 'RIPEMD128withRSA');
  FAlgorithmMap.AddOrSetValue('RIPEMD128WITHRSAENCRYPTION', 'RIPEMD128withRSA');
  FAlgorithmOidMap.AddOrSetValue(TTeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD128, 'RIPEMD128withRSA');

  FAlgorithmMap.AddOrSetValue('RIPEMD160WITHRSA', 'RIPEMD160withRSA');
  FAlgorithmMap.AddOrSetValue('RIPEMD160WITHRSAENCRYPTION', 'RIPEMD160withRSA');
  FAlgorithmOidMap.AddOrSetValue(TTeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD160, 'RIPEMD160withRSA');

  FAlgorithmMap.AddOrSetValue('RIPEMD256WITHRSA', 'RIPEMD256withRSA');
  FAlgorithmMap.AddOrSetValue('RIPEMD256WITHRSAENCRYPTION', 'RIPEMD256withRSA');
  FAlgorithmOidMap.AddOrSetValue(TTeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD256, 'RIPEMD256withRSA');

  FAlgorithmMap.AddOrSetValue('NONEWITHRSA', 'RSA');
  FAlgorithmMap.AddOrSetValue('RSAWITHNONE', 'RSA');
  FAlgorithmMap.AddOrSetValue('RAWRSA', 'RSA');

  FAlgorithmMap.AddOrSetValue('RAWRSAPSS', 'RAWRSASSA-PSS');
  FAlgorithmMap.AddOrSetValue('NONEWITHRSAPSS', 'RAWRSASSA-PSS');
  FAlgorithmMap.AddOrSetValue('NONEWITHRSASSA-PSS', 'RAWRSASSA-PSS');

  FAlgorithmMap.AddOrSetValue('NONEWITHDSA', 'NONEwithDSA');
  FAlgorithmMap.AddOrSetValue('DSAWITHNONE', 'NONEwithDSA');
  FAlgorithmMap.AddOrSetValue('RAWDSA', 'NONEwithDSA');

  FAlgorithmMap.AddOrSetValue('DSA', 'SHA-1withDSA');
  FAlgorithmMap.AddOrSetValue('DSAWITHSHA1', 'SHA-1withDSA');
  FAlgorithmMap.AddOrSetValue('DSAWITHSHA-1', 'SHA-1withDSA');
  FAlgorithmMap.AddOrSetValue('SHA/DSA', 'SHA-1withDSA');
  FAlgorithmMap.AddOrSetValue('SHA1/DSA', 'SHA-1withDSA');
  FAlgorithmMap.AddOrSetValue('SHA-1/DSA', 'SHA-1withDSA');
  FAlgorithmMap.AddOrSetValue('SHA1WITHDSA', 'SHA-1withDSA');
  FAlgorithmMap.AddOrSetValue('SHA-1WITHDSA', 'SHA-1withDSA');
  FAlgorithmOidMap.AddOrSetValue(TX9ObjectIdentifiers.IdDsaWithSha1, 'SHA-1withDSA');
  FAlgorithmOidMap.AddOrSetValue(TOiwObjectIdentifiers.DsaWithSha1, 'SHA-1withDSA');

  FAlgorithmMap.AddOrSetValue('DSAWITHSHA224', 'SHA-224withDSA');
  FAlgorithmMap.AddOrSetValue('DSAWITHSHA-224', 'SHA-224withDSA');
  FAlgorithmMap.AddOrSetValue('SHA224/DSA', 'SHA-224withDSA');
  FAlgorithmMap.AddOrSetValue('SHA-224/DSA', 'SHA-224withDSA');
  FAlgorithmMap.AddOrSetValue('SHA224WITHDSA', 'SHA-224withDSA');
  FAlgorithmMap.AddOrSetValue('SHA-224WITHDSA', 'SHA-224withDSA');
  FAlgorithmOidMap.AddOrSetValue(TNistObjectIdentifiers.DsaWithSha224, 'SHA-224withDSA');

  FAlgorithmMap.AddOrSetValue('DSAWITHSHA256', 'SHA-256withDSA');
  FAlgorithmMap.AddOrSetValue('DSAWITHSHA-256', 'SHA-256withDSA');
  FAlgorithmMap.AddOrSetValue('SHA256/DSA', 'SHA-256withDSA');
  FAlgorithmMap.AddOrSetValue('SHA-256/DSA', 'SHA-256withDSA');
  FAlgorithmMap.AddOrSetValue('SHA256WITHDSA', 'SHA-256withDSA');
  FAlgorithmMap.AddOrSetValue('SHA-256WITHDSA', 'SHA-256withDSA');
  FAlgorithmOidMap.AddOrSetValue(TNistObjectIdentifiers.DsaWithSha256, 'SHA-256withDSA');

  FAlgorithmMap.AddOrSetValue('DSAWITHSHA384', 'SHA-384withDSA');
  FAlgorithmMap.AddOrSetValue('DSAWITHSHA-384', 'SHA-384withDSA');
  FAlgorithmMap.AddOrSetValue('SHA384/DSA', 'SHA-384withDSA');
  FAlgorithmMap.AddOrSetValue('SHA-384/DSA', 'SHA-384withDSA');
  FAlgorithmMap.AddOrSetValue('SHA384WITHDSA', 'SHA-384withDSA');
  FAlgorithmMap.AddOrSetValue('SHA-384WITHDSA', 'SHA-384withDSA');
  FAlgorithmOidMap.AddOrSetValue(TNistObjectIdentifiers.DsaWithSha384, 'SHA-384withDSA');

  FAlgorithmMap.AddOrSetValue('DSAWITHSHA512', 'SHA-512withDSA');
  FAlgorithmMap.AddOrSetValue('DSAWITHSHA-512', 'SHA-512withDSA');
  FAlgorithmMap.AddOrSetValue('SHA512/DSA', 'SHA-512withDSA');
  FAlgorithmMap.AddOrSetValue('SHA-512/DSA', 'SHA-512withDSA');
  FAlgorithmMap.AddOrSetValue('SHA512WITHDSA', 'SHA-512withDSA');
  FAlgorithmMap.AddOrSetValue('SHA-512WITHDSA', 'SHA-512withDSA');
  FAlgorithmOidMap.AddOrSetValue(TNistObjectIdentifiers.DsaWithSha512, 'SHA-512withDSA');

  FAlgorithmMap.AddOrSetValue('DSAWITHSHA3-224', 'SHA3-224withDSA');
  FAlgorithmMap.AddOrSetValue('SHA3-224/DSA', 'SHA3-224withDSA');
  FAlgorithmMap.AddOrSetValue('SHA3-224WITHDSA', 'SHA3-224withDSA');
  FAlgorithmOidMap.AddOrSetValue(TNistObjectIdentifiers.IdDsaWithSha3_224, 'SHA3-224withDSA');

  FAlgorithmMap.AddOrSetValue('DSAWITHSHA3-256', 'SHA3-256withDSA');
  FAlgorithmMap.AddOrSetValue('SHA3-256/DSA', 'SHA3-256withDSA');
  FAlgorithmMap.AddOrSetValue('SHA3-256WITHDSA', 'SHA3-256withDSA');
  FAlgorithmOidMap.AddOrSetValue(TNistObjectIdentifiers.IdDsaWithSha3_256, 'SHA3-256withDSA');

  FAlgorithmMap.AddOrSetValue('DSAWITHSHA3-384', 'SHA3-384withDSA');
  FAlgorithmMap.AddOrSetValue('SHA3-384/DSA', 'SHA3-384withDSA');
  FAlgorithmMap.AddOrSetValue('SHA3-384WITHDSA', 'SHA3-384withDSA');
  FAlgorithmOidMap.AddOrSetValue(TNistObjectIdentifiers.IdDsaWithSha3_384, 'SHA3-384withDSA');

  FAlgorithmMap.AddOrSetValue('DSAWITHSHA3-512', 'SHA3-512withDSA');
  FAlgorithmMap.AddOrSetValue('SHA3-512/DSA', 'SHA3-512withDSA');
  FAlgorithmMap.AddOrSetValue('SHA3-512WITHDSA', 'SHA3-512withDSA');
  FAlgorithmOidMap.AddOrSetValue(TNistObjectIdentifiers.IdDsaWithSha3_512, 'SHA3-512withDSA');

  FAlgorithmMap.AddOrSetValue('NONEWITHECDSA', 'NONEwithECDSA');
  FAlgorithmMap.AddOrSetValue('ECDSAWITHNONE', 'NONEwithECDSA');

  FAlgorithmMap.AddOrSetValue('ECDSA', 'SHA-1withECDSA');
  FAlgorithmMap.AddOrSetValue('SHA1/ECDSA', 'SHA-1withECDSA');
  FAlgorithmMap.AddOrSetValue('SHA-1/ECDSA', 'SHA-1withECDSA');
  FAlgorithmMap.AddOrSetValue('ECDSAWITHSHA1', 'SHA-1withECDSA');
  FAlgorithmMap.AddOrSetValue('ECDSAWITHSHA-1', 'SHA-1withECDSA');
  FAlgorithmMap.AddOrSetValue('SHA1WITHECDSA', 'SHA-1withECDSA');
  FAlgorithmMap.AddOrSetValue('SHA-1WITHECDSA', 'SHA-1withECDSA');
  FAlgorithmOidMap.AddOrSetValue(TX9ObjectIdentifiers.ECDsaWithSha1, 'SHA-1withECDSA');
  FAlgorithmOidMap.AddOrSetValue(TTeleTrusTObjectIdentifiers.ECSignWithSha1, 'SHA-1withECDSA');

  FAlgorithmMap.AddOrSetValue('SHA224/ECDSA', 'SHA-224withECDSA');
  FAlgorithmMap.AddOrSetValue('SHA-224/ECDSA', 'SHA-224withECDSA');
  FAlgorithmMap.AddOrSetValue('ECDSAWITHSHA224', 'SHA-224withECDSA');
  FAlgorithmMap.AddOrSetValue('ECDSAWITHSHA-224', 'SHA-224withECDSA');
  FAlgorithmMap.AddOrSetValue('SHA224WITHECDSA', 'SHA-224withECDSA');
  FAlgorithmMap.AddOrSetValue('SHA-224WITHECDSA', 'SHA-224withECDSA');
  FAlgorithmOidMap.AddOrSetValue(TX9ObjectIdentifiers.ECDsaWithSha224, 'SHA-224withECDSA');

  FAlgorithmMap.AddOrSetValue('SHA256/ECDSA', 'SHA-256withECDSA');
  FAlgorithmMap.AddOrSetValue('SHA-256/ECDSA', 'SHA-256withECDSA');
  FAlgorithmMap.AddOrSetValue('ECDSAWITHSHA256', 'SHA-256withECDSA');
  FAlgorithmMap.AddOrSetValue('ECDSAWITHSHA-256', 'SHA-256withECDSA');
  FAlgorithmMap.AddOrSetValue('SHA256WITHECDSA', 'SHA-256withECDSA');
  FAlgorithmMap.AddOrSetValue('SHA-256WITHECDSA', 'SHA-256withECDSA');
  FAlgorithmOidMap.AddOrSetValue(TX9ObjectIdentifiers.ECDsaWithSha256, 'SHA-256withECDSA');

  FAlgorithmMap.AddOrSetValue('SHA384/ECDSA', 'SHA-384withECDSA');
  FAlgorithmMap.AddOrSetValue('SHA-384/ECDSA', 'SHA-384withECDSA');
  FAlgorithmMap.AddOrSetValue('ECDSAWITHSHA384', 'SHA-384withECDSA');
  FAlgorithmMap.AddOrSetValue('ECDSAWITHSHA-384', 'SHA-384withECDSA');
  FAlgorithmMap.AddOrSetValue('SHA384WITHECDSA', 'SHA-384withECDSA');
  FAlgorithmMap.AddOrSetValue('SHA-384WITHECDSA', 'SHA-384withECDSA');
  FAlgorithmOidMap.AddOrSetValue(TX9ObjectIdentifiers.ECDsaWithSha384, 'SHA-384withECDSA');

  FAlgorithmMap.AddOrSetValue('SHA512/ECDSA', 'SHA-512withECDSA');
  FAlgorithmMap.AddOrSetValue('SHA-512/ECDSA', 'SHA-512withECDSA');
  FAlgorithmMap.AddOrSetValue('ECDSAWITHSHA512', 'SHA-512withECDSA');
  FAlgorithmMap.AddOrSetValue('ECDSAWITHSHA-512', 'SHA-512withECDSA');
  FAlgorithmMap.AddOrSetValue('SHA512WITHECDSA', 'SHA-512withECDSA');
  FAlgorithmMap.AddOrSetValue('SHA-512WITHECDSA', 'SHA-512withECDSA');
  FAlgorithmOidMap.AddOrSetValue(TX9ObjectIdentifiers.ECDsaWithSha512, 'SHA-512withECDSA');

  FAlgorithmMap.AddOrSetValue('RIPEMD160/ECDSA', 'RIPEMD160withECDSA');
  FAlgorithmMap.AddOrSetValue('ECDSAWITHRIPEMD160', 'RIPEMD160withECDSA');
  FAlgorithmMap.AddOrSetValue('RIPEMD160WITHECDSA', 'RIPEMD160withECDSA');
  FAlgorithmOidMap.AddOrSetValue(TTeleTrusTObjectIdentifiers.ECSignWithRipeMD160, 'RIPEMD160withECDSA');

  FAlgorithmMap.AddOrSetValue('SHA3-224/ECDSA', 'SHA3-224withECDSA');
  FAlgorithmMap.AddOrSetValue('ECDSAWITHSHA3-224', 'SHA3-224withECDSA');
  FAlgorithmMap.AddOrSetValue('SHA3-224WITHECDSA', 'SHA3-224withECDSA');
  FAlgorithmOidMap.AddOrSetValue(TNistObjectIdentifiers.IdEcdsaWithSha3_224, 'SHA3-224withECDSA');

  FAlgorithmMap.AddOrSetValue('SHA3-256/ECDSA', 'SHA3-256withECDSA');
  FAlgorithmMap.AddOrSetValue('ECDSAWITHSHA3-256', 'SHA3-256withECDSA');
  FAlgorithmMap.AddOrSetValue('SHA3-256WITHECDSA', 'SHA3-256withECDSA');
  FAlgorithmOidMap.AddOrSetValue(TNistObjectIdentifiers.IdEcdsaWithSha3_256, 'SHA3-256withECDSA');

  FAlgorithmMap.AddOrSetValue('SHA3-384/ECDSA', 'SHA3-384withECDSA');
  FAlgorithmMap.AddOrSetValue('ECDSAWITHSHA3-384', 'SHA3-384withECDSA');
  FAlgorithmMap.AddOrSetValue('SHA3-384WITHECDSA', 'SHA3-384withECDSA');
  FAlgorithmOidMap.AddOrSetValue(TNistObjectIdentifiers.IdEcdsaWithSha3_384, 'SHA3-384withECDSA');

  FAlgorithmMap.AddOrSetValue('SHA3-512/ECDSA', 'SHA3-512withECDSA');
  FAlgorithmMap.AddOrSetValue('ECDSAWITHSHA3-512', 'SHA3-512withECDSA');
  FAlgorithmMap.AddOrSetValue('SHA3-512WITHECDSA', 'SHA3-512withECDSA');
  FAlgorithmOidMap.AddOrSetValue(TNistObjectIdentifiers.IdEcdsaWithSha3_512, 'SHA3-512withECDSA');

  FAlgorithmMap.AddOrSetValue('NONEWITHCVC-ECDSA', 'NONEwithCVC-ECDSA');
  FAlgorithmMap.AddOrSetValue('CVC-ECDSAWITHNONE', 'NONEwithCVC-ECDSA');

  FAlgorithmMap.AddOrSetValue('SHA1/CVC-ECDSA', 'SHA-1withCVC-ECDSA');
  FAlgorithmMap.AddOrSetValue('SHA-1/CVC-ECDSA', 'SHA-1withCVC-ECDSA');
  FAlgorithmMap.AddOrSetValue('CVC-ECDSAWITHSHA1', 'SHA-1withCVC-ECDSA');
  FAlgorithmMap.AddOrSetValue('CVC-ECDSAWITHSHA-1', 'SHA-1withCVC-ECDSA');
  FAlgorithmMap.AddOrSetValue('SHA1WITHCVC-ECDSA', 'SHA-1withCVC-ECDSA');
  FAlgorithmMap.AddOrSetValue('SHA-1WITHCVC-ECDSA', 'SHA-1withCVC-ECDSA');
  FAlgorithmOidMap.AddOrSetValue(TEacObjectIdentifiers.IdTAEcdsaSha1, 'SHA-1withCVC-ECDSA');

  FAlgorithmMap.AddOrSetValue('SHA224/CVC-ECDSA', 'SHA-224withCVC-ECDSA');
  FAlgorithmMap.AddOrSetValue('SHA-224/CVC-ECDSA', 'SHA-224withCVC-ECDSA');
  FAlgorithmMap.AddOrSetValue('CVC-ECDSAWITHSHA224', 'SHA-224withCVC-ECDSA');
  FAlgorithmMap.AddOrSetValue('CVC-ECDSAWITHSHA-224', 'SHA-224withCVC-ECDSA');
  FAlgorithmMap.AddOrSetValue('SHA224WITHCVC-ECDSA', 'SHA-224withCVC-ECDSA');
  FAlgorithmMap.AddOrSetValue('SHA-224WITHCVC-ECDSA', 'SHA-224withCVC-ECDSA');
  FAlgorithmOidMap.AddOrSetValue(TEacObjectIdentifiers.IdTAEcdsaSha224, 'SHA-224withCVC-ECDSA');

  FAlgorithmMap.AddOrSetValue('SHA256/CVC-ECDSA', 'SHA-256withCVC-ECDSA');
  FAlgorithmMap.AddOrSetValue('SHA-256/CVC-ECDSA', 'SHA-256withCVC-ECDSA');
  FAlgorithmMap.AddOrSetValue('CVC-ECDSAWITHSHA256', 'SHA-256withCVC-ECDSA');
  FAlgorithmMap.AddOrSetValue('CVC-ECDSAWITHSHA-256', 'SHA-256withCVC-ECDSA');
  FAlgorithmMap.AddOrSetValue('SHA256WITHCVC-ECDSA', 'SHA-256withCVC-ECDSA');
  FAlgorithmMap.AddOrSetValue('SHA-256WITHCVC-ECDSA', 'SHA-256withCVC-ECDSA');
  FAlgorithmOidMap.AddOrSetValue(TEacObjectIdentifiers.IdTAEcdsaSha256, 'SHA-256withCVC-ECDSA');

  FAlgorithmMap.AddOrSetValue('SHA384/CVC-ECDSA', 'SHA-384withCVC-ECDSA');
  FAlgorithmMap.AddOrSetValue('SHA-384/CVC-ECDSA', 'SHA-384withCVC-ECDSA');
  FAlgorithmMap.AddOrSetValue('CVC-ECDSAWITHSHA384', 'SHA-384withCVC-ECDSA');
  FAlgorithmMap.AddOrSetValue('CVC-ECDSAWITHSHA-384', 'SHA-384withCVC-ECDSA');
  FAlgorithmMap.AddOrSetValue('SHA384WITHCVC-ECDSA', 'SHA-384withCVC-ECDSA');
  FAlgorithmMap.AddOrSetValue('SHA-384WITHCVC-ECDSA', 'SHA-384withCVC-ECDSA');
  FAlgorithmOidMap.AddOrSetValue(TEacObjectIdentifiers.IdTAEcdsaSha384, 'SHA-384withCVC-ECDSA');

  FAlgorithmMap.AddOrSetValue('SHA512/CVC-ECDSA', 'SHA-512withCVC-ECDSA');
  FAlgorithmMap.AddOrSetValue('SHA-512/CVC-ECDSA', 'SHA-512withCVC-ECDSA');
  FAlgorithmMap.AddOrSetValue('CVC-ECDSAWITHSHA512', 'SHA-512withCVC-ECDSA');
  FAlgorithmMap.AddOrSetValue('CVC-ECDSAWITHSHA-512', 'SHA-512withCVC-ECDSA');
  FAlgorithmMap.AddOrSetValue('SHA512WITHCVC-ECDSA', 'SHA-512withCVC-ECDSA');
  FAlgorithmMap.AddOrSetValue('SHA-512WITHCVC-ECDSA', 'SHA-512withCVC-ECDSA');
  FAlgorithmOidMap.AddOrSetValue(TEacObjectIdentifiers.IdTAEcdsaSha512, 'SHA-512withCVC-ECDSA');

  FAlgorithmMap.AddOrSetValue('NONEWITHPLAIN-ECDSA', 'NONEwithPLAIN-ECDSA');
  FAlgorithmMap.AddOrSetValue('PLAIN-ECDSAWITHNONE', 'NONEwithPLAIN-ECDSA');

  FAlgorithmMap.AddOrSetValue('SHA1/PLAIN-ECDSA', 'SHA-1withPLAIN-ECDSA');
  FAlgorithmMap.AddOrSetValue('SHA-1/PLAIN-ECDSA', 'SHA-1withPLAIN-ECDSA');
  FAlgorithmMap.AddOrSetValue('PLAIN-ECDSAWITHSHA1', 'SHA-1withPLAIN-ECDSA');
  FAlgorithmMap.AddOrSetValue('PLAIN-ECDSAWITHSHA-1', 'SHA-1withPLAIN-ECDSA');
  FAlgorithmMap.AddOrSetValue('SHA1WITHPLAIN-ECDSA', 'SHA-1withPLAIN-ECDSA');
  FAlgorithmMap.AddOrSetValue('SHA-1WITHPLAIN-ECDSA', 'SHA-1withPLAIN-ECDSA');
  FAlgorithmOidMap.AddOrSetValue(TBsiObjectIdentifiers.EcdsaPlainSha1, 'SHA-1withPLAIN-ECDSA');

  FAlgorithmMap.AddOrSetValue('SHA224/PLAIN-ECDSA', 'SHA-224withPLAIN-ECDSA');
  FAlgorithmMap.AddOrSetValue('SHA-224/PLAIN-ECDSA', 'SHA-224withPLAIN-ECDSA');
  FAlgorithmMap.AddOrSetValue('PLAIN-ECDSAWITHSHA224', 'SHA-224withPLAIN-ECDSA');
  FAlgorithmMap.AddOrSetValue('PLAIN-ECDSAWITHSHA-224', 'SHA-224withPLAIN-ECDSA');
  FAlgorithmMap.AddOrSetValue('SHA224WITHPLAIN-ECDSA', 'SHA-224withPLAIN-ECDSA');
  FAlgorithmMap.AddOrSetValue('SHA-224WITHPLAIN-ECDSA', 'SHA-224withPLAIN-ECDSA');
  FAlgorithmOidMap.AddOrSetValue(TBsiObjectIdentifiers.EcdsaPlainSha224, 'SHA-224withPLAIN-ECDSA');

  FAlgorithmMap.AddOrSetValue('SHA256/PLAIN-ECDSA', 'SHA-256withPLAIN-ECDSA');
  FAlgorithmMap.AddOrSetValue('SHA-256/PLAIN-ECDSA', 'SHA-256withPLAIN-ECDSA');
  FAlgorithmMap.AddOrSetValue('PLAIN-ECDSAWITHSHA256', 'SHA-256withPLAIN-ECDSA');
  FAlgorithmMap.AddOrSetValue('PLAIN-ECDSAWITHSHA-256', 'SHA-256withPLAIN-ECDSA');
  FAlgorithmMap.AddOrSetValue('SHA256WITHPLAIN-ECDSA', 'SHA-256withPLAIN-ECDSA');
  FAlgorithmMap.AddOrSetValue('SHA-256WITHPLAIN-ECDSA', 'SHA-256withPLAIN-ECDSA');
  FAlgorithmOidMap.AddOrSetValue(TBsiObjectIdentifiers.EcdsaPlainSha256, 'SHA-256withPLAIN-ECDSA');

  FAlgorithmMap.AddOrSetValue('SHA384/PLAIN-ECDSA', 'SHA-384withPLAIN-ECDSA');
  FAlgorithmMap.AddOrSetValue('SHA-384/PLAIN-ECDSA', 'SHA-384withPLAIN-ECDSA');
  FAlgorithmMap.AddOrSetValue('PLAIN-ECDSAWITHSHA384', 'SHA-384withPLAIN-ECDSA');
  FAlgorithmMap.AddOrSetValue('PLAIN-ECDSAWITHSHA-384', 'SHA-384withPLAIN-ECDSA');
  FAlgorithmMap.AddOrSetValue('SHA384WITHPLAIN-ECDSA', 'SHA-384withPLAIN-ECDSA');
  FAlgorithmMap.AddOrSetValue('SHA-384WITHPLAIN-ECDSA', 'SHA-384withPLAIN-ECDSA');
  FAlgorithmOidMap.AddOrSetValue(TBsiObjectIdentifiers.EcdsaPlainSha384, 'SHA-384withPLAIN-ECDSA');

  FAlgorithmMap.AddOrSetValue('SHA512/PLAIN-ECDSA', 'SHA-512withPLAIN-ECDSA');
  FAlgorithmMap.AddOrSetValue('SHA-512/PLAIN-ECDSA', 'SHA-512withPLAIN-ECDSA');
  FAlgorithmMap.AddOrSetValue('PLAIN-ECDSAWITHSHA512', 'SHA-512withPLAIN-ECDSA');
  FAlgorithmMap.AddOrSetValue('PLAIN-ECDSAWITHSHA-512', 'SHA-512withPLAIN-ECDSA');
  FAlgorithmMap.AddOrSetValue('SHA512WITHPLAIN-ECDSA', 'SHA-512withPLAIN-ECDSA');
  FAlgorithmMap.AddOrSetValue('SHA-512WITHPLAIN-ECDSA', 'SHA-512withPLAIN-ECDSA');
  FAlgorithmOidMap.AddOrSetValue(TBsiObjectIdentifiers.EcdsaPlainSha512, 'SHA-512withPLAIN-ECDSA');

  FAlgorithmMap.AddOrSetValue('RIPEMD160/PLAIN-ECDSA', 'RIPEMD160withPLAIN-ECDSA');
  FAlgorithmMap.AddOrSetValue('PLAIN-ECDSAWITHRIPEMD160', 'RIPEMD160withPLAIN-ECDSA');
  FAlgorithmMap.AddOrSetValue('RIPEMD160WITHPLAIN-ECDSA', 'RIPEMD160withPLAIN-ECDSA');
  FAlgorithmOidMap.AddOrSetValue(TBsiObjectIdentifiers.EcdsaPlainRipeMD160, 'RIPEMD160withPLAIN-ECDSA');

  FAlgorithmMap.AddOrSetValue('SHA3-224/PLAIN-ECDSA', 'SHA3-224withPLAIN-ECDSA');
  FAlgorithmMap.AddOrSetValue('PLAIN-ECDSAWITHSHA3-224', 'SHA3-224withPLAIN-ECDSA');
  FAlgorithmMap.AddOrSetValue('SHA3-224WITHPLAIN-ECDSA', 'SHA3-224withPLAIN-ECDSA');
  FAlgorithmOidMap.AddOrSetValue(TBsiObjectIdentifiers.EcdsaPlainSha3_224, 'SHA3-224withPLAIN-ECDSA');

  FAlgorithmMap.AddOrSetValue('SHA3-256/PLAIN-ECDSA', 'SHA3-256withPLAIN-ECDSA');
  FAlgorithmMap.AddOrSetValue('PLAIN-ECDSAWITHSHA3-256', 'SHA3-256withPLAIN-ECDSA');
  FAlgorithmMap.AddOrSetValue('SHA3-256WITHPLAIN-ECDSA', 'SHA3-256withPLAIN-ECDSA');
  FAlgorithmOidMap.AddOrSetValue(TBsiObjectIdentifiers.EcdsaPlainSha3_256, 'SHA3-256withPLAIN-ECDSA');

  FAlgorithmMap.AddOrSetValue('SHA3-384/PLAIN-ECDSA', 'SHA3-384withPLAIN-ECDSA');
  FAlgorithmMap.AddOrSetValue('PLAIN-ECDSAWITHSHA3-384', 'SHA3-384withPLAIN-ECDSA');
  FAlgorithmMap.AddOrSetValue('SHA3-384WITHPLAIN-ECDSA', 'SHA3-384withPLAIN-ECDSA');
  FAlgorithmOidMap.AddOrSetValue(TBsiObjectIdentifiers.EcdsaPlainSha3_384, 'SHA3-384withPLAIN-ECDSA');

  FAlgorithmMap.AddOrSetValue('SHA3-512/PLAIN-ECDSA', 'SHA3-512withPLAIN-ECDSA');
  FAlgorithmMap.AddOrSetValue('PLAIN-ECDSAWITHSHA3-512', 'SHA3-512withPLAIN-ECDSA');
  FAlgorithmMap.AddOrSetValue('SHA3-512WITHPLAIN-ECDSA', 'SHA3-512withPLAIN-ECDSA');
  FAlgorithmOidMap.AddOrSetValue(TBsiObjectIdentifiers.EcdsaPlainSha3_512, 'SHA3-512withPLAIN-ECDSA');

  FAlgorithmMap.AddOrSetValue('SHA1WITHECNR', 'SHA-1withECNR');
  FAlgorithmMap.AddOrSetValue('SHA-1WITHECNR', 'SHA-1withECNR');
  FAlgorithmMap.AddOrSetValue('SHA224WITHECNR', 'SHA-224withECNR');
  FAlgorithmMap.AddOrSetValue('SHA-224WITHECNR', 'SHA-224withECNR');
  FAlgorithmMap.AddOrSetValue('SHA256WITHECNR', 'SHA-256withECNR');
  FAlgorithmMap.AddOrSetValue('SHA-256WITHECNR', 'SHA-256withECNR');
  FAlgorithmMap.AddOrSetValue('SHA384WITHECNR', 'SHA-384withECNR');
  FAlgorithmMap.AddOrSetValue('SHA-384WITHECNR', 'SHA-384withECNR');
  FAlgorithmMap.AddOrSetValue('SHA512WITHECNR', 'SHA-512withECNR');
  FAlgorithmMap.AddOrSetValue('SHA-512WITHECNR', 'SHA-512withECNR');

  FOids.AddOrSetValue('MD2withRSA', TPkcsObjectIdentifiers.MD2WithRsaEncryption);
  FOids.AddOrSetValue('MD4withRSA', TPkcsObjectIdentifiers.MD4WithRsaEncryption);
  FOids.AddOrSetValue('MD5withRSA', TPkcsObjectIdentifiers.MD5WithRsaEncryption);

  FOids.AddOrSetValue('SHA-1withRSA', TPkcsObjectIdentifiers.Sha1WithRsaEncryption);
  FOids.AddOrSetValue('SHA-224withRSA', TPkcsObjectIdentifiers.Sha224WithRsaEncryption);
  FOids.AddOrSetValue('SHA-256withRSA', TPkcsObjectIdentifiers.Sha256WithRsaEncryption);
  FOids.AddOrSetValue('SHA-384withRSA', TPkcsObjectIdentifiers.Sha384WithRsaEncryption);
  FOids.AddOrSetValue('SHA-512withRSA', TPkcsObjectIdentifiers.Sha512WithRsaEncryption);
  FOids.AddOrSetValue('SHA-512(224)withRSA', TPkcsObjectIdentifiers.Sha512_224WithRSAEncryption);
  FOids.AddOrSetValue('SHA-512(256)withRSA', TPkcsObjectIdentifiers.Sha512_256WithRSAEncryption);
  FOids.AddOrSetValue('SHA3-224withRSA', TNistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_224);
  FOids.AddOrSetValue('SHA3-256withRSA', TNistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_256);
  FOids.AddOrSetValue('SHA3-384withRSA', TNistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_384);
  FOids.AddOrSetValue('SHA3-512withRSA', TNistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_512);

  FOids.AddOrSetValue('PSSwithRSA', TPkcsObjectIdentifiers.IdRsassaPss);
  FOids.AddOrSetValue('SHA-1withRSAandMGF1', TPkcsObjectIdentifiers.IdRsassaPss);
  FOids.AddOrSetValue('SHA-224withRSAandMGF1', TPkcsObjectIdentifiers.IdRsassaPss);
  FOids.AddOrSetValue('SHA-256withRSAandMGF1', TPkcsObjectIdentifiers.IdRsassaPss);
  FOids.AddOrSetValue('SHA-384withRSAandMGF1', TPkcsObjectIdentifiers.IdRsassaPss);
  FOids.AddOrSetValue('SHA-512withRSAandMGF1', TPkcsObjectIdentifiers.IdRsassaPss);

  FOids.AddOrSetValue('RIPEMD128withRSA', TTeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD128);
  FOids.AddOrSetValue('RIPEMD160withRSA', TTeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD160);
  FOids.AddOrSetValue('RIPEMD256withRSA', TTeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD256);

  FOids.AddOrSetValue('SHA-1withDSA', TX9ObjectIdentifiers.IdDsaWithSha1);
  FOids.AddOrSetValue('SHA-224withDSA', TNistObjectIdentifiers.DsaWithSha224);
  FOids.AddOrSetValue('SHA-256withDSA', TNistObjectIdentifiers.DsaWithSha256);
  FOids.AddOrSetValue('SHA-384withDSA', TNistObjectIdentifiers.DsaWithSha384);
  FOids.AddOrSetValue('SHA-512withDSA', TNistObjectIdentifiers.DsaWithSha512);

  FOids.AddOrSetValue('SHA3-224withDSA', TNistObjectIdentifiers.IdDsaWithSha3_224);
  FOids.AddOrSetValue('SHA3-256withDSA', TNistObjectIdentifiers.IdDsaWithSha3_256);
  FOids.AddOrSetValue('SHA3-384withDSA', TNistObjectIdentifiers.IdDsaWithSha3_384);
  FOids.AddOrSetValue('SHA3-512withDSA', TNistObjectIdentifiers.IdDsaWithSha3_512);

  FOids.AddOrSetValue('SHA-1withECDSA', TX9ObjectIdentifiers.ECDsaWithSha1);
  FOids.AddOrSetValue('SHA-224withECDSA', TX9ObjectIdentifiers.ECDsaWithSha224);
  FOids.AddOrSetValue('SHA-256withECDSA', TX9ObjectIdentifiers.ECDsaWithSha256);
  FOids.AddOrSetValue('SHA-384withECDSA', TX9ObjectIdentifiers.ECDsaWithSha384);
  FOids.AddOrSetValue('SHA-512withECDSA', TX9ObjectIdentifiers.ECDsaWithSha512);
  FOids.AddOrSetValue('RIPEMD160withECDSA', TTeleTrusTObjectIdentifiers.ECSignWithRipeMD160);

  FOids.AddOrSetValue('SHA3-224withECDSA', TNistObjectIdentifiers.IdEcdsaWithSha3_224);
  FOids.AddOrSetValue('SHA3-256withECDSA', TNistObjectIdentifiers.IdEcdsaWithSha3_256);
  FOids.AddOrSetValue('SHA3-384withECDSA', TNistObjectIdentifiers.IdEcdsaWithSha3_384);
  FOids.AddOrSetValue('SHA3-512withECDSA', TNistObjectIdentifiers.IdEcdsaWithSha3_512);

  FOids.AddOrSetValue('SHA-1withCVC-ECDSA', TEacObjectIdentifiers.IdTAEcdsaSha1);
  FOids.AddOrSetValue('SHA-224withCVC-ECDSA', TEacObjectIdentifiers.IdTAEcdsaSha224);
  FOids.AddOrSetValue('SHA-256withCVC-ECDSA', TEacObjectIdentifiers.IdTAEcdsaSha256);
  FOids.AddOrSetValue('SHA-384withCVC-ECDSA', TEacObjectIdentifiers.IdTAEcdsaSha384);
  FOids.AddOrSetValue('SHA-512withCVC-ECDSA', TEacObjectIdentifiers.IdTAEcdsaSha512);

  FOids.AddOrSetValue('SHA-1withPLAIN-ECDSA', TBsiObjectIdentifiers.EcdsaPlainSha1);
  FOids.AddOrSetValue('SHA-224withPLAIN-ECDSA', TBsiObjectIdentifiers.EcdsaPlainSha224);
  FOids.AddOrSetValue('SHA-256withPLAIN-ECDSA', TBsiObjectIdentifiers.EcdsaPlainSha256);
  FOids.AddOrSetValue('SHA-384withPLAIN-ECDSA', TBsiObjectIdentifiers.EcdsaPlainSha384);
  FOids.AddOrSetValue('SHA-512withPLAIN-ECDSA', TBsiObjectIdentifiers.EcdsaPlainSha512);
  FOids.AddOrSetValue('RIPEMD160withPLAIN-ECDSA', TBsiObjectIdentifiers.EcdsaPlainRipeMD160);

  FOids.AddOrSetValue('SHA3-224withPLAIN-ECDSA', TBsiObjectIdentifiers.EcdsaPlainSha3_224);
  FOids.AddOrSetValue('SHA3-256withPLAIN-ECDSA', TBsiObjectIdentifiers.EcdsaPlainSha3_256);
  FOids.AddOrSetValue('SHA3-384withPLAIN-ECDSA', TBsiObjectIdentifiers.EcdsaPlainSha3_384);
  FOids.AddOrSetValue('SHA3-512withPLAIN-ECDSA', TBsiObjectIdentifiers.EcdsaPlainSha3_512);

  // EdDSA algorithms
  AddAlgorithm('Ed25519', TEdECObjectIdentifiers.IdEd25519, True);
  AddAlgorithm('Ed25519ctx', nil, True);
  AddAlgorithm('Ed25519ph', nil, True);
end;

class constructor TSignerUtilities.Create;
begin
  Boot;
end;

class destructor TSignerUtilities.Destroy;
begin
  FAlgorithmMap.Free;
  FAlgorithmOidMap.Free;
  FNoRandom.Free;
  FOids.Free;
end;

class function TSignerUtilities.GetMechanism(const AAlgorithm: String): String;
var
  LOid: IDerObjectIdentifier;
  LMechanism: String;
begin
  if FAlgorithmMap.TryGetValue(AAlgorithm, LMechanism) then
  begin
    Result := LMechanism;
    Exit;
  end;
  if TDerObjectIdentifier.TryFromID(AAlgorithm, LOid) and FAlgorithmOidMap.TryGetValue(LOid, LMechanism) then
  begin
    Result := LMechanism;
    Exit;
  end;
  Result := '';
end;

class function TSignerUtilities.GetAlgorithms: TCryptoLibStringArray;
var
  LList: TList<String>;
  LKey: String;
begin
  LList := TList<String>.Create;
  try
    for LKey in FOids.Keys do
      LList.Add(LKey);
    Result := LList.ToArray;
  finally
    LList.Free;
  end;
end;

class function TSignerUtilities.GetEncodingName(const AOid: IDerObjectIdentifier): String;
begin
  Result := TCollectionUtilities.GetValueOrNull<IDerObjectIdentifier, String>(FAlgorithmOidMap, AOid);
end;

class function TSignerUtilities.GetObjectIdentifier(const AMechanism: String): IDerObjectIdentifier;
var
  LCanonical: String;
begin
  if AMechanism = '' then
    raise EArgumentNilCryptoLibException.CreateRes(@SMechanismNil);
  LCanonical := TCollectionUtilities.GetValueOrKey<String>(FAlgorithmMap, UpperCase(AMechanism));
  FOids.TryGetValue(LCanonical, Result);
end;

class function TSignerUtilities.GetSigner(const AOid: IDerObjectIdentifier): ISigner;
var
  LMechanism: String;
  LSigner: ISigner;
begin
  if AOid = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SAlgorithmNil);

  if FAlgorithmOidMap.TryGetValue(AOid, LMechanism) then
  begin
    LSigner := GetSignerForMechanism(LMechanism);
    if LSigner <> nil then
    begin
      Result := LSigner;
      Exit;
    end;
  end;

  raise ESecurityUtilityCryptoLibException.CreateRes(@SUnRecognizedAlgorithm);
end;

class function TSignerUtilities.GetSigner(const AAlgorithm: String): ISigner;
var
  LMechanism: String;
  LSigner: ISigner;
begin
  if AAlgorithm = '' then
    raise EArgumentNilCryptoLibException.CreateRes(@SAlgorithmNil);

  LMechanism := GetMechanism(AAlgorithm);
  if LMechanism = '' then
    LMechanism := TStringUtilities.ToUpperInvariant(AAlgorithm);

  LSigner := GetSignerForMechanism(LMechanism);
  if LSigner <> nil then
  begin
    Result := LSigner;
    Exit;
  end;

  raise ESecurityUtilityCryptoLibException.CreateResFmt(@SUnRecognizedAlgorithm, [AAlgorithm]);
end;

class function TSignerUtilities.GetDefaultX509Parameters(const AOid: IDerObjectIdentifier): IAsn1Encodable;
var
  LMechanism: String;
begin
  if AOid = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SAlgorithmNil);

  if FAlgorithmOidMap.TryGetValue(AOid, LMechanism) then
    Result := GetDefaultX509ParametersForMechanism(LMechanism)
  else
    Result := TDerNull.Instance;
end;

class function TSignerUtilities.GetDefaultX509Parameters(const AAlgorithm: String): IAsn1Encodable;
var
  LMechanism: String;
begin
  if AAlgorithm = '' then
    raise EArgumentNilCryptoLibException.CreateRes(@SAlgorithmNil);

  LMechanism := GetMechanism(AAlgorithm);
  if LMechanism = '' then
    LMechanism := AAlgorithm;

  Result := GetDefaultX509ParametersForMechanism(LMechanism);
end;

class function TSignerUtilities.GetDefaultX509ParametersForMechanism(const AMechanism: String): IAsn1Encodable;
var
  LDigestName: String;
begin
  if AMechanism = 'PSSwithRSA' then
  begin
    // TODO The Sha1Digest here is a default. In JCE version, the actual digest
    // to be used can be overridden by subsequent parameter settings.
    Result := GetPssX509Parameters('SHA-1');
    Exit;
  end;

  if TStringUtilities.EndsWith(AMechanism, 'withRSAandMGF1') then
  begin
    LDigestName := TStringUtilities.Substring(AMechanism, 1, TStringUtilities.LastIndexOf(AMechanism, 'with') - 1);
    Result := GetPssX509Parameters(LDigestName);
    Exit;
  end;

  Result := TDerNull.Instance;
end;

class function TSignerUtilities.GetPssX509Parameters(const ADigestName: String): IAsn1Encodable;
var
  LHashAlgorithm: IAlgorithmIdentifier;
  LMaskGenAlgorithm: IAlgorithmIdentifier;
  LSaltLen: Int32;
  LDigest: IDigest;
begin
  LHashAlgorithm := TAlgorithmIdentifier.Create(
    TDigestUtilities.GetObjectIdentifier(ADigestName), TDerNull.Instance);

  // TODO Is it possible for the MGF hash alg to be different from the PSS one?
  LMaskGenAlgorithm := TAlgorithmIdentifier.Create(
    TPkcsObjectIdentifiers.IdMgf1, LHashAlgorithm);

  LDigest := TDigestUtilities.GetDigest(ADigestName);
  LSaltLen := LDigest.GetDigestSize();
  Result := TRsassaPssParameters.Create(LHashAlgorithm, LMaskGenAlgorithm,
    TDerInteger.ValueOf(LSaltLen), TRsassaPssParameters.DefaultTrailerField);
end;

class function TSignerUtilities.GetSignerForMechanism(const AMechanism: String): ISigner;
var
  LDigestName: String;
  LDigest: IDigest;
  LWithPos, LEndPos: Int32;
  LCipherName: String;
  LX931: String;
  LCipher: IAsymmetricBlockCipher;
begin
  Result := nil;

  // EdDSA algorithms
  if TStringUtilities.StartsWith(AMechanism, 'Ed') then
  begin
    if AMechanism = 'Ed25519' then
    begin
      Result := TEd25519Signer.Create() as IEd25519Signer;
      Exit;
    end;
    if AMechanism = 'Ed25519ctx' then
    begin
      Result := TEd25519CtxSigner.Create(nil) as IEd25519CtxSigner;
      Exit;
    end;
    if AMechanism = 'Ed25519ph' then
    begin
      Result := TEd25519PhSigner.Create(nil) as IEd25519PhSigner;
      Exit;
    end;
  end;

  if AMechanism = 'RSA' then
  begin
    Result := TGenericSigner.Create(TPkcs1Encoding.Create(TRsaBlindedEngine.Create() as IRsaBlindedEngine) as IPkcs1Encoding, TDigestUtilities.GetDigest('NONE'));
    Exit;
  end;

  if AMechanism = 'RAWRSASSA-PSS' then
  begin
    // TODO Add support for other parameter settings
    Result := TPssSigner.CreateRawSigner(TRsaBlindedEngine.Create() as IRsaBlindedEngine, TDigestUtilities.GetDigest('SHA-1'));
    Exit;
  end;

  if AMechanism = 'PSSwithRSA' then
  begin
    // TODO The Sha1Digest here is a default. In JCE version, the actual digest
    // to be used can be overridden by subsequent parameter settings.
    Result := TPssSigner.Create(TRsaBlindedEngine.Create() as IRsaBlindedEngine, TDigestUtilities.GetDigest('SHA-1'));
    Exit;
  end;

  if TStringUtilities.EndsWith(AMechanism, 'withRSA') then
  begin
    LDigestName := TStringUtilities.Substring(AMechanism, 1, TStringUtilities.LastIndexOf(AMechanism, 'with') - 1);
    LDigest := TDigestUtilities.GetDigest(LDigestName);
    Result := TRsaDigestSigner.Create(LDigest);
    Exit;
  end;

  if TStringUtilities.EndsWith(AMechanism, 'withRSAandMGF1') then
  begin
    LDigestName := TStringUtilities.Substring(AMechanism, 1, TStringUtilities.LastIndexOf(AMechanism, 'with') - 1);
    LDigest := TDigestUtilities.GetDigest(LDigestName);
    Result := TPssSigner.Create(TRsaBlindedEngine.Create() as IRsaBlindedEngine, LDigest);
    Exit;
  end;

  if TStringUtilities.EndsWith(AMechanism, 'withDSA') then
  begin
    LDigestName := TStringUtilities.Substring(AMechanism, 1, TStringUtilities.LastIndexOf(AMechanism, 'with') - 1);
    LDigest := TDigestUtilities.GetDigest(LDigestName);
    Result := TDsaDigestSigner.Create(TDsaSigner.Create() as IDsaSigner, LDigest);
    Exit;
  end;

  if TStringUtilities.EndsWith(AMechanism, 'withECDSA') then
  begin
    LDigestName := TStringUtilities.Substring(AMechanism, 1, TStringUtilities.LastIndexOf(AMechanism, 'with') - 1);
    LDigest := TDigestUtilities.GetDigest(LDigestName);
    Result := TDsaDigestSigner.Create(TECDsaSigner.Create() as IECDsaSigner, LDigest);
    Exit;
  end;

  if TStringUtilities.EndsWith(AMechanism, 'withCVC-ECDSA') or TStringUtilities.EndsWith(AMechanism, 'withPLAIN-ECDSA') then
  begin
    LDigestName := TStringUtilities.Substring(AMechanism, 1, TStringUtilities.LastIndexOf(AMechanism, 'with') - 1);
    LDigest := TDigestUtilities.GetDigest(LDigestName);
    Result := TDsaDigestSigner.Create(TECDsaSigner.Create() as IECDsaSigner, LDigest, TPlainDsaEncoding.Instance);
    Exit;
  end;

  if TStringUtilities.EndsWith(AMechanism, 'withECNR') then
  begin
    LDigestName := TStringUtilities.Substring(AMechanism, 1, TStringUtilities.LastIndexOf(AMechanism, 'with') - 1);
    LDigest := TDigestUtilities.GetDigest(LDigestName);
    Result := TDsaDigestSigner.Create(TECNRSigner.Create() as IECNRSigner, LDigest);
    Exit;
  end;

  // X9.31 section
  if TStringUtilities.EndsWith(AMechanism, '/X9.31') then
  begin
    LX931 := TStringUtilities.Substring(AMechanism, 1, System.Length(AMechanism) - System.Length('/X9.31'));
    LWithPos := TStringUtilities.IndexOf(LX931, 'WITH');
    if LWithPos > 0 then
    begin
      LEndPos := LWithPos + System.Length('WITH');

      LCipherName := TStringUtilities.Substring(LX931, LEndPos, System.Length(LX931) - LEndPos + 1);
      if LCipherName = 'RSA' then
      begin
        LCipher := TRsaBlindedEngine.Create();

        LDigestName := TStringUtilities.Substring(LX931, 1, LWithPos - 1);
        LDigest := TDigestUtilities.GetDigest(LDigestName);

        Result := TX931Signer.Create(LCipher, LDigest);
        Exit;
      end;
    end;
  end;
end;

class function TSignerUtilities.InitSigner(const AAlgorithmOid: IDerObjectIdentifier;
  AForSigning: Boolean; const APrivateKey: IAsymmetricKeyParameter;
  const ARandom: ISecureRandom): ISigner;
var
  LMechanism: String;
begin
  if AAlgorithmOid = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SAlgorithmNil);

  if not FAlgorithmOidMap.TryGetValue(AAlgorithmOid, LMechanism) then
    raise ESecurityUtilityCryptoLibException.CreateRes(@SUnRecognizedAlgorithm);

  Result := InitSignerForMechanism(LMechanism, AForSigning, APrivateKey, ARandom);
end;

class function TSignerUtilities.InitSigner(const AAlgorithm: String; AForSigning: Boolean;
  const APrivateKey: IAsymmetricKeyParameter; const ARandom: ISecureRandom): ISigner;
var
  LMechanism: String;
begin
  if AAlgorithm = '' then
    raise EArgumentNilCryptoLibException.CreateRes(@SAlgorithmNil);

  LMechanism := GetMechanism(AAlgorithm);
  if LMechanism = '' then
    LMechanism := TStringUtilities.ToUpperInvariant(AAlgorithm);

  Result := InitSignerForMechanism(LMechanism, AForSigning, APrivateKey, ARandom);
end;

class function TSignerUtilities.InitSignerForMechanism(const AMechanism: String;
  AForSigning: Boolean; const AKey: IAsymmetricKeyParameter;
  const ARandom: ISecureRandom): ISigner;
var
  LSigner: ISigner;
  LCipherParameters: ICipherParameters;
begin
  LSigner := GetSignerForMechanism(AMechanism);
  if LSigner = nil then
    raise ESecurityUtilityCryptoLibException.CreateResFmt(@SUnRecognizedAlgorithm, [AMechanism]);

  LCipherParameters := AKey;
  if AForSigning and (not FNoRandom.ContainsKey(AMechanism)) then
  begin
    LCipherParameters := TParameterUtilities.WithRandom(LCipherParameters, ARandom);
  end;

  LSigner.Init(AForSigning, LCipherParameters);
  Result := LSigner;
end;

end.
