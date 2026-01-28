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

unit ClpPkcs10CertificationRequest;

{$I ..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  Classes,
  Generics.Collections,
  ClpIAsn1Core,
  ClpAsn1Objects,
  ClpIAsn1Objects,
  ClpIPkcsAsn1Objects,
  ClpPkcsAsn1Objects,
  ClpPkcsObjectIdentifiers,
  ClpX509Asn1Objects,
  ClpIX509Asn1Objects,
  ClpX509Utilities,
  ClpX509ExtensionsGenerator,
  ClpIX509ExtensionsGenerator,
  ClpAsn1SignatureFactory,
  ClpAsn1VerifierFactoryProvider,
  ClpSubjectPublicKeyInfoFactory,
  ClpPublicKeyFactory,
  ClpISignatureFactory,
  ClpIVerifierFactory,
  ClpIVerifierFactoryProvider,
  ClpIAsymmetricKeyParameter,
  ClpNistObjectIdentifiers,
  ClpOiwObjectIdentifiers,
  ClpTeleTrusTObjectIdentifiers,
  ClpCryptoProObjectIdentifiers,
  ClpBsiObjectIdentifiers,
  ClpEdECObjectIdentifiers,
  ClpRosstandartObjectIdentifiers,
  ClpX9ObjectIdentifiers,
  ClpCryptoLibComparers,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// Interface for Pkcs10CertificationRequest (PKCS#10 CSR with verify/get public key/extensions).
  /// </summary>
  IPkcs10CertificationRequest = interface(ICertificationRequest)
    ['{D4E5F6A7-B8C9-0123-DEF0-123456789ABC}']

    function GetPublicKey: IAsymmetricKeyParameter;
    function GetRequestedExtensions: IX509Extensions;
    function Verify: Boolean; overload;
    function Verify(const APublicKey: IAsymmetricKeyParameter): Boolean; overload;
    function Verify(const AVerifierProvider: IVerifierFactoryProvider): Boolean; overload;
    function Verify(const AVerifier: IVerifierFactory): Boolean; overload;

    property RequestedExtensions: IX509Extensions read GetRequestedExtensions;
  end;

  /// <summary>
  /// A class for verifying and creating PKCS#10 Certification requests.
  /// </summary>
  TPkcs10CertificationRequest = class(TCertificationRequest, IPkcs10CertificationRequest)
  strict private
    procedure Init(const ASignatureFactory: ISignatureFactory;
      const ASubject: IX509Name; const APublicKey: IAsymmetricKeyParameter;
      const AAttributes: IAsn1Set); overload;
    procedure Init(const ASignatureFactory: ISignatureFactory;
      const ASubject: IX509Name; const APubInfo: ISubjectPublicKeyInfo;
      const AAttributes: IAsn1Set); overload;
  protected
    class var
      FAlgorithms: TDictionary<String, IDerObjectIdentifier>;
      FExParams: TDictionary<String, IAsn1Encodable>;
      FNoParams: TDictionary<IDerObjectIdentifier, Boolean>;
      FKeyAlgorithms: TDictionary<IDerObjectIdentifier, String>;
    class procedure Boot; static;
    class function CreatePssParams(const AHashAlgId: IAlgorithmIdentifier;
      ASaltSize: Int32): IRsassaPssParameters; static;
    class constructor Create;
    class destructor Destroy;
  public
    constructor Create(const AEncoded: TCryptoLibByteArray); overload;
    constructor Create(const ASeq: IAsn1Sequence); overload;
    constructor Create(const AInput: TStream); overload;

    constructor Create(const ASignatureAlgorithm: String;
      const ASubject: IX509Name; const APublicKey: IAsymmetricKeyParameter;
      const AAttributes: IAsn1Set; const ASigningKey: IAsymmetricKeyParameter); overload;
    constructor Create(const ASignatureAlgorithm: String;
      const ASubject: IX509Name; const APubInfo: ISubjectPublicKeyInfo;
      const AAttributes: IAsn1Set; const ASigningKey: IAsymmetricKeyParameter); overload;

    constructor Create(const ASignatureFactory: ISignatureFactory;
      const ASubject: IX509Name; const APublicKey: IAsymmetricKeyParameter;
      const AAttributes: IAsn1Set); overload;
    constructor Create(const ASignatureFactory: ISignatureFactory;
      const ASubject: IX509Name; const APubInfo: ISubjectPublicKeyInfo;
      const AAttributes: IAsn1Set); overload;

    function GetPublicKey: IAsymmetricKeyParameter;
    function GetRequestedExtensions: IX509Extensions;
    function Verify: Boolean; overload;
    function Verify(const APublicKey: IAsymmetricKeyParameter): Boolean; overload;
    function Verify(const AVerifierProvider: IVerifierFactoryProvider): Boolean; overload;
    function Verify(const AVerifier: IVerifierFactory): Boolean; overload;

    class function GetSignatureName(const ASigAlgId: IAlgorithmIdentifier): String; static;
    class function GetDigestAlgName(const ADigestAlgOID: IDerObjectIdentifier): String; static;
  end;

implementation

{ TPkcs10CertificationRequest }

class constructor TPkcs10CertificationRequest.Create;
begin
  Boot;
end;

class destructor TPkcs10CertificationRequest.Destroy;
begin
  FAlgorithms.Free;
  FExParams.Free;
  FNoParams.Free;
  FKeyAlgorithms.Free;
end;

class function TPkcs10CertificationRequest.CreatePssParams(const AHashAlgId: IAlgorithmIdentifier;
  ASaltSize: Int32): IRsassaPssParameters;
var
  LMgfAlgId: IAlgorithmIdentifier;
begin
  LMgfAlgId := TAlgorithmIdentifier.Create(TPkcsObjectIdentifiers.IdMgf1, AHashAlgId);
  Result := TRsassaPssParameters.Create(AHashAlgId, LMgfAlgId,
    TDerInteger.ValueOf(ASaltSize), TRsassaPssParameters.DefaultTrailerField);
end;

class procedure TPkcs10CertificationRequest.Boot;
var
  LSha1AlgId, LSha224AlgId, LSha256AlgId, LSha384AlgId, LSha512AlgId: IAlgorithmIdentifier;
begin
  FAlgorithms := TDictionary<String, IDerObjectIdentifier>.Create(TCryptoLibComparers.OrdinalIgnoreCaseEqualityComparer);
  FExParams := TDictionary<String, IAsn1Encodable>.Create(TCryptoLibComparers.OrdinalIgnoreCaseEqualityComparer);
  FNoParams := TDictionary<IDerObjectIdentifier, Boolean>.Create(TCryptoLibComparers.OidEqualityComparer);
  FKeyAlgorithms := TDictionary<IDerObjectIdentifier, String>.Create(TCryptoLibComparers.OidEqualityComparer);

  // FAlgorithms
  FAlgorithms.Add('MD2WITHRSAENCRYPTION', TPkcsObjectIdentifiers.MD2WithRsaEncryption);
  FAlgorithms.Add('MD2WITHRSA', TPkcsObjectIdentifiers.MD2WithRsaEncryption);
  FAlgorithms.Add('MD5WITHRSAENCRYPTION', TPkcsObjectIdentifiers.MD5WithRsaEncryption);
  FAlgorithms.Add('MD5WITHRSA', TPkcsObjectIdentifiers.MD5WithRsaEncryption);
  FAlgorithms.Add('RSAWITHMD5', TPkcsObjectIdentifiers.MD5WithRsaEncryption);
  FAlgorithms.Add('SHA1WITHRSAENCRYPTION', TPkcsObjectIdentifiers.Sha1WithRsaEncryption);
  FAlgorithms.Add('SHA-1WITHRSAENCRYPTION', TPkcsObjectIdentifiers.Sha1WithRsaEncryption);
  FAlgorithms.Add('SHA1WITHRSA', TPkcsObjectIdentifiers.Sha1WithRsaEncryption);
  FAlgorithms.Add('SHA-1WITHRSA', TPkcsObjectIdentifiers.Sha1WithRsaEncryption);
  FAlgorithms.Add('SHA224WITHRSAENCRYPTION', TPkcsObjectIdentifiers.Sha224WithRsaEncryption);
  FAlgorithms.Add('SHA-224WITHRSAENCRYPTION', TPkcsObjectIdentifiers.Sha224WithRsaEncryption);
  FAlgorithms.Add('SHA224WITHRSA', TPkcsObjectIdentifiers.Sha224WithRsaEncryption);
  FAlgorithms.Add('SHA-224WITHRSA', TPkcsObjectIdentifiers.Sha224WithRsaEncryption);
  FAlgorithms.Add('SHA256WITHRSAENCRYPTION', TPkcsObjectIdentifiers.Sha256WithRsaEncryption);
  FAlgorithms.Add('SHA-256WITHRSAENCRYPTION', TPkcsObjectIdentifiers.Sha256WithRsaEncryption);
  FAlgorithms.Add('SHA256WITHRSA', TPkcsObjectIdentifiers.Sha256WithRsaEncryption);
  FAlgorithms.Add('SHA-256WITHRSA', TPkcsObjectIdentifiers.Sha256WithRsaEncryption);
  FAlgorithms.Add('SHA384WITHRSAENCRYPTION', TPkcsObjectIdentifiers.Sha384WithRsaEncryption);
  FAlgorithms.Add('SHA-384WITHRSAENCRYPTION', TPkcsObjectIdentifiers.Sha384WithRsaEncryption);
  FAlgorithms.Add('SHA384WITHRSA', TPkcsObjectIdentifiers.Sha384WithRsaEncryption);
  FAlgorithms.Add('SHA-384WITHRSA', TPkcsObjectIdentifiers.Sha384WithRsaEncryption);
  FAlgorithms.Add('SHA512WITHRSAENCRYPTION', TPkcsObjectIdentifiers.Sha512WithRsaEncryption);
  FAlgorithms.Add('SHA-512WITHRSAENCRYPTION', TPkcsObjectIdentifiers.Sha512WithRsaEncryption);
  FAlgorithms.Add('SHA512WITHRSA', TPkcsObjectIdentifiers.Sha512WithRsaEncryption);
  FAlgorithms.Add('SHA-512WITHRSA', TPkcsObjectIdentifiers.Sha512WithRsaEncryption);
  FAlgorithms.Add('SHA512(224)WITHRSAENCRYPTION', TPkcsObjectIdentifiers.Sha512_224WithRsaEncryption);
  FAlgorithms.Add('SHA-512(224)WITHRSAENCRYPTION', TPkcsObjectIdentifiers.Sha512_224WithRsaEncryption);
  FAlgorithms.Add('SHA512(224)WITHRSA', TPkcsObjectIdentifiers.Sha512_224WithRsaEncryption);
  FAlgorithms.Add('SHA-512(224)WITHRSA', TPkcsObjectIdentifiers.Sha512_224WithRsaEncryption);
  FAlgorithms.Add('SHA512(256)WITHRSAENCRYPTION', TPkcsObjectIdentifiers.Sha512_256WithRsaEncryption);
  FAlgorithms.Add('SHA-512(256)WITHRSAENCRYPTION', TPkcsObjectIdentifiers.Sha512_256WithRsaEncryption);
  FAlgorithms.Add('SHA512(256)WITHRSA', TPkcsObjectIdentifiers.Sha512_256WithRsaEncryption);
  FAlgorithms.Add('SHA-512(256)WITHRSA', TPkcsObjectIdentifiers.Sha512_256WithRsaEncryption);
  FAlgorithms.Add('SHA1WITHRSAANDMGF1', TPkcsObjectIdentifiers.IdRsassaPss);
  FAlgorithms.Add('SHA224WITHRSAANDMGF1', TPkcsObjectIdentifiers.IdRsassaPss);
  FAlgorithms.Add('SHA256WITHRSAANDMGF1', TPkcsObjectIdentifiers.IdRsassaPss);
  FAlgorithms.Add('SHA384WITHRSAANDMGF1', TPkcsObjectIdentifiers.IdRsassaPss);
  FAlgorithms.Add('SHA512WITHRSAANDMGF1', TPkcsObjectIdentifiers.IdRsassaPss);
  FAlgorithms.Add('RSAWITHSHA1', TPkcsObjectIdentifiers.Sha1WithRsaEncryption);
  FAlgorithms.Add('RIPEMD128WITHRSAENCRYPTION', TTeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD128);
  FAlgorithms.Add('RIPEMD128WITHRSA', TTeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD128);
  FAlgorithms.Add('RIPEMD160WITHRSAENCRYPTION', TTeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD160);
  FAlgorithms.Add('RIPEMD160WITHRSA', TTeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD160);
  FAlgorithms.Add('RIPEMD256WITHRSAENCRYPTION', TTeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD256);
  FAlgorithms.Add('RIPEMD256WITHRSA', TTeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD256);
  FAlgorithms.Add('GOST3411WITHGOST3410', TCryptoProObjectIdentifiers.GostR3411x94WithGostR3410x94);
  FAlgorithms.Add('GOST3410WITHGOST3411', TCryptoProObjectIdentifiers.GostR3411x94WithGostR3410x94);
  FAlgorithms.Add('GOST3411WITHECGOST3410', TCryptoProObjectIdentifiers.GostR3411x94WithGostR3410x2001);
  FAlgorithms.Add('GOST3411WITHECGOST3410-2001', TCryptoProObjectIdentifiers.GostR3411x94WithGostR3410x2001);
  FAlgorithms.Add('GOST3411WITHGOST3410-2001', TCryptoProObjectIdentifiers.GostR3411x94WithGostR3410x2001);
  FAlgorithms.Add('GOST3411-2012-256WITHECGOST3410', TRosstandartObjectIdentifiers.IdTc26SignWithDigestGost3410_12_256);
  FAlgorithms.Add('GOST3411-2012-256WITHECGOST3410-2012-256', TRosstandartObjectIdentifiers.IdTc26SignWithDigestGost3410_12_256);
  FAlgorithms.Add('GOST3411-2012-512WITHECGOST3410', TRosstandartObjectIdentifiers.IdTc26SignWithDigestGost3410_12_512);
  FAlgorithms.Add('GOST3411-2012-512WITHECGOST3410-2012-512', TRosstandartObjectIdentifiers.IdTc26SignWithDigestGost3410_12_512);
  FAlgorithms.Add('SHA1WITHDSA', TX9ObjectIdentifiers.IdDsaWithSha1);
  FAlgorithms.Add('DSAWITHSHA1', TX9ObjectIdentifiers.IdDsaWithSha1);
  FAlgorithms.Add('SHA224WITHDSA', TNistObjectIdentifiers.DsaWithSha224);
  FAlgorithms.Add('SHA256WITHDSA', TNistObjectIdentifiers.DsaWithSha256);
  FAlgorithms.Add('SHA384WITHDSA', TNistObjectIdentifiers.DsaWithSha384);
  FAlgorithms.Add('SHA512WITHDSA', TNistObjectIdentifiers.DsaWithSha512);
  FAlgorithms.Add('SHA3-224WITHDSA', TNistObjectIdentifiers.IdDsaWithSha3_224);
  FAlgorithms.Add('SHA3-256WITHDSA', TNistObjectIdentifiers.IdDsaWithSha3_256);
  FAlgorithms.Add('SHA3-384WITHDSA', TNistObjectIdentifiers.IdDsaWithSha3_384);
  FAlgorithms.Add('SHA3-512WITHDSA', TNistObjectIdentifiers.IdDsaWithSha3_512);
  FAlgorithms.Add('SHA1WITHECDSA', TX9ObjectIdentifiers.ECDsaWithSha1);
  FAlgorithms.Add('ECDSAWITHSHA1', TX9ObjectIdentifiers.ECDsaWithSha1);
  FAlgorithms.Add('SHA224WITHECDSA', TX9ObjectIdentifiers.ECDsaWithSha224);
  FAlgorithms.Add('SHA256WITHECDSA', TX9ObjectIdentifiers.ECDsaWithSha256);
  FAlgorithms.Add('SHA384WITHECDSA', TX9ObjectIdentifiers.ECDsaWithSha384);
  FAlgorithms.Add('SHA512WITHECDSA', TX9ObjectIdentifiers.ECDsaWithSha512);
  FAlgorithms.Add('SHA3-224WITHECDSA', TNistObjectIdentifiers.IdECDsaWithSha3_224);
  FAlgorithms.Add('SHA3-256WITHECDSA', TNistObjectIdentifiers.IdECDsaWithSha3_256);
  FAlgorithms.Add('SHA3-384WITHECDSA', TNistObjectIdentifiers.IdECDsaWithSha3_384);
  FAlgorithms.Add('SHA3-512WITHECDSA', TNistObjectIdentifiers.IdECDsaWithSha3_512);
  FAlgorithms.Add('SHA1WITHPLAIN-ECDSA', TBsiObjectIdentifiers.EcdsaPlainSha1);
  FAlgorithms.Add('SHA224WITHPLAIN-ECDSA', TBsiObjectIdentifiers.EcdsaPlainSha224);
  FAlgorithms.Add('SHA256WITHPLAIN-ECDSA', TBsiObjectIdentifiers.EcdsaPlainSha256);
  FAlgorithms.Add('SHA384WITHPLAIN-ECDSA', TBsiObjectIdentifiers.EcdsaPlainSha384);
  FAlgorithms.Add('SHA512WITHPLAIN-ECDSA', TBsiObjectIdentifiers.EcdsaPlainSha512);
  FAlgorithms.Add('RIPEMD160WITHPLAIN-ECDSA', TBsiObjectIdentifiers.EcdsaPlainRipeMD160);
  FAlgorithms.Add('SHA3-224WITHPLAIN-ECDSA', TBsiObjectIdentifiers.EcdsaPlainSha3_224);
  FAlgorithms.Add('SHA3-256WITHPLAIN-ECDSA', TBsiObjectIdentifiers.EcdsaPlainSha3_256);
  FAlgorithms.Add('SHA3-384WITHPLAIN-ECDSA', TBsiObjectIdentifiers.EcdsaPlainSha3_384);
  FAlgorithms.Add('SHA3-512WITHPLAIN-ECDSA', TBsiObjectIdentifiers.EcdsaPlainSha3_512);
  FAlgorithms.Add('Ed25519', TEdECObjectIdentifiers.IdEd25519);
  FAlgorithms.Add('Ed448', TEdECObjectIdentifiers.IdEd448);

  // FKeyAlgorithms
  FKeyAlgorithms.Add(TPkcsObjectIdentifiers.RsaEncryption, 'RSA');
  FKeyAlgorithms.Add(TX9ObjectIdentifiers.IdDsa, 'DSA');

  // FNoParams
  FNoParams.Add(TX9ObjectIdentifiers.IdDsaWithSha1, True);
  FNoParams.Add(TOiwObjectIdentifiers.DsaWithSha1, True);
  FNoParams.Add(TNistObjectIdentifiers.DsaWithSha224, True);
  FNoParams.Add(TNistObjectIdentifiers.DsaWithSha256, True);
  FNoParams.Add(TNistObjectIdentifiers.DsaWithSha384, True);
  FNoParams.Add(TNistObjectIdentifiers.DsaWithSha512, True);
  FNoParams.Add(TNistObjectIdentifiers.IdDsaWithSha3_224, True);
  FNoParams.Add(TNistObjectIdentifiers.IdDsaWithSha3_256, True);
  FNoParams.Add(TNistObjectIdentifiers.IdDsaWithSha3_384, True);
  FNoParams.Add(TNistObjectIdentifiers.IdDsaWithSha3_512, True);
  FNoParams.Add(TX9ObjectIdentifiers.ECDsaWithSha1, True);
  FNoParams.Add(TX9ObjectIdentifiers.ECDsaWithSha224, True);
  FNoParams.Add(TX9ObjectIdentifiers.ECDsaWithSha256, True);
  FNoParams.Add(TX9ObjectIdentifiers.ECDsaWithSha384, True);
  FNoParams.Add(TX9ObjectIdentifiers.ECDsaWithSha512, True);
  FNoParams.Add(TNistObjectIdentifiers.IdECDsaWithSha3_224, True);
  FNoParams.Add(TNistObjectIdentifiers.IdECDsaWithSha3_256, True);
  FNoParams.Add(TNistObjectIdentifiers.IdECDsaWithSha3_384, True);
  FNoParams.Add(TNistObjectIdentifiers.IdECDsaWithSha3_512, True);
  FNoParams.Add(TBsiObjectIdentifiers.EcdsaPlainSha224, True);
  FNoParams.Add(TBsiObjectIdentifiers.EcdsaPlainSha256, True);
  FNoParams.Add(TBsiObjectIdentifiers.EcdsaPlainSha384, True);
  FNoParams.Add(TBsiObjectIdentifiers.EcdsaPlainSha512, True);
  FNoParams.Add(TBsiObjectIdentifiers.EcdsaPlainSha3_224, True);
  FNoParams.Add(TBsiObjectIdentifiers.EcdsaPlainSha3_256, True);
  FNoParams.Add(TBsiObjectIdentifiers.EcdsaPlainSha3_384, True);
  FNoParams.Add(TBsiObjectIdentifiers.EcdsaPlainSha3_512, True);
  FNoParams.Add(TCryptoProObjectIdentifiers.GostR3411x94WithGostR3410x94, True);
  FNoParams.Add(TCryptoProObjectIdentifiers.GostR3411x94WithGostR3410x2001, True);
  FNoParams.Add(TEdECObjectIdentifiers.IdEd25519, True);
  FNoParams.Add(TEdECObjectIdentifiers.IdEd448, True);

  // FExParams (PSS)
  LSha1AlgId := TAlgorithmIdentifier.Create(TOiwObjectIdentifiers.IdSha1, TDerNull.Instance);
  FExParams.Add('SHA1WITHRSAANDMGF1', CreatePssParams(LSha1AlgId, 20));
  LSha224AlgId := TAlgorithmIdentifier.Create(TNistObjectIdentifiers.IdSha224, TDerNull.Instance);
  FExParams.Add('SHA224WITHRSAANDMGF1', CreatePssParams(LSha224AlgId, 28));
  LSha256AlgId := TAlgorithmIdentifier.Create(TNistObjectIdentifiers.IdSha256, TDerNull.Instance);
  FExParams.Add('SHA256WITHRSAANDMGF1', CreatePssParams(LSha256AlgId, 32));
  LSha384AlgId := TAlgorithmIdentifier.Create(TNistObjectIdentifiers.IdSha384, TDerNull.Instance);
  FExParams.Add('SHA384WITHRSAANDMGF1', CreatePssParams(LSha384AlgId, 48));
  LSha512AlgId := TAlgorithmIdentifier.Create(TNistObjectIdentifiers.IdSha512, TDerNull.Instance);
  FExParams.Add('SHA512WITHRSAANDMGF1', CreatePssParams(LSha512AlgId, 64));
end;

constructor TPkcs10CertificationRequest.Create(const AEncoded: TCryptoLibByteArray);
begin
  inherited Create(TAsn1Sequence.GetInstance(AEncoded));
end;

constructor TPkcs10CertificationRequest.Create(const ASeq: IAsn1Sequence);
begin
  inherited Create(ASeq);
end;

constructor TPkcs10CertificationRequest.Create(const AInput: TStream);
begin
  inherited Create(TAsn1Sequence.GetInstance(TAsn1Object.FromStream(AInput)));
end;

constructor TPkcs10CertificationRequest.Create(const ASignatureAlgorithm: String;
  const ASubject: IX509Name; const APublicKey: IAsymmetricKeyParameter;
  const AAttributes: IAsn1Set; const ASigningKey: IAsymmetricKeyParameter);
begin
  inherited Create();
  Init(TAsn1SignatureFactory.Create(ASignatureAlgorithm, ASigningKey), ASubject, APublicKey, AAttributes);
end;

constructor TPkcs10CertificationRequest.Create(const ASignatureAlgorithm: String;
  const ASubject: IX509Name; const APubInfo: ISubjectPublicKeyInfo;
  const AAttributes: IAsn1Set; const ASigningKey: IAsymmetricKeyParameter);
begin
  inherited Create();
  Init(TAsn1SignatureFactory.Create(ASignatureAlgorithm, ASigningKey), ASubject, APubInfo, AAttributes);
end;

constructor TPkcs10CertificationRequest.Create(const ASignatureFactory: ISignatureFactory;
  const ASubject: IX509Name; const APublicKey: IAsymmetricKeyParameter;
  const AAttributes: IAsn1Set);
begin
  inherited Create();
  if ASignatureFactory = nil then
    raise EArgumentNilCryptoLibException.Create('signatureFactory');
  if ASubject = nil then
    raise EArgumentNilCryptoLibException.Create('subject');
  if APublicKey = nil then
    raise EArgumentNilCryptoLibException.Create('publicKey');
  if APublicKey.IsPrivate then
    raise EArgumentCryptoLibException.Create('expected public key');
  Init(ASignatureFactory, ASubject, APublicKey, AAttributes);
end;

constructor TPkcs10CertificationRequest.Create(const ASignatureFactory: ISignatureFactory;
  const ASubject: IX509Name; const APubInfo: ISubjectPublicKeyInfo;
  const AAttributes: IAsn1Set);
begin
  inherited Create();
  if ASignatureFactory = nil then
    raise EArgumentNilCryptoLibException.Create('signatureFactory');
  if ASubject = nil then
    raise EArgumentNilCryptoLibException.Create('subject');
  if APubInfo = nil then
    raise EArgumentNilCryptoLibException.Create('pubInfo');
  Init(ASignatureFactory, ASubject, APubInfo, AAttributes);
end;

procedure TPkcs10CertificationRequest.Init(const ASignatureFactory: ISignatureFactory;
  const ASubject: IX509Name; const APublicKey: IAsymmetricKeyParameter;
  const AAttributes: IAsn1Set);
var
  LPubInfo: ISubjectPublicKeyInfo;
begin
  LPubInfo := TSubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(APublicKey);
  Init(ASignatureFactory, ASubject, LPubInfo, AAttributes);
end;

procedure TPkcs10CertificationRequest.Init(const ASignatureFactory: ISignatureFactory;
  const ASubject: IX509Name; const APubInfo: ISubjectPublicKeyInfo;
  const AAttributes: IAsn1Set);
begin
  FSigAlgId := ASignatureFactory.AlgorithmDetails;
  FReqInfo := TCertificationRequestInfo.Create(ASubject, APubInfo, AAttributes);
  FSigBits := TX509Utilities.GenerateSignature(ASignatureFactory, FReqInfo);
end;

function TPkcs10CertificationRequest.GetPublicKey: IAsymmetricKeyParameter;
begin
  Result := TPublicKeyFactory.CreateKey(GetCertificationRequestInfo.SubjectPublicKeyInfo);
end;

function TPkcs10CertificationRequest.Verify: Boolean;
begin
  Result := Verify(GetPublicKey());
end;

function TPkcs10CertificationRequest.Verify(const APublicKey: IAsymmetricKeyParameter): Boolean;
begin
  Result := Verify(TAsn1VerifierFactoryProvider.Create(APublicKey));
end;

function TPkcs10CertificationRequest.Verify(const AVerifierProvider: IVerifierFactoryProvider): Boolean;
var
  LVerifier: IVerifierFactory;
begin
  LVerifier := AVerifierProvider.CreateVerifierFactory(GetSignatureAlgorithm);
  Result := Verify(LVerifier);
end;

function TPkcs10CertificationRequest.Verify(const AVerifier: IVerifierFactory): Boolean;
begin
  try
    Result := TX509Utilities.VerifySignature(AVerifier, FReqInfo, FSigBits);
  except
    on E: Exception do
      raise EInvalidOperationCryptoLibException.Create('exception encoding TBS cert request: ' + E.Message);
  end;
end;

function TPkcs10CertificationRequest.GetRequestedExtensions: IX509Extensions;
var
  LAttrs: IAsn1Set;
  I, J, LCount: Int32;
  LAttr: IAttributePkcs;
  LAttrValues: IAsn1Set;
  LExtSeq: IAsn1Sequence;
  LItemSeq: IAsn1Sequence;
  LGen: IX509ExtensionsGenerator;
  LCritical: Boolean;
begin
  Result := nil;
  LAttrs := GetCertificationRequestInfo.Attributes;
  if LAttrs = nil then
    Exit;

  for I := 0 to LAttrs.Count - 1 do
  begin
    try
      LAttr := TAttributePkcs.GetInstance(LAttrs[I]);
    except
      on E: Exception do
        raise EArgumentCryptoLibException.Create('encountered non PKCS attribute in extensions block: ' + E.Message);
    end;

    if TPkcsObjectIdentifiers.Pkcs9AtExtensionRequest.Equals(LAttr.AttrType) then
    begin
      LGen := TX509ExtensionsGenerator.Create();
      LAttrValues := LAttr.AttrValues;
      if (LAttrValues = nil) or (LAttrValues.Count = 0) then
        raise EInvalidOperationCryptoLibException.Create('pkcs_9_at_extensionRequest present but has no value');

      LExtSeq := TAsn1Sequence.GetInstance(LAttrValues[0]);
      try
        for J := 0 to LExtSeq.Count - 1 do
        begin
          LItemSeq := TAsn1Sequence.GetInstance(LExtSeq[J]);
          LCount := LItemSeq.Count;
          if LCount = 2 then
            LGen.AddExtension(TDerObjectIdentifier.GetInstance(LItemSeq[0]), False,
              TAsn1OctetString.GetInstance(LItemSeq[1]).GetOctets())
          else if LCount = 3 then
          begin
            LCritical := TDerBoolean.GetInstance(LItemSeq[1]).IsTrue;
            LGen.AddExtension(TDerObjectIdentifier.GetInstance(LItemSeq[0]), LCritical,
              TAsn1OctetString.GetInstance(LItemSeq[2]).GetOctets());
          end
          else
            raise EInvalidOperationCryptoLibException.CreateFmt(
              'incorrect sequence size of X509Extension got %d expected 2 or 3', [LCount]);
        end;
      except
        on E: EArgumentCryptoLibException do
          raise;
        on E: Exception do
          raise EInvalidOperationCryptoLibException.Create('asn1 processing issue: ' + E.Message);
      end;
      Result := LGen.Generate();
      Exit;
    end;
  end;
end;

class function TPkcs10CertificationRequest.GetSignatureName(const ASigAlgId: IAlgorithmIdentifier): String;
var
  LParams: IAsn1Encodable;
  LRsaParams: IRsassaPssParameters;
begin
  LParams := ASigAlgId.Parameters;
  if (LParams <> nil) and (not TDerNull.Instance.Equals(LParams)) then
  begin
    if ASigAlgId.Algorithm.Equals(TPkcsObjectIdentifiers.IdRsassaPss) then
    begin
      LRsaParams := TRsassaPssParameters.GetInstance(LParams);
      Result := GetDigestAlgName(LRsaParams.HashAlgorithm.Algorithm) + 'withRSAandMGF1';
      Exit;
    end;
  end;
  Result := ASigAlgId.Algorithm.Id;
end;

class function TPkcs10CertificationRequest.GetDigestAlgName(const ADigestAlgOID: IDerObjectIdentifier): String;
begin
  if TPkcsObjectIdentifiers.MD5.Equals(ADigestAlgOID) then
    Result := 'MD5'
  else if TOiwObjectIdentifiers.IdSha1.Equals(ADigestAlgOID) then
    Result := 'SHA1'
  else if TNistObjectIdentifiers.IdSha224.Equals(ADigestAlgOID) then
    Result := 'SHA224'
  else if TNistObjectIdentifiers.IdSha256.Equals(ADigestAlgOID) then
    Result := 'SHA256'
  else if TNistObjectIdentifiers.IdSha384.Equals(ADigestAlgOID) then
    Result := 'SHA384'
  else if TNistObjectIdentifiers.IdSha512.Equals(ADigestAlgOID) then
    Result := 'SHA512'
  else if TNistObjectIdentifiers.IdSha512_224.Equals(ADigestAlgOID) then
    Result := 'SHA512(224)'
  else if TNistObjectIdentifiers.IdSha512_256.Equals(ADigestAlgOID) then
    Result := 'SHA512(256)'
  else if TTeleTrusTObjectIdentifiers.RipeMD128.Equals(ADigestAlgOID) then
    Result := 'RIPEMD128'
  else if TTeleTrusTObjectIdentifiers.RipeMD160.Equals(ADigestAlgOID) then
    Result := 'RIPEMD160'
  else if TTeleTrusTObjectIdentifiers.RipeMD256.Equals(ADigestAlgOID) then
    Result := 'RIPEMD256'
  else if TCryptoProObjectIdentifiers.GostR3411.Equals(ADigestAlgOID) then
    Result := 'GOST3411'
  else
    Result := ADigestAlgOID.Id;
end;

end.
