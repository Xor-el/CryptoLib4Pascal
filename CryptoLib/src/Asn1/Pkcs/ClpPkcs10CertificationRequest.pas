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

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpAsn1Objects,
  ClpIAsn1Objects,
  ClpAlgorithmIdentifier,
  ClpIAlgorithmIdentifier,
  ClpSubjectPublicKeyInfo,
  ClpISubjectPublicKeyInfo,
  ClpIX500Name,
  ClpIPkcs10CertificationRequest,
  ClpIAsymmetricKeyParameter,
  ClpIECPublicKeyParameters,
  ClpIECPrivateKeyParameters,
  ClpIDigest,
  ClpDigestUtilities,
  ClpECDsaSigner,
  ClpIECDsaSigner,
  ClpSignersEncodings,
  ClpISignersEncodings,
  ClpHMacDsaKCalculator,
  ClpIHMacDsaKCalculator,
  ClpX9ObjectIdentifiers,
  ClpEncoders,
  ClpBigInteger,
  // EdDSA support
  ClpIEd25519PublicKeyParameters,
  ClpIEd25519PrivateKeyParameters,
  ClpSignerUtilities,
  ClpISigner,
  ClpEdECObjectIdentifiers,
  ClpCryptoLibTypes,
  Generics.Collections;

resourcestring
  SInvalidPkcs10Request = 'Invalid PKCS#10 Certification Request: %s';
  SBadSequenceSize = 'Bad Sequence Size: %d';
  SUnsupportedDigest = 'Unsupported digest algorithm: %s';
  SPublicKeyNotSet = 'Public key must be set before adding Subject Key Identifier';
  SSubjectNotSet = 'Subject must be set before calling Build';
  SPublicKeyRequiredForBuild = 'Public key must be set before calling Build';

type
  /// <summary>
  /// PKCS#9 Object Identifiers
  /// </summary>
  TPkcs9Oids = class abstract(TObject)
  strict private
    class var
      FExtensionRequest: IDerObjectIdentifier;
      class function GetExtensionRequest: IDerObjectIdentifier; static;
  public
    /// <summary>extensionRequest (1.2.840.113549.1.9.14)</summary>
    class property ExtensionRequest: IDerObjectIdentifier read GetExtensionRequest;
  end;

  /// <summary>
  /// X.509 Extension Object Identifiers
  /// </summary>
  TX509ExtensionOids = class abstract(TObject)
  strict private
    class var
      FSubjectKeyIdentifier: IDerObjectIdentifier;
      class function GetSubjectKeyIdentifier: IDerObjectIdentifier; static;
  public
    /// <summary>subjectKeyIdentifier (2.5.29.14)</summary>
    class property SubjectKeyIdentifier: IDerObjectIdentifier read GetSubjectKeyIdentifier;
  end;

type
  /// <summary>
  /// PKCS#10 CertificationRequestInfo - the to-be-signed portion
  /// CertificationRequestInfo ::= SEQUENCE {
  ///   version INTEGER { v1(0) },
  ///   subject Name,
  ///   subjectPKInfo SubjectPublicKeyInfo,
  ///   attributes [0] IMPLICIT Attributes {{ CRIAttributes }} }
  /// </summary>
  TPkcs10CertificationRequestInfo = class(TAsn1Encodable, IPkcs10CertificationRequestInfo)

  strict private
  var
    FVersion: IDerInteger;
    FSubject: IX500Name;
    FSubjectPublicKeyInfo: ISubjectPublicKeyInfo;
    FAttributes: IDerTaggedObject;

    function GetVersion: IDerInteger;
    function GetSubject: IX500Name;
    function GetSubjectPublicKeyInfo: ISubjectPublicKeyInfo;

  public
    constructor Create(const subject: IX500Name;
      const subjectPublicKeyInfo: ISubjectPublicKeyInfo;
      const attributes: IDerTaggedObject = nil); overload;

    function ToAsn1Object(): IAsn1Object; override;

    property Version: IDerInteger read GetVersion;
    property Subject: IX500Name read GetSubject;
    property SubjectPublicKeyInfo: ISubjectPublicKeyInfo read GetSubjectPublicKeyInfo;
  end;

type
  /// <summary>
  /// Complete PKCS#10 CertificationRequest
  /// CertificationRequest ::= SEQUENCE {
  ///   certificationRequestInfo CertificationRequestInfo,
  ///   signatureAlgorithm AlgorithmIdentifier,
  ///   signature BIT STRING }
  /// </summary>
  TPkcs10CertificationRequest = class(TAsn1Encodable, IPkcs10CertificationRequest)

  strict private
  var
    FCertificationRequestInfo: IPkcs10CertificationRequestInfo;
    FSignatureAlgorithm: IAlgorithmIdentifier;
    FSignature: IDerBitString;

    function GetCertificationRequestInfo: IPkcs10CertificationRequestInfo;
    function GetSignatureAlgorithm: IAlgorithmIdentifier;
    function GetSignature: IDerBitString;

  public
    constructor Create(const certReqInfo: IPkcs10CertificationRequestInfo;
      const sigAlg: IAlgorithmIdentifier; const signature: IDerBitString);

    function ToAsn1Object(): IAsn1Object; override;
    function GetEncoded(): TCryptoLibByteArray; overload;
    function GetPemEncoded: string;

    property CertificationRequestInfo: IPkcs10CertificationRequestInfo read GetCertificationRequestInfo;
    property SignatureAlgorithm: IAlgorithmIdentifier read GetSignatureAlgorithm;
    property Signature: IDerBitString read GetSignature;
  end;

type
  /// <summary>
  /// Abstract base class for PKCS#10 Certification Request Builders.
  /// Provides common functionality for SetSubject and CSR creation.
  /// </summary>
  TPkcs10CertificationRequestBuilderBase = class abstract(TInterfacedObject, IPkcs10CertificationRequestBuilder)
  strict protected
  var
    FSubject: IX500Name;
    FExtensions: TList<IAsn1Encodable>;
    FPublicKeyBytes: TCryptoLibByteArray;

    /// <summary>
    /// Creates the final CSR from the provided components.
    /// Shared helper used by all subclasses.
    /// </summary>
    function CreateCSR(const subjectPKInfo: ISubjectPublicKeyInfo;
      const sigAlg: IAlgorithmIdentifier;
      const sigBytes: TCryptoLibByteArray): IPkcs10CertificationRequest;

    /// <summary>
    /// Builds the extensionRequest attribute from stored extensions.
    /// </summary>
    function BuildAttributes: IDerTaggedObject;

    /// <summary>
    /// Stores the public key bytes for Subject Key Identifier computation.
    /// </summary>
    procedure SetPublicKeyBytes(const pubKeyBytes: TCryptoLibByteArray);

  public
    constructor Create();
    destructor Destroy; override;

    function SetSubject(const subject: IX500Name): IPkcs10CertificationRequestBuilder;
    function SetPublicKey(const publicKey: IAsymmetricKeyParameter): IPkcs10CertificationRequestBuilder; virtual; abstract;
    function Build(const privateKey: IAsymmetricKeyParameter): IPkcs10CertificationRequest; virtual; abstract;
    function AddExtension(const oid: IDerObjectIdentifier; critical: Boolean;
      const value: IAsn1Encodable): IPkcs10CertificationRequestBuilder;
    function AddSubjectKeyIdentifier: IPkcs10CertificationRequestBuilder;
  end;

type
  /// <summary>
  /// ECDSA-based PKCS#10 Certification Request Builder.
  /// Digest algorithm is specified at construction time.
  /// </summary>
  TECDSACertificationRequestBuilder = class(TPkcs10CertificationRequestBuilderBase)
  strict private
  class var
    FDigestToOidMap: TDictionary<string, IDerObjectIdentifier>;

  var
    FPublicKey: IECPublicKeyParameters;
    FDigest: IDigest;

    function GetSignatureAlgorithmOid: IDerObjectIdentifier;

    class constructor Create;
    class destructor Destroy;

  public
    /// <summary>
    /// Create ECDSA builder with specified digest algorithm.
    /// </summary>
    constructor Create(const digest: IDigest);

    function SetPublicKey(const publicKey: IAsymmetricKeyParameter): IPkcs10CertificationRequestBuilder; override;
    function Build(const privateKey: IAsymmetricKeyParameter): IPkcs10CertificationRequest; override;
  end;

type
  /// <summary>
  /// EdDSA-based PKCS#10 Certification Request Builder.
  /// Supports EdDSA (Ed25519). No digest parameter needed.
  /// </summary>
  TEdDSACertificationRequestBuilder = class(TPkcs10CertificationRequestBuilderBase)
  strict private
  var
    FEd25519PublicKey: IEd25519PublicKeyParameters;

  public
    constructor Create();

    function SetPublicKey(const publicKey: IAsymmetricKeyParameter): IPkcs10CertificationRequestBuilder; override;
    function Build(const privateKey: IAsymmetricKeyParameter): IPkcs10CertificationRequest; override;
  end;

implementation

{ TPkcs10CertificationRequestInfo }

constructor TPkcs10CertificationRequestInfo.Create(const subject: IX500Name;
  const subjectPublicKeyInfo: ISubjectPublicKeyInfo;
  const attributes: IDerTaggedObject = nil);
begin
  inherited Create();
  FVersion := TDerInteger.Create(0); // v1(0)
  FSubject := subject;
  FSubjectPublicKeyInfo := subjectPublicKeyInfo;
  FAttributes := attributes;
end;

function TPkcs10CertificationRequestInfo.GetVersion: IDerInteger;
begin
  Result := FVersion;
end;

function TPkcs10CertificationRequestInfo.GetSubject: IX500Name;
begin
  Result := FSubject;
end;

function TPkcs10CertificationRequestInfo.GetSubjectPublicKeyInfo: ISubjectPublicKeyInfo;
begin
  Result := FSubjectPublicKeyInfo;
end;

function TPkcs10CertificationRequestInfo.ToAsn1Object: IAsn1Object;
var
  v: IAsn1EncodableVector;
  subjectAsn1, pkInfoAsn1: IAsn1Object;
  attrsToUse: IDerTaggedObject;
begin
  // Get the underlying ASN1 objects
  subjectAsn1 := FSubject.ToAsn1Object;
  pkInfoAsn1 := FSubjectPublicKeyInfo.ToAsn1Object;

  // Use provided attributes or empty SET
  if FAttributes <> nil then
    attrsToUse := FAttributes
  else
    attrsToUse := TDerTaggedObject.Create(False, 0,
      TDerSequence.Create() as IAsn1Encodable);

  // Build using vector
  v := TAsn1EncodableVector.Create();
  v.Add(FVersion);
  v.Add(subjectAsn1);
  v.Add(pkInfoAsn1);
  v.Add(attrsToUse);

  Result := TDerSequence.FromVector(v);
end;

{ TPkcs10CertificationRequest }

constructor TPkcs10CertificationRequest.Create(
  const certReqInfo: IPkcs10CertificationRequestInfo;
  const sigAlg: IAlgorithmIdentifier; const signature: IDerBitString);
begin
  inherited Create();
  FCertificationRequestInfo := certReqInfo;
  FSignatureAlgorithm := sigAlg;
  FSignature := signature;
end;

function TPkcs10CertificationRequest.GetCertificationRequestInfo: IPkcs10CertificationRequestInfo;
begin
  Result := FCertificationRequestInfo;
end;

function TPkcs10CertificationRequest.GetSignatureAlgorithm: IAlgorithmIdentifier;
begin
  Result := FSignatureAlgorithm;
end;

function TPkcs10CertificationRequest.GetSignature: IDerBitString;
begin
  Result := FSignature;
end;

function TPkcs10CertificationRequest.ToAsn1Object: IAsn1Object;
var
  v: IAsn1EncodableVector;
  certReqInfoAsn1, sigAlgAsn1: IAsn1Object;
begin
  certReqInfoAsn1 := FCertificationRequestInfo.ToAsn1Object;
  sigAlgAsn1 := FSignatureAlgorithm.ToAsn1Object;

  v := TAsn1EncodableVector.Create();
  v.Add(certReqInfoAsn1);
  v.Add(sigAlgAsn1);
  v.Add(FSignature);

  Result := TDerSequence.FromVector(v);
end;

function TPkcs10CertificationRequest.GetEncoded: TCryptoLibByteArray;
begin
  Result := ToAsn1Object.GetEncoded(TAsn1Encodable.Der);
end;

function TPkcs10CertificationRequest.GetPemEncoded: string;
var
  derBytes: TCryptoLibByteArray;
  base64: string;
  sb: TStringBuilder;
  i, lineLen: Integer;
begin
  derBytes := GetEncoded;
  base64 := TBase64.Encode(derBytes);

  sb := TStringBuilder.Create;
  try
    sb.AppendLine('-----BEGIN CERTIFICATE REQUEST-----');

    // Split into 64-character lines
    i := 1;
    lineLen := 64;
    while i <= Length(base64) do
    begin
      if i + lineLen - 1 <= Length(base64) then
        sb.AppendLine(Copy(base64, i, lineLen))
      else
        sb.AppendLine(Copy(base64, i, Length(base64) - i + 1));
      Inc(i, lineLen);
    end;

    sb.Append('-----END CERTIFICATE REQUEST-----');
    Result := sb.ToString;
  finally
    sb.Free;
  end;
end;

{ TPkcs9Oids }

class function TPkcs9Oids.GetExtensionRequest: IDerObjectIdentifier;
begin
  if FExtensionRequest = nil then
    FExtensionRequest := TDerObjectIdentifier.Create('1.2.840.113549.1.9.14');
  Result := FExtensionRequest;
end;

{ TX509ExtensionOids }

class function TX509ExtensionOids.GetSubjectKeyIdentifier: IDerObjectIdentifier;
begin
  if FSubjectKeyIdentifier = nil then
    FSubjectKeyIdentifier := TDerObjectIdentifier.Create('2.5.29.14');
  Result := FSubjectKeyIdentifier;
end;

{ TPkcs10CertificationRequestBuilderBase }

constructor TPkcs10CertificationRequestBuilderBase.Create;
begin
  inherited Create();
  FSubject := nil;
  FExtensions := TList<IAsn1Encodable>.Create;
  FPublicKeyBytes := nil;
end;

destructor TPkcs10CertificationRequestBuilderBase.Destroy;
begin
  FExtensions.Free;
  inherited Destroy;
end;

function TPkcs10CertificationRequestBuilderBase.SetSubject(
  const subject: IX500Name): IPkcs10CertificationRequestBuilder;
begin
  FSubject := subject;
  Result := Self;
end;

procedure TPkcs10CertificationRequestBuilderBase.SetPublicKeyBytes(
  const pubKeyBytes: TCryptoLibByteArray);
begin
  FPublicKeyBytes := pubKeyBytes;
end;

function TPkcs10CertificationRequestBuilderBase.AddExtension(
  const oid: IDerObjectIdentifier; critical: Boolean;
  const value: IAsn1Encodable): IPkcs10CertificationRequestBuilder;
var
  extSeqV: IAsn1EncodableVector;
  extValueBytes: TCryptoLibByteArray;
  extValueOctet: IDerOctetString;
begin
  // Extension ::= SEQUENCE { extnID, critical, extnValue OCTET STRING }
  extSeqV := TAsn1EncodableVector.Create();
  extSeqV.Add(oid);
  if critical then
    extSeqV.Add(TDerBoolean.True);

  // Encode value as OCTET STRING containing DER encoding
  extValueBytes := value.ToAsn1Object.GetEncoded(TAsn1Encodable.Der);
  extValueOctet := TDerOctetString.Create(extValueBytes);
  extSeqV.Add(extValueOctet);

  FExtensions.Add(TDerSequence.FromVector(extSeqV));
  Result := Self;
end;

function TPkcs10CertificationRequestBuilderBase.AddSubjectKeyIdentifier:
  IPkcs10CertificationRequestBuilder;
var
  sha1Digest: IDigest;
  hashBytes: TCryptoLibByteArray;
  skiValue: IDerOctetString;
begin
  if Length(FPublicKeyBytes) = 0 then
    raise EInvalidOperationCryptoLibException.Create(SPublicKeyNotSet);

  // Compute SHA-1 hash of public key bytes
  sha1Digest := TDigestUtilities.GetDigest('SHA-1');
  System.SetLength(hashBytes, sha1Digest.GetDigestSize);
  sha1Digest.BlockUpdate(FPublicKeyBytes, 0, Length(FPublicKeyBytes));
  sha1Digest.DoFinal(hashBytes, 0);

  // Subject Key Identifier is an OCTET STRING
  skiValue := TDerOctetString.Create(hashBytes);

  // Add as extension (not critical)
  Result := AddExtension(TX509ExtensionOids.SubjectKeyIdentifier, False, skiValue);
end;

function TPkcs10CertificationRequestBuilderBase.BuildAttributes: IDerTaggedObject;
var
  extensionsSeq: IDerSequence;
  extV: IAsn1EncodableVector;
  extReqSetV: IAsn1EncodableVector;
  attrSeqV: IAsn1EncodableVector;
  attrSeq: IDerSequence;
  attrsSetV: IAsn1EncodableVector;
  ext: IAsn1Encodable;
begin
  if FExtensions.Count = 0 then
  begin
    // No extensions - return empty attributes
    Result := TDerTaggedObject.Create(False, 0,
      TDerSequence.Create() as IAsn1Encodable);
    Exit;
  end;

  // Build Extensions SEQUENCE
  extV := TAsn1EncodableVector.Create();
  for ext in FExtensions do
    extV.Add(ext);
  extensionsSeq := TDerSequence.FromVector(extV);

  // extensionRequest attribute value is SET { Extensions }
  extReqSetV := TAsn1EncodableVector.Create();
  extReqSetV.Add(extensionsSeq);

  // Attribute ::= SEQUENCE { type OID, values SET }
  attrSeqV := TAsn1EncodableVector.Create();
  attrSeqV.Add(TPkcs9Oids.ExtensionRequest);
  attrSeqV.Add(TDerSet.FromVector(extReqSetV, False));
  attrSeq := TDerSequence.FromVector(attrSeqV);

  // Attributes is SET OF Attribute (but using SEQUENCE for [0] IMPLICIT)
  attrsSetV := TAsn1EncodableVector.Create();
  attrsSetV.Add(attrSeq);

  Result := TDerTaggedObject.Create(False, 0,
    TDerSequence.FromVector(attrsSetV) as IAsn1Encodable);
end;

function TPkcs10CertificationRequestBuilderBase.CreateCSR(
  const subjectPKInfo: ISubjectPublicKeyInfo;
  const sigAlg: IAlgorithmIdentifier;
  const sigBytes: TCryptoLibByteArray): IPkcs10CertificationRequest;
var
  certReqInfo: IPkcs10CertificationRequestInfo;
  sigBitString: IDerBitString;
  attrs: IDerTaggedObject;
begin
  // Build attributes with extensions
  attrs := BuildAttributes;

  // Build CertificationRequestInfo with attributes
  certReqInfo := TPkcs10CertificationRequestInfo.Create(FSubject, subjectPKInfo, attrs);

  sigBitString := TDerBitString.Create(sigBytes);

  Result := TPkcs10CertificationRequest.Create(certReqInfo, sigAlg, sigBitString);
end;

{ TECDSACertificationRequestBuilder }

constructor TECDSACertificationRequestBuilder.Create(const digest: IDigest);
begin
  inherited Create();
  FPublicKey := nil;
  FDigest := digest;
end;

function TECDSACertificationRequestBuilder.SetPublicKey(
  const publicKey: IAsymmetricKeyParameter): IPkcs10CertificationRequestBuilder;
begin
  if not Supports(publicKey, IECPublicKeyParameters) then
    raise EArgumentCryptoLibException.Create('Expected IECPublicKeyParameters');
  FPublicKey := publicKey as IECPublicKeyParameters;
  // Store encoded point for SKI computation
  SetPublicKeyBytes(FPublicKey.Q.GetEncoded(False));
  Result := Self;
end;

class constructor TECDSACertificationRequestBuilder.Create;
begin
  FDigestToOidMap := TDictionary<string, IDerObjectIdentifier>.Create;

  // SHA-256 variants
  FDigestToOidMap.Add('SHA-256', TX9ObjectIdentifiers.ECDsaWithSha256);
  FDigestToOidMap.Add('SHA256', TX9ObjectIdentifiers.ECDsaWithSha256);
  FDigestToOidMap.Add('SHA2_256', TX9ObjectIdentifiers.ECDsaWithSha256);

  // SHA-384 variants
  FDigestToOidMap.Add('SHA-384', TX9ObjectIdentifiers.ECDsaWithSha384);
  FDigestToOidMap.Add('SHA384', TX9ObjectIdentifiers.ECDsaWithSha384);
  FDigestToOidMap.Add('SHA2_384', TX9ObjectIdentifiers.ECDsaWithSha384);

  // SHA-512 variants
  FDigestToOidMap.Add('SHA-512', TX9ObjectIdentifiers.ECDsaWithSha512);
  FDigestToOidMap.Add('SHA512', TX9ObjectIdentifiers.ECDsaWithSha512);
  FDigestToOidMap.Add('SHA2_512', TX9ObjectIdentifiers.ECDsaWithSha512);

  // SHA-224 variants
  FDigestToOidMap.Add('SHA-224', TX9ObjectIdentifiers.ECDsaWithSha224);
  FDigestToOidMap.Add('SHA224', TX9ObjectIdentifiers.ECDsaWithSha224);
  FDigestToOidMap.Add('SHA2_224', TX9ObjectIdentifiers.ECDsaWithSha224);

  // SHA-1 variants
  FDigestToOidMap.Add('SHA-1', TX9ObjectIdentifiers.ECDsaWithSha1);
  FDigestToOidMap.Add('SHA1', TX9ObjectIdentifiers.ECDsaWithSha1);
end;

class destructor TECDSACertificationRequestBuilder.Destroy;
begin
  FDigestToOidMap.Free;
end;

function TECDSACertificationRequestBuilder.GetSignatureAlgorithmOid: IDerObjectIdentifier;
var
  digestName: string;
begin
  digestName := UpperCase(FDigest.AlgorithmName);

  if not FDigestToOidMap.TryGetValue(digestName, Result) then
    raise EArgumentCryptoLibException.CreateResFmt(@SUnsupportedDigest,
      [FDigest.AlgorithmName]);
end;

function TECDSACertificationRequestBuilder.Build(
  const privateKey: IAsymmetricKeyParameter): IPkcs10CertificationRequest;
var
  ecPrivKey: IECPrivateKeyParameters;
  subjectPKInfo: ISubjectPublicKeyInfo;
  certReqInfo: IPkcs10CertificationRequestInfo;
  tbsBytes: TCryptoLibByteArray;
  hashBytes: TCryptoLibByteArray;
  signer: IECDsaSigner;
  sigValues: TCryptoLibGenericArray<TBigInteger>;
  sigBytes: TCryptoLibByteArray;
  sigAlg: IAlgorithmIdentifier;
  attrs: IDerTaggedObject;
begin
  // Validate required fields
  if FSubject = nil then
    raise EInvalidOperationCryptoLibException.Create(SSubjectNotSet);
  if FPublicKey = nil then
    raise EInvalidOperationCryptoLibException.Create(SPublicKeyRequiredForBuild);

  if not Supports(privateKey, IECPrivateKeyParameters) then
    raise EArgumentCryptoLibException.Create('Expected IECPrivateKeyParameters');
  ecPrivKey := privateKey as IECPrivateKeyParameters;

  // Build SubjectPublicKeyInfo from EC public key
  subjectPKInfo := TSubjectPublicKeyInfo.CreateFromPublicKey(FPublicKey);

  // Build attributes with extensions (must be included in TBS for correct signature)
  attrs := BuildAttributes;

  // Build CertificationRequestInfo for TBS data (with attributes!)
  certReqInfo := TPkcs10CertificationRequestInfo.Create(FSubject, subjectPKInfo, attrs);

  // Get DER encoding of the to-be-signed portion
  tbsBytes := certReqInfo.ToAsn1Object.GetEncoded(TAsn1Encodable.Der);

  // Hash the TBS data
  System.SetLength(hashBytes, FDigest.GetDigestSize);
  FDigest.BlockUpdate(tbsBytes, 0, System.Length(tbsBytes));
  FDigest.DoFinal(hashBytes, 0);

  // Sign using ECDSA with deterministic K (RFC 6979)
  signer := TECDsaSigner.Create(THMacDsaKCalculator.Create(FDigest) as IHMacDsaKCalculator);
  signer.Init(True, ecPrivKey);
  sigValues := signer.GenerateSignature(hashBytes);

  // Encode signature as DER SEQUENCE of two INTEGERs
  sigBytes := TStandardDsaEncoding.Instance.Encode(
    ecPrivKey.Parameters.N, sigValues[0], sigValues[1]);

  // Get signature algorithm OID based on digest
  sigAlg := TAlgorithmIdentifier.Create(GetSignatureAlgorithmOid);

  // Create final CSR - pass certReqInfo directly since it already has attrs
  Result := TPkcs10CertificationRequest.Create(certReqInfo, sigAlg, TDerBitString.Create(sigBytes));
end;

{ TEdDSACertificationRequestBuilder }

constructor TEdDSACertificationRequestBuilder.Create;
begin
  inherited Create();
  FEd25519PublicKey := nil;
end;

function TEdDSACertificationRequestBuilder.SetPublicKey(
  const publicKey: IAsymmetricKeyParameter): IPkcs10CertificationRequestBuilder;
begin
  // Detect key type and store appropriately
  if Supports(publicKey, IEd25519PublicKeyParameters) then
  begin
    FEd25519PublicKey := publicKey as IEd25519PublicKeyParameters;
    // Store encoded key for SKI computation
    SetPublicKeyBytes(FEd25519PublicKey.GetEncoded);
  end
  else
    raise EArgumentCryptoLibException.Create('Expected IEd25519PublicKeyParameters');
  Result := Self;
end;

function TEdDSACertificationRequestBuilder.Build(
  const privateKey: IAsymmetricKeyParameter): IPkcs10CertificationRequest;
var
  subjectPKInfo: ISubjectPublicKeyInfo;
  certReqInfo: IPkcs10CertificationRequestInfo;
  tbsBytes: TCryptoLibByteArray;
  signer: ISigner;
  sigBytes: TCryptoLibByteArray;
  sigAlg: IAlgorithmIdentifier;
  attrs: IDerTaggedObject;
begin
  // Validate required fields
  if FSubject = nil then
    raise EInvalidOperationCryptoLibException.Create(SSubjectNotSet);
  if FEd25519PublicKey = nil then
    raise EInvalidOperationCryptoLibException.Create(SPublicKeyRequiredForBuild);

  // Detect key type and handle appropriately
  if Supports(privateKey, IEd25519PrivateKeyParameters) then
  begin
    // Build SubjectPublicKeyInfo from Ed25519 public key
    subjectPKInfo := TSubjectPublicKeyInfo.CreateFromPublicKey(FEd25519PublicKey);

    // Build attributes with extensions (must be included in TBS for correct signature)
    attrs := BuildAttributes;

    // Build CertificationRequestInfo for TBS data (with attributes!)
    certReqInfo := TPkcs10CertificationRequestInfo.Create(FSubject, subjectPKInfo, attrs);

    // Get DER encoding of the to-be-signed portion
    tbsBytes := certReqInfo.ToAsn1Object.GetEncoded(TAsn1Encodable.Der);

    // Use SignerUtilities to create Ed25519 signer
    signer := TSignerUtilities.GetSigner('Ed25519');
    signer.Init(True, privateKey);
    signer.BlockUpdate(tbsBytes, 0, System.Length(tbsBytes));
    sigBytes := signer.GenerateSignature();

    // Ed25519 signature algorithm - no parameters per RFC 8410
    sigAlg := TAlgorithmIdentifier.Create(TEdECObjectIdentifiers.id_Ed25519);

    // Create final CSR - pass certReqInfo directly since it already has attrs
    Result := TPkcs10CertificationRequest.Create(certReqInfo, sigAlg, TDerBitString.Create(sigBytes));
  end
  else
    raise EArgumentCryptoLibException.Create('Expected IEd25519PrivateKeyParameters');
end;

end.
