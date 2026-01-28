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

unit ClpPkcsAsn1Objects;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpBigInteger,
  ClpAsn1Objects,
  ClpIAsn1Objects,
  ClpAsn1Core,
  ClpIAsn1Core,
  ClpAsn1Tags,
  ClpIPkcsAsn1Objects,
  ClpX509Asn1Objects,
  ClpIX509Asn1Objects,
  ClpPkcsObjectIdentifiers,
  ClpOiwObjectIdentifiers,
  ClpCryptoLibTypes,
  ClpAsn1Utilities,
  ClpPlatformUtilities;

resourcestring
  SBadSequenceSize = 'Bad sequence size: %d';
  SAttrTypeNil = 'attrType';
  SAttrValuesNil = 'attrValues';
  SWrongNumberOfElements = 'Wrong number of elements in sequence';
  SRequestInfoNil = 'requestInfo';
  SAlgorithmNil = 'algorithm';
  SSignatureNil = 'signature';
  SSubjectNil = 'subject';
  SSubjectPKInfoNil = 'subjectPKInfo';
  SUnexpectedElementsInSequence = 'Unexpected elements in sequence';
  SChallengePasswordMustHaveSingleValue = 'challengePassword attribute must have exactly one value';
  SUnstructuredNameMustHaveSingleValue = 'unstructuredName attribute must have exactly one value';
  SPrivateKeyAlgorithmNil = 'privateKeyAlgorithm';
  SPrivateKeyNil = 'privateKey';
  SVersionNil = 'version';

type
  /// <summary>
  /// The ContentInfo object (PKCS#7).
  /// </summary>
  TContentInfo = class(TAsn1Encodable, IContentInfo)
  strict private
  var
    FContentType: IDerObjectIdentifier;
    FContent: IAsn1Encodable;

  strict protected
    function GetContentType: IDerObjectIdentifier;
    function GetContent: IAsn1Encodable;

  public
    class function GetInstance(AObj: TObject): IContentInfo; overload; static;
    class function GetInstance(const AObj: IAsn1Convertible): IContentInfo; overload; static;
    class function GetInstance(const AEncoded: TCryptoLibByteArray): IContentInfo; overload; static;
    class function GetInstance(const AObj: IAsn1TaggedObject;
      AExplicitly: Boolean): IContentInfo; overload; static;
    class function GetTagged(const ATaggedObject: IAsn1TaggedObject;
      ADeclaredExplicit: Boolean): IContentInfo; static;

    constructor Create(const ASeq: IAsn1Sequence); overload;
    constructor Create(const AContentType: IDerObjectIdentifier;
      const AContent: IAsn1Encodable); overload;

    function ToAsn1Object: IAsn1Object; override;

    property ContentType: IDerObjectIdentifier read GetContentType;
    property Content: IAsn1Encodable read GetContent;
  end;

  /// <summary>
  /// The SignedData object (PKCS#7).
  /// </summary>
  TSignedData = class(TAsn1Encodable, ISignedData)
  strict private
  var
    FVersion: IDerInteger;
    FDigestAlgorithms: IAsn1Set;
    FContentInfo: IContentInfo;
    FCertificates: IAsn1Set;
    FCrls: IAsn1Set;
    FSignerInfos: IAsn1Set;

  strict protected
    function GetVersion: IDerInteger;
    function GetDigestAlgorithms: IAsn1Set;
    function GetContentInfo: IContentInfo;
    function GetCertificates: IAsn1Set;
    function GetCrls: IAsn1Set;
    function GetSignerInfos: IAsn1Set;

  public
    class function GetInstance(AObj: TObject): ISignedData; overload; static;
    class function GetInstance(const AObj: IAsn1Convertible): ISignedData; overload; static;
    class function GetInstance(const AEncoded: TCryptoLibByteArray): ISignedData; overload; static;
    class function GetInstance(const AObj: IAsn1TaggedObject;
      AExplicitly: Boolean): ISignedData; overload; static;
    class function GetTagged(const ATaggedObject: IAsn1TaggedObject;
      ADeclaredExplicit: Boolean): ISignedData; static;

    constructor Create(const ASeq: IAsn1Sequence); overload;
    constructor Create(const AVersion: IDerInteger;
      const ADigestAlgorithms: IAsn1Set; const AContentInfo: IContentInfo;
      const ACertificates: IAsn1Set; const ACrls: IAsn1Set;
      const ASignerInfos: IAsn1Set); overload;

    function ToAsn1Object: IAsn1Object; override;

    property Version: IDerInteger read GetVersion;
    property DigestAlgorithms: IAsn1Set read GetDigestAlgorithms;
    property ContentInfo: IContentInfo read GetContentInfo;
    property Certificates: IAsn1Set read GetCertificates;
    property Crls: IAsn1Set read GetCrls;
    property SignerInfos: IAsn1Set read GetSignerInfos;
  end;

  /// <summary>
  /// The AttributePkcs object.
  /// </summary>
  TAttributePkcs = class(TAsn1Encodable, IAttributePkcs)

  strict private
  var
    FAttrType: IDerObjectIdentifier;
    FAttrValues: IAsn1Set;

  strict protected
    function GetAttrType: IDerObjectIdentifier;
    function GetAttrValues: IAsn1Set;

  public
    class function GetInstance(AObj: TObject): IAttributePkcs; overload; static;
    class function GetInstance(const AObj: IAsn1Convertible): IAttributePkcs; overload; static;
    class function GetInstance(const AEncoded: TCryptoLibByteArray): IAttributePkcs; overload; static;
    class function GetInstance(const AObj: IAsn1TaggedObject;
      AExplicitly: Boolean): IAttributePkcs; overload; static;
    class function GetTagged(const ATaggedObject: IAsn1TaggedObject;
      ADeclaredExplicit: Boolean): IAttributePkcs; static;

    constructor Create(const ASeq: IAsn1Sequence); overload;
    constructor Create(const AAttrType: IDerObjectIdentifier;
      const AAttrValues: IAsn1Set); overload;

    function ToAsn1Object: IAsn1Object; override;

    property AttrType: IDerObjectIdentifier read GetAttrType;
    property AttrValues: IAsn1Set read GetAttrValues;

  end;

  /// <summary>
  /// The CertificationRequestInfo object.
  /// </summary>
  TCertificationRequestInfo = class(TAsn1Encodable, ICertificationRequestInfo)

  strict private
  var
    FVersion: IDerInteger;
    FSubject: IX509Name;
    FSubjectPKInfo: ISubjectPublicKeyInfo;
    FAttributes: IAsn1Set;

  strict protected
    function GetVersion: IDerInteger;
    function GetSubject: IX509Name;
    function GetSubjectPublicKeyInfo: ISubjectPublicKeyInfo;
    function GetAttributes: IAsn1Set;

  public
    class function ValidateAttributes(const AAttributes: IAsn1Set): IAsn1Set; static;

    class function GetInstance(AObj: TObject): ICertificationRequestInfo; overload; static;
    class function GetInstance(const AObj: IAsn1Convertible): ICertificationRequestInfo; overload; static;
    class function GetInstance(const AEncoded: TCryptoLibByteArray): ICertificationRequestInfo; overload; static;
    class function GetInstance(const AObj: IAsn1TaggedObject;
      AExplicitly: Boolean): ICertificationRequestInfo; overload; static;
    class function GetTagged(const ATaggedObject: IAsn1TaggedObject;
      ADeclaredExplicit: Boolean): ICertificationRequestInfo; static;

    constructor Create(const ASeq: IAsn1Sequence); overload;
    constructor Create(const ASubject: IX509Name;
      const APkInfo: ISubjectPublicKeyInfo; const AAttributes: IAsn1Set); overload;

    function ToAsn1Object: IAsn1Object; override;

    property Version: IDerInteger read GetVersion;
    property Subject: IX509Name read GetSubject;
    property SubjectPublicKeyInfo: ISubjectPublicKeyInfo read GetSubjectPublicKeyInfo;
    property Attributes: IAsn1Set read GetAttributes;

  end;

  /// <summary>
  /// The CertificationRequest object.
  /// </summary>
  TCertificationRequest = class(TAsn1Encodable, ICertificationRequest)

  strict protected
  var
    FReqInfo: ICertificationRequestInfo;
    FSigAlgId: IAlgorithmIdentifier;
    FSigBits: IDerBitString;

  strict protected
    function GetCertificationRequestInfo: ICertificationRequestInfo;
    function GetSignatureAlgorithm: IAlgorithmIdentifier;
    function GetSignature: IDerBitString;
    function GetSignatureOctets: TCryptoLibByteArray;

    /// <summary>Protected parameterless constructor for TPkcs10CertificationRequest.Init.</summary>
    constructor Create; overload;

  public
    class function GetInstance(AObj: TObject): ICertificationRequest; overload; static;
    class function GetInstance(const AObj: IAsn1Convertible): ICertificationRequest; overload; static;
    class function GetInstance(const AEncoded: TCryptoLibByteArray): ICertificationRequest; overload; static;
    class function GetInstance(const AObj: IAsn1TaggedObject;
      AExplicitly: Boolean): ICertificationRequest; overload; static;
    class function GetTagged(const ATaggedObject: IAsn1TaggedObject;
      ADeclaredExplicit: Boolean): ICertificationRequest; static;

    constructor Create(const ASeq: IAsn1Sequence); overload;
    constructor Create(const ARequestInfo: ICertificationRequestInfo;
      const AAlgorithm: IAlgorithmIdentifier; const ASignature: IDerBitString); overload;

    function ToAsn1Object: IAsn1Object; override;

    property SignatureAlgorithm: IAlgorithmIdentifier read GetSignatureAlgorithm;
    property Signature: IDerBitString read GetSignature;

  end;

  /// <summary>
  /// The PrivateKeyInfo object.
  /// </summary>
  TPrivateKeyInfo = class(TAsn1Encodable, IPrivateKeyInfo)

  strict private
  var
    FVersion: IDerInteger;
    FPrivateKeyAlgorithm: IAlgorithmIdentifier;
    FPrivateKey: IAsn1OctetString;
    FAttributes: IAsn1Set;
    FPublicKey: IDerBitString;

  strict protected
    function GetVersion: IDerInteger;
    function GetPrivateKeyAlgorithm: IAlgorithmIdentifier;
    function GetPrivateKey: IAsn1OctetString;
    function GetPrivateKeyLength: Int32;
    function GetAttributes: IAsn1Set;
    function GetPublicKey: IDerBitString;
    function HasPublicKey: Boolean;
    function ParsePrivateKey: IAsn1Object;
    function ParsePublicKey: IAsn1Object;

  public
    class function GetInstance(AObj: TObject): IPrivateKeyInfo; overload; static;
    class function GetInstance(const AObj: IAsn1Convertible): IPrivateKeyInfo; overload; static;
    class function GetInstance(const AEncoded: TCryptoLibByteArray): IPrivateKeyInfo; overload; static;
    class function GetInstance(const AObj: IAsn1TaggedObject;
      AExplicitly: Boolean): IPrivateKeyInfo; overload; static;
    class function GetOptional(const AElement: IAsn1Encodable): IPrivateKeyInfo; static;
    class function GetTagged(const ATaggedObject: IAsn1TaggedObject;
      ADeclaredExplicit: Boolean): IPrivateKeyInfo; static;

    constructor Create(const ASeq: IAsn1Sequence); overload;
    constructor Create(const APrivateKeyAlgorithm: IAlgorithmIdentifier;
      const APrivateKey: IAsn1Encodable); overload;
    constructor Create(const APrivateKeyAlgorithm: IAlgorithmIdentifier;
      const APrivateKey: IAsn1Encodable; const AAttributes: IAsn1Set); overload;
    constructor Create(const APrivateKeyAlgorithm: IAlgorithmIdentifier;
      const APrivateKey: IAsn1Encodable; const AAttributes: IAsn1Set;
      const APublicKey: TCryptoLibByteArray); overload;

    function ToAsn1Object: IAsn1Object; override;

    property Version: IDerInteger read GetVersion;
    property PrivateKeyAlgorithm: IAlgorithmIdentifier read GetPrivateKeyAlgorithm;
    property PrivateKey: IAsn1OctetString read GetPrivateKey;
    property PrivateKeyLength: Int32 read GetPrivateKeyLength;
    property Attributes: IAsn1Set read GetAttributes;
    property PublicKey: IDerBitString read GetPublicKey;

  end;

  /// <summary>
  /// The RsaPrivateKeyStructure object.
  /// </summary>
  TRsaPrivateKeyStructure = class(TAsn1Encodable, IRsaPrivateKeyStructure)

  strict private
  var
    FVersion: IDerInteger;
    FModulus: TBigInteger;
    FPublicExponent: TBigInteger;
    FPrivateExponent: TBigInteger;
    FPrime1: TBigInteger;
    FPrime2: TBigInteger;
    FExponent1: TBigInteger;
    FExponent2: TBigInteger;
    FCoefficient: TBigInteger;

  strict protected
    function GetModulus: TBigInteger;
    function GetPublicExponent: TBigInteger;
    function GetPrivateExponent: TBigInteger;
    function GetPrime1: TBigInteger;
    function GetPrime2: TBigInteger;
    function GetExponent1: TBigInteger;
    function GetExponent2: TBigInteger;
    function GetCoefficient: TBigInteger;

  public
    class function GetInstance(AObj: TObject): IRsaPrivateKeyStructure; overload; static;
    class function GetInstance(const AObj: IAsn1Convertible): IRsaPrivateKeyStructure; overload; static;
    class function GetInstance(const AEncoded: TCryptoLibByteArray): IRsaPrivateKeyStructure; overload; static;
    class function GetInstance(const AObj: IAsn1TaggedObject;
      AExplicitly: Boolean): IRsaPrivateKeyStructure; overload; static;
    class function GetTagged(const ATaggedObject: IAsn1TaggedObject;
      ADeclaredExplicit: Boolean): IRsaPrivateKeyStructure; static;

    constructor Create(const ASeq: IAsn1Sequence); overload;
    constructor Create(const AModulus, APublicExponent, APrivateExponent,
      APrime1, APrime2, AExponent1, AExponent2, ACoefficient: TBigInteger); overload;

    function ToAsn1Object: IAsn1Object; override;

    property Modulus: TBigInteger read GetModulus;
    property PublicExponent: TBigInteger read GetPublicExponent;
    property PrivateExponent: TBigInteger read GetPrivateExponent;
    property Prime1: TBigInteger read GetPrime1;
    property Prime2: TBigInteger read GetPrime2;
    property Exponent1: TBigInteger read GetExponent1;
    property Exponent2: TBigInteger read GetExponent2;
    property Coefficient: TBigInteger read GetCoefficient;

  end;

  /// <summary>
  /// The RsassaPssParameters object.
  /// <pre>
  /// RSASSA-PSS-params ::= SEQUENCE {
  ///   hashAlgorithm      [0] OAEP-PSSDigestAlgorithms  DEFAULT sha1,
  ///    maskGenAlgorithm   [1] PKCS1MGFAlgorithms  DEFAULT mgf1SHA1,
  ///    saltLength         [2] INTEGER  DEFAULT 20,
  ///    trailerField       [3] TrailerField  DEFAULT trailerFieldBC
  ///  }
  /// </pre>
  /// </summary>
  TRsassaPssParameters = class(TAsn1Encodable, IRsassaPssParameters)

  public
    class var
      DefaultHashAlgorithm: IAlgorithmIdentifier;
      DefaultMaskGenAlgorithm: IAlgorithmIdentifier;
      DefaultMaskGenFunction: IAlgorithmIdentifier; // Obsolete, use DefaultMaskGenAlgorithm
      DefaultSaltLength: IDerInteger;
      DefaultTrailerField: IDerInteger;

    class procedure Boot; static;
    class constructor Create;

  strict private
  var
    FHashAlgorithm: IAlgorithmIdentifier;
    FMaskGenAlgorithm: IAlgorithmIdentifier;
    FSaltLength: IDerInteger;
    FTrailerField: IDerInteger;

  strict protected
    function GetHashAlgorithm: IAlgorithmIdentifier;
    function GetMaskGenAlgorithm: IAlgorithmIdentifier;
    function GetSaltLength: IDerInteger;
    function GetTrailerField: IDerInteger;

  public
    class function GetInstance(AObj: TObject): IRsassaPssParameters; overload; static;
    class function GetInstance(const AObj: IAsn1Convertible): IRsassaPssParameters; overload; static;
    class function GetInstance(const AEncoded: TCryptoLibByteArray): IRsassaPssParameters; overload; static;
    class function GetInstance(const AObj: IAsn1TaggedObject;
      AExplicitly: Boolean): IRsassaPssParameters; overload; static;
    class function GetTagged(const ATaggedObject: IAsn1TaggedObject;
      ADeclaredExplicit: Boolean): IRsassaPssParameters; static;

    constructor Create(const ASeq: IAsn1Sequence); overload;
    constructor Create; overload;
    constructor Create(const AHashAlgorithm, AMaskGenAlgorithm: IAlgorithmIdentifier;
      const ASaltLength, ATrailerField: IDerInteger); overload;

    function ToAsn1Object: IAsn1Object; override;

    property HashAlgorithm: IAlgorithmIdentifier read GetHashAlgorithm;
    property MaskGenAlgorithm: IAlgorithmIdentifier read GetMaskGenAlgorithm;
    property SaltLength: IDerInteger read GetSaltLength;
    property TrailerField: IDerInteger read GetTrailerField;

  end;

implementation

{ TAttributePkcs }

class function TAttributePkcs.GetInstance(AObj: TObject): IAttributePkcs;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IAttributePkcs, Result) then
    Exit;

  Result := TAttributePkcs.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TAttributePkcs.GetInstance(const AObj: IAsn1Convertible): IAttributePkcs;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IAttributePkcs, Result) then
    Exit;

  Result := TAttributePkcs.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TAttributePkcs.GetInstance(const AEncoded: TCryptoLibByteArray): IAttributePkcs;
begin
  if AEncoded = nil then
  begin
    Result := nil;
    Exit;
  end;

  Result := TAttributePkcs.Create(TAsn1Sequence.GetInstance(AEncoded));
end;

class function TAttributePkcs.GetInstance(const AObj: IAsn1TaggedObject;
  AExplicitly: Boolean): IAttributePkcs;
begin
  Result := TAttributePkcs.Create(TAsn1Sequence.GetInstance(AObj, AExplicitly));
end;

class function TAttributePkcs.GetTagged(const ATaggedObject: IAsn1TaggedObject;
  ADeclaredExplicit: Boolean): IAttributePkcs;
begin
  Result := TAttributePkcs.Create(TAsn1Sequence.GetTagged(ATaggedObject, ADeclaredExplicit));
end;

constructor TAttributePkcs.Create(const ASeq: IAsn1Sequence);
var
  LCount: Int32;
begin
  inherited Create();

  LCount := ASeq.Count;
  if LCount <> 2 then
  begin
    raise EArgumentCryptoLibException.CreateResFmt(@SBadSequenceSize, [LCount]);
  end;

  FAttrType := TDerObjectIdentifier.GetInstance(ASeq[0]);
  FAttrValues := TAsn1Set.GetInstance(ASeq[1]);
end;

constructor TAttributePkcs.Create(const AAttrType: IDerObjectIdentifier;
  const AAttrValues: IAsn1Set);
begin
  inherited Create();

  if AAttrType = nil then
    raise EArgumentNilCryptoLibException.Create(SAttrTypeNil);
  if AAttrValues = nil then
    raise EArgumentNilCryptoLibException.Create(SAttrValuesNil);

  FAttrType := AAttrType;
  FAttrValues := AAttrValues;
end;

function TAttributePkcs.GetAttrType: IDerObjectIdentifier;
begin
  Result := FAttrType;
end;

function TAttributePkcs.GetAttrValues: IAsn1Set;
begin
  Result := FAttrValues;
end;

function TAttributePkcs.ToAsn1Object: IAsn1Object;
begin
  Result := TDerSequence.Create([FAttrType, FAttrValues]);
end;

{ TCertificationRequestInfo }

class function TCertificationRequestInfo.GetInstance(AObj: TObject): ICertificationRequestInfo;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, ICertificationRequestInfo, Result) then
    Exit;

  Result := TCertificationRequestInfo.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TCertificationRequestInfo.GetInstance(const AObj: IAsn1Convertible): ICertificationRequestInfo;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, ICertificationRequestInfo, Result) then
    Exit;

  Result := TCertificationRequestInfo.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TCertificationRequestInfo.GetInstance(const AEncoded: TCryptoLibByteArray): ICertificationRequestInfo;
begin
  if AEncoded = nil then
  begin
    Result := nil;
    Exit;
  end;

  Result := TCertificationRequestInfo.Create(TAsn1Sequence.GetInstance(AEncoded));
end;

class function TCertificationRequestInfo.GetInstance(const AObj: IAsn1TaggedObject;
  AExplicitly: Boolean): ICertificationRequestInfo;
begin
  Result := TCertificationRequestInfo.Create(TAsn1Sequence.GetInstance(AObj, AExplicitly));
end;

class function TCertificationRequestInfo.GetTagged(const ATaggedObject: IAsn1TaggedObject;
  ADeclaredExplicit: Boolean): ICertificationRequestInfo;
begin
  Result := TCertificationRequestInfo.Create(TAsn1Sequence.GetTagged(ATaggedObject, ADeclaredExplicit));
end;

constructor TCertificationRequestInfo.Create(const ASeq: IAsn1Sequence);
var
  LCount, LPos: Int32;
begin
  inherited Create();

  LCount := ASeq.Count;
  LPos := 0;
  if (LCount < 3) or (LCount > 4) then
  begin
    raise EArgumentCryptoLibException.CreateResFmt(@SBadSequenceSize, [LCount]);
  end;

  FVersion := TDerInteger.GetInstance(ASeq[LPos]);
  System.Inc(LPos);
  FSubject := TX509Name.GetInstance(ASeq[LPos]);
  System.Inc(LPos);
  FSubjectPKInfo := TSubjectPublicKeyInfo.GetInstance(ASeq[LPos]);
  System.Inc(LPos);

  // NOTE: some CertificationRequestInfo objects seem to treat this field as optional.
  FAttributes := TAsn1Utilities.ReadOptionalContextTagged<Boolean, IAsn1Set>(ASeq, LPos, 0, False,
    function(ATagged: IAsn1TaggedObject; AState: Boolean): IAsn1Set
    begin
      Result := TAsn1Set.GetTagged(ATagged, AState);
    end);

  if LPos <> LCount then
  begin
    raise EArgumentCryptoLibException.Create(SUnexpectedElementsInSequence);
  end;

  ValidateAttributes(FAttributes);
end;

constructor TCertificationRequestInfo.Create(const ASubject: IX509Name;
  const APkInfo: ISubjectPublicKeyInfo; const AAttributes: IAsn1Set);
begin
  inherited Create();

  FVersion := TDerInteger.Zero;
  if ASubject = nil then
    raise EArgumentNilCryptoLibException.Create(SSubjectNil);
  if APkInfo = nil then
    raise EArgumentNilCryptoLibException.Create(SSubjectPKInfoNil);

  FSubject := ASubject;
  FSubjectPKInfo := APkInfo;
  FAttributes := ValidateAttributes(AAttributes);
end;

class function TCertificationRequestInfo.ValidateAttributes(const AAttributes: IAsn1Set): IAsn1Set;
var
  I: Int32;
  LAttr: IAttributePkcs;
begin
  if AAttributes <> nil then
  begin
    for I := 0 to AAttributes.Count - 1 do
    begin
      LAttr := TAttributePkcs.GetInstance(AAttributes[I]);
      if TPkcsObjectIdentifiers.Pkcs9AtChallengePassword.Equals(LAttr.AttrType) then
      begin
        if LAttr.AttrValues.Count <> 1 then
        begin
          raise EArgumentCryptoLibException.Create(SChallengePasswordMustHaveSingleValue);
        end;
      end
      else if TPkcsObjectIdentifiers.Pkcs9AtUnstructuredName.Equals(LAttr.AttrType) then
      begin
        if LAttr.AttrValues.Count <> 1 then
        begin
          raise EArgumentCryptoLibException.Create(SUnstructuredNameMustHaveSingleValue);
        end;
      end;
    end;
  end;
  Result := AAttributes;
end;

function TCertificationRequestInfo.GetVersion: IDerInteger;
begin
  Result := FVersion;
end;

function TCertificationRequestInfo.GetSubject: IX509Name;
begin
  Result := FSubject;
end;

function TCertificationRequestInfo.GetSubjectPublicKeyInfo: ISubjectPublicKeyInfo;
begin
  Result := FSubjectPKInfo;
end;

function TCertificationRequestInfo.GetAttributes: IAsn1Set;
begin
  Result := FAttributes;
end;

function TCertificationRequestInfo.ToAsn1Object: IAsn1Object;
var
  LV: IAsn1EncodableVector;
begin
  LV := TAsn1EncodableVector.Create(4);
  LV.Add([FVersion, FSubject, FSubjectPKInfo]);
  LV.AddOptionalTagged(False, 0, FAttributes);
  Result := TDerSequence.Create(LV);
end;

{ TCertificationRequest }

class function TCertificationRequest.GetInstance(AObj: TObject): ICertificationRequest;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, ICertificationRequest, Result) then
    Exit;

  Result := TCertificationRequest.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TCertificationRequest.GetInstance(const AObj: IAsn1Convertible): ICertificationRequest;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, ICertificationRequest, Result) then
    Exit;

  Result := TCertificationRequest.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TCertificationRequest.GetInstance(const AEncoded: TCryptoLibByteArray): ICertificationRequest;
begin
  if AEncoded = nil then
  begin
    Result := nil;
    Exit;
  end;

  Result := TCertificationRequest.Create(TAsn1Sequence.GetInstance(AEncoded));
end;

class function TCertificationRequest.GetInstance(const AObj: IAsn1TaggedObject;
  AExplicitly: Boolean): ICertificationRequest;
begin
  Result := TCertificationRequest.Create(TAsn1Sequence.GetInstance(AObj, AExplicitly));
end;

class function TCertificationRequest.GetTagged(const ATaggedObject: IAsn1TaggedObject;
  ADeclaredExplicit: Boolean): ICertificationRequest;
begin
  Result := TCertificationRequest.Create(TAsn1Sequence.GetTagged(ATaggedObject, ADeclaredExplicit));
end;

constructor TCertificationRequest.Create;
begin
  inherited Create();
end;

constructor TCertificationRequest.Create(const ASeq: IAsn1Sequence);
var
  LCount: Int32;
begin
  inherited Create();

  LCount := ASeq.Count;
  if LCount <> 3 then
  begin
    raise EArgumentCryptoLibException.Create(SWrongNumberOfElements);
  end;

  FReqInfo := TCertificationRequestInfo.GetInstance(ASeq[0]);
  FSigAlgId := TAlgorithmIdentifier.GetInstance(ASeq[1]);
  FSigBits := TDerBitString.GetInstance(ASeq[2]);
end;

constructor TCertificationRequest.Create(const ARequestInfo: ICertificationRequestInfo;
  const AAlgorithm: IAlgorithmIdentifier; const ASignature: IDerBitString);
begin
  inherited Create();

  if ARequestInfo = nil then
    raise EArgumentNilCryptoLibException.Create(SRequestInfoNil);
  if AAlgorithm = nil then
    raise EArgumentNilCryptoLibException.Create(SAlgorithmNil);
  if ASignature = nil then
    raise EArgumentNilCryptoLibException.Create(SSignatureNil);

  FReqInfo := ARequestInfo;
  FSigAlgId := AAlgorithm;
  FSigBits := ASignature;
end;

function TCertificationRequest.GetCertificationRequestInfo: ICertificationRequestInfo;
begin
  Result := FReqInfo;
end;

function TCertificationRequest.GetSignatureAlgorithm: IAlgorithmIdentifier;
begin
  Result := FSigAlgId;
end;

function TCertificationRequest.GetSignature: IDerBitString;
begin
  Result := FSigBits;
end;

function TCertificationRequest.GetSignatureOctets: TCryptoLibByteArray;
begin
  Result := FSigBits.GetOctets();
end;

function TCertificationRequest.ToAsn1Object: IAsn1Object;
begin
  Result := TDerSequence.Create([FReqInfo, FSigAlgId, FSigBits]);
end;

{ TPrivateKeyInfo }

class function TPrivateKeyInfo.GetInstance(AObj: TObject): IPrivateKeyInfo;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IPrivateKeyInfo, Result) then
    Exit;

  Result := TPrivateKeyInfo.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TPrivateKeyInfo.GetInstance(const AObj: IAsn1Convertible): IPrivateKeyInfo;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IPrivateKeyInfo, Result) then
    Exit;

  Result := TPrivateKeyInfo.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TPrivateKeyInfo.GetInstance(const AEncoded: TCryptoLibByteArray): IPrivateKeyInfo;
begin
  if AEncoded = nil then
  begin
    Result := nil;
    Exit;
  end;

  Result := TPrivateKeyInfo.Create(TAsn1Sequence.GetInstance(AEncoded));
end;

class function TPrivateKeyInfo.GetInstance(const AObj: IAsn1TaggedObject;
  AExplicitly: Boolean): IPrivateKeyInfo;
begin
  Result := TPrivateKeyInfo.Create(TAsn1Sequence.GetInstance(AObj, AExplicitly));
end;

class function TPrivateKeyInfo.GetOptional(const AElement: IAsn1Encodable): IPrivateKeyInfo;
var
  LSequence: IAsn1Sequence;
begin
  if AElement = nil then
    raise EArgumentNilCryptoLibException.Create('element');

  if Supports(AElement, IPrivateKeyInfo, Result) then
    Exit;

  LSequence := TAsn1Sequence.GetOptional(AElement);
  if LSequence <> nil then
    Result := TPrivateKeyInfo.Create(LSequence)
  else
    Result := nil;
end;

class function TPrivateKeyInfo.GetTagged(const ATaggedObject: IAsn1TaggedObject;
  ADeclaredExplicit: Boolean): IPrivateKeyInfo;
begin
  Result := TPrivateKeyInfo.Create(TAsn1Sequence.GetTagged(ATaggedObject, ADeclaredExplicit));
end;

constructor TPrivateKeyInfo.Create(const ASeq: IAsn1Sequence);
var
  LCount, LPos, LVersionValue: Int32;
begin
  inherited Create();

  LCount := ASeq.Count;
  LPos := 0;
  if (LCount < 3) or (LCount > 5) then
  begin
    raise EArgumentCryptoLibException.CreateResFmt(@SBadSequenceSize, [LCount]);
  end;

  FVersion := TDerInteger.GetInstance(ASeq[LPos]);
  System.Inc(LPos);
  FPrivateKeyAlgorithm := TAlgorithmIdentifier.GetInstance(ASeq[LPos]);
  System.Inc(LPos);
  FPrivateKey := TAsn1OctetString.GetInstance(ASeq[LPos]);
  System.Inc(LPos);

  FAttributes := TAsn1Utilities.ReadOptionalContextTagged<Boolean, IAsn1Set>(ASeq, LPos, 0, False,
    function(ATagged: IAsn1TaggedObject; AState: Boolean): IAsn1Set
    begin
      Result := TAsn1Set.GetTagged(ATagged, AState);
    end);

  FPublicKey := TAsn1Utilities.ReadOptionalContextTagged<Boolean, IDerBitString>(ASeq, LPos, 1, False,
    function(ATagged: IAsn1TaggedObject; AState: Boolean): IDerBitString
    begin
      Result := TDerBitString.GetTagged(ATagged, AState);
    end);

  if LPos <> LCount then
  begin
    raise EArgumentCryptoLibException.Create(SUnexpectedElementsInSequence);
  end;

  LVersionValue := FVersion.IntValueExact;
  if (FPublicKey <> nil) and (LVersionValue < 1) then
  begin
    raise EArgumentCryptoLibException.Create('''publicKey'' requires version v2(1) or later');
  end;
end;

constructor TPrivateKeyInfo.Create(const APrivateKeyAlgorithm: IAlgorithmIdentifier;
  const APrivateKey: IAsn1Encodable);
begin
  Create(APrivateKeyAlgorithm, APrivateKey, nil, nil);
end;

constructor TPrivateKeyInfo.Create(const APrivateKeyAlgorithm: IAlgorithmIdentifier;
  const APrivateKey: IAsn1Encodable; const AAttributes: IAsn1Set);
begin
  Create(APrivateKeyAlgorithm, APrivateKey, AAttributes, nil);
end;

constructor TPrivateKeyInfo.Create(const APrivateKeyAlgorithm: IAlgorithmIdentifier;
  const APrivateKey: IAsn1Encodable; const AAttributes: IAsn1Set;
  const APublicKey: TCryptoLibByteArray);
begin
  inherited Create();

  if APublicKey <> nil then
    FVersion := TDerInteger.ValueOf(1)
  else
    FVersion := TDerInteger.Zero;

  if APrivateKeyAlgorithm = nil then
    raise EArgumentNilCryptoLibException.Create('privateKeyAlgorithm');
  if APrivateKey = nil then
    raise EArgumentNilCryptoLibException.Create('privateKey');

  FPrivateKeyAlgorithm := APrivateKeyAlgorithm;
  FPrivateKey := TDerOctetString.Create(APrivateKey);
  FAttributes := AAttributes;
  if APublicKey <> nil then
    FPublicKey := TDerBitString.FromContentsOptional(APublicKey)
  else
    FPublicKey := nil;
end;

function TPrivateKeyInfo.GetVersion: IDerInteger;
begin
  Result := FVersion;
end;

function TPrivateKeyInfo.GetPrivateKeyAlgorithm: IAlgorithmIdentifier;
begin
  Result := FPrivateKeyAlgorithm;
end;

function TPrivateKeyInfo.GetPrivateKeyLength: Int32;
begin
  Result := FPrivateKey.GetOctetsLength;
end;

function TPrivateKeyInfo.GetPrivateKey: IAsn1OctetString;
begin
  Result := FPrivateKey;
end;

function TPrivateKeyInfo.GetAttributes: IAsn1Set;
begin
  Result := FAttributes;
end;

function TPrivateKeyInfo.GetPublicKey: IDerBitString;
begin
  Result := FPublicKey;
end;

function TPrivateKeyInfo.HasPublicKey: Boolean;
begin
  Result := FPublicKey <> nil;
end;

function TPrivateKeyInfo.ParsePrivateKey: IAsn1Object;
begin
  Result := TAsn1Object.FromByteArray(FPrivateKey.GetOctets());
end;

function TPrivateKeyInfo.ParsePublicKey: IAsn1Object;
begin
  if FPublicKey = nil then
  begin
    Result := nil;
    Exit;
  end;

  Result := TAsn1Object.FromStream(FPublicKey.GetOctetStream());
end;

function TPrivateKeyInfo.ToAsn1Object: IAsn1Object;
var
  LV: IAsn1EncodableVector;
begin
  LV := TAsn1EncodableVector.Create(5);
  LV.Add([FVersion, FPrivateKeyAlgorithm, FPrivateKey]);
  LV.AddOptionalTagged(False, 0, FAttributes);
  LV.AddOptionalTagged(False, 1, FPublicKey);
  Result := TDerSequence.Create(LV);
end;

{ TRsaPrivateKeyStructure }

class function TRsaPrivateKeyStructure.GetInstance(AObj: TObject): IRsaPrivateKeyStructure;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IRsaPrivateKeyStructure, Result) then
    Exit;

  Result := TRsaPrivateKeyStructure.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TRsaPrivateKeyStructure.GetInstance(const AObj: IAsn1Convertible): IRsaPrivateKeyStructure;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IRsaPrivateKeyStructure, Result) then
    Exit;

  Result := TRsaPrivateKeyStructure.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TRsaPrivateKeyStructure.GetInstance(const AEncoded: TCryptoLibByteArray): IRsaPrivateKeyStructure;
begin
  if AEncoded = nil then
  begin
    Result := nil;
    Exit;
  end;

  Result := TRsaPrivateKeyStructure.Create(TAsn1Sequence.GetInstance(AEncoded));
end;

class function TRsaPrivateKeyStructure.GetInstance(const AObj: IAsn1TaggedObject;
  AExplicitly: Boolean): IRsaPrivateKeyStructure;
begin
  Result := TRsaPrivateKeyStructure.Create(TAsn1Sequence.GetInstance(AObj, AExplicitly));
end;

class function TRsaPrivateKeyStructure.GetTagged(const ATaggedObject: IAsn1TaggedObject;
  ADeclaredExplicit: Boolean): IRsaPrivateKeyStructure;
begin
  Result := TRsaPrivateKeyStructure.Create(TAsn1Sequence.GetTagged(ATaggedObject, ADeclaredExplicit));
end;

constructor TRsaPrivateKeyStructure.Create(const ASeq: IAsn1Sequence);
var
  LCount: Int32;
  LVersion: IDerInteger;
begin
  inherited Create();

  LCount := ASeq.Count;
  if LCount <> 9 then
  begin
    raise EArgumentCryptoLibException.CreateResFmt(@SBadSequenceSize, [LCount]);
  end;

  LVersion := TDerInteger.GetInstance(ASeq[0]);
  FModulus := TDerInteger.GetInstance(ASeq[1]).Value;
  FPublicExponent := TDerInteger.GetInstance(ASeq[2]).Value;
  FPrivateExponent := TDerInteger.GetInstance(ASeq[3]).Value;
  FPrime1 := TDerInteger.GetInstance(ASeq[4]).Value;
  FPrime2 := TDerInteger.GetInstance(ASeq[5]).Value;
  FExponent1 := TDerInteger.GetInstance(ASeq[6]).Value;
  FExponent2 := TDerInteger.GetInstance(ASeq[7]).Value;
  FCoefficient := TDerInteger.GetInstance(ASeq[8]).Value;

  if not LVersion.HasValue(0) then
    raise EArgumentCryptoLibException.Create('wrong version for RSA private key');

  FVersion := LVersion;
end;

constructor TRsaPrivateKeyStructure.Create(const AModulus, APublicExponent, APrivateExponent,
  APrime1, APrime2, AExponent1, AExponent2, ACoefficient: TBigInteger);
begin
  inherited Create();

  if not AModulus.IsInitialized then
    raise EArgumentNilCryptoLibException.Create('modulus');
  if not APublicExponent.IsInitialized then
    raise EArgumentNilCryptoLibException.Create('publicExponent');
  if not APrivateExponent.IsInitialized then
    raise EArgumentNilCryptoLibException.Create('privateExponent');
  if not APrime1.IsInitialized then
    raise EArgumentNilCryptoLibException.Create('prime1');
  if not APrime2.IsInitialized then
    raise EArgumentNilCryptoLibException.Create('prime2');
  if not AExponent1.IsInitialized then
    raise EArgumentNilCryptoLibException.Create('exponent1');
  if not AExponent2.IsInitialized then
    raise EArgumentNilCryptoLibException.Create('exponent2');
  if not ACoefficient.IsInitialized then
    raise EArgumentNilCryptoLibException.Create('coefficient');

  FVersion := TDerInteger.Zero;
  FModulus := AModulus;
  FPublicExponent := APublicExponent;
  FPrivateExponent := APrivateExponent;
  FPrime1 := APrime1;
  FPrime2 := APrime2;
  FExponent1 := AExponent1;
  FExponent2 := AExponent2;
  FCoefficient := ACoefficient;
end;

function TRsaPrivateKeyStructure.GetModulus: TBigInteger;
begin
  Result := FModulus;
end;

function TRsaPrivateKeyStructure.GetPublicExponent: TBigInteger;
begin
  Result := FPublicExponent;
end;

function TRsaPrivateKeyStructure.GetPrivateExponent: TBigInteger;
begin
  Result := FPrivateExponent;
end;

function TRsaPrivateKeyStructure.GetPrime1: TBigInteger;
begin
  Result := FPrime1;
end;

function TRsaPrivateKeyStructure.GetPrime2: TBigInteger;
begin
  Result := FPrime2;
end;

function TRsaPrivateKeyStructure.GetExponent1: TBigInteger;
begin
  Result := FExponent1;
end;

function TRsaPrivateKeyStructure.GetExponent2: TBigInteger;
begin
  Result := FExponent2;
end;

function TRsaPrivateKeyStructure.GetCoefficient: TBigInteger;
begin
  Result := FCoefficient;
end;

function TRsaPrivateKeyStructure.ToAsn1Object: IAsn1Object;
begin
  Result := TDerSequence.Create([
    FVersion,
    TDerInteger.Create(FModulus),
    TDerInteger.Create(FPublicExponent),
    TDerInteger.Create(FPrivateExponent),
    TDerInteger.Create(FPrime1),
    TDerInteger.Create(FPrime2),
    TDerInteger.Create(FExponent1),
    TDerInteger.Create(FExponent2),
    TDerInteger.Create(FCoefficient)
  ]);
end;

{ TRsassaPssParameters }

class constructor TRsassaPssParameters.Create;
begin
  Boot;
end;

class procedure TRsassaPssParameters.Boot;
begin
  DefaultHashAlgorithm := TAlgorithmIdentifier.Create(TOiwObjectIdentifiers.IdSha1, TDerNull.Instance);
  DefaultMaskGenAlgorithm := TAlgorithmIdentifier.Create(TPkcsObjectIdentifiers.IdMgf1, DefaultHashAlgorithm);
  DefaultMaskGenFunction := DefaultMaskGenAlgorithm; // Obsolete, use DefaultMaskGenAlgorithm
  DefaultSaltLength := TDerInteger.ValueOf(20);
  DefaultTrailerField := TDerInteger.One;
end;

class function TRsassaPssParameters.GetInstance(AObj: TObject): IRsassaPssParameters;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IRsassaPssParameters, Result) then
    Exit;

  Result := TRsassaPssParameters.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TRsassaPssParameters.GetInstance(const AObj: IAsn1Convertible): IRsassaPssParameters;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IRsassaPssParameters, Result) then
    Exit;

  Result := TRsassaPssParameters.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TRsassaPssParameters.GetInstance(const AEncoded: TCryptoLibByteArray): IRsassaPssParameters;
begin
  if AEncoded = nil then
  begin
    Result := nil;
    Exit;
  end;

  Result := TRsassaPssParameters.Create(TAsn1Sequence.GetInstance(AEncoded));
end;

class function TRsassaPssParameters.GetInstance(const AObj: IAsn1TaggedObject;
  AExplicitly: Boolean): IRsassaPssParameters;
begin
  Result := TRsassaPssParameters.Create(TAsn1Sequence.GetInstance(AObj, AExplicitly));
end;

class function TRsassaPssParameters.GetTagged(const ATaggedObject: IAsn1TaggedObject;
  ADeclaredExplicit: Boolean): IRsassaPssParameters;
begin
  Result := TRsassaPssParameters.Create(TAsn1Sequence.GetTagged(ATaggedObject, ADeclaredExplicit));
end;

constructor TRsassaPssParameters.Create(const ASeq: IAsn1Sequence);
var
  LCount, LPos: Int32;
begin
  inherited Create();
  LCount := ASeq.Count;
  LPos := 0;
  if (LCount < 0) or (LCount > 4) then
    raise EArgumentCryptoLibException.CreateResFmt(@SBadSequenceSize, [LCount]);

  FHashAlgorithm := TAsn1Utilities.ReadOptionalContextTagged<Boolean, IAlgorithmIdentifier>(ASeq, LPos, 0, True,
    function(ATagged: IAsn1TaggedObject; AState: Boolean): IAlgorithmIdentifier
    begin
      Result := TAlgorithmIdentifier.GetTagged(ATagged, AState);
    end);
  if FHashAlgorithm = nil then
    FHashAlgorithm := DefaultHashAlgorithm;

  FMaskGenAlgorithm := TAsn1Utilities.ReadOptionalContextTagged<Boolean, IAlgorithmIdentifier>(ASeq, LPos, 1, True,
    function(ATagged: IAsn1TaggedObject; AState: Boolean): IAlgorithmIdentifier
    begin
      Result := TAlgorithmIdentifier.GetTagged(ATagged, AState);
    end);
  if FMaskGenAlgorithm = nil then
    FMaskGenAlgorithm := DefaultMaskGenAlgorithm;

  FSaltLength := TAsn1Utilities.ReadOptionalContextTagged<Boolean, IDerInteger>(ASeq, LPos, 2, True,
    function(ATagged: IAsn1TaggedObject; AState: Boolean): IDerInteger
    begin
      Result := TDerInteger.GetTagged(ATagged, AState);
    end);
  if FSaltLength = nil then
    FSaltLength := DefaultSaltLength;

  FTrailerField := TAsn1Utilities.ReadOptionalContextTagged<Boolean, IDerInteger>(ASeq, LPos, 3, True,
    function(ATagged: IAsn1TaggedObject; AState: Boolean): IDerInteger
    begin
      Result := TDerInteger.GetTagged(ATagged, AState);
    end);
  if FTrailerField = nil then
    FTrailerField := DefaultTrailerField;

  if LPos <> LCount then
    raise EArgumentCryptoLibException.CreateRes(@SUnexpectedElementsInSequence);
end;

constructor TRsassaPssParameters.Create;
begin
  inherited Create();
  FHashAlgorithm := DefaultHashAlgorithm;
  FMaskGenAlgorithm := DefaultMaskGenAlgorithm;
  FSaltLength := DefaultSaltLength;
  FTrailerField := DefaultTrailerField;
end;

constructor TRsassaPssParameters.Create(const AHashAlgorithm, AMaskGenAlgorithm: IAlgorithmIdentifier;
  const ASaltLength, ATrailerField: IDerInteger);
begin
  inherited Create();
  if AHashAlgorithm = nil then
    FHashAlgorithm := DefaultHashAlgorithm
  else
    FHashAlgorithm := AHashAlgorithm;

  if AMaskGenAlgorithm = nil then
    FMaskGenAlgorithm := DefaultMaskGenAlgorithm
  else
    FMaskGenAlgorithm := AMaskGenAlgorithm;

  if ASaltLength = nil then
    FSaltLength := DefaultSaltLength
  else
    FSaltLength := ASaltLength;

  if ATrailerField = nil then
    FTrailerField := DefaultTrailerField
  else
    FTrailerField := ATrailerField;
end;

function TRsassaPssParameters.GetHashAlgorithm: IAlgorithmIdentifier;
begin
  Result := FHashAlgorithm;
end;

function TRsassaPssParameters.GetMaskGenAlgorithm: IAlgorithmIdentifier;
begin
  Result := FMaskGenAlgorithm;
end;

function TRsassaPssParameters.GetSaltLength: IDerInteger;
begin
  Result := FSaltLength;
end;

function TRsassaPssParameters.GetTrailerField: IDerInteger;
begin
  Result := FTrailerField;
end;

function TRsassaPssParameters.ToAsn1Object: IAsn1Object;
var
  LV: IAsn1EncodableVector;
begin
  LV := TAsn1EncodableVector.Create(4);

  if not DefaultHashAlgorithm.Equals(FHashAlgorithm) then
  begin
    LV.Add(TDerTaggedObject.Create(True, 0, FHashAlgorithm));
  end;

  if not DefaultMaskGenAlgorithm.Equals(FMaskGenAlgorithm) then
  begin
    LV.Add(TDerTaggedObject.Create(True, 1, FMaskGenAlgorithm));
  end;

  if not DefaultSaltLength.Equals(FSaltLength) then
  begin
    LV.Add(TDerTaggedObject.Create(True, 2, FSaltLength));
  end;

  if not DefaultTrailerField.Equals(FTrailerField) then
  begin
    LV.Add(TDerTaggedObject.Create(True, 3, FTrailerField));
  end;

  Result := TDerSequence.Create(LV);
end;

{ TContentInfo }

class function TContentInfo.GetInstance(AObj: TObject): IContentInfo;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IContentInfo, Result) then
    Exit;

  raise EArgumentCryptoLibException.CreateFmt('illegal object in GetInstance: %s', [TPlatformUtilities.GetTypeName(AObj)]);
end;

class function TContentInfo.GetInstance(const AObj: IAsn1Convertible): IContentInfo;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IContentInfo, Result) then
    Exit;

  Result := TContentInfo.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TContentInfo.GetInstance(const AEncoded: TCryptoLibByteArray): IContentInfo;
begin
  if AEncoded = nil then
  begin
    Result := nil;
    Exit;
  end;

  Result := TContentInfo.Create(TAsn1Sequence.GetInstance(AEncoded));
end;

class function TContentInfo.GetInstance(const AObj: IAsn1TaggedObject;
  AExplicitly: Boolean): IContentInfo;
begin
  Result := GetInstance(TAsn1Sequence.GetInstance(AObj, AExplicitly));
end;

class function TContentInfo.GetTagged(const ATaggedObject: IAsn1TaggedObject;
  ADeclaredExplicit: Boolean): IContentInfo;
begin
  Result := GetInstance(TAsn1Sequence.GetTagged(ATaggedObject, ADeclaredExplicit));
end;

constructor TContentInfo.Create(const ASeq: IAsn1Sequence);
var
  LCount: Int32;
  LTagged: IAsn1TaggedObject;
begin
  Inherited Create();
  LCount := ASeq.Count;
  if (LCount < 1) or (LCount > 2) then
    raise EArgumentCryptoLibException.CreateFmt('Bad sequence size: %d', [LCount]);

  FContentType := TDerObjectIdentifier.GetInstance(ASeq[0]);

  if ASeq.Count > 1 then
  begin
    LTagged := TAsn1TaggedObject.GetInstance(ASeq[1] as TObject, TAsn1Tags.ContextSpecific, 0);
    FContent := LTagged.GetExplicitBaseObject();
  end
  else
  begin
    FContent := nil;
  end;
end;

constructor TContentInfo.Create(const AContentType: IDerObjectIdentifier;
  const AContent: IAsn1Encodable);
begin
  Inherited Create();
  if AContentType = nil then
    raise EArgumentNilCryptoLibException.Create('contentType');
  FContentType := AContentType;
  FContent := AContent;
end;

function TContentInfo.GetContentType: IDerObjectIdentifier;
begin
  Result := FContentType;
end;

function TContentInfo.GetContent: IAsn1Encodable;
begin
  Result := FContent;
end;

function TContentInfo.ToAsn1Object: IAsn1Object;
var
  LV: IAsn1EncodableVector;
begin
  LV := TAsn1EncodableVector.Create(2);
  LV.Add(FContentType);
  if FContent <> nil then
  begin
    LV.Add(TBerTaggedObject.Create(True, 0, FContent));
  end;
  Result := TBerSequence.Create(LV);
end;

{ TSignedData }

class function TSignedData.GetInstance(AObj: TObject): ISignedData;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, ISignedData, Result) then
    Exit;

  raise EArgumentCryptoLibException.CreateFmt('illegal object in GetInstance: %s', [TPlatformUtilities.GetTypeName(AObj)]);
end;

class function TSignedData.GetInstance(const AObj: IAsn1Convertible): ISignedData;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, ISignedData, Result) then
    Exit;

  Result := TSignedData.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TSignedData.GetInstance(const AEncoded: TCryptoLibByteArray): ISignedData;
begin
  if AEncoded = nil then
  begin
    Result := nil;
    Exit;
  end;

  Result := TSignedData.Create(TAsn1Sequence.GetInstance(AEncoded));
end;

class function TSignedData.GetInstance(const AObj: IAsn1TaggedObject;
  AExplicitly: Boolean): ISignedData;
begin
  Result := GetInstance(TAsn1Sequence.GetInstance(AObj, AExplicitly));
end;

class function TSignedData.GetTagged(const ATaggedObject: IAsn1TaggedObject;
  ADeclaredExplicit: Boolean): ISignedData;
begin
  Result := GetInstance(TAsn1Sequence.GetTagged(ATaggedObject, ADeclaredExplicit));
end;

constructor TSignedData.Create(const ASeq: IAsn1Sequence);
var
  LCount, LPos: Int32;
begin
  Inherited Create();
  LCount := ASeq.Count;
  LPos := 0;
  if (LCount < 4) or (LCount > 6) then
    raise EArgumentCryptoLibException.CreateFmt(SBadSequenceSize, [LCount]);

  FVersion := TDerInteger.GetInstance(ASeq[LPos]);
  System.Inc(LPos);
  FDigestAlgorithms := TAsn1Set.GetInstance(ASeq[LPos]);
  System.Inc(LPos);
  FContentInfo := TContentInfo.GetInstance(ASeq[LPos]);
  System.Inc(LPos);
  FCertificates := TAsn1Utilities.ReadOptionalContextTagged<IAsn1Sequence, IAsn1Set>(
    ASeq, LPos, 0, ASeq,
    function(ATagged: IAsn1TaggedObject; AState: IAsn1Sequence): IAsn1Set
    begin
      Result := TAsn1Set.GetTagged(ATagged, False);
    end);
  FCrls := TAsn1Utilities.ReadOptionalContextTagged<IAsn1Sequence, IAsn1Set>(
    ASeq, LPos, 1, ASeq,
    function(ATagged: IAsn1TaggedObject; AState: IAsn1Sequence): IAsn1Set
    begin
      Result := TAsn1Set.GetTagged(ATagged, False);
    end);
  FSignerInfos := TAsn1Set.GetInstance(ASeq[LPos]);
  System.Inc(LPos);

  if LPos <> LCount then
    raise EArgumentCryptoLibException.Create(SUnexpectedElementsInSequence);
end;

constructor TSignedData.Create(const AVersion: IDerInteger;
  const ADigestAlgorithms: IAsn1Set; const AContentInfo: IContentInfo;
  const ACertificates: IAsn1Set; const ACrls: IAsn1Set;
  const ASignerInfos: IAsn1Set);
begin
  Inherited Create();
  if AVersion = nil then
    raise EArgumentNilCryptoLibException.Create(SVersionNil);
  if ADigestAlgorithms = nil then
    raise EArgumentNilCryptoLibException.Create('digestAlgorithms');
  if AContentInfo = nil then
    raise EArgumentNilCryptoLibException.Create('contentInfo');
  if ASignerInfos = nil then
    raise EArgumentNilCryptoLibException.Create('signerInfos');

  FVersion := AVersion;
  FDigestAlgorithms := ADigestAlgorithms;
  FContentInfo := AContentInfo;
  FCertificates := ACertificates;
  FCrls := ACrls;
  FSignerInfos := ASignerInfos;
end;

function TSignedData.GetVersion: IDerInteger;
begin
  Result := FVersion;
end;

function TSignedData.GetDigestAlgorithms: IAsn1Set;
begin
  Result := FDigestAlgorithms;
end;

function TSignedData.GetContentInfo: IContentInfo;
begin
  Result := FContentInfo;
end;

function TSignedData.GetCertificates: IAsn1Set;
begin
  Result := FCertificates;
end;

function TSignedData.GetCrls: IAsn1Set;
begin
  Result := FCrls;
end;

function TSignedData.GetSignerInfos: IAsn1Set;
begin
  Result := FSignerInfos;
end;

function TSignedData.ToAsn1Object: IAsn1Object;
var
  LV: IAsn1EncodableVector;
begin
  LV := TAsn1EncodableVector.Create(6);
  LV.Add([FVersion, FDigestAlgorithms, FContentInfo]);
  LV.AddOptionalTagged(False, 0, FCertificates);
  LV.AddOptionalTagged(False, 1, FCrls);
  LV.Add(FSignerInfos);
  Result := TBerSequence.Create(LV);
end;

end.
