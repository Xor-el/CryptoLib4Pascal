{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                           Author - Ugochukwu Mmaduekwe                          * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ *                                                                                 * }
{ *                              Acknowledgements:                                  * }
{ *                                                                                 * }
{ *      Thanks to Sphere 10 Software (http://www.sphere10.com/) for sponsoring     * }
{ *                         the development of this library                         * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit ClpCmsAsn1Objects;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpAsn1Objects,
  ClpAsn1Tags,
  ClpAsn1Core,
  ClpAsn1Utilities,
  ClpIAsn1Objects,
  ClpIAsn1Core,
  ClpICmsAsn1Objects,
  ClpCmsObjectIdentifiers,
  ClpIX509Asn1Objects,
  ClpX509Asn1Objects,
  ClpDateTimeUtilities,
  ClpArrayUtilities,
  ClpCryptoLibTypes,
  ClpCryptoLibExceptions;

resourcestring
  SCmsContentTypeNil = 'CMS content type cannot be nil';
  SCmsAsn1ElementNil = 'ASN.1 encodable element cannot be nil';
  SCmsIssuerNil = 'CMS issuer name cannot be nil';
  SCmsSerialNumberNil = 'CMS serial number cannot be nil';
  SCmsIssuerAndSerialNumberNil = 'CMS issuer and serial number cannot be nil';
  SCmsSubjectKeyIdentifierNil = 'CMS subject key identifier cannot be nil';
  SCmsSignerIDNil = 'CMS signer identifier cannot be nil';
  SCmsDigestAlgorithmNil = 'CMS digest algorithm cannot be nil';
  SCmsSignatureAlgorithmNil = 'CMS signature algorithm cannot be nil';
  SCmsSignatureNil = 'CMS signature value cannot be nil';
  SCmsDigestAlgorithmsNil = 'CMS digest algorithms set cannot be nil';
  SCmsEncapContentInfoNil = 'CMS encapsulated content info cannot be nil';
  SCmsSignerInfosNil = 'CMS signer infos set cannot be nil';
  SCmsBinaryTimeCannotBeNegative = 'BinaryTime seconds cannot be negative';
  SCmsBinaryTimeOutOfDateTimeRange = 'BinaryTime out of DateTime range';
  SCmsNoContentFound = 'No content found.';
  SCmsMalformedContent = 'Malformed content.';
  SCmsInvalidIcvLen = 'Invalid ''aes-ICVlen'': %d';
  SCmsIcvLenNotInt32 = 'Invalid ''aes-ICVlen'' (outside Int32 range)';


type

  /// <summary>
  /// RFC 6019 BinaryTime type: unsigned integer count of seconds since 1970-01-01T00:00:00Z (UTC).
  /// </summary>
  TBinaryTime = class(TAsn1Encodable, IBinaryTime)
  strict private
  var
    FTime: IDerInteger;

  strict protected
    function GetTime: IDerInteger;

  public
    class function GetInstance(AObj: TObject): IBinaryTime; overload; static;
    class function GetInstance(const AObj: IAsn1Convertible): IBinaryTime; overload; static;
    class function GetInstance(const AObj: IAsn1TaggedObject;
      ADeclaredExplicit: Boolean): IBinaryTime; overload; static;
    class function GetTagged(const ATaggedObject: IAsn1TaggedObject;
      ADeclaredExplicit: Boolean): IBinaryTime; static;

    constructor Create(const ADateTime: TDateTime); overload;
    constructor Create(ASeconds: Int64); overload;
    constructor Create(const ATime: IDerInteger); overload;

    function GetDateTime: TDateTime;
    function TryGetDateTime(out ADateTime: TDateTime): Boolean;
    function ToAsn1Object: IAsn1Object; override;

    property Time: IDerInteger read GetTime;
  end;

  /// <summary>
  /// CMS ContentInfo (EncapsulatedContentInfo); supports DL/BER encoding choice.
  /// </summary>
  TCmsContentInfo = class(TAsn1Encodable, ICmsContentInfo)
  strict private
  var
    FContentType: IDerObjectIdentifier;
    FContent: IAsn1Encodable;
    FIsDefiniteLength: Boolean;

  strict private
    function IsDLSequence(const ASeq: IAsn1Sequence): Boolean;
    function IsDLSequenceObj(const AAsn1Object: IAsn1Object): Boolean;
    function IsDLOctetString(const AAsn1Object: IAsn1Object): Boolean;
    function IsDLContent(const AContent: IAsn1Encodable): Boolean;

  strict protected
    function GetContentType: IDerObjectIdentifier;
    function GetContent: IAsn1Encodable;
    function GetIsDefiniteLength: Boolean;

  public
    class function GetInstance(AObj: TObject): ICmsContentInfo; overload; static;
    class function GetInstance(const AObj: IAsn1Convertible): ICmsContentInfo; overload; static;
    class function GetInstance(const AEncoded: TCryptoLibByteArray): ICmsContentInfo; overload; static;
    class function GetInstance(const AObj: IAsn1TaggedObject;
      AExplicitly: Boolean): ICmsContentInfo; overload; static;
    class function GetOptional(const AElement: IAsn1Encodable): ICmsContentInfo; static;
    class function GetTagged(const ATaggedObject: IAsn1TaggedObject;
      ADeclaredExplicit: Boolean): ICmsContentInfo; static;

    constructor Create(const ASeq: IAsn1Sequence); overload;
    constructor Create(const AContentType: IDerObjectIdentifier;
      const AContent: IAsn1Encodable); overload;

    function ToAsn1Object: IAsn1Object; override;

    property ContentType: IDerObjectIdentifier read GetContentType;
    property Content: IAsn1Encodable read GetContent;
    property IsDefiniteLength: Boolean read GetIsDefiniteLength;
  end;

  /// <summary>
  /// RFC 5084 AES-CCM AlgorithmIdentifier parameters.
  /// </summary>
  TCcmParameters = class(TAsn1Encodable, ICcmParameters)
  strict private
  const
    DefaultIcvLen = 12;

  var
    FNonce: IAsn1OctetString;
    FIcvLen: Int32;

    class function ValidateIcvLen(const AIcvLen: IDerInteger): Int32; static;
    class function ValidateIcvLenValue(AIcvLen: Int32): Int32; static;

  strict protected
    function GetNonce: TCryptoLibByteArray;
    function GetIcvLen: Int32;

    constructor Create(const ASeq: IAsn1Sequence); overload;

  public
    class function GetInstance(AObj: TObject): ICcmParameters; overload; static;
    class function GetInstance(const AObj: IAsn1Convertible): ICcmParameters; overload; static;
    class function GetInstance(const AObj: IAsn1TaggedObject;
      AExplicitly: Boolean): ICcmParameters; overload; static;
    class function GetTagged(const ATaggedObject: IAsn1TaggedObject;
      ADeclaredExplicit: Boolean): ICcmParameters; static;

    constructor Create(const ANonce: TCryptoLibByteArray; AIcvLen: Int32); overload;

    function ToAsn1Object: IAsn1Object; override;

    property Nonce: TCryptoLibByteArray read GetNonce;
    property IcvLen: Int32 read GetIcvLen;
  end;

  /// <summary>
  /// RFC 5084 AES-GCM AlgorithmIdentifier parameters.
  /// </summary>
  TGcmParameters = class(TAsn1Encodable, IGcmParameters)
  strict private
  const
    DefaultIcvLen = 12;

  var
    FNonce: IAsn1OctetString;
    FIcvLen: Int32;

    class function ValidateIcvLen(const AIcvLen: IDerInteger): Int32; static;
    class function ValidateIcvLenValue(AIcvLen: Int32): Int32; static;

  strict protected
    function GetNonce: TCryptoLibByteArray;
    function GetIcvLen: Int32;

    constructor Create(const ASeq: IAsn1Sequence); overload;

  public
    class function GetInstance(AObj: TObject): IGcmParameters; overload; static;
    class function GetInstance(const AObj: IAsn1Convertible): IGcmParameters; overload; static;
    class function GetInstance(const AObj: IAsn1TaggedObject;
      AExplicitly: Boolean): IGcmParameters; overload; static;
    class function GetTagged(const ATaggedObject: IAsn1TaggedObject;
      ADeclaredExplicit: Boolean): IGcmParameters; static;

    constructor Create(const ANonce: TCryptoLibByteArray; AIcvLen: Int32); overload;

    function ToAsn1Object: IAsn1Object; override;

    property Nonce: TCryptoLibByteArray read GetNonce;
    property IcvLen: Int32 read GetIcvLen;
  end;

  /// <summary>
  /// CMS IssuerAndSerialNumber (issuer Name + serialNumber).
  /// </summary>
  TCmsIssuerAndSerialNumber = class(TAsn1Encodable, ICmsIssuerAndSerialNumber)
  strict private
  var
    FIssuer: IX509Name;
    FSerialNumber: IDerInteger;

  strict protected
    function GetIssuer: IX509Name;
    function GetSerialNumber: IDerInteger;

  public
    class function GetInstance(AObj: TObject): ICmsIssuerAndSerialNumber; overload; static;
    class function GetInstance(const AObj: IAsn1Convertible): ICmsIssuerAndSerialNumber; overload; static;
    class function GetInstance(const AObj: IAsn1TaggedObject;
      AExplicitly: Boolean): ICmsIssuerAndSerialNumber; overload; static;
    class function GetOptional(const AElement: IAsn1Encodable): ICmsIssuerAndSerialNumber; static;
    class function GetTagged(const ATaggedObject: IAsn1TaggedObject;
      ADeclaredExplicit: Boolean): ICmsIssuerAndSerialNumber; static;

    constructor Create(const ASeq: IAsn1Sequence); overload;
    constructor Create(const AIssuer: IX509Name; const ASerialNumber: IDerInteger); overload;

    function ToAsn1Object: IAsn1Object; override;

    property Issuer: IX509Name read GetIssuer;
    property SerialNumber: IDerInteger read GetSerialNumber;
  end;

  /// <summary>
  /// CMS SignerIdentifier (CHOICE: IssuerAndSerialNumber or [0] SubjectKeyIdentifier).
  /// </summary>
  TCmsSignerIdentifier = class(TAsn1Encodable, ICmsSignerIdentifier)
  strict private
  var
    FId: IAsn1Encodable;

    class function ChoiceGetOptional(AElement: IAsn1Encodable): ICmsSignerIdentifier; static;
    class function ChoiceGetInstance(AElement: IAsn1Encodable): ICmsSignerIdentifier; static;
    class function GetTaggedAsn1OctetString(ATagged: IAsn1TaggedObject; AState: Boolean): IAsn1Encodable; static;

  strict protected
    function GetIsTagged: Boolean;
    function GetID: IAsn1Encodable;

  public
    class function GetInstance(AObj: TObject): ICmsSignerIdentifier; overload; static;
    class function GetInstance(const AObj: IAsn1Convertible): ICmsSignerIdentifier; overload; static;
    class function GetInstance(const AObj: IAsn1TaggedObject;
      ADeclaredExplicit: Boolean): ICmsSignerIdentifier; overload; static;
    class function GetOptional(const AElement: IAsn1Encodable): ICmsSignerIdentifier; static;
    class function GetTagged(const ATaggedObject: IAsn1TaggedObject;
      ADeclaredExplicit: Boolean): ICmsSignerIdentifier; static;

    constructor Create(const AIssuerAndSerialNumber: ICmsIssuerAndSerialNumber); overload;
    constructor Create(const ASubjectKeyIdentifier: IAsn1OctetString); overload;

    function ToAsn1Object: IAsn1Object; override;

    property IsTagged: Boolean read GetIsTagged;
    property ID: IAsn1Encodable read GetID;
  end;

  /// <summary>
  /// CMS SignerInfo (per-signer information in SignedData).
  /// </summary>
  TCmsSignerInfo = class(TAsn1Encodable, ICmsSignerInfo)
  strict private
  var
    FVersion: IDerInteger;
    FSignerID: ICmsSignerIdentifier;
    FDigestAlgorithm: IAlgorithmIdentifier;
    FSignedAttrs: IAsn1Set;
    FSignatureAlgorithm: IAlgorithmIdentifier;
    FSignature: IAsn1OctetString;
    FUnsignedAttrs: IAsn1Set;

  strict protected
    function GetVersion: IDerInteger;
    function GetSignerID: ICmsSignerIdentifier;
    function GetDigestAlgorithm: IAlgorithmIdentifier;
    function GetSignedAttrs: IAsn1Set;
    function GetSignatureAlgorithm: IAlgorithmIdentifier;
    function GetSignature: IAsn1OctetString;
    function GetUnsignedAttrs: IAsn1Set;

  public
    class function GetInstance(AObj: TObject): ICmsSignerInfo; overload; static;
    class function GetInstance(const AObj: IAsn1Convertible): ICmsSignerInfo; overload; static;
    class function GetInstance(const AObj: IAsn1TaggedObject;
      AExplicitly: Boolean): ICmsSignerInfo; overload; static;
    class function GetTagged(const ATaggedObject: IAsn1TaggedObject;
      ADeclaredExplicit: Boolean): ICmsSignerInfo; static;

    constructor Create(const ASeq: IAsn1Sequence); overload;
    constructor Create(const ASignerID: ICmsSignerIdentifier;
      const ADigestAlgorithm: IAlgorithmIdentifier; const ASignedAttrs: IAsn1Set;
      const ASignatureAlgorithm: IAlgorithmIdentifier; const ASignature: IAsn1OctetString;
      const AUnsignedAttrs: IAsn1Set); overload;

    function ToAsn1Object: IAsn1Object; override;

    property Version: IDerInteger read GetVersion;
    property SignerID: ICmsSignerIdentifier read GetSignerID;
    property DigestAlgorithm: IAlgorithmIdentifier read GetDigestAlgorithm;
    property SignedAttrs: IAsn1Set read GetSignedAttrs;
    property SignatureAlgorithm: IAlgorithmIdentifier read GetSignatureAlgorithm;
    property Signature: IAsn1OctetString read GetSignature;
    property UnsignedAttrs: IAsn1Set read GetUnsignedAttrs;
  end;

  /// <summary>
  /// CMS SignedData (RFC 3852).
  /// </summary>
  TCmsSignedData = class(TAsn1Encodable, ICmsSignedData)
  strict private
  var
    FVersion: IDerInteger;
    FDigestAlgorithms: IAsn1Set;
    FEncapContentInfo: ICmsContentInfo;
    FCertificates: IAsn1Set;
    FCrls: IAsn1Set;
    FSignerInfos: IAsn1Set;
    FCertsBer: Boolean;
    FCrlsBer: Boolean;
    FDigsBer: Boolean;
    FSigsBer: Boolean;

  strict private
    class procedure ReadOptionalTaggedSet(const ASeq: IAsn1Sequence; var APos: Int32;
      ATagNo: Int32; out ASet: IAsn1Set; out AIsBer: Boolean); static;
    class function CalculateVersionField(const AContentOid: IDerObjectIdentifier;
      const ACerts, ACrls, ASignerInfs: IAsn1Set): IDerInteger; static;
    class function HasV3SignerInfos(const ASignerInfs: IAsn1Set): Boolean; static;

  strict protected
    function GetVersion: IDerInteger;
    function GetDigestAlgorithms: IAsn1Set;
    function GetEncapContentInfo: ICmsContentInfo;
    function GetCertificates: IAsn1Set;
    function GetCrls: IAsn1Set;
    function GetSignerInfos: IAsn1Set;

  public
    class function GetInstance(AObj: TObject): ICmsSignedData; overload; static;
    class function GetInstance(const AObj: IAsn1Convertible): ICmsSignedData; overload; static;
    class function GetInstance(const AEncoded: TCryptoLibByteArray): ICmsSignedData; overload; static;
    class function GetInstance(const AObj: IAsn1TaggedObject;
      AExplicitly: Boolean): ICmsSignedData; overload; static;
    class function GetTagged(const ATaggedObject: IAsn1TaggedObject;
      ADeclaredExplicit: Boolean): ICmsSignedData; static;
    class function FromContentInfo(const AInfo: ICmsContentInfo): ICmsSignedData; static;

    constructor Create(const ASeq: IAsn1Sequence); overload;
    constructor Create(const ADigestAlgorithms: IAsn1Set; const AEncapContentInfo: ICmsContentInfo;
      const ACertificates, ACrls, ASignerInfos: IAsn1Set); overload;

    function ToAsn1Object: IAsn1Object; override;

    property Version: IDerInteger read GetVersion;
    property DigestAlgorithms: IAsn1Set read GetDigestAlgorithms;
    property EncapContentInfo: ICmsContentInfo read GetEncapContentInfo;
    property Certificates: IAsn1Set read GetCertificates;
    property Crls: IAsn1Set read GetCrls;
    property SignerInfos: IAsn1Set read GetSignerInfos;
  end;

implementation

{ TBinaryTime }

class function TBinaryTime.GetInstance(AObj: TObject): IBinaryTime;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IBinaryTime, Result) then
    Exit;

  Result := TBinaryTime.Create(TDerInteger.GetInstance(AObj));
end;

class function TBinaryTime.GetInstance(const AObj: IAsn1Convertible): IBinaryTime;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IBinaryTime, Result) then
    Exit;

  Result := TBinaryTime.Create(TDerInteger.GetInstance(AObj));
end;

class function TBinaryTime.GetInstance(const AObj: IAsn1TaggedObject;
  ADeclaredExplicit: Boolean): IBinaryTime;
begin
  Result := TBinaryTime.Create(TDerInteger.GetInstance(AObj, ADeclaredExplicit));
end;

class function TBinaryTime.GetTagged(const ATaggedObject: IAsn1TaggedObject;
  ADeclaredExplicit: Boolean): IBinaryTime;
begin
  Result := TBinaryTime.Create(TDerInteger.GetTagged(ATaggedObject, ADeclaredExplicit));
end;

constructor TBinaryTime.Create(const ADateTime: TDateTime);
begin
  Create(TDateTimeUtilities.DateTimeToUnixMs(ADateTime) div 1000);
end;

constructor TBinaryTime.Create(ASeconds: Int64);
begin
  Create(TDerInteger.ValueOf(ASeconds));
end;

constructor TBinaryTime.Create(const ATime: IDerInteger);
begin
  inherited Create();
  if ATime = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SCmsAsn1ElementNil);
  if ATime.IsNegative then
    raise EArgumentOutOfRangeCryptoLibException.CreateRes(@SCmsBinaryTimeCannotBeNegative);

  FTime := ATime;
end;

function TBinaryTime.GetTime: IDerInteger;
begin
  Result := FTime;
end;

function TBinaryTime.GetDateTime: TDateTime;
begin
  if not TryGetDateTime(Result) then
    raise EArithmeticCryptoLibException.CreateRes(@SCmsBinaryTimeOutOfDateTimeRange);
end;

function TBinaryTime.TryGetDateTime(out ADateTime: TDateTime): Boolean;
var
  LSeconds: Int64;
begin
  if FTime.TryGetLongValueExact(LSeconds) and (LSeconds <= High(Int64) div 1000) then
  begin
    ADateTime := TDateTimeUtilities.UnixMsToDateTime(LSeconds * 1000);
    Result := True;
    Exit;
  end;

  ADateTime := 0;
  Result := False;
end;

function TBinaryTime.ToAsn1Object: IAsn1Object;
begin
  Result := FTime;
end;

{ TCmsContentInfo }

class function TCmsContentInfo.GetInstance(AObj: TObject): ICmsContentInfo;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, ICmsContentInfo, Result) then
    Exit;

  Result := TCmsContentInfo.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TCmsContentInfo.GetInstance(const AObj: IAsn1Convertible): ICmsContentInfo;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, ICmsContentInfo, Result) then
    Exit;

  Result := TCmsContentInfo.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TCmsContentInfo.GetInstance(const AEncoded: TCryptoLibByteArray): ICmsContentInfo;
var
  LSeq: IAsn1Sequence;
begin
  if AEncoded = nil then
    raise EArgumentCryptoLibException.CreateRes(@SCmsNoContentFound);

  LSeq := TAsn1Sequence.GetInstance(AEncoded);
  if LSeq = nil then
    raise EArgumentCryptoLibException.CreateRes(@SCmsNoContentFound);

  Result := TCmsContentInfo.Create(LSeq);
end;

class function TCmsContentInfo.GetInstance(const AObj: IAsn1TaggedObject;
  AExplicitly: Boolean): ICmsContentInfo;
begin
  Result := TCmsContentInfo.Create(TAsn1Sequence.GetInstance(AObj, AExplicitly));
end;

class function TCmsContentInfo.GetTagged(const ATaggedObject: IAsn1TaggedObject;
  ADeclaredExplicit: Boolean): ICmsContentInfo;
begin
  Result := TCmsContentInfo.Create(TAsn1Sequence.GetTagged(ATaggedObject, ADeclaredExplicit));
end;

function TCmsContentInfo.IsDLSequence(const ASeq: IAsn1Sequence): Boolean;
var
  LObj: IAsn1Object;
begin
  if ASeq = nil then
  begin
    Result := False;
    Exit;
  end;
  LObj := ASeq as IAsn1Object;
  Result := Supports(LObj, IDLSequence);
end;

function TCmsContentInfo.IsDLSequenceObj(const AAsn1Object: IAsn1Object): Boolean;
begin
  Result := (AAsn1Object <> nil) and Supports(AAsn1Object, IDLSequence);
end;

function TCmsContentInfo.IsDLOctetString(const AAsn1Object: IAsn1Object): Boolean;
begin
  Result := (AAsn1Object <> nil) and Supports(AAsn1Object, IDerOctetString);
end;

function TCmsContentInfo.IsDLContent(const AContent: IAsn1Encodable): Boolean;
var
  LObj: IAsn1Object;
begin
  if AContent = nil then
  begin
    Result := True;
    Exit;
  end;
  LObj := AContent.ToAsn1Object();
  Result := IsDLOctetString(LObj) or IsDLSequenceObj(LObj);
end;

class function TCmsContentInfo.GetOptional(const AElement: IAsn1Encodable): ICmsContentInfo;
var
  LSeq: IAsn1Sequence;
begin
  if AElement = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SCmsAsn1ElementNil);
  if Supports(AElement, ICmsContentInfo, Result) then
    Exit;
  LSeq := TAsn1Sequence.GetOptional(AElement);
  if LSeq <> nil then
  begin
    Result := TCmsContentInfo.Create(LSeq);
    Exit;
  end;
  Result := nil;
end;

constructor TCmsContentInfo.Create(const ASeq: IAsn1Sequence);
var
  LPos: Int32;
begin
  Inherited Create();
  LPos := 0;
  TAsn1Utilities.CheckSequenceSize(ASeq, 1, 2);
  FContentType := TAsn1Utilities.Read<IDerObjectIdentifier>(ASeq, LPos, TDerObjectIdentifier.GetInstance);
  FContent := TAsn1Utilities.ReadOptionalContextTagged<IAsn1Encodable>(ASeq, LPos, 0, True,
    TAsn1Utilities.GetTaggedExplicitBaseObject);
  TAsn1Utilities.RequireEndOfSequence(ASeq, LPos);
  FIsDefiniteLength := IsDLSequence(ASeq);
end;

constructor TCmsContentInfo.Create(const AContentType: IDerObjectIdentifier;
  const AContent: IAsn1Encodable);
begin
  Inherited Create();
  if AContentType = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SCmsContentTypeNil);
  FContentType := AContentType;
  FContent := AContent;
  FIsDefiniteLength := IsDLContent(AContent);
end;

function TCmsContentInfo.GetContentType: IDerObjectIdentifier;
begin
  Result := FContentType;
end;

function TCmsContentInfo.GetContent: IAsn1Encodable;
begin
  Result := FContent;
end;

function TCmsContentInfo.GetIsDefiniteLength: Boolean;
begin
  Result := FIsDefiniteLength;
end;

function TCmsContentInfo.ToAsn1Object: IAsn1Object;
begin
  if FIsDefiniteLength then
  begin
    if FContent = nil then
      Result := TDLSequence.Create(FContentType)
    else
      Result := TDLSequence.Create(FContentType, TDLTaggedObject.Create(0, FContent) as IDLTaggedObject);
  end
  else
  begin
    if FContent = nil then
      Result := TBerSequence.Create(FContentType)
    else
      Result := TBerSequence.Create(FContentType, TBerTaggedObject.Create(True, 0, FContent) AS IBerTaggedObject);
  end;
end;

{ TCmsIssuerAndSerialNumber }

class function TCmsIssuerAndSerialNumber.GetInstance(AObj: TObject): ICmsIssuerAndSerialNumber;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;
  if Supports(AObj, ICmsIssuerAndSerialNumber, Result) then
    Exit;
  Result := TCmsIssuerAndSerialNumber.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TCmsIssuerAndSerialNumber.GetInstance(const AObj: IAsn1Convertible): ICmsIssuerAndSerialNumber;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;
  if Supports(AObj, ICmsIssuerAndSerialNumber, Result) then
    Exit;
  Result := TCmsIssuerAndSerialNumber.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TCmsIssuerAndSerialNumber.GetInstance(const AObj: IAsn1TaggedObject;
  AExplicitly: Boolean): ICmsIssuerAndSerialNumber;
begin
  Result := TCmsIssuerAndSerialNumber.Create(TAsn1Sequence.GetInstance(AObj, AExplicitly));
end;

class function TCmsIssuerAndSerialNumber.GetOptional(const AElement: IAsn1Encodable): ICmsIssuerAndSerialNumber;
var
  LSeq: IAsn1Sequence;
begin
  if AElement = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SCmsAsn1ElementNil);
  if Supports(AElement, ICmsIssuerAndSerialNumber, Result) then
    Exit;
  LSeq := TAsn1Sequence.GetOptional(AElement);
  if LSeq <> nil then
  begin
    Result := TCmsIssuerAndSerialNumber.Create(LSeq);
    Exit;
  end;
  Result := nil;
end;

class function TCmsIssuerAndSerialNumber.GetTagged(const ATaggedObject: IAsn1TaggedObject;
  ADeclaredExplicit: Boolean): ICmsIssuerAndSerialNumber;
begin
  Result := TCmsIssuerAndSerialNumber.Create(TAsn1Sequence.GetTagged(ATaggedObject, ADeclaredExplicit));
end;

constructor TCmsIssuerAndSerialNumber.Create(const ASeq: IAsn1Sequence);
var
  LPos: Int32;
begin
  Inherited Create();
  LPos := 0;
  TAsn1Utilities.CheckSequenceSize(ASeq, 2, 2);
  FIssuer := TAsn1Utilities.Read<IX509Name>(ASeq, LPos, TX509Name.GetInstance);
  FSerialNumber := TAsn1Utilities.Read<IDerInteger>(ASeq, LPos, TDerInteger.GetInstance);
  TAsn1Utilities.RequireEndOfSequence(ASeq, LPos);
end;

constructor TCmsIssuerAndSerialNumber.Create(const AIssuer: IX509Name; const ASerialNumber: IDerInteger);
begin
  Inherited Create();
  if AIssuer = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SCmsIssuerNil);
  if ASerialNumber = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SCmsSerialNumberNil);
  FIssuer := AIssuer;
  FSerialNumber := ASerialNumber;
end;

function TCmsIssuerAndSerialNumber.GetIssuer: IX509Name;
begin
  Result := FIssuer;
end;

function TCmsIssuerAndSerialNumber.GetSerialNumber: IDerInteger;
begin
  Result := FSerialNumber;
end;

function TCmsIssuerAndSerialNumber.ToAsn1Object: IAsn1Object;
begin
  Result := TDerSequence.Create([FIssuer, FSerialNumber]);
end;

{ TCmsSignerIdentifier }

class function TCmsSignerIdentifier.ChoiceGetOptional(AElement: IAsn1Encodable): ICmsSignerIdentifier;
begin
  Result := GetOptional(AElement);
end;

class function TCmsSignerIdentifier.ChoiceGetInstance(AElement: IAsn1Encodable): ICmsSignerIdentifier;
begin
  Result := GetInstance(AElement);
end;

class function TCmsSignerIdentifier.GetTaggedAsn1OctetString(ATagged: IAsn1TaggedObject; AState: Boolean): IAsn1Encodable;
begin
  Result := TAsn1OctetString.GetTagged(ATagged, AState);
end;

class function TCmsSignerIdentifier.GetInstance(AObj: TObject): ICmsSignerIdentifier;
begin
  Result := TAsn1Utilities.GetInstanceChoice<ICmsSignerIdentifier>(AObj, ChoiceGetOptional);
end;

class function TCmsSignerIdentifier.GetInstance(const AObj: IAsn1Convertible): ICmsSignerIdentifier;
var
  LObj: IAsn1Object;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;
  LObj := AObj.ToAsn1Object();
  Result := TAsn1Utilities.GetInstanceChoice<ICmsSignerIdentifier>(LObj, ChoiceGetOptional);
end;

class function TCmsSignerIdentifier.GetInstance(const AObj: IAsn1TaggedObject;
  ADeclaredExplicit: Boolean): ICmsSignerIdentifier;
begin
  Result := TAsn1Utilities.GetInstanceChoice<ICmsSignerIdentifier>(AObj, ADeclaredExplicit, ChoiceGetOptional);
end;

class function TCmsSignerIdentifier.GetOptional(const AElement: IAsn1Encodable): ICmsSignerIdentifier;
var
  LIssuerAndSerial: ICmsIssuerAndSerialNumber;
  LTagged: IAsn1TaggedObject;
begin
  if AElement = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SCmsAsn1ElementNil);
  if Supports(AElement, ICmsSignerIdentifier, Result) then
    Exit;
  LIssuerAndSerial := TCmsIssuerAndSerialNumber.GetOptional(AElement);
  if LIssuerAndSerial <> nil then
  begin
    Result := TCmsSignerIdentifier.Create(LIssuerAndSerial);
    Exit;
  end;
  LTagged := TAsn1TaggedObject.GetOptional(AElement);
  if (LTagged <> nil) and LTagged.HasContextTag(0) then
  begin
    Result := TCmsSignerIdentifier.Create(TAsn1OctetString.GetTagged(LTagged, False));
    Exit;
  end;
  Result := nil;
end;

class function TCmsSignerIdentifier.GetTagged(const ATaggedObject: IAsn1TaggedObject;
  ADeclaredExplicit: Boolean): ICmsSignerIdentifier;
begin
  Result := TAsn1Utilities.GetTaggedChoice<ICmsSignerIdentifier>(ATaggedObject, ADeclaredExplicit, ChoiceGetInstance);
end;

constructor TCmsSignerIdentifier.Create(const AIssuerAndSerialNumber: ICmsIssuerAndSerialNumber);
begin
  Inherited Create();
  if AIssuerAndSerialNumber = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SCmsIssuerAndSerialNumberNil);
  FId := AIssuerAndSerialNumber;
end;

constructor TCmsSignerIdentifier.Create(const ASubjectKeyIdentifier: IAsn1OctetString);
begin
  Inherited Create();
  if ASubjectKeyIdentifier = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SCmsSubjectKeyIdentifierNil);
  FId := TDerTaggedObject.Create(False, 0, ASubjectKeyIdentifier) as IAsn1Encodable;
end;

function TCmsSignerIdentifier.GetIsTagged: Boolean;
begin
  Result := Supports(FId, IAsn1TaggedObject);
end;

function TCmsSignerIdentifier.GetID: IAsn1Encodable;
var
  LResult: IAsn1Encodable;
begin
  if TAsn1Utilities.TryGetOptionalContextTagged<Boolean, IAsn1Encodable>(FId, 0, False, LResult,
    GetTaggedAsn1OctetString) then
    Result := LResult
  else
    Result := TCmsIssuerAndSerialNumber.GetInstance(FId);
end;

function TCmsSignerIdentifier.ToAsn1Object: IAsn1Object;
begin
  Result := FId.ToAsn1Object();
end;

{ TCmsSignerInfo }

class function TCmsSignerInfo.GetInstance(AObj: TObject): ICmsSignerInfo;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;
  if Supports(AObj, ICmsSignerInfo, Result) then
    Exit;
  Result := TCmsSignerInfo.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TCmsSignerInfo.GetInstance(const AObj: IAsn1Convertible): ICmsSignerInfo;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;
  if Supports(AObj, ICmsSignerInfo, Result) then
    Exit;
  Result := TCmsSignerInfo.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TCmsSignerInfo.GetInstance(const AObj: IAsn1TaggedObject;
  AExplicitly: Boolean): ICmsSignerInfo;
begin
  Result := TCmsSignerInfo.Create(TAsn1Sequence.GetInstance(AObj, AExplicitly));
end;

class function TCmsSignerInfo.GetTagged(const ATaggedObject: IAsn1TaggedObject;
  ADeclaredExplicit: Boolean): ICmsSignerInfo;
begin
  Result := TCmsSignerInfo.Create(TAsn1Sequence.GetTagged(ATaggedObject, ADeclaredExplicit));
end;

constructor TCmsSignerInfo.Create(const ASeq: IAsn1Sequence);
var
  LPos: Int32;
begin
  Inherited Create();
  LPos := 0;
  TAsn1Utilities.CheckSequenceSize(ASeq, 5, 7);
  FVersion := TAsn1Utilities.Read<IDerInteger>(ASeq, LPos, TDerInteger.GetInstance);
  FSignerID := TAsn1Utilities.Read<ICmsSignerIdentifier>(ASeq, LPos, TCmsSignerIdentifier.GetInstance);
  FDigestAlgorithm := TAsn1Utilities.Read<IAlgorithmIdentifier>(ASeq, LPos, TAlgorithmIdentifier.GetInstance);
  FSignedAttrs := TAsn1Utilities.ReadOptionalContextTagged<IAsn1Set>(ASeq, LPos, 0, False, TAsn1Set.GetTagged);
  FSignatureAlgorithm := TAsn1Utilities.Read<IAlgorithmIdentifier>(ASeq, LPos, TAlgorithmIdentifier.GetInstance);
  FSignature := TAsn1Utilities.Read<IAsn1OctetString>(ASeq, LPos, TAsn1OctetString.GetInstance);
  FUnsignedAttrs := TAsn1Utilities.ReadOptionalContextTagged<IAsn1Set>(ASeq, LPos, 1, False, TAsn1Set.GetTagged);
  TAsn1Utilities.RequireEndOfSequence(ASeq, LPos);
end;

constructor TCmsSignerInfo.Create(const ASignerID: ICmsSignerIdentifier;
  const ADigestAlgorithm: IAlgorithmIdentifier; const ASignedAttrs: IAsn1Set;
  const ASignatureAlgorithm: IAlgorithmIdentifier; const ASignature: IAsn1OctetString;
  const AUnsignedAttrs: IAsn1Set);
begin
  Inherited Create();
  if ASignerID = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SCmsSignerIDNil);
  if ADigestAlgorithm = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SCmsDigestAlgorithmNil);
  if ASignatureAlgorithm = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SCmsSignatureAlgorithmNil);
  if ASignature = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SCmsSignatureNil);
  FSignerID := ASignerID;
  FDigestAlgorithm := ADigestAlgorithm;
  FSignedAttrs := ASignedAttrs;
  FSignatureAlgorithm := ASignatureAlgorithm;
  FSignature := ASignature;
  FUnsignedAttrs := AUnsignedAttrs;
  if ASignerID.IsTagged then
    FVersion := TDerInteger.Three
  else
    FVersion := TDerInteger.One;
end;

function TCmsSignerInfo.GetVersion: IDerInteger;
begin
  Result := FVersion;
end;

function TCmsSignerInfo.GetSignerID: ICmsSignerIdentifier;
begin
  Result := FSignerID;
end;

function TCmsSignerInfo.GetDigestAlgorithm: IAlgorithmIdentifier;
begin
  Result := FDigestAlgorithm;
end;

function TCmsSignerInfo.GetSignedAttrs: IAsn1Set;
begin
  Result := FSignedAttrs;
end;

function TCmsSignerInfo.GetSignatureAlgorithm: IAlgorithmIdentifier;
begin
  Result := FSignatureAlgorithm;
end;

function TCmsSignerInfo.GetSignature: IAsn1OctetString;
begin
  Result := FSignature;
end;

function TCmsSignerInfo.GetUnsignedAttrs: IAsn1Set;
begin
  Result := FUnsignedAttrs;
end;

function TCmsSignerInfo.ToAsn1Object: IAsn1Object;
var
  LV: IAsn1EncodableVector;
begin
  LV := TAsn1EncodableVector.Create(7);
  LV.Add([FVersion, FSignerID, FDigestAlgorithm]);
  LV.AddOptionalTagged(False, 0, FSignedAttrs);
  LV.Add(FSignatureAlgorithm);
  LV.Add(FSignature);
  LV.AddOptionalTagged(False, 1, FUnsignedAttrs);
  Result := TDerSequence.Create(LV);
end;

{ TCmsSignedData }

class procedure TCmsSignedData.ReadOptionalTaggedSet(const ASeq: IAsn1Sequence; var APos: Int32;
  ATagNo: Int32; out ASet: IAsn1Set; out AIsBer: Boolean);
var
  LTagged: IAsn1TaggedObject;
  LFound: Boolean;
begin
  LFound := TAsn1Utilities.TryReadOptionalContextTagged<IAsn1TaggedObject>(ASeq, APos, ATagNo, False,
    LTagged, TAsn1Utilities.GetTaggedObjectIdentity);
  if LFound then
  begin
    ASet := TAsn1Set.GetTagged(LTagged, False);
    AIsBer := Supports(LTagged, IBerTaggedObject);
  end
  else
  begin
    ASet := nil;
    AIsBer := False;
  end;
end;

class function TCmsSignedData.CalculateVersionField(const AContentOid: IDerObjectIdentifier;
  const ACerts, ACrls, ASignerInfs: IAsn1Set): IDerInteger;
var
  LI: Int32;
  LTagged: IAsn1TaggedObject;
  LAnyV1AttrCerts, LAnyV2AttrCerts: Boolean;
  LElement: IAsn1Encodable;
begin
  (*
  * RFC3852, section 5.1:
  * IF((certificates is present) AND
  *    (any certificates with a type of other are present)) OR
  *    ((crls is present) AND
  *    (any crls with a type of other are present))
  * THEN version MUST be 5
  * ELSE
  *    IF(certificates is present) AND
  *       (any version 2 attribute certificates are present)
  *    THEN version MUST be 4
  *    ELSE
  *       IF((certificates is present) AND
  *          (any version 1 attribute certificates are present)) OR
  *          (any SignerInfo structures are version 3) OR
  *          (encapContentInfo eContentType is other than id - data)
  *       THEN version MUST be 3
  *       ELSE version MUST be 1
  *)

  if ACrls <> nil then
  begin
    for LI := 0 to ACrls.Count - 1 do
    begin
      LElement := ACrls.Items[LI];
      LTagged := TAsn1TaggedObject.GetOptional(LElement);
      if LTagged <> nil then
      begin
        if LTagged.HasContextTag(1) then
          Exit(TDerInteger.Five);
      end;
    end;
  end;

  LAnyV1AttrCerts := False;
  if ACerts <> nil then
  begin
    LAnyV2AttrCerts := False;
    for LI := 0 to ACerts.Count - 1 do
    begin
      LElement := ACerts.Items[LI];
      LTagged := TAsn1TaggedObject.GetOptional(LElement);
      if LTagged <> nil then
      begin
        if LTagged.HasContextTag(3) then
          Exit(TDerInteger.Five);
        LAnyV2AttrCerts := LAnyV2AttrCerts or LTagged.HasContextTag(2);
        LAnyV1AttrCerts := LAnyV1AttrCerts or LTagged.HasContextTag(1);
      end;
    end;
    if LAnyV2AttrCerts then
      Exit(TDerInteger.Four);
  end;

  if LAnyV1AttrCerts or (not TCmsObjectIdentifiers.Data.Equals(AContentOid)) or HasV3SignerInfos(ASignerInfs) then
    Exit(TDerInteger.Three);

  Result := TDerInteger.One;
end;

class function TCmsSignedData.HasV3SignerInfos(const ASignerInfs: IAsn1Set): Boolean;
var
  LI: Int32;
  LSignerInfo: ICmsSignerInfo;
  LElement: IAsn1Encodable;
begin
  if ASignerInfs = nil then
  begin
    Result := False;
    Exit;
  end;
  for LI := 0 to ASignerInfs.Count - 1 do
  begin
    LElement := ASignerInfs.Items[LI];
    LSignerInfo := TCmsSignerInfo.GetInstance(LElement);
    if (LSignerInfo <> nil) and LSignerInfo.Version.HasValue(3) then
      Exit(True);
  end;
  Result := False;
end;

class function TCmsSignedData.GetInstance(AObj: TObject): ICmsSignedData;
var
  LSeq: IAsn1Sequence;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;
  if Supports(AObj, ICmsSignedData, Result) then
    Exit;
  LSeq := TAsn1Sequence.GetInstance(AObj);
  if LSeq = nil then
    raise EArgumentCryptoLibException.CreateRes(@SCmsMalformedContent);
  Result := TCmsSignedData.Create(LSeq);
end;

class function TCmsSignedData.GetInstance(const AObj: IAsn1Convertible): ICmsSignedData;
var
  LSeq: IAsn1Sequence;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;
  if Supports(AObj, ICmsSignedData, Result) then
    Exit;
  LSeq := TAsn1Sequence.GetInstance(AObj);
  if LSeq = nil then
    raise EArgumentCryptoLibException.CreateRes(@SCmsMalformedContent);
  Result := TCmsSignedData.Create(LSeq);
end;

class function TCmsSignedData.GetInstance(const AEncoded: TCryptoLibByteArray): ICmsSignedData;
var
  LSeq: IAsn1Sequence;
begin
  if AEncoded = nil then
  begin
    Result := nil;
    Exit;
  end;
  LSeq := TAsn1Sequence.GetInstance(AEncoded);
  if LSeq = nil then
    raise EArgumentCryptoLibException.CreateRes(@SCmsMalformedContent);
  Result := TCmsSignedData.Create(LSeq);
end;

class function TCmsSignedData.GetInstance(const AObj: IAsn1TaggedObject;
  AExplicitly: Boolean): ICmsSignedData;
begin
  Result := GetInstance(TAsn1Sequence.GetInstance(AObj, AExplicitly));
end;

class function TCmsSignedData.GetTagged(const ATaggedObject: IAsn1TaggedObject;
  ADeclaredExplicit: Boolean): ICmsSignedData;
begin
  Result := GetInstance(TAsn1Sequence.GetTagged(ATaggedObject, ADeclaredExplicit));
end;

class function TCmsSignedData.FromContentInfo(const AInfo: ICmsContentInfo): ICmsSignedData;
begin
  // Empty input and content-less ContentInfo (valid DER, optional [0] content) must be rejected
  // with a declared exception, not an access violation on the next field access.
  if AInfo = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SCmsAsn1ElementNil);
  Result := GetInstance(AInfo.Content);
  if Result = nil then
    raise EArgumentCryptoLibException.CreateRes(@SCmsMalformedContent);
end;

constructor TCmsSignedData.Create(const ASeq: IAsn1Sequence);
var
  LPos: Int32;
begin
  Inherited Create();
  LPos := 0;
  TAsn1Utilities.CheckSequenceSize(ASeq, 4, 6);
  FVersion := TAsn1Utilities.Read<IDerInteger>(ASeq, LPos, TDerInteger.GetInstance);
  FDigestAlgorithms := TAsn1Utilities.Read<IAsn1Set>(ASeq, LPos, TAsn1Set.GetInstance);
  FEncapContentInfo := TAsn1Utilities.Read<ICmsContentInfo>(ASeq, LPos, TCmsContentInfo.GetInstance);
  ReadOptionalTaggedSet(ASeq, LPos, 0, FCertificates, FCertsBer);
  ReadOptionalTaggedSet(ASeq, LPos, 1, FCrls, FCrlsBer);
  FSignerInfos := TAsn1Utilities.Read<IAsn1Set>(ASeq, LPos, TAsn1Set.GetInstance);
  TAsn1Utilities.RequireEndOfSequence(ASeq, LPos);

  FDigsBer := Supports(FDigestAlgorithms, IBerSet);
  FSigsBer := Supports(FSignerInfos, IBerSet);
end;

constructor TCmsSignedData.Create(const ADigestAlgorithms: IAsn1Set; const AEncapContentInfo: ICmsContentInfo;
  const ACertificates, ACrls, ASignerInfos: IAsn1Set);
begin
  Inherited Create();
  if ADigestAlgorithms = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SCmsDigestAlgorithmsNil);
  if AEncapContentInfo = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SCmsEncapContentInfoNil);
  if ASignerInfos = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SCmsSignerInfosNil);

  FDigestAlgorithms := ADigestAlgorithms;
  FEncapContentInfo := AEncapContentInfo;
  FCertificates := ACertificates;
  FCrls := ACrls;
  FSignerInfos := ASignerInfos;
  FVersion := CalculateVersionField(AEncapContentInfo.ContentType, ACertificates, ACrls, ASignerInfos);
  FCertsBer := Supports(FCertificates, IBerSet);
  FCrlsBer := Supports(FCrls, IBerSet);
  FDigsBer := Supports(FDigestAlgorithms, IBerSet);
  FSigsBer := Supports(FSignerInfos, IBerSet);
end;

function TCmsSignedData.GetVersion: IDerInteger;
begin
  Result := FVersion;
end;

function TCmsSignedData.GetDigestAlgorithms: IAsn1Set;
begin
  Result := FDigestAlgorithms;
end;

function TCmsSignedData.GetEncapContentInfo: ICmsContentInfo;
begin
  Result := FEncapContentInfo;
end;

function TCmsSignedData.GetCertificates: IAsn1Set;
begin
  Result := FCertificates;
end;

function TCmsSignedData.GetCrls: IAsn1Set;
begin
  Result := FCrls;
end;

function TCmsSignedData.GetSignerInfos: IAsn1Set;
begin
  Result := FSignerInfos;
end;

function TCmsSignedData.ToAsn1Object: IAsn1Object;
var
  LV: IAsn1EncodableVector;
begin
  LV := TAsn1EncodableVector.Create(6);
  LV.Add([FVersion, FDigestAlgorithms, FEncapContentInfo]);

  if FCertificates <> nil then
  begin
    if FCertsBer then
      LV.Add(TBerTaggedObject.Create(False, 0, FCertificates)
      as IBerTaggedObject)
    else
      LV.Add(TDerTaggedObject.Create(False, 0, FCertificates)
      as IDerTaggedObject);
  end;

  if FCrls <> nil then
  begin
    if FCrlsBer then
      LV.Add(TBerTaggedObject.Create(False, 1, FCrls) as IBerTaggedObject)
    else
      LV.Add(TDerTaggedObject.Create(False, 1, FCrls) as IDerTaggedObject);
  end;

  LV.Add(FSignerInfos);

  if (not FEncapContentInfo.IsDefiniteLength) or FCertsBer or FCrlsBer or FDigsBer or FSigsBer then
    Result := TBerSequence.Create(LV)
  else
    Result := TDLSequence.Create(LV);
end;

{ TCcmParameters }

class function TCcmParameters.ValidateIcvLen(const AIcvLen: IDerInteger): Int32;
var
  LValue: Int32;
begin
  if AIcvLen = nil then
    Exit(DefaultIcvLen);
  if not AIcvLen.TryGetIntValueExact(LValue) then
    raise EArgumentCryptoLibException.CreateRes(@SCmsIcvLenNotInt32);
  Result := ValidateIcvLenValue(LValue);
end;

class function TCcmParameters.ValidateIcvLenValue(AIcvLen: Int32): Int32;
begin
  if (AIcvLen < 4) or (AIcvLen > 16) or ((AIcvLen and 1) <> 0) then
    raise EArgumentCryptoLibException.CreateResFmt(@SCmsInvalidIcvLen, [AIcvLen]);
  Result := AIcvLen;
end;

class function TCcmParameters.GetInstance(AObj: TObject): ICcmParameters;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;
  if Supports(AObj, ICcmParameters, Result) then
    Exit;
  Result := TCcmParameters.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TCcmParameters.GetInstance(const AObj: IAsn1Convertible): ICcmParameters;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;
  if Supports(AObj, ICcmParameters, Result) then
    Exit;
  Result := TCcmParameters.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TCcmParameters.GetInstance(const AObj: IAsn1TaggedObject;
  AExplicitly: Boolean): ICcmParameters;
begin
  Result := TCcmParameters.Create(TAsn1Sequence.GetInstance(AObj, AExplicitly));
end;

class function TCcmParameters.GetTagged(const ATaggedObject: IAsn1TaggedObject;
  ADeclaredExplicit: Boolean): ICcmParameters;
begin
  Result := TCcmParameters.Create(TAsn1Sequence.GetTagged(ATaggedObject, ADeclaredExplicit));
end;

constructor TCcmParameters.Create(const ASeq: IAsn1Sequence);
var
  LPos: Int32;
  LIcvLen: IDerInteger;
begin
  inherited Create();
  LPos := 0;
  TAsn1Utilities.CheckSequenceSize(ASeq, 1, 2);
  FNonce := TAsn1Utilities.Read<IAsn1OctetString>(ASeq, LPos, TAsn1OctetString.GetInstance);
  LIcvLen := TAsn1Utilities.ReadOptional<IDerInteger>(ASeq, LPos, TDerInteger.GetOptional);
  TAsn1Utilities.RequireEndOfSequence(ASeq, LPos);

  FIcvLen := ValidateIcvLen(LIcvLen);
end;

constructor TCcmParameters.Create(const ANonce: TCryptoLibByteArray; AIcvLen: Int32);
begin
  inherited Create();
  FNonce := TDerOctetString.FromContents(ANonce);
  FIcvLen := ValidateIcvLenValue(AIcvLen);
end;

function TCcmParameters.GetNonce: TCryptoLibByteArray;
begin
  Result := TArrayUtilities.CopyOfRange<Byte>(FNonce.GetOctets(), 0,
    FNonce.GetOctetsLength());
end;

function TCcmParameters.GetIcvLen: Int32;
begin
  Result := FIcvLen;
end;

function TCcmParameters.ToAsn1Object: IAsn1Object;
begin
  if FIcvLen = DefaultIcvLen then
    Result := TDerSequence.Create([FNonce])
  else
    Result := TDerSequence.Create([FNonce, TDerInteger.ValueOf(FIcvLen)]);
end;

{ TGcmParameters }

class function TGcmParameters.ValidateIcvLen(const AIcvLen: IDerInteger): Int32;
var
  LValue: Int32;
begin
  if AIcvLen = nil then
    Exit(DefaultIcvLen);
  if not AIcvLen.TryGetIntValueExact(LValue) then
    raise EArgumentCryptoLibException.CreateRes(@SCmsIcvLenNotInt32);
  Result := ValidateIcvLenValue(LValue);
end;

class function TGcmParameters.ValidateIcvLenValue(AIcvLen: Int32): Int32;
begin
  if (AIcvLen < 12) or (AIcvLen > 16) then
    raise EArgumentCryptoLibException.CreateResFmt(@SCmsInvalidIcvLen, [AIcvLen]);
  Result := AIcvLen;
end;

class function TGcmParameters.GetInstance(AObj: TObject): IGcmParameters;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;
  if Supports(AObj, IGcmParameters, Result) then
    Exit;
  Result := TGcmParameters.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TGcmParameters.GetInstance(const AObj: IAsn1Convertible): IGcmParameters;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;
  if Supports(AObj, IGcmParameters, Result) then
    Exit;
  Result := TGcmParameters.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TGcmParameters.GetInstance(const AObj: IAsn1TaggedObject;
  AExplicitly: Boolean): IGcmParameters;
begin
  Result := TGcmParameters.Create(TAsn1Sequence.GetInstance(AObj, AExplicitly));
end;

class function TGcmParameters.GetTagged(const ATaggedObject: IAsn1TaggedObject;
  ADeclaredExplicit: Boolean): IGcmParameters;
begin
  Result := TGcmParameters.Create(TAsn1Sequence.GetTagged(ATaggedObject, ADeclaredExplicit));
end;

constructor TGcmParameters.Create(const ASeq: IAsn1Sequence);
var
  LPos: Int32;
  LIcvLen: IDerInteger;
begin
  inherited Create();
  LPos := 0;
  TAsn1Utilities.CheckSequenceSize(ASeq, 1, 2);
  FNonce := TAsn1Utilities.Read<IAsn1OctetString>(ASeq, LPos, TAsn1OctetString.GetInstance);
  LIcvLen := TAsn1Utilities.ReadOptional<IDerInteger>(ASeq, LPos, TDerInteger.GetOptional);
  TAsn1Utilities.RequireEndOfSequence(ASeq, LPos);

  FIcvLen := ValidateIcvLen(LIcvLen);
end;

constructor TGcmParameters.Create(const ANonce: TCryptoLibByteArray; AIcvLen: Int32);
begin
  inherited Create();
  FNonce := TDerOctetString.FromContents(ANonce);
  FIcvLen := ValidateIcvLenValue(AIcvLen);
end;

function TGcmParameters.GetNonce: TCryptoLibByteArray;
begin
  Result := TArrayUtilities.CopyOfRange<Byte>(FNonce.GetOctets(), 0,
    FNonce.GetOctetsLength());
end;

function TGcmParameters.GetIcvLen: Int32;
begin
  Result := FIcvLen;
end;

function TGcmParameters.ToAsn1Object: IAsn1Object;
begin
  if FIcvLen = DefaultIcvLen then
    Result := TDerSequence.Create([FNonce])
  else
    Result := TDerSequence.Create([FNonce, TDerInteger.ValueOf(FIcvLen)]);
end;

end.
