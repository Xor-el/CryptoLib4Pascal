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
  ClpCryptoLibTypes;

resourcestring
  SCmsBadSequenceSize = 'Bad sequence size: %d';
  SCmsBadIssuerAndSerialNumberSize = 'Bad sequence size: %d';
  SCmsBadSignerInfoSequenceSize = 'Bad sequence size: %d';
  SCmsUnexpectedElementsInSequence = 'Unexpected elements in sequence';

type
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
    class function ReadOptionalTaggedSet(const ASequence: IAsn1Sequence;
      var ASequencePosition: Int32; ATagNo: Int32; out AIsBer: Boolean): IAsn1Set; static;
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
begin
  if AEncoded = nil then
  begin
    Result := nil;
    Exit;
  end;

  Result := TCmsContentInfo.Create(TAsn1Sequence.GetInstance(AEncoded));
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

constructor TCmsContentInfo.Create(const ASeq: IAsn1Sequence);
var
  LCount: Int32;
  LTagged: IAsn1TaggedObject;
begin
  Inherited Create();
  LCount := ASeq.Count;
  if (LCount < 1) or (LCount > 2) then
    raise EArgumentCryptoLibException.CreateResFmt(@SCmsBadSequenceSize, [LCount]);

  FContentType := TDerObjectIdentifier.GetInstance(ASeq[0]);

  if ASeq.Count > 1 then
  begin
    LTagged := TAsn1TaggedObject.GetInstance(ASeq[1], TAsn1Tags.ContextSpecific, 0);
    FContent := LTagged.GetExplicitBaseObject();
  end
  else
    FContent := nil;

  FIsDefiniteLength := IsDLSequence(ASeq);
end;

constructor TCmsContentInfo.Create(const AContentType: IDerObjectIdentifier;
  const AContent: IAsn1Encodable);
begin
  Inherited Create();
  if AContentType = nil then
    raise EArgumentNilCryptoLibException.Create('contentType');
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
    raise EArgumentNilCryptoLibException.Create('element');
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
  LCount: Int32;
begin
  Inherited Create();
  LCount := ASeq.Count;
  if LCount <> 2 then
    raise EArgumentCryptoLibException.CreateResFmt(@SCmsBadIssuerAndSerialNumberSize, [LCount]);
  FIssuer := TX509Name.GetInstance(ASeq[0]);
  FSerialNumber := TDerInteger.GetInstance(ASeq[1]);
end;

constructor TCmsIssuerAndSerialNumber.Create(const AIssuer: IX509Name; const ASerialNumber: IDerInteger);
begin
  Inherited Create();
  if AIssuer = nil then
    raise EArgumentNilCryptoLibException.Create('issuer');
  if ASerialNumber = nil then
    raise EArgumentNilCryptoLibException.Create('serialNumber');
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

class function TCmsSignerIdentifier.GetInstance(AObj: TObject): ICmsSignerIdentifier;
begin
  Result := TAsn1Utilities.GetInstanceChoice<ICmsSignerIdentifier>(AObj,
    function(AElement: IAsn1Encodable): ICmsSignerIdentifier
    begin
      Result := GetOptional(AElement);
    end);
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
  Result := TAsn1Utilities.GetInstanceChoice<ICmsSignerIdentifier>(LObj,
    function(AElement: IAsn1Encodable): ICmsSignerIdentifier
    begin
      Result := GetOptional(AElement);
    end);
end;

class function TCmsSignerIdentifier.GetInstance(const AObj: IAsn1TaggedObject;
  ADeclaredExplicit: Boolean): ICmsSignerIdentifier;
begin
  Result := TAsn1Utilities.GetInstanceChoice<ICmsSignerIdentifier>(AObj, ADeclaredExplicit,
    function(AElement: IAsn1Encodable): ICmsSignerIdentifier
    begin
      Result := GetOptional(AElement);
    end);
end;

class function TCmsSignerIdentifier.GetOptional(const AElement: IAsn1Encodable): ICmsSignerIdentifier;
var
  LIssuerAndSerial: ICmsIssuerAndSerialNumber;
  LTagged: IAsn1TaggedObject;
begin
  if AElement = nil then
    raise EArgumentNilCryptoLibException.Create('element');
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
  Result := TAsn1Utilities.GetTaggedChoice<ICmsSignerIdentifier>(ATaggedObject, ADeclaredExplicit,
    function(AElement: IAsn1Encodable): ICmsSignerIdentifier
    begin
      Result := GetInstance(AElement);
    end);
end;

constructor TCmsSignerIdentifier.Create(const AIssuerAndSerialNumber: ICmsIssuerAndSerialNumber);
begin
  Inherited Create();
  if AIssuerAndSerialNumber = nil then
    raise EArgumentNilCryptoLibException.Create('issuerAndSerialNumber');
  FId := AIssuerAndSerialNumber;
end;

constructor TCmsSignerIdentifier.Create(const ASubjectKeyIdentifier: IAsn1OctetString);
begin
  Inherited Create();
  if ASubjectKeyIdentifier = nil then
    raise EArgumentNilCryptoLibException.Create('subjectKeyIdentifier');
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
    function(ATagged: IAsn1TaggedObject; AState: Boolean): IAsn1Encodable
    begin
      Result := TAsn1OctetString.GetTagged(ATagged, AState);
    end) then
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
  LCount, LPos: Int32;
begin
  Inherited Create();
  LCount := ASeq.Count;
  if (LCount < 5) or (LCount > 7) then
    raise EArgumentCryptoLibException.CreateResFmt(@SCmsBadSignerInfoSequenceSize, [LCount]);
  LPos := 0;
  FVersion := TDerInteger.GetInstance(ASeq[LPos]);
  System.Inc(LPos);
  FSignerID := TCmsSignerIdentifier.GetInstance(ASeq[LPos]);
  System.Inc(LPos);
  FDigestAlgorithm := TAlgorithmIdentifier.GetInstance(ASeq[LPos]);
  System.Inc(LPos);
  FSignedAttrs := TAsn1Utilities.ReadOptionalContextTagged<Boolean, IAsn1Set>(ASeq, LPos, 0, False,
    function(ATagged: IAsn1TaggedObject; AState: Boolean): IAsn1Set
    begin
      Result := TAsn1Set.GetTagged(ATagged, AState);
    end);
  FSignatureAlgorithm := TAlgorithmIdentifier.GetInstance(ASeq[LPos]);
  System.Inc(LPos);
  FSignature := TAsn1OctetString.GetInstance(ASeq[LPos]);
  System.Inc(LPos);
  FUnsignedAttrs := TAsn1Utilities.ReadOptionalContextTagged<Boolean, IAsn1Set>(ASeq, LPos, 1, False,
    function(ATagged: IAsn1TaggedObject; AState: Boolean): IAsn1Set
    begin
      Result := TAsn1Set.GetTagged(ATagged, AState);
    end);
  if LPos <> LCount then
    raise EArgumentCryptoLibException.Create(SCmsUnexpectedElementsInSequence);
end;

constructor TCmsSignerInfo.Create(const ASignerID: ICmsSignerIdentifier;
  const ADigestAlgorithm: IAlgorithmIdentifier; const ASignedAttrs: IAsn1Set;
  const ASignatureAlgorithm: IAlgorithmIdentifier; const ASignature: IAsn1OctetString;
  const AUnsignedAttrs: IAsn1Set);
begin
  Inherited Create();
  if ASignerID = nil then
    raise EArgumentNilCryptoLibException.Create('signerID');
  if ADigestAlgorithm = nil then
    raise EArgumentNilCryptoLibException.Create('digestAlgorithm');
  if ASignatureAlgorithm = nil then
    raise EArgumentNilCryptoLibException.Create('signatureAlgorithm');
  if ASignature = nil then
    raise EArgumentNilCryptoLibException.Create('signature');
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

class function TCmsSignedData.ReadOptionalTaggedSet(const ASequence: IAsn1Sequence;
  var ASequencePosition: Int32; ATagNo: Int32; out AIsBer: Boolean): IAsn1Set;
var
  LElement: IAsn1Encodable;
  LTagged: IAsn1TaggedObject;
begin
  Result := nil;
  AIsBer := False;
  if ASequencePosition >= ASequence.Count then
    Exit;
  LElement := ASequence.Items[ASequencePosition];
  if not Supports(LElement, IAsn1TaggedObject, LTagged) then
    Exit;
  if not LTagged.HasContextTag(ATagNo) then
    Exit;
  Result := TAsn1Set.GetTagged(LTagged, False);
  AIsBer := Supports(LElement, IBerTaggedObject);
  System.Inc(ASequencePosition);
end;

class function TCmsSignedData.CalculateVersionField(const AContentOid: IDerObjectIdentifier;
  const ACerts, ACrls, ASignerInfs: IAsn1Set): IDerInteger;
var
  I: Int32;
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
    for I := 0 to ACrls.Count - 1 do
    begin
      LElement := ACrls.Items[I];
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
    for I := 0 to ACerts.Count - 1 do
    begin
      LElement := ACerts.Items[I];
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
  I: Int32;
  LSignerInfo: ICmsSignerInfo;
  LElement: IAsn1Encodable;
begin
  if ASignerInfs = nil then
  begin
    Result := False;
    Exit;
  end;
  for I := 0 to ASignerInfs.Count - 1 do
  begin
    LElement := ASignerInfs.Items[I];
    LSignerInfo := TCmsSignerInfo.GetInstance(LElement);
    if (LSignerInfo <> nil) and LSignerInfo.Version.HasValue(3) then
      Exit(True);
  end;
  Result := False;
end;

class function TCmsSignedData.GetInstance(AObj: TObject): ICmsSignedData;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;
  if Supports(AObj, ICmsSignedData, Result) then
    Exit;
  Result := TCmsSignedData.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TCmsSignedData.GetInstance(const AObj: IAsn1Convertible): ICmsSignedData;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;
  if Supports(AObj, ICmsSignedData, Result) then
    Exit;
  Result := TCmsSignedData.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TCmsSignedData.GetInstance(const AEncoded: TCryptoLibByteArray): ICmsSignedData;
begin
  if AEncoded = nil then
  begin
    Result := nil;
    Exit;
  end;
  Result := TCmsSignedData.Create(TAsn1Sequence.GetInstance(AEncoded));
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

constructor TCmsSignedData.Create(const ASeq: IAsn1Sequence);
var
  LCount, LPos: Int32;
begin
  Inherited Create();
  LCount := ASeq.Count;
  if (LCount < 4) or (LCount > 6) then
    raise EArgumentCryptoLibException.CreateResFmt(@SCmsBadSequenceSize, [LCount]);

  LPos := 0;
  FVersion := TDerInteger.GetInstance(ASeq[LPos]);
  System.Inc(LPos);
  FDigestAlgorithms := TAsn1Set.GetInstance(ASeq[LPos]);
  System.Inc(LPos);
  FEncapContentInfo := TCmsContentInfo.GetInstance(ASeq[LPos]);
  System.Inc(LPos);
  FCertificates := ReadOptionalTaggedSet(ASeq, LPos, 0, FCertsBer);
  FCrls := ReadOptionalTaggedSet(ASeq, LPos, 1, FCrlsBer);
  FSignerInfos := TAsn1Set.GetInstance(ASeq[LPos]);
  System.Inc(LPos);

  if LPos <> LCount then
    raise EArgumentCryptoLibException.Create(SCmsUnexpectedElementsInSequence);

  FDigsBer := Supports(FDigestAlgorithms, IBerSet);
  FSigsBer := Supports(FSignerInfos, IBerSet);
end;

constructor TCmsSignedData.Create(const ADigestAlgorithms: IAsn1Set; const AEncapContentInfo: ICmsContentInfo;
  const ACertificates, ACrls, ASignerInfos: IAsn1Set);
begin
  Inherited Create();
  if ADigestAlgorithms = nil then
    raise EArgumentNilCryptoLibException.Create('digestAlgorithms');
  if AEncapContentInfo = nil then
    raise EArgumentNilCryptoLibException.Create('contentInfo');
  if ASignerInfos = nil then
    raise EArgumentNilCryptoLibException.Create('signerInfos');

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

end.
