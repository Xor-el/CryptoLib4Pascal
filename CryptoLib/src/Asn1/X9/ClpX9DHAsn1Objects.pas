{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                           Author - Ugochukwu Mmaduekwe                          * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }

{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }

{ *                              Acknowledgements:                                  * }
{ *                                                                                 * }
{ *      Thanks to Sphere 10 Software (http://www.sphere10.com/) for sponsoring     * }
{ *                           development of this library                           * }

{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit ClpX9DHAsn1Objects;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpAsn1Objects,
  ClpIAsn1Objects,
  ClpAsn1Core,
  ClpIAsn1Core,
  ClpIX9DHAsn1Objects,
  ClpCryptoLibTypes,
  ClpAsn1Utilities;

resourcestring
  SInvalidParameters = 'Invalid parameters';
  SBadSequenceSize = 'Bad sequence size: %d';
  SUnexpectedElementsInSequence = 'Unexpected elements in sequence';
  SSeedNil = 'Seed Cannot be Nil';
  SPGenCounterNil = 'PGenCounter Cannot be Nil';
  SInvalidDHValidationParms = 'Invalid DHValidationParms: %s';
  SPNil = 'P Cannot be Nil';
  SGNil = 'G Cannot be Nil';
  SQNil = 'Q Cannot be Nil';
  SJNil = 'J Cannot be Nil';
  SInvalidDHDomainParameters = 'Invalid DHDomainParameters: %s';
  SYNil = 'Y Cannot be Nil';
  SAlgorithmNil = 'Algorithm cannot be Nil';
  SCounterNil = 'Counter cannot be Nil';
  SKeyInfoNil = 'KeyInfo cannot be Nil';
  SSuppPubInfoNil = 'SuppPubInfo cannot be Nil';

type
  /// <summary>
  /// The DHPublicKey object (X9.42).
  /// </summary>
  TDHPublicKey = class(TAsn1Encodable, IDHPublicKey)

  strict private
  var
    FY: IDerInteger;

  strict protected
    function GetY: IDerInteger;

  public
    class function GetInstance(AObj: TObject): IDHPublicKey; overload; static;
    class function GetInstance(const AObj: IAsn1Convertible): IDHPublicKey; overload; static;
    class function GetInstance(const AEncoded: TCryptoLibByteArray): IDHPublicKey; overload; static;
    class function GetInstance(const AObj: IAsn1TaggedObject;
      AExplicitly: Boolean): IDHPublicKey; overload; static;
    class function GetTagged(const ATaggedObject: IAsn1TaggedObject;
      ADeclaredExplicit: Boolean): IDHPublicKey; static;

    constructor Create(const AY: IDerInteger);

    function ToAsn1Object: IAsn1Object; override;

    property Y: IDerInteger read GetY;

  end;

  /// <summary>
  /// The DHValidationParms object.
  /// </summary>
  TDHValidationParms = class(TAsn1Encodable, IDHValidationParms)

  strict private
  var
    FSeed: IDerBitString;
    FPGenCounter: IDerInteger;

  strict protected
    function GetSeed: IDerBitString;
    function GetPGenCounter: IDerInteger;

    constructor Create(const ASeq: IAsn1Sequence); overload;

  public
    /// <summary>
    /// Parse a DHValidationParms from an object.
    /// </summary>
    class function GetInstance(AObj: TObject): IDHValidationParms; overload; static;
    /// <summary>
    /// Get instance from ASN.1 convertible.
    /// </summary>
    class function GetInstance(const AObj: IAsn1Convertible): IDHValidationParms; overload; static;
    /// <summary>
    /// Parse a DHValidationParms from DER-encoded bytes.
    /// </summary>
    class function GetInstance(const AEncoded: TCryptoLibByteArray): IDHValidationParms; overload; static;
    /// <summary>
    /// Parse a DHValidationParms from a tagged object.
    /// </summary>
    class function GetInstance(const AObj: IAsn1TaggedObject;
      AExplicitly: Boolean): IDHValidationParms; overload; static;
    /// <summary>
    /// Get optional DHValidationParms.
    /// </summary>
    class function GetOptional(const AElement: IAsn1Encodable): IDHValidationParms; static;
    /// <summary>
    /// Get tagged DHValidationParms.
    /// </summary>
    class function GetTagged(const ATaggedObject: IAsn1TaggedObject;
      ADeclaredExplicit: Boolean): IDHValidationParms; static;

    constructor Create(const ASeed: IDerBitString;
      const APGenCounter: IDerInteger); overload;

    function ToAsn1Object: IAsn1Object; override;

    property Seed: IDerBitString read GetSeed;
    property PGenCounter: IDerInteger read GetPGenCounter;

  end;

  /// <summary>
  /// The DHDomainParameters object.
  /// </summary>
  TDHDomainParameters = class(TAsn1Encodable, IDHDomainParameters)

  strict private
  var
    FP, FG, FQ, FJ: IDerInteger;
    FValidationParms: IDHValidationParms;

    class function ReadOptionalSubgroupFactor(AElement: IAsn1Encodable): IDerInteger; static;
    class function ReadOptionalValidationParms(AElement: IAsn1Encodable): IDHValidationParms; static;

  strict protected
    function GetP: IDerInteger;
    function GetG: IDerInteger;
    function GetQ: IDerInteger;
    function GetJ: IDerInteger;
    function GetValidationParms: IDHValidationParms;

    constructor Create(const ASeq: IAsn1Sequence); overload;

  public
    /// <summary>
    /// Parse a DHDomainParameters from an object.
    /// </summary>
    class function GetInstance(AObj: TObject): IDHDomainParameters; overload; static;
    /// <summary>
    /// Get instance from ASN.1 convertible.
    /// </summary>
    class function GetInstance(const AObj: IAsn1Convertible): IDHDomainParameters; overload; static;
    /// <summary>
    /// Parse a DHDomainParameters from DER-encoded bytes.
    /// </summary>
    class function GetInstance(const AEncoded: TCryptoLibByteArray): IDHDomainParameters; overload; static;
    /// <summary>
    /// Parse a DHDomainParameters from a tagged object.
    /// </summary>
    class function GetInstance(const AObj: IAsn1TaggedObject;
      AExplicitly: Boolean): IDHDomainParameters; overload; static;
    /// <summary>
    /// Get tagged DHDomainParameters.
    /// </summary>
    class function GetTagged(const ATaggedObject: IAsn1TaggedObject;
      ADeclaredExplicit: Boolean): IDHDomainParameters; static;

    constructor Create(const AP, AG, AQ, AJ: IDerInteger;
      const AValidationParms: IDHValidationParms); overload;

    function ToAsn1Object: IAsn1Object; override;

    property P: IDerInteger read GetP;
    property G: IDerInteger read GetG;
    property Q: IDerInteger read GetQ;
    property J: IDerInteger read GetJ;
    property ValidationParms: IDHValidationParms read GetValidationParms;

  end;

  /// <summary>
  /// ASN.1 KeySpecificInfo structure (RFC 2631 / X9.42).
  /// </summary>
  TKeySpecificInfo = class(TAsn1Encodable, IKeySpecificInfo)

  strict private
  var
    FAlgorithm: IDerObjectIdentifier;
    FCounter: IAsn1OctetString;

  strict protected
    function GetAlgorithm: IDerObjectIdentifier;
    function GetCounter: IAsn1OctetString;

    constructor Create(const ASeq: IAsn1Sequence); overload;

  public
    class function GetInstance(AObj: TObject): IKeySpecificInfo; overload; static;
    class function GetInstance(const AObj: IAsn1Convertible): IKeySpecificInfo; overload; static;
    class function GetInstance(const AEncoded: TCryptoLibByteArray): IKeySpecificInfo; overload; static;
    class function GetInstance(const AObj: IAsn1TaggedObject;
      AExplicitly: Boolean): IKeySpecificInfo; overload; static;
    class function GetTagged(const ATaggedObject: IAsn1TaggedObject;
      ADeclaredExplicit: Boolean): IKeySpecificInfo; static;

    constructor Create(const AAlgorithm: IDerObjectIdentifier;
      const ACounter: IAsn1OctetString); overload;

    function ToAsn1Object: IAsn1Object; override;

    property Algorithm: IDerObjectIdentifier read GetAlgorithm;
    property Counter: IAsn1OctetString read GetCounter;

  end;

  /// <summary>
  /// ASN.1 OtherInfo structure (RFC 2631 / X9.42).
  /// </summary>
  TOtherInfo = class(TAsn1Encodable, IOtherInfo)

  strict private
  var
    FKeyInfo: IKeySpecificInfo;
    FPartyAInfo: IAsn1OctetString;
    FSuppPubInfo: IAsn1OctetString;

    class function GetTaggedAsn1OctetString(ATagged: IAsn1TaggedObject; AState: Boolean): IAsn1OctetString; static;

  strict protected
    function GetKeyInfo: IKeySpecificInfo;
    function GetPartyAInfo: IAsn1OctetString;
    function GetSuppPubInfo: IAsn1OctetString;

    constructor Create(const ASeq: IAsn1Sequence); overload;

  public
    class function GetInstance(AObj: TObject): IOtherInfo; overload; static;
    class function GetInstance(const AObj: IAsn1Convertible): IOtherInfo; overload; static;
    class function GetInstance(const AEncoded: TCryptoLibByteArray): IOtherInfo; overload; static;
    class function GetInstance(const AObj: IAsn1TaggedObject;
      AExplicitly: Boolean): IOtherInfo; overload; static;
    class function GetTagged(const ATaggedObject: IAsn1TaggedObject;
      ADeclaredExplicit: Boolean): IOtherInfo; static;

    constructor Create(const AKeyInfo: IKeySpecificInfo;
      const APartyAInfo: IAsn1OctetString; const ASuppPubInfo: IAsn1OctetString); overload;

    function ToAsn1Object: IAsn1Object; override;

    property KeyInfo: IKeySpecificInfo read GetKeyInfo;
    property PartyAInfo: IAsn1OctetString read GetPartyAInfo;
    property SuppPubInfo: IAsn1OctetString read GetSuppPubInfo;

  end;

implementation

{ TDHPublicKey }

class function TDHPublicKey.GetInstance(AObj: TObject): IDHPublicKey;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IDHPublicKey, Result) then
    Exit;

  Result := TDHPublicKey.Create(TDerInteger.GetInstance(AObj));
end;

class function TDHPublicKey.GetInstance(const AObj: IAsn1Convertible): IDHPublicKey;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IDHPublicKey, Result) then
    Exit;

  Result := TDHPublicKey.Create(TDerInteger.GetInstance(AObj));
end;

class function TDHPublicKey.GetInstance(const AEncoded: TCryptoLibByteArray): IDHPublicKey;
begin
  Result := TDHPublicKey.Create(TDerInteger.GetInstance(AEncoded));
end;

class function TDHPublicKey.GetInstance(const AObj: IAsn1TaggedObject;
  AExplicitly: Boolean): IDHPublicKey;
begin
  Result := TDHPublicKey.Create(TDerInteger.GetInstance(AObj, AExplicitly));
end;

class function TDHPublicKey.GetTagged(const ATaggedObject: IAsn1TaggedObject;
  ADeclaredExplicit: Boolean): IDHPublicKey;
begin
  Result := TDHPublicKey.Create(TDerInteger.GetTagged(ATaggedObject, ADeclaredExplicit));
end;

constructor TDHPublicKey.Create(const AY: IDerInteger);
begin
  inherited Create();
  if AY = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SYNil);
  FY := AY;
end;

function TDHPublicKey.GetY: IDerInteger;
begin
  Result := FY;
end;

function TDHPublicKey.ToAsn1Object: IAsn1Object;
begin
  Result := FY;
end;

{ TDHValidationParms }

class function TDHValidationParms.GetInstance(AObj: TObject): IDHValidationParms;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IDHValidationParms, Result) then
    Exit;

  Result := TDHValidationParms.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TDHValidationParms.GetInstance(const AObj: IAsn1Convertible): IDHValidationParms;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IDHValidationParms, Result) then
    Exit;

  Result := TDHValidationParms.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TDHValidationParms.GetInstance(const AEncoded: TCryptoLibByteArray): IDHValidationParms;
begin
  Result := TDHValidationParms.Create(TAsn1Sequence.GetInstance(AEncoded));
end;

class function TDHValidationParms.GetInstance(const AObj: IAsn1TaggedObject;
  AExplicitly: Boolean): IDHValidationParms;
begin
  Result := TDHValidationParms.Create(TAsn1Sequence.GetInstance(AObj, AExplicitly));
end;

class function TDHValidationParms.GetOptional(const AElement: IAsn1Encodable): IDHValidationParms;
var
  LSequence: IAsn1Sequence;
begin
  if AElement = nil then
    raise EArgumentNilCryptoLibException.Create('element');

  if Supports(AElement, IDHValidationParms, Result) then
    Exit;

  LSequence := TAsn1Sequence.GetOptional(AElement);
  if LSequence <> nil then
    Result := TDHValidationParms.Create(LSequence)
  else
    Result := nil;
end;

class function TDHValidationParms.GetTagged(const ATaggedObject: IAsn1TaggedObject;
  ADeclaredExplicit: Boolean): IDHValidationParms;
begin
  Result := TDHValidationParms.Create(TAsn1Sequence.GetTagged(ATaggedObject, ADeclaredExplicit));
end;

constructor TDHValidationParms.Create(const ASeq: IAsn1Sequence);
begin
  inherited Create();
  if ASeq.Count <> 2 then
    raise EArgumentCryptoLibException.CreateResFmt(@SBadSequenceSize, [ASeq.Count]);

  FSeed := TDerBitString.GetInstance(ASeq[0]);
  FPGenCounter := TDerInteger.GetInstance(ASeq[1]);
end;

constructor TDHValidationParms.Create(const ASeed: IDerBitString;
  const APGenCounter: IDerInteger);
begin
  inherited Create();

  if ASeed = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SSeedNil);

  if APGenCounter = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SPGenCounterNil);

  FSeed := ASeed;
  FPGenCounter := APGenCounter;
end;

function TDHValidationParms.GetSeed: IDerBitString;
begin
  Result := FSeed;
end;

function TDHValidationParms.GetPGenCounter: IDerInteger;
begin
  Result := FPGenCounter;
end;

function TDHValidationParms.ToAsn1Object: IAsn1Object;
begin
  Result := TDerSequence.Create([FSeed, FPGenCounter]);
end;

{ TDHDomainParameters }

class function TDHDomainParameters.GetInstance(AObj: TObject): IDHDomainParameters;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IDHDomainParameters, Result) then
    Exit;

  Result := TDHDomainParameters.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TDHDomainParameters.GetInstance(const AObj: IAsn1Convertible): IDHDomainParameters;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IDHDomainParameters, Result) then
    Exit;

  Result := TDHDomainParameters.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TDHDomainParameters.GetInstance(const AEncoded: TCryptoLibByteArray): IDHDomainParameters;
begin
  Result := TDHDomainParameters.Create(TAsn1Sequence.GetInstance(AEncoded));
end;

class function TDHDomainParameters.GetInstance(const AObj: IAsn1TaggedObject;
  AExplicitly: Boolean): IDHDomainParameters;
begin
  Result := TDHDomainParameters.Create(TAsn1Sequence.GetInstance(AObj, AExplicitly));
end;

class function TDHDomainParameters.GetTagged(const ATaggedObject: IAsn1TaggedObject;
  ADeclaredExplicit: Boolean): IDHDomainParameters;
begin
  Result := TDHDomainParameters.Create(TAsn1Sequence.GetTagged(ATaggedObject, ADeclaredExplicit));
end;

class function TDHDomainParameters.ReadOptionalSubgroupFactor(AElement: IAsn1Encodable): IDerInteger;
begin
  Result := TDerInteger.GetOptional(AElement);
end;

class function TDHDomainParameters.ReadOptionalValidationParms(AElement: IAsn1Encodable): IDHValidationParms;
begin
  Result := TDHValidationParms.GetOptional(AElement);
end;

constructor TDHDomainParameters.Create(const ASeq: IAsn1Sequence);
var
  LCount, LPos: Int32;
begin
  inherited Create();
  LCount := ASeq.Count;
  LPos := 0;
  if (LCount < 3) or (LCount > 5) then
    raise EArgumentCryptoLibException.CreateResFmt(@SBadSequenceSize, [LCount]);

  FP := TDerInteger.GetInstance(ASeq[LPos]);
  System.Inc(LPos);

  FG := TDerInteger.GetInstance(ASeq[LPos]);
  System.Inc(LPos);

  FQ := TDerInteger.GetInstance(ASeq[LPos]);
  System.Inc(LPos);

  FJ := TAsn1Utilities.ReadOptional<IDerInteger>(ASeq, LPos, ReadOptionalSubgroupFactor);

  FValidationParms := TAsn1Utilities.ReadOptional<IDHValidationParms>(ASeq, LPos, ReadOptionalValidationParms);

  if LPos <> LCount then
    raise EArgumentCryptoLibException.CreateRes(@SUnexpectedElementsInSequence);
end;

constructor TDHDomainParameters.Create(const AP, AG, AQ, AJ: IDerInteger;
  const AValidationParms: IDHValidationParms);
begin
  inherited Create();

  if AP = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SPNil);

  if AG = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SGNil);

  if AQ = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SQNil);

  FP := AP;
  FG := AG;
  FQ := AQ;
  FJ := AJ;
  FValidationParms := AValidationParms;
end;

function TDHDomainParameters.GetP: IDerInteger;
begin
  Result := FP;
end;

function TDHDomainParameters.GetG: IDerInteger;
begin
  Result := FG;
end;

function TDHDomainParameters.GetQ: IDerInteger;
begin
  Result := FQ;
end;

function TDHDomainParameters.GetJ: IDerInteger;
begin
  Result := FJ;
end;

function TDHDomainParameters.GetValidationParms: IDHValidationParms;
begin
  Result := FValidationParms;
end;

function TDHDomainParameters.ToAsn1Object: IAsn1Object;
var
  LV: IAsn1EncodableVector;
begin
  LV := TAsn1EncodableVector.Create([FP, FG, FQ]);
  if FJ <> nil then
    LV.Add([FJ]);
  if FValidationParms <> nil then
    LV.Add([FValidationParms]);
  Result := TDerSequence.Create(LV);
end;

{ TKeySpecificInfo }

class function TKeySpecificInfo.GetInstance(AObj: TObject): IKeySpecificInfo;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IKeySpecificInfo, Result) then
    Exit;

  Result := TKeySpecificInfo.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TKeySpecificInfo.GetInstance(const AObj: IAsn1Convertible): IKeySpecificInfo;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IKeySpecificInfo, Result) then
    Exit;

  Result := TKeySpecificInfo.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TKeySpecificInfo.GetInstance(const AEncoded: TCryptoLibByteArray): IKeySpecificInfo;
begin
  Result := TKeySpecificInfo.Create(TAsn1Sequence.GetInstance(AEncoded));
end;

class function TKeySpecificInfo.GetInstance(const AObj: IAsn1TaggedObject;
  AExplicitly: Boolean): IKeySpecificInfo;
begin
  Result := TKeySpecificInfo.Create(TAsn1Sequence.GetInstance(AObj, AExplicitly));
end;

class function TKeySpecificInfo.GetTagged(const ATaggedObject: IAsn1TaggedObject;
  ADeclaredExplicit: Boolean): IKeySpecificInfo;
begin
  Result := TKeySpecificInfo.Create(TAsn1Sequence.GetTagged(ATaggedObject, ADeclaredExplicit));
end;

constructor TKeySpecificInfo.Create(const ASeq: IAsn1Sequence);
begin
  inherited Create();
  if ASeq.Count <> 2 then
    raise EArgumentCryptoLibException.CreateResFmt(@SBadSequenceSize, [ASeq.Count]);

  FAlgorithm := TDerObjectIdentifier.GetInstance(ASeq[0]);
  FCounter := TAsn1OctetString.GetInstance(ASeq[1]);
end;

constructor TKeySpecificInfo.Create(const AAlgorithm: IDerObjectIdentifier;
  const ACounter: IAsn1OctetString);
begin
  inherited Create();

  if AAlgorithm = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SAlgorithmNil);

  if ACounter = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SCounterNil);

  FAlgorithm := AAlgorithm;
  FCounter := ACounter;
end;

function TKeySpecificInfo.GetAlgorithm: IDerObjectIdentifier;
begin
  Result := FAlgorithm;
end;

function TKeySpecificInfo.GetCounter: IAsn1OctetString;
begin
  Result := FCounter;
end;

function TKeySpecificInfo.ToAsn1Object: IAsn1Object;
begin
  Result := TDerSequence.Create(FAlgorithm, FCounter);
end;

{ TOtherInfo }

class function TOtherInfo.GetInstance(AObj: TObject): IOtherInfo;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IOtherInfo, Result) then
    Exit;

  Result := TOtherInfo.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TOtherInfo.GetInstance(const AObj: IAsn1Convertible): IOtherInfo;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IOtherInfo, Result) then
    Exit;

  Result := TOtherInfo.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TOtherInfo.GetInstance(const AEncoded: TCryptoLibByteArray): IOtherInfo;
begin
  Result := TOtherInfo.Create(TAsn1Sequence.GetInstance(AEncoded));
end;

class function TOtherInfo.GetInstance(const AObj: IAsn1TaggedObject;
  AExplicitly: Boolean): IOtherInfo;
begin
  Result := TOtherInfo.Create(TAsn1Sequence.GetInstance(AObj, AExplicitly));
end;

class function TOtherInfo.GetTagged(const ATaggedObject: IAsn1TaggedObject;
  ADeclaredExplicit: Boolean): IOtherInfo;
begin
  Result := TOtherInfo.Create(TAsn1Sequence.GetTagged(ATaggedObject, ADeclaredExplicit));
end;

class function TOtherInfo.GetTaggedAsn1OctetString(ATagged: IAsn1TaggedObject; AState: Boolean): IAsn1OctetString;
begin
  Result := TAsn1OctetString.GetTagged(ATagged, AState);
end;

constructor TOtherInfo.Create(const ASeq: IAsn1Sequence);
var
  LCount, LPos: Int32;
begin
  inherited Create();
  LCount := ASeq.Count;
  LPos := 0;
  if (LCount < 2) or (LCount > 3) then
    raise EArgumentCryptoLibException.CreateResFmt(@SBadSequenceSize, [LCount]);

  FKeyInfo := TKeySpecificInfo.GetInstance(ASeq[LPos]);
  System.Inc(LPos);

  FPartyAInfo := TAsn1Utilities.ReadOptionalContextTagged<Boolean, IAsn1OctetString>(ASeq, LPos, 0, True,
    GetTaggedAsn1OctetString);

  FSuppPubInfo := TAsn1Utilities.ReadContextTagged<Boolean, IAsn1OctetString>(ASeq, LPos, 2, True,
    GetTaggedAsn1OctetString);

  if LPos <> LCount then
    raise EArgumentCryptoLibException.CreateRes(@SUnexpectedElementsInSequence);
end;

constructor TOtherInfo.Create(const AKeyInfo: IKeySpecificInfo;
  const APartyAInfo: IAsn1OctetString; const ASuppPubInfo: IAsn1OctetString);
begin
  inherited Create();

  if AKeyInfo = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SKeyInfoNil);

  if ASuppPubInfo = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SSuppPubInfoNil);

  FKeyInfo := AKeyInfo;
  FPartyAInfo := APartyAInfo;
  FSuppPubInfo := ASuppPubInfo;
end;

function TOtherInfo.GetKeyInfo: IKeySpecificInfo;
begin
  Result := FKeyInfo;
end;

function TOtherInfo.GetPartyAInfo: IAsn1OctetString;
begin
  Result := FPartyAInfo;
end;

function TOtherInfo.GetSuppPubInfo: IAsn1OctetString;
begin
  Result := FSuppPubInfo;
end;

function TOtherInfo.ToAsn1Object: IAsn1Object;
var
  LV: IAsn1EncodableVector;
begin
  LV := TAsn1EncodableVector.Create(3);
  LV.Add(FKeyInfo);
  LV.AddOptionalTagged(True, 0, FPartyAInfo);
  LV.AddTagged(True, 2, FSuppPubInfo);
  Result := TDerSequence.Create(LV);
end;

end.
