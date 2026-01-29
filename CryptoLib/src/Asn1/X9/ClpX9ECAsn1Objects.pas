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

unit ClpX9ECAsn1Objects;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  SyncObjs,
  ClpAsn1Objects,
  ClpIAsn1Objects,
  ClpAsn1Core,
  ClpIAsn1Core,
  ClpIX9ECAsn1Objects,
  ClpBigInteger,
  ClpIECC,
  ClpECAlgorithms,
  ClpX9ObjectIdentifiers,
  ClpX9IntegerConverter,
  ClpCryptoLibTypes,
  ClpAsn1Utilities,
  ClpIFiniteField,
  ClpIPolynomialExtensionField,
  ClpECC;

resourcestring
  SBadSequenceSize = 'Bad sequence size: %d';
  SUnexpectedElementsInSequence = 'Unexpected elements in sequence';
  SBadVersion = 'bad version in X9ECParameters';
  SFieldIDNil = 'fieldID';
  SSeqNil = 'seq';
  SCurveNil = 'curve';
  SFieldElementNil = 'f';
  SCurveNotImplemented = 'This type of ECCurve is not implemented';
  SCharacteristicTwoFieldNotImplemented = 'This CharacteristicTwoField representation is not implemented';
  SUnsupportedCurveType = '''curve'' is of an unsupported type';
  SOnlyTrinomialAndPentanomial = 'Only trinomial and pentomial curves are supported';
  SInconsistentKValues = 'inconsistent k values';
  SEncodingNil = 'encoding';
  SOctetStringNil = 's';

type
  /// <summary>
  /// ASN.1 def for Elliptic-Curve Field ID structure. See X9.62 for further details.
  /// </summary>
  TX9FieldID = class(TAsn1Encodable, IX9FieldID)

  strict private
  var
    FFieldType: IDerObjectIdentifier;
    FParameters: IAsn1Object;

  strict protected
    function GetFieldType: IDerObjectIdentifier;
    function GetParameters: IAsn1Object;

    constructor Create(const ASeq: IAsn1Sequence); overload;

  public
    /// <summary>
    /// Parse a X9FieldID from an object.
    /// </summary>
    class function GetInstance(AObj: TObject): IX9FieldID; overload; static;
    /// <summary>
    /// Get instance from ASN.1 convertible.
    /// </summary>
    class function GetInstance(const AObj: IAsn1Convertible): IX9FieldID; overload; static;
    /// <summary>
    /// Parse a X9FieldID from DER-encoded bytes.
    /// </summary>
    class function GetInstance(const AEncoded: TCryptoLibByteArray): IX9FieldID; overload; static;
    /// <summary>
    /// Parse a X9FieldID from a tagged object.
    /// </summary>
    class function GetInstance(const AObj: IAsn1TaggedObject;
      AExplicitly: Boolean): IX9FieldID; overload; static;
    /// <summary>
    /// Get optional X9FieldID.
    /// </summary>
    class function GetOptional(const AElement: IAsn1Encodable): IX9FieldID; static;
    /// <summary>
    /// Get tagged X9FieldID.
    /// </summary>
    class function GetTagged(const ATaggedObject: IAsn1TaggedObject;
      ADeclaredExplicit: Boolean): IX9FieldID; static;

    /// <summary>
    /// Constructor for elliptic curves over prime fields.
    /// </summary>
    constructor Create(const APrimeP: TBigInteger); overload;
    /// <summary>
    /// Constructor for elliptic curves over binary fields (trinomial).
    /// </summary>
    constructor Create(AM, AK1: Int32); overload;
    /// <summary>
    /// Constructor for elliptic curves over binary fields (pentanomial).
    /// </summary>
    constructor Create(AM, AK1, AK2, AK3: Int32); overload;

    function ToAsn1Object: IAsn1Object; override;

    property FieldType: IDerObjectIdentifier read GetFieldType;
    property Parameters: IAsn1Object read GetParameters;

  end;

  /// <summary>
  /// Class for processing an ECFieldElement as a DER object.
  /// </summary>
  TX9FieldElement = class(TAsn1Encodable, IX9FieldElement)

  strict private
  var
    FF: IECFieldElement;

  strict protected
    function GetValue: IECFieldElement;

  public
    constructor Create(const AF: IECFieldElement);

    function ToAsn1Object: IAsn1Object; override;

    property Value: IECFieldElement read GetValue;

  end;

  /// <summary>
  /// ASN.1 def for Elliptic-Curve Curve structure. See X9.62 for further details.
  /// </summary>
  TX9Curve = class(TAsn1Encodable, IX9Curve)

  strict private
  var
    FCurve: IECCurve;
    FSeed: IDerBitString;
    FFieldType: IDerObjectIdentifier;

  strict protected
    function GetCurve: IECCurve;
    function GetSeed: IDerBitString;
    function GetSeedBytes: TCryptoLibByteArray;

  public
    constructor Create(const ACurve: IECCurve); overload;
    constructor Create(const ACurve: IECCurve; const ASeed: TCryptoLibByteArray); overload;
    constructor Create(const ACurve: IECCurve; const ASeed: IDerBitString); overload;
    constructor Create(const AFieldID: IX9FieldID; const AOrder, ACofactor: TBigInteger;
      const ASeq: IAsn1Sequence); overload;

    function ToAsn1Object: IAsn1Object; override;

    property Curve: IECCurve read GetCurve;
    property Seed: IDerBitString read GetSeed;

  end;

  /// <summary>
  /// class for describing an ECPoint as a Der object.
  /// </summary>
  TX9ECPoint = class(TAsn1Encodable, IX9ECPoint)

  strict private
  var
    FEncoding: IAsn1OctetString;
    FC: IECCurve;
    FP: IECPoint;
    FLock: TCriticalSection;

  strict protected
    function GetPoint: IECPoint;
    function GetPointEncoding: IAsn1OctetString;
    function GetIsPointCompressed: Boolean;

    function CreatePoint: IECPoint;

  public
    constructor Create(const AP: IECPoint; ACompressed: Boolean); overload;
    constructor Create(const AC: IECCurve; const AEncoding: TCryptoLibByteArray); overload;
    constructor Create(const AC: IECCurve; const &AS: IAsn1OctetString); overload;

    destructor Destroy; override;

    function ToAsn1Object: IAsn1Object; override;

    property Point: IECPoint read GetPoint;
    property PointEncoding: IAsn1OctetString read GetPointEncoding;
    property IsPointCompressed: Boolean read GetIsPointCompressed;

  end;

  /// <summary>
  /// ASN.1 definition for Elliptic-Curve ECParameters structure. See X9.62 for further details.
  /// </summary>
  TX9ECParameters = class(TAsn1Encodable, IX9ECParameters)

  strict private
  var
    FFieldID: IX9FieldID;
    FCurve: IX9Curve;
    FG: IX9ECPoint;
    FN: TBigInteger;
    FH: TBigInteger;

  strict protected
    function GetCurve: IECCurve;
    function GetG: IECPoint;
    function GetN: TBigInteger;
    function GetH: TBigInteger;
    function GetCurveEntry: IX9Curve;
    function GetFieldIDEntry: IX9FieldID;
    function GetBaseEntry: IX9ECPoint;

    constructor Create(const ASeq: IAsn1Sequence); overload; deprecated 'Use GetInstance instead';

  public
    /// <summary>
    /// Parse a X9ECParameters from an object.
    /// </summary>
    class function GetInstance(AObj: TObject): IX9ECParameters; overload; static;
    /// <summary>
    /// Get instance from ASN.1 convertible.
    /// </summary>
    class function GetInstance(const AObj: IAsn1Convertible): IX9ECParameters; overload; static;
    /// <summary>
    /// Parse a X9ECParameters from DER-encoded bytes.
    /// </summary>
    class function GetInstance(const AEncoded: TCryptoLibByteArray): IX9ECParameters; overload; static;
    /// <summary>
    /// Parse a X9ECParameters from a tagged object.
    /// </summary>
    class function GetInstance(const AObj: IAsn1TaggedObject; AExplicitly: Boolean): IX9ECParameters; overload; static;
    /// <summary>
    /// Get optional X9ECParameters.
    /// </summary>
    class function GetOptional(const AElement: IAsn1Encodable): IX9ECParameters; static;
    /// <summary>
    /// Get tagged X9ECParameters.
    /// </summary>
    class function GetTagged(const ATaggedObject: IAsn1TaggedObject; ADeclaredExplicit: Boolean): IX9ECParameters; static;

    constructor Create(const ACurve: IECCurve; const AG: IX9ECPoint;
      const AN: TBigInteger); overload;
    constructor Create(const ACurve: IECCurve; const AG: IX9ECPoint;
      const AN, AH: TBigInteger); overload;
    constructor Create(const ACurve: IECCurve; const AG: IX9ECPoint;
      const AN, AH: TBigInteger; const ASeed: TCryptoLibByteArray); overload;
    constructor Create(const ACurve: IECCurve; const AG: IX9ECPoint;
      const AN, AH: TBigInteger; const ASeed: IDerBitString); overload;

    function GetSeed: TCryptoLibByteArray;

    function ToAsn1Object: IAsn1Object; override;

    property Curve: IECCurve read GetCurve;
    property G: IECPoint read GetG;
    property N: TBigInteger read GetN;
    property H: TBigInteger read GetH;
    property CurveEntry: IX9Curve read GetCurveEntry;
    property FieldIDEntry: IX9FieldID read GetFieldIDEntry;
    property BaseEntry: IX9ECPoint read GetBaseEntry;

  end;

implementation

uses
  ClpFiniteFields;

{ TX9FieldID }

class function TX9FieldID.GetInstance(AObj: TObject): IX9FieldID;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IX9FieldID, Result) then
    Exit;

  Result := TX9FieldID.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TX9FieldID.GetInstance(const AObj: IAsn1Convertible): IX9FieldID;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IX9FieldID, Result) then
    Exit;

  Result := TX9FieldID.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TX9FieldID.GetInstance(const AEncoded: TCryptoLibByteArray): IX9FieldID;
begin
  Result := TX9FieldID.Create(TAsn1Sequence.GetInstance(AEncoded));
end;

class function TX9FieldID.GetInstance(const AObj: IAsn1TaggedObject; AExplicitly: Boolean): IX9FieldID;
begin
  Result := TX9FieldID.Create(TAsn1Sequence.GetInstance(AObj, AExplicitly));
end;

class function TX9FieldID.GetOptional(const AElement: IAsn1Encodable): IX9FieldID;
var
  LSequence: IAsn1Sequence;
begin
  if AElement = nil then
    raise EArgumentNilCryptoLibException.Create('element');

  if Supports(AElement, IX9FieldID, Result) then
    Exit;

  LSequence := TAsn1Sequence.GetOptional(AElement);
  if LSequence <> nil then
    Result := TX9FieldID.Create(LSequence)
  else
    Result := nil;
end;

class function TX9FieldID.GetTagged(const ATaggedObject: IAsn1TaggedObject;
  ADeclaredExplicit: Boolean): IX9FieldID;
begin
  Result := TX9FieldID.Create(TAsn1Sequence.GetTagged(ATaggedObject, ADeclaredExplicit));
end;

constructor TX9FieldID.Create(const ASeq: IAsn1Sequence);
var
  LCount: Int32;
begin
  inherited Create();
  LCount := ASeq.Count;
  if LCount <> 2 then
    raise EArgumentCryptoLibException.CreateResFmt(@SBadSequenceSize, [LCount]);

  FFieldType := TDerObjectIdentifier.GetInstance(ASeq[0]);
  FParameters := ASeq[1].ToAsn1Object();
end;

constructor TX9FieldID.Create(const APrimeP: TBigInteger);
begin
  inherited Create();
  FFieldType := TX9ObjectIdentifiers.PrimeField;
  FParameters := TDerInteger.Create(APrimeP);
end;

constructor TX9FieldID.Create(AM, AK1: Int32);
begin
  Create(AM, AK1, 0, 0);
end;

constructor TX9FieldID.Create(AM, AK1, AK2, AK3: Int32);
var
  LFieldIdParams: IAsn1EncodableVector;
begin
  inherited Create();
  FFieldType := TX9ObjectIdentifiers.CharacteristicTwoField;

  LFieldIdParams := TAsn1EncodableVector.Create(3);
  LFieldIdParams.Add([TDerInteger.ValueOf(AM)]);

  if AK2 = 0 then
  begin
    if AK3 <> 0 then
      raise EArgumentCryptoLibException.CreateRes(@SInconsistentKValues);

    LFieldIdParams.Add([TX9ObjectIdentifiers.TPBasis, TDerInteger.ValueOf(AK1)]);
  end
  else
  begin
    if (AK2 <= AK1) or (AK3 <= AK2) then
      raise EArgumentCryptoLibException.CreateRes(@SInconsistentKValues);

    LFieldIdParams.Add([TX9ObjectIdentifiers.PPBasis, TDerSequence.Create([
      TDerInteger.ValueOf(AK1), TDerInteger.ValueOf(AK2), TDerInteger.ValueOf(AK3)])]);
  end;

  FParameters := TDerSequence.Create(LFieldIdParams);
end;

function TX9FieldID.GetFieldType: IDerObjectIdentifier;
begin
  Result := FFieldType;
end;

function TX9FieldID.GetParameters: IAsn1Object;
begin
  Result := FParameters;
end;

function TX9FieldID.ToAsn1Object: IAsn1Object;
begin
  Result := TDerSequence.Create([FFieldType, FParameters]);
end;

{ TX9FieldElement }

constructor TX9FieldElement.Create(const AF: IECFieldElement);
begin
  inherited Create();
  if AF = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SFieldElementNil);
  FF := AF;
end;

function TX9FieldElement.GetValue: IECFieldElement;
begin
  Result := FF;
end;

function TX9FieldElement.ToAsn1Object: IAsn1Object;
var
  LByteCount: Int32;
  LPaddedBigInteger: TCryptoLibByteArray;
begin
  LByteCount := TX9IntegerConverter.GetByteLength(FF);
  LPaddedBigInteger := TX9IntegerConverter.IntegerToBytes(FF.ToBigInteger(), LByteCount);
  Result := TDerOctetString.Create(LPaddedBigInteger);
end;

{ TX9Curve }

constructor TX9Curve.Create(const ACurve: IECCurve);
begin
  Create(ACurve, nil);
end;

constructor TX9Curve.Create(const ACurve: IECCurve; const ASeed: TCryptoLibByteArray);
begin
  Create(ACurve, TDerBitString.FromContentsOptional(ASeed));
end;

constructor TX9Curve.Create(const ACurve: IECCurve; const ASeed: IDerBitString);
var
  LField: IFiniteField;
begin
  inherited Create();
  if ACurve = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SCurveNil);
  FCurve := ACurve;
  FSeed := ASeed;

  LField := ACurve.Field;
  if TECAlgorithms.IsFpField(LField) then
  begin
    FFieldType := TX9ObjectIdentifiers.PrimeField;
  end
  else if TECAlgorithms.IsF2mField(LField) then
  begin
    FFieldType := TX9ObjectIdentifiers.CharacteristicTwoField;
  end
  else
  begin
    raise EArgumentCryptoLibException.CreateRes(@SCurveNotImplemented);
  end;
end;

constructor TX9Curve.Create(const AFieldID: IX9FieldID; const AOrder, ACofactor: TBigInteger;
  const ASeq: IAsn1Sequence);
var
  LP: TBigInteger;
  LA, LB: TBigInteger;
  LParameters: IAsn1Sequence;
  LM: Int32;
  LRepresentation: IDerObjectIdentifier;
  LK1, LK2, LK3: Int32;
  LPentanomial: IAsn1Sequence;
  LPolynomialField: IPolynomialExtensionField;
  LExponents: TCryptoLibInt32Array;
begin
  inherited Create();
  if AFieldID = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SFieldIDNil);
  if ASeq = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SSeqNil);

  FFieldType := AFieldID.FieldType;

  if TX9ObjectIdentifiers.PrimeField.Equals(FFieldType) then
  begin
    LP := TDerInteger.GetInstance(AFieldID.Parameters).Value;
    LA := TBigInteger.Create(1, TAsn1OctetString.GetInstance(ASeq[0]).GetOctets());
    LB := TBigInteger.Create(1, TAsn1OctetString.GetInstance(ASeq[1]).GetOctets());
    FCurve := TFpCurve.Create(LP, LA, LB, AOrder, ACofactor);
  end
  else if TX9ObjectIdentifiers.CharacteristicTwoField.Equals(FFieldType) then
  begin
    // Characteristic two field
    LParameters := TAsn1Sequence.GetInstance(AFieldID.Parameters);
    LM := TDerInteger.GetInstance(LParameters[0]).IntValueExact;
    LRepresentation := TDerObjectIdentifier.GetInstance(LParameters[1]);

    if TX9ObjectIdentifiers.TPBasis.Equals(LRepresentation) then
    begin
      // Trinomial basis representation
      LK1 := TDerInteger.GetInstance(LParameters[2]).IntValueExact;
      LK2 := 0;
      LK3 := 0;
    end
    else if TX9ObjectIdentifiers.PPBasis.Equals(LRepresentation) then
    begin
      // Pentanomial basis representation
      LPentanomial := TAsn1Sequence.GetInstance(LParameters[2]);
      LK1 := TDerInteger.GetInstance(LPentanomial[0]).IntValueExact;
      LK2 := TDerInteger.GetInstance(LPentanomial[1]).IntValueExact;
      LK3 := TDerInteger.GetInstance(LPentanomial[2]).IntValueExact;
    end
    else
    begin
      raise EArgumentCryptoLibException.CreateRes(@SCharacteristicTwoFieldNotImplemented);
    end;

    LA := TBigInteger.Create(1, TAsn1OctetString.GetInstance(ASeq[0]).GetOctets());
    LB := TBigInteger.Create(1, TAsn1OctetString.GetInstance(ASeq[1]).GetOctets());
    FCurve := TF2mCurve.Create(LM, LK1, LK2, LK3, LA, LB, AOrder, ACofactor);
  end
  else
  begin
    raise EArgumentCryptoLibException.CreateRes(@SCurveNotImplemented);
  end;

  if ASeq.Count = 3 then
  begin
    FSeed := TDerBitString.GetInstance(ASeq[2]);
  end;
end;

function TX9Curve.GetCurve: IECCurve;
begin
  Result := FCurve;
end;

function TX9Curve.GetSeed: IDerBitString;
begin
  Result := FSeed;
end;

function TX9Curve.GetSeedBytes: TCryptoLibByteArray;
begin
  Result := nil;
  if FSeed <> nil then
    Result := FSeed.GetBytes();
end;

function TX9Curve.ToAsn1Object: IAsn1Object;
var
  LA, LB: TX9FieldElement;
begin
  LA := TX9FieldElement.Create(FCurve.A);
  LB := TX9FieldElement.Create(FCurve.B);

  if FSeed = nil then
    Result := TDerSequence.Create([LA, LB])
  else
    Result := TDerSequence.Create([LA, LB, FSeed]);
end;

{ TX9ECPoint }

constructor TX9ECPoint.Create(const AP: IECPoint; ACompressed: Boolean);
begin
  inherited Create();
  FC := AP.Curve;
  FP := AP.Normalize();
  FEncoding := TDerOctetString.Create(AP.GetEncoded(ACompressed));
  FLock := TCriticalSection.Create;
end;

constructor TX9ECPoint.Create(const AC: IECCurve; const AEncoding: TCryptoLibByteArray);
begin
  Create(AC, TDerOctetString.FromContents(AEncoding));
end;

constructor TX9ECPoint.Create(const AC: IECCurve; const &AS: IAsn1OctetString);
begin
  inherited Create();
  if AC = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SCurveNil);
  if &AS = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SOctetStringNil);
  FC := AC;
  FP := nil;
  FEncoding := &AS;
  FLock := TCriticalSection.Create;
end;

destructor TX9ECPoint.Destroy;
begin
  FLock.Free;
  inherited Destroy;
end;

function TX9ECPoint.CreatePoint: IECPoint;
begin
  Result := FC.DecodePoint(FEncoding.GetOctets());
end;

function TX9ECPoint.GetPoint: IECPoint;
begin
  FLock.Acquire;
  try
    if FP = nil then
    begin
      FP := CreatePoint();
    end;
    Result := FP;
  finally
    FLock.Release;
  end;
end;

function TX9ECPoint.GetPointEncoding: IAsn1OctetString;
begin
  Result := FEncoding;
end;

function TX9ECPoint.GetIsPointCompressed: Boolean;
var
  LOctets: TCryptoLibByteArray;
begin
  LOctets := FEncoding.GetOctets();
  Result := (LOctets <> nil) and (System.Length(LOctets) > 0) and
    ((LOctets[0] = 2) or (LOctets[0] = 3));
end;

function TX9ECPoint.ToAsn1Object: IAsn1Object;
begin
  Result := FEncoding;
end;

{ TX9ECParameters }

class function TX9ECParameters.GetInstance(AObj: TObject): IX9ECParameters;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IX9ECParameters, Result) then
    Exit;

  Result := TX9ECParameters.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TX9ECParameters.GetInstance(const AObj: IAsn1Convertible): IX9ECParameters;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IX9ECParameters, Result) then
    Exit;

  Result := TX9ECParameters.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TX9ECParameters.GetInstance(const AEncoded: TCryptoLibByteArray): IX9ECParameters;
begin
  Result := TX9ECParameters.Create(TAsn1Sequence.GetInstance(AEncoded));
end;

class function TX9ECParameters.GetInstance(const AObj: IAsn1TaggedObject;
  AExplicitly: Boolean): IX9ECParameters;
begin
  Result := TX9ECParameters.Create(TAsn1Sequence.GetInstance(AObj, AExplicitly));
end;

class function TX9ECParameters.GetOptional(const AElement: IAsn1Encodable): IX9ECParameters;
var
  LSequence: IAsn1Sequence;
begin
  if AElement = nil then
    raise EArgumentNilCryptoLibException.Create('element');

  if Supports(AElement, IX9ECParameters, Result) then
    Exit;

  LSequence := TAsn1Sequence.GetOptional(AElement);
  if LSequence <> nil then
    Result := TX9ECParameters.Create(LSequence)
  else
    Result := nil;
end;

class function TX9ECParameters.GetTagged(const ATaggedObject: IAsn1TaggedObject;
  ADeclaredExplicit: Boolean): IX9ECParameters;
begin
  Result := TX9ECParameters.Create(TAsn1Sequence.GetTagged(ATaggedObject, ADeclaredExplicit));
end;

constructor TX9ECParameters.Create(const ASeq: IAsn1Sequence);
var
  LCount, LPos: Int32;
  LVersion: IDerInteger;
  LX9CurveSequence: IAsn1Sequence;
  LP: IAsn1Encodable;
  LX9ECPoint: IX9ECPoint;
begin
  inherited Create();
  LCount := ASeq.Count;
  LPos := 0;
  if (LCount < 5) or (LCount > 6) then
    raise EArgumentCryptoLibException.CreateResFmt(@SBadSequenceSize, [LCount]);

  LVersion := TDerInteger.GetInstance(ASeq[LPos] as TAsn1Encodable);
  System.Inc(LPos);
  FFieldID := TX9FieldID.GetInstance(ASeq[LPos] as TAsn1Encodable);
  System.Inc(LPos);
  LX9CurveSequence := TAsn1Sequence.GetInstance(ASeq[LPos]);
  System.Inc(LPos);
  LP := ASeq[LPos] as TAsn1Encodable;
  System.Inc(LPos);
  FN := (TDerInteger.GetInstance(ASeq[LPos] as TAsn1Encodable) as IDerInteger).Value;
  System.Inc(LPos);
  FH := TAsn1Utilities.ReadOptional<TBigInteger>(ASeq, LPos, function(AElement: IAsn1Encodable): TBigInteger
    var
      LDerInt: IDerInteger;
    begin
      LDerInt := TDerInteger.GetOptional(AElement);
      if LDerInt <> nil then
        Result := LDerInt.Value
      else
        Result := Default(TBigInteger);
    end);

  if LPos <> LCount then
    raise EArgumentCryptoLibException.CreateRes(@SUnexpectedElementsInSequence);

  if not LVersion.HasValue(1) then
    raise EArgumentCryptoLibException.CreateRes(@SBadVersion);

  FCurve := TX9Curve.Create(FFieldID, FN, FH, LX9CurveSequence);

  if Supports(LP, IX9ECPoint, LX9ECPoint) then
  begin
    FG := LX9ECPoint;
  end
  else
  begin
    FG := TX9ECPoint.Create(FCurve.Curve, TAsn1OctetString.GetInstance(LP));
  end;
end;

constructor TX9ECParameters.Create(const ACurve: IECCurve; const AG: IX9ECPoint;
  const AN: TBigInteger);
begin
  Create(ACurve, AG, AN, TBigInteger.GetDefault, nil);
end;

constructor TX9ECParameters.Create(const ACurve: IECCurve; const AG: IX9ECPoint;
  const AN, AH: TBigInteger);
begin
  Create(ACurve, AG, AN, AH, nil);
end;

constructor TX9ECParameters.Create(const ACurve: IECCurve; const AG: IX9ECPoint;
  const AN, AH: TBigInteger; const ASeed: TCryptoLibByteArray);
begin
  Create(ACurve, AG, AN, AH, TDerBitString.FromContentsOptional(ASeed));
end;

constructor TX9ECParameters.Create(const ACurve: IECCurve; const AG: IX9ECPoint;
  const AN, AH: TBigInteger; const ASeed: IDerBitString);
var
  LField: IFiniteField;
  LF2mField: IPolynomialExtensionField;
  LExponents: TCryptoLibInt32Array;
begin
  inherited Create();
  FCurve := TX9Curve.Create(ACurve, ASeed);
  FG := AG;
  FN := AN;
  FH := AH;

  LField := ACurve.Field;
  if TECAlgorithms.IsFpField(LField) then
  begin
    FFieldID := TX9FieldID.Create(LField.Characteristic);
  end
  else if TECAlgorithms.IsF2mField(LField) then
  begin
    if not Supports(LField, IPolynomialExtensionField, LF2mField) then
      raise EArgumentCryptoLibException.CreateRes(@SUnsupportedCurveType);

    LExponents := LF2mField.MinimalPolynomial.GetExponentsPresent();
    if System.Length(LExponents) = 3 then
    begin
      FFieldID := TX9FieldID.Create(LExponents[2], LExponents[1]);
    end
    else if System.Length(LExponents) = 5 then
    begin
      FFieldID := TX9FieldID.Create(LExponents[4], LExponents[1], LExponents[2], LExponents[3]);
    end
    else
    begin
      raise EArgumentCryptoLibException.CreateRes(@SOnlyTrinomialAndPentanomial);
    end;
  end
  else
  begin
    raise EArgumentCryptoLibException.CreateRes(@SUnsupportedCurveType);
  end;
end;

function TX9ECParameters.GetCurve: IECCurve;
begin
  Result := FCurve.Curve;
end;

function TX9ECParameters.GetG: IECPoint;
begin
  Result := FG.Point;
end;

function TX9ECParameters.GetN: TBigInteger;
begin
  Result := FN;
end;

function TX9ECParameters.GetH: TBigInteger;
begin
  Result := FH;
end;

function TX9ECParameters.GetCurveEntry: IX9Curve;
begin
  Result := FCurve;
end;

function TX9ECParameters.GetFieldIDEntry: IX9FieldID;
begin
  Result := FFieldID;
end;

function TX9ECParameters.GetBaseEntry: IX9ECPoint;
begin
  Result := FG;
end;

function TX9ECParameters.GetSeed: TCryptoLibByteArray;
begin
  Result := FCurve.GetSeedBytes();
end;

function TX9ECParameters.ToAsn1Object: IAsn1Object;
var
  LV: IAsn1EncodableVector;
begin
  LV := TAsn1EncodableVector.Create(6);
  LV.Add([TDerInteger.One, FFieldID, FCurve, FG, TDerInteger.Create(FN) as IDerInteger]);

  if FH.IsInitialized then
  begin
    LV.Add([TDerInteger.Create(FH) as IDerInteger]);
  end;

  Result := TDerSequence.Create(LV);
end;

end.
