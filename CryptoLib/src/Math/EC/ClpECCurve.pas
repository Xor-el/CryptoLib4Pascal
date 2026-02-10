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

unit ClpECCurve;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  SyncObjs,
  Generics.Collections,
  ClpBigInteger,
  ClpIFiniteField,
  ClpIECCommon,
  ClpLongArray,
  ClpECAlgorithms,
  ClpFiniteFields,
  ClpPrimes,
  ClpSecureRandom,
  ClpECFieldElement,
  ClpIECFieldElement,
  ClpIPreCompCallback,
  ClpIPreCompInfo,
  ClpISecureRandom,
  ClpBitOperations,
  ClpBigIntegers,
  ClpECLookupTables,
  ClpECCurveConstants,
  ClpCryptoLibTypes;

resourcestring
  SMustBeNonNilAndOnThisCurve = 'must be non-null and on this curve';
  SInvalidRangeSpecified = 'invalid range specified';
  SEntriesMustBeNullOrOnThisCurve = 'entries must be null or on this curve';
  SNoDefaultMultiplier = 'No default multiplier set for curve';
  SIncorrectLengthForInfinityEncoding = 'Incorrect length for infinity encoding';
  SIncorrectLengthForCompressedEncoding = 'Incorrect length for compressed encoding';
  SIncorrectLengthForUncompressedEncoding = 'Incorrect length for uncompressed encoding';
  SIncorrectLengthForHybridEncoding = 'Incorrect length for hybrid encoding';
  SInvalidPointEncoding = 'Invalid point encoding %d';
  SInvalidInfinityEncoding = 'Invalid infinity encoding';
  SPointCompressionNotSupported = 'Point compression not supported';
  SInvalidPointCoordinates = 'Invalid point coordinates';
  SInconsistentYCoordinateInHybridEncoding = 'Inconsistent Y coordinate in hybrid encoding';
  SUnsupportedCoordinateSystem = 'unsupported coordinate system';
  SImplementationReturnedCurrentCurve = 'implementation returned current curve';

type
  TECCurve = class abstract(TInterfacedObject, IECCurve)
  strict private
type
  TDefaultLookupTable = class sealed(TAbstractECLookupTable, IECLookupTable)
  strict private
    FOuter: IECCurve;
    FTable: TCryptoLibByteArray;
    FSize: Int32;
    function CreatePoint(const AX, AY: TCryptoLibByteArray): IECPoint;
  public
    constructor Create(const AOuter: IECCurve; const ATable: TCryptoLibByteArray; ASize: Int32);
    function GetSize: Int32; override;
    function Lookup(AIndex: Int32): IECPoint; override;
    function LookupVar(AIndex: Int32): IECPoint; override;
  end;

  strict protected
    FField: IFiniteField;
    FA, FB: IECFieldElement;
    FOrder, FCofactor: TBigInteger;
    FCoord: Int32;
    FMultiplier: IECMultiplier;
    FEndomorphism: IECEndomorphism;
    FPreCompTable: TDictionary<String, IPreCompInfo>;
    FLock: TCriticalSection;
    FTableLock: TCriticalSection;

    function CreateDefaultMultiplier(): IECMultiplier; virtual;
    procedure CheckPoint(const APoint: IECPoint); virtual;
    procedure CheckPoints(const APoints: TCryptoLibGenericArray<IECPoint>); overload; virtual;
    procedure CheckPoints(const APoints: TCryptoLibGenericArray<IECPoint>;
      AOff, ALen: Int32); overload; virtual;
    function DecompressPoint(AYTilde: Int32; const AX1: TBigInteger): IECPoint; virtual;
    function CloneCurve: IECCurve; virtual; abstract;
  public
type
  TECCurveConfig = class sealed(TInterfacedObject, IECCurveConfig)
  strict private
    FOuter: IECCurve;
    FCoord: Int32;
    FEndomorphism: IECEndomorphism;
    FMultiplier: IECMultiplier;
  public
    constructor Create(const AOuter: IECCurve; ACoord: Int32;
      const AEndomorphism: IECEndomorphism; const AMultiplier: IECMultiplier);
    function SetCoordinateSystem(ACoord: Int32): IECCurveConfig;
    function SetEndomorphism(const AEndomorphism: IECEndomorphism): IECCurveConfig;
    function SetMultiplier(const AMultiplier: IECMultiplier): IECCurveConfig;
    function CreateCurve: IECCurve;
  end;

    constructor Create(const AField: IFiniteField);
    destructor Destroy; override;

    class function GetAllCoordinateSystems: TCryptoLibInt32Array; static;

    function GetFieldSize: Int32; virtual; abstract;
    function GetFieldElementEncodingLength: Int32; virtual;
    function GetInfinity: IECPoint; virtual; abstract;
    function GetOrder: TBigInteger; virtual;
    function GetCofactor: TBigInteger; virtual;
    function GetCoordinateSystem: Int32; virtual;
    function GetA: IECFieldElement; virtual;
    function GetB: IECFieldElement; virtual;
    function GetMultiplier: IECMultiplier; virtual;
    function GetEndomorphism: IECEndomorphism; virtual;

    function FromBigInteger(const AX: TBigInteger): IECFieldElement; virtual; abstract;
    function IsValidFieldElement(const AX: TBigInteger): Boolean; virtual; abstract;
    function RandomFieldElement(const ARandom: ISecureRandom): IECFieldElement; virtual; abstract;
    function CreatePoint(const AX, AY: TBigInteger): IECPoint; virtual;
    function CreateRawPoint(const AX: IECFieldElement; const AY: IECFieldElement): IECPoint; overload; virtual; abstract;
    function CreateRawPoint(const AX: IECFieldElement; const AY: IECFieldElement; const AZs: TCryptoLibGenericArray<IECFieldElement>): IECPoint; overload; virtual; abstract;
    function RandomFieldElementMult(const ARandom: ISecureRandom): IECFieldElement; virtual; abstract;

    function GetAffinePointEncodingLength(ACompressed: Boolean): Int32; virtual;
    function CreateCacheSafeLookupTable(const APoints: TCryptoLibGenericArray<IECPoint>;
      AOff, ALen: Int32): IECLookupTable; virtual;
    function GetPreCompInfo(const APoint: IECPoint; const AName: String): IPreCompInfo; virtual;
    function Precompute(const APoint: IECPoint; const AName: String;
      const ACallback: IPreCompCallback): IPreCompInfo; overload; virtual;
    function Precompute(const AName: String; const ACallback: IPreCompCallback): IPreCompInfo; overload; virtual;

    function SupportsCoordinateSystem(ACoord: Int32): Boolean; virtual;
    procedure NormalizeAll(const APoints: TCryptoLibGenericArray<IECPoint>); overload; virtual;
    procedure NormalizeAll(const APoints: TCryptoLibGenericArray<IECPoint>;
      AOff, ALen: Int32; const AIso: IECFieldElement); overload; virtual;
    function ImportPoint(const AP: IECPoint): IECPoint; virtual;
    function GetField: IFiniteField; virtual;
    function DecodePoint(const AEncoded: TCryptoLibByteArray): IECPoint; virtual;
    function ValidatePoint(const AX, AY: TBigInteger): IECPoint; virtual;
    function Configure: IECCurveConfig; virtual;
    procedure ApplyConfig(ACoord: Int32; const AEndomorphism: IECEndomorphism;
      const AMultiplier: IECMultiplier); virtual;
    function Equals(const AOther: IECCurve): Boolean; reintroduce; virtual;
    function GetHashCode: {$IFDEF DELPHI}Int32; {$ELSE}PtrInt; {$ENDIF DELPHI} override;
  end;

  TAbstractFpCurve = class abstract(TECCurve, IECCurve, IAbstractFpCurve)
  strict private
    class var
      FKnownPrimes: TDictionary<TBigInteger, Boolean>;
      FLockPrimes: TCriticalSection;
      FMaxFieldSize: Int32;
      FCertainty: Int32;
    class procedure ImplCheckQ(const AQ: TBigInteger); static;
    class function ImplIsPrime(const AQ: TBigInteger): Boolean; static;
    class function ImplGetIterations(ABits, ACertainty: Int32): Int32; static;
  strict protected
    class function ImplRandomFieldElement(const ARandom: ISecureRandom;
      const AP: TBigInteger): TBigInteger; static;
    class function ImplRandomFieldElementMult(const ARandom: ISecureRandom;
      const AP: TBigInteger): TBigInteger; static;
  public
    class constructor Create;
    class destructor Destroy;
    constructor Create(const AQ: TBigInteger); overload;
    constructor Create(const AQ: TBigInteger; AIsInternal: Boolean); overload;
    function IsValidFieldElement(const AX: TBigInteger): Boolean; override;
    function RandomFieldElement(const ARandom: ISecureRandom): IECFieldElement; override;
    function RandomFieldElementMult(const ARandom: ISecureRandom): IECFieldElement; override;
    function DecompressPoint(AYTilde: Int32; const AX1: TBigInteger): IECPoint; override;
    class property MaxFieldSize: Int32 read FMaxFieldSize write FMaxFieldSize;
    class property Certainty: Int32 read FCertainty write FCertainty;
  end;

  TFpCurve = class sealed(TAbstractFpCurve, IECCurve, IFpCurve)
  strict protected
    FQ, FR: TBigInteger;
    FInfinity: IECPoint;
  public
    const FP_DEFAULT_COORDS = TECCurveConstants.COORD_JACOBIAN_MODIFIED;
    constructor Create(const AQ, AA, AB, AOrder, ACofactor: TBigInteger); overload;
    constructor Create(const AQ, AA, AB, AOrder, ACofactor: TBigInteger;
      AIsInternal: Boolean); overload;
    constructor Create(const AQ, AR: TBigInteger; const AA, AB: IECFieldElement;
      const AOrder, ACofactor: TBigInteger); overload;
    function CloneCurve: IECCurve; override;
    function GetFieldSize: Int32; override;
    function ImportPoint(const AP: IECPoint): IECPoint; override;
    function GetInfinity: IECPoint; override;
    function FromBigInteger(const AX: TBigInteger): IECFieldElement; override;
    function CreateRawPoint(const AX: IECFieldElement; const AY: IECFieldElement): IECPoint; override;
    function CreateRawPoint(const AX: IECFieldElement; const AY: IECFieldElement; const AZs: TCryptoLibGenericArray<IECFieldElement>): IECPoint; override;
    function SupportsCoordinateSystem(ACoord: Int32): Boolean; override;
    function GetQ: TBigInteger;
    property Q: TBigInteger read GetQ;
  end;

  TAbstractF2mCurve = class abstract(TECCurve, IECCurve, IAbstractF2mCurve)
  strict private
    class var FMaxFieldSize: Int32;
  strict protected
    class function ImplRandomFieldElementMult(const ARandom: ISecureRandom; AM: Int32): TBigInteger; static;
    function GetIsKoblitz: Boolean; virtual;
  public
    class constructor Create;
    constructor Create(AM, AK1, AK2, AK3: Int32);
    class function Inverse(AM: Int32; const AKs: TCryptoLibInt32Array; const AX: TBigInteger): TBigInteger; static;
    function CreatePoint(const AX, AY: TBigInteger): IECPoint; override;
    function IsValidFieldElement(const AX: TBigInteger): Boolean; override;
    function RandomFieldElement(const ARandom: ISecureRandom): IECFieldElement; override;
    function RandomFieldElementMult(const ARandom: ISecureRandom): IECFieldElement; override;
    function DecompressPoint(AYTilde: Int32; const AX1: TBigInteger): IECPoint; override;
    function SolveQuadraticEquation(const ABeta: IECFieldElement): IECFieldElement; virtual;
    class property MaxFieldSize: Int32 read FMaxFieldSize write FMaxFieldSize;
  end;

  TF2mCurve = class sealed(TAbstractF2mCurve, IECCurve, IF2mCurve)
  strict protected
    FM, FK1, FK2, FK3: Int32;
    FKs: TCryptoLibInt32Array;
    FInfinity: IECPoint;
    function CreateDefaultMultiplier: IECMultiplier; override;
  strict private
type
  TDefaultF2mLookupTable = class sealed(TAbstractECLookupTable, IECLookupTable)
  strict private
    FOuter: IF2mCurve;
    FTable: TCryptoLibUInt64Array;
    FSize: Int32;
    function CreatePoint(const AX, AY: TCryptoLibUInt64Array): IECPoint;
  public
    constructor Create(const AOuter: IF2mCurve; const ATable: TCryptoLibUInt64Array; ASize: Int32);
    function GetSize: Int32; override;
    function Lookup(AIndex: Int32): IECPoint; override;
    function LookupVar(AIndex: Int32): IECPoint; override;
  end;

  public
    const F2M_DEFAULT_COORDS = TECCurveConstants.COORD_LAMBDA_PROJECTIVE;
    constructor Create(AM, AK: Int32; const AA, AB: TBigInteger); overload; deprecated;
    constructor Create(AM, AK: Int32; const AA, AB, AOrder, ACofactor: TBigInteger); overload;
    constructor Create(AM, AK1, AK2, AK3: Int32; const AA, AB, AOrder, ACofactor: TBigInteger); overload;
    constructor Create(AM, AK1, AK2, AK3: Int32; const AA, AB: IECFieldElement;
      const AOrder, ACofactor: TBigInteger); overload;
    function CloneCurve: IECCurve; override;
    function GetFieldSize: Int32; override;
    function GetInfinity: IECPoint; override;
    function FromBigInteger(const AX: TBigInteger): IECFieldElement; override;
    function CreateRawPoint(const AX: IECFieldElement; const AY: IECFieldElement): IECPoint; override;
    function CreateRawPoint(const AX: IECFieldElement; const AY: IECFieldElement; const AZs: TCryptoLibGenericArray<IECFieldElement>): IECPoint; override;
    function CreateCacheSafeLookupTable(const APoints: TCryptoLibGenericArray<IECPoint>; AOff, ALen: Int32): IECLookupTable; override;
    function SupportsCoordinateSystem(ACoord: Int32): Boolean; override;
    function IsTrinomial: Boolean;
    function GetM: Int32;
    function GetK1: Int32;
    function GetK2: Int32;
    function GetK3: Int32;
    property M: Int32 read GetM;
    property K1: Int32 read GetK1;
    property K2: Int32 read GetK2;
    property K3: Int32 read GetK3;
  end;

implementation

uses
  ClpECPoint,
  ClpMultipliers;

{ TECCurve.TDefaultLookupTable }

constructor TECCurve.TDefaultLookupTable.Create(const AOuter: IECCurve; const ATable: TCryptoLibByteArray; ASize: Int32);
begin
  Inherited Create();
  FOuter := AOuter;
  FTable := ATable;
  FSize := ASize;
end;

function TECCurve.TDefaultLookupTable.GetSize: Int32;
begin
  Result := FSize;
end;

function TECCurve.TDefaultLookupTable.Lookup(AIndex: Int32): IECPoint;
var
  LFeBytes, LPos, I, J: Int32;
  LMask: Byte;
  LX, LY: TCryptoLibByteArray;
begin
  LFeBytes := FOuter.GetFieldElementEncodingLength();
  SetLength(LX, LFeBytes);
  SetLength(LY, LFeBytes);
  LPos := 0;
  for I := 0 to FSize - 1 do
  begin
    LMask := Byte(TBitOperations.Asr32((I xor AIndex) - 1, 31));
    for J := 0 to LFeBytes - 1 do
    begin
      LX[J] := Byte(LX[J] xor (FTable[LPos + J] and LMask));
      LY[J] := Byte(LY[J] xor (FTable[LPos + LFeBytes + J] and LMask));
    end;
    Inc(LPos, LFeBytes * 2);
  end;
  Result := CreatePoint(LX, LY);
end;

function TECCurve.TDefaultLookupTable.LookupVar(AIndex: Int32): IECPoint;
var
  LFeBytes, LPos, J: Int32;
  LX, LY: TCryptoLibByteArray;
begin
  LFeBytes := FOuter.GetFieldElementEncodingLength();
  SetLength(LX, LFeBytes);
  SetLength(LY, LFeBytes);
  LPos := AIndex * LFeBytes * 2;
  for J := 0 to LFeBytes - 1 do
  begin
    LX[J] := FTable[LPos + J];
    LY[J] := FTable[LPos + LFeBytes + J];
  end;
  Result := CreatePoint(LX, LY);
end;

function TECCurve.TDefaultLookupTable.CreatePoint(const AX, AY: TCryptoLibByteArray): IECPoint;
var
  LX, LY: IECFieldElement;
begin
  LX := FOuter.FromBigInteger(TBigInteger.Create(1, AX));
  LY := FOuter.FromBigInteger(TBigInteger.Create(1, AY));
  Result := FOuter.CreateRawPoint(LX, LY);
end;

{ TF2mCurve.TDefaultF2mLookupTable }

constructor TF2mCurve.TDefaultF2mLookupTable.Create(const AOuter: IF2mCurve; const ATable: TCryptoLibUInt64Array; ASize: Int32);
begin
  Inherited Create();
  FOuter := AOuter;
  FTable := ATable;
  FSize := ASize;
end;

function TF2mCurve.TDefaultF2mLookupTable.GetSize: Int32;
begin
  Result := FSize;
end;

function TF2mCurve.TDefaultF2mLookupTable.Lookup(AIndex: Int32): IECPoint;
var
  LFeLongs, LPos, I, J: Int32;
  LMask: UInt64;
  LX, LY: TCryptoLibUInt64Array;
begin
  LFeLongs := (FOuter.M + 63) div 64;
  System.SetLength(LX, LFeLongs);
  System.SetLength(LY, LFeLongs);
  LPos := 0;

  for I := 0 to FSize - 1 do
  begin
    LMask := UInt64(Int64(TBitOperations.Asr32((I xor AIndex) - 1, 31)));

    for J := 0 to LFeLongs - 1 do
    begin
      LX[J] := LX[J] xor (FTable[LPos + J] and LMask);
      LY[J] := LY[J] xor (FTable[LPos + LFeLongs + J] and LMask);
    end;

    Inc(LPos, LFeLongs * 2);
  end;

  Result := CreatePoint(LX, LY);
end;

function TF2mCurve.TDefaultF2mLookupTable.LookupVar(AIndex: Int32): IECPoint;
var
  LFeLongs, LPos, J: Int32;
  LX, LY: TCryptoLibUInt64Array;
begin
  LFeLongs := (FOuter.M + 63) div 64;
  System.SetLength(LX, LFeLongs);
  System.SetLength(LY, LFeLongs);
  LPos := AIndex * LFeLongs * 2;

  for J := 0 to LFeLongs - 1 do
  begin
    LX[J] := FTable[LPos + J];
    LY[J] := FTable[LPos + LFeLongs + J];
  end;

  Result := CreatePoint(LX, LY);
end;

function TF2mCurve.TDefaultF2mLookupTable.CreatePoint(const AX, AY: TCryptoLibUInt64Array): IECPoint;
var
  LKs: TCryptoLibInt32Array;
  LXfe, LYfe: IECFieldElement;
begin
  if FOuter.IsTrinomial then
    LKs := TCryptoLibInt32Array.Create(FOuter.K1)
  else
    LKs := TCryptoLibInt32Array.Create(FOuter.K1, FOuter.K2, FOuter.K3);
  LXfe := TF2mFieldElement.Create(FOuter.M, LKs, TLongArray.Create(AX));
  LYfe := TF2mFieldElement.Create(FOuter.M, LKs, TLongArray.Create(AY));
  Result := FOuter.CreateRawPoint(LXfe, LYfe);
end;

{ TECCurve }

constructor TECCurve.Create(const AField: IFiniteField);
begin
  Inherited Create();
  FField := AField;
  FA := nil;
  FB := nil;
  FOrder := TBigInteger.GetDefault();
  FCofactor := TBigInteger.GetDefault();
  FCoord := TECCurveConstants.COORD_AFFINE;
  FMultiplier := nil;
  FEndomorphism := nil;
  FPreCompTable := nil;
  FLock := TCriticalSection.Create;
  FTableLock := TCriticalSection.Create;
end;

destructor TECCurve.Destroy;
begin
  FPreCompTable.Free;
  FTableLock.Free;
  FLock.Free;
  inherited;
end;

class function TECCurve.GetAllCoordinateSystems: TCryptoLibInt32Array;
begin
  Result := TECCurveConstants.GetAllCoordinateSystems();
end;

function TECCurve.CreateDefaultMultiplier: IECMultiplier;
var
  LGlv: IGlvEndomorphism;
begin
  if Supports(FEndomorphism, IGlvEndomorphism, LGlv) then
    Result := TGlvMultiplier.Create(Self as IECCurve, LGlv) as IECMultiplier
  else
    Result := TWNafL2RMultiplier.Create() as IECMultiplier;
end;

procedure TECCurve.CheckPoint(const APoint: IECPoint);
begin
  if (APoint = nil) or (Self as IECCurve <> APoint.Curve) then
    raise EArgumentCryptoLibException.CreateRes(@SMustBeNonNilAndOnThisCurve);
end;

procedure TECCurve.CheckPoints(const APoints: TCryptoLibGenericArray<IECPoint>);
begin
  CheckPoints(APoints, 0, System.Length(APoints));
end;

procedure TECCurve.CheckPoints(const APoints: TCryptoLibGenericArray<IECPoint>;
  AOff, ALen: Int32);
var
  I: Int32;
  LPoint: IECPoint;
begin
  if APoints = nil then
    raise EArgumentNilCryptoLibException.Create('points');
  if (AOff < 0) or (ALen < 0) or (AOff > (System.Length(APoints) - ALen)) then
    raise EArgumentCryptoLibException.CreateRes(@SInvalidRangeSpecified);
  for I := 0 to ALen - 1 do
  begin
    LPoint := APoints[AOff + I];
    if (LPoint <> nil) and (Self as IECCurve <> LPoint.Curve) then
      raise EArgumentCryptoLibException.CreateRes(@SEntriesMustBeNullOrOnThisCurve);
  end;
end;

function TECCurve.GetFieldElementEncodingLength: Int32;
begin
  Result := (GetFieldSize() + 7) div 8;
end;

function TECCurve.GetOrder: TBigInteger;
begin
  Result := FOrder;
end;

function TECCurve.GetCofactor: TBigInteger;
begin
  Result := FCofactor;
end;

function TECCurve.GetCoordinateSystem: Int32;
begin
  Result := FCoord;
end;

function TECCurve.GetA: IECFieldElement;
begin
  Result := FA;
end;

function TECCurve.GetB: IECFieldElement;
begin
  Result := FB;
end;

function TECCurve.GetMultiplier: IECMultiplier;
begin
  if FMultiplier = nil then
    FMultiplier := CreateDefaultMultiplier();
  Result := FMultiplier;
end;

function TECCurve.CreatePoint(const AX, AY: TBigInteger): IECPoint;
begin
  Result := CreateRawPoint(FromBigInteger(AX), FromBigInteger(AY));
end;

function TECCurve.GetAffinePointEncodingLength(ACompressed: Boolean): Int32;
var
  LFieldLen: Int32;
begin
  LFieldLen := GetFieldElementEncodingLength();
  if ACompressed then
    Result := 1 + LFieldLen
  else
    Result := 1 + (LFieldLen * 2);
end;

function TECCurve.CreateCacheSafeLookupTable(const APoints: TCryptoLibGenericArray<IECPoint>;
  AOff, ALen: Int32): IECLookupTable;
var
  LFeBytes, LPos, I: Int32;
  LTable: TCryptoLibByteArray;
  LP: IECPoint;
begin
  LFeBytes := GetFieldElementEncodingLength();
  System.SetLength(LTable, ALen * LFeBytes * 2);
  LPos := 0;
  for I := 0 to System.Pred(ALen) do
  begin
    LP := APoints[AOff + I];
    LP.RawXCoord.EncodeTo(LTable, LPos);
    LPos := LPos + LFeBytes;
    LP.RawYCoord.EncodeTo(LTable, LPos);
    LPos := LPos + LFeBytes;
  end;
  Result := TDefaultLookupTable.Create(Self, LTable, ALen);
end;

function TECCurve.GetPreCompInfo(const APoint: IECPoint; const AName: String): IPreCompInfo;
begin
  CheckPoint(APoint);
  Result := APoint.GetPreCompInfo(AName);
end;

function TECCurve.Precompute(const AName: String; const ACallback: IPreCompCallback): IPreCompInfo;
var
  LTable: TDictionary<String, IPreCompInfo>;
  LExisting: IPreCompInfo;
begin
  FLock.Enter;
  try
    LTable := FPreCompTable;
    if LTable = nil then
    begin
      LTable := TDictionary<String, IPreCompInfo>.Create();
      FPreCompTable := LTable;
    end;
  finally
    FLock.Leave;
  end;

  FTableLock.Enter;
  try
    if LTable.TryGetValue(AName, LExisting) then
      { use existing }
    else
      LExisting := nil;
    Result := ACallback.Precompute(LExisting);
    if Result <> LExisting then
      LTable.AddOrSetValue(AName, Result);
  finally
    FTableLock.Leave;
  end;
end;

function TECCurve.GetEndomorphism: IECEndomorphism;
begin
  Result := FEndomorphism;
end;

function TECCurve.SupportsCoordinateSystem(ACoord: Int32): Boolean;
begin
  Result := ACoord = TECCurveConstants.COORD_AFFINE;
end;

procedure TECCurve.NormalizeAll(const APoints: TCryptoLibGenericArray<IECPoint>);
begin
  NormalizeAll(APoints, 0, System.Length(APoints), nil);
end;

procedure TECCurve.NormalizeAll(const APoints: TCryptoLibGenericArray<IECPoint>;
  AOff, ALen: Int32; const AIso: IECFieldElement);
var
  LZs: TCryptoLibGenericArray<IECFieldElement>;
  LIndices: TCryptoLibInt32Array;
  LCount, I, LCoord: Int32;
  LP: IECPoint;
begin
  CheckPoints(APoints, AOff, ALen);

  LCoord := GetCoordinateSystem();
  case LCoord of
    TECCurveConstants.COORD_AFFINE, TECCurveConstants.COORD_LAMBDA_AFFINE:
      begin
        if AIso <> nil then
          raise EArgumentCryptoLibException.Create('not valid for affine coordinates');
        Exit;
      end;
  end;

  System.SetLength(LZs, ALen);
  System.SetLength(LIndices, ALen);
  LCount := 0;
  for I := 0 to ALen - 1 do
  begin
    LP := APoints[AOff + I];
    if (LP <> nil) and ((AIso <> nil) or not LP.IsNormalized) then
    begin
      LZs[LCount] := LP.GetZCoord(0);
      LIndices[LCount] := AOff + I;
      Inc(LCount);
    end;
  end;

  if LCount = 0 then
    Exit;

  TECAlgorithms.MontgomeryTrick(LZs, 0, LCount, AIso);

  for I := 0 to LCount - 1 do
    APoints[LIndices[I]] := APoints[LIndices[I]].Normalize(LZs[I]);
end;

function TECCurve.ImportPoint(const AP: IECPoint): IECPoint;
var
  LP: IECPoint;
begin
  if (Self as IECCurve) = AP.Curve then
    Exit(AP);
  if AP.IsInfinity then
    Exit(GetInfinity());
  LP := AP.Normalize();
  Result := CreatePoint(LP.XCoord.ToBigInteger(), LP.YCoord.ToBigInteger());
end;

function TECCurve.Precompute(const APoint: IECPoint; const AName: String;
  const ACallback: IPreCompCallback): IPreCompInfo;
begin
  CheckPoint(APoint);
  Result := APoint.Precompute(AName, ACallback);
end;

function TECCurve.GetField: IFiniteField;
begin
  Result := FField;
end;

function TECCurve.DecompressPoint(AYTilde: Int32; const AX1: TBigInteger): IECPoint;
begin
  raise EArgumentCryptoLibException.Create(SPointCompressionNotSupported);
end;

function TECCurve.ValidatePoint(const AX, AY: TBigInteger): IECPoint;
var
  LP: IECPoint;
begin
  LP := CreatePoint(AX, AY);
  if not LP.IsValid() then
    raise EArgumentCryptoLibException.Create(SInvalidPointCoordinates);
  Result := LP;
end;

function TECCurve.Configure: IECCurveConfig;
begin
  Result := TECCurveConfig.Create(Self, FCoord, FEndomorphism, FMultiplier);
end;

procedure TECCurve.ApplyConfig(ACoord: Int32; const AEndomorphism: IECEndomorphism;
  const AMultiplier: IECMultiplier);
begin
  FCoord := ACoord;
  FEndomorphism := AEndomorphism;
  FMultiplier := AMultiplier;
end;

{ TECCurve.TECCurveConfig }

constructor TECCurve.TECCurveConfig.Create(const AOuter: IECCurve; ACoord: Int32;
  const AEndomorphism: IECEndomorphism; const AMultiplier: IECMultiplier);
begin
  inherited Create();
  FOuter := AOuter;
  FCoord := ACoord;
  FEndomorphism := AEndomorphism;
  FMultiplier := AMultiplier;
end;

function TECCurve.TECCurveConfig.SetCoordinateSystem(ACoord: Int32): IECCurveConfig;
begin
  FCoord := ACoord;
  Result := Self;
end;

function TECCurve.TECCurveConfig.SetEndomorphism(const AEndomorphism: IECEndomorphism): IECCurveConfig;
begin
  FEndomorphism := AEndomorphism;
  Result := Self;
end;

function TECCurve.TECCurveConfig.SetMultiplier(const AMultiplier: IECMultiplier): IECCurveConfig;
begin
  FMultiplier := AMultiplier;
  Result := Self;
end;

function TECCurve.TECCurveConfig.CreateCurve: IECCurve;
var
  LClone: IECCurve;
begin
  if not FOuter.SupportsCoordinateSystem(FCoord) then
    raise EInvalidOperationCryptoLibException.Create(SUnsupportedCoordinateSystem);
  LClone := FOuter.CloneCurve();
  if LClone = FOuter then
    raise EInvalidOperationCryptoLibException.Create(SImplementationReturnedCurrentCurve);
  LClone.ApplyConfig(FCoord, FEndomorphism, FMultiplier);
  Result := LClone;
end;

function TECCurve.DecodePoint(const AEncoded: TCryptoLibByteArray): IECPoint;
var
  LExpectedLength: Int32;
  LType: Byte;
  LYTilde: Int32;
  LX, LY: TBigInteger;
  LP: IECPoint;
begin
  if (AEncoded = nil) or (System.Length(AEncoded) < 1) then
    raise EArgumentCryptoLibException.CreateResFmt(@SInvalidPointEncoding, [0]);

  LExpectedLength := GetFieldElementEncodingLength();
  LType := AEncoded[0];

  case LType of
    $00: // infinity
      begin
        if System.Length(AEncoded) <> 1 then
          raise EArgumentCryptoLibException.Create(SIncorrectLengthForInfinityEncoding);
        LP := GetInfinity();
      end;
    $02, $03: // compressed
      begin
        if System.Length(AEncoded) <> (LExpectedLength + 1) then
          raise EArgumentCryptoLibException.Create(SIncorrectLengthForCompressedEncoding);
        LYTilde := LType and 1;
        LX := TBigInteger.Create(1, AEncoded, 1, LExpectedLength);
        LP := DecompressPoint(LYTilde, LX);
        if not LP.ImplIsValid(True, True) then
          raise EArgumentCryptoLibException.Create(SInvalidPointCoordinates);
      end;
    $04: // uncompressed
      begin
        if System.Length(AEncoded) <> (2 * LExpectedLength + 1) then
          raise EArgumentCryptoLibException.Create(SIncorrectLengthForUncompressedEncoding);
        LX := TBigInteger.Create(1, AEncoded, 1, LExpectedLength);
        LY := TBigInteger.Create(1, AEncoded, 1 + LExpectedLength, LExpectedLength);
        LP := ValidatePoint(LX, LY);
      end;
    $06, $07: // hybrid
      begin
        if System.Length(AEncoded) <> (2 * LExpectedLength + 1) then
          raise EArgumentCryptoLibException.Create(SIncorrectLengthForHybridEncoding);
        LX := TBigInteger.Create(1, AEncoded, 1, LExpectedLength);
        LY := TBigInteger.Create(1, AEncoded, 1 + LExpectedLength, LExpectedLength);
        if LY.TestBit(0) <> (LType = $07) then
          raise EArgumentCryptoLibException.Create(SInconsistentYCoordinateInHybridEncoding);
        LP := ValidatePoint(LX, LY);
      end;
  else
    raise EFormatCryptoLibException.CreateResFmt(@SInvalidPointEncoding, [LType]);
  end;

  if (LType <> $00) and LP.IsInfinity then
    raise EArgumentCryptoLibException.Create(SInvalidInfinityEncoding);

  Result := LP;
end;

function TECCurve.Equals(const AOther: IECCurve): Boolean;
var
  LA, LB: TBigInteger;
begin
  if AOther = nil then
    Exit(False);
  if (Self as IECCurve) = AOther then
    Exit(True);
  if not FField.Equals(AOther.Field) then
    Exit(False);
  LA := FA.ToBigInteger();
  LB := AOther.A.ToBigInteger();
  if not LA.Equals(LB) then
    Exit(False);
  LA := FB.ToBigInteger();
  LB := AOther.B.ToBigInteger();
  Result := LA.Equals(LB);
end;

function TECCurve.GetHashCode: {$IFDEF DELPHI}Int32{$ELSE}PtrInt{$ENDIF};
var
  LHa, LHb: Int32;
begin
  Result := FField.GetHashCode();
  LHa := FA.ToBigInteger().GetHashCode();
  Result := Result xor Int32(TBitOperations.RotateLeft32(UInt32(LHa), 8));
  LHb := FB.ToBigInteger().GetHashCode();
  Result := Result xor Int32(TBitOperations.RotateLeft32(UInt32(LHb), 16));
end;

{ TAbstractFpCurve }

class constructor TAbstractFpCurve.Create;
begin
  FKnownPrimes := TDictionary<TBigInteger, Boolean>.Create(TBigIntegers.BigIntegerEqualityComparer);
  FLockPrimes := TCriticalSection.Create;
  FMaxFieldSize := 1042; // 2 * 521
  FCertainty := 100;
end;

class destructor TAbstractFpCurve.Destroy;
begin
  FLockPrimes.Free;
  FKnownPrimes.Free;
end;

constructor TAbstractFpCurve.Create(const AQ: TBigInteger);
begin
  Create(AQ, False);
end;

constructor TAbstractFpCurve.Create(const AQ: TBigInteger; AIsInternal: Boolean);
var
  LFound: Boolean;
begin
  inherited Create(TFiniteFields.GetPrimeField(AQ));
  FLockPrimes.Enter;
  try
    if AIsInternal then
    begin
      FKnownPrimes.AddOrSetValue(AQ, True);
    end
    else
    begin
      LFound := FKnownPrimes.ContainsKey(AQ);
      if not LFound then
      begin
        ImplCheckQ(AQ);
        FKnownPrimes.Add(AQ, False);
      end;
    end;
  finally
    FLockPrimes.Leave;
  end;
end;

class procedure TAbstractFpCurve.ImplCheckQ(const AQ: TBigInteger);
begin
  if AQ.BitLength > FMaxFieldSize then
    raise EArgumentCryptoLibException.Create('Fp q value out of range');
  if not ImplIsPrime(AQ) then
    raise EArgumentCryptoLibException.Create('Fp q value not prime');
end;

class function TAbstractFpCurve.ImplIsPrime(const AQ: TBigInteger): Boolean;
var
  LIterations: Int32;
begin
  if TPrimes.HasAnySmallFactors(AQ) then
    Exit(False);
  LIterations := ImplGetIterations(AQ.BitLength, FCertainty);
  Result := TPrimes.IsMRProbablePrime(AQ, TSecureRandom.MasterRandom, LIterations);
end;

class function TAbstractFpCurve.ImplGetIterations(ABits, ACertainty: Int32): Int32;
begin
  if ABits >= 1536 then
  begin
    if ACertainty <= 100 then Exit(3)
    else if ACertainty <= 128 then Exit(4)
    else Exit(4 + (ACertainty - 128 + 1) div 2);
  end
  else if ABits >= 1024 then
  begin
    if ACertainty <= 100 then Exit(4)
    else if ACertainty <= 112 then Exit(5)
    else Exit(5 + (ACertainty - 112 + 1) div 2);
  end
  else if ABits >= 512 then
  begin
    if ACertainty <= 80 then Exit(5)
    else if ACertainty <= 100 then Exit(7)
    else Exit(7 + (ACertainty - 100 + 1) div 2);
  end
  else
  begin
    if ACertainty <= 80 then Exit(40)
    else Exit(40 + (ACertainty - 80 + 1) div 2);
  end;
end;

class function TAbstractFpCurve.ImplRandomFieldElement(const ARandom: ISecureRandom;
  const AP: TBigInteger): TBigInteger;
var
  LX: TBigInteger;
begin
  repeat
    LX := TBigIntegers.CreateRandomBigInteger(AP.BitLength, ARandom);
  until LX.CompareTo(AP) < 0;
  Result := LX;
end;

class function TAbstractFpCurve.ImplRandomFieldElementMult(const ARandom: ISecureRandom;
  const AP: TBigInteger): TBigInteger;
var
  LX: TBigInteger;
begin
  repeat
    LX := TBigIntegers.CreateRandomBigInteger(AP.BitLength, ARandom);
  until (LX.SignValue > 0) and (LX.CompareTo(AP) < 0);
  Result := LX;
end;

function TAbstractFpCurve.IsValidFieldElement(const AX: TBigInteger): Boolean;
var
  LP: TBigInteger;
begin
  if (not AX.IsInitialized) or (AX.SignValue < 0) then
    Exit(False);
  LP := FField.Characteristic;
  Result := AX.CompareTo(LP) < 0;
end;

function TAbstractFpCurve.RandomFieldElement(const ARandom: ISecureRandom): IECFieldElement;
var
  LP: TBigInteger;
  LFe1, LFe2: IECFieldElement;
begin
  LP := FField.Characteristic;
  LFe1 := FromBigInteger(ImplRandomFieldElement(ARandom, LP));
  LFe2 := FromBigInteger(ImplRandomFieldElement(ARandom, LP));
  Result := LFe1.Multiply(LFe2);
end;

function TAbstractFpCurve.RandomFieldElementMult(const ARandom: ISecureRandom): IECFieldElement;
var
  LP: TBigInteger;
  LFe1, LFe2: IECFieldElement;
begin
  LP := FField.Characteristic;
  LFe1 := FromBigInteger(ImplRandomFieldElementMult(ARandom, LP));
  LFe2 := FromBigInteger(ImplRandomFieldElementMult(ARandom, LP));
  Result := LFe1.Multiply(LFe2);
end;

function TAbstractFpCurve.DecompressPoint(AYTilde: Int32; const AX1: TBigInteger): IECPoint;
var
  LX, LRhs, LY: IECFieldElement;
begin
  LX := FromBigInteger(AX1);
  LRhs := LX.Square().Add(FA).Multiply(LX).Add(FB);
  LY := LRhs.Sqrt();
  if LY = nil then
    raise EArgumentCryptoLibException.Create(SInvalidPointCoordinates);
  if LY.TestBitZero <> (AYTilde = 1) then
    LY := LY.Negate();
  Result := CreateRawPoint(LX, LY);
end;

{ TFpCurve }

constructor TFpCurve.Create(const AQ, AA, AB, AOrder, ACofactor: TBigInteger);
begin
  Create(AQ, AA, AB, AOrder, ACofactor, False);
end;

constructor TFpCurve.Create(const AQ, AA, AB, AOrder, ACofactor: TBigInteger;
  AIsInternal: Boolean);
begin
  inherited Create(AQ, AIsInternal);
  FQ := AQ;
  FR := TFpFieldElement.CalculateResidue(AQ);
  FInfinity := TFpPoint.Create(Self as IECCurve, nil, nil);
  FA := FromBigInteger(AA);
  FB := FromBigInteger(AB);
  FOrder := AOrder;
  FCofactor := ACofactor;
  FCoord := FP_DEFAULT_COORDS;
end;

constructor TFpCurve.Create(const AQ, AR: TBigInteger; const AA, AB: IECFieldElement;
  const AOrder, ACofactor: TBigInteger);
begin
  inherited Create(AQ, True);
  FQ := AQ;
  FR := AR;
  FInfinity := TFpPoint.Create(Self as IECCurve, nil, nil);
  FA := AA;
  FB := AB;
  FOrder := AOrder;
  FCofactor := ACofactor;
  FCoord := FP_DEFAULT_COORDS;
end;

function TFpCurve.CloneCurve: IECCurve;
begin
  Result := TFpCurve.Create(FQ, FR, FA, FB, FOrder, FCofactor);
end;

function TFpCurve.ImportPoint(const AP: IECPoint): IECPoint;
begin
  if ((Self as IECCurve) <> AP.Curve) and (GetCoordinateSystem() = TECCurveConstants.COORD_JACOBIAN)
    and (not AP.IsInfinity) then
  begin
    case AP.Curve.CoordinateSystem of
      TECCurveConstants.COORD_JACOBIAN, TECCurveConstants.COORD_JACOBIAN_CHUDNOVSKY, TECCurveConstants.COORD_JACOBIAN_MODIFIED:
        begin
          Result := TFpPoint.Create(Self as IECCurve,
            FromBigInteger(AP.RawXCoord.ToBigInteger()),
            FromBigInteger(AP.RawYCoord.ToBigInteger()),
            TCryptoLibGenericArray<IECFieldElement>.Create(
              FromBigInteger(AP.GetZCoord(0).ToBigInteger())));
          Exit;
        end;
    else
      ;
    end;
  end;
  Result := inherited ImportPoint(AP);
end;

function TFpCurve.GetFieldSize: Int32;
begin
  Result := FQ.BitLength;
end;

function TFpCurve.GetInfinity: IECPoint;
begin
  Result := FInfinity;
end;

function TFpCurve.FromBigInteger(const AX: TBigInteger): IECFieldElement;
begin
  if (not AX.IsInitialized) or (AX.SignValue < 0) or (AX.CompareTo(FQ) >= 0) then
    raise EArgumentCryptoLibException.Create('value invalid for Fp field element');
  Result := TFpFieldElement.Create(FQ, FR, AX);
end;

function TFpCurve.CreateRawPoint(const AX: IECFieldElement; const AY: IECFieldElement): IECPoint;
begin
  Result := TFpPoint.Create(Self as IECCurve, AX, AY);
end;

function TFpCurve.CreateRawPoint(const AX: IECFieldElement; const AY: IECFieldElement; const AZs: TCryptoLibGenericArray<IECFieldElement>): IECPoint;
begin
  Result := TFpPoint.Create(Self as IECCurve, AX, AY, AZs);
end;

function TFpCurve.SupportsCoordinateSystem(ACoord: Int32): Boolean;
begin
  case ACoord of
    TECCurveConstants.COORD_AFFINE, TECCurveConstants.COORD_HOMOGENEOUS, TECCurveConstants.COORD_JACOBIAN, TECCurveConstants.COORD_JACOBIAN_MODIFIED:
      Result := True;
  else
    Result := False;
  end;
end;

function TFpCurve.GetQ: TBigInteger;
begin
  Result := FQ;
end;

{ TAbstractF2mCurve }

class constructor TAbstractF2mCurve.Create;
begin
  FMaxFieldSize := 1142; // 2 * 571
end;

function BuildF2mField(AM, AK1, AK2, AK3: Int32): IFiniteField;
var
  LExponents: TCryptoLibInt32Array;
begin
  if AM > TAbstractF2mCurve.MaxFieldSize then
    raise EArgumentCryptoLibException.Create('F2m m value out of range');
  if (AK2 or AK3) = 0 then
    LExponents := TCryptoLibInt32Array.Create(0, AK1, AM)
  else
    LExponents := TCryptoLibInt32Array.Create(0, AK1, AK2, AK3, AM);
  Result := TFiniteFields.GetBinaryExtensionField(LExponents);
end;

constructor TAbstractF2mCurve.Create(AM, AK1, AK2, AK3: Int32);
begin
  inherited Create(BuildF2mField(AM, AK1, AK2, AK3));
end;

class function TAbstractF2mCurve.ImplRandomFieldElementMult(const ARandom: ISecureRandom; AM: Int32): TBigInteger;
var
  LX: TBigInteger;
begin
  repeat
    LX := TBigIntegers.CreateRandomBigInteger(AM, ARandom);
  until LX.SignValue > 0;
  Result := LX;
end;

function TAbstractF2mCurve.CreatePoint(const AX, AY: TBigInteger): IECPoint;
var
  LX, LY: IECFieldElement;
begin
  LX := FromBigInteger(AX);
  LY := FromBigInteger(AY);

  case GetCoordinateSystem() of
    TECCurveConstants.COORD_LAMBDA_AFFINE,
    TECCurveConstants.COORD_LAMBDA_PROJECTIVE:
    begin
      if LX.IsZero then
      begin
        if not LY.Square().Equals(FB) then
          raise EArgumentCryptoLibException.Create('');
      end
      else
      begin
        // Y becomes Lambda (X + Y/X) here
        LY := LY.Divide(LX).Add(LX);
      end;
    end;
  end;

  Result := CreateRawPoint(LX, LY);
end;

function TAbstractF2mCurve.IsValidFieldElement(const AX: TBigInteger): Boolean;
begin
  Result := (AX.IsInitialized) and (AX.SignValue >= 0) and (AX.BitLength <= GetFieldSize());
end;

function TAbstractF2mCurve.RandomFieldElement(const ARandom: ISecureRandom): IECFieldElement;
begin
  Result := FromBigInteger(TBigIntegers.CreateRandomBigInteger(GetFieldSize(), ARandom));
end;

function TAbstractF2mCurve.RandomFieldElementMult(const ARandom: ISecureRandom): IECFieldElement;
var
  LFe1, LFe2: IECFieldElement;
begin
  LFe1 := FromBigInteger(ImplRandomFieldElementMult(ARandom, GetFieldSize()));
  LFe2 := FromBigInteger(ImplRandomFieldElementMult(ARandom, GetFieldSize()));
  Result := LFe1.Multiply(LFe2);
end;

function TAbstractF2mCurve.DecompressPoint(AYTilde: Int32; const AX1: TBigInteger): IECPoint;
var
  LXp, LYp, LBeta, LZ: IECFieldElement;
begin
  LXp := FromBigInteger(AX1);
  LYp := nil;
  if LXp.IsZero then
  begin
    LYp := FB.Sqrt();
  end
  else
  begin
    LBeta := LXp.Square().Invert().Multiply(FB).Add(FA).Add(LXp);
    LZ := SolveQuadraticEquation(LBeta);

    if LZ <> nil then
    begin
      if LZ.TestBitZero <> (AYTilde = 1) then
        LZ := LZ.AddOne();

      case GetCoordinateSystem() of
        TECCurveConstants.COORD_LAMBDA_AFFINE,
        TECCurveConstants.COORD_LAMBDA_PROJECTIVE:
          LYp := LZ.Add(LXp);
      else
        LYp := LZ.Multiply(LXp);
      end;
    end;
  end;

  if LYp = nil then
    raise EArgumentCryptoLibException.Create(SInvalidPointCoordinates);

  Result := CreateRawPoint(LXp, LYp);
end;

function TAbstractF2mCurve.SolveQuadraticEquation(const ABeta: IECFieldElement): IECFieldElement;
var
  LBetaF2m: IAbstractF2mFieldElement;
  LFastTrace: Boolean;
  LM, LI: Int32;
  LR, LZeroElement, LT, LZ, LW, LW2, LGamma: IECFieldElement;
begin
  if not Supports(ABeta, IAbstractF2mFieldElement, LBetaF2m) then
    raise EInvalidCastCryptoLibException.Create('Expected AbstractF2mFieldElement');

  LFastTrace := LBetaF2m.HasFastTrace;
  if LFastTrace and (0 <> LBetaF2m.Trace) then
    Exit(nil);

  LM := GetFieldSize();

  // For odd m, use the half-trace
  if (LM and 1) <> 0 then
  begin
    LR := LBetaF2m.HalfTrace();
    if LFastTrace or LR.Square().Add(LR).Add(ABeta).IsZero then
      Exit(LR);

    Exit(nil);
  end;

  if ABeta.IsZero then
    Exit(ABeta);

  LZeroElement := FromBigInteger(TBigInteger.Zero);

  repeat
    LT := FromBigInteger(TBigInteger.Arbitrary(LM));
    LZ := LZeroElement;
    LW := ABeta;
    for LI := 1 to LM - 1 do
    begin
      LW2 := LW.Square();
      LZ := LZ.Square().Add(LW2.Multiply(LT));
      LW := LW2.Add(ABeta);
    end;
    if not LW.IsZero then
      Exit(nil);
    LGamma := LZ.Square().Add(LZ);
  until not LGamma.IsZero;

  Result := LZ;
end;

class function TAbstractF2mCurve.Inverse(AM: Int32; const AKs: TCryptoLibInt32Array; const AX: TBigInteger): TBigInteger;
begin
  Result := TLongArray.Create(AX).ModInverse(AM, AKs).ToBigInteger();
end;

function TAbstractF2mCurve.GetIsKoblitz: Boolean;
begin
  Result := (FOrder.IsInitialized) and (FCofactor.IsInitialized) and FB.IsOne
    and (FA.IsZero or FA.IsOne);
end;

{ TF2mCurve }

constructor TF2mCurve.Create(AM, AK: Int32; const AA, AB: TBigInteger);
begin
  Create(AM, AK, 0, 0, AA, AB, TBigInteger.GetDefault(), TBigInteger.GetDefault());
end;

constructor TF2mCurve.Create(AM, AK: Int32; const AA, AB, AOrder, ACofactor: TBigInteger);
begin
  Create(AM, AK, 0, 0, AA, AB, AOrder, ACofactor);
end;

constructor TF2mCurve.Create(AM, AK1, AK2, AK3: Int32; const AA, AB, AOrder, ACofactor: TBigInteger);
begin
  inherited Create(AM, AK1, AK2, AK3);
  FM := AM;
  FK1 := AK1;
  FK2 := AK2;
  FK3 := AK3;
  if (AK2 or AK3) = 0 then
    FKs := TCryptoLibInt32Array.Create(AK1)
  else
    FKs := TCryptoLibInt32Array.Create(AK1, AK2, AK3);
  FOrder := AOrder;
  FCofactor := ACofactor;
  FInfinity := TF2mPoint.Create(Self as IECCurve, nil, nil);
  FA := FromBigInteger(AA);
  FB := FromBigInteger(AB);
  FCoord := F2M_DEFAULT_COORDS;
end;

constructor TF2mCurve.Create(AM, AK1, AK2, AK3: Int32; const AA, AB: IECFieldElement;
  const AOrder, ACofactor: TBigInteger);
begin
  inherited Create(AM, AK1, AK2, AK3);
  FM := AM;
  FK1 := AK1;
  FK2 := AK2;
  FK3 := AK3;
  if (AK2 or AK3) = 0 then
    FKs := TCryptoLibInt32Array.Create(AK1)
  else
    FKs := TCryptoLibInt32Array.Create(AK1, AK2, AK3);
  FOrder := AOrder;
  FCofactor := ACofactor;
  FInfinity := TF2mPoint.Create(Self as IECCurve, nil, nil);
  FA := AA;
  FB := AB;
  FCoord := F2M_DEFAULT_COORDS;
end;

function TF2mCurve.CloneCurve: IECCurve;
begin
  Result := TF2mCurve.Create(FM, FK1, FK2, FK3, FA, FB, FOrder, FCofactor);
end;

function TF2mCurve.GetFieldSize: Int32;
begin
  Result := FM;
end;

function TF2mCurve.GetInfinity: IECPoint;
begin
  Result := FInfinity;
end;

function TF2mCurve.FromBigInteger(const AX: TBigInteger): IECFieldElement;
var
  LX: TLongArray;
begin
  if (not AX.IsInitialized) or (AX.SignValue < 0) or (AX.BitLength > FM) then
    raise EArgumentCryptoLibException.Create('value invalid for F2m field element');

  LX := TLongArray.Create(AX);
  Result := TF2mFieldElement.Create(FM, FKs, LX);
end;

function TF2mCurve.CreateRawPoint(const AX: IECFieldElement; const AY: IECFieldElement): IECPoint;
begin
  Result := TF2mPoint.Create(Self as IECCurve, AX, AY);
end;

function TF2mCurve.CreateRawPoint(const AX: IECFieldElement; const AY: IECFieldElement; const AZs: TCryptoLibGenericArray<IECFieldElement>): IECPoint;
begin
  Result := TF2mPoint.Create(Self as IECCurve, AX, AY, AZs);
end;

function TF2mCurve.SupportsCoordinateSystem(ACoord: Int32): Boolean;
begin
  case ACoord of
    TECCurveConstants.COORD_AFFINE, TECCurveConstants.COORD_HOMOGENEOUS, TECCurveConstants.COORD_LAMBDA_PROJECTIVE:
      Result := True;
  else
    Result := False;
  end;
end;

function TF2mCurve.CreateDefaultMultiplier: IECMultiplier;
begin
  if GetIsKoblitz then
    Result := TWTauNafMultiplier.Create()
  else
    Result := inherited CreateDefaultMultiplier();
end;

function TF2mCurve.IsTrinomial: Boolean;
begin
  Result := (FK2 = 0) and (FK3 = 0);
end;

function TF2mCurve.GetM: Int32;
begin
  Result := FM;
end;

function TF2mCurve.GetK1: Int32;
begin
  Result := FK1;
end;

function TF2mCurve.GetK2: Int32;
begin
  Result := FK2;
end;

function TF2mCurve.GetK3: Int32;
begin
  Result := FK3;
end;

function TF2mCurve.CreateCacheSafeLookupTable(const APoints: TCryptoLibGenericArray<IECPoint>;
  AOff, ALen: Int32): IECLookupTable;
var
  LFeLongs, LPos, I: Int32;
  LTable: TCryptoLibUInt64Array;
  LP: IECPoint;
begin
  LFeLongs := (FM + 63) div 64;
  System.SetLength(LTable, ALen * LFeLongs * 2);
  LPos := 0;
  for I := 0 to ALen - 1 do
  begin
    LP := APoints[AOff + I];
    (LP.RawXCoord as IF2mFieldElement).X.CopyTo(LTable, LPos);
    Inc(LPos, LFeLongs);
    (LP.RawYCoord as IF2mFieldElement).X.CopyTo(LTable, LPos);
    Inc(LPos, LFeLongs);
  end;
  Result := TDefaultF2mLookupTable.Create(Self, LTable, ALen);
end;

end.
