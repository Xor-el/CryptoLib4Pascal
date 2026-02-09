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

unit ClpECPoint;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  SyncObjs,
  Generics.Collections,
  ClpBitOperations,
  ClpECAlgorithms,
  ClpECFieldElement,
  ClpECCurveConstants,
  ClpIValidityPreCompInfo,
  ClpValidityPreCompInfo,
  ClpBigInteger,
  ClpIECCommon,
  ClpIECFieldElement,
  ClpIPreCompCallback,
  ClpIPreCompInfo,
  ClpISecureRandom,
  ClpSecureRandom,
  ClpCryptoLibTypes;

resourcestring
  SPointNotInNormalForm = 'point not in normal form';
  SUnknownCoordinateSystem = 'unknown coordinate system';
  SUnsupportedCoordinateSystem = 'unsupported coordinate system';
  SDetachedPointsMustBeInAffine = 'Detached points must be in affine coordinates';
  SNotAProjectiveCoordinateSystem = 'not a projective coordinate system';
  SInvalidTimesPow2Exponent = 'exponent cannot be negative';

type
  TECPoint = class abstract(TInterfacedObject, IECPoint)
  strict private
type
  TValidityCallback = class sealed(TInterfacedObject, IPreCompCallback)
  strict private
    FOuter: IECPoint;
    FDecompressed: Boolean;
    FCheckOrder: Boolean;
  public
    constructor Create(const AOuter: IECPoint; ADecompressed, ACheckOrder: Boolean);
    function Precompute(const AExisting: IPreCompInfo): IPreCompInfo;
  end;

  var
    FPreCompTable: TDictionary<String, IPreCompInfo>;
    FPointLock: TCriticalSection;
    FTableLock: TCriticalSection;
    class function GetInitialZCoords(const ACurve: IECCurve): TCryptoLibGenericArray<IECFieldElement>; static;
  strict protected
    FCurve: IECCurve;
    FX, FY: IECFieldElement;
    FZs: TCryptoLibGenericArray<IECFieldElement>;

    function GetCurveCoordinateSystem: Int32; virtual;
    function CreateScaledPoint(const ASx, ASy: IECFieldElement): IECPoint; virtual;

    function GetRawXCoord: IECFieldElement; inline;
    function GetRawYCoord: IECFieldElement; inline;
    function GetRawZCoords: TCryptoLibGenericArray<IECFieldElement>; inline;

    property RawXCoord: IECFieldElement read GetRawXCoord;
    property RawYCoord: IECFieldElement read GetRawYCoord;
    property RawZCoords: TCryptoLibGenericArray<IECFieldElement> read GetRawZCoords;

    procedure CheckNormalized; virtual;

    function Detach: IECPoint; virtual; abstract;  // called from GetDetachedPoint on normalized point
    function GetCompressionYTilde: Boolean; virtual; abstract;
  public
    constructor Create(const ACurve: IECCurve; const AX, AY: IECFieldElement); overload;
    constructor Create(const ACurve: IECCurve; const AX, AY: IECFieldElement;
      const AZs: TCryptoLibGenericArray<IECFieldElement>); overload;
    destructor Destroy; override;

    function GetCurve: IECCurve; virtual;
    property Curve: IECCurve read GetCurve;
    function GetIsInfinity: Boolean; virtual;
    property IsInfinity: Boolean read GetIsInfinity;
    function GetXCoord: IECFieldElement; virtual;
    function GetYCoord: IECFieldElement; virtual;
    property XCoord: IECFieldElement read GetXCoord;
    property YCoord: IECFieldElement read GetYCoord;
    function GetZCoord(AIndex: Int32): IECFieldElement; virtual;
    function GetZCoords: TCryptoLibGenericArray<IECFieldElement>; virtual;

    function IsNormalized: Boolean; virtual;
    function Normalize: IECPoint; overload; virtual;
    function Normalize(const AZInv: IECFieldElement): IECPoint; overload; virtual;
    function GetDetachedPoint: IECPoint; virtual;

    function ScaleX(const AScale: IECFieldElement): IECPoint; virtual;
    function ScaleXNegateY(const AScale: IECFieldElement): IECPoint; virtual;
    function ScaleY(const AScale: IECFieldElement): IECPoint; virtual;
    function ScaleYNegateX(const AScale: IECFieldElement): IECPoint; virtual;

    function GetPreCompInfo(const AName: String): IPreCompInfo; virtual;
    function Precompute(const AName: String; const ACallback: IPreCompCallback): IPreCompInfo; virtual;

    function GetEncoded: TCryptoLibByteArray; overload; virtual;
    function GetEncoded(ACompressed: Boolean): TCryptoLibByteArray; overload; virtual; abstract;
    function GetEncodedLength(ACompressed: Boolean): Int32; virtual; abstract;
    procedure EncodeTo(ACompressed: Boolean; var ABuf: TCryptoLibByteArray; AOff: Int32); virtual; abstract;

    function GetAffineXCoord: IECFieldElement; virtual;
    function GetAffineYCoord: IECFieldElement; virtual;
    property AffineXCoord: IECFieldElement read GetAffineXCoord;
    property AffineYCoord: IECFieldElement read GetAffineYCoord;
    function Add(const AB: IECPoint): IECPoint; virtual; abstract;
    function Subtract(const AB: IECPoint): IECPoint; virtual; abstract;
    function Negate: IECPoint; virtual; abstract;
    function Twice: IECPoint; virtual; abstract;
    function Multiply(const AK: TBigInteger): IECPoint; virtual; abstract;
    function TimesPow2(AE: Int32): IECPoint; virtual;
    function TwicePlus(const AB: IECPoint): IECPoint; virtual;
    function ThreeTimes: IECPoint; virtual;

    function ImplIsValid(ADecompressed, ACheckOrder: Boolean): Boolean; virtual;
    function SatisfiesCurveEquation: Boolean; virtual; abstract;
    function SatisfiesOrder: Boolean; virtual;
    function IsValid: Boolean; virtual;
    function IsValidPartial: Boolean; virtual;

    function Equals(const AOther: IECPoint): Boolean;
    function GetHashCode: {$IFDEF DELPHI}Int32; {$ELSE}PtrInt; {$ENDIF DELPHI} override;
    function ToString: String; override;
  end;

  TECPointBase = class abstract(TECPoint, IECPointBase)
  public
    constructor Create(const ACurve: IECCurve; const AX, AY: IECFieldElement); overload;
    constructor Create(const ACurve: IECCurve; const AX, AY: IECFieldElement;
      const AZs: TCryptoLibGenericArray<IECFieldElement>); overload;
    function GetEncoded(ACompressed: Boolean): TCryptoLibByteArray; overload; override;
    function GetEncodedLength(ACompressed: Boolean): Int32; override;
    procedure EncodeTo(ACompressed: Boolean; var ABuf: TCryptoLibByteArray; AOff: Int32); override;
    function Multiply(const AK: TBigInteger): IECPoint; override;
  end;

  TAbstractFpPoint = class abstract(TECPointBase, IAbstractFpPoint)
  strict protected
    function GetCompressionYTilde: Boolean; override;
  public
    function SatisfiesCurveEquation: Boolean; override;
    function Subtract(const AB: IECPoint): IECPoint; override;
  end;

  TFpPoint = class sealed(TAbstractFpPoint, IFpPoint)
  strict protected
    function Detach: IECPoint; override;
    function Two(const AX: IECFieldElement): IECFieldElement; virtual;
    function Three(const AX: IECFieldElement): IECFieldElement; virtual;
    function Four(const AX: IECFieldElement): IECFieldElement; virtual;
    function Eight(const AX: IECFieldElement): IECFieldElement; virtual;
    function DoubleProductFromSquares(const AA, AB, AASquared, ABSquared: IECFieldElement): IECFieldElement; virtual;
    function CalculateJacobianModifiedW(const AZ, AZSquared: IECFieldElement): IECFieldElement; virtual;
    function GetJacobianModifiedW: IECFieldElement; virtual;
    function TwiceJacobianModified(ACalculateW: Boolean): IECPoint; virtual;
  public
    constructor Create(const ACurve: IECCurve; const AX, AY: IECFieldElement); overload;
    constructor Create(const ACurve: IECCurve; const AX, AY: IECFieldElement;
      const AZs: TCryptoLibGenericArray<IECFieldElement>); overload;
    function GetZCoord(AIndex: Int32): IECFieldElement; override;
    function Add(const AB: IECPoint): IECPoint; override;
    function Twice: IECPoint; override;
    function TwicePlus(const AB: IECPoint): IECPoint; override;
    function ThreeTimes: IECPoint; override;
    function TimesPow2(AE: Int32): IECPoint; override;
    function Negate: IECPoint; override;
  end;

  TAbstractF2mPoint = class abstract(TECPointBase, IAbstractF2mPoint)
  strict protected
    function SatisfiesOrder: Boolean; override;
  public
    function SatisfiesCurveEquation: Boolean; override;
    function ScaleX(const AScale: IECFieldElement): IECPoint; override;
    function ScaleXNegateY(const AScale: IECFieldElement): IECPoint; override;
    function ScaleY(const AScale: IECFieldElement): IECPoint; override;
    function ScaleYNegateX(const AScale: IECFieldElement): IECPoint; override;
    function Subtract(const AB: IECPoint): IECPoint; override;
    function Tau: IAbstractF2mPoint; virtual;
    function TauPow(APow: Int32): IAbstractF2mPoint; virtual;
  end;

  TF2mPoint = class sealed(TAbstractF2mPoint, IF2mPoint)
  strict protected
    function Detach: IECPoint; override;
    function GetCompressionYTilde: Boolean; override;
  public
    constructor Create(const ACurve: IECCurve; const AX, AY: IECFieldElement); overload;
    constructor Create(const ACurve: IECCurve; const AX, AY: IECFieldElement;
      const AZs: TCryptoLibGenericArray<IECFieldElement>); overload;
    function GetYCoord: IECFieldElement; override;
    function TwicePlus(const AB: IECPoint): IECPoint; override;
    function Add(const AB: IECPoint): IECPoint; override;
    function Twice: IECPoint; override;
    function Negate: IECPoint; override;
  end;

implementation

{ TECPoint.TValidityCallback }

constructor TECPoint.TValidityCallback.Create(const AOuter: IECPoint; ADecompressed,
  ACheckOrder: Boolean);
begin
  inherited Create;
  FOuter := AOuter;
  FDecompressed := ADecompressed;
  FCheckOrder := ACheckOrder;
end;

function TECPoint.TValidityCallback.Precompute(const AExisting: IPreCompInfo): IPreCompInfo;
var
  LValidity: IValidityPreCompInfo;
begin
  if not Supports(AExisting, IValidityPreCompInfo, LValidity) then
    LValidity := TValidityPreCompInfo.Create;
  if LValidity.HasFailed then
    Exit(LValidity);
  if not LValidity.HasCurveEquationPassed then
  begin
    if (not FDecompressed) and (not FOuter.SatisfiesCurveEquation) then
    begin
      LValidity.ReportFailed;
      Exit(LValidity);
    end;
    LValidity.ReportCurveEquationPassed;
  end;
  if FCheckOrder and (not LValidity.HasOrderPassed) then
  begin
    if not FOuter.SatisfiesOrder then
    begin
      LValidity.ReportFailed;
      Exit(LValidity);
    end;
    LValidity.ReportOrderPassed;
  end;
  Result := LValidity;
end;

{ TECPoint }

class function TECPoint.GetInitialZCoords(const ACurve: IECCurve): TCryptoLibGenericArray<IECFieldElement>;
var
  LCoord: Int32;
  LOne: IECFieldElement;
begin
  if ACurve = nil then
    LCoord := TECCurveConstants.COORD_AFFINE
  else
    LCoord := ACurve.CoordinateSystem;

  case LCoord of
    TECCurveConstants.COORD_AFFINE, TECCurveConstants.COORD_LAMBDA_AFFINE:
      SetLength(Result, 0);
  else
    begin
      LOne := ACurve.FromBigInteger(TBigInteger.One);
      case LCoord of
        TECCurveConstants.COORD_HOMOGENEOUS, TECCurveConstants.COORD_JACOBIAN, TECCurveConstants.COORD_LAMBDA_PROJECTIVE:
          Result := TCryptoLibGenericArray<IECFieldElement>.Create(LOne);
        TECCurveConstants.COORD_JACOBIAN_CHUDNOVSKY:
          Result := TCryptoLibGenericArray<IECFieldElement>.Create(LOne, LOne, LOne);
        TECCurveConstants.COORD_JACOBIAN_MODIFIED:
          Result := TCryptoLibGenericArray<IECFieldElement>.Create(LOne, ACurve.A);
      else
        raise EArgumentCryptoLibException.Create(SUnknownCoordinateSystem);
      end;
    end;
  end;
end;

constructor TECPoint.Create(const ACurve: IECCurve; const AX, AY: IECFieldElement);
begin
  Create(ACurve, AX, AY, GetInitialZCoords(ACurve));
end;

constructor TECPoint.Create(const ACurve: IECCurve; const AX, AY: IECFieldElement;
  const AZs: TCryptoLibGenericArray<IECFieldElement>);
begin
  Inherited Create;
  FPreCompTable := nil;
  FPointLock := TCriticalSection.Create;
  FTableLock := TCriticalSection.Create;
  FCurve := ACurve;
  FX := AX;
  FY := AY;
  FZs := AZs;
end;

destructor TECPoint.Destroy;
begin
  FPreCompTable.Free;
  FTableLock.Free;
  FPointLock.Free;
  inherited;
end;

function TECPoint.GetCurveCoordinateSystem: Int32;
begin
  if FCurve = nil then
    Result := TECCurveConstants.COORD_AFFINE
  else
    Result := FCurve.CoordinateSystem;
end;

function TECPoint.GetRawXCoord: IECFieldElement;
begin
  Result := FX;
end;

function TECPoint.GetRawYCoord: IECFieldElement;
begin
  Result := FY;
end;

function TECPoint.GetRawZCoords: TCryptoLibGenericArray<IECFieldElement>;
begin
  Result := FZs;
end;

function TECPoint.GetCurve: IECCurve;
begin
  Result := FCurve;
end;

function TECPoint.GetIsInfinity: Boolean;
begin
  Result := (FX = nil) and (FY = nil);
end;

function TECPoint.GetXCoord: IECFieldElement;
begin
  Result := FX;
end;

function TECPoint.GetYCoord: IECFieldElement;
begin
  Result := FY;
end;

function TECPoint.GetZCoord(AIndex: Int32): IECFieldElement;
begin
  if (AIndex < 0) or (AIndex >= System.Length(FZs)) then
    Result := nil
  else
    Result := FZs[AIndex];
end;

function TECPoint.GetZCoords: TCryptoLibGenericArray<IECFieldElement>;
var
  LZsLen, I: Int32;
begin
  LZsLen := System.Length(FZs);
  if LZsLen = 0 then
    Result := FZs
  else
  begin
    SetLength(Result, LZsLen);
    for I := 0 to System.Pred(LZsLen) do
      Result[I] := FZs[I];
  end;
end;

procedure TECPoint.CheckNormalized;
begin
  if not IsNormalized then
    raise EInvalidOperationCryptoLibException.Create(SPointNotInNormalForm);
end;

function TECPoint.IsNormalized: Boolean;
var
  LCoord: Int32;
begin
  LCoord := GetCurveCoordinateSystem();
  Result := (LCoord = TECCurveConstants.COORD_AFFINE) or (LCoord = TECCurveConstants.COORD_LAMBDA_AFFINE) or
    IsInfinity or RawZCoords[0].IsOne;
end;

function TECPoint.SatisfiesOrder: Boolean;
var
  LOrder: TBigInteger;
  LMult: IECPoint;
begin
  if TBigInteger.One.Equals(FCurve.Cofactor) then
    Exit(True);
  LOrder := FCurve.Order;
  if LOrder.Equals(TBigInteger.GetDefault()) then
    Exit(True);
  LMult := TECAlgorithms.ReferenceMultiply(Self as IECPoint, LOrder);
  Result := LMult.IsInfinity;
end;

function TECPoint.CreateScaledPoint(const ASx, ASy: IECFieldElement): IECPoint;
begin
  Result := FCurve.CreateRawPoint(RawXCoord.Multiply(ASx), RawYCoord.Multiply(ASy));
end;

function TECPoint.Normalize(const AZInv: IECFieldElement): IECPoint;
var
  LCoord: Int32;
  LZInv2, LZInv3: IECFieldElement;
begin
  LCoord := GetCurveCoordinateSystem();
  case LCoord of
    TECCurveConstants.COORD_HOMOGENEOUS, TECCurveConstants.COORD_LAMBDA_PROJECTIVE:
      Result := CreateScaledPoint(AZInv, AZInv);
    TECCurveConstants.COORD_JACOBIAN, TECCurveConstants.COORD_JACOBIAN_CHUDNOVSKY, TECCurveConstants.COORD_JACOBIAN_MODIFIED:
      begin
        LZInv2 := AZInv.Square();
        LZInv3 := LZInv2.Multiply(AZInv);
        Result := CreateScaledPoint(LZInv2, LZInv3);
      end;
  else
    raise EInvalidOperationCryptoLibException.Create(SNotAProjectiveCoordinateSystem);
  end;
end;

function TECPoint.Normalize: IECPoint;
var
  LCoord: Int32;
  LZ: IECFieldElement;
  LB, LZInv: IECFieldElement;
begin
  if IsInfinity then
    Exit(Self as IECPoint);

  LCoord := GetCurveCoordinateSystem();
  case LCoord of
    TECCurveConstants.COORD_AFFINE, TECCurveConstants.COORD_LAMBDA_AFFINE:
      Result := Self as IECPoint;
  else
    begin
      LZ := RawZCoords[0];
      if LZ.IsOne then
        Exit(Self as IECPoint);

      if FCurve = nil then
        raise EInvalidOperationCryptoLibException.Create(SDetachedPointsMustBeInAffine);

      LB := FCurve.RandomFieldElementMult(TSecureRandom.MasterRandom);
      LZInv := LZ.Multiply(LB).Invert().Multiply(LB);
      Result := Normalize(LZInv);
    end;
  end;
end;

function TECPoint.GetDetachedPoint: IECPoint;
begin
  Result := Normalize().Detach;
end;

function TECPoint.GetPreCompInfo(const AName: String): IPreCompInfo;
var
  LTable: TDictionary<String, IPreCompInfo>;
begin
  FPointLock.Enter;
  try
    LTable := FPreCompTable;
  finally
    FPointLock.Leave;
  end;

  if LTable = nil then
    Exit(nil);

  FTableLock.Enter;
  try
    if not LTable.TryGetValue(AName, Result) then
      Result := nil;
  finally
    FTableLock.Leave;
  end;
end;

function TECPoint.Precompute(const AName: String; const ACallback: IPreCompCallback): IPreCompInfo;
var
  LTable: TDictionary<String, IPreCompInfo>;
  LExisting: IPreCompInfo;
begin
  FPointLock.Enter;
  try
    LTable := FPreCompTable;
    if LTable = nil then
    begin
      LTable := TDictionary<String, IPreCompInfo>.Create();
      FPreCompTable := LTable;
    end;
  finally
    FPointLock.Leave;
  end;

  FTableLock.Enter;
  try
    if not LTable.TryGetValue(AName, LExisting) then
      LExisting := nil;
    Result := ACallback.Precompute(LExisting);
    if Result <> LExisting then
      LTable.AddOrSetValue(AName, Result);
  finally
    FTableLock.Leave;
  end;
end;

function TECPoint.GetAffineXCoord: IECFieldElement;
begin
  CheckNormalized();
  Result := XCoord;
end;

function TECPoint.GetAffineYCoord: IECFieldElement;
begin
  CheckNormalized();
  Result := YCoord;
end;

function TECPoint.GetEncoded: TCryptoLibByteArray;
begin
  Result := GetEncoded(False);
end;

{ TECPointBase }

constructor TECPointBase.Create(const ACurve: IECCurve; const AX, AY: IECFieldElement);
begin
  inherited Create(ACurve, AX, AY);
end;

constructor TECPointBase.Create(const ACurve: IECCurve; const AX, AY: IECFieldElement;
  const AZs: TCryptoLibGenericArray<IECFieldElement>);
begin
  inherited Create(ACurve, AX, AY, AZs);
end;

function TECPointBase.GetEncoded(ACompressed: Boolean): TCryptoLibByteArray;
var
  LNormed: IECPoint;
  LX, LY: TCryptoLibByteArray;
  LLen: Int32;
begin
  if IsInfinity then
  begin
    System.SetLength(Result, 1);
    Result[0] := $00;
    Exit;
  end;
  LNormed := Normalize();
  LX := LNormed.XCoord.GetEncoded();
  if ACompressed then
  begin
    System.SetLength(Result, 1 + System.Length(LX));
    Result[0] := $02;
    if LNormed.GetCompressionYTilde then
      Result[0] := $03;
    System.Move(LX[0], Result[1], System.Length(LX) * System.SizeOf(Byte));
    Exit;
  end;
  LY := LNormed.YCoord.GetEncoded();
  LLen := 1 + System.Length(LX) + System.Length(LY);
  System.SetLength(Result, LLen);
  Result[0] := $04;
  System.Move(LX[0], Result[1], System.Length(LX) * System.SizeOf(Byte));
  System.Move(LY[0], Result[1 + System.Length(LX)], System.Length(LY) * System.SizeOf(Byte));
end;

function TECPointBase.GetEncodedLength(ACompressed: Boolean): Int32;
begin
  if IsInfinity then
    Exit(1);
  if ACompressed then
    Exit(1 + XCoord.GetEncodedLength())
  else
    Exit(1 + XCoord.GetEncodedLength() + YCoord.GetEncodedLength());
end;

procedure TECPointBase.EncodeTo(ACompressed: Boolean; var ABuf: TCryptoLibByteArray; AOff: Int32);
var
  LNormed: IECPoint;
  LXLen: Int32;
begin
  if IsInfinity then
  begin
    ABuf[AOff] := $00;
    Exit;
  end;
  LNormed := Normalize();
  if ACompressed then
  begin
    ABuf[AOff] := $02;
    if LNormed.GetCompressionYTilde then
      ABuf[AOff] := $03;
    LNormed.XCoord.EncodeTo(ABuf, AOff + 1);
    Exit;
  end;
  ABuf[AOff] := $04;
  LXLen := LNormed.XCoord.GetEncodedLength();
  LNormed.XCoord.EncodeTo(ABuf, AOff + 1);
  LNormed.YCoord.EncodeTo(ABuf, AOff + 1 + LXLen);
end;

function TECPointBase.Multiply(const AK: TBigInteger): IECPoint;
begin
  Result := FCurve.Multiplier.Multiply(Self as IECPoint, AK);
end;

function TECPoint.TimesPow2(AE: Int32): IECPoint;
var
  P: IECPoint;
begin
  if AE < 0 then
    raise EArgumentCryptoLibException.Create(SInvalidTimesPow2Exponent);
  P := Self as IECPoint;
  while AE > 0 do
  begin
    Dec(AE);
    P := P.Twice();
  end;
  Result := P;
end;

function TECPoint.TwicePlus(const AB: IECPoint): IECPoint;
begin
  Result := Twice().Add(AB);
end;

function TECPoint.ThreeTimes: IECPoint;
begin
  Result := TwicePlus(Self as IECPoint);
end;

function TECPoint.ImplIsValid(ADecompressed, ACheckOrder: Boolean): Boolean;
var
  LCallback: IPreCompCallback;
  LValidity: IValidityPreCompInfo;
  LResult: IPreCompInfo;
begin
  if IsInfinity then
    Exit(True);
  LCallback := TValidityCallback.Create(Self, ADecompressed, ACheckOrder);
  LResult := FCurve.Precompute(Self as IECPoint, TValidityPreCompInfo.PRECOMP_NAME, LCallback);
  LValidity := LResult as IValidityPreCompInfo;
  Result := not LValidity.HasFailed;
end;

function TECPoint.IsValid: Boolean;
begin
  Result := ImplIsValid(False, True);
end;

function TECPoint.IsValidPartial: Boolean;
begin
  Result := ImplIsValid(False, False);
end;

function TECPoint.ScaleX(const AScale: IECFieldElement): IECPoint;
begin
  if IsInfinity then
    Result := Self as IECPoint
  else
    Result := FCurve.CreateRawPoint(RawXCoord.Multiply(AScale), RawYCoord, RawZCoords);
end;

function TECPoint.ScaleXNegateY(const AScale: IECFieldElement): IECPoint;
begin
  if IsInfinity then
    Result := Self as IECPoint
  else
    Result := FCurve.CreateRawPoint(RawXCoord.Multiply(AScale), RawYCoord.Negate(), RawZCoords);
end;

function TECPoint.ScaleY(const AScale: IECFieldElement): IECPoint;
begin
  if IsInfinity then
    Result := Self as IECPoint
  else
    Result := FCurve.CreateRawPoint(RawXCoord, RawYCoord.Multiply(AScale), RawZCoords);
end;

function TECPoint.ScaleYNegateX(const AScale: IECFieldElement): IECPoint;
begin
  if IsInfinity then
    Result := Self as IECPoint
  else
    Result := FCurve.CreateRawPoint(RawXCoord.Negate(), RawYCoord.Multiply(AScale), RawZCoords);
end;

function TECPoint.Equals(const AOther: IECPoint): Boolean;
var
  LC1, LC2: IECCurve;
  LN1, LN2, LI1, LI2: Boolean;
  LP1, LP2: IECPoint;
  LPoints: TCryptoLibGenericArray<IECPoint>;
begin
  if AOther = nil then
    Exit(False);
  if (Self as IECPoint) = AOther then
    Exit(True);

  LC1 := Curve;
  LC2 := AOther.Curve;
  LN1 := LC1 = nil;
  LN2 := LC2 = nil;
  LI1 := IsInfinity;
  LI2 := AOther.IsInfinity;

  if LI1 or LI2 then
    Exit((LI1 and LI2) and (LN1 or LN2 or LC1.Equals(LC2)));

  LP1 := Self as IECPoint;
  LP2 := AOther;

  if LN1 and LN2 then
    { points with null curve are in affine form }
  else if LN1 then
    LP2 := LP2.Normalize()
  else if LN2 then
    LP1 := LP1.Normalize()
  else if not LC1.Equals(LC2) then
    Exit(False)
  else
  begin
    LPoints := TCryptoLibGenericArray<IECPoint>.Create(LP1, LC1.ImportPoint(LP2));
    LC1.NormalizeAll(LPoints);
    LP1 := LPoints[0];
    LP2 := LPoints[1];
  end;

  Result := LP1.XCoord.Equals(LP2.XCoord) and LP1.YCoord.Equals(LP2.YCoord);
end;

function TECPoint.GetHashCode: {$IFDEF DELPHI}Int32{$ELSE}PtrInt{$ENDIF};
var
  LC: IECCurve;
  LP: IECPoint;
begin
  LC := GetCurve();
  if LC = nil then
    Result := 0
  else
    Result := not LC.GetHashCode();

  if not IsInfinity then
  begin
    LP := Normalize();
    Result := Result xor ((LP.XCoord.GetHashCode()) * 17);
    Result := Result xor ((LP.YCoord.GetHashCode()) * 257);
  end;
end;

function TECPoint.ToString: String;
var
  I: Int32;
begin
  if IsInfinity then
    Exit('INF');

  Result := '(' + RawXCoord.ToString() + ',' + RawYCoord.ToString();
  for I := 0 to System.High(FZs) do
    Result := Result + ',' + FZs[I].ToString();
  Result := Result + ')';
end;

{ TAbstractFpPoint }

function TAbstractFpPoint.GetCompressionYTilde: Boolean;
begin
  Result := GetAffineYCoord.TestBitZero();
end;

function TAbstractFpPoint.SatisfiesCurveEquation: Boolean;
var
  LCoord: Int32;
  X, Y, A, B, Lhs, Rhs: IECFieldElement;
  Z, Z2, Z3, Z4, Z6: IECFieldElement;
begin
  X := RawXCoord;
  Y := RawYCoord;
  A := FCurve.A;
  B := FCurve.B;
  Lhs := Y.Square();
  LCoord := GetCurveCoordinateSystem();
  case LCoord of
    TECCurveConstants.COORD_AFFINE:
      ;
    TECCurveConstants.COORD_HOMOGENEOUS:
      begin
        Z := RawZCoords[0];
        if not Z.IsOne then
        begin
          Z2 := Z.Square();
          Z3 := Z2.Multiply(Z);
          Lhs := Lhs.Multiply(Z);
          A := A.Multiply(Z2);
          B := B.Multiply(Z3);
        end;
      end;
    TECCurveConstants.COORD_JACOBIAN, TECCurveConstants.COORD_JACOBIAN_CHUDNOVSKY, TECCurveConstants.COORD_JACOBIAN_MODIFIED:
      begin
        Z := RawZCoords[0];
        if not Z.IsOne then
        begin
          Z2 := Z.Square();
          Z4 := Z2.Square();
          Z6 := Z2.Multiply(Z4);
          A := A.Multiply(Z4);
          B := B.Multiply(Z6);
        end;
      end;
  else
    raise EInvalidOperationCryptoLibException.Create(SUnsupportedCoordinateSystem);
  end;
  Rhs := X.Square().Add(A).Multiply(X).Add(B);
  Result := Lhs.Equals(Rhs);
end;

function TAbstractFpPoint.Subtract(const AB: IECPoint): IECPoint;
begin
  if AB.IsInfinity then
    Exit(Self as IECPoint);
  Result := Add(AB.Negate());
end;

{ TFpPoint }

constructor TFpPoint.Create(const ACurve: IECCurve; const AX, AY: IECFieldElement);
begin
  inherited Create(ACurve, AX, AY);
  if (AX = nil) <> (AY = nil) then
    raise EArgumentCryptoLibException.Create('Exactly one of the field elements is null');
end;

constructor TFpPoint.Create(const ACurve: IECCurve; const AX, AY: IECFieldElement;
  const AZs: TCryptoLibGenericArray<IECFieldElement>);
begin
  inherited Create(ACurve, AX, AY, AZs);
end;

function TFpPoint.Detach: IECPoint;
begin
  Result := TFpPoint.Create(nil, GetAffineXCoord, GetAffineYCoord);
end;

function TFpPoint.GetZCoord(AIndex: Int32): IECFieldElement;
begin
  if (AIndex = 1) and (TECCurveConstants.COORD_JACOBIAN_MODIFIED = GetCurveCoordinateSystem()) then
    Exit(GetJacobianModifiedW());
  Result := inherited GetZCoord(AIndex);
end;

function TFpPoint.Two(const AX: IECFieldElement): IECFieldElement;
begin
  Result := AX.Add(AX);
end;

function TFpPoint.Three(const AX: IECFieldElement): IECFieldElement;
begin
  Result := Two(AX).Add(AX);
end;

function TFpPoint.Four(const AX: IECFieldElement): IECFieldElement;
begin
  Result := Two(Two(AX));
end;

function TFpPoint.Eight(const AX: IECFieldElement): IECFieldElement;
begin
  Result := Four(Two(AX));
end;

function TFpPoint.DoubleProductFromSquares(const AA, AB, AASquared, ABSquared: IECFieldElement): IECFieldElement;
begin
  Result := AA.Add(AB).Square().Subtract(AASquared).Subtract(ABSquared);
end;

function TFpPoint.CalculateJacobianModifiedW(const AZ, AZSquared: IECFieldElement): IECFieldElement;
var
  La4, La4Neg, LW, LZSq: IECFieldElement;
begin
  La4 := FCurve.A;
  if La4.IsZero or AZ.IsOne then
    Exit(La4);

  LZSq := AZSquared;
  if LZSq = nil then
    LZSq := AZ.Square();

  LW := LZSq.Square();
  La4Neg := La4.Negate();
  if La4Neg.GetBitLength < La4.GetBitLength then
    LW := LW.Multiply(La4Neg).Negate()
  else
    LW := LW.Multiply(La4);
  Result := LW;
end;

function TFpPoint.GetJacobianModifiedW: IECFieldElement;
var
  LZZ: TCryptoLibGenericArray<IECFieldElement>;
  LW: IECFieldElement;
begin
  LZZ := RawZCoords;
  LW := LZZ[1];
  if LW = nil then
  begin
    // NOTE: Rarely, TwicePlus will result in the need for a lazy W1 calculation here
    LW := CalculateJacobianModifiedW(LZZ[0], nil);
    LZZ[1] := LW;
  end;
  Result := LW;
end;

function TFpPoint.TwiceJacobianModified(ACalculateW: Boolean): IECPoint;
var
  X1, Y1, Z1, W1: IECFieldElement;
  X1Squared, M, L2Y1, L2Y1Squared, S, X3, L4T, L8T, Y3, W3, Z3: IECFieldElement;
begin
  X1 := RawXCoord;
  Y1 := RawYCoord;
  Z1 := RawZCoords[0];
  W1 := GetJacobianModifiedW();

  X1Squared := X1.Square();
  M := Three(X1Squared).Add(W1);
  L2Y1 := Two(Y1);
  L2Y1Squared := L2Y1.Multiply(Y1);
  S := Two(X1.Multiply(L2Y1Squared));
  X3 := M.Square().Subtract(Two(S));
  L4T := L2Y1Squared.Square();
  L8T := Two(L4T);
  Y3 := M.Multiply(S.Subtract(X3)).Subtract(L8T);
  if ACalculateW then
    W3 := Two(L8T.Multiply(W1))
  else
    W3 := nil;
  if Z1.IsOne then
    Z3 := L2Y1
  else
    Z3 := L2Y1.Multiply(Z1);

  Result := TFpPoint.Create(FCurve, X3, Y3,
    TCryptoLibGenericArray<IECFieldElement>.Create(Z3, W3));
end;

function TFpPoint.Add(const AB: IECPoint): IECPoint;
var
  LCurve: IECCurve;
  LCoord: Int32;
  X1, Y1, X2, Y2, Dx, Dy, Gamma, X3, Y3, Z3: IECFieldElement;
  Z1, Z2, LU1, LU2, LV1, LV2, LU, LV, LW: IECFieldElement;
  LVSquared, LVCubed, LVSquaredV2, LA: IECFieldElement;
  LZ1IsOne, LZ2IsOne: Boolean;
  LZ1Squared, LS2, LZ2Squared, LS1, LH, LR: IECFieldElement;
  LHSquared, LG: IECFieldElement;
  LZ1Cubed, LZ2Cubed, LU2b, LS2b, LU1b, LS1b: IECFieldElement;
  LC, LW1, LW2b, LA1: IECFieldElement;
  LZ3Squared, LW3: IECFieldElement;
  LZs: TCryptoLibGenericArray<IECFieldElement>;
begin
  if IsInfinity then
    Exit(AB);
  if AB.IsInfinity then
    Exit(Self as IECPoint);
  if (Self as IECPoint) = AB then
    Exit(Twice());

  LCurve := FCurve;
  LCoord := GetCurveCoordinateSystem();
  X1 := RawXCoord;
  Y1 := RawYCoord;
  X2 := AB.RawXCoord;
  Y2 := AB.RawYCoord;

  case LCoord of
    TECCurveConstants.COORD_AFFINE:
    begin
      Dx := X2.Subtract(X1);
      Dy := Y2.Subtract(Y1);
      if Dx.IsZero then
      begin
        if Dy.IsZero then
          Exit(Twice());
        Exit(LCurve.Infinity);
      end;
      Gamma := Dy.Divide(Dx);
      X3 := Gamma.Square().Subtract(X1).Subtract(X2);
      Y3 := Gamma.Multiply(X1.Subtract(X3)).Subtract(Y1);
      Result := TFpPoint.Create(LCurve, X3, Y3);
    end;

    TECCurveConstants.COORD_HOMOGENEOUS:
    begin
      Z1 := RawZCoords[0];
      Z2 := AB.GetZCoord(0);

      LZ1IsOne := Z1.IsOne;
      LZ2IsOne := Z2.IsOne;

      if LZ1IsOne then LU1 := Y2 else LU1 := Y2.Multiply(Z1);
      if LZ2IsOne then LU2 := Y1 else LU2 := Y1.Multiply(Z2);
      LU := LU1.Subtract(LU2);
      if LZ1IsOne then LV1 := X2 else LV1 := X2.Multiply(Z1);
      if LZ2IsOne then LV2 := X1 else LV2 := X1.Multiply(Z2);
      LV := LV1.Subtract(LV2);

      // Check if b == this or b == -this
      if LV.IsZero then
      begin
        if LU.IsZero then
          Exit(Twice());
        Exit(LCurve.Infinity);
      end;

      // TODO Optimize for when w == 1
      if LZ1IsOne then LW := Z2
      else if LZ2IsOne then LW := Z1
      else LW := Z1.Multiply(Z2);

      LVSquared := LV.Square();
      LVCubed := LVSquared.Multiply(LV);
      LVSquaredV2 := LVSquared.Multiply(LV2);
      LA := LU.Square().Multiply(LW).Subtract(LVCubed).Subtract(Two(LVSquaredV2));

      X3 := LV.Multiply(LA);
      Y3 := LVSquaredV2.Subtract(LA).MultiplyMinusProduct(LU, LU2, LVCubed);
      Z3 := LVCubed.Multiply(LW);

      Result := TFpPoint.Create(LCurve, X3, Y3,
        TCryptoLibGenericArray<IECFieldElement>.Create(Z3));
    end;

    TECCurveConstants.COORD_JACOBIAN,
    TECCurveConstants.COORD_JACOBIAN_MODIFIED:
    begin
      Z1 := RawZCoords[0];
      Z2 := AB.GetZCoord(0);

      LZ1IsOne := Z1.IsOne;

      X3 := nil;
      Y3 := nil;
      Z3 := nil;
      LZ3Squared := nil;

      if (not LZ1IsOne) and Z1.Equals(Z2) then
      begin
        // coZ addition
        Dx := X1.Subtract(X2);
        Dy := Y1.Subtract(Y2);
        if Dx.IsZero then
        begin
          if Dy.IsZero then
            Exit(Twice());
          Exit(LCurve.Infinity);
        end;

        LC := Dx.Square();
        LW1 := X1.Multiply(LC);
        LW2b := X2.Multiply(LC);
        LA1 := LW1.Subtract(LW2b).Multiply(Y1);

        X3 := Dy.Square().Subtract(LW1).Subtract(LW2b);
        Y3 := LW1.Subtract(X3).Multiply(Dy).Subtract(LA1);
        Z3 := Dx;

        if LZ1IsOne then
          LZ3Squared := LC
        else
          Z3 := Z3.Multiply(Z1);
      end
      else
      begin
        if LZ1IsOne then
        begin
          LZ1Squared := Z1;
          LU2b := X2;
          LS2b := Y2;
        end
        else
        begin
          LZ1Squared := Z1.Square();
          LU2b := LZ1Squared.Multiply(X2);
          LZ1Cubed := LZ1Squared.Multiply(Z1);
          LS2b := LZ1Cubed.Multiply(Y2);
        end;

        LZ2IsOne := Z2.IsOne;
        if LZ2IsOne then
        begin
          LZ2Squared := Z2;
          LU1b := X1;
          LS1b := Y1;
        end
        else
        begin
          LZ2Squared := Z2.Square();
          LU1b := LZ2Squared.Multiply(X1);
          LZ2Cubed := LZ2Squared.Multiply(Z2);
          LS1b := LZ2Cubed.Multiply(Y1);
        end;

        LH := LU1b.Subtract(LU2b);
        LR := LS1b.Subtract(LS2b);

        // Check if b == this or b == -this
        if LH.IsZero then
        begin
          if LR.IsZero then
            Exit(Twice());
          Exit(LCurve.Infinity);
        end;

        LHSquared := LH.Square();
        LG := LHSquared.Multiply(LH);
        LV2 := LHSquared.Multiply(LU1b);

        X3 := LR.Square().Add(LG).Subtract(Two(LV2));
        Y3 := LV2.Subtract(X3).MultiplyMinusProduct(LR, LG, LS1b);

        Z3 := LH;
        if not LZ1IsOne then
          Z3 := Z3.Multiply(Z1);
        if not LZ2IsOne then
          Z3 := Z3.Multiply(Z2);

        if Z3 = LH then
          LZ3Squared := LHSquared;
      end;

      if LCoord = TECCurveConstants.COORD_JACOBIAN_MODIFIED then
      begin
        // TODO If the result will only be used in a subsequent addition, we don't need W3
        LW3 := CalculateJacobianModifiedW(Z3, LZ3Squared);
        LZs := TCryptoLibGenericArray<IECFieldElement>.Create(Z3, LW3);
      end
      else
      begin
        LZs := TCryptoLibGenericArray<IECFieldElement>.Create(Z3);
      end;

      Result := TFpPoint.Create(LCurve, X3, Y3, LZs);
    end;
  else
    raise EInvalidOperationCryptoLibException.Create(SUnsupportedCoordinateSystem);
  end;
end;

function TFpPoint.Twice: IECPoint;
var
  LCurve: IECCurve;
  LCoord: Int32;
  X1, Y1, X3, Y3, Z3: IECFieldElement;
  X1Squared, Gamma: IECFieldElement;
  Z1, LW, LS, LT, LB, L4B, LH, L2S, L2T, L4SSquared: IECFieldElement;
  LZ1IsOne: Boolean;
  LY1Squared, LT2, La4, La4Neg, LM: IECFieldElement;
  LZ1Squared, LZ1Pow4: IECFieldElement;
begin
  if IsInfinity then
    Exit(Self as IECPoint);

  Y1 := RawYCoord;
  if Y1.IsZero then
    Exit(FCurve.Infinity);

  LCurve := FCurve;
  LCoord := GetCurveCoordinateSystem();
  X1 := RawXCoord;

  case LCoord of
    TECCurveConstants.COORD_AFFINE:
    begin
      X1Squared := X1.Square();
      Gamma := Three(X1Squared).Add(LCurve.A).Divide(Two(Y1));
      X3 := Gamma.Square().Subtract(Two(X1));
      Y3 := Gamma.Multiply(X1.Subtract(X3)).Subtract(Y1);
      Result := TFpPoint.Create(LCurve, X3, Y3);
    end;

    TECCurveConstants.COORD_HOMOGENEOUS:
    begin
      Z1 := RawZCoords[0];
      LZ1IsOne := Z1.IsOne;

      // TODO Optimize for small negative a4 and -3
      LW := LCurve.A;
      if (not LW.IsZero) and (not LZ1IsOne) then
        LW := LW.Multiply(Z1.Square());
      LW := LW.Add(Three(X1.Square()));

      if LZ1IsOne then LS := Y1 else LS := Y1.Multiply(Z1);
      if LZ1IsOne then LT := Y1.Square() else LT := LS.Multiply(Y1);
      LB := X1.Multiply(LT);
      L4B := Four(LB);
      LH := LW.Square().Subtract(Two(L4B));

      L2S := Two(LS);
      X3 := LH.Multiply(L2S);
      L2T := Two(LT);
      Y3 := L4B.Subtract(LH).Multiply(LW).Subtract(Two(L2T.Square()));
      if LZ1IsOne then L4SSquared := Two(L2T) else L4SSquared := L2S.Square();
      Z3 := Two(L4SSquared).Multiply(LS);

      Result := TFpPoint.Create(LCurve, X3, Y3,
        TCryptoLibGenericArray<IECFieldElement>.Create(Z3));
    end;

    TECCurveConstants.COORD_JACOBIAN:
    begin
      Z1 := RawZCoords[0];
      LZ1IsOne := Z1.IsOne;

      LY1Squared := Y1.Square();
      LT2 := LY1Squared.Square();

      La4 := LCurve.A;
      La4Neg := La4.Negate();

      if La4Neg.ToBigInteger().Equals(TBigInteger.Three) then
      begin
        if LZ1IsOne then LZ1Squared := Z1 else LZ1Squared := Z1.Square();
        LM := Three(X1.Add(LZ1Squared).Multiply(X1.Subtract(LZ1Squared)));
        LS := Four(LY1Squared.Multiply(X1));
      end
      else
      begin
        X1Squared := X1.Square();
        LM := Three(X1Squared);
        if LZ1IsOne then
        begin
          LM := LM.Add(La4);
        end
        else if not La4.IsZero then
        begin
          if LZ1IsOne then LZ1Squared := Z1 else LZ1Squared := Z1.Square();
          LZ1Pow4 := LZ1Squared.Square();
          if La4Neg.GetBitLength < La4.GetBitLength then
            LM := LM.Subtract(LZ1Pow4.Multiply(La4Neg))
          else
            LM := LM.Add(LZ1Pow4.Multiply(La4));
        end;
        LS := Four(X1.Multiply(LY1Squared));
      end;

      X3 := LM.Square().Subtract(Two(LS));
      Y3 := LS.Subtract(X3).Multiply(LM).Subtract(Eight(LT2));

      Z3 := Two(Y1);
      if not LZ1IsOne then
        Z3 := Z3.Multiply(Z1);

      Result := TFpPoint.Create(LCurve, X3, Y3,
        TCryptoLibGenericArray<IECFieldElement>.Create(Z3));
    end;

    TECCurveConstants.COORD_JACOBIAN_MODIFIED:
    begin
      Result := TwiceJacobianModified(True);
    end;
  else
    raise EInvalidOperationCryptoLibException.Create(SUnsupportedCoordinateSystem);
  end;
end;

function TFpPoint.TwicePlus(const AB: IECPoint): IECPoint;
var
  LCurve: IECCurve;
  LCoord: Int32;
  X1, Y1, X2, Y2, Dx, Dy: IECFieldElement;
  LX, LY, Ld, LBigD, LI, LL1, LL2, X4, Y4: IECFieldElement;
begin
  if (Self as IECPoint) = AB then
    Exit(ThreeTimes());
  if IsInfinity then
    Exit(AB);
  if AB.IsInfinity then
    Exit(Twice());

  Y1 := RawYCoord;
  if Y1.IsZero then
    Exit(AB);

  LCurve := FCurve;
  LCoord := GetCurveCoordinateSystem();

  case LCoord of
    TECCurveConstants.COORD_AFFINE:
    begin
      X1 := RawXCoord;
      X2 := AB.RawXCoord;
      Y2 := AB.RawYCoord;

      Dx := X2.Subtract(X1);
      Dy := Y2.Subtract(Y1);

      if Dx.IsZero then
      begin
        if Dy.IsZero then
          Exit(ThreeTimes());
        Exit(Self as IECPoint);
      end;

      LX := Dx.Square();
      LY := Dy.Square();
      Ld := LX.Multiply(Two(X1).Add(X2)).Subtract(LY);
      if Ld.IsZero then
        Exit(LCurve.Infinity);

      LBigD := Ld.Multiply(Dx);
      LI := LBigD.Invert();
      LL1 := Ld.Multiply(LI).Multiply(Dy);
      LL2 := Two(Y1).Multiply(LX).Multiply(Dx).Multiply(LI).Subtract(LL1);
      X4 := LL2.Subtract(LL1).Multiply(LL1.Add(LL2)).Add(X2);
      Y4 := X1.Subtract(X4).Multiply(LL2).Subtract(Y1);

      Result := TFpPoint.Create(LCurve, X4, Y4);
    end;

    TECCurveConstants.COORD_JACOBIAN_MODIFIED:
    begin
      Result := TwiceJacobianModified(False).Add(AB);
    end;
  else
    Result := Twice().Add(AB);
  end;
end;

function TFpPoint.ThreeTimes: IECPoint;
var
  LCurve: IECCurve;
  LCoord: Int32;
  X1, Y1: IECFieldElement;
  L2Y1, LX, LZ, LY, Ld, LBigD, LI, LL1, LL2, X4, Y4: IECFieldElement;
begin
  if IsInfinity then
    Exit(Self as IECPoint);

  Y1 := RawYCoord;
  if Y1.IsZero then
    Exit(Self as IECPoint);

  LCurve := FCurve;
  LCoord := GetCurveCoordinateSystem();

  case LCoord of
    TECCurveConstants.COORD_AFFINE:
    begin
      X1 := RawXCoord;

      L2Y1 := Two(Y1);
      LX := L2Y1.Square();
      LZ := Three(X1.Square()).Add(LCurve.A);
      LY := LZ.Square();

      Ld := Three(X1).Multiply(LX).Subtract(LY);
      if Ld.IsZero then
        Exit(LCurve.Infinity);

      LBigD := Ld.Multiply(L2Y1);
      LI := LBigD.Invert();
      LL1 := Ld.Multiply(LI).Multiply(LZ);
      LL2 := LX.Square().Multiply(LI).Subtract(LL1);

      X4 := LL2.Subtract(LL1).Multiply(LL1.Add(LL2)).Add(X1);
      Y4 := X1.Subtract(X4).Multiply(LL2).Subtract(Y1);
      Result := TFpPoint.Create(LCurve, X4, Y4);
    end;

    TECCurveConstants.COORD_JACOBIAN_MODIFIED:
    begin
      Result := TwiceJacobianModified(False).Add(Self as IECPoint);
    end;
  else
    // NOTE: Be careful about recursions between TwicePlus and ThreeTimes
    Result := Twice().Add(Self as IECPoint);
  end;
end;

function TFpPoint.TimesPow2(AE: Int32): IECPoint;
var
  LCurve: IECCurve;
  LCoord, I: Int32;
  Y1, X1, Z1, W1: IECFieldElement;
  LZ1Sq: IECFieldElement;
  X1Squared, LM, L2Y1, L2Y1Squared, LS, L4T, L8T: IECFieldElement;
  LZInv, LZInv2, LZInv3: IECFieldElement;
begin
  if AE < 0 then
    raise EArgumentCryptoLibException.Create('cannot be negative');
  if (AE = 0) or IsInfinity then
    Exit(Self as IECPoint);
  if AE = 1 then
    Exit(Twice());

  LCurve := FCurve;

  Y1 := RawYCoord;
  if Y1.IsZero then
    Exit(LCurve.Infinity);

  LCoord := GetCurveCoordinateSystem();

  W1 := LCurve.A;
  X1 := RawXCoord;
  if System.Length(RawZCoords) < 1 then
    Z1 := LCurve.FromBigInteger(TBigInteger.One)
  else
    Z1 := RawZCoords[0];

  if not Z1.IsOne then
  begin
    case LCoord of
      TECCurveConstants.COORD_HOMOGENEOUS:
      begin
        LZ1Sq := Z1.Square();
        X1 := X1.Multiply(Z1);
        Y1 := Y1.Multiply(LZ1Sq);
        W1 := CalculateJacobianModifiedW(Z1, LZ1Sq);
      end;
      TECCurveConstants.COORD_JACOBIAN:
      begin
        W1 := CalculateJacobianModifiedW(Z1, nil);
      end;
      TECCurveConstants.COORD_JACOBIAN_MODIFIED:
      begin
        W1 := GetJacobianModifiedW();
      end;
    end;
  end;

  for I := 0 to AE - 1 do
  begin
    if Y1.IsZero then
      Exit(LCurve.Infinity);

    X1Squared := X1.Square();
    LM := Three(X1Squared);
    L2Y1 := Two(Y1);
    L2Y1Squared := L2Y1.Multiply(Y1);
    LS := Two(X1.Multiply(L2Y1Squared));
    L4T := L2Y1Squared.Square();
    L8T := Two(L4T);

    if not W1.IsZero then
    begin
      LM := LM.Add(W1);
      W1 := Two(L8T.Multiply(W1));
    end;

    X1 := LM.Square().Subtract(Two(LS));
    Y1 := LM.Multiply(LS.Subtract(X1)).Subtract(L8T);
    if Z1.IsOne then Z1 := L2Y1 else Z1 := L2Y1.Multiply(Z1);
  end;

  case LCoord of
    TECCurveConstants.COORD_AFFINE:
    begin
      LZInv := Z1.Invert();
      LZInv2 := LZInv.Square();
      LZInv3 := LZInv2.Multiply(LZInv);
      Result := TFpPoint.Create(LCurve, X1.Multiply(LZInv2), Y1.Multiply(LZInv3));
    end;
    TECCurveConstants.COORD_HOMOGENEOUS:
    begin
      X1 := X1.Multiply(Z1);
      Z1 := Z1.Multiply(Z1.Square());
      Result := TFpPoint.Create(LCurve, X1, Y1,
        TCryptoLibGenericArray<IECFieldElement>.Create(Z1));
    end;
    TECCurveConstants.COORD_JACOBIAN:
    begin
      Result := TFpPoint.Create(LCurve, X1, Y1,
        TCryptoLibGenericArray<IECFieldElement>.Create(Z1));
    end;
    TECCurveConstants.COORD_JACOBIAN_MODIFIED:
    begin
      Result := TFpPoint.Create(LCurve, X1, Y1,
        TCryptoLibGenericArray<IECFieldElement>.Create(Z1, W1));
    end;
  else
    raise EInvalidOperationCryptoLibException.Create(SUnsupportedCoordinateSystem);
  end;
end;

function TFpPoint.Negate: IECPoint;
var
  LCoord: Int32;
begin
  if IsInfinity then
    Exit(Self as IECPoint);
  LCoord := GetCurveCoordinateSystem();
  if LCoord <> TECCurveConstants.COORD_AFFINE then
    Exit(TFpPoint.Create(FCurve, RawXCoord, RawYCoord.Negate(), RawZCoords));
  Result := TFpPoint.Create(FCurve, RawXCoord, RawYCoord.Negate());
end;

{ TAbstractF2mPoint }

function TAbstractF2mPoint.SatisfiesCurveEquation: Boolean;
var
  LCurve: IECCurve;
  LCoord: Int32;
  X, Y, A, B, Lhs, Rhs: IECFieldElement;
  Z, L, X2, Z2, Z3, Z4: IECFieldElement;
  LZIsOne: Boolean;
begin
  LCurve := FCurve;
  X := RawXCoord;
  Y := RawYCoord;
  A := LCurve.A;
  B := LCurve.B;

  LCoord := LCurve.CoordinateSystem;
  if LCoord = TECCurveConstants.COORD_LAMBDA_PROJECTIVE then
  begin
    Z := RawZCoords[0];
    LZIsOne := Z.IsOne;

    if X.IsZero then
    begin
      // NOTE: For x == 0, we expect the affine-y instead of the lambda-y
      Lhs := Y.Square();
      Rhs := B;
      if not LZIsOne then
      begin
        Z2 := Z.Square();
        Rhs := Rhs.Multiply(Z2);
      end;
    end
    else
    begin
      L := Y;
      X2 := X.Square();
      if LZIsOne then
      begin
        Lhs := L.Square().Add(L).Add(A);
        Rhs := X2.Square().Add(B);
      end
      else
      begin
        Z2 := Z.Square();
        Z4 := Z2.Square();
        Lhs := L.Add(Z).MultiplyPlusProduct(L, A, Z2);
        // TODO If sqrt(b) is precomputed this can be simplified to a single square
        Rhs := X2.SquarePlusProduct(B, Z4);
      end;
      Lhs := Lhs.Multiply(X2);
    end;
  end
  else
  begin
    Lhs := Y.Add(X).Multiply(Y);

    case LCoord of
      TECCurveConstants.COORD_AFFINE:
        ;
      TECCurveConstants.COORD_HOMOGENEOUS:
      begin
        Z := RawZCoords[0];
        if not Z.IsOne then
        begin
          Z2 := Z.Square();
          Z3 := Z.Multiply(Z2);
          Lhs := Lhs.Multiply(Z);
          A := A.Multiply(Z);
          B := B.Multiply(Z3);
        end;
      end;
    else
      raise EInvalidOperationCryptoLibException.Create(SUnsupportedCoordinateSystem);
    end;

    Rhs := X.Add(A).Multiply(X.Square()).Add(B);
  end;

  Result := Lhs.Equals(Rhs);
end;

function TAbstractF2mPoint.SatisfiesOrder: Boolean;
var
  LCurve: IECCurve;
  LCofactor: TBigInteger;
  LN: IECPoint;
  LX, LY, LL, LT: IECFieldElement;
  LF2mCurve: IAbstractF2mCurve;
begin
  LCurve := FCurve;
  LCofactor := LCurve.Cofactor;
  if TBigInteger.Two.Equals(LCofactor) then
  begin
    {
      Check that 0 == Tr(X + A); then there exists a solution to L^2 + L = X + A, and
      so a halving is possible, so this point is the double of another.

      Note: Tr(A) == 1 for cofactor 2 curves.
    }
    LN := Normalize();
    LX := LN.AffineXCoord;
    Exit(0 <> (LX as IAbstractF2mFieldElement).Trace());
  end;
  if TBigInteger.Four.Equals(LCofactor) then
  begin
    {
      Solve L^2 + L = X + A to find the half of this point, if it exists (fail if not).

      Note: Tr(A) == 0 for cofactor 4 curves.
    }
    LN := Normalize();
    LX := LN.AffineXCoord;
    LF2mCurve := LCurve as IAbstractF2mCurve;
    LL := LF2mCurve.SolveQuadraticEquation(LX.Add(LCurve.A));
    if LL = nil then
      Exit(False);

    {
      A solution exists, therefore 0 == Tr(X + A) == Tr(X).
    }
    LY := LN.AffineYCoord;
    LT := LX.Multiply(LL).Add(LY);

    {
      Either T or (T + X) is the square of a half-point's x coordinate (hx). In either
      case, the half-point can be halved again when 0 == Tr(hx + A).

      Check that 0 == Tr(T); then there exists a solution to L^2 + L = hx + A, and so a
      second halving is possible and this point is four times some other.
    }
    Exit(0 = (LT as IAbstractF2mFieldElement).Trace());
  end;
  Result := inherited SatisfiesOrder();
end;

function TAbstractF2mPoint.ScaleX(const AScale: IECFieldElement): IECPoint;
var
  LX, LL, LX2, LL2, LZ, LZ2: IECFieldElement;
begin
  if IsInfinity then
    Exit(Self as IECPoint);

  case GetCurveCoordinateSystem() of
    TECCurveConstants.COORD_LAMBDA_AFFINE:
    begin
      // Y is actually Lambda (X + Y/X) here
      LX := RawXCoord;
      LL := RawYCoord;
      LX2 := LX.Multiply(AScale);
      LL2 := LL.Add(LX).Divide(AScale).Add(LX2);
      Result := FCurve.CreateRawPoint(LX, LL2, RawZCoords);
    end;
    TECCurveConstants.COORD_LAMBDA_PROJECTIVE:
    begin
      // Y is actually Lambda (X + Y/X) here
      LX := RawXCoord;
      LL := RawYCoord;
      LZ := RawZCoords[0];
      // We scale the Z coordinate also, to avoid an inversion
      LX2 := LX.Multiply(AScale.Square());
      LL2 := LL.Add(LX).Add(LX2);
      LZ2 := LZ.Multiply(AScale);
      Result := FCurve.CreateRawPoint(LX, LL2,
        TCryptoLibGenericArray<IECFieldElement>.Create(LZ2));
    end;
  else
    Result := inherited ScaleX(AScale);
  end;
end;

function TAbstractF2mPoint.ScaleXNegateY(const AScale: IECFieldElement): IECPoint;
begin
  Result := ScaleX(AScale);
end;

function TAbstractF2mPoint.ScaleY(const AScale: IECFieldElement): IECPoint;
var
  LX, LL, LL2: IECFieldElement;
begin
  if IsInfinity then
    Exit(Self as IECPoint);

  case GetCurveCoordinateSystem() of
    TECCurveConstants.COORD_LAMBDA_AFFINE,
    TECCurveConstants.COORD_LAMBDA_PROJECTIVE:
    begin
      LX := RawXCoord;
      LL := RawYCoord;
      // Y is actually Lambda (X + Y/X) here
      LL2 := LL.Add(LX).Multiply(AScale).Add(LX);
      Result := FCurve.CreateRawPoint(LX, LL2, RawZCoords);
    end;
  else
    Result := inherited ScaleY(AScale);
  end;
end;

function TAbstractF2mPoint.ScaleYNegateX(const AScale: IECFieldElement): IECPoint;
begin
  Result := ScaleY(AScale);
end;

function TAbstractF2mPoint.Subtract(const AB: IECPoint): IECPoint;
begin
  if AB.IsInfinity then
    Exit(Self as IECPoint);
  Result := Add(AB.Negate());
end;

function TAbstractF2mPoint.Tau: IAbstractF2mPoint;
var
  LCurve: IECCurve;
  LCoord: Int32;
  LX1, LY1, LZ1: IECFieldElement;
begin
  if IsInfinity then
    Exit(Self as IAbstractF2mPoint);

  LCurve := GetCurve;
  LCoord := LCurve.CoordinateSystem;

  LX1 := RawXCoord;

  case LCoord of
    TECCurveConstants.COORD_AFFINE,
    TECCurveConstants.COORD_LAMBDA_AFFINE:
    begin
      LY1 := RawYCoord;
      Result := LCurve.CreateRawPoint(LX1.Square(), LY1.Square()) as IAbstractF2mPoint;
    end;
    TECCurveConstants.COORD_HOMOGENEOUS,
    TECCurveConstants.COORD_LAMBDA_PROJECTIVE:
    begin
      LY1 := RawYCoord;
      LZ1 := RawZCoords[0];
      Result := LCurve.CreateRawPoint(LX1.Square(), LY1.Square(),
        TCryptoLibGenericArray<IECFieldElement>.Create(LZ1.Square())) as IAbstractF2mPoint;
    end
  else
    raise EInvalidOperationCryptoLibException.Create(SUnsupportedCoordinateSystem);
  end;
end;

function TAbstractF2mPoint.TauPow(APow: Int32): IAbstractF2mPoint;
var
  LCurve: IECCurve;
  LCoord: Int32;
  LX1, LY1, LZ1: IECFieldElement;
begin
  if IsInfinity then
    Exit(Self as IAbstractF2mPoint);

  LCurve := GetCurve;
  LCoord := LCurve.CoordinateSystem;

  LX1 := RawXCoord;

  case LCoord of
    TECCurveConstants.COORD_AFFINE,
    TECCurveConstants.COORD_LAMBDA_AFFINE:
    begin
      LY1 := RawYCoord;
      Result := LCurve.CreateRawPoint(LX1.SquarePow(APow), LY1.SquarePow(APow)) as IAbstractF2mPoint;
    end;
    TECCurveConstants.COORD_HOMOGENEOUS,
    TECCurveConstants.COORD_LAMBDA_PROJECTIVE:
    begin
      LY1 := RawYCoord;
      LZ1 := RawZCoords[0];
      Result := LCurve.CreateRawPoint(LX1.SquarePow(APow), LY1.SquarePow(APow),
        TCryptoLibGenericArray<IECFieldElement>.Create(LZ1.SquarePow(APow))) as IAbstractF2mPoint;
    end
  else
    raise EInvalidOperationCryptoLibException.Create(SUnsupportedCoordinateSystem);
  end;
end;

{ TF2mPoint }

function TF2mPoint.GetCompressionYTilde: Boolean;
var
  LX, LY: IECFieldElement;
begin
  LX := RawXCoord;
  if LX.IsZero then
    Exit(False);

  LY := RawYCoord;
  case GetCurveCoordinateSystem() of
    TECCurveConstants.COORD_LAMBDA_AFFINE,
    TECCurveConstants.COORD_LAMBDA_PROJECTIVE:
      Result := LY.TestBitZero() <> LX.TestBitZero();
  else
    Result := LY.Divide(LX).TestBitZero();
  end;
end;

constructor TF2mPoint.Create(const ACurve: IECCurve; const AX, AY: IECFieldElement);
begin
  inherited Create(ACurve, AX, AY);
  if (AX = nil) <> (AY = nil) then
    raise EArgumentCryptoLibException.Create('Exactly one of the field elements is null');
  if AX <> nil then
  begin
    TF2mFieldElement.CheckFieldElements(AX, AY);
    if ACurve <> nil then
      TF2mFieldElement.CheckFieldElements(AX, ACurve.A);
  end;
end;

constructor TF2mPoint.Create(const ACurve: IECCurve; const AX, AY: IECFieldElement;
  const AZs: TCryptoLibGenericArray<IECFieldElement>);
begin
  inherited Create(ACurve, AX, AY, AZs);
end;

function TF2mPoint.Detach: IECPoint;
begin
  Result := TF2mPoint.Create(nil, GetAffineXCoord, GetAffineYCoord);
end;

function TF2mPoint.GetYCoord: IECFieldElement;
var
  LCoord: Int32;
  LX, LL, LY, LZ: IECFieldElement;
begin
  LCoord := GetCurveCoordinateSystem();
  case LCoord of
    TECCurveConstants.COORD_LAMBDA_AFFINE,
    TECCurveConstants.COORD_LAMBDA_PROJECTIVE:
    begin
      LX := RawXCoord;
      LL := RawYCoord;

      if IsInfinity or LX.IsZero then
        Exit(LL);

      // Y is actually Lambda (X + Y/X) here; convert to affine value on the fly
      LY := LL.Add(LX).Multiply(LX);
      if TECCurveConstants.COORD_LAMBDA_PROJECTIVE = LCoord then
      begin
        LZ := RawZCoords[0];
        if not LZ.IsOne then
          LY := LY.Divide(LZ);
      end;
      Result := LY;
    end;
  else
    Result := RawYCoord;
  end;
end;

function TF2mPoint.Add(const AB: IECPoint): IECPoint;
var
  LCurve: IECCurve;
  LCoord: Int32;
  X1, X2, Y1, Y2, Dx, Dy, LL, X3, Y3, Z3: IECFieldElement;
  Z1, Z2, LU1, LU2, LV1, LV2, LU, LV: IECFieldElement;
  LVSq, LVCu, LW, LUV, LA, LVSqZ2: IECFieldElement;
  LZ1IsOne, LZ2IsOne: Boolean;
  L1, L2, LS1, LS2, LA2, LB2, LAU1, LAU2, LABZ2, L3: IECFieldElement;
  LP: IECPoint;
begin
  if IsInfinity then
    Exit(AB);
  if AB.IsInfinity then
    Exit(Self as IECPoint);

  LCurve := FCurve;
  LCoord := GetCurveCoordinateSystem();

  X1 := RawXCoord;
  X2 := AB.RawXCoord;

  case LCoord of
    TECCurveConstants.COORD_AFFINE:
    begin
      Y1 := RawYCoord;
      Y2 := AB.RawYCoord;

      Dx := X1.Add(X2);
      Dy := Y1.Add(Y2);

      if Dx.IsZero then
      begin
        if Dy.IsZero then
          Exit(Twice());
        Exit(LCurve.Infinity);
      end;

      LL := Dy.Divide(Dx);
      X3 := LL.Square().Add(LL).Add(Dx).Add(LCurve.A);
      Y3 := LL.Multiply(X1.Add(X3)).Add(X3).Add(Y1);
      Result := TF2mPoint.Create(LCurve, X3, Y3);
    end;

    TECCurveConstants.COORD_HOMOGENEOUS:
    begin
      Y1 := RawYCoord;
      Z1 := RawZCoords[0];
      Y2 := AB.RawYCoord;
      Z2 := AB.GetZCoord(0);

      LZ1IsOne := Z1.IsOne;
      LU1 := Y2;
      LV1 := X2;
      if not LZ1IsOne then
      begin
        LU1 := LU1.Multiply(Z1);
        LV1 := LV1.Multiply(Z1);
      end;

      LZ2IsOne := Z2.IsOne;
      LU2 := Y1;
      LV2 := X1;
      if not LZ2IsOne then
      begin
        LU2 := LU2.Multiply(Z2);
        LV2 := LV2.Multiply(Z2);
      end;

      LU := LU1.Add(LU2);
      LV := LV1.Add(LV2);

      if LV.IsZero then
      begin
        if LU.IsZero then
          Exit(Twice());
        Exit(LCurve.Infinity);
      end;

      LVSq := LV.Square();
      LVCu := LVSq.Multiply(LV);
      if LZ1IsOne then LW := Z2
      else if LZ2IsOne then LW := Z1
      else LW := Z1.Multiply(Z2);
      LUV := LU.Add(LV);
      LA := LUV.MultiplyPlusProduct(LU, LVSq, LCurve.A).Multiply(LW).Add(LVCu);

      X3 := LV.Multiply(LA);
      if LZ2IsOne then LVSqZ2 := LVSq else LVSqZ2 := LVSq.Multiply(Z2);
      Y3 := LU.MultiplyPlusProduct(X1, LV, Y1).MultiplyPlusProduct(LVSqZ2, LUV, LA);
      Z3 := LVCu.Multiply(LW);

      Result := TF2mPoint.Create(LCurve, X3, Y3,
        TCryptoLibGenericArray<IECFieldElement>.Create(Z3));
    end;

    TECCurveConstants.COORD_LAMBDA_PROJECTIVE:
    begin
      if X1.IsZero then
      begin
        if X2.IsZero then
          Exit(LCurve.Infinity);
        Exit(AB.Add(Self as IECPoint));
      end;

      L1 := RawYCoord;
      Z1 := RawZCoords[0];
      L2 := AB.RawYCoord;
      Z2 := AB.GetZCoord(0);

      LZ1IsOne := Z1.IsOne;
      LU2 := X2;
      LS2 := L2;
      if not LZ1IsOne then
      begin
        LU2 := LU2.Multiply(Z1);
        LS2 := LS2.Multiply(Z1);
      end;

      LZ2IsOne := Z2.IsOne;
      LU1 := X1;
      LS1 := L1;
      if not LZ2IsOne then
      begin
        LU1 := LU1.Multiply(Z2);
        LS1 := LS1.Multiply(Z2);
      end;

      LA2 := LS1.Add(LS2);
      LB2 := LU1.Add(LU2);

      if LB2.IsZero then
      begin
        if LA2.IsZero then
          Exit(Twice());
        Exit(LCurve.Infinity);
      end;

      if X2.IsZero then
      begin
        // TODO This can probably be optimized quite a bit
        LP := (Self as IECPoint).Normalize();
        X1 := LP.RawXCoord;
        Y1 := LP.YCoord;

        Y2 := L2;
        LL := Y1.Add(Y2).Divide(X1);

        X3 := LL.Square().Add(LL).Add(X1).Add(LCurve.A);
        if X3.IsZero then
          Exit(TF2mPoint.Create(LCurve, X3, LCurve.B.Sqrt()));

        Y3 := LL.Multiply(X1.Add(X3)).Add(X3).Add(Y1);
        L3 := Y3.Divide(X3).Add(X3);
        Z3 := LCurve.FromBigInteger(TBigInteger.One);
      end
      else
      begin
        LB2 := LB2.Square();

        LAU1 := LA2.Multiply(LU1);
        LAU2 := LA2.Multiply(LU2);

        X3 := LAU1.Multiply(LAU2);
        if X3.IsZero then
          Exit(TF2mPoint.Create(LCurve, X3, LCurve.B.Sqrt()));

        LABZ2 := LA2.Multiply(LB2);
        if not LZ2IsOne then
          LABZ2 := LABZ2.Multiply(Z2);

        L3 := LAU2.Add(LB2).SquarePlusProduct(LABZ2, L1.Add(Z1));

        Z3 := LABZ2;
        if not LZ1IsOne then
          Z3 := Z3.Multiply(Z1);
      end;

      Result := TF2mPoint.Create(LCurve, X3, L3,
        TCryptoLibGenericArray<IECFieldElement>.Create(Z3));
    end;
  else
    raise EInvalidOperationCryptoLibException.Create(SUnsupportedCoordinateSystem);
  end;
end;

function TF2mPoint.Twice: IECPoint;
var
  LCurve: IECCurve;
  LCoord: Int32;
  X1, Y1, L1, X3, Y3, Z3, L3: IECFieldElement;
  Z1, LX1Z1, LY1Z1, LX1Sq, LS, LV, LVSquared, LSV, LH: IECFieldElement;
  LZ1IsOne: Boolean;
  LL1Z1, LZ1Sq, La, LaZ1Sq, LT, Lb, Lt1, Lt2, LX1Z1b: IECFieldElement;
begin
  if IsInfinity then
    Exit(Self as IECPoint);

  LCurve := FCurve;
  X1 := RawXCoord;

  if X1.IsZero then
    Exit(LCurve.Infinity);

  LCoord := GetCurveCoordinateSystem();

  case LCoord of
    TECCurveConstants.COORD_AFFINE:
    begin
      Y1 := RawYCoord;
      L1 := Y1.Divide(X1).Add(X1);
      X3 := L1.Square().Add(L1).Add(LCurve.A);
      Y3 := X1.SquarePlusProduct(X3, L1.AddOne());
      Result := TF2mPoint.Create(LCurve, X3, Y3);
    end;

    TECCurveConstants.COORD_HOMOGENEOUS:
    begin
      Y1 := RawYCoord;
      Z1 := RawZCoords[0];

      LZ1IsOne := Z1.IsOne;
      if LZ1IsOne then LX1Z1 := X1 else LX1Z1 := X1.Multiply(Z1);
      if LZ1IsOne then LY1Z1 := Y1 else LY1Z1 := Y1.Multiply(Z1);

      LX1Sq := X1.Square();
      LS := LX1Sq.Add(LY1Z1);
      LV := LX1Z1;
      LVSquared := LV.Square();
      LSV := LS.Add(LV);
      LH := LSV.MultiplyPlusProduct(LS, LVSquared, LCurve.A);

      X3 := LV.Multiply(LH);
      Y3 := LX1Sq.Square().MultiplyPlusProduct(LV, LH, LSV);
      Z3 := LV.Multiply(LVSquared);

      Result := TF2mPoint.Create(LCurve, X3, Y3,
        TCryptoLibGenericArray<IECFieldElement>.Create(Z3));
    end;

    TECCurveConstants.COORD_LAMBDA_PROJECTIVE:
    begin
      L1 := RawYCoord;
      Z1 := RawZCoords[0];

      LZ1IsOne := Z1.IsOne;
      if LZ1IsOne then LL1Z1 := L1 else LL1Z1 := L1.Multiply(Z1);
      if LZ1IsOne then LZ1Sq := Z1 else LZ1Sq := Z1.Square();
      La := LCurve.A;
      if LZ1IsOne then LaZ1Sq := La else LaZ1Sq := La.Multiply(LZ1Sq);
      LT := L1.Square().Add(LL1Z1).Add(LaZ1Sq);
      if LT.IsZero then
        Exit(TF2mPoint.Create(LCurve, LT, LCurve.B.Sqrt()));

      X3 := LT.Square();
      if LZ1IsOne then Z3 := LT else Z3 := LT.Multiply(LZ1Sq);

      Lb := LCurve.B;
      if Lb.GetBitLength < TBitOperations.Asr32(LCurve.FieldSize, 1) then
      begin
        Lt1 := L1.Add(X1).Square();
        if Lb.IsOne then
          Lt2 := LaZ1Sq.Add(LZ1Sq).Square()
        else
          // TODO Can be calculated with one square if we pre-compute sqrt(b)
          Lt2 := LaZ1Sq.SquarePlusProduct(Lb, LZ1Sq.Square());
        L3 := Lt1.Add(LT).Add(LZ1Sq).Multiply(Lt1).Add(Lt2).Add(X3);
        if La.IsZero then
          L3 := L3.Add(Z3)
        else if not La.IsOne then
          L3 := L3.Add(La.AddOne().Multiply(Z3));
      end
      else
      begin
        if LZ1IsOne then LX1Z1b := X1 else LX1Z1b := X1.Multiply(Z1);
        L3 := LX1Z1b.SquarePlusProduct(LT, LL1Z1).Add(X3).Add(Z3);
      end;

      Result := TF2mPoint.Create(LCurve, X3, L3,
        TCryptoLibGenericArray<IECFieldElement>.Create(Z3));
    end;
  else
    raise EInvalidOperationCryptoLibException.Create(SUnsupportedCoordinateSystem);
  end;
end;

function TF2mPoint.TwicePlus(const AB: IECPoint): IECPoint;
var
  LCurve: IECCurve;
  LCoord: Int32;
  X1, X2, Z2, L1, Z1, L2: IECFieldElement;
  LX1Sq, LL1Sq, LZ1Sq, LL1Z1, LT, LL2plus1, LA, LX2Z1Sq, LB2: IECFieldElement;
  X3, Z3, L3: IECFieldElement;
begin
  if IsInfinity then
    Exit(AB);
  if AB.IsInfinity then
    Exit(Twice());

  LCurve := FCurve;
  X1 := RawXCoord;
  if X1.IsZero then
    Exit(AB);

  LCoord := GetCurveCoordinateSystem();

  case LCoord of
    TECCurveConstants.COORD_LAMBDA_PROJECTIVE:
    begin
      // NOTE: twicePlus() only optimized for lambda-affine argument
      X2 := AB.RawXCoord;
      Z2 := AB.GetZCoord(0);
      if X2.IsZero or (not Z2.IsOne) then
        Exit(Twice().Add(AB));

      L1 := RawYCoord;
      Z1 := RawZCoords[0];
      L2 := AB.RawYCoord;

      LX1Sq := X1.Square();
      LL1Sq := L1.Square();
      LZ1Sq := Z1.Square();
      LL1Z1 := L1.Multiply(Z1);

      LT := LCurve.A.Multiply(LZ1Sq).Add(LL1Sq).Add(LL1Z1);
      LL2plus1 := L2.AddOne();
      LA := LCurve.A.Add(LL2plus1).Multiply(LZ1Sq).Add(LL1Sq).MultiplyPlusProduct(LT, LX1Sq, LZ1Sq);
      LX2Z1Sq := X2.Multiply(LZ1Sq);
      LB2 := LX2Z1Sq.Add(LT).Square();

      if LB2.IsZero then
      begin
        if LA.IsZero then
          Exit(AB.Twice());
        Exit(LCurve.Infinity);
      end;

      if LA.IsZero then
        Exit(TF2mPoint.Create(LCurve, LA, LCurve.B.Sqrt()));

      X3 := LA.Square().Multiply(LX2Z1Sq);
      Z3 := LA.Multiply(LB2).Multiply(LZ1Sq);
      L3 := LA.Add(LB2).Square().MultiplyPlusProduct(LT, LL2plus1, Z3);

      Result := TF2mPoint.Create(LCurve, X3, L3,
        TCryptoLibGenericArray<IECFieldElement>.Create(Z3));
    end;
  else
    Result := Twice().Add(AB);
  end;
end;

function TF2mPoint.Negate: IECPoint;
var
  LCurve: IECCurve;
  LX, LY, LZ, LL: IECFieldElement;
  LCoord: Int32;
begin
  if IsInfinity then
    Exit(Self as IECPoint);

  LX := RawXCoord;
  if LX.IsZero then
    Exit(Self as IECPoint);

  LCurve := FCurve;
  LCoord := LCurve.CoordinateSystem;
  case LCoord of
    TECCurveConstants.COORD_AFFINE:
    begin
      LY := RawYCoord;
      Result := TF2mPoint.Create(LCurve, LX, LY.Add(LX));
    end;
    TECCurveConstants.COORD_HOMOGENEOUS:
    begin
      LY := RawYCoord;
      LZ := RawZCoords[0];
      Result := TF2mPoint.Create(LCurve, LX, LY.Add(LX),
        TCryptoLibGenericArray<IECFieldElement>.Create(LZ));
    end;
    TECCurveConstants.COORD_LAMBDA_AFFINE:
    begin
      LL := RawYCoord;
      Result := TF2mPoint.Create(LCurve, LX, LL.AddOne());
    end;
    TECCurveConstants.COORD_LAMBDA_PROJECTIVE:
    begin
      LL := RawYCoord;
      LZ := RawZCoords[0];
      Result := TF2mPoint.Create(LCurve, LX, LL.Add(LZ),
        TCryptoLibGenericArray<IECFieldElement>.Create(LZ));
    end;
  else
    raise EInvalidOperationCryptoLibException.Create(SUnsupportedCoordinateSystem);
  end;
end;

end.
