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
  Generics.Collections,
  Classes,
  SysUtils,
  ClpBits,
  ClpCryptoLibTypes,
  ClpSetWeakRef,
  ClpBigInteger,
  ClpIPreCompInfo,
  ClpIPreCompCallBack,
  ClpValidityPrecompInfo,
  ClpIValidityPrecompInfo,
  ClpIECFieldElement,
  ClpIECInterface,
  ClpECAlgorithms,
  ClpECFieldElement;

resourcestring
  SUnSupportedCoordinateSystem = 'UnSupported Coordinate System';
  SUnknownCoordSystem = 'Unknown Coordinate System';
  SPointNotInNormalForm = 'Point not in Normal Form';
  SNotProjectiveCoordSystem = 'Not a Projective Coordinate System';
  SCannotBeNegative = 'Cannot be Negative, "e"';
  SNilFieldElement = 'Exactly one of the Field Elements is Nil';

type

  /// <summary>
  /// base class for points on elliptic curves.
  /// </summary>
  TECPoint = class abstract(TInterfacedObject, IECPoint)

  strict private

  type
    IValidityCallback = interface(IPreCompCallback)
      ['{FD571D52-9852-45A6-BD53-47765EB86F20}']

    end;

  type
    TValidityCallback = class(TInterfacedObject, IPreCompCallback,
      IValidityCallback)

    strict private
    var
      Fm_outer: IECPoint;
      Fm_decompressed, Fm_checkOrder: Boolean;

    public
      constructor Create(const outer: IECPoint;
        decompressed, checkOrder: Boolean);

      function Precompute(const existing: IPreCompInfo): IPreCompInfo;

    end;

  function GetIsInfinity: Boolean; inline;
  function GetIsCompressed: Boolean; inline;
  function GetpreCompTable: TDictionary<String, IPreCompInfo>; inline;
  procedure SetpreCompTable(const Value
    : TDictionary<String, IPreCompInfo>); inline;
  function GetCurve: IECCurve; virtual;
  function GetCurveCoordinateSystem: Int32; virtual;
  function GetAffineXCoord: IECFieldElement; virtual;
  function GetAffineYCoord: IECFieldElement; virtual;
  function GetXCoord: IECFieldElement; virtual;

  class constructor ECPoint();

  strict protected

    class var

      FEMPTY_ZS: TCryptoLibGenericArray<IECFieldElement>;

  var
    Fm_zs: TCryptoLibGenericArray<IECFieldElement>;
    Fm_withCompression: Boolean;
    Fm_curve: IECCurve;

    Fm_x, Fm_y: IECFieldElement;

    function GetCompressionYTilde: Boolean; virtual; abstract;

    constructor Create(const curve: IECCurve; const x, y: IECFieldElement;
      withCompression: Boolean); overload;

    function SatisfiesOrder(): Boolean; virtual;
    function SatisfiesCurveEquation(): Boolean; virtual; abstract;
    function Detach(): IECPoint; virtual; abstract;

    function RawXCoord: IECFieldElement; inline;

    function RawYCoord: IECFieldElement; inline;

    function RawZCoords: TCryptoLibGenericArray<IECFieldElement>; inline;

    function CreateScaledPoint(const sx, sy: IECFieldElement)
      : IECPoint; virtual;

    procedure CheckNormalized(); virtual;

    property CurveCoordinateSystem: Int32 read GetCurveCoordinateSystem;

    property CompressionYTilde: Boolean read GetCompressionYTilde;

    class function GetInitialZCoords(const curve: IECCurve)
      : TCryptoLibGenericArray<IECFieldElement>; static;

  public
  var
    // Dictionary is (string -> PreCompInfo)
    Fm_preCompTable: TDictionary<String, IPreCompInfo>;

    function GetYCoord: IECFieldElement; virtual;
    constructor Create(const curve: IECCurve; const x, y: IECFieldElement;
      const zs: TCryptoLibGenericArray<IECFieldElement>;
      withCompression: Boolean); overload;
    destructor Destroy; override;

    function GetDetachedPoint(): IECPoint; inline;
    function GetZCoord(index: Int32): IECFieldElement; virtual;
    function GetZCoords(): TCryptoLibGenericArray<IECFieldElement>; virtual;

    function IsNormalized(): Boolean; virtual;

    /// <summary>
    /// Normalization ensures that any projective coordinate is 1, and
    /// therefore that the x, y <br />coordinates reflect those of the
    /// equivalent point in an affine coordinate system.
    /// </summary>
    /// <returns>
    /// a new ECPoint instance representing the same point, but with
    /// normalized coordinates
    /// </returns>
    function Normalize(): IECPoint; overload; virtual;

    function Normalize(const zInv: IECFieldElement): IECPoint;
      overload; virtual;

    function ImplIsValid(decompressed, checkOrder: Boolean): Boolean;

    function IsValid(): Boolean; inline;
    function IsValidPartial(): Boolean; inline;

    function ScaleX(const scale: IECFieldElement): IECPoint; virtual;
    function ScaleY(const scale: IECFieldElement): IECPoint; virtual;

    function GetEncoded(): TCryptoLibByteArray; overload; virtual;
    function GetEncoded(compressed: Boolean): TCryptoLibByteArray; overload;
      virtual; abstract;

    function Add(const b: IECPoint): IECPoint; virtual; abstract;
    function Subtract(const b: IECPoint): IECPoint; virtual; abstract;
    function Negate(): IECPoint; virtual; abstract;
    function TimesPow2(e: Int32): IECPoint; virtual;

    function Twice(): IECPoint; virtual; abstract;
    function Multiply(b: TBigInteger): IECPoint; virtual; abstract;

    function TwicePlus(const b: IECPoint): IECPoint; virtual;

    function ThreeTimes(): IECPoint; virtual;

    function Equals(const other: IECPoint): Boolean; reintroduce;
    function GetHashCode(): {$IFDEF DELPHI}Int32; {$ELSE}PtrInt;
{$ENDIF DELPHI}override;

    function ToString(): String; override;

    property preCompTable: TDictionary<String, IPreCompInfo>
      read GetpreCompTable write SetpreCompTable;

    /// <summary>
    /// Returns the affine x-coordinate after checking that this point is
    /// normalized.
    /// </summary>
    /// <value>
    /// The affine x-coordinate of this point
    /// </value>
    /// <exception cref="ClpCryptoLibTypes|EInvalidOperationCryptoLibException">
    /// if the point is not normalized
    /// </exception>
    property AffineXCoord: IECFieldElement read GetAffineXCoord;
    /// <summary>
    /// Returns the affine y-coordinate after checking that this point is
    /// normalized.
    /// </summary>
    /// <value>
    /// The affine y-coordinate of this point
    /// </value>
    /// <exception cref="ClpCryptoLibTypes|EInvalidOperationCryptoLibException">
    /// if the point is not normalized
    /// </exception>
    property AffineYCoord: IECFieldElement read GetAffineYCoord;

    /// <summary>
    /// Returns the x-coordinate. <br />Caution: depending on the curve's
    /// coordinate system, this may not be the same value as in an <br />
    /// affine coordinate system; use Normalize() to get a point where the
    /// coordinates have their <br />affine values, or use AffineXCoord if
    /// you expect the point to already have been normalized.
    /// </summary>
    /// <value>
    /// the x-coordinate of this point
    /// </value>
    property XCoord: IECFieldElement read GetXCoord;
    /// <summary>
    /// Returns the y-coordinate. <br />Caution: depending on the curve's
    /// coordinate system, this may not be the same value as in an <br />
    /// affine coordinate system; use Normalize() to get a point where the
    /// coordinates have their <br />affine values, or use AffineYCoord if
    /// you expect the point to already have been normalized.
    /// </summary>
    /// <value>
    /// the y-coordinate of this point
    /// </value>
    property YCoord: IECFieldElement read GetYCoord;

    property curve: IECCurve read GetCurve;

    property IsInfinity: Boolean read GetIsInfinity;

    property IsCompressed: Boolean read GetIsCompressed;

  end;

type
  TECPointBase = class abstract(TECPoint, IECPointBase)

  strict protected

    constructor Create(const curve: IECCurve; const x, y: IECFieldElement;
      withCompression: Boolean); overload;

    constructor Create(const curve: IECCurve; const x, y: IECFieldElement;
      const zs: TCryptoLibGenericArray<IECFieldElement>;
      withCompression: Boolean); overload;

  public

    destructor Destroy; override;

    /// <summary>
    /// return the field element encoded with point compression. (S 4.3.6)
    /// </summary>
    function GetEncoded(compressed: Boolean): TCryptoLibByteArray; override;

    /// <summary>
    /// Multiplies this <c>ECPoint</c> by the given number.
    /// </summary>
    /// <param name="k">
    /// The multiplicator.
    /// </param>
    /// <returns>
    /// <c>k * this</c>
    /// </returns>
    function Multiply(k: TBigInteger): IECPoint; override;

  end;

type
  TAbstractFpPoint = class abstract(TECPointBase, IAbstractFpPoint)

  strict protected

    constructor Create(const curve: IECCurve; const x, y: IECFieldElement;
      withCompression: Boolean); overload;

    constructor Create(const curve: IECCurve; const x, y: IECFieldElement;
      const zs: TCryptoLibGenericArray<IECFieldElement>;
      withCompression: Boolean); overload;

    function GetCompressionYTilde(): Boolean; override;

    function SatisfiesCurveEquation(): Boolean; override;

    property CompressionYTilde: Boolean read GetCompressionYTilde;

  public

    destructor Destroy; override;
    function Subtract(const b: IECPoint): IECPoint; override;

  end;

type

  /// <summary>
  /// Elliptic curve points over Fp
  /// </summary>
  TFpPoint = class(TAbstractFpPoint, IFpPoint)

  strict protected

    function Detach(): IECPoint; override;

    function Two(const x: IECFieldElement): IECFieldElement; virtual;
    function Three(const x: IECFieldElement): IECFieldElement; virtual;
    function Four(const x: IECFieldElement): IECFieldElement; virtual;
    function Eight(const x: IECFieldElement): IECFieldElement; virtual;
    function DoubleProductFromSquares(const a, b, aSquared,
      bSquared: IECFieldElement): IECFieldElement; virtual;

    function CalculateJacobianModifiedW(const Z: IECFieldElement;
      const ZSquared: IECFieldElement): IECFieldElement; virtual;

    function GetJacobianModifiedW(): IECFieldElement; virtual;

    function TwiceJacobianModified(calculateW: Boolean): IFpPoint; virtual;

  public

    /// <summary>
    /// Create a point which encodes without point compression.
    /// </summary>
    /// <param name="curve">
    /// curve the curve to use
    /// </param>
    /// <param name="x">
    /// affine x co-ordinate
    /// </param>
    /// <param name="y">
    /// affine y co-ordinate
    /// </param>
    constructor Create(const curve: IECCurve; const x, y: IECFieldElement);
      overload; deprecated 'Use ECCurve.CreatePoint to construct points';

    /// <summary>
    /// Create a point which encodes without point compression.
    /// </summary>
    /// <param name="curve">
    /// curve the curve to use
    /// </param>
    /// <param name="x">
    /// affine x co-ordinate
    /// </param>
    /// <param name="y">
    /// affine y co-ordinate
    /// </param>
    /// <param name="withCompression">
    /// if true encode with point compression
    /// </param>
    constructor Create(const curve: IECCurve; const x, y: IECFieldElement;
      withCompression: Boolean); overload;
      deprecated
      'Per-point compression property will be removed, see GetEncoded(boolean)';

    constructor Create(const curve: IECCurve; const x, y: IECFieldElement;
      const zs: TCryptoLibGenericArray<IECFieldElement>;
      withCompression: Boolean); overload;

    destructor Destroy; override;

    function GetZCoord(index: Int32): IECFieldElement; override;
    // B.3 pg 62
    function Add(const b: IECPoint): IECPoint; override;

    // B.3 pg 62
    function Twice(): IECPoint; override;

    function TwicePlus(const b: IECPoint): IECPoint; override;

    function ThreeTimes(): IECPoint; override;

    function TimesPow2(e: Int32): IECPoint; override;

    function Negate(): IECPoint; override;

  end;

type
  TAbstractF2mPoint = class abstract(TECPointBase, IAbstractF2mPoint)

  strict protected
    constructor Create(const curve: IECCurve; const x, y: IECFieldElement;
      withCompression: Boolean); overload;

    constructor Create(const curve: IECCurve; const x, y: IECFieldElement;
      const zs: TCryptoLibGenericArray<IECFieldElement>;
      withCompression: Boolean); overload;

    function SatisfiesOrder(): Boolean; override;
    function SatisfiesCurveEquation(): Boolean; override;

  public
    destructor Destroy; override;
    function ScaleX(const scale: IECFieldElement): IECPoint; override;
    function ScaleY(const scale: IECFieldElement): IECPoint; override;

    function Subtract(const b: IECPoint): IECPoint; override;

    function Tau(): IAbstractF2mPoint; virtual;

    function TauPow(pow: Int32): IAbstractF2mPoint; virtual;
  end;

type

  /// <summary>
  /// Elliptic curve points over F2m
  /// </summary>
  TF2mPoint = class(TAbstractF2mPoint, IF2mPoint)

  strict protected
    function GetCompressionYTilde: Boolean; override;
    function Detach(): IECPoint; override;
    property CompressionYTilde: Boolean read GetCompressionYTilde;
  public

    function GetYCoord: IECFieldElement; override;

    /// <param name="curve">
    /// base curve
    /// </param>
    /// <param name="x">
    /// x point
    /// </param>
    /// <param name="y">
    /// y point
    /// </param>
    constructor Create(const curve: IECCurve; const x, y: IECFieldElement);
      overload; deprecated 'Use ECCurve.CreatePoint to construct points';

    /// <param name="curve">
    /// base curve
    /// </param>
    /// <param name="x">
    /// x point
    /// </param>
    /// <param name="y">
    /// y point
    /// </param>
    /// <param name="withCompression">
    /// true if encode with point compression.
    /// </param>
    constructor Create(const curve: IECCurve; const x, y: IECFieldElement;
      withCompression: Boolean); overload;
      deprecated
      'Per-point compression property will be removed, see GetEncoded(boolean)';

    constructor Create(const curve: IECCurve; const x, y: IECFieldElement;
      const zs: TCryptoLibGenericArray<IECFieldElement>;
      withCompression: Boolean); overload;

    destructor Destroy; override;

    function Add(const b: IECPoint): IECPoint; override;

    function Twice(): IECPoint; override;

    function TwicePlus(const b: IECPoint): IECPoint; override;

    function Negate(): IECPoint; override;

    property YCoord: IECFieldElement read GetYCoord;
  end;

implementation

uses
  ClpECCurve; // included here to avoid circular dependency :)

{ TECPoint }

function TECPoint.GetIsCompressed: Boolean;
begin
  result := Fm_withCompression;
end;

function TECPoint.GetIsInfinity: Boolean;
begin
  // result := (Fm_x = Nil) and (Fm_y = Nil);
  result := (Fm_x = Nil) or (Fm_y = Nil) or
    ((System.Length(Fm_zs) > 0) and (Fm_zs[0].IsZero));
end;

function TECPoint.RawXCoord: IECFieldElement;
begin
  result := Fm_x;
end;

function TECPoint.RawYCoord: IECFieldElement;
begin
  result := Fm_y;
end;

function TECPoint.RawZCoords: TCryptoLibGenericArray<IECFieldElement>;
begin
  result := Fm_zs;
end;

function TECPoint.Normalize: IECPoint;
var
  Z1: IECFieldElement;
begin
  if (IsInfinity) then
  begin
    result := Self;
    Exit;
  end;

  case CurveCoordinateSystem of
    TECCurve.COORD_AFFINE, TECCurve.COORD_LAMBDA_AFFINE:
      begin
        result := Self;
        Exit;
      end
  else
    begin

      Z1 := RawZCoords[0];
      if (Z1.IsOne) then
      begin
        result := Self;
        Exit;
      end;

      result := Normalize(Z1.Invert());
    end;
  end;
end;

function TECPoint.SatisfiesOrder: Boolean;
var
  n: TBigInteger;
begin
  if (TBigInteger.One.Equals(curve.getCofactor())) then
  begin
    result := True;
    Exit;
  end;

  n := curve.getOrder();

  // TODO Require order to be available for all curves

  result := (not(n.IsInitialized)) or TECAlgorithms.ReferenceMultiply
    (Self as IECPoint, n).IsInfinity;
end;

function TECPoint.ScaleX(const scale: IECFieldElement): IECPoint;
begin
  if IsInfinity then
  begin
    result := Self;
  end
  else
  begin
    result := curve.CreateRawPoint(RawXCoord.Multiply(scale), RawYCoord,
      RawZCoords, IsCompressed);
  end;
end;

function TECPoint.ScaleY(const scale: IECFieldElement): IECPoint;
begin
  if IsInfinity then
  begin
    result := Self;
  end
  else
  begin
    result := curve.CreateRawPoint(RawXCoord, RawYCoord.Multiply(scale),
      RawZCoords, IsCompressed);
  end;
end;

procedure TECPoint.SetpreCompTable(const Value
  : TDictionary<String, IPreCompInfo>);
begin
  Fm_preCompTable := Value;
end;

function TECPoint.ThreeTimes: IECPoint;
begin
  result := TwicePlus(Self);
end;

function TECPoint.TimesPow2(e: Int32): IECPoint;
var
  p: IECPoint;
begin
  if (e < 0) then
  begin
    raise EArgumentCryptoLibException.CreateRes(@SCannotBeNegative);
  end;

  p := Self;
  System.Dec(e);
  while (e >= 0) do
  begin
    p := p.Twice();
    System.Dec(e);
  end;
  result := p;
end;

function TECPoint.ToString: String;
var
  sl: TStringList;
  i: Int32;
begin
  if (IsInfinity) then
  begin
    result := 'INF';
    Exit;
  end;

  sl := TStringList.Create();
  sl.LineBreak := '';
  try
    sl.Add('(');
    sl.Add(RawXCoord.ToString);
    sl.Add(',');
    sl.Add(RawYCoord.ToString);
    for i := 0 to System.Pred(System.Length(Fm_zs)) do
    begin
      sl.Add(',');
      sl.Add(Fm_zs[i].ToString);
    end;
    sl.Add(')');
    result := sl.Text;
  finally
    sl.Free;
  end;
end;

function TECPoint.TwicePlus(const b: IECPoint): IECPoint;
begin
  result := Twice().Add(b);
end;

constructor TECPoint.Create(const curve: IECCurve; const x, y: IECFieldElement;
  withCompression: Boolean);
begin
  Create(curve, x, y, GetInitialZCoords(curve), withCompression);
end;

procedure TECPoint.CheckNormalized;
begin
  if (not IsNormalized()) then
  begin
    raise EInvalidOperationCryptoLibException.CreateRes(@SPointNotInNormalForm);
  end;
end;

constructor TECPoint.Create(const curve: IECCurve; const x, y: IECFieldElement;
  const zs: TCryptoLibGenericArray<IECFieldElement>; withCompression: Boolean);
begin
  Inherited Create();
  // Fm_curve := curve;
  TSetWeakRef.SetWeakReference(@Fm_curve, curve);
  Fm_x := x;
  Fm_y := y;
  Fm_zs := zs;
  Fm_withCompression := withCompression;
end;

function TECPoint.CreateScaledPoint(const sx, sy: IECFieldElement): IECPoint;
begin
  result := curve.CreateRawPoint(RawXCoord.Multiply(sx), RawYCoord.Multiply(sy),
    IsCompressed);
end;

destructor TECPoint.Destroy;
begin
  TSetWeakRef.SetWeakReference(@Fm_curve, Nil);
  Fm_preCompTable.Free;
  inherited Destroy;
end;

class constructor TECPoint.ECPoint;
begin
  System.SetLength(FEMPTY_ZS, 0);
end;

function TECPoint.Equals(const other: IECPoint): Boolean;
var
  c1, c2: IECCurve;
  n1, n2, i1, i2: Boolean;
  p1, p2: IECPoint;
  points: TCryptoLibGenericArray<IECPoint>;
begin
  if ((Self as IECPoint) = other) then
  begin
    result := True;
    Exit;
  end;
  if (other = Nil) then
  begin
    result := false;
    Exit;
  end;

  c1 := Self.curve;
  c2 := other.curve;
  n1 := (c1 = Nil);
  n2 := (c2 = Nil);
  i1 := IsInfinity;
  i2 := other.IsInfinity;

  if (i1 or i2) then
  begin
    result := (i1 and i2) and (n1 or n2 or c1.Equals(c2));
    Exit;
  end;

  p1 := Self as IECPoint;
  p2 := other;
  if (n1 and n2) then
  begin
    // Points with null curve are in affine form, so already normalized
  end
  else if (n1) then
  begin
    p2 := p2.Normalize();
  end
  else if (n2) then
  begin
    p1 := p1.Normalize();
  end
  else if (not c1.Equals(c2)) then
  begin
    result := false;
    Exit;
  end
  else
  begin
    // TODO Consider just requiring already normalized, to avoid silent performance degradation

    points := TCryptoLibGenericArray<IECPoint>.Create(Self, c1.ImportPoint(p2));

    // TODO This is a little strong, really only requires coZNormalizeAll to get Zs equal
    c1.NormalizeAll(points);

    p1 := points[0];
    p2 := points[1];
  end;

  result := p1.XCoord.Equals(p2.XCoord) and p1.YCoord.Equals(p2.YCoord);
end;

function TECPoint.GetEncoded: TCryptoLibByteArray;
begin
  result := GetEncoded(Fm_withCompression);
end;

function TECPoint.GetHashCode: {$IFDEF DELPHI}Int32; {$ELSE}PtrInt;
{$ENDIF DELPHI}

var
  c: IECCurve;
  p: IECPoint;
  hc: Int32;
begin
  c := curve;
  if c = Nil then
  begin
    hc := 0;
  end
  else
  begin
    hc := not c.GetHashCode();
  end;

  if (not IsInfinity) then
  begin
    // TODO Consider just requiring already normalized, to avoid silent performance degradation

    p := Normalize();

    hc := hc xor (p.XCoord.GetHashCode() * 17);
    hc := hc xor (p.YCoord.GetHashCode() * 257);
  end;

  result := hc;
end;

class function TECPoint.GetInitialZCoords(const curve: IECCurve)
  : TCryptoLibGenericArray<IECFieldElement>;
var
  coord: Int32;
  One: IECFieldElement;
begin
  // Cope with null curve, most commonly used by implicitlyCa
  if curve = Nil then
  begin
    coord := TECCurve.COORD_AFFINE;
  end
  else
  begin
    coord := curve.CoordinateSystem;
  end;

  case coord of
    TECCurve.COORD_AFFINE, TECCurve.COORD_LAMBDA_AFFINE:
      begin
        result := FEMPTY_ZS;
        Exit;
      end;
  end;

  One := curve.FromBigInteger(TBigInteger.One);

  case coord of

    TECCurve.COORD_HOMOGENEOUS, TECCurve.COORD_JACOBIAN,
      TECCurve.COORD_LAMBDA_PROJECTIVE:
      begin
        result := TCryptoLibGenericArray<IECFieldElement>.Create(One);
        Exit;
      end;

    TECCurve.COORD_JACOBIAN_CHUDNOVSKY:
      begin
        result := TCryptoLibGenericArray<IECFieldElement>.Create(One, One, One);
        Exit;
      end;

    TECCurve.COORD_JACOBIAN_MODIFIED:
      begin
        result := TCryptoLibGenericArray<IECFieldElement>.Create(One, curve.a);
        Exit;
      end

  else
    begin
      raise EArgumentCryptoLibException.CreateRes(@SUnknownCoordSystem);
    end;

  end;

end;

function TECPoint.GetpreCompTable: TDictionary<String, IPreCompInfo>;
begin
  result := Fm_preCompTable;
end;

function TECPoint.GetXCoord: IECFieldElement;
begin
  result := Fm_x;
end;

function TECPoint.GetYCoord: IECFieldElement;
begin
  result := Fm_y;
end;

function TECPoint.GetZCoord(index: Int32): IECFieldElement;
begin
  if ((index < 0) or (index >= System.Length(Fm_zs))) then
  begin
    result := Nil;
  end
  else
  begin
    result := Fm_zs[index];
  end;
end;

function TECPoint.GetZCoords: TCryptoLibGenericArray<IECFieldElement>;
var
  zsLen: Int32;
begin
  zsLen := System.Length(Fm_zs);
  if (zsLen = 0) then
  begin
    result := Fm_zs;
    Exit;
  end;
  System.SetLength(result, zsLen);
  result := System.Copy(Fm_zs, 0, zsLen);
end;

function TECPoint.ImplIsValid(decompressed, checkOrder: Boolean): Boolean;
var
  Validity: IValidityPrecompInfo;
  callback: IValidityCallback;
begin

  if (IsInfinity) then
  begin
    result := True;
    Exit;
  end;

  callback := TValidityCallback.Create(Self as IECPoint, decompressed,
    checkOrder);
  Validity := curve.Precompute(Self as IECPoint,
    TValidityPrecompInfo.PRECOMP_NAME, callback) as IValidityPrecompInfo;

  result := not(Validity.hasFailed());
end;

function TECPoint.IsNormalized: Boolean;
var
  coord: Int32;
begin
  coord := CurveCoordinateSystem;

  result := (coord = TECCurve.COORD_AFFINE) or
    (coord = TECCurve.COORD_LAMBDA_AFFINE) or (IsInfinity) or
    (RawZCoords[0].IsOne);
end;

function TECPoint.IsValid: Boolean;
begin
  result := ImplIsValid(false, True);
end;

function TECPoint.IsValidPartial: Boolean;
begin
  result := ImplIsValid(false, false);
end;

function TECPoint.Normalize(const zInv: IECFieldElement): IECPoint;
var
  zInv2, zInv3: IECFieldElement;
begin
  case CurveCoordinateSystem of
    TECCurve.COORD_HOMOGENEOUS, TECCurve.COORD_LAMBDA_PROJECTIVE:
      begin
        result := CreateScaledPoint(zInv, zInv);
        Exit;
      end;

    TECCurve.COORD_JACOBIAN, TECCurve.COORD_JACOBIAN_CHUDNOVSKY,
      TECCurve.COORD_JACOBIAN_MODIFIED:
      begin
        zInv2 := zInv.Square();
        zInv3 := zInv2.Multiply(zInv);
        result := CreateScaledPoint(zInv2, zInv3);
        Exit;
      end
  else
    begin
      raise EInvalidOperationCryptoLibException.CreateRes
        (@SNotProjectiveCoordSystem);
    end;

  end;
end;

function TECPoint.GetAffineXCoord: IECFieldElement;
begin
  CheckNormalized();
  result := XCoord;
end;

function TECPoint.GetAffineYCoord: IECFieldElement;
begin
  CheckNormalized();
  result := YCoord;
end;

function TECPoint.GetCurve: IECCurve;
begin
  result := Fm_curve;
end;

function TECPoint.GetCurveCoordinateSystem: Int32;
begin
  // Cope with null curve, most commonly used by implicitlyCa
  if Fm_curve = Nil then
  begin
    result := TECCurve.COORD_AFFINE;
  end
  else
  begin
    result := Fm_curve.CoordinateSystem;
  end;
end;

function TECPoint.GetDetachedPoint: IECPoint;
begin
  result := Normalize().Detach();
end;

{ TF2mPoint }

constructor TF2mPoint.Create(const curve: IECCurve;
  const x, y: IECFieldElement);
begin
  Create(curve, x, y, false);
end;

constructor TF2mPoint.Create(const curve: IECCurve; const x, y: IECFieldElement;
  withCompression: Boolean);
begin
  Inherited Create(curve, x, y, withCompression);
  if ((x = Nil) <> (y = Nil)) then
  begin
    raise EArgumentCryptoLibException.CreateRes(@SNilFieldElement);
  end;

  if (x <> Nil) then
  begin
    // Check if x and y are elements of the same field
    TF2mFieldElement.CheckFieldElements(x, y);

    // Check if x and a are elements of the same field
    if (curve <> Nil) then
    begin
      TF2mFieldElement.CheckFieldElements(x, curve.a);
    end;
  end;
end;

function TF2mPoint.Add(const b: IECPoint): IECPoint;
var
  ecCurve: IECCurve;
  coord: Int32;
  X1, X2, Y1, Y2, dx, dy, L, X3, Y3, Z1, Z2, U1, V1, U2, V2, U, V, Vsq, Vcu, W,
    a, VSqZ2, uv, Z3, L3, L1, L2, S2, S1, ABZ2, AU1, AU2, bigB: IECFieldElement;
  Z1IsOne, Z2IsOne: Boolean;
  p: IECPoint;
begin
  if (IsInfinity) then
  begin
    result := b;
    Exit;
  end;
  if (b.IsInfinity) then
  begin
    result := Self;
    Exit;
  end;

  ecCurve := curve;
  coord := ecCurve.CoordinateSystem;

  X1 := RawXCoord;
  X2 := b.RawXCoord;

  case coord of
    TECCurve.COORD_AFFINE:
      begin
        Y1 := RawYCoord;
        Y2 := b.RawYCoord;

        dx := X1.Add(X2);
        dy := Y1.Add(Y2);
        if (dx.IsZero) then
        begin
          if (dy.IsZero) then
          begin
            result := Twice();
            Exit;
          end;

          result := ecCurve.Infinity;
          Exit;
        end;

        L := dy.Divide(dx);

        X3 := L.Square().Add(L).Add(dx).Add(ecCurve.a);
        Y3 := L.Multiply(X1.Add(X3)).Add(X3).Add(Y1);

        result := TF2mPoint.Create(ecCurve, X3, Y3, IsCompressed);
        Exit;
      end;
    TECCurve.COORD_HOMOGENEOUS:
      begin
        Y1 := RawYCoord;
        Z1 := RawZCoords[0];
        Y2 := b.RawYCoord;
        Z2 := b.RawZCoords[0];

        Z1IsOne := Z1.IsOne;
        U1 := Y2;
        V1 := X2;
        if (not Z1IsOne) then
        begin
          U1 := U1.Multiply(Z1);
          V1 := V1.Multiply(Z1);
        end;

        Z2IsOne := Z2.IsOne;
        U2 := Y1;
        V2 := X1;
        if (not Z2IsOne) then
        begin
          U2 := U2.Multiply(Z2);
          V2 := V2.Multiply(Z2);
        end;

        U := U1.Add(U2);
        V := V1.Add(V2);

        if (V.IsZero) then
        begin
          if (U.IsZero) then
          begin
            result := Twice();
            Exit;
          end;

          result := ecCurve.Infinity;
          Exit;
        end;

        Vsq := V.Square();
        Vcu := Vsq.Multiply(V);

        if Z1IsOne then
        begin
          W := Z2;
        end
        else if Z2IsOne then
        begin
          W := Z1;
        end
        else
        begin
          W := Z1.Multiply(Z2);
        end;

        uv := U.Add(V);
        a := uv.MultiplyPlusProduct(U, Vsq, ecCurve.a).Multiply(W).Add(Vcu);

        X3 := V.Multiply(a);
        if Z2IsOne then
        begin
          VSqZ2 := Vsq;
        end
        else
        begin
          VSqZ2 := Vsq.Multiply(Z2);
        end;

        Y3 := U.MultiplyPlusProduct(X1, V, Y1).MultiplyPlusProduct
          (VSqZ2, uv, a);
        Z3 := Vcu.Multiply(W);

        result := TF2mPoint.Create(ecCurve, X3, Y3,
          TCryptoLibGenericArray<IECFieldElement>.Create(Z3), IsCompressed);
        Exit;
      end;

    TECCurve.COORD_LAMBDA_PROJECTIVE:
      begin
        if (X1.IsZero) then
        begin
          if (X2.IsZero) then
          begin
            result := ecCurve.Infinity;
            Exit;
          end;

          result := b.Add(Self);
          Exit;
        end;

        L1 := RawYCoord;
        Z1 := RawZCoords[0];
        L2 := b.RawYCoord;
        Z2 := b.RawZCoords[0];

        Z1IsOne := Z1.IsOne;
        U2 := X2;
        S2 := L2;
        if (not Z1IsOne) then
        begin
          U2 := U2.Multiply(Z1);
          S2 := S2.Multiply(Z1);
        end;

        Z2IsOne := Z2.IsOne;
        U1 := X1;
        S1 := L1;
        if (not Z2IsOne) then
        begin
          U1 := U1.Multiply(Z2);
          S1 := S1.Multiply(Z2);
        end;

        a := S1.Add(S2);
        bigB := U1.Add(U2);

        if (bigB.IsZero) then
        begin
          if (a.IsZero) then
          begin
            result := Twice();
            Exit;
          end;

          result := ecCurve.Infinity;
          Exit;
        end;

        if (X2.IsZero) then
        begin
          // TODO This can probably be optimized quite a bit
          p := Normalize();
          X1 := p.RawXCoord;
          Y1 := p.YCoord;

          Y2 := L2;
          L := Y1.Add(Y2).Divide(X1);

          X3 := L.Square().Add(L).Add(X1).Add(ecCurve.a);
          if (X3.IsZero) then
          begin
            result := TF2mPoint.Create(ecCurve, X3, ecCurve.b.Sqrt(),
              IsCompressed);
            Exit;
          end;

          Y3 := L.Multiply(X1.Add(X3)).Add(X3).Add(Y1);
          L3 := Y3.Divide(X3).Add(X3);
          Z3 := ecCurve.FromBigInteger(TBigInteger.One);
        end
        else
        begin
          bigB := bigB.Square();

          AU1 := a.Multiply(U1);
          AU2 := a.Multiply(U2);

          X3 := AU1.Multiply(AU2);
          if (X3.IsZero) then
          begin
            result := TF2mPoint.Create(ecCurve, X3, ecCurve.b.Sqrt(),
              IsCompressed);
            Exit;
          end;

          ABZ2 := a.Multiply(bigB);
          if (not Z2IsOne) then
          begin
            ABZ2 := ABZ2.Multiply(Z2);
          end;

          L3 := AU2.Add(bigB).SquarePlusProduct(ABZ2, L1.Add(Z1));

          Z3 := ABZ2;
          if (not Z1IsOne) then
          begin
            Z3 := Z3.Multiply(Z1);
          end;
        end;

        result := TF2mPoint.Create(ecCurve, X3, L3,
          TCryptoLibGenericArray<IECFieldElement>.Create(Z3), IsCompressed);
        Exit;
      end
  else
    begin
      raise EInvalidOperationCryptoLibException.CreateRes
        (@SUnSupportedCoordinateSystem);
    end;

  end;

end;

constructor TF2mPoint.Create(const curve: IECCurve; const x, y: IECFieldElement;
  const zs: TCryptoLibGenericArray<IECFieldElement>; withCompression: Boolean);
begin
  Inherited Create(curve, x, y, zs, withCompression);
end;

destructor TF2mPoint.Destroy;
begin
  inherited Destroy;
end;

function TF2mPoint.Detach: IECPoint;
begin
  result := TF2mPoint.Create(Nil, AffineXCoord, AffineYCoord, false);
end;

function TF2mPoint.GetCompressionYTilde: Boolean;
var
  lx, ly: IECFieldElement;
begin
  lx := RawXCoord;
  if (lx.IsZero) then
  begin
    result := false;
    Exit;
  end;

  ly := RawYCoord;

  case CurveCoordinateSystem of
    TECCurve.COORD_LAMBDA_AFFINE, TECCurve.COORD_LAMBDA_PROJECTIVE:
      begin
        // Y is actually Lambda (X + Y/X) here
        result := ly.TestBitZero() <> lx.TestBitZero();
        Exit;
      end
  else
    begin
      result := ly.Divide(lx).TestBitZero();
    end;
  end;

end;

function TF2mPoint.GetYCoord: IECFieldElement;
var
  coord: Int32;
  lx, L, ly, Z: IECFieldElement;
begin
  coord := CurveCoordinateSystem;

  case coord of
    TECCurve.COORD_LAMBDA_AFFINE, TECCurve.COORD_LAMBDA_PROJECTIVE:
      begin
        lx := RawXCoord;
        L := RawYCoord;

        if (IsInfinity or lx.IsZero) then
        begin
          result := L;
          Exit;
        end;

        // Y is actually Lambda (X + Y/X) here; convert to affine value on the fly
        ly := L.Add(lx).Multiply(lx);
        if (TECCurve.COORD_LAMBDA_PROJECTIVE = coord) then
        begin
          Z := RawZCoords[0];
          if (not Z.IsOne) then
          begin
            ly := ly.Divide(Z);
          end;
        end;
        result := ly;
        Exit;
      end
  else
    begin
      result := RawYCoord;
    end;
  end;

end;

function TF2mPoint.Negate: IECPoint;
var
  lx, ly, bigY, Z, L: IECFieldElement;
  ecCurve: IECCurve;
  coord: Int32;
begin
  if (IsInfinity) then
  begin
    result := Self;
    Exit;
  end;

  lx := RawXCoord;
  if (lx.IsZero) then
  begin
    result := Self;
    Exit;
  end;

  ecCurve := curve;
  coord := ecCurve.CoordinateSystem;

  case coord of
    TECCurve.COORD_AFFINE:
      begin
        bigY := RawYCoord;
        result := TF2mPoint.Create(ecCurve, lx, bigY.Add(lx), IsCompressed);
        Exit;
      end;

    TECCurve.COORD_HOMOGENEOUS:
      begin
        ly := RawYCoord;
        Z := RawZCoords[0];
        result := TF2mPoint.Create(ecCurve, lx, ly.Add(lx),
          TCryptoLibGenericArray<IECFieldElement>.Create(Z), IsCompressed);
        Exit;
      end;

    TECCurve.COORD_LAMBDA_AFFINE:
      begin
        L := RawYCoord;
        result := TF2mPoint.Create(ecCurve, lx, L.AddOne(), IsCompressed);
        Exit;
      end;

    TECCurve.COORD_LAMBDA_PROJECTIVE:
      begin
        // L is actually Lambda (X + Y/X) here
        L := RawYCoord;
        Z := RawZCoords[0];
        result := TF2mPoint.Create(ecCurve, lx, L.Add(Z),
          TCryptoLibGenericArray<IECFieldElement>.Create(Z), IsCompressed);
        Exit;
      end

  else
    begin
      raise EInvalidOperationCryptoLibException.CreateRes
        (@SUnSupportedCoordinateSystem);
    end;

  end;

end;

function TF2mPoint.Twice: IECPoint;
var
  ecCurve: IECCurve;
  X1, Y1, L1, X3, Y3, Z1, X1Z1, X1Sq, Y1Z1, S, V, vSquared, sv, h, Z3, L1Z1,
    Z1Sq, a, aZ1Sq, L3, T, b, t1, t2: IECFieldElement;
  coord: Int32;
  Z1IsOne: Boolean;
begin
  if (IsInfinity) then
  begin
    result := Self;
    Exit;
  end;

  ecCurve := curve;

  X1 := RawXCoord;
  if (X1.IsZero) then
  begin
    // A point with X == 0 is it's own additive inverse
    result := ecCurve.Infinity;
    Exit;
  end;

  coord := ecCurve.CoordinateSystem;
  case coord of
    TECCurve.COORD_AFFINE:
      begin
        Y1 := RawYCoord;

        L1 := Y1.Divide(X1).Add(X1);

        X3 := L1.Square().Add(L1).Add(ecCurve.a);
        Y3 := X1.SquarePlusProduct(X3, L1.AddOne());

        result := TF2mPoint.Create(ecCurve, X3, Y3, IsCompressed);
        Exit;
      end;
    TECCurve.COORD_HOMOGENEOUS:
      begin
        Y1 := RawYCoord;
        Z1 := RawZCoords[0];

        Z1IsOne := Z1.IsOne;

        if Z1IsOne then
        begin
          X1Z1 := X1;
        end
        else
        begin
          X1Z1 := X1.Multiply(Z1);
        end;

        if Z1IsOne then
        begin
          Y1Z1 := Y1;
        end
        else
        begin
          Y1Z1 := Y1.Multiply(Z1);
        end;

        X1Sq := X1.Square();
        S := X1Sq.Add(Y1Z1);
        V := X1Z1;
        vSquared := V.Square();
        sv := S.Add(V);
        h := sv.MultiplyPlusProduct(S, vSquared, ecCurve.a);

        X3 := V.Multiply(h);
        Y3 := X1Sq.Square().MultiplyPlusProduct(V, h, sv);
        Z3 := V.Multiply(vSquared);

        result := TF2mPoint.Create(ecCurve, X3, Y3,
          TCryptoLibGenericArray<IECFieldElement>.Create(Z3), IsCompressed);
        Exit;
      end;
    TECCurve.COORD_LAMBDA_PROJECTIVE:
      begin
        L1 := RawYCoord;
        Z1 := RawZCoords[0];

        Z1IsOne := Z1.IsOne;
        if Z1IsOne then
        begin
          L1Z1 := L1;
        end
        else
        begin
          L1Z1 := L1.Multiply(Z1);
        end;

        if Z1IsOne then
        begin
          Z1Sq := Z1;
        end
        else
        begin
          Z1Sq := Z1.Square();
        end;

        a := ecCurve.a;

        if Z1IsOne then
        begin
          aZ1Sq := a;
        end
        else
        begin
          aZ1Sq := a.Multiply(Z1Sq);
        end;

        T := L1.Square().Add(L1Z1).Add(aZ1Sq);
        if (T.IsZero) then
        begin
          result := TF2mPoint.Create(ecCurve, T, ecCurve.b.Sqrt(),
            IsCompressed);
          Exit;
        end;

        X3 := T.Square();

        if Z1IsOne then
        begin
          Z3 := T;
        end
        else
        begin
          Z3 := T.Multiply(Z1Sq);
        end;

        b := ecCurve.b;

        if (b.BitLength < (TBits.Asr32(ecCurve.FieldSize, 1))) then
        begin
          t1 := L1.Add(X1).Square();

          if (b.IsOne) then
          begin
            t2 := aZ1Sq.Add(Z1Sq).Square();
          end
          else
          begin
            // TODO Can be calculated with one square if we pre-compute sqrt(b)
            t2 := aZ1Sq.SquarePlusProduct(b, Z1Sq.Square());
          end;
          L3 := t1.Add(T).Add(Z1Sq).Multiply(t1).Add(t2).Add(X3);
          if (a.IsZero) then
          begin
            L3 := L3.Add(Z3);
          end
          else if (not a.IsOne) then
          begin
            L3 := L3.Add(a.AddOne().Multiply(Z3));
          end
        end
        else
        begin

          if Z1IsOne then
          begin
            X1Z1 := X1;
          end
          else
          begin
            X1Z1 := X1.Multiply(Z1);
          end;
          L3 := X1Z1.SquarePlusProduct(T, L1Z1).Add(X3).Add(Z3);
        end;

        result := TF2mPoint.Create(ecCurve, X3, L3,
          TCryptoLibGenericArray<IECFieldElement>.Create(Z3), IsCompressed);
        Exit;
      end
  else
    begin
      raise EInvalidOperationCryptoLibException.CreateRes
        (@SUnSupportedCoordinateSystem);
    end;
  end;
end;

function TF2mPoint.TwicePlus(const b: IECPoint): IECPoint;
var
  ecCurve: IECCurve;
  X1, X2, Z2, L1, L2, Z1, X1Sq, L1Sq, Z1Sq, L1Z1, T, L2plus1, a, X2Z1Sq, bigB,
    X3, L3, Z3: IECFieldElement;
  coord: Int32;
begin
  if (IsInfinity) then
  begin
    result := b;
    Exit;
  end;
  if (b.IsInfinity) then
  begin
    result := Twice();
    Exit;
  end;

  ecCurve := curve;

  X1 := RawXCoord;
  if (X1.IsZero) then
  begin
    // A point with X == 0 is it's own additive inverse
    result := b;
    Exit;
  end;

  coord := ecCurve.CoordinateSystem;

  case coord of
    TECCurve.COORD_LAMBDA_PROJECTIVE:
      begin

        // NOTE: twicePlus() only optimized for lambda-affine argument
        X2 := b.RawXCoord;
        Z2 := b.RawZCoords[0];
        if ((X2.IsZero) or (not Z2.IsOne)) then
        begin
          result := Twice().Add(b);
          Exit;
        end;

        L1 := RawYCoord;
        Z1 := RawZCoords[0];
        L2 := b.RawYCoord;

        X1Sq := X1.Square();
        L1Sq := L1.Square();
        Z1Sq := Z1.Square();
        L1Z1 := L1.Multiply(Z1);

        T := ecCurve.a.Multiply(Z1Sq).Add(L1Sq).Add(L1Z1);
        L2plus1 := L2.AddOne();
        a := ecCurve.a.Add(L2plus1).Multiply(Z1Sq).Add(L1Sq)
          .MultiplyPlusProduct(T, X1Sq, Z1Sq);
        X2Z1Sq := X2.Multiply(Z1Sq);
        bigB := X2Z1Sq.Add(T).Square();

        if (bigB.IsZero) then
        begin
          if (a.IsZero) then
          begin
            result := b.Twice();
            Exit;
          end;

          result := ecCurve.Infinity;
          Exit;
        end;

        if (a.IsZero) then
        begin
          result := TF2mPoint.Create(ecCurve, a, ecCurve.b.Sqrt(),
            IsCompressed);
          Exit;
        end;

        X3 := a.Square().Multiply(X2Z1Sq);
        Z3 := a.Multiply(bigB).Multiply(Z1Sq);
        L3 := a.Add(bigB).Square().MultiplyPlusProduct(T, L2plus1, Z3);

        result := TF2mPoint.Create(ecCurve, X3, L3,
          TCryptoLibGenericArray<IECFieldElement>.Create(Z3), IsCompressed);
        Exit;
      end
  else
    begin
      result := Twice().Add(b);
      Exit;
    end;
  end;

end;

{ TECPointBase }

constructor TECPointBase.Create(const curve: IECCurve;
  const x, y: IECFieldElement; withCompression: Boolean);
begin
  Inherited Create(curve, x, y, withCompression);
end;

constructor TECPointBase.Create(const curve: IECCurve;
  const x, y: IECFieldElement;
  const zs: TCryptoLibGenericArray<IECFieldElement>; withCompression: Boolean);
begin
  Inherited Create(curve, x, y, zs, withCompression);
end;

destructor TECPointBase.Destroy;
begin
  inherited Destroy;
end;

function TECPointBase.GetEncoded(compressed: Boolean): TCryptoLibByteArray;
var
  normed: IECPoint;
  lx, ly, PO: TCryptoLibByteArray;
begin
  if (IsInfinity) then
  begin
    System.SetLength(result, 1);
    Exit;
  end;

  normed := Normalize();

  lx := normed.XCoord.GetEncoded();

  if (compressed) then
  begin
    System.SetLength(PO, System.Length(lx) + 1);
    if normed.CompressionYTilde then
    begin
      PO[0] := Byte($03);
    end
    else
    begin
      PO[0] := Byte($02);
    end;

    System.Move(lx[0], PO[1], System.Length(lx) * System.SizeOf(Byte));

    result := PO;
    Exit;
  end;

  ly := normed.YCoord.GetEncoded();

  System.SetLength(PO, System.Length(lx) + System.Length(ly) + 1);

  PO[0] := $04;

  System.Move(lx[0], PO[1], System.Length(lx) * System.SizeOf(Byte));
  System.Move(ly[0], PO[System.Length(lx) + 1],
    System.Length(ly) * System.SizeOf(Byte));

  result := PO;

end;

function TECPointBase.Multiply(k: TBigInteger): IECPoint;
begin
  result := curve.GetMultiplier().Multiply(Self as IECPoint, k);
end;

{ TAbstractFpPoint }

function TAbstractFpPoint.GetCompressionYTilde: Boolean;
begin
  result := AffineYCoord.TestBitZero();
end;

constructor TAbstractFpPoint.Create(const curve: IECCurve;
  const x, y: IECFieldElement; withCompression: Boolean);
begin
  Inherited Create(curve, x, y, withCompression);
end;

constructor TAbstractFpPoint.Create(const curve: IECCurve;
  const x, y: IECFieldElement;
  const zs: TCryptoLibGenericArray<IECFieldElement>; withCompression: Boolean);
begin
  Inherited Create(curve, x, y, zs, withCompression);
end;

destructor TAbstractFpPoint.Destroy;
begin
  inherited Destroy;
end;

function TAbstractFpPoint.SatisfiesCurveEquation: Boolean;
var
  lx, ly, a, b, lhs, rhs, Z, Z2, Z3, Z4, Z6: IECFieldElement;
begin
  lx := RawXCoord;
  ly := RawYCoord;
  a := curve.a;
  b := curve.b;
  lhs := ly.Square();

  case CurveCoordinateSystem of
    TECCurve.COORD_AFFINE:
      begin
        // do nothing
      end;

    TECCurve.COORD_HOMOGENEOUS:
      begin
        Z := RawZCoords[0];
        if (not Z.IsOne) then
        begin
          Z2 := Z.Square();
          Z3 := Z.Multiply(Z2);
          lhs := lhs.Multiply(Z);
          a := a.Multiply(Z2);
          b := b.Multiply(Z3);
        end;
      end;

    TECCurve.COORD_JACOBIAN, TECCurve.COORD_JACOBIAN_CHUDNOVSKY,
      TECCurve.COORD_JACOBIAN_MODIFIED:
      begin
        Z := RawZCoords[0];
        if (not Z.IsOne) then
        begin
          Z2 := Z.Square();
          Z4 := Z2.Square();
          Z6 := Z2.Multiply(Z4);
          a := a.Multiply(Z4);
          b := b.Multiply(Z6);
        end;
      end
  else
    begin
      raise EInvalidOperationCryptoLibException.CreateRes
        (@SUnSupportedCoordinateSystem);
    end;

  end;

  rhs := lx.Square().Add(a).Multiply(lx).Add(b);
  result := lhs.Equals(rhs);
end;

function TAbstractFpPoint.Subtract(const b: IECPoint): IECPoint;
begin
  if (b.IsInfinity) then
  begin
    result := Self;
    Exit;
  end;

  // Add -b
  result := Add(b.Negate());
end;

{ TFpPoint }

function TFpPoint.Add(const b: IECPoint): IECPoint;
var
  ecCurve: IECCurve;
  coord: Int32;
  gamma, X1, X2, Y1, Y2, dx, dy, X3, Y3, Z1, Z2, U1, V1, U2, V2, U, V, W, a, Z3,
    S2, S1, vSquared, vCubed, vSquaredV2, Z1Squared, bigU2, Z3Squared, c, W1,
    W2, A1, Z1Cubed, Z2Squared, bigU1, h, R, HSquared, G, W3,
    Z2Cubed: IECFieldElement;
  zs: TCryptoLibGenericArray<IECFieldElement>;
  Z1IsOne, Z2IsOne: Boolean;
begin
  if (IsInfinity) then
  begin
    result := b;
    Exit;
  end;
  if (b.IsInfinity) then
  begin
    result := Self;
    Exit;
  end;

  if (Self as IECPoint = b) then
  begin
    result := Twice();
    Exit;
  end;

  ecCurve := curve;
  coord := ecCurve.CoordinateSystem;

  X1 := RawXCoord;
  Y1 := RawYCoord;
  X2 := b.RawXCoord;
  Y2 := b.RawYCoord;

  case coord of
    TECCurve.COORD_AFFINE:
      begin

        dx := X2.Subtract(X1);
        dy := Y2.Subtract(Y1);

        if (dx.IsZero) then
        begin
          if (dy.IsZero) then
          begin
            // this == b, i.e. this must be doubled
            result := Twice();
            Exit;
          end;

          // this == -b, i.e. the result is the point at infinity
          result := curve.Infinity;
          Exit;
        end;

        gamma := dy.Divide(dx);
        X3 := gamma.Square().Subtract(X1).Subtract(X2);
        Y3 := gamma.Multiply(X1.Subtract(X3)).Subtract(Y1);

        result := TFpPoint.Create(curve, X3, Y3, IsCompressed);
        Exit;
      end;
    TECCurve.COORD_HOMOGENEOUS:
      begin
        Z1 := RawZCoords[0];
        Z2 := b.RawZCoords[0];

        Z1IsOne := Z1.IsOne;
        Z2IsOne := Z2.IsOne;

        if Z1IsOne then
        begin
          U1 := Y2;
        end
        else
        begin
          U1 := Y2.Multiply(Z1);
        end;

        if Z2IsOne then
        begin
          U2 := Y1;
        end
        else
        begin
          U2 := Y1.Multiply(Z2);
        end;

        U := U1.Subtract(U2);

        if Z1IsOne then
        begin
          V1 := X2;
        end
        else
        begin
          V1 := X2.Multiply(Z1);
        end;

        if Z2IsOne then
        begin
          V2 := X1;
        end
        else
        begin
          V2 := X1.Multiply(Z2);
        end;

        V := V1.Subtract(V2);

        // Check if b = this or b = -this
        if (V.IsZero) then
        begin
          if (U.IsZero) then
          begin
            // this = b, i.e. this must be doubled
            result := Twice();
            Exit;
          end;

          // this = -b, i.e. the result is the point at infinity
          result := ecCurve.Infinity;
          Exit;
        end;

        // TODO Optimize for when w = 1
        if Z1IsOne then
        begin
          W := Z2;
        end
        else if Z2IsOne then

        begin
          W := Z1;
        end
        else
        begin
          W := Z1.Multiply(Z2);
        end;

        vSquared := V.Square();
        vCubed := vSquared.Multiply(V);
        vSquaredV2 := vSquared.Multiply(V2);
        a := U.Square().Multiply(W).Subtract(vCubed).Subtract(Two(vSquaredV2));

        X3 := V.Multiply(a);
        Y3 := vSquaredV2.Subtract(a).MultiplyMinusProduct(U, U2, vCubed);
        Z3 := vCubed.Multiply(W);

        result := TFpPoint.Create(ecCurve, X3, Y3,
          TCryptoLibGenericArray<IECFieldElement>.Create(Z3), IsCompressed);
        Exit;
      end;

    TECCurve.COORD_JACOBIAN, TECCurve.COORD_JACOBIAN_MODIFIED:
      begin
        Z1 := RawZCoords[0];
        Z2 := b.RawZCoords[0];

        Z1IsOne := Z1.IsOne;

        X3 := Nil;
        Y3 := Nil;
        Z3 := Nil;
        Z3Squared := Nil;

        if ((not Z1IsOne) and (Z1.Equals(Z2))) then
        begin
          // TODO Make this available as public method coZAdd?

          dx := X1.Subtract(X2);
          dy := Y1.Subtract(Y2);
          if (dx.IsZero) then
          begin
            if (dy.IsZero) then
            begin
              result := Twice();
              Exit;
            end;
            result := ecCurve.Infinity;
            Exit;
          end;

          c := dx.Square();
          W1 := X1.Multiply(c);
          W2 := X2.Multiply(c);
          A1 := W1.Subtract(W2).Multiply(Y1);

          X3 := dy.Square().Subtract(W1).Subtract(W2);
          Y3 := W1.Subtract(X3).Multiply(dy).Subtract(A1);
          Z3 := dx;

          if (Z1IsOne) then
          begin
            Z3Squared := c;
          end
          else
          begin
            Z3 := Z3.Multiply(Z1);
          end
        end
        else
        begin

          if (Z1IsOne) then
          begin
            Z1Squared := Z1;
            bigU2 := X2;
            S2 := Y2;
          end
          else
          begin
            Z1Squared := Z1.Square();
            bigU2 := Z1Squared.Multiply(X2);
            Z1Cubed := Z1Squared.Multiply(Z1);
            S2 := Z1Cubed.Multiply(Y2);
          end;

          Z2IsOne := Z2.IsOne;

          if (Z2IsOne) then
          begin
            Z2Squared := Z2;
            bigU1 := X1;
            S1 := Y1;
          end
          else
          begin
            Z2Squared := Z2.Square();
            bigU1 := Z2Squared.Multiply(X1);
            Z2Cubed := Z2Squared.Multiply(Z2);
            S1 := Z2Cubed.Multiply(Y1);
          end;

          h := bigU1.Subtract(bigU2);
          R := S1.Subtract(S2);

          // Check if b == this or b == -this
          if (h.IsZero) then
          begin
            if (R.IsZero) then
            begin
              // this == b, i.e. this must be doubled
              result := Twice();
              Exit;
            end;

            // this == -b, i.e. the result is the point at infinity
            result := ecCurve.Infinity;
            Exit;
          end;

          HSquared := h.Square();
          G := HSquared.Multiply(h);
          V := HSquared.Multiply(bigU1);

          X3 := R.Square().Add(G).Subtract(Two(V));
          Y3 := V.Subtract(X3).MultiplyMinusProduct(R, G, S1);

          Z3 := h;
          if (not Z1IsOne) then
          begin
            Z3 := Z3.Multiply(Z1);
          end;
          if (not Z2IsOne) then
          begin
            Z3 := Z3.Multiply(Z2);
          end;

          // Alternative calculation of Z3 using fast square
          // X3 := four(X3);
          // Y3 := eight(Y3);
          // Z3 := doubleProductFromSquares(Z1, Z2, Z1Squared, Z2Squared).Multiply(H);

          if (Z3 = h) then
          begin
            Z3Squared := HSquared;
          end;
        end;

        if (coord = TECCurve.COORD_JACOBIAN_MODIFIED) then
        begin
          // TODO If the result will only be used in a subsequent addition, we don't need W3
          W3 := CalculateJacobianModifiedW(Z3, Z3Squared);

          zs := TCryptoLibGenericArray<IECFieldElement>.Create(Z3, W3);
        end
        else
        begin
          zs := TCryptoLibGenericArray<IECFieldElement>.Create(Z3);
        end;

        result := TFpPoint.Create(ecCurve, X3, Y3, zs, IsCompressed);
        Exit;
      end
  else
    begin
      raise EInvalidOperationCryptoLibException.CreateRes
        (@SUnSupportedCoordinateSystem);
    end;

  end;

end;

function TFpPoint.CalculateJacobianModifiedW(const Z: IECFieldElement;
  const ZSquared: IECFieldElement): IECFieldElement;
var
  a4, W, a4Neg, LZSquared: IECFieldElement;
begin
  a4 := curve.a;
  LZSquared := ZSquared;
  if ((a4.IsZero) or (Z.IsOne)) then
  begin
    result := a4;
    Exit;
  end;

  if (LZSquared = Nil) then
  begin
    LZSquared := Z.Square();
  end;

  W := LZSquared.Square();
  a4Neg := a4.Negate();
  if (a4Neg.BitLength < a4.BitLength) then
  begin
    W := W.Multiply(a4Neg).Negate();
  end
  else
  begin
    W := W.Multiply(a4);
  end;
  result := W;
end;

constructor TFpPoint.Create(const curve: IECCurve; const x, y: IECFieldElement;
  const zs: TCryptoLibGenericArray<IECFieldElement>; withCompression: Boolean);
begin
  Inherited Create(curve, x, y, zs, withCompression);
end;

constructor TFpPoint.Create(const curve: IECCurve; const x, y: IECFieldElement;
  withCompression: Boolean);
begin
  Inherited Create(curve, x, y, withCompression);
  if ((x = Nil) <> (y = Nil)) then
  begin
    raise EArgumentCryptoLibException.CreateRes(@SNilFieldElement);
  end;
end;

constructor TFpPoint.Create(const curve: IECCurve; const x, y: IECFieldElement);
begin
  Create(curve, x, y, false);
end;

destructor TFpPoint.Destroy;
begin
  inherited Destroy;
end;

function TFpPoint.Detach: IECPoint;
begin
  result := TFpPoint.Create(Nil, AffineXCoord, AffineYCoord, false);
end;

function TFpPoint.DoubleProductFromSquares(const a, b, aSquared,
  bSquared: IECFieldElement): IECFieldElement;
begin
  // /*
  // * NOTE: If squaring in the field is faster than multiplication, then this is a quicker
  // * way to calculate 2.A.B, if A^2 and B^2 are already known.
  // */
  result := a.Add(b).Square().Subtract(aSquared).Subtract(bSquared);
end;

function TFpPoint.Eight(const x: IECFieldElement): IECFieldElement;
begin
  result := Four(Two(x));
end;

function TFpPoint.Four(const x: IECFieldElement): IECFieldElement;
begin
  result := Two(Two(x));
end;

function TFpPoint.GetJacobianModifiedW: IECFieldElement;
var
  ZZ: TCryptoLibGenericArray<IECFieldElement>;
  W: IECFieldElement;
begin
  ZZ := RawZCoords;
  W := ZZ[1];
  if (W = Nil) then
  begin
    // NOTE: Rarely, TwicePlus will result in the need for a lazy W1 calculation here
    W := CalculateJacobianModifiedW(ZZ[0], Nil);
    ZZ[1] := W;
  end;
  result := W;
end;

function TFpPoint.GetZCoord(index: Int32): IECFieldElement;
begin
  if ((index = 1) and (TECCurve.COORD_JACOBIAN_MODIFIED = CurveCoordinateSystem))
  then
  begin
    result := GetJacobianModifiedW();
    Exit;
  end;

  result := (Inherited GetZCoord(index));
end;

function TFpPoint.Negate: IECPoint;
var
  Lcurve: IECCurve;
  coord: Int32;
begin
  if (IsInfinity) then
  begin
    result := Self;
    Exit;
  end;

  Lcurve := curve;
  coord := Lcurve.CoordinateSystem;

  if (TECCurve.COORD_AFFINE <> coord) then
  begin
    result := TFpPoint.Create(Lcurve, RawXCoord, RawYCoord.Negate(), RawZCoords,
      IsCompressed);
    Exit;
  end;

  result := TFpPoint.Create(Lcurve, RawXCoord, RawYCoord.Negate(),
    IsCompressed);
end;

function TFpPoint.Three(const x: IECFieldElement): IECFieldElement;
begin
  result := Two(x).Add(x);
end;

function TFpPoint.ThreeTimes: IECPoint;
var
  Y1, X1, _2Y1, lx, Z, ly, d, bigD, i, L1, L2, X4, Y4: IECFieldElement;
  ecCurve: IECCurve;
  coord: Int32;
begin
  if (IsInfinity) then
  begin
    result := Self;
    Exit;
  end;

  Y1 := RawYCoord;
  if (Y1.IsZero) then
  begin
    result := Self;
    Exit;
  end;

  ecCurve := curve;
  coord := ecCurve.CoordinateSystem;

  case coord of
    TECCurve.COORD_AFFINE:
      begin

        X1 := RawXCoord;

        _2Y1 := Two(Y1);
        lx := _2Y1.Square();
        Z := Three(X1.Square()).Add(curve.a);
        ly := Z.Square();

        d := Three(X1).Multiply(lx).Subtract(ly);
        if (d.IsZero) then
        begin
          result := curve.Infinity;
          Exit;
        end;

        bigD := d.Multiply(_2Y1);
        i := bigD.Invert();
        L1 := d.Multiply(i).Multiply(Z);
        L2 := lx.Square().Multiply(i).Subtract(L1);

        X4 := (L2.Subtract(L1)).Multiply(L1.Add(L2)).Add(X1);
        Y4 := (X1.Subtract(X4)).Multiply(L2).Subtract(Y1);
        result := TFpPoint.Create(curve, X4, Y4, IsCompressed);
        Exit;
      end;
    TECCurve.COORD_JACOBIAN_MODIFIED:
      begin
        result := TwiceJacobianModified(false).Add(Self);
        Exit;
      end
  else
    begin
      // NOTE: Be careful about recursions between TwicePlus and ThreeTimes
      result := Twice().Add(Self);
    end;

  end;

end;

function TFpPoint.TimesPow2(e: Int32): IECPoint;
var
  ecCurve: IECCurve;
  Y1, W1, X1, Z1, Z1Sq, X1Squared, M, _2Y1, _2Y1Squared, S, _4T, _8T, zInv,
    zInv2, zInv3: IECFieldElement;
  coord, i: Int32;
begin
  if (e < 0) then
  begin
    raise EArgumentCryptoLibException.CreateRes(@SCannotBeNegative);
  end;
  if ((e = 0) or (IsInfinity)) then
  begin
    result := Self;
    Exit;
  end;
  if (e = 1) then
  begin
    result := Twice();
    Exit;
  end;

  ecCurve := curve;

  Y1 := RawYCoord;
  if (Y1.IsZero) then
  begin
    result := ecCurve.Infinity;
    Exit;
  end;

  coord := ecCurve.CoordinateSystem;

  W1 := ecCurve.a;
  X1 := RawXCoord;
  if RawZCoords = Nil then
  begin
    Z1 := ecCurve.FromBigInteger(TBigInteger.One);
  end
  else
  begin
    Z1 := RawZCoords[0];
  end;

  if (not Z1.IsOne) then
  begin
    case coord of
      TECCurve.COORD_HOMOGENEOUS:
        begin
          Z1Sq := Z1.Square();
          X1 := X1.Multiply(Z1);
          Y1 := Y1.Multiply(Z1Sq);
          W1 := CalculateJacobianModifiedW(Z1, Z1Sq);
        end;
      TECCurve.COORD_JACOBIAN:
        begin
          W1 := CalculateJacobianModifiedW(Z1, Nil);
        end;

      TECCurve.COORD_JACOBIAN_MODIFIED:
        begin
          W1 := GetJacobianModifiedW();
        end;
    end;

  end;

  i := 0;
  while i < e do
  begin
    if (Y1.IsZero) then
    begin
      result := ecCurve.Infinity;
      Exit;
    end;

    X1Squared := X1.Square();
    M := Three(X1Squared);
    _2Y1 := Two(Y1);
    _2Y1Squared := _2Y1.Multiply(Y1);
    S := Two(X1.Multiply(_2Y1Squared));
    _4T := _2Y1Squared.Square();
    _8T := Two(_4T);

    if (not W1.IsZero) then
    begin
      M := M.Add(W1);
      W1 := Two(_8T.Multiply(W1));
    end;

    X1 := M.Square().Subtract(Two(S));
    Y1 := M.Multiply(S.Subtract(X1)).Subtract(_8T);
    if Z1.IsOne then
    begin
      Z1 := _2Y1;
    end
    else
    begin
      Z1 := _2Y1.Multiply(Z1);
    end;

    System.Inc(i);
  end;

  case coord of
    TECCurve.COORD_AFFINE:
      begin
        zInv := Z1.Invert();
        zInv2 := zInv.Square();
        zInv3 := zInv2.Multiply(zInv);

        result := TFpPoint.Create(ecCurve, X1.Multiply(zInv2),
          Y1.Multiply(zInv3), IsCompressed);
        Exit;
      end;

    TECCurve.COORD_HOMOGENEOUS:
      begin
        X1 := X1.Multiply(Z1);
        Z1 := Z1.Multiply(Z1.Square());
        result := TFpPoint.Create(ecCurve, X1, Y1,
          TCryptoLibGenericArray<IECFieldElement>.Create(Z1), IsCompressed);
        Exit;
      end;
    TECCurve.COORD_JACOBIAN:
      begin
        result := TFpPoint.Create(ecCurve, X1, Y1,
          TCryptoLibGenericArray<IECFieldElement>.Create(Z1), IsCompressed);
        Exit;
      end;

    TECCurve.COORD_JACOBIAN_MODIFIED:
      begin
        result := TFpPoint.Create(ecCurve, X1, Y1,
          TCryptoLibGenericArray<IECFieldElement>.Create(Z1, W1), IsCompressed);
        Exit;
      end
  else
    begin
      raise EInvalidOperationCryptoLibException.CreateRes
        (@SUnSupportedCoordinateSystem);
    end;

  end;

end;

function TFpPoint.Twice: IECPoint;
var
  ecCurve: IECCurve;
  Y1, X1, X1Squared, gamma, X3, Y3, Z1, W, S, T, b, _4B, h, _2s, _2t,
    _4sSquared, Z3, M, Y1Squared, a4, a4Neg, Z1Squared, Z1Pow4: IECFieldElement;
  coord: Int32;
  Z1IsOne: Boolean;
begin
  if (IsInfinity) then
  begin
    result := Self;
    Exit;
  end;

  ecCurve := curve;

  Y1 := RawYCoord;

  if (Y1.IsZero) then
  begin
    result := ecCurve.Infinity;
    Exit;
  end;

  coord := ecCurve.CoordinateSystem;

  X1 := RawXCoord;

  case coord of
    TECCurve.COORD_AFFINE:
      begin
        X1Squared := X1.Square();
        gamma := Three(X1Squared).Add(curve.a).Divide(Two(Y1));
        X3 := gamma.Square().Subtract(Two(X1));
        Y3 := gamma.Multiply(X1.Subtract(X3)).Subtract(Y1);

        result := TFpPoint.Create(curve, X3, Y3, IsCompressed);
        Exit;
      end;

    TECCurve.COORD_HOMOGENEOUS:
      begin
        Z1 := RawZCoords[0];

        Z1IsOne := Z1.IsOne;

        // TODO Optimize for small negative a4 and -3
        W := ecCurve.a;
        if ((not W.IsZero) and (not Z1IsOne)) then
        begin
          W := W.Multiply(Z1.Square());
        end;
        W := W.Add(Three(X1.Square()));

        if Z1IsOne then
        begin
          S := Y1;
        end
        else
        begin
          S := Y1.Multiply(Z1);
        end;

        if Z1IsOne then
        begin
          T := Y1.Square();
        end
        else
        begin
          T := S.Multiply(Y1);
        end;

        b := X1.Multiply(T);
        _4B := Four(b);
        h := W.Square().Subtract(Two(_4B));

        _2s := Two(S);
        X3 := h.Multiply(_2s);
        _2t := Two(T);
        Y3 := _4B.Subtract(h).Multiply(W).Subtract(Two(_2t.Square()));

        if Z1IsOne then
        begin
          _4sSquared := Two(_2t);
        end
        else
        begin
          _4sSquared := _2s.Square();
        end;

        Z3 := Two(_4sSquared).Multiply(S);

        result := TFpPoint.Create(ecCurve, X3, Y3,
          TCryptoLibGenericArray<IECFieldElement>.Create(Z3), IsCompressed);
        Exit;
      end;

    TECCurve.COORD_JACOBIAN:
      begin
        Z1 := RawZCoords[0];

        Z1IsOne := Z1.IsOne;

        Y1Squared := Y1.Square();
        T := Y1Squared.Square();

        a4 := ecCurve.a;
        a4Neg := a4.Negate();

        if (a4Neg.ToBigInteger().Equals(TBigInteger.ValueOf(3))) then
        begin

          if Z1IsOne then
          begin
            Z1Squared := Z1;
          end
          else
          begin
            Z1Squared := Z1.Square();
          end;

          M := Three(X1.Add(Z1Squared).Multiply(X1.Subtract(Z1Squared)));
          S := Four(Y1Squared.Multiply(X1));
        end
        else
        begin
          X1Squared := X1.Square();
          M := Three(X1Squared);
          if (Z1IsOne) then
          begin
            M := M.Add(a4);
          end
          else if (not a4.IsZero) then
          begin

            if Z1IsOne then
            begin
              Z1Squared := Z1;
            end
            else
            begin
              Z1Squared := Z1.Square();
            end;

            Z1Pow4 := Z1Squared.Square();
            if (a4Neg.BitLength < a4.BitLength) then
            begin
              M := M.Subtract(Z1Pow4.Multiply(a4Neg));
            end
            else
            begin
              M := M.Add(Z1Pow4.Multiply(a4));
            end
          end;
          // S := two(doubleProductFromSquares(X1, Y1Squared, X1Squared, T));
          S := Four(X1.Multiply(Y1Squared));
        end;

        X3 := M.Square().Subtract(Two(S));
        Y3 := S.Subtract(X3).Multiply(M).Subtract(Eight(T));

        Z3 := Two(Y1);
        if (not Z1IsOne) then
        begin
          Z3 := Z3.Multiply(Z1);
        end;

        // Alternative calculation of Z3 using fast square
        // Z3 := doubleProductFromSquares(Y1, Z1, Y1Squared, Z1Squared);
        result := TFpPoint.Create(ecCurve, X3, Y3,
          TCryptoLibGenericArray<IECFieldElement>.Create(Z3), IsCompressed);
        Exit;
      end;

    TECCurve.COORD_JACOBIAN_MODIFIED:
      begin
        result := TwiceJacobianModified(True);
        Exit;
      end
  else
    begin
      raise EInvalidOperationCryptoLibException.CreateRes
        (@SUnSupportedCoordinateSystem);
    end;

  end;
end;

function TFpPoint.TwiceJacobianModified(calculateW: Boolean): IFpPoint;
var
  X1, Y1, Z1, W1, X1Squared, M, _2Y1, _2Y1Squared, S, X3, _4T, _8T, Y3, W3,
    Z3: IECFieldElement;
begin
  X1 := RawXCoord;
  Y1 := RawYCoord;
  Z1 := RawZCoords[0];
  W1 := GetJacobianModifiedW();

  X1Squared := X1.Square();
  M := Three(X1Squared).Add(W1);
  _2Y1 := Two(Y1);
  _2Y1Squared := _2Y1.Multiply(Y1);
  S := Two(X1.Multiply(_2Y1Squared));
  X3 := M.Square().Subtract(Two(S));
  _4T := _2Y1Squared.Square();
  _8T := Two(_4T);
  Y3 := M.Multiply(S.Subtract(X3)).Subtract(_8T);

  if calculateW then
  begin
    W3 := Two(_8T.Multiply(W1));
  end
  else
  begin
    W3 := Nil;
  end;

  if Z1.IsOne then
  begin
    Z3 := _2Y1;
  end
  else
  begin
    Z3 := _2Y1.Multiply(Z1);
  end;

  result := TFpPoint.Create(curve, X3, Y3,
    TCryptoLibGenericArray<IECFieldElement>.Create(Z3, W3), IsCompressed);
end;

function TFpPoint.TwicePlus(const b: IECPoint): IECPoint;
var
  Y1, X1, X2, Y2, dx, dy, lx, ly, d, i, L1, L2, X4, Y4, bigD: IECFieldElement;
  ecCurve: IECCurve;
  coord: Int32;

begin
  if (Self as IECPoint = b) then
  begin
    result := ThreeTimes();
    Exit;
  end;
  if (IsInfinity) then
  begin
    result := b;
    Exit;
  end;
  if (b.IsInfinity) then
  begin
    result := Twice();
    Exit;
  end;

  Y1 := RawYCoord;
  if (Y1.IsZero) then
  begin
    result := b;
    Exit;
  end;

  ecCurve := curve;
  coord := ecCurve.CoordinateSystem;

  case coord of
    TECCurve.COORD_AFFINE:
      begin
        X1 := RawXCoord;
        X2 := b.RawXCoord;
        Y2 := b.RawYCoord;

        dx := X2.Subtract(X1);
        dy := Y2.Subtract(Y1);

        if (dx.IsZero) then
        begin
          if (dy.IsZero) then
          begin
            // this == b i.e. the result is 3P
            result := ThreeTimes();
            Exit;
          end;

          // this == -b, i.e. the result is P
          result := Self;
          Exit;
        end;

        // / * * Optimized calculation of 2 p + Q, as described
        // in " Trading Inversions for * Multiplications
        // in Elliptic curve Cryptography ", by Ciet, Joye, Lauter,
        // Montgomery. * /

        lx := dx.Square();
        ly := dy.Square();
        d := lx.Multiply(Two(X1).Add(X2)).Subtract(ly);
        if (d.IsZero) then
        begin
          result := curve.Infinity;
          Exit;
        end;

        bigD := d.Multiply(dx);
        i := bigD.Invert();
        L1 := d.Multiply(i).Multiply(dy);
        L2 := Two(Y1).Multiply(lx).Multiply(dx).Multiply(i).Subtract(L1);
        X4 := (L2.Subtract(L1)).Multiply(L1.Add(L2)).Add(X2);
        Y4 := (X1.Subtract(X4)).Multiply(L2).Subtract(Y1);

        result := TFpPoint.Create(curve, X4, Y4, IsCompressed);
        Exit;
      end;
    TECCurve.COORD_JACOBIAN_MODIFIED:
      begin
        result := TwiceJacobianModified(false).Add(b);
        Exit;
      end
  else
    begin
      result := Twice().Add(b);
      Exit;
    end;
  end;

end;

function TFpPoint.Two(const x: IECFieldElement): IECFieldElement;
begin
  result := x.Add(x);
end;

{ TAbstractF2mPoint }

constructor TAbstractF2mPoint.Create(const curve: IECCurve;
  const x, y: IECFieldElement; withCompression: Boolean);
begin
  Inherited Create(curve, x, y, withCompression);
end;

constructor TAbstractF2mPoint.Create(const curve: IECCurve;
  const x, y: IECFieldElement;
  const zs: TCryptoLibGenericArray<IECFieldElement>; withCompression: Boolean);
begin
  Inherited Create(curve, x, y, zs, withCompression);
end;

destructor TAbstractF2mPoint.Destroy;
begin
  inherited Destroy;
end;

function TAbstractF2mPoint.SatisfiesCurveEquation: Boolean;
var
  Z, Z2, Z3, x, ly, a, b, lhs, rhs, L, X2, Z4: IECFieldElement;
  ecCurve: IECCurve;
  coord: Int32;
  ZIsOne: Boolean;
begin
  ecCurve := curve;
  x := RawXCoord;
  ly := RawYCoord;
  a := ecCurve.a;
  b := ecCurve.b;

  coord := ecCurve.CoordinateSystem;
  if (coord = TECCurve.COORD_LAMBDA_PROJECTIVE) then
  begin
    Z := RawZCoords[0];
    ZIsOne := Z.IsOne;

    if (x.IsZero) then
    begin
      // NOTE: For x == 0, we expect the affine-y instead of the lambda-y
      lhs := ly.Square();
      rhs := b;
      if (not ZIsOne) then
      begin
        Z2 := Z.Square();
        rhs := rhs.Multiply(Z2);
      end
    end
    else
    begin
      L := ly;
      X2 := x.Square();
      if (ZIsOne) then
      begin
        lhs := L.Square().Add(L).Add(a);
        rhs := X2.Square().Add(b);
      end
      else
      begin
        Z2 := Z.Square();
        Z4 := Z2.Square();
        lhs := L.Add(Z).MultiplyPlusProduct(L, a, Z2);
        // TODO If sqrt(b) is precomputed this can be simplified to a single square
        rhs := X2.SquarePlusProduct(b, Z4);
      end;
      lhs := lhs.Multiply(X2);
    end
  end
  else
  begin
    lhs := ly.Add(x).Multiply(ly);

    case coord of
      TECCurve.COORD_AFFINE:
        begin
          // do nothing;
        end;

      TECCurve.COORD_HOMOGENEOUS:
        begin
          Z := RawZCoords[0];
          if (not Z.IsOne) then
          begin
            Z2 := Z.Square();
            Z3 := Z.Multiply(Z2);
            lhs := lhs.Multiply(Z);
            a := a.Multiply(Z);
            b := b.Multiply(Z3);
          end;
        end

    else
      begin
        raise EInvalidOperationCryptoLibException.CreateRes
          (@SUnSupportedCoordinateSystem);
      end;

    end;

    rhs := x.Add(a).Multiply(x.Square()).Add(b);
  end;

  result := lhs.Equals(rhs);
end;

function TAbstractF2mPoint.SatisfiesOrder: Boolean;
var
  cofactor: TBigInteger;
  n: IECPoint;
  x, rhs, lambda, W, T: IECFieldElement;
  Lcurve: IECCurve;
begin
  Lcurve := curve;
  cofactor := Lcurve.getCofactor();
  if (TBigInteger.Two.Equals(cofactor)) then
  begin
    // /*
    // *  Check that the trace of (X + A) is 0, then there exists a solution to L^2 + L = X + A,
    // *  and so a halving is possible, so this point is the double of another.
    // */
    n := Normalize();
    x := n.AffineXCoord;
    rhs := x.Add(Lcurve.a);
    result := (rhs as IAbstractF2mFieldElement).Trace() = 0;
    Exit;
  end;
  if (TBigInteger.Four.Equals(cofactor)) then
  begin
    // /*
    // * Solve L^2 + L = X + A to find the half of this point, if it exists (fail if not).
    // * Generate both possibilities for the square of the half-point's x-coordinate (w),
    // * and check if Tr(w + A) == 0 for at least one; then a second halving is possible
    // * (see comments for cofactor 2 above), so this point is four times another.
    // *
    // * Note: Tr(x^2) == Tr(x).
    // */
    n := Normalize();
    x := n.AffineXCoord;
    lambda := (Lcurve as IAbstractF2mCurve).SolveQuadraticEquation
      (x.Add(curve.a));
    if (lambda = Nil) then
    begin
      result := false;
      Exit;
    end;
    W := x.Multiply(lambda).Add(n.AffineYCoord);
    T := W.Add(Lcurve.a);
    result := ((T as IAbstractF2mFieldElement).Trace() = 0) or
      ((T.Add(x) as IAbstractF2mFieldElement).Trace() = 0);
    Exit;
  end;

  result := Inherited SatisfiesOrder();
end;

function TAbstractF2mPoint.ScaleX(const scale: IECFieldElement): IECPoint;
var
  lx, L, X2, L2, Z, Z2: IECFieldElement;
begin
  if (IsInfinity) then
  begin
    result := Self;
    Exit;
  end;

  case CurveCoordinateSystem of
    TECCurve.COORD_LAMBDA_AFFINE:
      begin
        // Y is actually Lambda (X + Y/X) here
        lx := RawXCoord;
        L := RawYCoord;

        X2 := lx.Multiply(scale);
        L2 := L.Add(lx).Divide(scale).Add(X2);

        result := curve.CreateRawPoint(lx, L2, RawZCoords, IsCompressed);
        Exit;
      end;

    TECCurve.COORD_LAMBDA_PROJECTIVE:
      begin
        // Y is actually Lambda (X + Y/X) here
        lx := RawXCoord;
        L := RawYCoord;
        Z := RawZCoords[0];

        // We scale the Z coordinate also, to avoid an inversion
        X2 := lx.Multiply(scale.Square());
        L2 := L.Add(lx).Add(X2);
        Z2 := Z.Multiply(scale);

        result := curve.CreateRawPoint(lx, L2,
          TCryptoLibGenericArray<IECFieldElement>.Create(Z2), IsCompressed);
        Exit;
      end
  else
    begin
      result := (Inherited ScaleX(scale));
    end;

  end;

end;

function TAbstractF2mPoint.ScaleY(const scale: IECFieldElement): IECPoint;
var
  lx, L, L2: IECFieldElement;
begin
  if (IsInfinity) then
  begin
    result := Self;
    Exit;
  end;

  case CurveCoordinateSystem of
    TECCurve.COORD_LAMBDA_AFFINE, TECCurve.COORD_LAMBDA_PROJECTIVE:
      begin
        lx := RawXCoord;
        L := RawYCoord;

        // Y is actually Lambda (X + Y/X) here
        L2 := L.Add(lx).Multiply(scale).Add(lx);

        result := curve.CreateRawPoint(lx, L2, RawZCoords, IsCompressed);
        Exit;
      end
  else
    begin
      result := (Inherited ScaleY(scale));
    end;
  end;

end;

function TAbstractF2mPoint.Subtract(const b: IECPoint): IECPoint;
begin
  if (b.IsInfinity) then
  begin
    result := Self;
  end;

  // Add -b
  result := Add(b.Negate());
end;

function TAbstractF2mPoint.Tau: IAbstractF2mPoint;
var
  ecCurve: IECCurve;
  coord: Int32;
  X1, Y1, Z1: IECFieldElement;
begin
  if (IsInfinity) then
  begin
    result := Self;
    Exit;
  end;

  ecCurve := curve;
  coord := ecCurve.CoordinateSystem;

  X1 := RawXCoord;

  case coord of
    TECCurve.COORD_AFFINE, TECCurve.COORD_LAMBDA_AFFINE:
      begin
        Y1 := RawYCoord;
        result := ecCurve.CreateRawPoint(X1.Square(), Y1.Square(), IsCompressed)
          as IAbstractF2mPoint;
        Exit;
      end;

    TECCurve.COORD_HOMOGENEOUS, TECCurve.COORD_LAMBDA_PROJECTIVE:
      begin
        Y1 := RawYCoord;
        Z1 := RawZCoords[0];
        result := ecCurve.CreateRawPoint(X1.Square(), Y1.Square(),
          TCryptoLibGenericArray<IECFieldElement>.Create(Z1.Square()),
          IsCompressed) as IAbstractF2mPoint;
        Exit;
      end

  else
    begin
      raise EInvalidOperationCryptoLibException.CreateRes
        (@SUnSupportedCoordinateSystem);
    end;

  end;
end;

function TAbstractF2mPoint.TauPow(pow: Int32): IAbstractF2mPoint;
var
  ecCurve: IECCurve;
  coord: Int32;
  X1, Y1, Z1: IECFieldElement;
begin
  if (IsInfinity) then
  begin
    result := Self;
    Exit;
  end;

  ecCurve := curve;
  coord := ecCurve.CoordinateSystem;

  X1 := RawXCoord;

  case coord of
    TECCurve.COORD_AFFINE, TECCurve.COORD_LAMBDA_AFFINE:
      begin
        Y1 := RawYCoord;
        result := ecCurve.CreateRawPoint(X1.SquarePow(pow), Y1.SquarePow(pow),
          IsCompressed) as IAbstractF2mPoint;
        Exit;
      end;

    TECCurve.COORD_HOMOGENEOUS, TECCurve.COORD_LAMBDA_PROJECTIVE:
      begin
        Y1 := RawYCoord;
        Z1 := RawZCoords[0];
        result := ecCurve.CreateRawPoint(X1.SquarePow(pow), Y1.SquarePow(pow),
          TCryptoLibGenericArray<IECFieldElement>.Create(Z1.SquarePow(pow)),
          IsCompressed) as IAbstractF2mPoint;
        Exit;
      end

  else
    begin
      raise EInvalidOperationCryptoLibException.CreateRes
        (@SUnSupportedCoordinateSystem);
    end;

  end;
end;

{ TECPoint.TValidityCallback }

constructor TECPoint.TValidityCallback.Create(const outer: IECPoint;
  decompressed, checkOrder: Boolean);
begin
  Inherited Create();
  Fm_outer := outer;
  Fm_decompressed := decompressed;
  Fm_checkOrder := checkOrder;
end;

function TECPoint.TValidityCallback.Precompute(const existing: IPreCompInfo)
  : IPreCompInfo;
var
  info: IValidityPrecompInfo;
begin
  if (not(Supports(existing, IValidityPrecompInfo, info))) then
  begin
    info := TValidityPrecompInfo.Create();
  end;

  if (info.hasFailed()) then
  begin
    result := info;
    Exit;
  end;
  if (not(info.hasCurveEquationPassed())) then
  begin
    if (not(Fm_decompressed) and not(Fm_outer.SatisfiesCurveEquation())) then
    begin
      info.reportFailed();
      result := info;
      Exit;
    end;
    info.reportCurveEquationPassed();
  end;

  if ((Fm_checkOrder) and (not(info.HasOrderPassed()))) then
  begin
    if (not(Fm_outer.SatisfiesOrder())) then
    begin
      info.reportFailed();
      result := info;
      Exit;
    end;
    info.reportOrderPassed();
  end;
  result := info;
end;

end.
