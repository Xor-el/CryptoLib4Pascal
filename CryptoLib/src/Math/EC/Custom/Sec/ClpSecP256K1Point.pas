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

unit ClpSecP256K1Point;

{$I ..\..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpNat,
  ClpNat256,
  ClpECPoint,
  ClpSecP256K1Field,
  ClpISecP256K1Point,
  ClpISecP256K1FieldElement,
  ClpIECFieldElement,
  ClpIECInterface,
  ClpCryptoLibTypes;

resourcestring
  SOneOfECFieldElementIsNil = 'Exactly One of the Field Elements is Nil';

type
  TSecP256K1Point = class sealed(TAbstractFpPoint, ISecP256K1Point)

  strict protected
    function Detach(): IECPoint; override;

  public

    /// <summary>
    /// Create a point which encodes without point compression.
    /// </summary>
    /// <param name="curve">
    /// the curve to use
    /// </param>
    /// <param name="x">
    /// affine x co-ordinate
    /// </param>
    /// <param name="y">
    /// affine y co-ordinate
    /// </param>
    constructor Create(const curve: IECCurve; const x, y: IECFieldElement);
      overload; deprecated 'Use ECCurve.createPoint to construct points';

    /// <summary>
    /// Create a point that encodes with or without point compresion.
    /// </summary>
    /// <param name="curve">
    /// the curve to use
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

    function Add(const b: IECPoint): IECPoint; override;
    function Negate(): IECPoint; override;

    function Twice(): IECPoint; override;
    function TwicePlus(const b: IECPoint): IECPoint; override;

    function ThreeTimes(): IECPoint; override;

  end;

implementation

uses
  // included here to avoid circular dependency :)
  ClpSecP256K1FieldElement;

{ TSecP256K1Point }

constructor TSecP256K1Point.Create(const curve: IECCurve;
  const x, y: IECFieldElement);
begin
  Create(curve, x, y, false);
end;

constructor TSecP256K1Point.Create(const curve: IECCurve;
  const x, y: IECFieldElement; withCompression: Boolean);
begin
  Inherited Create(curve, x, y, withCompression);
  if ((x = Nil) <> (y = Nil)) then
  begin
    raise EArgumentCryptoLibException.CreateRes(@SOneOfECFieldElementIsNil);
  end;
end;

constructor TSecP256K1Point.Create(const curve: IECCurve;
  const x, y: IECFieldElement;
  const zs: TCryptoLibGenericArray<IECFieldElement>; withCompression: Boolean);
begin
  Inherited Create(curve, x, y, zs, withCompression);
end;

function TSecP256K1Point.Add(const b: IECPoint): IECPoint;
var
  Lcurve: IECCurve;
  X1, Y1, X2, Y2, Z1, Z2, X3, Y3, Z3: ISecP256K1FieldElement;
  c: UInt32;
  tt1, t2, t3, t4, U2, S2, U1, S1, H, R, HSquared, G, V: TCryptoLibUInt32Array;
  Z1IsOne, Z2IsOne: Boolean;
  zs: TCryptoLibGenericArray<IECFieldElement>;
begin
  if (IsInfinity) then
  begin
    result := b;
    Exit;
  end;
  if (b.IsInfinity) then
  begin
    result := Self as IECPoint;
    Exit;
  end;
  if ((Self as IECPoint) = b) then
  begin
    result := Twice();
    Exit;
  end;

  Lcurve := curve;

  X1 := RawXCoord as ISecP256K1FieldElement;
  Y1 := RawYCoord as ISecP256K1FieldElement;
  X2 := b.RawXCoord as ISecP256K1FieldElement;
  Y2 := b.RawYCoord as ISecP256K1FieldElement;

  Z1 := RawZCoords[0] as ISecP256K1FieldElement;
  Z2 := b.RawZCoords[0] as ISecP256K1FieldElement;

  tt1 := TNat256.CreateExt();
  t2 := TNat256.Create();
  t3 := TNat256.Create();
  t4 := TNat256.Create();

  Z1IsOne := Z1.IsOne;

  if (Z1IsOne) then
  begin
    U2 := X2.x;
    S2 := Y2.x;
  end
  else
  begin
    S2 := t3;
    TSecP256K1Field.Square(Z1.x, S2);

    U2 := t2;
    TSecP256K1Field.Multiply(S2, X2.x, U2);

    TSecP256K1Field.Multiply(S2, Z1.x, S2);
    TSecP256K1Field.Multiply(S2, Y2.x, S2);
  end;

  Z2IsOne := Z2.IsOne;
  if (Z2IsOne) then
  begin
    U1 := X1.x;
    S1 := Y1.x;
  end
  else
  begin
    S1 := t4;
    TSecP256K1Field.Square(Z2.x, S1);

    U1 := tt1;
    TSecP256K1Field.Multiply(S1, X1.x, U1);

    TSecP256K1Field.Multiply(S1, Z2.x, S1);
    TSecP256K1Field.Multiply(S1, Y1.x, S1);
  end;

  H := TNat256.Create();
  TSecP256K1Field.Subtract(U1, U2, H);

  R := t2;
  TSecP256K1Field.Subtract(S1, S2, R);

  // Check if b = Self or b = -Self
  if (TNat256.IsZero(H)) then
  begin
    if (TNat256.IsZero(R)) then
    begin
      // Self = b, i.e. Self must be doubled
      result := Twice();
      Exit;
    end;

    // Self = -b, i.e. the result is the point at infinity
    result := Lcurve.Infinity;
    Exit;
  end;

  HSquared := t3;
  TSecP256K1Field.Square(H, HSquared);

  G := TNat256.Create();
  TSecP256K1Field.Multiply(HSquared, H, G);

  V := t3;
  TSecP256K1Field.Multiply(HSquared, U1, V);

  TSecP256K1Field.Negate(G, G);
  TNat256.Mul(S1, G, tt1);

  c := TNat256.AddBothTo(V, V, G);
  TSecP256K1Field.Reduce32(c, G);

  X3 := TSecP256K1FieldElement.Create(t4);
  TSecP256K1Field.Square(R, X3.x);
  TSecP256K1Field.Subtract(X3.x, G, X3.x);

  Y3 := TSecP256K1FieldElement.Create(G);
  TSecP256K1Field.Subtract(V, X3.x, Y3.x);
  TSecP256K1Field.MultiplyAddToExt(Y3.x, R, tt1);
  TSecP256K1Field.Reduce(tt1, Y3.x);

  Z3 := TSecP256K1FieldElement.Create(H);
  if (not(Z1IsOne)) then
  begin
    TSecP256K1Field.Multiply(Z3.x, Z1.x, Z3.x);
  end;
  if (not(Z2IsOne)) then
  begin
    TSecP256K1Field.Multiply(Z3.x, Z2.x, Z3.x);
  end;

  zs := TCryptoLibGenericArray<IECFieldElement>.Create(Z3);

  result := TSecP256K1Point.Create(Lcurve, X3, Y3, zs, IsCompressed)
    as IECPoint;
end;

function TSecP256K1Point.Detach: IECPoint;
begin
  result := TSecP256K1Point.Create(Nil, AffineXCoord, AffineYCoord) as IECPoint;
end;

function TSecP256K1Point.Negate: IECPoint;
begin
  if (IsInfinity) then
  begin
    result := Self as IECPoint;
    Exit;
  end;

  result := TSecP256K1Point.Create(curve, RawXCoord, RawYCoord.Negate(),
    RawZCoords, IsCompressed) as IECPoint;
end;

function TSecP256K1Point.ThreeTimes: IECPoint;
begin
  if ((IsInfinity) or (RawYCoord.IsZero)) then
  begin
    result := Self as IECPoint;
    Exit;
  end;

  // NOTE: Be careful about recursions between TwicePlus and ThreeTimes
  result := Twice().Add(Self as IECPoint);
end;

function TSecP256K1Point.Twice: IECPoint;
var
  Lcurve: IECCurve;
  Y1, X1, Z1, X3, Y3, Z3: ISecP256K1FieldElement;
  c: UInt32;
  Y1Squared, T, M, S, t1: TCryptoLibUInt32Array;
begin

  if (IsInfinity) then
  begin
    result := Self as IECPoint;
    Exit;
  end;

  Lcurve := curve;

  Y1 := RawYCoord as ISecP256K1FieldElement;
  if (Y1.IsZero) then
  begin
    result := Lcurve.Infinity;
    Exit;
  end;

  X1 := RawXCoord as ISecP256K1FieldElement;
  Z1 := RawZCoords[0] as ISecP256K1FieldElement;

  Y1Squared := TNat256.Create();
  TSecP256K1Field.Square(Y1.x, Y1Squared);

  T := TNat256.Create();
  TSecP256K1Field.Square(Y1Squared, T);

  M := TNat256.Create();
  TSecP256K1Field.Square(X1.x, M);
  c := TNat256.AddBothTo(M, M, M);
  TSecP256K1Field.Reduce32(c, M);

  S := Y1Squared;
  TSecP256K1Field.Multiply(Y1Squared, X1.x, S);
  c := TNat.ShiftUpBits(8, S, 2, 0);
  TSecP256K1Field.Reduce32(c, S);

  t1 := TNat256.Create();
  c := TNat.ShiftUpBits(8, T, 3, 0, t1);
  TSecP256K1Field.Reduce32(c, t1);

  X3 := TSecP256K1FieldElement.Create(T);
  TSecP256K1Field.Square(M, X3.x);
  TSecP256K1Field.Subtract(X3.x, S, X3.x);
  TSecP256K1Field.Subtract(X3.x, S, X3.x);

  Y3 := TSecP256K1FieldElement.Create(S);
  TSecP256K1Field.Subtract(S, X3.x, Y3.x);
  TSecP256K1Field.Multiply(Y3.x, M, Y3.x);
  TSecP256K1Field.Subtract(Y3.x, t1, Y3.x);

  Z3 := TSecP256K1FieldElement.Create(M);
  TSecP256K1Field.Twice(Y1.x, Z3.x);
  if (not(Z1.IsOne)) then
  begin
    TSecP256K1Field.Multiply(Z3.x, Z1.x, Z3.x);
  end;

  result := TSecP256K1Point.Create(Lcurve, X3, Y3,
    TCryptoLibGenericArray<IECFieldElement>.Create(Z3), IsCompressed)
    as IECPoint;
end;

function TSecP256K1Point.TwicePlus(const b: IECPoint): IECPoint;
var
  Y1: IECFieldElement;
begin
  if ((Self as IECPoint) = b) then
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

  result := Twice().Add(b);
end;

end.
