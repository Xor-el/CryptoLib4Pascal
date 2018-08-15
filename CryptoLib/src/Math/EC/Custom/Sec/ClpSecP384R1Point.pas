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

unit ClpSecP384R1Point;

{$I ..\..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpNat,
  ClpNat384,
  ClpECPoint,
  ClpSecP384R1Field,
  ClpISecP384R1Point,
  ClpISecP384R1FieldElement,
  ClpIECFieldElement,
  ClpIECInterface,
  ClpCryptoLibTypes;

resourcestring
  SOneOfECFieldElementIsNil = 'Exactly One of the Field Elements is Nil';

type
  TSecP384R1Point = class sealed(TAbstractFpPoint, ISecP384R1Point)

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
  ClpSecP384R1FieldElement;

{ TSecP384R1Point }

constructor TSecP384R1Point.Create(const curve: IECCurve;
  const x, y: IECFieldElement);
begin
  Create(curve, x, y, false);
end;

constructor TSecP384R1Point.Create(const curve: IECCurve;
  const x, y: IECFieldElement; withCompression: Boolean);
begin
  Inherited Create(curve, x, y, withCompression);
  if ((x = Nil) <> (y = Nil)) then
  begin
    raise EArgumentCryptoLibException.CreateRes(@SOneOfECFieldElementIsNil);
  end;
end;

constructor TSecP384R1Point.Create(const curve: IECCurve;
  const x, y: IECFieldElement;
  const zs: TCryptoLibGenericArray<IECFieldElement>; withCompression: Boolean);
begin
  Inherited Create(curve, x, y, zs, withCompression);
end;

function TSecP384R1Point.Add(const b: IECPoint): IECPoint;
var
  Lcurve: IECCurve;
  X1, Y1, X2, Y2, Z1, Z2, X3, Y3, Z3: ISecP384R1FieldElement;
  c: UInt32;
  tt1, tt2, t3, t4, U2, S2, U1, S1, H, R, HSquared, G, V: TCryptoLibUInt32Array;
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

  X1 := RawXCoord as ISecP384R1FieldElement;
  Y1 := RawYCoord as ISecP384R1FieldElement;
  X2 := b.RawXCoord as ISecP384R1FieldElement;
  Y2 := b.RawYCoord as ISecP384R1FieldElement;

  Z1 := RawZCoords[0] as ISecP384R1FieldElement;
  Z2 := b.RawZCoords[0] as ISecP384R1FieldElement;

  tt1 := TNat.Create(24);
  tt2 := TNat.Create(24);
  t3 := TNat.Create(12);
  t4 := TNat.Create(12);

  Z1IsOne := Z1.IsOne;

  if (Z1IsOne) then
  begin
    U2 := X2.x;
    S2 := Y2.x;
  end
  else
  begin
    S2 := t3;
    TSecP384R1Field.Square(Z1.x, S2);

    U2 := tt2;
    TSecP384R1Field.Multiply(S2, X2.x, U2);

    TSecP384R1Field.Multiply(S2, Z1.x, S2);
    TSecP384R1Field.Multiply(S2, Y2.x, S2);
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
    TSecP384R1Field.Square(Z2.x, S1);

    U1 := tt1;
    TSecP384R1Field.Multiply(S1, X1.x, U1);

    TSecP384R1Field.Multiply(S1, Z2.x, S1);
    TSecP384R1Field.Multiply(S1, Y1.x, S1);
  end;

  H := TNat.Create(12);
  TSecP384R1Field.Subtract(U1, U2, H);

  R := TNat.Create(12);
  TSecP384R1Field.Subtract(S1, S2, R);

  // Check if b = Self or b = -Self
  if (TNat.IsZero(12, H)) then
  begin
    if (TNat.IsZero(12, R)) then
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
  TSecP384R1Field.Square(H, HSquared);

  G := TNat.Create(12);
  TSecP384R1Field.Multiply(HSquared, H, G);

  V := t3;
  TSecP384R1Field.Multiply(HSquared, U1, V);

  TSecP384R1Field.Negate(G, G);
  TNat384.Mul(S1, G, tt1);

  c := TNat.AddBothTo(12, V, V, G);
  TSecP384R1Field.Reduce32(c, G);

  X3 := TSecP384R1FieldElement.Create(t4);
  TSecP384R1Field.Square(R, X3.x);
  TSecP384R1Field.Subtract(X3.x, G, X3.x);

  Y3 := TSecP384R1FieldElement.Create(G);
  TSecP384R1Field.Subtract(V, X3.x, Y3.x);
  TNat384.Mul(Y3.x, R, tt2);
  TSecP384R1Field.AddExt(tt1, tt2, tt1);
  TSecP384R1Field.Reduce(tt1, Y3.x);

  Z3 := TSecP384R1FieldElement.Create(H);
  if (not(Z1IsOne)) then
  begin
    TSecP384R1Field.Multiply(Z3.x, Z1.x, Z3.x);
  end;
  if (not(Z2IsOne)) then
  begin
    TSecP384R1Field.Multiply(Z3.x, Z2.x, Z3.x);
  end;

  zs := TCryptoLibGenericArray<IECFieldElement>.Create(Z3);

  result := TSecP384R1Point.Create(Lcurve, X3, Y3, zs, IsCompressed)
    as IECPoint;
end;

function TSecP384R1Point.Detach: IECPoint;
begin
  result := TSecP384R1Point.Create(Nil, AffineXCoord, AffineYCoord) as IECPoint;
end;

function TSecP384R1Point.Negate: IECPoint;
begin
  if (IsInfinity) then
  begin
    result := Self as IECPoint;
    Exit;
  end;

  result := TSecP384R1Point.Create(curve, RawXCoord, RawYCoord.Negate(),
    RawZCoords, IsCompressed) as IECPoint;
end;

function TSecP384R1Point.ThreeTimes: IECPoint;
begin
  if ((IsInfinity) or (RawYCoord.IsZero)) then
  begin
    result := Self as IECPoint;
    Exit;
  end;

  // NOTE: Be careful about recursions between TwicePlus and ThreeTimes
  result := Twice().Add(Self as IECPoint);
end;

function TSecP384R1Point.Twice: IECPoint;
var
  Lcurve: IECCurve;
  Y1, X1, Z1, X3, Y3, Z3: ISecP384R1FieldElement;
  c: UInt32;
  Y1Squared, Z1Squared, T, M, S, t1, t2: TCryptoLibUInt32Array;
  Z1IsOne: Boolean;
begin

  if (IsInfinity) then
  begin
    result := Self as IECPoint;
    Exit;
  end;

  Lcurve := curve;

  Y1 := RawYCoord as ISecP384R1FieldElement;
  if (Y1.IsZero) then
  begin
    result := Lcurve.Infinity;
    Exit;
  end;

  X1 := RawXCoord as ISecP384R1FieldElement;
  Z1 := RawZCoords[0] as ISecP384R1FieldElement;

  t1 := TNat.Create(12);
  t2 := TNat.Create(12);
  Y1Squared := TNat.Create(12);
  TSecP384R1Field.Square(Y1.x, Y1Squared);

  T := TNat.Create(12);
  TSecP384R1Field.Square(Y1Squared, T);

  Z1IsOne := Z1.IsOne;

  Z1Squared := Z1.x;
  if (not(Z1IsOne)) then
  begin
    Z1Squared := t2;
    TSecP384R1Field.Square(Z1.x, Z1Squared);
  end;

  TSecP384R1Field.Subtract(X1.x, Z1Squared, t1);

  M := t2;
  TSecP384R1Field.Add(X1.x, Z1Squared, M);
  TSecP384R1Field.Multiply(M, t1, M);
  c := TNat.AddBothTo(12, M, M, M);
  TSecP384R1Field.Reduce32(c, M);

  S := Y1Squared;
  TSecP384R1Field.Multiply(Y1Squared, X1.x, S);
  c := TNat.ShiftUpBits(12, S, 2, 0);
  TSecP384R1Field.Reduce32(c, S);

  c := TNat.ShiftUpBits(12, T, 3, 0, t1);
  TSecP384R1Field.Reduce32(c, t1);

  X3 := TSecP384R1FieldElement.Create(T);
  TSecP384R1Field.Square(M, X3.x);
  TSecP384R1Field.Subtract(X3.x, S, X3.x);
  TSecP384R1Field.Subtract(X3.x, S, X3.x);

  Y3 := TSecP384R1FieldElement.Create(S);
  TSecP384R1Field.Subtract(S, X3.x, Y3.x);
  TSecP384R1Field.Multiply(Y3.x, M, Y3.x);
  TSecP384R1Field.Subtract(Y3.x, t1, Y3.x);

  Z3 := TSecP384R1FieldElement.Create(M);
  TSecP384R1Field.Twice(Y1.x, Z3.x);
  if (not(Z1IsOne)) then
  begin
    TSecP384R1Field.Multiply(Z3.x, Z1.x, Z3.x);
  end;

  result := TSecP384R1Point.Create(Lcurve, X3, Y3,
    TCryptoLibGenericArray<IECFieldElement>.Create(Z3), IsCompressed)
    as IECPoint;
end;

function TSecP384R1Point.TwicePlus(const b: IECPoint): IECPoint;
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
