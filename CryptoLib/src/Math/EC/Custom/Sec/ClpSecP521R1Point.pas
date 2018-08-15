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

unit ClpSecP521R1Point;

{$I ..\..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpNat,
  ClpECPoint,
  ClpSecP521R1Field,
  ClpISecP521R1Point,
  ClpISecP521R1FieldElement,
  ClpIECFieldElement,
  ClpIECInterface,
  ClpCryptoLibTypes;

resourcestring
  SOneOfECFieldElementIsNil = 'Exactly One of the Field Elements is Nil';

type
  TSecP521R1Point = class sealed(TAbstractFpPoint, ISecP521R1Point)

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
  ClpSecP521R1FieldElement;

{ TSecP521R1Point }

constructor TSecP521R1Point.Create(const curve: IECCurve;
  const x, y: IECFieldElement);
begin
  Create(curve, x, y, false);
end;

constructor TSecP521R1Point.Create(const curve: IECCurve;
  const x, y: IECFieldElement; withCompression: Boolean);
begin
  Inherited Create(curve, x, y, withCompression);
  if ((x = Nil) <> (y = Nil)) then
  begin
    raise EArgumentCryptoLibException.CreateRes(@SOneOfECFieldElementIsNil);
  end;
end;

constructor TSecP521R1Point.Create(const curve: IECCurve;
  const x, y: IECFieldElement;
  const zs: TCryptoLibGenericArray<IECFieldElement>; withCompression: Boolean);
begin
  Inherited Create(curve, x, y, zs, withCompression);
end;

function TSecP521R1Point.Add(const b: IECPoint): IECPoint;
var
  Lcurve: IECCurve;
  X1, Y1, X2, Y2, Z1, Z2, X3, Y3, Z3: ISecP521R1FieldElement;
  t1, t2, t3, t4, U2, S2, U1, S1, H, R, HSquared, G, V: TCryptoLibUInt32Array;
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

  X1 := RawXCoord as ISecP521R1FieldElement;
  Y1 := RawYCoord as ISecP521R1FieldElement;
  X2 := b.RawXCoord as ISecP521R1FieldElement;
  Y2 := b.RawYCoord as ISecP521R1FieldElement;

  Z1 := RawZCoords[0] as ISecP521R1FieldElement;
  Z2 := b.RawZCoords[0] as ISecP521R1FieldElement;

  t1 := TNat.Create(17);
  t2 := TNat.Create(17);
  t3 := TNat.Create(17);
  t4 := TNat.Create(17);

  Z1IsOne := Z1.IsOne;

  if (Z1IsOne) then
  begin
    U2 := X2.x;
    S2 := Y2.x;
  end
  else
  begin
    S2 := t3;
    TSecP521R1Field.Square(Z1.x, S2);

    U2 := t2;
    TSecP521R1Field.Multiply(S2, X2.x, U2);

    TSecP521R1Field.Multiply(S2, Z1.x, S2);
    TSecP521R1Field.Multiply(S2, Y2.x, S2);
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
    TSecP521R1Field.Square(Z2.x, S1);

    U1 := t1;
    TSecP521R1Field.Multiply(S1, X1.x, U1);

    TSecP521R1Field.Multiply(S1, Z2.x, S1);
    TSecP521R1Field.Multiply(S1, Y1.x, S1);
  end;

  H := TNat.Create(17);
  TSecP521R1Field.Subtract(U1, U2, H);

  R := t2;
  TSecP521R1Field.Subtract(S1, S2, R);

  // Check if b = Self or b = -Self
  if (TNat.IsZero(17, H)) then
  begin
    if (TNat.IsZero(17, R)) then
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
  TSecP521R1Field.Square(H, HSquared);

  G := TNat.Create(17);
  TSecP521R1Field.Multiply(HSquared, H, G);

  V := t3;
  TSecP521R1Field.Multiply(HSquared, U1, V);

  TSecP521R1Field.Multiply(S1, G, t1);

  X3 := TSecP521R1FieldElement.Create(t4);
  TSecP521R1Field.Square(R, X3.x);
  TSecP521R1Field.Add(X3.x, G, X3.x);
  TSecP521R1Field.Subtract(X3.x, V, X3.x);
  TSecP521R1Field.Subtract(X3.x, V, X3.x);

  Y3 := TSecP521R1FieldElement.Create(G);
  TSecP521R1Field.Subtract(V, X3.x, Y3.x);
  TSecP521R1Field.Multiply(Y3.x, R, t2);
  TSecP521R1Field.Subtract(t2, t1, Y3.x);

  Z3 := TSecP521R1FieldElement.Create(H);
  if (not(Z1IsOne)) then
  begin
    TSecP521R1Field.Multiply(Z3.x, Z1.x, Z3.x);
  end;
  if (not(Z2IsOne)) then
  begin
    TSecP521R1Field.Multiply(Z3.x, Z2.x, Z3.x);
  end;

  zs := TCryptoLibGenericArray<IECFieldElement>.Create(Z3);

  result := TSecP521R1Point.Create(Lcurve, X3, Y3, zs, IsCompressed)
    as IECPoint;
end;

function TSecP521R1Point.Detach: IECPoint;
begin
  result := TSecP521R1Point.Create(Nil, AffineXCoord, AffineYCoord) as IECPoint;
end;

function TSecP521R1Point.Negate: IECPoint;
begin
  if (IsInfinity) then
  begin
    result := Self as IECPoint;
    Exit;
  end;

  result := TSecP521R1Point.Create(curve, RawXCoord, RawYCoord.Negate(),
    RawZCoords, IsCompressed) as IECPoint;
end;

function TSecP521R1Point.ThreeTimes: IECPoint;
begin
  if ((IsInfinity) or (RawYCoord.IsZero)) then
  begin
    result := Self as IECPoint;
    Exit;
  end;

  // NOTE: Be careful about recursions between TwicePlus and ThreeTimes
  result := Twice().Add(Self as IECPoint);
end;

function TSecP521R1Point.Twice: IECPoint;
var
  Lcurve: IECCurve;
  Y1, X1, Z1, X3, Y3, Z3: ISecP521R1FieldElement;
  Y1Squared, Z1Squared, T, M, S, t1, t2: TCryptoLibUInt32Array;
  Z1IsOne: Boolean;
begin

  if (IsInfinity) then
  begin
    result := Self as IECPoint;
    Exit;
  end;

  Lcurve := curve;

  Y1 := RawYCoord as ISecP521R1FieldElement;
  if (Y1.IsZero) then
  begin
    result := Lcurve.Infinity;
    Exit;
  end;

  X1 := RawXCoord as ISecP521R1FieldElement;
  Z1 := RawZCoords[0] as ISecP521R1FieldElement;

  t1 := TNat.Create(17);
  t2 := TNat.Create(17);
  Y1Squared := TNat.Create(17);
  TSecP521R1Field.Square(Y1.x, Y1Squared);

  T := TNat.Create(17);
  TSecP521R1Field.Square(Y1Squared, T);

  Z1IsOne := Z1.IsOne;

  Z1Squared := Z1.x;
  if (not(Z1IsOne)) then
  begin
    Z1Squared := t2;
    TSecP521R1Field.Square(Z1.x, Z1Squared);
  end;

  TSecP521R1Field.Subtract(X1.x, Z1Squared, t1);

  M := t2;
  TSecP521R1Field.Add(X1.x, Z1Squared, M);
  TSecP521R1Field.Multiply(M, t1, M);
  TNat.AddBothTo(17, M, M, M);
  TSecP521R1Field.Reduce23(M);

  S := Y1Squared;
  TSecP521R1Field.Multiply(Y1Squared, X1.x, S);
  TNat.ShiftUpBits(17, S, 2, 0);
  TSecP521R1Field.Reduce23(S);

  TNat.ShiftUpBits(17, T, 3, 0, t1);
  TSecP521R1Field.Reduce23(t1);

  X3 := TSecP521R1FieldElement.Create(T);
  TSecP521R1Field.Square(M, X3.x);
  TSecP521R1Field.Subtract(X3.x, S, X3.x);
  TSecP521R1Field.Subtract(X3.x, S, X3.x);

  Y3 := TSecP521R1FieldElement.Create(S);
  TSecP521R1Field.Subtract(S, X3.x, Y3.x);
  TSecP521R1Field.Multiply(Y3.x, M, Y3.x);
  TSecP521R1Field.Subtract(Y3.x, t1, Y3.x);

  Z3 := TSecP521R1FieldElement.Create(M);
  TSecP521R1Field.Twice(Y1.x, Z3.x);
  if (not(Z1IsOne)) then
  begin
    TSecP521R1Field.Multiply(Z3.x, Z1.x, Z3.x);
  end;

  result := TSecP521R1Point.Create(Lcurve, X3, Y3,
    TCryptoLibGenericArray<IECFieldElement>.Create(Z3), IsCompressed)
    as IECPoint;
end;

function TSecP521R1Point.TwicePlus(const b: IECPoint): IECPoint;
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
