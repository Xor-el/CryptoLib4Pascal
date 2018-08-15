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

unit ClpSecT283K1Point;

{$I ..\..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpECPoint,
  ClpISecT283K1Point,
  ClpIECFieldElement,
  ClpIECInterface,
  ClpBigInteger,
  ClpCryptoLibTypes;

resourcestring
  SOneOfECFieldElementIsNil = 'Exactly One of the Field Elements is Nil';

type
  TSecT283K1Point = class sealed(TAbstractF2mPoint, ISecT283K1Point)

  strict protected
    function Detach(): IECPoint; override;

    function GetCompressionYTilde: Boolean; override;
    property CompressionYTilde: Boolean read GetCompressionYTilde;

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

    function GetYCoord: IECFieldElement; override;
    property YCoord: IECFieldElement read GetYCoord;

  end;

implementation

{ TSecT283K1Point }

function TSecT283K1Point.Add(const b: IECPoint): IECPoint;
var
  LCurve: IECCurve;
  X1, X2, L1, L2, Z1, Z2, U2, S2, U1, S1, A, LB, X3, L3, Z3, Y1, Y2, L, Y3, AU1,
    AU2, ABZ2: IECFieldElement;
  Z1IsOne, Z2IsOne: Boolean;
  p: IECPoint;
begin
  if ((IsInfinity)) then
  begin
    result := b;
    Exit;
  end;
  if ((b.IsInfinity)) then
  begin
    result := Self as IECPoint;
    Exit;
  end;

  LCurve := curve;

  X1 := RawXCoord;
  X2 := b.RawXCoord;

  if (X1.IsZero) then
  begin
    if (X2.IsZero) then
    begin
      result := LCurve.Infinity;
      Exit;
    end;

    result := b.Add(Self as IECPoint);
    Exit;
  end;

  L1 := RawYCoord;
  Z1 := RawZCoords[0];
  L2 := b.RawYCoord;
  Z2 := b.RawZCoords[0];

  Z1IsOne := Z1.IsOne;
  U2 := X2;
  S2 := L2;
  if (not(Z1IsOne)) then
  begin
    U2 := U2.Multiply(Z1);
    S2 := S2.Multiply(Z1);
  end;

  Z2IsOne := Z2.IsOne;
  U1 := X1;
  S1 := L1;
  if (not(Z2IsOne)) then
  begin
    U1 := U1.Multiply(Z2);
    S1 := S1.Multiply(Z2);
  end;

  A := S1.Add(S2);
  LB := U1.Add(U2);

  if (LB.IsZero) then
  begin
    if (A.IsZero) then
    begin
      result := Twice();
      Exit;
    end;

    result := LCurve.Infinity;
    Exit;
  end;

  if (X2.IsZero) then
  begin
    // TODO This can probably be optimized quite a bit
    p := Self.Normalize();
    X1 := p.XCoord;
    Y1 := p.YCoord;

    Y2 := L2;
    L := Y1.Add(Y2).Divide(X1);

    X3 := L.Square().Add(L).Add(X1);
    if (X3.IsZero) then
    begin
      result := TSecT283K1Point.Create(LCurve, X3, LCurve.b, IsCompressed);
      Exit;
    end;

    Y3 := L.Multiply(X1.Add(X3)).Add(X3).Add(Y1);
    L3 := Y3.Divide(X3).Add(X3);
    Z3 := LCurve.FromBigInteger(TBigInteger.One);
  end
  else
  begin
    LB := LB.Square();

    AU1 := A.Multiply(U1);
    AU2 := A.Multiply(U2);

    X3 := AU1.Multiply(AU2);
    if (X3.IsZero) then
    begin
      result := TSecT283K1Point.Create(curve, X3, curve.b, IsCompressed);
      Exit;
    end;

    ABZ2 := A.Multiply(LB);
    if (not(Z2IsOne)) then
    begin
      ABZ2 := ABZ2.Multiply(Z2);
    end;

    L3 := AU2.Add(LB).SquarePlusProduct(ABZ2, L1.Add(Z1));

    Z3 := ABZ2;
    if (not(Z1IsOne)) then
    begin
      Z3 := Z3.Multiply(Z1);
    end;
  end;

  result := TSecT283K1Point.Create(LCurve, X3, L3,
    TCryptoLibGenericArray<IECFieldElement>.Create(Z3), IsCompressed);
end;

constructor TSecT283K1Point.Create(const curve: IECCurve;
  const x, y: IECFieldElement);
begin
  Create(curve, x, y, false);
end;

constructor TSecT283K1Point.Create(const curve: IECCurve;
  const x, y: IECFieldElement;
  const zs: TCryptoLibGenericArray<IECFieldElement>; withCompression: Boolean);
begin
  Inherited Create(curve, x, y, zs, withCompression);
end;

constructor TSecT283K1Point.Create(const curve: IECCurve;
  const x, y: IECFieldElement; withCompression: Boolean);
begin
  Inherited Create(curve, x, y, withCompression);
  if ((x = Nil) <> (y = Nil)) then
  begin
    raise EArgumentCryptoLibException.CreateRes(@SOneOfECFieldElementIsNil);
  end;
end;

function TSecT283K1Point.Detach: IECPoint;
begin
  result := TSecT283K1Point.Create(Nil, AffineXCoord, AffineYCoord);
end;

function TSecT283K1Point.GetCompressionYTilde: Boolean;
var
  x, y: IECFieldElement;
begin
  x := RawXCoord;
  if (x.IsZero) then
  begin
    result := false;
    Exit;
  end;

  y := RawYCoord;

  // Y is actually Lambda (X + Y/X) here
  result := y.TestBitZero() <> x.TestBitZero();
end;

function TSecT283K1Point.GetYCoord: IECFieldElement;
var
  x, L, y, Z: IECFieldElement;
begin
  x := RawXCoord;
  L := RawYCoord;

  if ((IsInfinity) or (x.IsZero)) then
  begin
    result := L;
    Exit;
  end;

  // Y is actually Lambda (X + Y/X) here; convert to affine value on the fly
  y := L.Add(x).Multiply(x);

  Z := RawZCoords[0];
  if (not(Z.IsOne)) then
  begin
    y := y.Divide(Z);
  end;

  result := y;
end;

function TSecT283K1Point.Negate: IECPoint;
var
  x, L, Z: IECFieldElement;
begin
  if (IsInfinity) then
  begin
    result := Self as IECPoint;
    Exit;
  end;

  x := RawXCoord;
  if (x.IsZero) then
  begin
    result := Self as IECPoint;
    Exit;
  end;

  // L is actually Lambda (X + Y/X) here
  L := RawYCoord;
  Z := RawZCoords[0];
  result := TSecT283K1Point.Create(curve, x, L.Add(Z),
    TCryptoLibGenericArray<IECFieldElement>.Create(Z), IsCompressed);
end;

function TSecT283K1Point.Twice: IECPoint;
var
  LCurve: IECCurve;
  X1, L1, Z1, Z1Sq, T, X3, Z3, t1, t2, L3: IECFieldElement;
  Z1IsOne: Boolean;
begin
  if ((IsInfinity)) then
  begin
    result := Self as IECPoint;
    Exit;
  end;

  LCurve := Self.curve;

  X1 := RawXCoord;
  if (X1.IsZero) then
  begin
    // A point with X == 0 is it's own Additive inverse
    result := LCurve.Infinity;
    Exit;
  end;

  L1 := RawYCoord;
  Z1 := RawZCoords[0];

  Z1IsOne := Z1.IsOne;
  if Z1IsOne then
  begin
    Z1Sq := Z1;
  end
  else
  begin
    Z1Sq := Z1.Square();
  end;

  if (Z1IsOne) then
  begin
    T := L1.Square().Add(L1);
  end
  else
  begin
    T := L1.Add(Z1).Multiply(L1);
  end;

  if (T.IsZero) then
  begin
    result := TSecT283K1Point.Create(LCurve, T, LCurve.b, IsCompressed);
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

  t1 := L1.Add(X1).Square();

  if Z1IsOne then
  begin
    t2 := Z1;
  end
  else
  begin
    t2 := Z1Sq.Square();
  end;

  L3 := t1.Add(T).Add(Z1Sq).Multiply(t1).Add(t2).Add(X3).Add(Z3);

  result := TSecT283K1Point.Create(LCurve, X3, L3,
    TCryptoLibGenericArray<IECFieldElement>.Create(Z3), IsCompressed);
end;

function TSecT283K1Point.TwicePlus(const b: IECPoint): IECPoint;
var
  LCurve: IECCurve;
  X1, X2, Z2, L1, Z1, L2, X1Sq, L1Sq, Z1Sq, L1Z1, T, L2plus1, A, X2Z1Sq, LB, X3,
    Z3, L3: IECFieldElement;
begin
  if ((IsInfinity)) then
  begin
    result := b;
    Exit;
  end;
  if (b.IsInfinity) then
  begin
    result := Twice();
    Exit;
  end;

  LCurve := Self.curve;

  X1 := RawXCoord;
  if (X1.IsZero) then
  begin
    // A point with X == 0 is it's own Additive inverse
    result := b;
    Exit;
  end;

  // NOTE: TwicePlus() only optimized for lambda-affine argument
  X2 := b.RawXCoord;
  Z2 := b.RawZCoords[0];
  if ((X2.IsZero) or (not(Z2.IsOne))) then
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

  T := L1Sq.Add(L1Z1);
  L2plus1 := L2.AddOne();
  A := L2plus1.Multiply(Z1Sq).Add(L1Sq).MultiplyPlusProduct(T, X1Sq, Z1Sq);
  X2Z1Sq := X2.Multiply(Z1Sq);
  LB := X2Z1Sq.Add(T).Square();

  if (LB.IsZero) then
  begin
    if (A.IsZero) then
    begin
      result := b.Twice();
      Exit;
    end;

    result := LCurve.Infinity;
    Exit;
  end;

  if (A.IsZero) then
  begin
    result := TSecT283K1Point.Create(LCurve, A, LCurve.b, IsCompressed);
    Exit;
  end;

  X3 := A.Square().Multiply(X2Z1Sq);
  Z3 := A.Multiply(LB).Multiply(Z1Sq);
  L3 := A.Add(LB).Square().MultiplyPlusProduct(T, L2plus1, Z3);

  result := TSecT283K1Point.Create(LCurve, X3, L3,
    TCryptoLibGenericArray<IECFieldElement>.Create(Z3), IsCompressed);
end;

end.
