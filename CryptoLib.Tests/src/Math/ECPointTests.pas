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

unit ECPointTests;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  Classes,
  SysUtils,
  Math,
{$IFDEF FPC}
  fpcunit,
  testregistry,
{$ELSE}
  TestFramework,
{$ENDIF FPC}
  Generics.Collections,
  ClpBits,
  ClpCustomNamedCurves,
  ClpECNamedCurveTable,
  ClpCryptoLibTypes,
  ClpSecureRandom,
  ClpISecureRandom,
  ClpBigInteger,
  ClpBigIntegers,
  ClpECAlgorithms,
  ClpECCompUtilities,
  ClpIFiniteField,
  ClpIX9ECParameters,
  ClpIX9ECC,
  ClpX9ECC,
  ClpECC,
  ClpIECC,
  ClpX9ECParameters,
  CryptoLibTestBase;

type
  // /**
  // * Nested class containing sample literature values for <code>Fp</code>.
  // */
  TFp = class

  public
  var

    Fq, Fa, Fb, Fn, Fh: TBigInteger;
    Fcurve: IECCurve;
    FInfinity: IECPoint;
    FpointSource: TCryptoLibInt32Array;
    Fp: TCryptoLibGenericArray<IECPoint>;

    constructor Create();
    procedure CreatePoints();

  end;

type
  // /**
  // * Nested class containing sample literature values for <code>F2m</code>.
  // */
  TF2m = class

  public

    const
    // Irreducible polynomial for TPB z^4 + z + 1
    m = Int32(4);

    k1 = Int32(1);

  var

    FaTpb, FbTpb, Fn, Fh: TBigInteger;
    Fcurve: IECCurve;
    FInfinity: IECPoint;
    FpointSource: TCryptoLibStringArray;
    Fp: TCryptoLibGenericArray<IECPoint>;

    constructor Create();
    procedure CreatePoints();

  end;

type

  TTestECPoint = class(TCryptoLibAlgorithmTestCase)
  private

  var
    // /**
    // * Random source used to generate random points
    // */
    FRandom: ISecureRandom;
    FpInstance: TFp;
    F2mInstance: TF2m;

    procedure AssertPointsEqual(const msg: String; const a, b: IECPoint);
    procedure AssertBigIntegersEqual(const a, b: TBigInteger);
    procedure AssertIFiniteFieldsEqual(const a, b: IFiniteField);
    procedure AssertOptionalValuesAgree(const a, b: TBigInteger); overload;
    procedure AssertOptionalValuesAgree(const a, b: TBytes); overload;

    procedure AssertECFieldElementsEqual(const a, b: IECFieldElement);

    // /**
    // * Tests <code>ECPoint.add()</code> against literature values.
    // *
    // * @param p
    // *            The array of literature values.
    // * @param infinity
    // *            The point at infinity on the respective curve.
    // */
    procedure ImplTestAdd(const p: TCryptoLibGenericArray<IECPoint>;
      const infinity: IECPoint);

    // /**
    // * Tests <code>ECPoint.twice()</code> against literature values.
    // *
    // * @param p
    // *            The array of literature values.
    // */
    procedure ImplTestTwice(const p: TCryptoLibGenericArray<IECPoint>);

    procedure ImplTestThreeTimes(const p: TCryptoLibGenericArray<IECPoint>);

    // /**
    // * Goes through all points on an elliptic curve and checks, if adding a
    // * point <code>k</code>-times is the same as multiplying the point by
    // * <code>k</code>, for all <code>k</code>. Should be called for points
    // * on very small elliptic curves only.
    // *
    // * @param p
    // *            The base point on the elliptic curve.
    // * @param infinity
    // *            The point at infinity on the elliptic curve.
    // */
    procedure ImplTestAllPoints(const p, infinity: IECPoint);
    // /**
    // * Checks, if the point multiplication algorithm of the given point yields
    // * the same result as point multiplication done by the reference
    // * implementation given in <code>multiply()</code>. This method chooses a
    // * random number by which the given point <code>p</code> is multiplied.
    // *
    // * @param p
    // *            The point to be multiplied.
    // * @param numBits
    // *            The bitlength of the random number by which <code>p</code>
    // *            is multiplied.
    // */
    procedure ImplTestMultiply(const p: IECPoint; numBits: Int32);
    // /**
    // * Checks, if the point multiplication algorithm of the given point yields
    // * the same result as point multiplication done by the reference
    // * implementation given in <code>multiply()</code>. This method tests
    // * multiplication of <code>p</code> by every number of bitlength
    // * <code>numBits</code> or less.
    // *
    // * @param p
    // *            The point to be multiplied.
    // * @param numBits
    // *            Try every multiplier up to this bitlength
    // */
    procedure ImplTestMultiplyAll(const p: IECPoint; numBits: Int32);
    // /**
    // * Tests <code>ECPoint.add()</code> and <code>ECPoint.subtract()</code>
    // * for the given point and the given point at infinity.
    // *
    // * @param p
    // *            The point on which the tests are performed.
    // * @param infinity
    // *            The point at infinity on the same curve as <code>p</code>.
    // */
    procedure ImplTestAddSubtract(const p, infinity: IECPoint);
    // /**
    // * Test encoding with and without point compression.
    // *
    // * @param p
    // *            The point to be encoded and decoded.
    // */
    procedure ImplTestEncoding(const p: IECPoint);

    procedure ImplAddSubtractMultiplyTwiceEncodingTest(const curve: IECCurve;
      const q: IECPoint; const n: TBigInteger);

    procedure ImplSqrtTest(const c: IECCurve);

    procedure ImplValidityTest(const c: IECCurve; const g: IECPoint);

    procedure ImplAddSubtractMultiplyTwiceEncodingTestAllCoords
      (const x9ECParameters: IX9ECParameters);

    function SolveQuadraticEquation(const c: IECCurve;
      const rhs: IECFieldElement): IECFieldElement;

    function ConfigureBasepoint(const curve: IECCurve; const encoding: String)
      : IX9ECPoint;

    function ConfigureCurve(const curve: IECCurve): IECCurve;

    function FromHex(const hex: String): TBigInteger;

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published

    /// <summary>
    /// Tests, if inconsistent points can be created, i.e. points with
    /// exactly one null coordinate (not permitted).
    /// </summary>
    procedure TestPointCreationConsistency();
    // /**
    // * Calls <code>implTestAdd()</code> for <code>Fp</code> and
    // * <code>F2m</code>.
    // */
    procedure TestAdd();

    // /**
    // * Calls <code>implTestTwice()</code> for <code>Fp</code> and
    // * <code>F2m</code>.
    // */
    procedure TestTwice();
    // /**
    // * Calls <code>implTestThreeTimes()</code> for <code>Fp</code> and
    // * <code>F2m</code>.
    // */
    procedure TestThreeTimes();

    // /**
    // * Calls <code>implTestAllPoints()</code> for the small literature curves,
    // * both for <code>Fp</code> and <code>F2m</code>.
    // */
    procedure TestAllPoints();
    // /**
    // * Calls <code>implTestAddSubtract()</code> for literature values, both
    // * for <code>Fp</code> and <code>F2m</code>.
    // */
    procedure TestAddSubtractMultiplySimple();

    // /**
    // * Calls <code>implTestAddSubtract()</code>,
    // * <code>implTestMultiply</code> and <code>implTestEncoding</code> for
    // * the standard elliptic curves as given in <code>SecNamedCurves</code>.
    // */
    procedure TestAddSubtractMultiplyTwiceEncoding();

    procedure TestExampleFpB0();

  end;

implementation

{ TTestECPoint }

procedure TTestECPoint.AssertECFieldElementsEqual(const a, b: IECFieldElement);
begin
  CheckEquals(True, a.Equals(b));
end;

procedure TTestECPoint.AssertBigIntegersEqual(const a, b: TBigInteger);
begin
  CheckEquals(True, a.Equals(b));
end;

procedure TTestECPoint.AssertIFiniteFieldsEqual(const a, b: IFiniteField);
begin
  CheckEquals(True, (a as TObject).Equals(b as TObject));
end;

procedure TTestECPoint.AssertOptionalValuesAgree(const a, b: TBigInteger);
begin
  if ((a.IsInitialized) and (b.IsInitialized)) then
  begin
    AssertBigIntegersEqual(a, b);
  end;
end;

procedure TTestECPoint.AssertOptionalValuesAgree(const a, b: TBytes);
begin
  if ((a <> Nil) and (b <> Nil)) then
  begin
    CheckTrue(AreEqual(a, b));
  end;
end;

procedure TTestECPoint.AssertPointsEqual(const msg: String;
  const a, b: IECPoint);
begin
  CheckEquals(True, a.Equals(b), msg);
  CheckEquals(True, b.Equals(a), msg);
end;

function TTestECPoint.ConfigureBasepoint(const curve: IECCurve;
  const encoding: String): IX9ECPoint;
begin
  result := TX9ECPoint.Create(curve, DecodeHex(encoding));
  TWNafUtilities.ConfigureBasepoint(result.Point);
end;

function TTestECPoint.ConfigureCurve(const curve: IECCurve): IECCurve;
begin
  result := curve;
end;

function TTestECPoint.FromHex(const hex: String): TBigInteger;
begin
  result := TBigInteger.Create(1, DecodeHex(hex));
end;

procedure TTestECPoint.ImplAddSubtractMultiplyTwiceEncodingTest
  (const curve: IECCurve; const q: IECPoint; const n: TBigInteger);
var
  infinity, p: IECPoint;
  i, logSize, rounds: Int32;
begin
  // Get point at infinity on the curve
  infinity := curve.infinity;

  ImplTestAddSubtract(q, infinity);
  ImplTestMultiply(q, n.BitLength);
  ImplTestMultiply(infinity, n.BitLength);

  logSize := 32 - TBits.NumberOfLeadingZeros(curve.FieldSize - 1);
  rounds := Max(2, Min(10, 32 - 3 * logSize));

  p := q;
  i := 0;
  while i < rounds do
  begin
    ImplTestEncoding(p);
    p := p.Twice();
    System.Inc(i);
  end;
end;

procedure TTestECPoint.ImplAddSubtractMultiplyTwiceEncodingTestAllCoords
  (const x9ECParameters: IX9ECParameters);
var
  n, b: TBigInteger;
  g, sg, q: IECPoint;
  c, sc: IECCurve;
  coords: TCryptoLibInt32Array;
  i, coord: Int32;
begin
  n := x9ECParameters.n;
  g := x9ECParameters.g;
  c := x9ECParameters.curve;

  coords := TECCurve.GetAllCoordinateSystems();
  i := 0;
  while i < System.Length(coords) do
  begin
    coord := coords[i];
    if (c.SupportsCoordinateSystem(coord)) then
    begin
      sc := c;
      sg := g;

      if (sc.CoordinateSystem <> coord) then
      begin
        sc := c.Configure().SetCoordinateSystem(coord).CreateCurve();
        sg := sc.ImportPoint(g);
      end;

      // The generator is multiplied by random b to get random q
      b := TBigInteger.Create(n.BitLength, FRandom);

      q := sg.Multiply(b).Normalize();

      ImplAddSubtractMultiplyTwiceEncodingTest(sc, q, n);

      ImplSqrtTest(sc);
      ImplValidityTest(sc, sg);
    end;
    System.Inc(i);
  end;
end;

procedure TTestECPoint.ImplSqrtTest(const c: IECCurve);
var
  p, pMinusOne, legendreExponent, nonSquare, x: TBigInteger;
  m, count, i: Int32;
  root, fe, sq, check: IECFieldElement;
begin
  if (TECAlgorithms.IsFpCurve(c)) then
  begin
    p := c.Field.Characteristic;
    pMinusOne := p.Subtract(TBigInteger.One);
    legendreExponent := p.ShiftRight(1);

    count := 0;
    while (count < 10) do
    begin
      nonSquare := TBigIntegers.CreateRandomInRange(TBigInteger.Two,
        pMinusOne, FRandom);
      if (not nonSquare.ModPow(legendreExponent, p).Equals(TBigInteger.One))
      then
      begin
        root := c.FromBigInteger(nonSquare).Sqrt();
        CheckNull(root);
        System.Inc(count);
      end;
    end
  end
  else if (TECAlgorithms.IsF2mCurve(c)) then
  begin
    m := c.FieldSize;
    x := TBigInteger.Create(m, FRandom);
    fe := c.FromBigInteger(x);
    i := 0;
    while i < 100 do
    begin
      sq := fe.Square();
      check := sq.Sqrt();
      AssertECFieldElementsEqual(fe, check);
      fe := sq;
      System.Inc(i);
    end;
  end;
end;

procedure TTestECPoint.ImplTestAdd(const p: TCryptoLibGenericArray<IECPoint>;
  const infinity: IECPoint);
var
  i: Int32;
begin
  AssertPointsEqual('p0 plus p1 does not equal p2', p[2], p[0].Add(p[1]));
  AssertPointsEqual('p1 plus p0 does not equal p2', p[2], p[1].Add(p[0]));
  for i := 0 to System.Pred(System.Length(p)) do
  begin
    AssertPointsEqual('Adding infinity failed', p[i], p[i].Add(infinity));
    AssertPointsEqual('Adding to infinity failed', p[i], infinity.Add(p[i]));
  end;
end;

procedure TTestECPoint.ImplTestAddSubtract(const p, infinity: IECPoint);
begin
  AssertPointsEqual('Twice and Add inconsistent', p.Twice(), p.Add(p));
  AssertPointsEqual('Twice p - p is not p', p, p.Twice().Subtract(p));
  AssertPointsEqual('TwicePlus(p, -p) is not p', p, p.TwicePlus(p.Negate()));
  AssertPointsEqual('p - p is not infinity', infinity, p.Subtract(p));
  AssertPointsEqual('p plus infinity is not p', p, p.Add(infinity));
  AssertPointsEqual('infinity plus p is not p', p, infinity.Add(p));
  AssertPointsEqual('infinity plus infinity is not infinity ', infinity,
    infinity.Add(infinity));
  AssertPointsEqual('Twice infinity is not infinity ', infinity,
    infinity.Twice());
end;

procedure TTestECPoint.ImplTestAllPoints(const p, infinity: IECPoint);
var
  adder, multiplier: IECPoint;
  i: TBigInteger;
begin
  adder := infinity;
  multiplier := infinity;

  i := TBigInteger.One;

  repeat
    adder := adder.Add(p);
    multiplier := p.Multiply(i);
    AssertPointsEqual('Results of Add() and Multiply() are inconsistent ' +
      i.ToString, adder, multiplier);
    i := i.Add(TBigInteger.One);
  until ((adder.Equals(infinity)));
end;

procedure TTestECPoint.ImplTestEncoding(const p: IECPoint);
var
  unCompBarr, compBarr: TBytes;
  decUnComp, decComp: IECPoint;
begin
  // Not Point Compression
  unCompBarr := p.GetEncoded(false);
  decUnComp := p.curve.DecodePoint(unCompBarr);
  AssertPointsEqual('Error decoding uncompressed point', p, decUnComp);

  // Point compression
  compBarr := p.GetEncoded(True);
  decComp := p.curve.DecodePoint(compBarr);
  AssertPointsEqual('Error decoding compressed point', p, decComp);
end;

procedure TTestECPoint.ImplTestMultiply(const p: IECPoint; numBits: Int32);
var
  k: TBigInteger;
  reff, q: IECPoint;
begin
  k := TBigInteger.Create(numBits, FRandom);
  reff := TECAlgorithms.ReferenceMultiply(p, k);
  q := p.Multiply(k);
  AssertPointsEqual('ECPoint.Multiply is incorrect', reff, q);
end;

procedure TTestECPoint.ImplTestMultiplyAll(const p: IECPoint; numBits: Int32);
var
  bound, k: TBigInteger;
  reff, q: IECPoint;
begin
  bound := TBigInteger.One.ShiftLeft(numBits);
  k := TBigInteger.Zero;

  repeat
    reff := TECAlgorithms.ReferenceMultiply(p, k);
    q := p.Multiply(k);
    AssertPointsEqual('ECPoint.Multiply is incorrect', reff, q);
    k := k.Add(TBigInteger.One);
  until (not(k.CompareTo(bound) < 0));

end;

procedure TTestECPoint.ImplTestThreeTimes
  (const p: TCryptoLibGenericArray<IECPoint>);
var
  Lp, _3P: IECPoint;
begin
  Lp := p[0];
  _3P := Lp.Add(Lp).Add(Lp);
  AssertPointsEqual('ThreeTimes incorrect', _3P, Lp.ThreeTimes());
  AssertPointsEqual('TwicePlus incorrect', _3P, Lp.TwicePlus(Lp));
end;

procedure TTestECPoint.ImplTestTwice(const p: TCryptoLibGenericArray<IECPoint>);
begin
  AssertPointsEqual('Twice incorrect', p[3], p[0].Twice());
  AssertPointsEqual('Add same point incorrect', p[3], p[0].Add(p[0]));
end;

procedure TTestECPoint.ImplValidityTest(const c: IECCurve; const g: IECPoint);
var
  h: TBigInteger;
  sqrtB, L, T, x, y: IECFieldElement;
  order2, bad2, good2, order4, bad4_1, bad4_2, bad4_3, good4: IECPoint;
begin
  CheckTrue(g.IsValid());

  if (TECAlgorithms.IsF2mCurve(c)) then
  begin
    h := c.Cofactor;
    if (h.IsInitialized) then
    begin
      if (not h.TestBit(0)) then
      begin
        sqrtB := c.b.Sqrt();
        order2 := c.CreatePoint(TBigInteger.Zero, sqrtB.ToBigInteger);
        CheckTrue(order2.Twice().IsInfinity);
        CheckFalse(order2.IsValid());
        bad2 := g.Add(order2);
        CheckFalse(bad2.IsValid());
        good2 := bad2.Add(order2);
        CheckTrue(good2.IsValid());

        if (not h.TestBit(1)) then
        begin
          L := SolveQuadraticEquation(c, c.a);
          CheckNotNull(L);
          T := sqrtB;
          x := T.Sqrt();
          y := T.Add(x.Multiply(L));
          order4 := c.CreatePoint(x.ToBigInteger(), y.ToBigInteger());
          CheckTrue(order4.Twice().Equals(order2));
          CheckFalse(order4.IsValid());
          bad4_1 := g.Add(order4);
          CheckFalse(bad4_1.IsValid());
          bad4_2 := bad4_1.Add(order4);
          CheckFalse(bad4_2.IsValid());
          bad4_3 := bad4_2.Add(order4);
          CheckFalse(bad4_3.IsValid());
          good4 := bad4_3.Add(order4);
          CheckTrue(good4.IsValid());
        end;
      end;
    end;
  end;
end;

procedure TTestECPoint.SetUp;
begin
  inherited;
  FRandom := TSecureRandom.Create();
  FpInstance := TFp.Create;
  FpInstance.CreatePoints;
  F2mInstance := TF2m.Create;
  F2mInstance.CreatePoints;
end;

function TTestECPoint.SolveQuadraticEquation(const c: IECCurve;
  const rhs: IECFieldElement): IECFieldElement;
var
  gamma, z, zeroElement, T, w, w2: IECFieldElement;
  m, i: Int32;
  rand: ISecureRandom;
begin
  if (rhs.IsZero) then
  begin
    result := rhs;
    Exit;
  end;

  zeroElement := c.FromBigInteger(TBigInteger.Zero);
  z := zeroElement;
  gamma := z;

  m := c.FieldSize;
  rand := TSecureRandom.Create();

  repeat
    T := c.FromBigInteger(TBigInteger.Create(m, rand));
    z := zeroElement;
    w := rhs;
    i := 1;

    while i < m do
    begin
      w2 := w.Square();
      z := z.Square().Add(w2.Multiply(T));
      w := w2.Add(rhs);
      System.Inc(i);
    end;

    if (not w.IsZero) then
    begin
      result := Nil;
      Exit;
    end;
    gamma := z.Square().Add(z);
  until (not gamma.IsZero);

  result := z;
end;

procedure TTestECPoint.TearDown;
begin
  inherited;
  FpInstance.Free;
  F2mInstance.Free;
end;

procedure TTestECPoint.TestAdd;
begin
  ImplTestAdd(FpInstance.Fp, FpInstance.FInfinity);
  ImplTestAdd(F2mInstance.Fp, F2mInstance.FInfinity);
end;

procedure TTestECPoint.TestAddSubtractMultiplySimple;
var
  fpBits, iFp, f2mBits, iF2m: Int32;
begin
  fpBits := FpInstance.Fcurve.Order.BitLength;
  for iFp := 0 to System.Pred(System.Length(FpInstance.FpointSource) div 2) do
  begin
    ImplTestAddSubtract(FpInstance.Fp[iFp], FpInstance.FInfinity);

    ImplTestMultiplyAll(FpInstance.Fp[iFp], fpBits);
    ImplTestMultiplyAll(FpInstance.FInfinity, fpBits);
  end;

  f2mBits := F2mInstance.Fcurve.Order.BitLength;
  for iF2m := 0 to System.Pred(System.Length(F2mInstance.FpointSource) div 2) do
  begin
    ImplTestAddSubtract(F2mInstance.Fp[iF2m], F2mInstance.FInfinity);

    ImplTestMultiplyAll(F2mInstance.Fp[iF2m], f2mBits);
    ImplTestMultiplyAll(F2mInstance.FInfinity, f2mBits);
  end;
end;

procedure TTestECPoint.TestAddSubtractMultiplyTwiceEncoding;
var
  tempList: TList<String>;
  tempDict: TDictionary<String, String>;
  uniqNames: TCryptoLibStringArray;
  s, name: string;
  x9A, x9B: IX9ECParameters;
  pA, pB: IECPoint;
  k: TBigInteger;
begin

  tempList := TList<String>.Create();
  try
    tempList.AddRange(TECNamedCurveTable.names); // get all collections
    tempList.AddRange(TCustomNamedCurves.names);
    tempDict := TDictionary<String, String>.Create();
    try
      for s in tempList do
      begin
        tempDict.AddOrSetValue(s, s); // make sure they are unique
      end;
      uniqNames := tempDict.Values.ToArray; // save unique instances to array
    finally
      tempDict.Free;
    end;
  finally
    tempList.Free;
  end;

  for name in uniqNames do
  begin
    x9A := TECNamedCurveTable.GetByName(name);
    x9B := TCustomNamedCurves.GetByName(name);

    if ((x9A <> Nil) and (x9B <> Nil)) then
    begin
      AssertIFiniteFieldsEqual(x9A.curve.Field, x9B.curve.Field);
      AssertBigIntegersEqual(x9A.curve.a.ToBigInteger(),
        x9B.curve.a.ToBigInteger());
      AssertBigIntegersEqual(x9A.curve.b.ToBigInteger(),
        x9B.curve.b.ToBigInteger());
      AssertOptionalValuesAgree(x9A.curve.Cofactor, x9B.curve.Cofactor);
      AssertOptionalValuesAgree(x9A.curve.Order, x9B.curve.Order);

      AssertPointsEqual('Custom curve base-point inconsistency', x9A.g, x9B.g);

      AssertBigIntegersEqual(x9A.h, x9B.h);
      AssertBigIntegersEqual(x9A.n, x9B.n);
      AssertOptionalValuesAgree(x9A.GetSeed(), x9B.GetSeed());

      k := TBigInteger.Create(x9A.n.BitLength, FRandom);
      pA := x9A.g.Multiply(k);
      pB := x9B.g.Multiply(k);
      AssertPointsEqual('Custom curve multiplication inconsistency', pA, pB);
    end;

    if (x9A <> Nil) then
    begin
      ImplAddSubtractMultiplyTwiceEncodingTestAllCoords(x9A);
    end;

    if (x9B <> Nil) then
    begin
      ImplAddSubtractMultiplyTwiceEncodingTestAllCoords(x9B);
    end;
  end;
end;

procedure TTestECPoint.TestAllPoints;
var
  i: Int32;
begin
  i := 0;
  while i < System.Length(FpInstance.Fp) do
  begin
    ImplTestAllPoints(FpInstance.Fp[i], FpInstance.FInfinity);
    System.Inc(i);
  end;

  i := 0;
  while i < System.Length(F2mInstance.Fp) do
  begin
    ImplTestAllPoints(F2mInstance.Fp[i], F2mInstance.FInfinity);
    System.Inc(i);
  end;
end;

procedure TTestECPoint.TestPointCreationConsistency;
begin
  try
    FpInstance.Fcurve.CreatePoint(TBigInteger.ValueOf(12),
      Default (TBigInteger));
    Fail('expected EArgumentCryptoLibException');
  except
    on e: EArgumentCryptoLibException do
    begin
      // expected
    end;

  end;

  try
    FpInstance.Fcurve.CreatePoint(Default (TBigInteger),
      TBigInteger.ValueOf(12));
    Fail('expected EArgumentCryptoLibException');
  except
    on e: EArgumentCryptoLibException do
    begin
      // expected
    end;

  end;

  try
    FpInstance.Fcurve.CreatePoint(TBigInteger.Create('1011'),
      Default (TBigInteger));
    Fail('expected EArgumentCryptoLibException');
  except
    on e: EArgumentCryptoLibException do
    begin
      // expected
    end;

  end;

  try
    FpInstance.Fcurve.CreatePoint(Default (TBigInteger),
      TBigInteger.Create('1011'));
    Fail('expected EArgumentCryptoLibException');
  except
    on e: EArgumentCryptoLibException do
    begin
      // expected
    end;

  end;

end;

procedure TTestECPoint.TestThreeTimes;
begin
  ImplTestThreeTimes(FpInstance.Fp);
  ImplTestThreeTimes(F2mInstance.Fp);
end;

procedure TTestECPoint.TestTwice;
begin
  ImplTestTwice(FpInstance.Fp);
  ImplTestTwice(F2mInstance.Fp);
end;

procedure TTestECPoint.TestExampleFpB0;
var
  p, a, b, n, h: TBigInteger;
  s: TBytes;
  curve: IECCurve;
  g: IX9ECPoint;
  x9: IX9ECParameters;
begin
  (*
    * The supersingular curve y^2 := x^3 - 3.x (i.e. with 'B' = 0) from RFC 6508 2.1, with
    * curve parameters from RFC 6509 Appendix A.
  *)
  p := FromHex('997ABB1F0A563FDA65C61198DAD0657A' +
    '416C0CE19CB48261BE9AE358B3E01A2E' + 'F40AAB27E2FC0F1B228730D531A59CB0' +
    'E791B39FF7C88A19356D27F4A666A6D0' + 'E26C6487326B4CD4512AC5CD65681CE1' +
    'B6AFF4A831852A82A7CF3C521C3C09AA' + '9F94D6AF56971F1FFCE3E82389857DB0' +
    '80C5DF10AC7ACE87666D807AFEA85FEB');
  a := p.Subtract(TBigInteger.ValueOf(3));
  b := TBigInteger.ValueOf(0);
  s := Nil;
  n := p.Add(TBigInteger.ValueOf(1)).ShiftRight(2);
  h := TBigInteger.ValueOf(4);

  curve := ConfigureCurve(TFpCurve.Create(p, a, b, n, h) as IFpCurve);

  g := ConfigureBasepoint(curve, '04'
    // Px
    + '53FC09EE332C29AD0A7990053ED9B52A' + '2B1A2FD60AEC69C698B2F204B6FF7CBF' +
    'B5EDB6C0F6CE2308AB10DB9030B09E10' + '43D5F22CDB9DFA55718BD9E7406CE890' +
    '9760AF765DD5BCCB337C86548B72F2E1' + 'A702C3397A60DE74A7C1514DBA66910D' +
    'D5CFB4CC80728D87EE9163A5B63F73EC' + '80EC46C4967E0979880DC8ABEAE63895'
    // Py
    + '0A8249063F6009F1F9F1F0533634A135' + 'D3E82016029906963D778D821E141178' +
    'F5EA69F4654EC2B9E7F7F5E5F0DE55F6' + '6B598CCF9A140B2E416CFF0CA9E032B9' +
    '70DAE117AD547C6CCAD696B5B7652FE0' + 'AC6F1E80164AA989492D979FC5A4D5F2' +
    '13515AD7E9CB99A980BDAD5AD5BB4636' + 'ADB9B5706A67DCDE75573FD71BEF16D7');

  x9 := TX9ECParameters.Create(curve, g, n, h, s);

  ImplAddSubtractMultiplyTwiceEncodingTestAllCoords(x9);
end;

{ TFp }

constructor TFp.Create;
begin
  Fq := TBigInteger.Create('29');

  Fa := TBigInteger.Create('4');

  Fb := TBigInteger.Create('20');

  Fn := TBigInteger.Create('38');

  Fh := TBigInteger.Create('1');

  Fcurve := TFpCurve.Create(Fq, Fa, Fb, Fn, Fh);

  FInfinity := Fcurve.infinity;

  FpointSource := TCryptoLibInt32Array.Create(5, 22, 16, 27, 13, 6, 14, 6);

  System.SetLength(Fp, System.Length(FpointSource) div 2);

end;

procedure TFp.CreatePoints;
var
  i: Int32;
begin
  for i := 0 to System.Pred(System.Length(FpointSource) div 2) do

  begin
    Fp[i] := Fcurve.CreatePoint(TBigInteger.Create(IntToStr(FpointSource[2 * i])
      ), TBigInteger.Create(IntToStr(FpointSource[2 * i + 1])));
  end;
end;

{ TF2m }

constructor TF2m.Create;
begin
  // a = z^3
  FaTpb := TBigInteger.Create('1000', 2);

  // b = z^3 + 1
  FbTpb := TBigInteger.Create('1001', 2);

  Fn := TBigInteger.Create('23');

  Fh := TBigInteger.Create('1');

  Fcurve := TF2mCurve.Create(m, k1, FaTpb, FbTpb, Fn, Fh);

  FInfinity := Fcurve.infinity;

  FpointSource := TCryptoLibStringArray.Create('0010', '1111', '1100', '1100',
    '0001', '0001', '1011', '0010');

  System.SetLength(Fp, System.Length(FpointSource) div 2);
end;

procedure TF2m.CreatePoints;
var
  i: Int32;
begin
  for i := 0 to System.Pred(System.Length(FpointSource) div 2) do

  begin
    Fp[i] := Fcurve.CreatePoint(TBigInteger.Create(FpointSource[2 * i], 2),
      TBigInteger.Create(FpointSource[(2 * i) + 1], 2));
  end;
end;

initialization

// Register any test cases with the test runner

{$IFDEF FPC}
  RegisterTest(TTestECPoint);
{$ELSE}
  RegisterTest(TTestECPoint.Suite);
{$ENDIF FPC}

end.
