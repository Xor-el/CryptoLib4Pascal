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
{$IFDEF FPC}
  fpcunit,
  testregistry,
{$ELSE}
  TestFramework,
{$ENDIF FPC}
  Generics.Collections,
  ClpCustomNamedCurves,
  ClpECNamedCurveTable,
  ClpCryptoLibTypes,
  ClpSecureRandom,
  ClpISecureRandom,
  ClpBigInteger,
  ClpBigIntegers,
  ClpECCurve,
  ClpECAlgorithms,
  ClpIFiniteField,
  ClpIX9ECParameters,
  ClpIECFieldElement,
  ClpIECInterface,
  ClpArrayUtils;

type

  TCryptoLibTestCase = class abstract(TTestCase)

  end;

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

  public const
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

  TTestECPoint = class(TCryptoLibTestCase)
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
    procedure AssertOptionalValuesAgree(const a,
      b: TCryptoLibByteArray); overload;

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

procedure TTestECPoint.AssertOptionalValuesAgree(const a,
  b: TCryptoLibByteArray);
begin
  if ((a <> Nil) and (b <> Nil)) then
  begin
    CheckTrue(TArrayUtils.AreEqual(a, b));
  end;
end;

procedure TTestECPoint.AssertPointsEqual(const msg: String;
  const a, b: IECPoint);
begin
  CheckEquals(True, a.Equals(b), msg);
  CheckEquals(True, b.Equals(a), msg);
end;

procedure TTestECPoint.ImplAddSubtractMultiplyTwiceEncodingTest
  (const curve: IECCurve; const q: IECPoint; const n: TBigInteger);
var
  infinity, p: IECPoint;
  i: Int32;
begin
  // Get point at infinity on the curve
  infinity := curve.infinity;

  ImplTestAddSubtract(q, infinity);
  ImplTestMultiply(q, n.BitLength);
  ImplTestMultiply(infinity, n.BitLength);
  //
  p := q;
  i := 0;
  while i < 10 do
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
  unCompBarr, compBarr: TCryptoLibByteArray;
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
  order2, bad: IECPoint;
begin
  CheckTrue(g.IsValid());

  h := c.getCofactor();
  if ((h.IsInitialized) and (h.CompareTo(TBigInteger.One) > 0)) then
  begin
    if (TECAlgorithms.IsF2mCurve(c)) then
    begin
      order2 := c.CreatePoint(TBigInteger.Zero, c.b.Sqrt().ToBigInteger());
      bad := g.Add(order2);
      CheckFalse(bad.IsValid());
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
    ImplTestAllPoints(FpInstance.Fp[0], FpInstance.FInfinity);
    System.Inc(i);
  end;

  i := 0;
  while i < System.Length(F2mInstance.Fp) do
  begin
    ImplTestAllPoints(F2mInstance.Fp[0], F2mInstance.FInfinity);
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
