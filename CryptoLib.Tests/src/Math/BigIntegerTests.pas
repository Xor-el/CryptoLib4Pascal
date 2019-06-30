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

unit BigIntegerTests;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  Classes,
  Math,
  SysUtils,
{$IFDEF FPC}
  fpcunit,
  testregistry,
{$ELSE}
  TestFramework,
{$ENDIF FPC}
  ClpSecureRandom,
  ClpISecureRandom,
  ClpBigInteger,
  ClpCryptoLibTypes,
  CryptoLibTestBase;

type

  TTestBigInteger = class(TCryptoLibAlgorithmTestCase)
  private

  var
    FminusTwo, FminusOne, Fzero, Fone, Ftwo, Fthree: TBigInteger;
    FfirstPrimes, FnonPrimes, FmersennePrimeExponents, FnonPrimeExponents
      : TCryptoLibInt32Array;
    FRandom: ISecureRandom;

    function val(n: Int64): TBigInteger;
    function IsEvenUsingMod(const n: TBigInteger): Boolean;
    function mersenne(e: Int32): TBigInteger;
    procedure CheckEqualsBigInteger(const a, b: TBigInteger;
      const msg: String = '');

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestMonoBug81857();
    procedure TestAbs();
    procedure TestAdd();
    procedure TestAnd();
    procedure TestAndNot();
    procedure TestBitCount();
    procedure TestBitLength();
    procedure TestClearBit();
    procedure TestCompareTo();
    procedure TestConstructors();
    procedure TestDivide();
    procedure TestDivideAndRemainder();
    procedure TestFlipBit();
    procedure TestGcd();
    procedure TestGetLowestSetBit();
    procedure TestInt32Value();
    procedure TestIsProbablePrime();
    procedure TestInt64Value();
    procedure TestMax();
    procedure TestMin();
    procedure TestMod();
    procedure TestModInverse();
    procedure TestModPow();
    procedure TestMultiply();
    procedure TestNegate();
    procedure TestNextProbablePrime();
    procedure TestNot();
    procedure TestOr();
    procedure TestPow();
    procedure TestRemainder();
    procedure TestSetBit();
    procedure TestShiftLeft();
    procedure TestShiftRight();
    procedure TestSignValue();
    procedure TestSubtract();
    procedure TestTestBit();
    procedure TestIsEven();
    procedure TestToByteArray();
    procedure TestToByteArrayUnsigned();
    procedure TestToString();
    procedure TestValueOf();
    procedure TestXor();
  end;

implementation

{ TTestBigInteger }

function TTestBigInteger.val(n: Int64): TBigInteger;
begin
  result := TBigInteger.ValueOf(n);
end;

procedure TTestBigInteger.CheckEqualsBigInteger(const a, b: TBigInteger;
  const msg: String = '');
begin
  CheckEquals(True, a.Equals(b), msg);
end;

function TTestBigInteger.IsEvenUsingMod(const n: TBigInteger): Boolean;
begin
  result := n.&Mod(TBigInteger.Two).Equals(TBigInteger.Zero);
end;

function TTestBigInteger.mersenne(e: Int32): TBigInteger;
begin
  result := Ftwo.Pow(e).Subtract(Fone);
end;

procedure TTestBigInteger.SetUp;
begin
  FminusTwo := TBigInteger.Two.Negate();
  FminusOne := TBigInteger.One.Negate();
  Fzero := TBigInteger.Zero;
  Fone := TBigInteger.One;
  Ftwo := TBigInteger.Two;
  Fthree := TBigInteger.Three;

  FfirstPrimes := TCryptoLibInt32Array.Create(2, 3, 5, 7, 11, 13, 17,
    19, 23, 29);
  FnonPrimes := TCryptoLibInt32Array.Create(0, 1, 4, 10, 20, 21, 22,
    25, 26, 27);

  FmersennePrimeExponents := TCryptoLibInt32Array.Create(2, 3, 5, 7, 13, 17, 19,
    31, 61, 89);
  FnonPrimeExponents := TCryptoLibInt32Array.Create(1, 4, 6, 9, 11, 15, 23,
    29, 37, 41);
  FRandom := TSecureRandom.Create();
end;

procedure TTestBigInteger.TearDown;
begin
  inherited;

end;

procedure TTestBigInteger.TestAbs;
begin
  CheckEqualsBigInteger(Fzero, Fzero.Abs());
  CheckEqualsBigInteger(Fone, Fone.Abs());
  CheckEqualsBigInteger(Fone, FminusOne.Abs());
  CheckEqualsBigInteger(Ftwo, Ftwo.Abs());
  CheckEqualsBigInteger(Ftwo, FminusTwo.Abs());
end;

procedure TTestBigInteger.TestAdd;
var
  i, j: Int32;
begin
  for i := -10 to 10 do
  begin
    for j := -10 to 10 do
    begin

      CheckEqualsBigInteger(val(Int64(i) + Int64(j)), val(i).Add(val(j)),
        Format('Problem: %d.Add(%d) should be %d', [i, j, (i + j)]));

    end;
  end;
end;

procedure TTestBigInteger.TestAnd;
var
  i, j: Int32;
begin
  for i := -10 to 10 do
  begin
    for j := -10 to 10 do
    begin

      CheckEqualsBigInteger(val(i and j), val(i).&And(val(j)),
        Format('Problem: %d.AND(%d) should be %d', [i, j, (i and j)]));

    end;
  end;
end;

procedure TTestBigInteger.TestAndNot;
var
  i, j: Int32;
begin
  for i := -10 to 10 do
  begin
    for j := -10 to 10 do
    begin

      CheckEqualsBigInteger(val(i and (not j)), val(i).AndNot(val(j)),
        Format('Problem: %d AND NOT (%d) should be %d',
        [i, j, (i and (not j))]));

    end;
  end;
end;

procedure TTestBigInteger.TestBitCount;
var
  i, bitCount, bit: Int32;
  pow2, test: TBigInteger;
begin
  CheckEquals(0, Fzero.bitCount);
  CheckEquals(1, Fone.bitCount);
  CheckEquals(0, FminusOne.bitCount);
  CheckEquals(1, Ftwo.bitCount);
  CheckEquals(1, FminusTwo.bitCount);

  for i := 0 to System.Pred(100) do

  begin
    pow2 := Fone.ShiftLeft(i);

    CheckEquals(1, pow2.bitCount);
    CheckEquals(i, pow2.Negate().bitCount);
  end;

  i := 0;
  while i < 10 do
  begin
    test := TBigInteger.Create(128, 0, FRandom);
    bitCount := 0;

    for bit := 0 to System.Pred(test.BitLength) do
    begin
      if (test.TestBit(bit)) then
      begin
        System.Inc(bitCount);
      end;
    end;

    CheckEquals(bitCount, test.bitCount);
    System.Inc(i);
  end;
end;

procedure TTestBigInteger.TestBitLength;
var
  i, bit: Int32;
  odd, pow2: TBigInteger;
begin
  CheckEquals(0, Fzero.BitLength);
  CheckEquals(1, Fone.BitLength);
  CheckEquals(0, FminusOne.BitLength);
  CheckEquals(2, Ftwo.BitLength);
  CheckEquals(1, FminusTwo.BitLength);

  for i := 0 to System.Pred(100) do

  begin
    bit := i + FRandom.Next(64);
    odd := TBigInteger.Create(bit, FRandom).SetBit(bit + 1).SetBit(0);
    pow2 := Fone.ShiftLeft(bit);
    CheckEquals(bit + 2, odd.BitLength);
    CheckEquals(bit + 2, odd.Negate().BitLength);
    CheckEquals(bit + 1, pow2.BitLength);
    CheckEquals(bit, pow2.Negate().BitLength);
  end;
end;

procedure TTestBigInteger.TestClearBit;
var
  i, j, pos: Int32;
  n, m, pow2, minusPow2, bigI, negI: TBigInteger;
  test: Boolean;
  data: string;
begin
  CheckEqualsBigInteger(Fzero, Fzero.ClearBit(0));
  CheckEqualsBigInteger(Fzero, Fone.ClearBit(0));
  CheckEqualsBigInteger(Ftwo, Ftwo.ClearBit(0));

  CheckEqualsBigInteger(Fzero, Fzero.ClearBit(1));
  CheckEqualsBigInteger(Fone, Fone.ClearBit(1));
  CheckEqualsBigInteger(Fzero, Ftwo.ClearBit(1));

  // TODO Tests for clearing bits in negative numbers

  // TODO Tests for clearing extended bits

  i := 0;
  while i < 10 do
  begin
    n := TBigInteger.Create(128, FRandom);

    j := 0;
    while j < 10 do
    begin
      pos := FRandom.Next(128);
      m := n.ClearBit(pos);
      test := m.ShiftRight(pos).Remainder(Ftwo).Equals(Fone);

      CheckFalse(test);
      System.Inc(j);
    end;
    System.Inc(i);
  end;

  for i := 0 to System.Pred(100) do
  begin
    pow2 := Fone.ShiftLeft(i);
    minusPow2 := pow2.Negate();

    CheckEqualsBigInteger(Fzero, pow2.ClearBit(i));
    CheckEqualsBigInteger(minusPow2.ShiftLeft(1), minusPow2.ClearBit(i));

    bigI := TBigInteger.ValueOf(i);
    negI := bigI.Negate();

    for j := 0 to System.Pred(10) do
    begin
      data := Format('i:=%d, j:=%d', [i, j]);
      CheckEqualsBigInteger(bigI.AndNot(Fone.ShiftLeft(j)),
        bigI.ClearBit(j), data);
      CheckEqualsBigInteger(negI.AndNot(Fone.ShiftLeft(j)),
        negI.ClearBit(j), data);
    end;
  end;
end;

procedure TTestBigInteger.TestCompareTo;
begin
  CheckEquals(0, FminusTwo.CompareTo(FminusTwo));
  CheckEquals(-1, FminusTwo.CompareTo(FminusOne));
  CheckEquals(-1, FminusTwo.CompareTo(Fzero));
  CheckEquals(-1, FminusTwo.CompareTo(Fone));
  CheckEquals(-1, FminusTwo.CompareTo(Ftwo));

  CheckEquals(1, FminusOne.CompareTo(FminusTwo));
  CheckEquals(0, FminusOne.CompareTo(FminusOne));
  CheckEquals(-1, FminusOne.CompareTo(Fzero));
  CheckEquals(-1, FminusOne.CompareTo(Fone));
  CheckEquals(-1, FminusOne.CompareTo(Ftwo));

  CheckEquals(1, Fzero.CompareTo(FminusTwo));
  CheckEquals(1, Fzero.CompareTo(FminusOne));
  CheckEquals(0, Fzero.CompareTo(Fzero));
  CheckEquals(-1, Fzero.CompareTo(Fone));
  CheckEquals(-1, Fzero.CompareTo(Ftwo));

  CheckEquals(1, Fone.CompareTo(FminusTwo));
  CheckEquals(1, Fone.CompareTo(FminusOne));
  CheckEquals(1, Fone.CompareTo(Fzero));
  CheckEquals(0, Fone.CompareTo(Fone));
  CheckEquals(-1, Fone.CompareTo(Ftwo));

  CheckEquals(1, Ftwo.CompareTo(FminusTwo));
  CheckEquals(1, Ftwo.CompareTo(FminusOne));
  CheckEquals(1, Ftwo.CompareTo(Fzero));
  CheckEquals(1, Ftwo.CompareTo(Fone));
  CheckEquals(0, Ftwo.CompareTo(Ftwo));
end;

procedure TTestBigInteger.TestConstructors;
var
  i: Int32;
begin
  CheckEqualsBigInteger(TBigInteger.Zero, TBigInteger.Create(TBytes.Create(0)));
  CheckEqualsBigInteger(TBigInteger.Zero,
    TBigInteger.Create(TBytes.Create(0, 0)));

  for i := 0 to System.Pred(10) do

  begin
    CheckTrue(TBigInteger.Create(i + 3, 0, FRandom).TestBit(0));
  end;

  // TODO Other constructors
end;

procedure TTestBigInteger.TestDivide;
var
  i, product, productPlus, rep, shift: Int32;
  bigProduct, bigProductPlus, expected, a, b, c, d, e, bShift: TBigInteger;
  divisor: Int32;
  data: string;
begin
  for i := -5 to System.Pred(5) do

  begin
    try

      val(i).Divide(Fzero);
      Fail('expected EArithmeticCryptoLibException');

    except
      on e: EArithmeticCryptoLibException do
      begin

      end;

    end;

  end;

  product := 1 * 2 * 3 * 4 * 5 * 6 * 7 * 8 * 9;
  productPlus := product + 1;

  bigProduct := val(product);
  bigProductPlus := val(productPlus);
  for divisor := 1 to System.Pred(10) do
  begin
    // Exact division
    expected := val(product div divisor);

    CheckEqualsBigInteger(expected, bigProduct.Divide(val(divisor)));
    CheckEqualsBigInteger(expected.Negate(), bigProduct.Negate()
      .Divide(val(divisor)));
    CheckEqualsBigInteger(expected.Negate(),
      bigProduct.Divide(val(divisor).Negate()));
    CheckEqualsBigInteger(expected, bigProduct.Negate()
      .Divide(val(divisor).Negate()));

    expected := val((product + 1) div divisor);

    CheckEqualsBigInteger(expected, bigProductPlus.Divide(val(divisor)));
    CheckEqualsBigInteger(expected.Negate(), bigProductPlus.Negate()
      .Divide(val(divisor)));
    CheckEqualsBigInteger(expected.Negate(),
      bigProductPlus.Divide(val(divisor).Negate()));
    CheckEqualsBigInteger(expected, bigProductPlus.Negate()
      .Divide(val(divisor).Negate()));
  end;

  for rep := 0 to System.Pred(10) do

  begin
    a := TBigInteger.Create(100 - rep, 0, FRandom);
    b := TBigInteger.Create(100 + rep, 0, FRandom);
    c := TBigInteger.Create(10 + rep, 0, FRandom);
    d := a.Multiply(b).Add(c);
    e := d.Divide(a);

    CheckEqualsBigInteger(b, e);
  end;

  // Special tests for power of two since uses different code path internally
  i := 0;
  while i < 100 do
  begin
    shift := FRandom.Next(64);
    a := Fone.ShiftLeft(shift);
    b := TBigInteger.Create(64 + FRandom.Next(64), FRandom);
    bShift := b.ShiftRight(shift);

    data := Format('shift:=%d, b:=%s', [shift, b.ToString(16)]);

    CheckEqualsBigInteger(bShift, b.Divide(a), data);
    CheckEqualsBigInteger(bShift.Negate(), b.Divide(a.Negate()), data);
    CheckEqualsBigInteger(bShift.Negate(), b.Negate().Divide(a), data);
    CheckEqualsBigInteger(bShift, b.Negate().Divide(a.Negate()), data);
    System.Inc(i);
  end;

  // Regression

  shift := 63;
  a := Fone.ShiftLeft(shift);
  b := TBigInteger.Create(1, DecodeHex('2504b470dc188499'));
  bShift := b.ShiftRight(shift);

  data := Format('shift:=%d, b:=%s', [shift, b.ToString(16)]);
  CheckEqualsBigInteger(bShift, b.Divide(a), data);
  CheckEqualsBigInteger(bShift.Negate(), b.Divide(a.Negate()), data);
  CheckEqualsBigInteger(bShift.Negate(), b.Negate().Divide(a), data);
  CheckEqualsBigInteger(bShift, b.Negate().Divide(a.Negate()), data);

end;

procedure TTestBigInteger.TestDivideAndRemainder;
var
  qr, es: TCryptoLibGenericArray<TBigInteger>;
  n, a, b, c, d, bShift, bMod: TBigInteger;
  rep, shift: Int32;
  data: string;
begin
  // TODO More basic tests

  n := TBigInteger.Create(48, FRandom);
  qr := n.DivideAndRemainder(n);
  CheckEqualsBigInteger(Fone, qr[0]);
  CheckEqualsBigInteger(Fzero, qr[1]);

  qr := n.DivideAndRemainder(Fone);
  CheckEqualsBigInteger(n, qr[0]);
  CheckEqualsBigInteger(Fzero, qr[1]);

  for rep := 0 to System.Pred(10) do

  begin
    a := TBigInteger.Create(100 - rep, 0, FRandom);
    b := TBigInteger.Create(100 + rep, 0, FRandom);
    c := TBigInteger.Create(10 + rep, 0, FRandom);
    d := a.Multiply(b).Add(c);
    es := d.DivideAndRemainder(a);

    CheckEqualsBigInteger(b, es[0]);
    CheckEqualsBigInteger(c, es[1]);
  end;

  // Special tests for power of two since uses different code path internally
  rep := 0;
  while rep < 100 do
  begin
    shift := FRandom.Next(64);
    a := Fone.ShiftLeft(shift);
    b := TBigInteger.Create(64 + FRandom.Next(64), FRandom);
    bShift := b.ShiftRight(shift);
    bMod := b.&And(a.Subtract(Fone));

    data := Format('shift:=%d, b:=%s', [shift, b.ToString(16)]);

    qr := b.DivideAndRemainder(a);
    CheckEqualsBigInteger(bShift, qr[0], data);
    CheckEqualsBigInteger(bMod, qr[1], data);

    qr := b.DivideAndRemainder(a.Negate());
    CheckEqualsBigInteger(bShift.Negate(), qr[0], data);
    CheckEqualsBigInteger(bMod, qr[1], data);

    qr := b.Negate().DivideAndRemainder(a);
    CheckEqualsBigInteger(bShift.Negate(), qr[0], data);
    CheckEqualsBigInteger(bMod.Negate(), qr[1], data);

    qr := b.Negate().DivideAndRemainder(a.Negate());
    CheckEqualsBigInteger(bShift, qr[0], data);
    CheckEqualsBigInteger(bMod.Negate(), qr[1], data);
    System.Inc(rep);
  end;
end;

procedure TTestBigInteger.TestFlipBit;
var
  i, j, x, pos: Int32;
  a, b, pow2, minusPow2, bigI, negI: TBigInteger;
  data: string;
begin

  i := 0;
  while i < 10 do
  begin
    a := TBigInteger.Create(128, 0, FRandom);
    b := a;

    x := 0;
    while x < 100 do
    begin
      // Note: Intentionally greater than initial size
      pos := FRandom.Next(256);

      a := a.FlipBit(pos);
      if b.TestBit(pos) then
      begin
        b := b.ClearBit(pos);
      end
      else
      begin
        b := b.SetBit(pos);
      end;

      System.Inc(x);
    end;

    CheckEqualsBigInteger(a, b);
    System.Inc(i);
  end;

  for i := 0 to System.Pred(100) do
  begin
    pow2 := Fone.ShiftLeft(i);
    minusPow2 := pow2.Negate();

    CheckEqualsBigInteger(Fzero, pow2.FlipBit(i));
    CheckEqualsBigInteger(minusPow2.ShiftLeft(1), minusPow2.FlipBit(i));

    bigI := TBigInteger.ValueOf(i);
    negI := bigI.Negate();

    for j := 0 to System.Pred(10) do
    begin

      data := Format('i:=%d, j:=%d', [i, j]);
      CheckEqualsBigInteger(bigI.&Xor(Fone.ShiftLeft(j)),
        bigI.FlipBit(j), data);
      CheckEqualsBigInteger(negI.&Xor(Fone.ShiftLeft(j)),
        negI.FlipBit(j), data);
    end;
  end;
end;

procedure TTestBigInteger.TestGcd;
var
  i: Int32;
  fac, p1, p2, gcd: TBigInteger;
begin
  i := 0;
  while i < 10 do
  begin
    fac := TBigInteger.Create(32, FRandom).Add(Ftwo);
    p1 := TBigInteger.ProbablePrime(63, FRandom);
    p2 := TBigInteger.ProbablePrime(64, FRandom);

    gcd := fac.Multiply(p1).gcd(fac.Multiply(p2));

    CheckEqualsBigInteger(fac, gcd);
    System.Inc(i);
  end;
end;

procedure TTestBigInteger.TestGetLowestSetBit;
var
  i, bit1, bit2, bit3: Int32;
  test: TBigInteger;
begin
  for i := 1 to 100 do

  begin
    test := TBigInteger.Create(i + 1, 0, FRandom).Add(Fone);
    bit1 := test.GetLowestSetBit();
    CheckEqualsBigInteger(test, test.ShiftRight(bit1).ShiftLeft(bit1));
    bit2 := test.ShiftLeft(i + 1).GetLowestSetBit();
    CheckEquals(i + 1, bit2 - bit1);
    bit3 := test.ShiftLeft(3 * i).GetLowestSetBit();
    CheckEquals(3 * i, bit3 - bit1);
  end;
end;

procedure TTestBigInteger.TestInt32Value;
var
  tests: TCryptoLibInt32Array;
  test: Int32;
begin
  tests := TCryptoLibInt32Array.Create(System.Low(Int32), -1234, -10, -1, 0,
    (not 0), 1, 10, 5678, System.High(Int32));

  for test in tests do
  begin
    CheckEquals(test, val(test).Int32Value);
  end;

  // TODO Tests for large numbers
end;

procedure TTestBigInteger.TestInt64Value;
var
  tests: TCryptoLibInt64Array;
  test: Int64;
begin
  tests := TCryptoLibInt64Array.Create(System.Low(Int64), Int64(-1234),
    Int64(-10), Int64(-1), Int64(0), (not Int64(0)), Int64(1), Int64(10),
    Int64(5678), Int64(System.High(Int64)));

  for test in tests do
  begin
    CheckEquals(test, (val(test).Int64Value));
  end;

  // TODO Tests for large numbers
end;

procedure TTestBigInteger.TestIsEven;
var
  RandomBigInteger: TBigInteger;
  idx: Int32;
begin
  CheckTrue(TBigInteger.ValueOf(2).IsEven);
  CheckTrue(TBigInteger.ValueOf(4).IsEven);
  CheckTrue(TBigInteger.ValueOf(6).IsEven);
  CheckTrue(TBigInteger.ValueOf(8).IsEven);
  CheckTrue(TBigInteger.ValueOf(10).IsEven);
  CheckTrue(TBigInteger.ValueOf(12).IsEven);

  CheckFalse(TBigInteger.ValueOf(1).IsEven);
  CheckFalse(TBigInteger.ValueOf(3).IsEven);
  CheckFalse(TBigInteger.ValueOf(5).IsEven);
  CheckFalse(TBigInteger.ValueOf(7).IsEven);
  CheckFalse(TBigInteger.ValueOf(9).IsEven);
  CheckFalse(TBigInteger.ValueOf(11).IsEven);

  idx := 0;

  while idx <= 1000 do
  begin
    RandomBigInteger := TBigInteger.Create(RandomRange(1, 256), FRandom);
    CheckEquals(RandomBigInteger.IsEven(), IsEvenUsingMod(RandomBigInteger),
      Format('IsEven Comparison failed with "%s"',
      [RandomBigInteger.ToString]));

    System.Inc(idx);
  end;
end;

procedure TTestBigInteger.TestIsProbablePrime;
var
  p, c, e: Int32;
begin
  CheckFalse(Fzero.IsProbablePrime(100));
  CheckTrue(Fzero.IsProbablePrime(0));
  CheckTrue(Fzero.IsProbablePrime(-10));
  CheckFalse(FminusOne.IsProbablePrime(100));
  CheckTrue(FminusTwo.IsProbablePrime(100));
  CheckTrue(val(-17).IsProbablePrime(100));
  CheckTrue(val(67).IsProbablePrime(100));
  CheckTrue(val(773).IsProbablePrime(100));

  for p in FfirstPrimes do
  begin
    CheckTrue(val(p).IsProbablePrime(100));
    CheckTrue(val(-p).IsProbablePrime(100));
  end;

  for c in FnonPrimes do

  begin
    CheckFalse(val(c).IsProbablePrime(100));
    CheckFalse(val(-c).IsProbablePrime(100));
  end;

  for e in FmersennePrimeExponents do
  begin
    CheckTrue(mersenne(e).IsProbablePrime(100));
    CheckTrue(mersenne(e).Negate().IsProbablePrime(100));
  end;

  for e in FnonPrimeExponents do

  begin
    CheckFalse(mersenne(e).IsProbablePrime(100));
    CheckFalse(mersenne(e).Negate().IsProbablePrime(100));
  end;

  // TODO Other examples of 'tricky' values?
end;

procedure TTestBigInteger.TestMax;
var
  i, j: Int32;
begin
  for i := -10 to 10 do
  begin

    for j := -10 to 10 do
    begin
      CheckEqualsBigInteger(val(Math.Max(i, j)), val(i).Max(val(j)));
    end;
  end;
end;

procedure TTestBigInteger.TestMin;
var
  i, j: Int32;
begin
  for i := -10 to 10 do
  begin

    for j := -10 to 10 do
    begin
      CheckEqualsBigInteger(val(Math.Min(i, j)), val(i).Min(val(j)));
    end;
  end;
end;

procedure TTestBigInteger.TestMod;
var
  rep, diff: Int32;
  a, b, c, d, e, pow2: TBigInteger;
begin
  // TODO Basic tests

  rep := 0;
  while rep < 100 do

  begin
    diff := FRandom.Next(25);
    a := TBigInteger.Create(100 - diff, 0, FRandom);
    b := TBigInteger.Create(100 + diff, 0, FRandom);
    c := TBigInteger.Create(10 + diff, 0, FRandom);

    d := a.Multiply(b).Add(c);
    e := d.&Mod(a);
    CheckEqualsBigInteger(c, e);

    pow2 := Fone.ShiftLeft(FRandom.Next(128));
    CheckEqualsBigInteger(b.&And(pow2.Subtract(Fone)), b.&Mod(pow2));
    System.Inc(rep);
  end;
end;

procedure TTestBigInteger.TestModInverse;
var
  i: Int32;
  p, q, inv, inv2, m, d, x, check: TBigInteger;
begin
  i := 0;
  while i < 10 do

  begin
    p := TBigInteger.ProbablePrime(64, FRandom);
    q := TBigInteger.Create(63, FRandom).Add(Fone);
    inv := q.ModInverse(p);
    inv2 := inv.ModInverse(p);

    CheckEqualsBigInteger(q, inv2);
    CheckEqualsBigInteger(Fone, q.Multiply(inv).&Mod(p));
    System.Inc(i);
  end;

  // ModInverse a power of 2 for a range of powers
  for i := 1 to 128 do
  begin
    m := Fone.ShiftLeft(i);
    d := TBigInteger.Create(i, FRandom).SetBit(0);
    x := d.ModInverse(m);
    check := x.Multiply(d).&Mod(m);

    CheckEqualsBigInteger(Fone, check);
  end;
end;

procedure TTestBigInteger.TestModPow;
var
  i: Int32;
  m, x, y, n, n3, resX, resY, res, res3, a, b: TBigInteger;
begin
  try

    Ftwo.ModPow(Fone, Fzero);
    Fail('expected EArithmeticCryptoLibException');

  except
    on e: EArithmeticCryptoLibException do
    begin

    end;

  end;

  CheckEqualsBigInteger(Fzero, Fzero.ModPow(Fzero, Fone));
  CheckEqualsBigInteger(Fone, Fzero.ModPow(Fzero, Ftwo));
  CheckEqualsBigInteger(Fzero, Ftwo.ModPow(Fone, Fone));
  CheckEqualsBigInteger(Fone, Ftwo.ModPow(Fzero, Ftwo));

  for i := 0 to System.Pred(100) do

  begin
    m := TBigInteger.ProbablePrime(10 + i, FRandom);
    x := TBigInteger.Create(m.BitLength - 1, FRandom);

    CheckEqualsBigInteger(x, x.ModPow(m, m));
    if (x.SignValue <> 0) then
    begin
      CheckEqualsBigInteger(Fzero, Fzero.ModPow(x, m));
      CheckEqualsBigInteger(Fone, x.ModPow(m.Subtract(Fone), m));
    end;

    y := TBigInteger.Create(m.BitLength - 1, FRandom);
    n := TBigInteger.Create(m.BitLength - 1, FRandom);
    n3 := n.ModPow(Fthree, m);

    resX := n.ModPow(x, m);
    resY := n.ModPow(y, m);
    res := resX.Multiply(resY).&Mod(m);
    res3 := res.ModPow(Fthree, m);

    CheckEqualsBigInteger(res3, n3.ModPow(x.Add(y), m));

    a := x.Add(Fone); // Make sure it's not zero
    b := y.Add(Fone); // Make sure it's not zero

    CheckEqualsBigInteger(a.ModPow(b, m).ModInverse(m),
      a.ModPow(b.Negate(), m));
  end;

end;

procedure TTestBigInteger.TestMonoBug81857;
var
  b, &Mod, expected, manual: TBigInteger;
begin
  b := TBigInteger.Create('18446744073709551616');
  &Mod := TBigInteger.Create('48112959837082048697');
  expected := TBigInteger.Create('4970597831480284165');

  manual := b.Multiply(b).&Mod(&Mod);
  CheckEquals(True, expected.Equals(manual), 'b * b % mod');
end;

procedure TTestBigInteger.TestMultiply;
var
  i, aLen, bLen, shift: Int32;
  One, a, b, c, ab, bc, bShift: TBigInteger;
begin
  One := TBigInteger.One;

  CheckEqualsBigInteger(One, One.Negate().Multiply(One.Negate()));

  i := 0;
  while i < 100 do
  begin
    aLen := 64 + FRandom.Next(64);
    bLen := 64 + FRandom.Next(64);

    a := TBigInteger.Create(aLen, FRandom).SetBit(aLen);
    b := TBigInteger.Create(bLen, FRandom).SetBit(bLen);
    c := TBigInteger.Create(32, FRandom);

    ab := a.Multiply(b);
    bc := b.Multiply(c);

    CheckEqualsBigInteger(ab.Add(bc), a.Add(c).Multiply(b));
    CheckEqualsBigInteger(ab.Subtract(bc), a.Subtract(c).Multiply(b));
    System.Inc(i);
  end;

  // Special tests for power of two since uses different code path internally
  i := 0;
  while i < 100 do
  begin
    shift := FRandom.Next(64);
    a := One.ShiftLeft(shift);
    b := TBigInteger.Create(64 + FRandom.Next(64), FRandom);
    bShift := b.ShiftLeft(shift);

    CheckEqualsBigInteger(bShift, a.Multiply(b));
    CheckEqualsBigInteger(bShift.Negate(), a.Multiply(b.Negate()));
    CheckEqualsBigInteger(bShift.Negate(), a.Negate().Multiply(b));
    CheckEqualsBigInteger(bShift, a.Negate().Multiply(b.Negate()));

    CheckEqualsBigInteger(bShift, b.Multiply(a));
    CheckEqualsBigInteger(bShift.Negate(), b.Multiply(a.Negate()));
    CheckEqualsBigInteger(bShift.Negate(), b.Negate().Multiply(a));
    CheckEqualsBigInteger(bShift, b.Negate().Multiply(a.Negate()));
    System.Inc(i);
  end;
end;

procedure TTestBigInteger.TestNegate;
var
  i: Int32;
begin
  for i := -10 to 10 do
  begin
    CheckEqualsBigInteger(val(-i), val(i).Negate());
  end;
end;

procedure TTestBigInteger.TestNextProbablePrime;
var
  firstPrime, nextPrime, check: TBigInteger;
begin
  firstPrime := TBigInteger.ProbablePrime(32, FRandom);
  nextPrime := firstPrime.NextProbablePrime();

  CheckTrue(firstPrime.IsProbablePrime(10));
  CheckTrue(nextPrime.IsProbablePrime(10));

  check := firstPrime.Add(Fone);

  while (check.CompareTo(nextPrime) < 0) do
  begin
    CheckFalse(check.IsProbablePrime(10));
    check := check.Add(Fone);
  end;
end;

procedure TTestBigInteger.TestNot;
var
  i: Int32;
begin
  for i := -10 to 10 do
  begin
    CheckEqualsBigInteger(val(not i), val(i).&Not(),
      Format('Problem: (not %d) should be %d', [i, (not i)]));

  end;
end;

procedure TTestBigInteger.TestOr;
var
  i, j: Int32;
begin
  for i := -10 to 10 do
  begin
    for j := -10 to 10 do
    begin
      CheckEqualsBigInteger(val(i or j), val(i).&Or(val(j)),
        Format('Problem: %d.OR(%d) should be %d', [i, j, (i or j)]));
    end;

  end;
end;

procedure TTestBigInteger.TestPow;
var
  i: Int32;
  n, result: TBigInteger;
begin
  CheckEqualsBigInteger(Fone, Fzero.&Pow(0));
  CheckEqualsBigInteger(Fzero, Fzero.&Pow(123));
  CheckEqualsBigInteger(Fone, Fone.&Pow(0));
  CheckEqualsBigInteger(Fone, Fone.&Pow(123));

  CheckEqualsBigInteger(Ftwo.&Pow(147), Fone.ShiftLeft(147));
  CheckEqualsBigInteger(Fone.ShiftLeft(7).Pow(11), Fone.ShiftLeft(77));

  n := TBigInteger.Create('1234567890987654321');
  result := Fone;
  for i := 0 to System.Pred(10) do

  begin

    try

      val(i).&Pow(-1);
      Fail('expected EArithmeticCryptoLibException');

    except
      on e: EArithmeticCryptoLibException do
      begin
        // expected
      end;

    end;

    CheckEqualsBigInteger(result, n.&Pow(i));

    result := result.Multiply(n);
  end;
end;

procedure TTestBigInteger.TestRemainder;
var
  rep: Int32;
  a, b, c, d, e: TBigInteger;
begin
  // TODO Basic tests
  for rep := 0 to System.Pred(10) do

  begin
    a := TBigInteger.Create(100 - rep, 0, FRandom);
    b := TBigInteger.Create(100 + rep, 0, FRandom);
    c := TBigInteger.Create(10 + rep, 0, FRandom);
    d := a.Multiply(b).Add(c);
    e := d.Remainder(a);

    CheckEqualsBigInteger(c, e);
  end;
end;

procedure TTestBigInteger.TestSetBit;
var
  i, j, pos: Int32;
  test: Boolean;
  m, n, pow2, minusPow2, bigI, negI: TBigInteger;
  data: string;
begin

  CheckEqualsBigInteger(Fone, Fzero.SetBit(0));
  CheckEqualsBigInteger(Fone, Fone.SetBit(0));
  CheckEqualsBigInteger(Fthree, Ftwo.SetBit(0));

  CheckEqualsBigInteger(Ftwo, Fzero.SetBit(1));
  CheckEqualsBigInteger(Fthree, Fone.SetBit(1));
  CheckEqualsBigInteger(Ftwo, Ftwo.SetBit(1));

  // TODO Tests for setting bits in negative numbers

  // TODO Tests for setting extended bits

  i := 0;
  while i < 10 do

  begin
    n := TBigInteger.Create(128, FRandom);

    j := 0;
    while j < 10 do
    begin
      pos := FRandom.Next(128);
      m := n.SetBit(pos);
      test := m.ShiftRight(pos).Remainder(Ftwo).Equals(Fone);

      CheckTrue(test);
      System.Inc(j);
    end;
    System.Inc(i);
  end;

  for i := 0 to System.Pred(100) do
  begin
    pow2 := Fone.ShiftLeft(i);
    minusPow2 := pow2.Negate();

    CheckEqualsBigInteger(pow2, pow2.SetBit(i));
    CheckEqualsBigInteger(minusPow2, minusPow2.SetBit(i));

    bigI := TBigInteger.ValueOf(i);
    negI := bigI.Negate();

    for j := 0 to System.Pred(10) do
    begin
      data := Format('i:=%d, j:=%d', [i, j]);
      CheckEqualsBigInteger(bigI.&Or(Fone.ShiftLeft(j)), bigI.SetBit(j), data);
      CheckEqualsBigInteger(negI.&Or(Fone.ShiftLeft(j)), negI.SetBit(j), data);
    end;
  end;
end;

procedure TTestBigInteger.TestShiftLeft;
var
  i, j, shift { , bits } : Int32;
  a, b, c, negA: TBigInteger;
  bt: TBytes;
begin
  for i := 0 to System.Pred(100) do
  begin
    shift := FRandom.Next(128);
    System.SetLength(bt, 1000);
    FRandom.NextBytes(bt);

    a := TBigInteger.Create(128 + i, FRandom).Add(Fone);
    // bits := a.bitCount; // Make sure nBits is set

    negA := a.Negate();
    // bits := negA.bitCount; // Make sure nBits is set

    b := a.ShiftLeft(shift);
    c := negA.ShiftLeft(shift);

    CheckEquals(a.bitCount, b.bitCount);
    CheckEquals(negA.bitCount + shift, c.bitCount);
    CheckEquals(a.BitLength + shift, b.BitLength);
    CheckEquals(negA.BitLength + shift, c.BitLength);

    j := 0;
    while j < shift do
    begin

      CheckFalse(b.TestBit(j));
      System.Inc(j);
    end;

    while j < b.BitLength do

    begin
      CheckEquals(a.TestBit(j - shift), b.TestBit(j));
      System.Inc(j);
    end;
  end;
end;

procedure TTestBigInteger.TestShiftRight;
var
  i, j, shift: Int32;
  a, b: TBigInteger;
begin
  for i := 0 to System.Pred(10) do
  begin
    shift := FRandom.Next(128);
    a := TBigInteger.Create(256 + i, FRandom).SetBit(256 + i);
    b := a.ShiftRight(shift);

    CheckEquals(a.BitLength - shift, b.BitLength);

    for j := 0 to System.Pred(b.BitLength) do
    begin
      CheckEquals(a.TestBit(j + shift), b.TestBit(j));
    end;
  end;
end;

procedure TTestBigInteger.TestSignValue;
var
  i: Int32;
begin
  for i := -10 to 10 do
  begin
    if i < 0 then
    begin
      CheckEquals(-1, val(i).SignValue);
    end
    else if i > 0 then
    begin
      CheckEquals(1, val(i).SignValue);
    end
    else
    begin
      CheckEquals(0, val(i).SignValue);
    end;

  end;
end;

procedure TTestBigInteger.TestSubtract;
var
  i, j: Int32;
begin
  for i := -10 to 10 do
  begin
    for j := -10 to 10 do
    begin
      CheckEqualsBigInteger(val(Int64(i) - Int64(j)), val(i).Subtract(val(j)),
        Format('Problem: %d.Subtract(%d) should be %d', [i, j, (i - j)]));
    end;

  end;
end;

procedure TTestBigInteger.TestTestBit;
var
  i, j, pos: Int32;
  n: TBigInteger;
  test: Boolean;
begin
  i := 0;
  while i < 10 do

  begin
    n := TBigInteger.Create(128, FRandom);

    CheckFalse(n.TestBit(128));
    CheckTrue(n.Negate().TestBit(128));

    j := 0;
    while j < 10 do
    begin
      pos := FRandom.Next(128);
      test := n.ShiftRight(pos).Remainder(Ftwo).Equals(Fone);

      CheckEquals(test, n.TestBit(pos));
      System.Inc(j);
    end;

    System.Inc(i);
  end;
end;

procedure TTestBigInteger.TestToByteArray;
var
  z, temp, b: TBytes;
  i: Int32;
  x, y: TBigInteger;
begin
  z := TBigInteger.Zero.ToByteArray();
  System.SetLength(temp, 1);
  CheckTrue(AreEqual(temp, z));
  for i := 16 to 48 do
  begin
    x := TBigInteger.ProbablePrime(i, FRandom);
    b := x.ToByteArray();
    CheckEquals(((i div 8) + 1), System.Length(b));
    y := TBigInteger.Create(b);
    CheckEqualsBigInteger(x, y);

    x := x.Negate();
    b := x.ToByteArray();
    CheckEquals(((i div 8) + 1), System.Length(b));
    y := TBigInteger.Create(b);
    CheckEqualsBigInteger(x, y);
  end;
end;

procedure TTestBigInteger.TestToByteArrayUnsigned;
var
  z, temp, b: TBytes;
  i: Int32;
  x, y: TBigInteger;
begin
  z := TBigInteger.Zero.ToByteArrayUnsigned();
  System.SetLength(temp, 0);
  CheckTrue(AreEqual(temp, z));
  for i := 16 to 48 do
  begin
    x := TBigInteger.ProbablePrime(i, FRandom);
    b := x.ToByteArrayUnsigned();
    CheckEquals(((i + 7) div 8), System.Length(b));
    y := TBigInteger.Create(1, b);
    CheckEqualsBigInteger(x, y);

    x := x.Negate();
    b := x.ToByteArrayUnsigned();
    CheckEquals(((i div 8) + 1), System.Length(b));
    y := TBigInteger.Create(b);
    CheckEqualsBigInteger(x, y);
  end;
end;

procedure TTestBigInteger.TestToString;
var
  s, str: string;
  radices: TCryptoLibInt32Array;
  tests: TCryptoLibGenericArray<TBigInteger>;
  i, trials, len, radix: Int32;
  n, n1, n2: TBigInteger;
begin
  s := '12345667890987654321';

  CheckEquals(s, TBigInteger.Create(s).ToString());
  CheckEquals(s, TBigInteger.Create(s, 10).ToString(10));
  CheckEquals(s, TBigInteger.Create(s, 16).ToString(16));

  CheckEquals('-e4437ed6010e88286f547fa90abfe4c3',
    TBigInteger.Create('-e4437ed6010e88286f547fa90abfe4c3', 16).ToString(16));

  for i := 0 to System.Pred(100) do
  begin

    n := TBigInteger.Create(i, FRandom);

    CheckEqualsBigInteger(n, TBigInteger.Create(n.ToString(2), 2));
    CheckEqualsBigInteger(n, TBigInteger.Create(n.ToString(8), 8));
    CheckEqualsBigInteger(n, TBigInteger.Create(n.ToString(10), 10));
    CheckEqualsBigInteger(n, TBigInteger.Create(n.ToString(16), 16));
  end;

  // Radix version
  radices := TCryptoLibInt32Array.Create(2, 8, 10, 16);
  trials := 256;

  System.SetLength(tests, trials);
  for i := 0 to System.Pred(trials) do

  begin
    len := FRandom.Next(i + 1);
    tests[i] := TBigInteger.Create(len, FRandom);
  end;

  for radix in radices do
  begin

    for i := 0 to System.Pred(trials) do
    begin
      n1 := tests[i];
      str := n1.ToString(radix);
      n2 := TBigInteger.Create(str, radix);
      CheckEqualsBigInteger(n1, n2);
    end;
  end;
end;

procedure TTestBigInteger.TestValueOf;
var
  i: Int32;
begin
  CheckEquals(-1, TBigInteger.ValueOf(-1).SignValue);
  CheckEquals(0, TBigInteger.ValueOf(0).SignValue);
  CheckEquals(1, TBigInteger.ValueOf(1).SignValue);

  for i := -5 to System.Pred(5) do
  begin
    CheckEquals(i, TBigInteger.ValueOf(i).Int32Value);
  end;
end;

procedure TTestBigInteger.TestXor;
var
  i, j: Int32;
begin
  for i := -10 to 10 do
  begin
    for j := -10 to 10 do
    begin

      CheckEqualsBigInteger(val(i xor j), val(i).&Xor(val(j)),
        Format('Problem: %d.XOR(%d) should be %d', [i, j, (i xor j)]));

    end;
  end;
end;

initialization

// Register any test cases with the test runner

{$IFDEF FPC}
  RegisterTest(TTestBigInteger);
{$ELSE}
  RegisterTest(TTestBigInteger.Suite);
{$ENDIF FPC}

end.
