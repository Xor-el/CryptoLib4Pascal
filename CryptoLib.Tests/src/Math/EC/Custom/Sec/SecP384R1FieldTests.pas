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

unit SecP384R1FieldTests;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  SysUtils,
{$IFDEF FPC}
  fpcunit,
  testregistry,
{$ELSE}
  TestFramework,
{$ENDIF FPC}
  ClpSecureRandom,
  ClpISecureRandom,
  ClpIX9ECParameters,
  ClpSecObjectIdentifiers,
  ClpConverters,
  ClpCustomNamedCurves,
  ClpIECC,
  ClpBigInteger,
  ClpCryptoLibTypes,
  CryptoLibTestBase;

type

  TTestSecP384R1Field = class(TCryptoLibAlgorithmTestCase)
  private
  var
    FRandom: ISecureRandom;
    FDP: IX9ECParameters;
    FQ: TBigInteger;

    procedure AssertAreBigIntegersEqual(const a, b: TBigInteger);
    function FE(const x: TBigInteger): IECFieldElement;
    function GenerateMultiplyInput_Random(): IECFieldElement;
    function GenerateSquareInput_CarryBug(): IECFieldElement;
    function Nat_Create(len: Int32): TCryptoLibUInt32Array;
    function Nat_ToBigInteger(len: Int32; const x: TCryptoLibUInt32Array)
      : TBigInteger;

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestMultiply1();
    procedure TestMultiply2();
    procedure TestSquare();
    procedure TestSquare_CarryBug();

    /// <summary>
    /// Based on another example input demonstrating the carry propagation
    /// bug in Nat192.square, as <br />reported by Joseph Friel on
    /// dev-crypto.
    /// </summary>
    procedure TestSquare_CarryBug_Reported();

  end;

implementation

{ TTestSecP384R1Field }

procedure TTestSecP384R1Field.AssertAreBigIntegersEqual(const a,
  b: TBigInteger);
begin
  CheckEquals(True, a.Equals(b));
end;

function TTestSecP384R1Field.FE(const x: TBigInteger): IECFieldElement;
begin
  result := FDP.Curve.FromBigInteger(x);
end;

function TTestSecP384R1Field.GenerateMultiplyInput_Random: IECFieldElement;
begin
  result := FE(TBigInteger.Create(FDP.Curve.FieldSize + 32, FRandom).&Mod(FQ));
end;

function TTestSecP384R1Field.GenerateSquareInput_CarryBug: IECFieldElement;
var
  x: TCryptoLibUInt32Array;
begin
  x := Nat_Create(12);
  x[0] := UInt32(FRandom.NextInt32()) shr 1;
  x[6] := 2;
  x[10] := $FFFF0000;
  x[11] := $FFFFFFFF;

  result := FE(Nat_ToBigInteger(12, x));
end;

function TTestSecP384R1Field.Nat_Create(len: Int32): TCryptoLibUInt32Array;
begin
  System.SetLength(result, len);
end;

function TTestSecP384R1Field.Nat_ToBigInteger(len: Int32;
  const x: TCryptoLibUInt32Array): TBigInteger;
var
  bs, temp: TBytes;
  i: Int32;
  x_i: UInt32;
begin
  System.SetLength(bs, len shl 2);
  for i := 0 to System.Pred(len) do

  begin
    x_i := x[i];
    if (x_i <> 0) then
    begin
      temp := TConverters.ReadUInt32AsBytesBE(x_i);
      System.Move(temp[0], bs[(len - 1 - i) shl 2], System.Length(temp) *
        SizeOf(Byte));

    end;
  end;
  result := TBigInteger.Create(1, bs);
end;

procedure TTestSecP384R1Field.SetUp;
begin
  inherited;
  FRandom := TSecureRandom.Create();
  FDP := TCustomNamedCurves.GetByOid(TSecObjectIdentifiers.SecP384r1);
  FQ := FDP.Curve.Field.Characteristic;
end;

procedure TTestSecP384R1Field.TearDown;
begin
  inherited;

end;

procedure TTestSecP384R1Field.TestMultiply1;
var
  Count, i: Int32;
  x, y, z: IECFieldElement;
  bigX, bigY, bigR, bigZ: TBigInteger;
begin
  Count := 1000;

  i := 0;

  while i < Count do
  begin

    x := GenerateMultiplyInput_Random();
    y := GenerateMultiplyInput_Random();

    bigX := x.ToBigInteger();
    bigY := y.ToBigInteger();
    bigR := bigX.Multiply(bigY).&Mod(FQ);

    z := x.Multiply(y);
    bigZ := z.ToBigInteger();

    AssertAreBigIntegersEqual(bigR, bigZ);

    System.Inc(i);
  end;

end;

procedure TTestSecP384R1Field.TestMultiply2;
var
  Count, i, J, K: Int32;
  ecFieldElements: TCryptoLibGenericArray<IECFieldElement>;
  bigIntegers: TCryptoLibGenericArray<TBigInteger>;
  bigR, bigZ: TBigInteger;
  z: IECFieldElement;
begin
  Count := 100;
  System.SetLength(ecFieldElements, Count);
  System.SetLength(bigIntegers, Count);

  for i := 0 to System.Pred(System.Length(ecFieldElements)) do

  begin
    ecFieldElements[i] := GenerateMultiplyInput_Random();
    bigIntegers[i] := ecFieldElements[i].ToBigInteger();
  end;

  for J := 0 to System.Pred(System.Length(ecFieldElements)) do
  begin
    for K := 0 to System.Pred(System.Length(ecFieldElements)) do
    begin
      bigR := bigIntegers[J].Multiply(bigIntegers[K]).&Mod(FQ);

      z := ecFieldElements[J].Multiply(ecFieldElements[K]);
      bigZ := z.ToBigInteger();

      AssertAreBigIntegersEqual(bigR, bigZ);
    end;
  end;
end;

procedure TTestSecP384R1Field.TestSquare;
var
  Count, i: Int32;
  x, z: IECFieldElement;
  bigX, bigY, bigZ: TBigInteger;
begin
  Count := 1000;
  i := 0;

  while i < Count do

  begin
    x := GenerateMultiplyInput_Random();

    bigX := x.ToBigInteger();
    bigY := bigX.Multiply(bigX).&Mod(FQ);

    z := x.Square();
    bigZ := z.ToBigInteger();

    AssertAreBigIntegersEqual(bigY, bigZ);
    System.Inc(i);
  end;
end;

procedure TTestSecP384R1Field.TestSquare_CarryBug;
var
  Count, i: Int32;
  x, z: IECFieldElement;
  bigX, bigR, bigZ: TBigInteger;
begin
  Count := 100;
  i := 0;

  while i < Count do

  begin
    x := GenerateSquareInput_CarryBug();

    bigX := x.ToBigInteger();
    bigR := bigX.Multiply(bigX).&Mod(FQ);

    z := x.Square();
    bigZ := z.ToBigInteger();

    AssertAreBigIntegersEqual(bigR, bigZ);
    System.Inc(i);
  end;
end;

procedure TTestSecP384R1Field.TestSquare_CarryBug_Reported;
var
  x, z: IECFieldElement;
  bigX, bigR, bigZ: TBigInteger;
begin
  x := FE(TBigInteger.Create
    ('2fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd',
    16));

  bigX := x.ToBigInteger();
  bigR := bigX.Multiply(bigX).&Mod(FQ);

  z := x.Square();
  bigZ := z.ToBigInteger();

  AssertAreBigIntegersEqual(bigR, bigZ);
end;

initialization

// Register any test cases with the test runner

{$IFDEF FPC}
  RegisterTest(TTestSecP384R1Field);
{$ELSE}
  RegisterTest(TTestSecP384R1Field.Suite);
{$ENDIF FPC}

end.
