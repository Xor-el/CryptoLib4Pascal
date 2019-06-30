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

unit SecP256R1FieldTests;

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

  TTestSecP256R1Field = class(TCryptoLibAlgorithmTestCase)
  private
  var
    FRandom: ISecureRandom;
    FDP: IX9ECParameters;
    FQ: TBigInteger;

    procedure AssertAreBigIntegersEqual(const a, b: TBigInteger);
    function FE(const x: TBigInteger): IECFieldElement;
    function GenerateMultiplyInput_Random(): IECFieldElement;
    function GenerateSquareInput_OpenSSLBug(): IECFieldElement;
    function GenerateMultiplyInputA_OpenSSLBug(): IECFieldElement;
    function GenerateMultiplyInputB_OpenSSLBug(): IECFieldElement;
    function Nat256_Create(): TCryptoLibUInt32Array;
    function Nat256_ToBigInteger(const x: TCryptoLibUInt32Array): TBigInteger;

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestMultiply1();
    procedure TestMultiply2();
    procedure TestSquare();

    /// <summary>
    /// <para>
    /// Test squaring with specifically selected values that triggered a
    /// bug in the modular reduction <br />in OpenSSL (last affected
    /// version 0.9.8g).
    /// </para>
    /// <para>
    /// See "Practical realisation and elimination of an ECC-related
    /// software bug attack", B. B. <br />Brumley, M. Barbarosa, D. Page,
    /// F. Vercauteren.
    /// </para>
    /// </summary>
    procedure TestSquare_OpenSSLBug();

    /// <summary>
    /// <para>
    /// Test multiplication with specifically selected values that
    /// triggered a bug in the modular <br />reduction in OpenSSL (last
    /// affected version 0.9.8g).
    /// </para>
    /// <para>
    /// See "Practical realisation and elimination of an ECC-related
    /// software bug attack", B. B. <br />Brumley, M. Barbarosa, D. Page,
    /// F. Vercauteren.
    /// </para>
    /// </summary>
    procedure TestMultiply_OpenSSLBug();

  end;

implementation

{ TTestSecP256R1Field }

procedure TTestSecP256R1Field.AssertAreBigIntegersEqual(const a,
  b: TBigInteger);
begin
  CheckEquals(True, a.Equals(b));
end;

function TTestSecP256R1Field.FE(const x: TBigInteger): IECFieldElement;
begin
  result := FDP.Curve.FromBigInteger(x);
end;

function TTestSecP256R1Field.GenerateMultiplyInputA_OpenSSLBug: IECFieldElement;
var
  x: TCryptoLibUInt32Array;
begin
  x := Nat256_Create();
  x[0] := UInt32(FRandom.NextInt32()) shr 1;
  x[4] := 3;
  x[7] := $FFFFFFFF;

  result := FE(Nat256_ToBigInteger(x));
end;

function TTestSecP256R1Field.GenerateMultiplyInputB_OpenSSLBug: IECFieldElement;
var
  x: TCryptoLibUInt32Array;
begin
  x := Nat256_Create();
  x[0] := UInt32(FRandom.NextInt32()) shr 1;
  x[3] := 1;
  x[7] := $FFFFFFFF;

  result := FE(Nat256_ToBigInteger(x));
end;

function TTestSecP256R1Field.GenerateMultiplyInput_Random: IECFieldElement;
begin
  result := FE(TBigInteger.Create(FDP.Curve.FieldSize + 32, FRandom).&Mod(FQ));
end;

function TTestSecP256R1Field.GenerateSquareInput_OpenSSLBug: IECFieldElement;
var
  x: TCryptoLibUInt32Array;
begin
  x := Nat256_Create();
  x[0] := UInt32(FRandom.NextInt32()) shr 1;
  x[4] := 2;
  x[7] := $FFFFFFFF;

  result := FE(Nat256_ToBigInteger(x));
end;

function TTestSecP256R1Field.Nat256_Create(): TCryptoLibUInt32Array;
begin
  System.SetLength(result, 8);
end;

function TTestSecP256R1Field.Nat256_ToBigInteger(const x: TCryptoLibUInt32Array)
  : TBigInteger;
var
  bs, temp: TBytes;
  i: Int32;
  x_i: UInt32;
begin
  System.SetLength(bs, 32);
  for i := 0 to System.Pred(8) do

  begin
    x_i := x[i];
    if (x_i <> 0) then
    begin
      temp := TConverters.ReadUInt32AsBytesBE(x_i);
      System.Move(temp[0], bs[(7 - i) shl 2], System.Length(temp) *
        SizeOf(Byte));

    end;
  end;
  result := TBigInteger.Create(1, bs);
end;

procedure TTestSecP256R1Field.SetUp;
begin
  inherited;
  FRandom := TSecureRandom.Create();
  FDP := TCustomNamedCurves.GetByOid(TSecObjectIdentifiers.SecP256r1);

  FQ := FDP.Curve.Field.Characteristic;
end;

procedure TTestSecP256R1Field.TearDown;
begin
  inherited;

end;

procedure TTestSecP256R1Field.TestMultiply1;
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

procedure TTestSecP256R1Field.TestMultiply2;
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

procedure TTestSecP256R1Field.TestSquare;
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

procedure TTestSecP256R1Field.TestSquare_OpenSSLBug;
var
  Count, i: Int32;
  x, z: IECFieldElement;
  bigX, bigR, bigZ: TBigInteger;
begin
  Count := 100;
  i := 0;

  while i < Count do

  begin
    x := GenerateSquareInput_OpenSSLBug();

    bigX := x.ToBigInteger();
    bigR := bigX.Multiply(bigX).&Mod(FQ);

    z := x.Square();
    bigZ := z.ToBigInteger();

    AssertAreBigIntegersEqual(bigR, bigZ);
    System.Inc(i);
  end;
end;

procedure TTestSecP256R1Field.TestMultiply_OpenSSLBug;
var
  x, y, z: IECFieldElement;
  bigR, bigX, bigY, bigZ: TBigInteger;
  Count, i: Int32;
begin

  Count := 100;
  i := 0;

  while i < Count do
  begin
    x := GenerateMultiplyInputA_OpenSSLBug();
    y := GenerateMultiplyInputB_OpenSSLBug();

    bigX := x.ToBigInteger();
    bigY := y.ToBigInteger();
    bigR := bigX.Multiply(bigY).&Mod(FQ);

    z := x.Multiply(y);
    bigZ := z.ToBigInteger();

    AssertAreBigIntegersEqual(bigR, bigZ);
    System.Inc(i);
  end;

end;

initialization

// Register any test cases with the test runner

{$IFDEF FPC}
  RegisterTest(TTestSecP256R1Field);
{$ELSE}
  RegisterTest(TTestSecP256R1Field.Suite);
{$ENDIF FPC}

end.
