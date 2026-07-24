{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                           Author - Ugochukwu Mmaduekwe                          * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ *                                                                                 * }
{ *                              Acknowledgements:                                  * }
{ *                                                                                 * }
{ *      Thanks to Sphere 10 Software (http://www.sphere10.com/) for sponsoring     * }
{ *                         the development of this library                         * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit SecPFieldTestBase;

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
  ClpIAsn1Objects,
  ClpIX9ECAsn1Objects,
  ClpPack,
  ClpCustomNamedCurves,
  ClpIECCommon,
  ClpIECFieldElement,
  ClpBigInteger,
  ClpCryptoLibTypes,
  CryptoLibTestBase;

type
  /// <summary>
  /// Shared scaffolding for the SecP***R1 custom-field tests: random-input
  /// generation, the fixed-length nat helpers, and the three generic
  /// multiply/square parity tests. Concrete suites supply the curve OID and
  /// add their own reduction-bug regression cases.
  /// </summary>
  TSecPFieldTestBase = class abstract(TCryptoLibAlgorithmTestCase)
  strict protected
    FRandom: ISecureRandom;
    FDP: IX9ECParameters;
    FQ: TBigInteger;

    // The curve OID whose field arithmetic this suite exercises.
    function GetCurveOid: IDerObjectIdentifier; virtual; abstract;

    procedure AssertAreBigIntegersEqual(const a, b: TBigInteger);
    function FE(const x: TBigInteger): IECFieldElement;
    function GenerateMultiplyInput_Random(): IECFieldElement;
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
  end;

implementation

{ TSecPFieldTestBase }

procedure TSecPFieldTestBase.AssertAreBigIntegersEqual(const a, b: TBigInteger);
begin
  CheckEquals(True, a.Equals(b));
end;

function TSecPFieldTestBase.FE(const x: TBigInteger): IECFieldElement;
begin
  result := FDP.Curve.FromBigInteger(x);
end;

function TSecPFieldTestBase.GenerateMultiplyInput_Random: IECFieldElement;
begin
  result := FE(TBigInteger.Create(FDP.Curve.FieldSize + 32, FRandom).&Mod(FQ));
end;

function TSecPFieldTestBase.Nat_Create(len: Int32): TCryptoLibUInt32Array;
begin
  System.SetLength(result, len);
end;

function TSecPFieldTestBase.Nat_ToBigInteger(len: Int32;
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
      temp := TPack.UInt32_To_BE(x_i);
      System.Move(temp[0], bs[(len - 1 - i) shl 2], System.Length(temp) *
        SizeOf(Byte));
    end;
  end;
  result := TBigInteger.Create(1, bs);
end;

procedure TSecPFieldTestBase.SetUp;
begin
  inherited;
  FRandom := TSecureRandom.Create();
  FDP := TCustomNamedCurves.GetByOid(GetCurveOid);
  FQ := FDP.Curve.Field.Characteristic;
end;

procedure TSecPFieldTestBase.TearDown;
begin
  inherited;
end;

procedure TSecPFieldTestBase.TestMultiply1;
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

procedure TSecPFieldTestBase.TestMultiply2;
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

procedure TSecPFieldTestBase.TestSquare;
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

end.
