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

unit SecureRandomTests;

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
  ClpAESPRNGRandom,
  ClpSecureRandom,
  ClpISecureRandom,
  ClpRandomNumberGenerator,
  ClpCryptoApiRandomGenerator,
  ClpICryptoApiRandomGenerator,
  ClpCryptoLibTypes,
  CryptoLibTestBase;

type

  TTestSecureRandom = class(TCryptoLibAlgorithmTestCase)
  private

    procedure CheckSecureRandom(const random: ISecureRandom);
    function RunChiSquaredTests(const random: ISecureRandom): Boolean;
    function MeasureChiSquared(const random: ISecureRandom;
      rounds: Int32): Double;

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestCryptoApi();
    procedure TestOSRandom();
    procedure TestAESPRNG();
    procedure TestAESPRNGRandom();
    procedure TestDefault();
    procedure TestSha1Prng();
    procedure TestSha256Prng();

  end;

implementation

{ TTestSecureRandom }

procedure TTestSecureRandom.CheckSecureRandom(const random: ISecureRandom);
begin
  // Note: This will periodically (< 1e-6 probability) give a false alarm.
  // That's randomness for you!
  CheckEquals(true, RunChiSquaredTests(random),
    'Chi2 test detected possible non-randomness');
end;

function TTestSecureRandom.MeasureChiSquared(const random: ISecureRandom;
  rounds: Int32): Double;
var
  opts, bs: TBytes;
  counts: TCryptoLibInt32Array;
  I, b, total, k, mask, shift: Int32;
  chi2, diff, diff2, temp: Double;
begin
  opts := random.GenerateSeed(2);
  System.SetLength(counts, 256);
  System.SetLength(bs, 256);

  I := 0;
  while I < rounds do
  begin
    random.NextBytes(bs);

    for b := 0 to System.Pred(256) do
    begin

      counts[bs[b]] := counts[bs[b]] + 1;

    end;

    System.Inc(I);
  end;

  mask := opts[0];

  I := 0;
  while I < rounds do
  begin
    random.NextBytes(bs);

    for b := 0 to System.Pred(256) do
    begin

      counts[bs[b] xor Byte(mask)] := counts[bs[b] xor Byte(mask)] + 1;

    end;
    System.Inc(mask);
    System.Inc(I);
  end;

  shift := opts[1];

  I := 0;
  while I < rounds do
  begin
    random.NextBytes(bs);

    for b := 0 to System.Pred(256) do
    begin

      counts[Byte(bs[b] + Byte(shift))] :=
        counts[Byte(bs[b] + Byte(shift))] + 1;

    end;
    System.Inc(shift);
    System.Inc(I);
  end;

  total := 3 * rounds;

  chi2 := 0;

  for k := 0 to System.Pred(System.Length(counts)) do
  begin
    temp := counts[k];
    diff := temp - total;
    diff2 := diff * diff;

    chi2 := chi2 + diff2;
  end;

  chi2 := chi2 / total;

  result := chi2;
end;

function TTestSecureRandom.RunChiSquaredTests(const random
  : ISecureRandom): Boolean;
var
  passes, tries: Int32;
  chi2: Double;
begin
  passes := 0;

  tries := 0;
  while tries < 100 do
  begin
    chi2 := MeasureChiSquared(random, 1000);

    // 255 degrees of freedom in test => Q ~ 10.0% for 285
    if (chi2 < 285.0) then
    begin
      System.Inc(passes);
    end;

    System.Inc(tries);
  end;

  result := passes > 75;
end;

procedure TTestSecureRandom.SetUp;
begin
  inherited;

end;

procedure TTestSecureRandom.TearDown;
begin
  inherited;

end;

procedure TTestSecureRandom.TestOSRandom;
var
  &random: ISecureRandom;
begin
  random := TSecureRandom.Create(TCryptoApiRandomGenerator.Create
    (TRandomNumberGenerator.CreateRNG
    (TRandomNumberGenerator.TRandomNumberGeneratorMode.rngmOS))
    as ICryptoApiRandomGenerator);

  CheckSecureRandom(random);
end;

procedure TTestSecureRandom.TestAESPRNG;
var
  &random: ISecureRandom;
begin
  random := TSecureRandom.Create(TCryptoApiRandomGenerator.Create
    (TRandomNumberGenerator.CreateRNG
    (TRandomNumberGenerator.TRandomNumberGeneratorMode.rngmAES))
    as ICryptoApiRandomGenerator);

  CheckSecureRandom(random);
end;

procedure TTestSecureRandom.TestAESPRNGRandom;
var
  b1, b2, NilBytes: TBytes;
  a1, a2: IAESPRNGRandom;
  Idx: Int32;
begin
  // it is hard to validate randomness - we just test the feature set
  System.SetLength(b1, 16);
  System.SetLength(b2, 16);
  NilBytes := Nil;
  TAESPRNGRandom.GetBytes(b1);
  TAESPRNGRandom.GetBytes(b2);

  CheckTrue(not AreEqual(b1, b2));

  a1 := TAESPRNGRandom.Create();
  a2 := TAESPRNGRandom.Create();

  a1.FillBytes(b1);
  a2.FillBytes(b2);
  CheckTrue(not AreEqual(b1, b2));
  a1.FillBytes(NilBytes);
  CheckEquals(System.Length(NilBytes), 0);

  for Idx := 1 to 10000 do
  begin
    System.SetLength(b1, Idx);
    System.SetLength(b2, Idx);
    a1.FillBytes(b1);
    a2.FillBytes(b2);

    CheckTrue(not AreEqual(b1, b2));
  end;

end;

procedure TTestSecureRandom.TestCryptoApi;
var
  &random: ISecureRandom;
begin
  random := TSecureRandom.Create(TCryptoApiRandomGenerator.Create()
    as ICryptoApiRandomGenerator);

  CheckSecureRandom(random);
end;

procedure TTestSecureRandom.TestDefault;
var
  &random: ISecureRandom;
begin
  random := TSecureRandom.Create();

  CheckSecureRandom(random);
end;

procedure TTestSecureRandom.TestSha1Prng;
var
  &random: ISecureRandom;
begin
  random := TSecureRandom.GetInstance('SHA1PRNG');

  CheckSecureRandom(random);
end;

procedure TTestSecureRandom.TestSha256Prng;
var
  &random: ISecureRandom;
begin
  random := TSecureRandom.GetInstance('SHA256PRNG');

  CheckSecureRandom(random);
end;

initialization

// Register any test cases with the test runner

{$IFDEF FPC}
  RegisterTest(TTestSecureRandom);
{$ELSE}
  RegisterTest(TTestSecureRandom.Suite);
{$ENDIF FPC}

end.
