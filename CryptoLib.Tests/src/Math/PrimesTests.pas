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

unit PrimesTests;

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
  ClpPrimes,
  ClpBigInteger,
  ClpBigIntegerUtilities,
  ClpSecureRandom,
  ClpISecureRandom,
  ClpDigestUtilities,
  ClpIDigest,
  ClpCryptoLibTypes,
  ClpArrayUtilities,
  CryptoLibTestBase;

type
  TTestPrimes = class(TCryptoLibAlgorithmTestCase)
  private
    const
      ITERATIONS = 10;
      PRIME_BITS = 256;
      PRIME_CERTAINTY = 100;
    var
      FRandom: ISecureRandom;

    function ReferenceIsMRProbablePrime(const AX: TBigInteger; ANumBases: Int32): Boolean;
    function IsPrime(const AX: TBigInteger): Boolean;
    function RandomPrime: TBigInteger;
  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestHasAnySmallFactors;
    procedure TestEnhancedMRProbablePrime;
    procedure TestMRProbablePrime;
    procedure TestMRProbablePrimeToBase;
    procedure TestSTRandomPrime;
  end;

implementation

{ TTestPrimes }

procedure TTestPrimes.SetUp;
begin
  inherited;
  FRandom := TSecureRandom.Create();
end;

procedure TTestPrimes.TearDown;
begin
  inherited;
end;

function TTestPrimes.RandomPrime: TBigInteger;
begin
  Result := TBigInteger.Create(PRIME_BITS, PRIME_CERTAINTY, FRandom);
end;

function TTestPrimes.IsPrime(const AX: TBigInteger): Boolean;
begin
  Result := AX.IsProbablePrime(PRIME_CERTAINTY);
end;

function TTestPrimes.ReferenceIsMRProbablePrime(const AX: TBigInteger;
  ANumBases: Int32): Boolean;
var
  LXSubTwo: TBigInteger;
  LI: Int32;
  LB: TBigInteger;
begin
  LXSubTwo := AX.Subtract(TBigInteger.Two);

  for LI := 0 to ANumBases - 1 do
  begin
    LB := TBigIntegerUtilities.CreateRandomInRange(TBigInteger.Two, LXSubTwo, FRandom);
    if not TPrimes.IsMRProbablePrimeToBase(AX, LB) then
      Exit(False);
  end;

  Result := True;
end;

procedure TTestPrimes.TestHasAnySmallFactors;
var
  LIterations, LSmallFactor: Int32;
  LPrime, LNonPrimeWithSmallFactor: TBigInteger;
begin
  for LIterations := 0 to ITERATIONS - 1 do
  begin
    LPrime := RandomPrime();
    CheckFalse(TPrimes.HasAnySmallFactors(LPrime), 'prime should not have small factors');

    for LSmallFactor := 2 to TPrimes.SmallFactorLimit do
    begin
      LNonPrimeWithSmallFactor := TBigInteger.ValueOf(LSmallFactor).Multiply(LPrime);
      CheckTrue(TPrimes.HasAnySmallFactors(LNonPrimeWithSmallFactor),
        'composite with small factor ' + IntToStr(LSmallFactor) + ' should be detected');
    end;
  end;
end;

procedure TTestPrimes.TestEnhancedMRProbablePrime;
var
  LMrIterations, LIterations, LI: Int32;
  LPrime, LPrimePower, LNonPrimePower: TBigInteger;
  LMr, LMr2, LMr3: TPrimes.IMROutput;
begin
  LMrIterations := (PRIME_CERTAINTY + 1) div 2;

  for LIterations := 0 to ITERATIONS - 1 do
  begin
    LPrime := RandomPrime();
    LMr := TPrimes.EnhancedMRProbablePrimeTest(LPrime, FRandom, LMrIterations);
    CheckFalse(LMr.IsProvablyComposite, 'prime: IsProvablyComposite');
    CheckFalse(LMr.IsNotPrimePower, 'prime: IsNotPrimePower');
    CheckFalse(LMr.Factor.IsInitialized, 'prime: Factor should be unset');

    LPrimePower := LPrime;
    for LI := 0 to (LIterations mod 8) do
      LPrimePower := LPrimePower.Multiply(LPrime);

    LMr2 := TPrimes.EnhancedMRProbablePrimeTest(LPrimePower, FRandom, LMrIterations);
    CheckTrue(LMr2.IsProvablyComposite, 'prime power: IsProvablyComposite');
    CheckFalse(LMr2.IsNotPrimePower, 'prime power: IsNotPrimePower');
    CheckTrue(LMr2.Factor.IsInitialized and LMr2.Factor.Equals(LPrime), 'prime power: Factor = prime');

    LNonPrimePower := RandomPrime().Multiply(LPrime);
    LMr3 := TPrimes.EnhancedMRProbablePrimeTest(LNonPrimePower, FRandom, LMrIterations);
    CheckTrue(LMr3.IsProvablyComposite, 'non-prime-power: IsProvablyComposite');
    CheckTrue(LMr3.IsNotPrimePower, 'non-prime-power: IsNotPrimePower');
    CheckFalse(LMr.Factor.IsInitialized, 'non-prime-power: Factor (mr) should be unset');
  end;
end;

procedure TTestPrimes.TestMRProbablePrime;
var
  LMrIterations, LIterations: Int32;
  LPrime, LNonPrime: TBigInteger;
begin
  LMrIterations := (PRIME_CERTAINTY + 1) div 2;

  for LIterations := 0 to ITERATIONS - 1 do
  begin
    LPrime := RandomPrime();
    CheckTrue(TPrimes.IsMRProbablePrime(LPrime, FRandom, LMrIterations), 'prime');

    LNonPrime := RandomPrime().Multiply(LPrime);
    CheckFalse(TPrimes.IsMRProbablePrime(LNonPrime, FRandom, LMrIterations), 'composite');
  end;
end;

procedure TTestPrimes.TestMRProbablePrimeToBase;
var
  LMrIterations, LIterations: Int32;
  LPrime, LNonPrime: TBigInteger;
begin
  LMrIterations := (PRIME_CERTAINTY + 1) div 2;

  for LIterations := 0 to ITERATIONS - 1 do
  begin
    LPrime := RandomPrime();
    CheckTrue(ReferenceIsMRProbablePrime(LPrime, LMrIterations), 'prime');

    LNonPrime := RandomPrime().Multiply(LPrime);
    CheckFalse(ReferenceIsMRProbablePrime(LNonPrime, LMrIterations), 'composite');
  end;
end;

procedure TTestPrimes.TestSTRandomPrime;
var
  LDigests: array [0 .. 1] of IDigest;
  LDigestIndex, LCoincidenceCount, LIterations, LI: Int32;
  LDigest: IDigest;
  LInputSeed: TCryptoLibByteArray;
  LSt, LSt2, LSt3: TPrimes.ISTOutput;
begin
  LDigests[0] := TDigestUtilities.GetDigest('SHA-1');
  LDigests[1] := TDigestUtilities.GetDigest('SHA-256');

  for LDigestIndex := 0 to 1 do
  begin
    LCoincidenceCount := 0;
    LDigest := LDigests[LDigestIndex];

    LIterations := 0;
    while LIterations < ITERATIONS do
    begin
      try
        System.SetLength(LInputSeed, 16);
        FRandom.NextBytes(LInputSeed, 0, 16);

        LSt := TPrimes.GenerateSTRandomPrime(LDigest, PRIME_BITS, LInputSeed);
        CheckTrue(IsPrime(LSt.Prime), 'generated prime should be prime');

        LSt2 := TPrimes.GenerateSTRandomPrime(LDigest, PRIME_BITS, LInputSeed);
        CheckTrue(LSt.Prime.Equals(LSt2.Prime), 'same seed -> same prime');
        CheckEquals(LSt.PrimeGenCounter, LSt2.PrimeGenCounter, 'same seed -> same counter');
        CheckTrue(AreEqual(LSt.PrimeSeed, LSt2.PrimeSeed), 'same seed -> same PrimeSeed');

        for LI := 0 to System.Length(LInputSeed) - 1 do
          LInputSeed[LI] := LInputSeed[LI] xor $FF;

        LSt3 := TPrimes.GenerateSTRandomPrime(LDigest, PRIME_BITS, LInputSeed);
        CheckTrue(not LSt.Prime.Equals(LSt3.Prime), 'different seed -> different prime');
        CheckFalse(AreEqual(LSt.PrimeSeed, LSt3.PrimeSeed), 'different seed -> different PrimeSeed');

        if LSt.PrimeGenCounter = LSt3.PrimeGenCounter then
          Inc(LCoincidenceCount);
      except
        on E: EInvalidOperationCryptoLibException do
        begin
          if E.Message.IndexOf('Too many iterations') >= 0 then
            Continue;
          raise;
        end;
      end;
      Inc(LIterations);
    end;

    CheckTrue(LCoincidenceCount * LCoincidenceCount < ITERATIONS, 'coincidence count check');
  end;
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestPrimes);
{$ELSE}
  RegisterTest(TTestPrimes.Suite);
{$ENDIF FPC}

end.
