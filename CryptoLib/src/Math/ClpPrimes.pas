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

unit ClpPrimes;

{$I ..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  Math,
  ClpBigInteger,
  ClpBigIntegers,
  ClpPack,
  ClpIDigest,
  ClpISecureRandom,
  ClpArrayUtilities,
  ClpBitOperations,
  ClpCryptoLibTypes;

resourcestring
  SPrimesHashNil = 'hash cannot be null';
  SPrimesLengthMustBeAtLeast2 = 'length must be >= 2';
  SPrimesInputSeedNil = 'inputSeed cannot be null';
  SPrimesInputSeedEmpty = 'inputSeed cannot be empty';
  SPrimesRandomNil = 'random cannot be null';
  SPrimesIterationsMustBePositive = 'iterations must be > 0';
  SPrimesBaseValueMustBeLess = 'baseValue must be < (candidate - 1)';
  SPrimesCandidateMustBeNonNull = 'must be non-null and >= 2';
  SPrimesTooManyIterations = 'Too many iterations in Shawe-Taylor Random_Prime Routine';

type
  /// <summary>
  /// Utility methods for generating primes and testing for primality.
  /// </summary>
  TPrimes = class sealed(TObject)
  public
    type
      /// <summary>Used to return the output from the Enhanced Miller-Rabin Probabilistic Primality Test.</summary>
      IMROutput = interface(IInterface)
        ['{A1B2C3D4-E5F6-4A5B-8C9D-0E1F2A3B4C5D}']

        function GetFactor: TBigInteger;
        function GetIsProvablyComposite: Boolean;
        function GetIsNotPrimePower: Boolean;

        property Factor: TBigInteger read GetFactor;
        property IsProvablyComposite: Boolean read GetIsProvablyComposite;
        property IsNotPrimePower: Boolean read GetIsNotPrimePower;
      end;

      TMROutput = class(TInterfacedObject, TPrimes.IMROutput)
      strict private
        FFactor: TBigInteger;
        FProvablyComposite: Boolean;
      public
        constructor Create(AProvablyComposite: Boolean; const AFactor: TBigInteger);
        function GetFactor: TBigInteger;
        function GetIsProvablyComposite: Boolean;
        function GetIsNotPrimePower: Boolean;
      end;

      /// <summary>Used to return the output from the Shawe-Taylor Random_Prime Routine.</summary>
      ISTOutput = interface(IInterface)
        ['{B2C3D4E5-F6A7-5B6C-9D0E-1F2A3B4C5D6E}']

        function GetPrime: TBigInteger;
        function GetPrimeSeed: TCryptoLibByteArray;
        function GetPrimeGenCounter: Int32;

        property Prime: TBigInteger read GetPrime;
        property PrimeSeed: TCryptoLibByteArray read GetPrimeSeed;
        property PrimeGenCounter: Int32 read GetPrimeGenCounter;
      end;

      TSTOutput = class(TInterfacedObject, TPrimes.ISTOutput)
      strict private
        FPrime: TBigInteger;
        FPrimeSeed: TCryptoLibByteArray;
        FPrimeGenCounter: Int32;
      public
        constructor Create(const APrime: TBigInteger;
          const APrimeSeed: TCryptoLibByteArray; APrimeGenCounter: Int32);
        function GetPrime: TBigInteger;
        function GetPrimeSeed: TCryptoLibByteArray;
        function GetPrimeGenCounter: Int32;
      end;

  const
    SmallFactorLimit = 211;

  class var
    FOne: TBigInteger;
    FTwo: TBigInteger;
    FThree: TBigInteger;

  private
    class procedure CheckCandidate(const AN: TBigInteger; const AName: String);
    class function ImplHasAnySmallFactors(const AX: TBigInteger): Boolean;
    class function ImplMRProbablePrimeToBase(const AW, AWSubOne, AM: TBigInteger;
      AA: Int32; const AB: TBigInteger): Boolean;
    class function ImplSTRandomPrime(const AD: IDigest; ALength: Int32;
      var APrimeSeed: TCryptoLibByteArray): TPrimes.ISTOutput;
    class procedure Hash(const AD: IDigest; const AInput: TCryptoLibByteArray;
      const AOutput: TCryptoLibByteArray; AOutPos: Int32);
    class function HashGen(const AD: IDigest; var ASeed: TCryptoLibByteArray;
      ACount: Int32): TBigInteger;
    class procedure IncSeed(var ASeed: TCryptoLibByteArray; AC: Int32);
    class function IsPrime32(AX: UInt32): Boolean;

  public
    class constructor Create;

    /// <summary>FIPS 186-4 C.6 Shawe-Taylor Random_Prime Routine.</summary>
    class function GenerateSTRandomPrime(const AHash: IDigest; ALength: Int32;
      const AInputSeed: TCryptoLibByteArray): TPrimes.ISTOutput; static;

    /// <summary>FIPS 186-4 C.3.2 Enhanced Miller-Rabin Probabilistic Primality Test.</summary>
    class function EnhancedMRProbablePrimeTest(const ACandidate: TBigInteger;
      const ARandom: ISecureRandom; AIterations: Int32): TPrimes.IMROutput; static;

    /// <summary>A fast check for small divisors, up to some implementation-specific limit.</summary>
    class function HasAnySmallFactors(const ACandidate: TBigInteger): Boolean; static;

    /// <summary>FIPS 186-4 C.3.1 Miller-Rabin Probabilistic Primality Test.</summary>
    class function IsMRProbablePrime(const ACandidate: TBigInteger;
      const ARandom: ISecureRandom; AIterations: Int32): Boolean; static;

    /// <summary>FIPS 186-4 C.3.1 Miller-Rabin Probabilistic Primality Test (to a fixed base).</summary>
    class function IsMRProbablePrimeToBase(const ACandidate: TBigInteger;
      const ABaseValue: TBigInteger): Boolean; static;

    class function ProbablyPrime(): TPrimes.IMROutput; static;
    class function ProvablyCompositeWithFactor(const AFactor: TBigInteger): TPrimes.IMROutput; static;
    class function ProvablyCompositeNotPrimePower(): TPrimes.IMROutput; static;
  end;

implementation

{ TPrimes.TMROutput }

constructor TPrimes.TMROutput.Create(AProvablyComposite: Boolean;
  const AFactor: TBigInteger);
begin
  inherited Create;
  FProvablyComposite := AProvablyComposite;
  FFactor := AFactor;
end;

function TPrimes.TMROutput.GetFactor: TBigInteger;
begin
  Result := FFactor;
end;

function TPrimes.TMROutput.GetIsProvablyComposite: Boolean;
begin
  Result := FProvablyComposite;
end;

function TPrimes.TMROutput.GetIsNotPrimePower: Boolean;
begin
  Result := FProvablyComposite and (not FFactor.IsInitialized);
end;

{ TPrimes.TSTOutput }

constructor TPrimes.TSTOutput.Create(const APrime: TBigInteger;
  const APrimeSeed: TCryptoLibByteArray; APrimeGenCounter: Int32);
begin
  inherited Create;
  FPrime := APrime;
  FPrimeSeed := System.Copy(APrimeSeed, 0, System.Length(APrimeSeed));
  FPrimeGenCounter := APrimeGenCounter;
end;

function TPrimes.TSTOutput.GetPrime: TBigInteger;
begin
  Result := FPrime;
end;

function TPrimes.TSTOutput.GetPrimeSeed: TCryptoLibByteArray;
begin
  Result := FPrimeSeed;
end;

function TPrimes.TSTOutput.GetPrimeGenCounter: Int32;
begin
  Result := FPrimeGenCounter;
end;

{ TPrimes }

class constructor TPrimes.Create;
begin
  FOne := TBigInteger.One;
  FTwo := TBigInteger.Two;
  FThree := TBigInteger.Three;
end;

class procedure TPrimes.CheckCandidate(const AN: TBigInteger; const AName: String);
begin
  if (not AN.IsInitialized) or (AN.SignValue < 1) or (AN.BitLength < 2) then
    raise EArgumentCryptoLibException.CreateRes(@SPrimesCandidateMustBeNonNull);
end;

class function TPrimes.ProbablyPrime: TPrimes.IMROutput;
begin
  Result := TPrimes.TMROutput.Create(False, TBigInteger.GetDefault());
end;

class function TPrimes.ProvablyCompositeWithFactor(const AFactor: TBigInteger): TPrimes.IMROutput;
begin
  Result := TPrimes.TMROutput.Create(True, AFactor);
end;

class function TPrimes.ProvablyCompositeNotPrimePower: TPrimes.IMROutput;
begin
  Result := TPrimes.TMROutput.Create(True, TBigInteger.GetDefault());
end;

class function TPrimes.GenerateSTRandomPrime(const AHash: IDigest; ALength: Int32;
  const AInputSeed: TCryptoLibByteArray): TPrimes.ISTOutput;
var
  LPrimeSeed: TCryptoLibByteArray;
begin
  if AHash = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SPrimesHashNil);
  if ALength < 2 then
    raise EArgumentCryptoLibException.CreateRes(@SPrimesLengthMustBeAtLeast2);
  if AInputSeed = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SPrimesInputSeedNil);
  if System.Length(AInputSeed) = 0 then
    raise EArgumentCryptoLibException.CreateRes(@SPrimesInputSeedEmpty);

  LPrimeSeed := TArrayUtilities.CopyOf<Byte>(AInputSeed, System.Length(AInputSeed));
  Result := ImplSTRandomPrime(AHash, ALength, LPrimeSeed);
end;

class function TPrimes.EnhancedMRProbablePrimeTest(const ACandidate: TBigInteger;
  const ARandom: ISecureRandom; AIterations: Int32): TPrimes.IMROutput;
var
  LW, LWSubOne, LWSubTwo, LB, LG, LZ, LM, LX: TBigInteger;
  LA, LI, LJ: Int32;
  LPrimeToBase: Boolean;
begin
  CheckCandidate(ACandidate, 'candidate');

  if ARandom = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SPrimesRandomNil);
  if AIterations < 1 then
    raise EArgumentCryptoLibException.CreateRes(@SPrimesIterationsMustBePositive);

  if ACandidate.BitLength = 2 then
    Exit(ProbablyPrime());

  if not ACandidate.TestBit(0) then
    Exit(ProvablyCompositeWithFactor(FTwo));

  LW := ACandidate;
  LWSubOne := ACandidate.Subtract(FOne);
  LWSubTwo := ACandidate.Subtract(FTwo);

  LA := LWSubOne.GetLowestSetBit();
  LM := LWSubOne.ShiftRight(LA);

  for LI := 0 to AIterations - 1 do
  begin
    LB := TBigIntegers.CreateRandomInRange(FTwo, LWSubTwo, ARandom);
    LG := LB.Gcd(LW);

    if LG.CompareTo(FOne) > 0 then
      Exit(ProvablyCompositeWithFactor(LG));

    LZ := LB.ModPow(LM, LW);

    if LZ.Equals(FOne) or LZ.Equals(LWSubOne) then
      Continue;

    LPrimeToBase := False;
    LX := LZ;

    for LJ := 1 to LA - 1 do
    begin
      LZ := LZ.Square().&Mod(LW);

      if LZ.Equals(LWSubOne) then
      begin
        LPrimeToBase := True;
        Break;
      end;

      if LZ.Equals(FOne) then
        Break;

      LX := LZ;
    end;

    if not LPrimeToBase then
    begin
      if not LZ.Equals(FOne) then
      begin
        LX := LZ;
        LZ := LZ.Square().&Mod(LW);

        if not LZ.Equals(FOne) then
          LX := LZ;
      end;

      LG := LX.Subtract(FOne).Gcd(LW);

      if LG.CompareTo(FOne) > 0 then
        Exit(ProvablyCompositeWithFactor(LG));

      Exit(ProvablyCompositeNotPrimePower());
    end;
  end;

  Result := ProbablyPrime();
end;

class function TPrimes.HasAnySmallFactors(const ACandidate: TBigInteger): Boolean;
begin
  CheckCandidate(ACandidate, 'candidate');
  Result := ImplHasAnySmallFactors(ACandidate);
end;

class function TPrimes.IsMRProbablePrime(const ACandidate: TBigInteger;
  const ARandom: ISecureRandom; AIterations: Int32): Boolean;
var
  LW, LWSubOne, LWSubTwo, LB, LM: TBigInteger;
  LA, LI: Int32;
begin
  CheckCandidate(ACandidate, 'candidate');

  if ARandom = nil then
    raise EArgumentCryptoLibException.Create('cannot be null');
  if AIterations < 1 then
    raise EArgumentCryptoLibException.CreateRes(@SPrimesIterationsMustBePositive);

  if ACandidate.BitLength = 2 then
    Exit(True);
  if not ACandidate.TestBit(0) then
    Exit(False);

  LW := ACandidate;
  LWSubOne := ACandidate.Subtract(FOne);
  LWSubTwo := ACandidate.Subtract(FTwo);

  LA := LWSubOne.GetLowestSetBit();
  LM := LWSubOne.ShiftRight(LA);

  for LI := 0 to AIterations - 1 do
  begin
    LB := TBigIntegers.CreateRandomInRange(FTwo, LWSubTwo, ARandom);

    if not ImplMRProbablePrimeToBase(LW, LWSubOne, LM, LA, LB) then
      Exit(False);
  end;

  Result := True;
end;

class function TPrimes.IsMRProbablePrimeToBase(const ACandidate: TBigInteger;
  const ABaseValue: TBigInteger): Boolean;
var
  LW, LWSubOne, LM: TBigInteger;
  LA: Int32;
begin
  CheckCandidate(ACandidate, 'candidate');
  CheckCandidate(ABaseValue, 'baseValue');

  if ABaseValue.CompareTo(ACandidate.Subtract(FOne)) >= 0 then
    raise EArgumentCryptoLibException.CreateRes(@SPrimesBaseValueMustBeLess);

  if ACandidate.BitLength = 2 then
    Exit(True);

  LW := ACandidate;
  LWSubOne := ACandidate.Subtract(FOne);

  LA := LWSubOne.GetLowestSetBit();
  LM := LWSubOne.ShiftRight(LA);

  Result := ImplMRProbablePrimeToBase(LW, LWSubOne, LM, LA, ABaseValue);
end;

class function TPrimes.ImplHasAnySmallFactors(const AX: TBigInteger): Boolean;
var
  LM, LR: Int32;
  LRem: TBigInteger;
begin
  LM := 2 * 3 * 5 * 7 * 11 * 13 * 17 * 19 * 23;
  LRem := AX.&Mod(TBigInteger.ValueOf(LM));
  LR := LRem.Int32Value;
  if ((LR mod 2) = 0) or ((LR mod 3) = 0) or ((LR mod 5) = 0) or ((LR mod 7) = 0) or
     ((LR mod 11) = 0) or ((LR mod 13) = 0) or ((LR mod 17) = 0) or ((LR mod 19) = 0) or ((LR mod 23) = 0) then
    Exit(True);

  LM := 29 * 31 * 37 * 41 * 43;
  LRem := AX.&Mod(TBigInteger.ValueOf(LM));
  LR := LRem.Int32Value;
  if ((LR mod 29) = 0) or ((LR mod 31) = 0) or ((LR mod 37) = 0) or ((LR mod 41) = 0) or ((LR mod 43) = 0) then
    Exit(True);

  LM := 47 * 53 * 59 * 61 * 67;
  LRem := AX.&Mod(TBigInteger.ValueOf(LM));
  LR := LRem.Int32Value;
  if ((LR mod 47) = 0) or ((LR mod 53) = 0) or ((LR mod 59) = 0) or ((LR mod 61) = 0) or ((LR mod 67) = 0) then
    Exit(True);

  LM := 71 * 73 * 79 * 83;
  LRem := AX.&Mod(TBigInteger.ValueOf(LM));
  LR := LRem.Int32Value;
  if ((LR mod 71) = 0) or ((LR mod 73) = 0) or ((LR mod 79) = 0) or ((LR mod 83) = 0) then
    Exit(True);

  LM := 89 * 97 * 101 * 103;
  LRem := AX.&Mod(TBigInteger.ValueOf(LM));
  LR := LRem.Int32Value;
  if ((LR mod 89) = 0) or ((LR mod 97) = 0) or ((LR mod 101) = 0) or ((LR mod 103) = 0) then
    Exit(True);

  LM := 107 * 109 * 113 * 127;
  LRem := AX.&Mod(TBigInteger.ValueOf(LM));
  LR := LRem.Int32Value;
  if ((LR mod 107) = 0) or ((LR mod 109) = 0) or ((LR mod 113) = 0) or ((LR mod 127) = 0) then
    Exit(True);

  LM := 131 * 137 * 139 * 149;
  LRem := AX.&Mod(TBigInteger.ValueOf(LM));
  LR := LRem.Int32Value;
  if ((LR mod 131) = 0) or ((LR mod 137) = 0) or ((LR mod 139) = 0) or ((LR mod 149) = 0) then
    Exit(True);

  LM := 151 * 157 * 163 * 167;
  LRem := AX.&Mod(TBigInteger.ValueOf(LM));
  LR := LRem.Int32Value;
  if ((LR mod 151) = 0) or ((LR mod 157) = 0) or ((LR mod 163) = 0) or ((LR mod 167) = 0) then
    Exit(True);

  LM := 173 * 179 * 181 * 191;
  LRem := AX.&Mod(TBigInteger.ValueOf(LM));
  LR := LRem.Int32Value;
  if ((LR mod 173) = 0) or ((LR mod 179) = 0) or ((LR mod 181) = 0) or ((LR mod 191) = 0) then
    Exit(True);

  LM := 193 * 197 * 199 * 211;
  LRem := AX.&Mod(TBigInteger.ValueOf(LM));
  LR := LRem.Int32Value;
  if ((LR mod 193) = 0) or ((LR mod 197) = 0) or ((LR mod 199) = 0) or ((LR mod 211) = 0) then
    Exit(True);

  Result := False;
end;

class function TPrimes.ImplMRProbablePrimeToBase(const AW, AWSubOne, AM: TBigInteger;
  AA: Int32; const AB: TBigInteger): Boolean;
var
  LZ: TBigInteger;
  LJ: Int32;
begin
  LZ := AB.ModPow(AM, AW);

  if LZ.Equals(FOne) or LZ.Equals(AWSubOne) then
    Exit(True);

  for LJ := 1 to AA - 1 do
  begin
    LZ := LZ.Square().&Mod(AW);

    if LZ.Equals(AWSubOne) then
      Exit(True);

    if LZ.Equals(FOne) then
      Exit(False);
  end;

  Result := False;
end;

class function TPrimes.ImplSTRandomPrime(const AD: IDigest; ALength: Int32;
  var APrimeSeed: TCryptoLibByteArray): TPrimes.ISTOutput;
var
  LDLen, LCLen, LPrimeGenCounter, LOutlen, LIterations, LOldCounter, LDt: Int32;
  LC0, LC1: TCryptoLibByteArray;
  LC: UInt32;
  LRec: TPrimes.ISTOutput;
  LPrimeSeedRec: TCryptoLibByteArray;
  LPrimeGenCounterRec: Int32;
  LC0Val, LX, LC0x2, LTx2, LCVal, LA, LZ: TBigInteger;
begin
  LDLen := AD.GetDigestSize();
  LCLen := Math.Max(4, LDLen);

  if ALength < 33 then
  begin
    LPrimeGenCounter := 0;
    System.SetLength(LC0, LCLen);
    System.SetLength(LC1, LCLen);

    while True do
    begin
      Hash(AD, APrimeSeed, LC0, LCLen - LDLen);
      IncSeed(APrimeSeed, 1);

      Hash(AD, APrimeSeed, LC1, LCLen - LDLen);
      IncSeed(APrimeSeed, 1);

      LC := TPack.BE_To_UInt32(LC0, LCLen - 4) xor TPack.BE_To_UInt32(LC1, LCLen - 4);
      LC := LC and (UInt32($FFFFFFFF) shr (32 - ALength));
      LC := LC or (UInt32(1) shl (ALength - 1)) or UInt32(1);

      Inc(LPrimeGenCounter);

      if IsPrime32(LC) then
        Exit(TPrimes.TSTOutput.Create(TBigInteger.ValueOf(Int64(LC)), APrimeSeed, LPrimeGenCounter));

      if LPrimeGenCounter > (4 * ALength) then
        raise EInvalidOperationCryptoLibException.CreateRes(@SPrimesTooManyIterations);
    end;
  end;

  LRec := ImplSTRandomPrime(AD, (ALength + 3) div 2, APrimeSeed);

  LPrimeSeedRec := LRec.GetPrimeSeed();
  APrimeSeed := LPrimeSeedRec;
  LPrimeGenCounterRec := LRec.GetPrimeGenCounter();
  LC0Val := LRec.GetPrime();

  LOutlen := 8 * LDLen;
  LIterations := (ALength - 1) div LOutlen;
  LOldCounter := LPrimeGenCounterRec;

  LX := HashGen(AD, APrimeSeed, LIterations + 1);
  LX := LX.&Mod(FOne.ShiftLeft(ALength - 1)).SetBit(ALength - 1);

  LC0x2 := LC0Val.ShiftLeft(1);
  LTx2 := LX.Subtract(FOne).Divide(LC0x2).Add(FOne).ShiftLeft(1);
  LDt := 0;

  LCVal := LTx2.Multiply(LC0Val).Add(FOne);

  while True do
  begin
    if LCVal.BitLength > ALength then
    begin
      LTx2 := FOne.ShiftLeft(ALength - 1).Subtract(FOne).Divide(LC0x2).Add(FOne).ShiftLeft(1);
      LCVal := LTx2.Multiply(LC0Val).Add(FOne);
    end;

    Inc(LPrimeGenCounterRec);

    if ImplHasAnySmallFactors(LCVal) then
      IncSeed(APrimeSeed, LIterations + 1)
    else
    begin
      LA := HashGen(AD, APrimeSeed, LIterations + 1);
      LA := LA.&Mod(LCVal.Subtract(FThree)).Add(FTwo);

      LTx2 := LTx2.Add(TBigInteger.ValueOf(LDt));
      LDt := 0;

      LZ := LA.ModPow(LTx2, LCVal);

      if LCVal.Gcd(LZ.Subtract(FOne)).Equals(FOne) and LZ.ModPow(LC0Val, LCVal).Equals(FOne) then
        Exit(TPrimes.TSTOutput.Create(LCVal, APrimeSeed, LPrimeGenCounterRec));
    end;

    if LPrimeGenCounterRec >= ((4 * ALength) + LOldCounter) then
      raise EInvalidOperationCryptoLibException.CreateRes(@SPrimesTooManyIterations);

    LDt := LDt + 2;
    LCVal := LCVal.Add(LC0x2);
  end;
end;

class procedure TPrimes.Hash(const AD: IDigest; const AInput: TCryptoLibByteArray;
  const AOutput: TCryptoLibByteArray; AOutPos: Int32);
begin
  AD.BlockUpdate(AInput, 0, System.Length(AInput));
  AD.DoFinal(AOutput, AOutPos);
end;

class function TPrimes.HashGen(const AD: IDigest; var ASeed: TCryptoLibByteArray;
  ACount: Int32): TBigInteger;
var
  LDLen, LPos, LI: Int32;
  LBuf: TCryptoLibByteArray;
begin
  LDLen := AD.GetDigestSize();
  LPos := ACount * LDLen;
  System.SetLength(LBuf, LPos);

  for LI := 0 to ACount - 1 do
  begin
    LPos := LPos - LDLen;
    Hash(AD, ASeed, LBuf, LPos);
    IncSeed(ASeed, 1);
  end;

  Result := TBigInteger.Create(1, LBuf);
end;

class procedure TPrimes.IncSeed(var ASeed: TCryptoLibByteArray; AC: Int32);
var
  LPos: Int32;
begin
  LPos := System.Length(ASeed);
  while (AC > 0) do
  begin
    Dec(LPos);
    if LPos < 0 then
      Break;
    AC := AC + ASeed[LPos];
    ASeed[LPos] := Byte(AC);
    AC := TBitOperations.Asr32(AC, 8);
  end;
end;

class function TPrimes.IsPrime32(AX: UInt32): Boolean;
const
  SMALL_PRIMES_MASK = UInt32($208A28AC);  // 0b0010_0000_1000_1010_0010_1000_1010_1100
  WHEEL_MASK = UInt32($A08A2882);         // 0b1010_0000_1000_1010_0010_1000_1000_0010
  DS: array [0 .. 7] of UInt32 = (1, 7, 11, 13, 17, 19, 23, 29);
var
  LB: UInt32;
  LPos: Int32;
  LD: UInt32;
begin
  if AX < 32 then
    Exit(((UInt32(1) shl Int32(AX)) and SMALL_PRIMES_MASK) <> 0);

  if ((UInt32(1) shl Int32(AX mod 30)) and WHEEL_MASK) = 0 then
    Exit(False);

  LB := 0;
  LPos := 1;

  while True do
  begin
    while LPos < 8 do
    begin
      LD := LB + DS[LPos];
      if AX mod LD = 0 then
        Exit(False);
      Inc(LPos);
    end;

    LB := LB + 30;

    if (LB shr 16 <> 0) or (UInt64(LB) * LB >= AX) then
      Exit(True);

    LPos := 0;
  end;
end;

end.
