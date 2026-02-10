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

unit ClpDsaGenerators;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  Math,
  SysUtils,
  HlpSHA1,
  ClpIDigest,
  ClpISecureRandom,
  ClpDsaParameters,
  ClpIDsaParameters,
  ClpIDsaGenerators,
  ClpEncoders,
  ClpDigestUtilities,
  ClpBigInteger,
  ClpBigIntegers,
  ClpBitOperations,
  ClpWNafUtilities,
  ClpAsymmetricCipherKeyPair,
  ClpIAsymmetricCipherKeyPair,
  ClpIKeyGenerationParameters,
  ClpIAsymmetricCipherKeyPairGenerator,
  ClpCryptoLibTypes;

resourcestring
  SParametersCannotBeNil = '"parameters" Cannot Be Nil';
  SInvalidLValue =
    'L Values Must be Between 1024 and 3072 and a Multiple of 1024';
  SInvalidNValueForSpecifiedL = 'N Must be " %d " for L = " %d "';
  SInvalidNValueForSpecifiedL_Two = 'N Must be " %d " or " %d " for L = " %d "';
  SDigestOutputSizeTooSmallForN =
    'Digest Output Size Too Small for Value of N Which is " %d "';
  SUnsupportedDigest =
    'Can Only Use SHA-1 For Generating FIPS 186-2 Parameters';
  SInvalidDsaKeyStrength =
    'Size Must Be From %d - %d and a multiple of %d, "%d"';

type
  TDsaKeyPairGenerator = class sealed(TInterfacedObject,
    IAsymmetricCipherKeyPairGenerator, IDsaKeyPairGenerator)
  strict private
    FParam: IDsaKeyGenerationParameters;
    class function GeneratePrivateKey(const AQ: TBigInteger;
      const ARandom: ISecureRandom): TBigInteger; static;
    class function CalculatePublicKey(const AP, AG, AX: TBigInteger): TBigInteger; static; inline;
  public
    procedure Init(const AParameters: IKeyGenerationParameters);
    function GenerateKeyPair(): IAsymmetricCipherKeyPair;
  end;

  TDsaParametersGenerator = class(TInterfacedObject, IDsaParametersGenerator)

  strict private
    FDigest: IDigest;
    FL, FN, FCertainty, FIterations, FUsageIndex: Int32;
    FRandom: ISecureRandom;
    FUse186_3: Boolean;

    function IsProbablePrime(const AX: TBigInteger): Boolean; inline;

    function GenerateParameters_FIPS186_2(): IDsaParameters;

    /// <summary>
    /// generate suitable parameters for DSA, in line with <i>FIPS 186-3 A.1
    /// Generation of the FFC Primes p and q</i>
    /// </summary>
    function GenerateParameters_FIPS186_3(): IDsaParameters;

    class function IsValidDsaStrength(AStrength: Int32): Boolean; static; inline;

    class function GetDefaultN(AL: Int32): Int32; static; inline;
    class function GetMinimumIterations(AL: Int32): Int32; static; inline;
    class procedure Hash(const ADigest: IDigest;
      const AInput, AOutput: TCryptoLibByteArray; AOutputPos: Int32);
      static; inline;

    class procedure Inc(const ABuf: TCryptoLibByteArray); static; inline;

    class function CalculateGenerator_FIPS186_2(const AP, AQ: TBigInteger;
      const ARandom: ISecureRandom): TBigInteger; static; inline;

    class function CalculateGenerator_FIPS186_3_Unverifiable(const AP,
      AQ: TBigInteger; const ARandom: ISecureRandom): TBigInteger; static; inline;

    class function CalculateGenerator_FIPS186_3_Verifiable(const ADigest: IDigest;
      const AP, AQ: TBigInteger; const ASeed: TCryptoLibByteArray; AIndex: Int32)
      : TBigInteger; static; inline;

  public
    constructor Create(); overload;
    constructor Create(const ADigest: IDigest); overload;

    /// <summary>
    /// initialise the key generator.
    /// </summary>
    /// <param name="size">
    /// size of the key (range 2^512 -&amp;gt; 2^1024 - 64 bit increments)
    /// </param>
    /// <param name="certainty">
    /// measure of robustness of prime (for FIPS 186-2 compliance this should
    /// be at least 80).
    /// </param>
    /// <param name="random">
    /// random byte source.
    /// </param>
    procedure Init(ASize, ACertainty: Int32;
      const ARandom: ISecureRandom); overload;

    /// <summary>
    /// initialise the key generator.
    /// </summary>
    /// <param name="size">
    /// size of the key (range 2^512 -&amp;gt; 2^1024 - 64 bit increments)
    /// </param>
    /// <param name="certainty">
    /// measure of robustness of prime (for FIPS 186-2 compliance this should
    /// be at least 80).
    /// </param>
    /// <param name="iterations">
    /// iterations
    /// </param>
    /// <param name="random">
    /// random byte source.
    /// </param>
    procedure Init(ASize, ACertainty, AIterations: Int32;
      const ARandom: ISecureRandom); overload;

    /// <summary>
    /// <para>
    /// Initialise the key generator for DSA 2.
    /// </para>
    /// <para>
    /// Use this init method if you need to generate parameters for DSA 2
    /// keys.
    /// </para>
    /// </summary>
    /// <param name="params">
    /// DSA 2 key generation parameters.
    /// </param>
    procedure Init(const AParams: IDsaParameterGenerationParameters); overload;

    /// <summary>
    /// <para>
    /// which generates the p and g values from the given parameters,
    /// returning the DSAParameters object.
    /// </para>
    /// <para>
    /// Note: can take a while...
    /// </para>
    /// </summary>
    /// <returns>
    /// a generated DSA parameters object.
    /// </returns>
    function GenerateParameters(): IDsaParameters; virtual;

  end;

implementation

{ TDsaKeyPairGenerator }

class function TDsaKeyPairGenerator.CalculatePublicKey(const AP, AG, AX: TBigInteger): TBigInteger;
begin
  Result := AG.ModPow(AX, AP);
end;

function TDsaKeyPairGenerator.GenerateKeyPair: IAsymmetricCipherKeyPair;
var
  LDsaParams: IDsaParameters;
  LX, LY: TBigInteger;
begin
  LDsaParams := FParam.Parameters;
  LX := GeneratePrivateKey(LDsaParams.Q, FParam.Random);
  LY := CalculatePublicKey(LDsaParams.P, LDsaParams.G, LX);
  Result := TAsymmetricCipherKeyPair.Create(TDsaPublicKeyParameters.Create(LY,
    LDsaParams) as IDsaPublicKeyParameters, TDsaPrivateKeyParameters.Create(LX,
    LDsaParams) as IDsaPrivateKeyParameters);
end;

class function TDsaKeyPairGenerator.GeneratePrivateKey(const AQ: TBigInteger;
  const ARandom: ISecureRandom): TBigInteger;
var
  LMinWeight: Int32;
  LX, LOne: TBigInteger;
begin
  LOne := TBigInteger.One;
  Result := TBigInteger.GetDefault;
  LMinWeight := TBitOperations.Asr32(AQ.BitLength, 2);
  while True do
  begin
    LX := TBigIntegers.CreateRandomInRange(LOne, AQ.Subtract(LOne), ARandom);
    if TWNafUtilities.GetNafWeight(LX) >= LMinWeight then
    begin
      Result := LX;
      Exit;
    end;
  end;
end;

procedure TDsaKeyPairGenerator.Init(const AParameters: IKeyGenerationParameters);
begin
  if AParameters = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SParametersCannotBeNil);
  if not Supports(AParameters, IDsaKeyGenerationParameters, FParam) then
    raise EArgumentNilCryptoLibException.CreateRes(@SParametersCannotBeNil);
end;

{ TDsaParametersGenerator }

function TDsaParametersGenerator.IsProbablePrime(const AX: TBigInteger): Boolean;
begin
  Result := AX.IsProbablePrime(FCertainty);
end;

class function TDsaParametersGenerator.IsValidDsaStrength
  (AStrength: Int32): Boolean;
begin
  // result := (AStrength >= 512) and (AStrength <= 1024) and ((AStrength mod 64) = 0);
  Result := (AStrength >= 512) and (AStrength <= 1024) and
    ((AStrength and 63) = 0);
end;

class function TDsaParametersGenerator.GetDefaultN(AL: Int32): Int32;
begin
  if AL > 1024 then
  begin
    Result := 256
  end
  else
  begin
    Result := 160;
  end;
end;

class function TDsaParametersGenerator.GetMinimumIterations(AL: Int32): Int32;
begin
  // Values based on FIPS 186-4 C.3 Table C.1
  if AL <= 1024 then
  begin
    Result := 40;
  end
  else
  begin
    Result := (48 + 8 * ((AL - 1) div 1024))
  end;
end;

class procedure TDsaParametersGenerator.Hash(const ADigest: IDigest;
  const AInput, AOutput: TCryptoLibByteArray; AOutputPos: Int32);
begin
  ADigest.BlockUpdate(AInput, 0, System.Length(AInput));
  ADigest.DoFinal(AOutput, AOutputPos);
end;

class procedure TDsaParametersGenerator.Inc(const ABuf: TCryptoLibByteArray);
var
  LI: Int32;
  LB: Byte;
begin
  LI := System.Length(ABuf) - 1;
  while LI >= 0 do
  begin
    LB := Byte((ABuf[LI] + 1) and $FF);
    ABuf[LI] := LB;

    if (LB <> 0) then
    begin
      Break;
    end;
    System.Dec(LI);
  end;
end;

constructor TDsaParametersGenerator.Create;
begin
  Create(TDigestUtilities.GetDigest('SHA-1'));
end;

class function TDsaParametersGenerator.CalculateGenerator_FIPS186_2(const AP,
  AQ: TBigInteger; const ARandom: ISecureRandom): TBigInteger;
var
  LE, LPSub2, LH, LG: TBigInteger;
begin
  Result := TBigInteger.GetDefault;
  LE := AP.Subtract(TBigInteger.One).Divide(AQ);
  LPSub2 := AP.Subtract(TBigInteger.Two);

  while True do
  begin
    LH := TBigIntegers.CreateRandomInRange(TBigInteger.Two, LPSub2, ARandom);
    LG := LH.ModPow(LE, AP);
    if (LG.BitLength > 1) then
    begin
      Result := LG;
      Exit;
    end;
  end;
end;

class function TDsaParametersGenerator.CalculateGenerator_FIPS186_3_Unverifiable
  (const AP, AQ: TBigInteger; const ARandom: ISecureRandom): TBigInteger;
begin
  Result := CalculateGenerator_FIPS186_2(AP, AQ, ARandom);
end;

class function TDsaParametersGenerator.CalculateGenerator_FIPS186_3_Verifiable
  (const ADigest: IDigest; const AP, AQ: TBigInteger; const ASeed: TCryptoLibByteArray;
  AIndex: Int32): TBigInteger;
var
  LE, LW, LG: TBigInteger;
  LGgen, LU, LSmallW: TCryptoLibByteArray;
  LCount: Int32;
begin
  // A.2.3 Verifiable Canonical Generation of the Generator g
  LE := AP.Subtract(TBigInteger.One).Divide(AQ);
  LGgen := THexEncoder.Decode('6767656E');

  // 7. U = domain_parameter_seed || "ggen" || index || count.
  System.SetLength(LU, System.Length(ASeed) + System.Length(LGgen) + 1 + 2);
  System.Move(ASeed[0], LU[0], System.Length(ASeed) * System.SizeOf(Byte));
  System.Move(LGgen[0], LU[System.Length(ASeed)], System.Length(LGgen) *
    System.SizeOf(Byte));
  LU[System.Length(LU) - 3] := Byte(AIndex);

  System.SetLength(LSmallW, ADigest.GetDigestSize());

  LCount := 1;
  while LCount < (1 shl 16) do
  begin
    Inc(LU);
    Hash(ADigest, LU, LSmallW, 0);
    LW := TBigInteger.Create(1, LSmallW);
    LG := LW.ModPow(LE, AP);
    if (LG.CompareTo(TBigInteger.Two) >= 0) then
    begin
      Result := LG;
      Exit;
    end;
    System.Inc(LCount);
  end;

  Result := TBigInteger.GetDefault;
end;

function TDsaParametersGenerator.GenerateParameters_FIPS186_2: IDsaParameters;
var
  LSeed, LPart1, LPart2, LU, LW, LOffset: TCryptoLibByteArray;
  LN, LI, LCounter, LK, LRemaining: Int32;
  LQ, LX, LC, LP, LG: TBigInteger;
begin
  Result := nil;
  System.SetLength(LSeed, 20);
  System.SetLength(LPart1, 20);
  System.SetLength(LPart2, 20);
  System.SetLength(LU, 20);
  LN := (FL - 1) div 160;
  System.SetLength(LW, FL div 8);

  if (not {$IFDEF FPC} (Supports(FDigest.GetUnderlyingIHash, TSHA1))
{$ELSE} (FDigest.GetUnderlyingIHash is TSHA1) {$ENDIF FPC}) then
  begin
    raise EInvalidParameterCryptoLibException.CreateRes(@SUnsupportedDigest);
  end;

  while True do
  begin
    FRandom.NextBytes(LSeed);

    Hash(FDigest, LSeed, LPart1, 0);
    System.Move(LSeed[0], LPart2[0], System.Length(LSeed) * System.SizeOf(Byte));
    Inc(LPart2);
    Hash(FDigest, LPart2, LPart2, 0);

    LI := 0;
    while LI <> System.Length(LU) do
    begin
      LU[LI] := Byte(LPart1[LI] xor LPart2[LI]);
      System.Inc(LI);
    end;

    LU[0] := LU[0] or Byte($80);
    LU[19] := LU[19] or Byte($01);

    LQ := TBigInteger.Create(1, LU);

    if (not IsProbablePrime(LQ)) then
    begin
      continue;
    end;

    LOffset := System.Copy(LSeed);
    Inc(LOffset);
    LCounter := 0;
    while LCounter < 4096 do
    begin

      LK := 1;
      while LK <= LN do
      begin
        Inc(LOffset);
        Hash(FDigest, LOffset, LW, System.Length(LW) - (LK * System.Length(LPart1)));
        System.Inc(LK);
      end;

      LRemaining := System.Length(LW) - (LN * System.Length(LPart1));
      Inc(LOffset);
      Hash(FDigest, LOffset, LPart1, 0);
      System.Move(LPart1[System.Length(LPart1) - LRemaining], LW[0], LRemaining);

      LW[0] := LW[0] or Byte($80);

      LX := TBigInteger.Create(1, LW);

      LC := LX.&Mod(LQ.ShiftLeft(1));

      LP := LX.Subtract(LC.Subtract(TBigInteger.One));

      if (LP.BitLength <> FL) then
      begin
        System.Inc(LCounter);
        continue;
      end;

      if (IsProbablePrime(LP)) then
      begin
        LG := CalculateGenerator_FIPS186_2(LP, LQ, FRandom);

        Result := TDsaParameters.Create(LP, LQ, LG,
          TDsaValidationParameters.Create(LSeed, LCounter)
          as IDsaValidationParameters);
        Exit;
      end;

      System.Inc(LCounter);
    end;
  end;
end;

function TDsaParametersGenerator.GenerateParameters_FIPS186_3: IDsaParameters;
var
  LDigest: IDigest;
  LOutLen, LSeedLen, LN, LCounterLimit, LCounter, LJ, LRemaining: Int32;
  LSeed, LW, LOutput, LOffset: TCryptoLibByteArray;
  LU, LQ, LX, LC, LP, LG: TBigInteger;
begin
  Result := nil;
  // A.1.1.2 Generation of the Probable Primes p and q Using an Approved Hash Function
  // TODO FIXME This should be configurable (digest size in bits must be >= N)
  LDigest := FDigest;
  LOutLen := LDigest.GetDigestSize() * 8;

  // 1. Check that the (L, N) pair is in the list of acceptable (L, N pairs) (see Section 4.2). If
  // the pair is not in the list, then return INVALID.
  // Note: checked at initialisation

  // 2. If (seedlen < N), then return INVALID.
  // TODO FIXME This should be configurable (must be >= N)
  LSeedLen := FN;
  System.SetLength(LSeed, LSeedLen div 8);

  // 3. n = ceiling(L / outlen) - 1.
  LN := (FL - 1) div LOutLen;

  // 4. b = L - 1 - (n * outlen).
  // b := (FL - 1) mod outlen;

  System.SetLength(LW, FL div 8);

  System.SetLength(LOutput, LDigest.GetDigestSize());

  while True do
  begin
    // 5. Get an arbitrary sequence of seedlen bits as the domain_parameter_seed.
    FRandom.NextBytes(LSeed);

    // 6. U = Hash (domain_parameter_seed) mod 2^(N–1).
    Hash(LDigest, LSeed, LOutput, 0);

    LU := TBigInteger.Create(1, LOutput).&Mod(TBigInteger.One.ShiftLeft(FN - 1));

    // 7. q = 2^(N–1) + U + 1 – ( U mod 2).
    LQ := LU.SetBit(0).SetBit(FN - 1);

    // 8. Test whether or not q is prime as specified in Appendix C.3.
    if (not IsProbablePrime(LQ)) then
    begin
      // 9. If q is not a prime, then go to step 5.
      continue;
    end;

    // 10. offset = 1.
    // Note: 'offset' value managed incrementally
    LOffset := System.Copy(LSeed);

    // 11. For counter = 0 to (4L – 1) do
    LCounterLimit := 4 * FL;
    LCounter := 0;
    while LCounter < LCounterLimit do
    begin
      // 11.1 For j = 0 to n do
      // Vj = Hash ((domain_parameter_seed + offset + j) mod 2^seedlen).
      // 11.2 W = V0 + (V1 * 2^outlen) + ... + (V^(n–1) * 2^((n–1) * outlen)) + ((Vn mod 2^b) * 2^(n * outlen)).

      LJ := 1;
      while LJ <= LN do
      begin
        Inc(LOffset);
        Hash(LDigest, LOffset, LW, System.Length(LW) - (LJ * System.Length(LOutput)));
        System.Inc(LJ);
      end;

      LRemaining := System.Length(LW) - (LN * System.Length(LOutput));
      Inc(LOffset);
      Hash(LDigest, LOffset, LOutput, 0);
      System.Move(LOutput[System.Length(LOutput) - LRemaining], LW[0], LRemaining);

      // 11.3 X = W + 2^(L–1). Comment: 0 ≤ W < 2^(L–1); hence, 2^(L–1) ≤ X < 2^L.
      LW[0] := LW[0] or Byte($80);

      LX := TBigInteger.Create(1, LW);

      // 11.4 c = X mod 2q.
      LC := LX.&Mod(LQ.ShiftLeft(1));

      // 11.5 p = X - (c - 1). Comment: p ≡ 1 (mod 2q).
      LP := LX.Subtract(LC.Subtract(TBigInteger.One));

      // 11.6 If (p < 2^(L-1)), then go to step 11.9
      if (LP.BitLength <> FL) then
      begin
        System.Inc(LCounter);
        continue;
      end;

      // 11.7 Test whether or not p is prime as specified in Appendix C.3.
      if (IsProbablePrime(LP)) then
      begin
        // 11.8 If p is determined to be prime, then return VALID and the values of p, q and
        // (optionally) the values of domain_parameter_seed and counter.
        if (FUsageIndex >= 0) then
        begin
          LG := CalculateGenerator_FIPS186_3_Verifiable(LDigest, LP, LQ, LSeed,
            FUsageIndex);
          if (LG.IsInitialized) then
          begin
            Result := TDsaParameters.Create(LP, LQ, LG,
              TDsaValidationParameters.Create(LSeed, LCounter, FUsageIndex)
              as IDsaValidationParameters);
            Exit;
          end;
        end;

        LG := CalculateGenerator_FIPS186_3_Unverifiable(LP, LQ, FRandom);

        Result := TDsaParameters.Create(LP, LQ, LG,
          TDsaValidationParameters.Create(LSeed, LCounter)
          as IDsaValidationParameters);
        Exit;
      end;

      // 11.9 offset = offset + n + 1.      Comment: Increment offset; then, as part of
      // the loop in step 11, increment counter; if
      // counter < 4L, repeat steps 11.1 through 11.8.
      // Note: 'offset' value already incremented in inner loop
      System.Inc(LCounter);
    end;
    // 12. Go to step 5.
  end;

end;

function TDsaParametersGenerator.GenerateParameters: IDsaParameters;
begin
  if FUse186_3 then
  begin
    Result := GenerateParameters_FIPS186_3()
  end
  else
  begin
    Result := GenerateParameters_FIPS186_2();
  end;
end;

constructor TDsaParametersGenerator.Create(const ADigest: IDigest);
begin
  inherited Create();
  FDigest := ADigest;
end;

procedure TDsaParametersGenerator.Init(ASize, ACertainty: Int32;
  const ARandom: ISecureRandom);
begin
  Init(ASize, ACertainty, Max(GetMinimumIterations(ASize),
    (ACertainty + 1) div 2), ARandom);
end;

procedure TDsaParametersGenerator.Init(ASize, ACertainty, AIterations: Int32;
  const ARandom: ISecureRandom);
begin
  if (not IsValidDsaStrength(ASize)) then
  begin
    raise EArgumentCryptoLibException.CreateResFmt(@SInvalidDsaKeyStrength,
      [512, 1024, 64, ASize]);
  end;
  FL := ASize;
  FN := GetDefaultN(ASize);
  FCertainty := ACertainty;
  FIterations := AIterations;
  FRandom := ARandom;
  FUse186_3 := False;
  FUsageIndex := -1;
end;

procedure TDsaParametersGenerator.Init(const AParams
  : IDsaParameterGenerationParameters);
var
  LL, LN: Int32;
begin
  LL := AParams.L;
  LN := AParams.N;

  // if (((LL < 1024) or (LL > 3072)) or ((LL mod 1024) <> 0))
  if (((LL < 1024) or (LL > 3072)) or ((LL and 1023) <> 0)) then
  begin
    raise EInvalidParameterCryptoLibException.CreateRes(@SInvalidLValue);
  end
  else if ((LL = 1024) and (LN <> 160)) then
  begin
    raise EInvalidParameterCryptoLibException.CreateResFmt
      (@SInvalidNValueForSpecifiedL, [160, 1024]);
  end
  else if ((LL = 2048) and ((LN <> 224) and (LN <> 256))) then
  begin
    raise EInvalidParameterCryptoLibException.CreateResFmt
      (@SInvalidNValueForSpecifiedL_Two, [224, 256, 2048]);
  end
  else if ((LL = 3072) and (LN <> 256)) then
  begin
    raise EInvalidParameterCryptoLibException.CreateResFmt
      (@SInvalidNValueForSpecifiedL, [256, 3072]);
  end;

  if ((FDigest.GetDigestSize * 8) < LN) then
  begin
    raise EInvalidParameterCryptoLibException.CreateResFmt
      (@SDigestOutputSizeTooSmallForN, [LN]);
  end;

  FL := LL;
  FN := LN;
  FCertainty := AParams.Certainty;
  FIterations := Max(GetMinimumIterations(LL), (FCertainty + 1) div 2);
  FRandom := AParams.Random;
  FUse186_3 := True;
  FUsageIndex := AParams.UsageIndex;
end;

end.
