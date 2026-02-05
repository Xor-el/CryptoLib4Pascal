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

unit ClpRsaGenerators;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpArrayUtilities,
  ClpBigInteger,
  ClpBigIntegers,
  ClpBitOperations,
  ClpIKeyGenerationParameters,
  ClpIRsaParameters,
  ClpRsaParameters,
  ClpIAsymmetricCipherKeyPair,
  ClpAsymmetricCipherKeyPair,
  ClpIAsymmetricCipherKeyPairGenerator,
  ClpIRsaGenerators,
  ClpECCompUtilities,
  ClpICipherParameters,
  ClpParameterUtilities,
  ClpISecureRandom,
  ClpSecureRandom,
  ClpCryptoLibTypes;

resourcestring
  SRsaKeyGenNotInit = 'RSA key pair generator not initialised';
  SGeneratorNotInit = 'Generator not initialised';
  SPublicKeyRequired = 'Generator requires RSA public key';
  SRsaKeyParametersRequired = 'Parameters must support IRsaKeyParameters';

type
  TRsaKeyPairGenerator = class(TInterfacedObject,
    IAsymmetricCipherKeyPairGenerator, IRsaKeyPairGenerator)
  strict private
  class var
    FDefaultPublicExponent: TBigInteger;
    FSpecialEValues: TCryptoLibInt32Array;
    FSpecialEHighest: Int32;
    FSpecialEBits: Int32;
  var
    FParam: IRsaKeyGenerationParameters;
    class constructor CreateRsaKeyPairGenerator;
    function ChooseRandomPrime(ABitLength: Int32;
      const AE: TBigInteger): TBigInteger;
  public
    const DefaultTests = 100;
    constructor Create();
    procedure Init(const AParameters: IKeyGenerationParameters);
    function GenerateKeyPair(): IAsymmetricCipherKeyPair;
  end;

  TRsaBlindingFactorGenerator = class(TInterfacedObject, IRsaBlindingFactorGenerator)
  strict private
    FKey: IRsaKeyParameters;
    FRandom: ISecureRandom;
  public
    constructor Create();
    procedure Init(const AParam: ICipherParameters);
    function GenerateBlindingFactor: TBigInteger;
  end;

implementation

{ TRsaKeyPairGenerator }

class constructor TRsaKeyPairGenerator.CreateRsaKeyPairGenerator;
begin
  FSpecialEValues := TCryptoLibInt32Array.Create(3, 5, 17, 257, 65537);
  FSpecialEHighest := 65537;
  FSpecialEBits := TBigInteger.ValueOf(FSpecialEHighest).BitLength;
  FDefaultPublicExponent := TBigInteger.ValueOf($10001);
end;

constructor TRsaKeyPairGenerator.Create;
begin
  inherited Create();
  FParam := nil;
end;

procedure TRsaKeyPairGenerator.Init(const AParameters: IKeyGenerationParameters);
begin
  if not Supports(AParameters, IRsaKeyGenerationParameters, FParam) then
    FParam := TRsaKeyGenerationParameters.Create(
      FDefaultPublicExponent, AParameters.Random, AParameters.Strength, DefaultTests);
end;

function TRsaKeyPairGenerator.ChooseRandomPrime(ABitLength: Int32;
  const AE: TBigInteger): TBigInteger;
var
  LP, LPSub1: TBigInteger;
  LEIsKnownOddPrime: Boolean;
begin
  LEIsKnownOddPrime := (AE.BitLength <= FSpecialEBits) and
    TArrayUtilities.Contains<Int32>(FSpecialEValues, AE.Int32Value);
  while True do
  begin
    LP := TBigInteger.Create(ABitLength, 1, FParam.Random);
    if LP.&Mod(AE).Equals(TBigInteger.One) then
      Continue;
    if not LP.IsProbablePrime(FParam.Certainty, True) then
      Continue;
    if not LEIsKnownOddPrime then
    begin
      LPSub1 := LP.Subtract(TBigInteger.One);
      if not AE.Gcd(LPSub1).Equals(TBigInteger.One) then
        Continue;
    end;
    Result := LP;
    Exit;
  end;
end;

function TRsaKeyPairGenerator.GenerateKeyPair: IAsymmetricCipherKeyPair;
var
  LStrength, LPBitLength, LQBitLength, LMinDiffBits, LMinWeight: Int32;
  LE, LP, LQ, LPSub1, LQSub1: TBigInteger;
  LN, LD, LDP, LDQ, LQInv: TBigInteger;
  LDiff, LGcd, LLcm, LTmp: TBigInteger;
  LPubKey: IRsaKeyParameters;
  LPrivKey: IRsaPrivateCrtKeyParameters;
begin
  if FParam = nil then
    raise EInvalidOperationCryptoLibException.CreateRes(@SRsaKeyGenNotInit);
  while True do
  begin
    LStrength := FParam.Strength;
    LE := FParam.PublicExponent;
    LPBitLength := (LStrength + 1) div 2;
    LQBitLength := LStrength - LPBitLength;
    LMinDiffBits := LStrength div 3;
    LMinWeight := TBitOperations.Asr32(LStrength, 2);
    LP := ChooseRandomPrime(LPBitLength, LE);
    while True do
    begin
      LQ := ChooseRandomPrime(LQBitLength, LE);
      LDiff := LQ.Subtract(LP).Abs();
      if LDiff.BitLength < LMinDiffBits then
        Continue;
      LN := LP.Multiply(LQ);
      if LN.BitLength <> LStrength then
      begin
        LP := LP.Max(LQ);
        Continue;
      end;
      if TWNafUtilities.GetNafWeight(LN) < LMinWeight then
      begin
        LP := ChooseRandomPrime(LPBitLength, LE);
        Continue;
      end;
      Break;
    end;
    if LP.CompareTo(LQ) < 0 then
    begin
      LTmp := LP;
      LP := LQ;
      LQ := LTmp;
    end;
    LPSub1 := LP.Subtract(TBigInteger.One);
    LQSub1 := LQ.Subtract(TBigInteger.One);
    LGcd := LPSub1.Gcd(LQSub1);
    LLcm := LPSub1.Divide(LGcd).Multiply(LQSub1);
    LD := LE.ModInverse(LLcm);
    if LD.BitLength <= LQBitLength then
      Continue;
    LDP := LD.Remainder(LPSub1);
    LDQ := LD.Remainder(LQSub1);
    LQInv := TBigIntegers.ModOddInverse(LP, LQ);
    LPubKey := TRsaKeyParameters.Create(False, LN, LE) as IRsaKeyParameters;
    LPrivKey := TRsaPrivateCrtKeyParameters.Create(LN, LE, LD, LP, LQ, LDP, LDQ, LQInv)
      as IRsaPrivateCrtKeyParameters;
    Result := TAsymmetricCipherKeyPair.Create(LPubKey, LPrivKey);
    Exit;
  end;
end;

{ TRsaBlindingFactorGenerator }

constructor TRsaBlindingFactorGenerator.Create;
begin
  inherited Create();
  FKey := nil;
  FRandom := nil;
end;

procedure TRsaBlindingFactorGenerator.Init(const AParam: ICipherParameters);
var
  LParameters: ICipherParameters;
  LProvidedRandom: ISecureRandom;
begin
  LParameters := TParameterUtilities.GetRandom(AParam, LProvidedRandom);
  if not Supports(LParameters, IRsaKeyParameters, FKey) then
    raise EArgumentCryptoLibException.CreateRes(@SRsaKeyParametersRequired);
  if LProvidedRandom <> nil then
    FRandom := LProvidedRandom
  else
    FRandom := TSecureRandom.Create();
  if FKey.IsPrivate then
    raise EArgumentCryptoLibException.CreateRes(@SPublicKeyRequired);
end;

function TRsaBlindingFactorGenerator.GenerateBlindingFactor: TBigInteger;
var
  LM: TBigInteger;
  LLen: Int32;
  LFactor: TBigInteger;
begin
  if FKey = nil then
    raise EInvalidOperationCryptoLibException.CreateRes(@SGeneratorNotInit);
  LM := FKey.Modulus;
  LLen := LM.BitLength - 1;
  repeat
    LFactor := TBigInteger.Create(LLen, FRandom);
  until (LFactor.CompareTo(TBigInteger.Two) >= 0) and
    TBigIntegers.ModOddIsCoprimeVar(LM, LFactor);
  Result := LFactor;
end;

end.
