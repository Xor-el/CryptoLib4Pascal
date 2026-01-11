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

unit ClpRsaKeyPairGenerator;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpBigInteger,
  ClpBigIntegers,
  ClpIKeyGenerationParameters,
  ClpIRsaKeyGenerationParameters,
  ClpRsaKeyGenerationParameters,
  ClpIRsaKeyParameters,
  ClpRsaKeyParameters,
  ClpIRsaPrivateCrtKeyParameters,
  ClpRsaPrivateCrtKeyParameters,
  ClpIAsymmetricCipherKeyPair,
  ClpAsymmetricCipherKeyPair,
  ClpIAsymmetricCipherKeyPairGenerator,
  ClpIRsaKeyPairGenerator,
  ClpISecureRandom,
  ClpECCompUtilities,
  ClpCryptoLibTypes;

resourcestring
  SRsaKeyGenNotInit = 'RSA key pair generator not initialised';

type
  /// <summary>
  /// RSA key pair generator.
  /// </summary>
  TRsaKeyPairGenerator = class(TInterfacedObject,
    IAsymmetricCipherKeyPairGenerator, IRsaKeyPairGenerator)

  strict private
  class var
    FDefaultPublicExponent: TBigInteger;

  const
    DefaultTests = 100;

  class var
    FSpecialEValues: TCryptoLibInt32Array;
    FSpecialEHighest: Int32;
    FSpecialEBits: Int32;

  var
    FParam: IRsaKeyGenerationParameters;

    class constructor CreateRsaKeyPairGenerator;

    function ChooseRandomPrime(bitLength: Int32;
      const e: TBigInteger): TBigInteger;


    class function ArrayContains(const arr: TCryptoLibInt32Array; value: Int32): Boolean; static;

  public
    constructor Create();

    procedure Init(const parameters: IKeyGenerationParameters);
    function GenerateKeyPair(): IAsymmetricCipherKeyPair;

  end;

implementation

{ TRsaKeyPairGenerator }

class constructor TRsaKeyPairGenerator.CreateRsaKeyPairGenerator;
begin
  FSpecialEValues := TCryptoLibInt32Array.Create(3, 5, 17, 257, 65537);
  FSpecialEHighest := 65537;
  FSpecialEBits := TBigInteger.ValueOf(FSpecialEHighest).BitLength;
  FDefaultPublicExponent := TBigInteger.ValueOf($10001);  // 65537
end;

constructor TRsaKeyPairGenerator.Create;
begin
  inherited Create();
  FParam := nil;
end;

procedure TRsaKeyPairGenerator.Init(const parameters: IKeyGenerationParameters);
begin
  if Supports(parameters, IRsaKeyGenerationParameters) then
    FParam := parameters as IRsaKeyGenerationParameters
  else
    // Create default RSA parameters if not provided
    FParam := TRsaKeyGenerationParameters.Create(
      FDefaultPublicExponent, parameters.Random, parameters.Strength, DefaultTests);
end;

class function TRsaKeyPairGenerator.ArrayContains(const arr: TCryptoLibInt32Array;
  value: Int32): Boolean;
var
  i: Int32;
begin
  for i := 0 to System.Length(arr) - 1 do
  begin
    if arr[i] = value then
    begin
      Result := True;
      Exit;
    end;
  end;
  Result := False;
end;



function TRsaKeyPairGenerator.ChooseRandomPrime(bitLength: Int32;
  const e: TBigInteger): TBigInteger;
var
  p, pSub1: TBigInteger;
  eIsKnownOddPrime: Boolean;
begin
  eIsKnownOddPrime := (e.BitLength <= FSpecialEBits) and ArrayContains(FSpecialEValues, e.Int32Value);

  while True do
  begin
    // Generate random odd number
    p := TBigInteger.Create(bitLength, 1, FParam.Random);

    // Check p mod e != 1
    if p.&Mod(e).Equals(TBigInteger.One) then
      Continue;

    // Check primality
    if not p.IsProbablePrime(FParam.Certainty, True) then
      Continue;

    // If e is not a known small prime, check gcd(e, p-1) = 1
    if not eIsKnownOddPrime then
    begin
      pSub1 := p.Subtract(TBigInteger.One);
      if not e.Gcd(pSub1).Equals(TBigInteger.One) then
        Continue;
    end;

    Result := p;
    Exit;
  end;
end;

function TRsaKeyPairGenerator.GenerateKeyPair: IAsymmetricCipherKeyPair;
var
  strength, pBitLength, qBitLength, minDiffBits, minWeight: Int32;
  e, p, q, pSub1, qSub1: TBigInteger;
  n, d, dP, dQ, qInv: TBigInteger;
  diff, gcd, lcm, tmp: TBigInteger;
  pubKey: IRsaKeyParameters;
  privKey: IRsaPrivateCrtKeyParameters;
begin
  if FParam = nil then
  begin
    raise EInvalidOperationCryptoLibException.CreateRes(@SRsaKeyGenNotInit);
  end;

  while True do
  begin
    strength := FParam.Strength;
    e := FParam.PublicExponent;

    // p and q bit lengths
    pBitLength := (strength + 1) div 2;
    qBitLength := strength - pBitLength;
    minDiffBits := strength div 3;
    minWeight := strength shr 2;

    // Generate p
    p := ChooseRandomPrime(pBitLength, e);

    // Generate q and modulus
    while True do
    begin
      q := ChooseRandomPrime(qBitLength, e);

      // p and q should not be too close together (or equal!)
      diff := q.Subtract(p).Abs();
      if diff.BitLength < minDiffBits then
        Continue;

      // Calculate the modulus
      n := p.Multiply(q);

      if n.BitLength <> strength then
      begin
        // If we get here our primes aren't big enough, make the largest
        // of the two p and try again
        p := p.Max(q);
        Continue;
      end;

      // Require a minimum weight of the NAF representation, since low-weight
      // composites may be weak against a version of the number-field-sieve
      // for factoring.
      // See "The number field sieve for integers of low weight", Oliver Schirokauer.
      if TWNafUtilities.GetNafWeight(n) < minWeight then
      begin
        p := ChooseRandomPrime(pBitLength, e);
        Continue;
      end;

      Break;
    end;

    // Ensure p > q (for CRT)
    if p.CompareTo(q) < 0 then
    begin
      tmp := p;
      p := q;
      q := tmp;
    end;

    // Calculate phi components
    pSub1 := p.Subtract(TBigInteger.One);
    qSub1 := q.Subtract(TBigInteger.One);

    // Calculate LCM(p-1, q-1) = (p-1) * (q-1) / gcd(p-1, q-1)
    gcd := pSub1.Gcd(qSub1);
    lcm := pSub1.Divide(gcd).Multiply(qSub1);

    // Calculate the private exponent d = e^(-1) mod lcm
    d := e.ModInverse(lcm);

    // Check d has sufficient bit length
    if d.BitLength <= qBitLength then
      Continue;

    // Calculate CRT parameters
    dP := d.Remainder(pSub1);
    dQ := d.Remainder(qSub1);
    qInv := TBigIntegers.ModOddInverse(p, q);

    // Create key pair
    pubKey := TRsaKeyParameters.Create(False, n, e) as IRsaKeyParameters;
    privKey := TRsaPrivateCrtKeyParameters.Create(n, e, d, p, q, dP, dQ, qInv)
      as IRsaPrivateCrtKeyParameters;

    Result := TAsymmetricCipherKeyPair.Create(pubKey, privKey);
    Exit;
  end;
end;

end.
