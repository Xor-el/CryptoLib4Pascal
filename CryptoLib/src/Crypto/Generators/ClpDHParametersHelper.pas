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

unit ClpDHParametersHelper;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpISecureRandom,
  ClpBigInteger,
  ClpWNafUtilities,
  ClpBitOperations,
  ClpCryptoLibTypes,
  ClpCryptoLibExceptions;

resourcestring
  SSizeTooSmall = 'size < 64';

type
  TDHParametersHelper = class sealed(TObject)

  strict private
  class var

    FTwo: TBigInteger;
    FTwelve: TBigInteger;
    FTwentyFour: TBigInteger;
    FPrimeProducts: TCryptoLibInt32Array;
    FPrimeLists: TCryptoLibMatrixInt32Array;
    FBigPrimeProducts: TCryptoLibGenericArray<TBigInteger>;
    class function ConstructBigPrimeProducts(const APrimeProducts
      : TCryptoLibInt32Array): TCryptoLibGenericArray<TBigInteger>; static;

    class function HasAnySmallFactorsSafe(const X: TBigInteger): Boolean; static;
    class constructor DHParametersHelper();

  public

    /// <summary>
    /// Finds a pair of prime BigInteger's {p, q: p = 2q + 1}.
    /// </summary>
    /// <remarks>
    /// See: Handbook of Applied Cryptography 4.86. If AForGenerator2 is true, the
    /// returned p will also have 2 as a quadratic residue (p === 7 mod 8).
    /// </remarks>
    class function GenerateSafePrimes(ABitLength, ACertainty: Int32;
      const ARandom: ISecureRandom; AForGenerator2: Boolean)
      : TCryptoLibGenericArray<TBigInteger>; static;
  end;

implementation

{ TDHParametersHelper }

class constructor TDHParametersHelper.DHParametersHelper;
begin
  FTwo := TBigInteger.Two;
  FTwelve := TBigInteger.ValueOf(12);
  FTwentyFour := TBigInteger.ValueOf(24);

  FPrimeLists := TBigInteger.primeLists;
  FPrimeProducts := TBigInteger.primeProducts;
  FBigPrimeProducts := ConstructBigPrimeProducts(FPrimeProducts);
end;

class function TDHParametersHelper.ConstructBigPrimeProducts(const APrimeProducts
  : TCryptoLibInt32Array): TCryptoLibGenericArray<TBigInteger>;
var
  LBpp: TCryptoLibGenericArray<TBigInteger>;
  LI: Int32;
begin
  System.SetLength(LBpp, System.Length(FPrimeProducts));

  for LI := 0 to System.Pred(System.Length(LBpp)) do
  begin
    LBpp[LI] := TBigInteger.ValueOf(APrimeProducts[LI]);
  end;

  Result := LBpp;
end;

class function TDHParametersHelper.HasAnySmallFactorsSafe(const X: TBigInteger): Boolean;
var
  LI, LJ, LR, LPrime: Int32;
  LPrimeList: TCryptoLibInt32Array;
begin
  for LI := 0 to System.Pred(System.Length(FPrimeLists)) do
  begin
    LR := X.Remainder(FBigPrimeProducts[LI]).Int32ValueExact;

    LPrimeList := FPrimeLists[LI];
    for LJ := 0 to System.Pred(System.Length(LPrimeList)) do
    begin
      LPrime := LPrimeList[LJ];
      if (LR mod LPrime) < 2 then
        Exit(True);
    end;
  end;

  Result := False;
end;

class function TDHParametersHelper.GenerateSafePrimes(ABitLength, ACertainty: Int32;
  const ARandom: ISecureRandom; AForGenerator2: Boolean)
  : TCryptoLibGenericArray<TBigInteger>;
var
  LP, LQ, LStep: TBigInteger;
  LLowBitsSet, LInc3, LMinWeight, LByteLength, LExtraBits, LCount, LPMod3: Int32;
  LBytes: TCryptoLibByteArray;
begin
  if ABitLength < 64 then
    raise EArgumentCryptoLibException.CreateRes(@SSizeTooSmall);

  LLowBitsSet := $03;
  LInc3 := 4;
  LStep := FTwelve;

  if AForGenerator2 then
  begin
    LLowBitsSet := $07;
    LInc3 := -8;
    LStep := FTwentyFour;
  end;

  LMinWeight := TBitOperations.Asr32(ABitLength, 2);
  LByteLength := (ABitLength + 7) div 8;
  LExtraBits := LByteLength * 8 - ABitLength;

  System.SetLength(LBytes, LByteLength);

  while True do
  begin
    ARandom.NextBytes(LBytes);

    LBytes[0] := (LBytes[0] and Byte($FF shr LExtraBits)) or Byte($80 shr LExtraBits);
    LBytes[System.Pred(LByteLength)] := LBytes[System.Pred(LByteLength)] or Byte(LLowBitsSet);

    LP := TBigInteger.Create(1, LBytes);

    LPMod3 := LP.&Mod(TBigInteger.Three).Int32ValueExact;
    if LPMod3 <> 2 then
      LP := LP.Add(TBigInteger.ValueOf((2 - Int64(LPMod3)) * LInc3));

    LCount := 0;
    while LCount < 256 do
    begin
      System.Inc(LCount);
      if LP.BitLength <> ABitLength then
        Break;

      if not HasAnySmallFactorsSafe(LP) then
      begin
        // NOTE: Pocklington criterion: Fermat test suffices to prove p prime given q is prime
        if FTwo.ModPow(LP, LP).Equals(FTwo) then
        begin
          LQ := LP.ShiftRight(1);
          if LQ.RabinMillerTest(ACertainty, ARandom, True) then
          begin
            if TWNafUtilities.GetNafWeight(LP) >= LMinWeight then
            begin
              Result := TCryptoLibGenericArray<TBigInteger>.Create(LP, LQ);
              Exit;
            end;
          end;
        end;

        Break;
      end;

      LP := LP.Add(LStep);
    end;
  end;
end;

{
// Select a high order element of the multiplicative group Zp*
// (see generateSafePrimes). Superseded by fixed generator g = 2 when
// GenerateSafePrimes is called with AForGenerator2 = true.
class function TDHParametersHelper.SelectGenerator(const AP, AQ: TBigInteger;
  const ARandom: ISecureRandom): TBigInteger;
var
  LG, LH, LPMinusTwo: TBigInteger;
begin
  LPMinusTwo := AP.Subtract(TBigInteger.Two);

  repeat
    LH := TBigIntegerUtilities.CreateRandomInRange(TBigInteger.Two, LPMinusTwo, ARandom);
    LG := LH.ModPow(TBigInteger.Two, AP);
  until not LG.Equals(TBigInteger.One);

  Result := LG;
end;
}

end.
