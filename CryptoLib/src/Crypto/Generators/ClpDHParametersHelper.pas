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

unit ClpDHParametersHelper;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpISecureRandom,
  ClpBigInteger,
  ClpBigIntegerUtilities,
  ClpWNafUtilities,
  ClpBitOperations,
  ClpCryptoLibTypes;

type
  TDHParametersHelper = class sealed(TObject)

  strict private
  class var

    FSix: TBigInteger;
    FPrimeProducts: TCryptoLibInt32Array;
    FPrimeLists: TCryptoLibMatrixInt32Array;
    FBigPrimeProducts: TCryptoLibGenericArray<TBigInteger>;
    FIsBooted: Boolean;

    class function ConstructBigPrimeProducts(const APrimeProducts
      : TCryptoLibInt32Array): TCryptoLibGenericArray<TBigInteger>; static;

    class procedure Boot(); static;

    class constructor DHParametersHelper();

  public

    /// <summary>
    /// <para>
    /// Finds a pair of prime BigInteger's {p, q: p = 2q + 1}
    /// </para>
    /// <para>
    /// (see: Handbook of Applied Cryptography 4.86)
    /// </para>
    /// </summary>
    class function GenerateSafePrimes(ASize, ACertainty: Int32;
      const ARandom: ISecureRandom): TCryptoLibGenericArray<TBigInteger>; static;

{$IFNDEF _FIXINSIGHT_}
    /// <summary>
    /// <para>
    /// Select a high order element of the multiplicative group Zp*
    /// </para>
    /// <para>
    /// p and q must be s.t. p = 2*q + 1, where p and q are prime (see
    /// generateSafePrimes)
    /// </para>
    /// </summary>
    class function SelectGenerator(const AP, AQ: TBigInteger;
      const ARandom: ISecureRandom): TBigInteger; static;
{$ENDIF}
  end;

implementation

{ TDHParametersHelper }

class procedure TDHParametersHelper.Boot;
begin
  if not FIsBooted then
  begin
    FSix := TBigInteger.ValueOf(6);

    FPrimeLists := TBigInteger.primeLists;
    FPrimeProducts := TBigInteger.primeProducts;
    FBigPrimeProducts := ConstructBigPrimeProducts(FPrimeProducts);

    FIsBooted := True;
  end;
end;

class constructor TDHParametersHelper.DHParametersHelper;
begin
  TDHParametersHelper.Boot;
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

class function TDHParametersHelper.GenerateSafePrimes(ASize, ACertainty: Int32;
  const ARandom: ISecureRandom): TCryptoLibGenericArray<TBigInteger>;
var
  LP, LQ: TBigInteger;
  LQLength, LMinWeight, LI, LTest, LRem3, LDiff, LJ, LPrime, LQRem: Int32;
  LRetryFlag: Boolean;
  LPrimeList: TCryptoLibInt32Array;
begin
  LRetryFlag := False;
  LQLength := ASize - 1;
  LMinWeight := TBitOperations.Asr32(ASize, 2);

  if ASize <= 32 then
  begin
    while True do
    begin
      LQ := TBigInteger.Create(LQLength, 2, ARandom);

      LP := LQ.ShiftLeft(1).Add(TBigInteger.One);

      if not LP.IsProbablePrime(ACertainty, True) then
        Continue;

      if (ACertainty > 2) and (not LQ.IsProbablePrime(ACertainty, True)) then
        Continue;

      Break;
    end;
  end
  else
  begin
    while True do
    begin
      LQ := TBigInteger.Create(LQLength, 0, ARandom);

      LI := 0;
      while LI < System.Length(FPrimeLists) do
      begin
        LTest := LQ.Remainder(FBigPrimeProducts[LI]).Int32Value;

        if LI = 0 then
        begin
          LRem3 := LTest mod 3;
          if LRem3 <> 2 then
          begin
            LDiff := (2 * LRem3) + 2;
            LQ := LQ.Add(TBigInteger.ValueOf(LDiff));
            LTest := (LTest + LDiff) mod FPrimeProducts[LI];
          end;
        end;

        LPrimeList := FPrimeLists[LI];
        for LJ := 0 to System.Pred(System.Length(LPrimeList)) do
        begin
          LPrime := LPrimeList[LJ];
          LQRem := LTest mod LPrime;
          if (LQRem = 0) or (LQRem = TBitOperations.Asr32(LPrime, 1)) then
          begin
            LQ := LQ.Add(FSix);
            LRetryFlag := True;
            Break;
          end;
        end;

        if LRetryFlag then
        begin
          LI := 0;
          LRetryFlag := False;
        end
        else
          System.Inc(LI);
      end;

      if LQ.BitLength <> LQLength then
        Continue;

      if not LQ.RabinMillerTest(2, ARandom, True) then
        Continue;

      LP := LQ.ShiftLeft(1).Add(TBigInteger.One);

      if not LP.RabinMillerTest(ACertainty, ARandom, True) then
        Continue;

      if (ACertainty > 2) and (not LQ.RabinMillerTest(ACertainty - 2, ARandom, True)) then
        Continue;

      if TWNafUtilities.GetNafWeight(LP) < LMinWeight then
        Continue;

      Break;
    end;
  end;

  Result := TCryptoLibGenericArray<TBigInteger>.Create(LP, LQ);
end;

{$IFNDEF _FIXINSIGHT_}

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
{$ENDIF}

end.
