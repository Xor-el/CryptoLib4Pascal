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

unit ClpDHKeyGeneratorHelper;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpISecureRandom,
  ClpBitOperations,
  ClpBigInteger,
  ClpBigIntegerUtilities,
  ClpCryptoLibConfig,
  ClpWNafUtilities,
  ClpCryptoLibExceptions,
  ClpIDHParameters;

resourcestring
  SPrivateValueLengthTooShort =
    'when l value specified, it must not be less than %d for a %d bit p';

type
  TDHKeyGeneratorHelper = class sealed(TObject)
  public
    // the security strength s of p, in bits (SP 800-56A Appendix D steps from 4096 bits up, SP 800-57 below).
    class function SecurityStrengthFor(const AP: TBigInteger): Int32; static;
    // refuse a private value length l below twice the security strength of p, unless the config allows it.
    class procedure CheckPrivateValueLength(const AP: TBigInteger; AL: Int32); static;
    class function CalculatePrivate(const ADHParams: IDHParameters;
      const ARandom: ISecureRandom): TBigInteger; static;
    class function CalculatePublic(const ADHParams: IDHParameters;
      const AX: TBigInteger): TBigInteger; static;
    // generate x and y, redrawing while y falls outside [2, p - 2].
    class procedure CalculateKeyPair(const ADHParams: IDHParameters; const ARandom: ISecureRandom;
      out AX, AY: TBigInteger); static;
  end;

implementation

{ TDHKeyGeneratorHelper }

class function TDHKeyGeneratorHelper.SecurityStrengthFor(const AP: TBigInteger): Int32;
var
  LPBits: Int32;
begin
  LPBits := AP.BitLength;
  if LPBits >= 15360 then
    Result := 256
  else if LPBits >= 8192 then
    Result := 200 // SP 800-56A Appendix D
  else if LPBits >= 7680 then
    Result := 192
  else if LPBits >= 6144 then
    Result := 176 // SP 800-56A Appendix D
  else if LPBits >= 4096 then
    Result := 152 // SP 800-56A Appendix D
  else if LPBits >= 3072 then
    Result := 128
  else if LPBits >= 2048 then
    Result := 112
  else if LPBits >= 1024 then
    Result := 80
  else
    Result := 20;
end;

class procedure TDHKeyGeneratorHelper.CheckPrivateValueLength(const AP: TBigInteger; AL: Int32);
var
  LMinL: Int32;
begin
  if AL = 0 then
    Exit;

  LMinL := 2 * SecurityStrengthFor(AP);
  if (AL < LMinL) and (not TCryptoLibConfig.DH.AllowShortPrivateValue) then
    raise EArgumentCryptoLibException.CreateResFmt(@SPrivateValueLengthTooShort,
      [LMinL, AP.BitLength]);
end;

class procedure TDHKeyGeneratorHelper.CalculateKeyPair(const ADHParams: IDHParameters;
  const ARandom: ISecureRandom; out AX, AY: TBigInteger);
var
  LPSub2: TBigInteger;
begin
  // DHParameters already requires g in [2, p - 2], so a suitable x always exists
  LPSub2 := ADHParams.P.Subtract(TBigInteger.Two);
  while True do
  begin
    AX := CalculatePrivate(ADHParams, ARandom);
    AY := CalculatePublic(ADHParams, AX);
    if (AY.CompareTo(TBigInteger.Two) >= 0) and (AY.CompareTo(LPSub2) <= 0) then
      Exit;
  end;
end;

class function TDHKeyGeneratorHelper.CalculatePrivate(const ADHParams: IDHParameters;
  const ARandom: ISecureRandom): TBigInteger;
var
  LLimit, LMinWeight, LM: Int32;
  LX, LMin, LQ, LMax: TBigInteger;
begin
  Result := TBigInteger.GetDefault;
  LLimit := ADHParams.L;

  if LLimit <> 0 then
  begin
    LMinWeight := TBitOperations.Asr32(LLimit, 2);

    while True do
    begin
      LX := TBigInteger.Create(LLimit, ARandom).SetBit(LLimit - 1);
      if TWNafUtilities.GetNafWeight(LX) >= LMinWeight then
      begin
        Result := LX;
        Exit;
      end;
    end;
  end;

  LMin := TBigInteger.Two;
  LM := ADHParams.M;
  if LM <> 0 then
  begin
    LMin := TBigInteger.One.ShiftLeft(LM - 1);
  end;

  LQ := ADHParams.Q;
  if not LQ.IsInitialized then
  begin
    LQ := ADHParams.P;
  end;
  LMax := LQ.Subtract(TBigInteger.Two);

  LMinWeight := TBitOperations.Asr32(LMax.BitLength, 2);

  while True do
  begin
    LX := TBigIntegerUtilities.CreateRandomInRange(LMin, LMax, ARandom);
    if TWNafUtilities.GetNafWeight(LX) >= LMinWeight then
    begin
      Result := LX;
      Exit;
    end;
  end;
end;

class function TDHKeyGeneratorHelper.CalculatePublic(const ADHParams: IDHParameters;
  const AX: TBigInteger): TBigInteger;
begin
  Result := ADHParams.G.ModPow(AX, ADHParams.P);
end;

end.
