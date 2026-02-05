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

unit ClpDHKeyGeneratorHelper;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpISecureRandom,
  ClpBitOperations,
  ClpBigInteger,
  ClpBigIntegers,
  ClpECCompUtilities,
  ClpIDHParameters;

type
  TDHKeyGeneratorHelper = class sealed(TObject)
  public
    class function CalculatePrivate(const ADHParams: IDHParameters;
      const ARandom: ISecureRandom): TBigInteger; static;
    class function CalculatePublic(const ADHParams: IDHParameters;
      const AX: TBigInteger): TBigInteger; static;
  end;

implementation

{ TDHKeyGeneratorHelper }

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
    LX := TBigIntegers.CreateRandomInRange(LMin, LMax, ARandom);
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
