{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                           Author - Ugochukwu Mmaduekwe                          * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }

{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }

{ *                              Acknowledgements:                                  * }
{ *                                                                                 * }
{ *      Thanks to Sphere 10 Software (http://www.sphere10.com/) for sponsoring     * }
{ *                           development of this library                           * }

{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit ClpBasicGcmExponentiator;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpBitOperations,
  ClpIGcmExponentiator,
  ClpGcmUtilities,
  ClpCryptoLibTypes;

type
  TBasicGcmExponentiator = class(TInterfacedObject, IGcmExponentiator)
  strict private
    FX: TFieldElement;
  public
    procedure Init(const AX: TCryptoLibByteArray);
    procedure ExponentiateX(APow: Int64; const AOutput: TCryptoLibByteArray);
  end;

implementation

{ TBasicGcmExponentiator }

procedure TBasicGcmExponentiator.Init(const AX: TCryptoLibByteArray);
begin
  TGcmUtilities.AsFieldElement(AX, FX);
end;

procedure TBasicGcmExponentiator.ExponentiateX(APow: Int64; const AOutput: TCryptoLibByteArray);
var
  LY, LPowX: TFieldElement;
begin
  TGcmUtilities.One(LY);

  if APow > 0 then
  begin
    LPowX := FX;
    repeat
      if (APow and Int64(1)) <> 0 then
      begin
        TGcmUtilities.Multiply(LY, LPowX);
      end;
      TGcmUtilities.Square(LPowX);
      APow := TBitOperations.Asr64(APow, 1);
    until APow <= 0;
  end;

  TGcmUtilities.AsBytes(LY, AOutput);
end;

end.
