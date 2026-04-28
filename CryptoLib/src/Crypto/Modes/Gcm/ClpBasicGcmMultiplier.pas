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

unit ClpBasicGcmMultiplier;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpIGcmMultiplier,
  ClpGcmUtilities,
  ClpCryptoLibTypes;

type
  TBasicGcmMultiplier = class(TInterfacedObject, IGcmMultiplier)
  strict private
    FH: TFieldElement;
  public
    procedure Init(const AH: TCryptoLibByteArray);
    procedure MultiplyH(const AX: TCryptoLibByteArray);
  end;

implementation

{ TBasicGcmMultiplier }

procedure TBasicGcmMultiplier.Init(const AH: TCryptoLibByteArray);
begin
  TGcmUtilities.AsFieldElement(AH, FH);
end;

procedure TBasicGcmMultiplier.MultiplyH(const AX: TCryptoLibByteArray);
var
  LT: TFieldElement;
begin
  TGcmUtilities.AsFieldElement(AX, LT);
  TGcmUtilities.Multiply(LT, FH);
  TGcmUtilities.AsBytes(LT, AX);
end;

end.
