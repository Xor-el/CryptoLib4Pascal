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

unit ClpWTauNafPreCompInfo;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpIECCore,
  ClpIPreCompInfo,
  ClpIWTauNafPreCompInfo,
  ClpCryptoLibTypes;

type
  TWTauNafPreCompInfo = class sealed(TInterfacedObject, IPreCompInfo,
    IWTauNafPreCompInfo)
  strict private
    FPreComp: TCryptoLibGenericArray<IAbstractF2mPoint>;
    function GetPreComp: TCryptoLibGenericArray<IAbstractF2mPoint>;
    procedure SetPreComp(const AValue: TCryptoLibGenericArray<IAbstractF2mPoint>);
  public
    property PreComp: TCryptoLibGenericArray<IAbstractF2mPoint> read GetPreComp write SetPreComp;
  end;

implementation

{ TWTauNafPreCompInfo }

function TWTauNafPreCompInfo.GetPreComp: TCryptoLibGenericArray<IAbstractF2mPoint>;
begin
  Result := FPreComp;
end;

procedure TWTauNafPreCompInfo.SetPreComp(const AValue: TCryptoLibGenericArray<IAbstractF2mPoint>);
begin
  FPreComp := AValue;
end;

end.
