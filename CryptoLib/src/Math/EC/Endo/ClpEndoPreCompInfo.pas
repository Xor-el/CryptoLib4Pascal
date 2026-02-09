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

unit ClpEndoPreCompInfo;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpIECCommon,
  ClpIPreCompInfo,
  ClpIEndoPreCompInfo;

type
  TEndoPreCompInfo = class(TInterfacedObject, IPreCompInfo, IEndoPreCompInfo)
  strict private
    FEndomorphism: IECEndomorphism;
    FMappedPoint: IECPoint;
    function GetEndomorphism: IECEndomorphism;
    procedure SetEndomorphism(const AValue: IECEndomorphism);
    function GetMappedPoint: IECPoint;
    procedure SetMappedPoint(const AValue: IECPoint);
  public
    property Endomorphism: IECEndomorphism read GetEndomorphism write SetEndomorphism;
    property MappedPoint: IECPoint read GetMappedPoint write SetMappedPoint;
  end;

implementation

function TEndoPreCompInfo.GetEndomorphism: IECEndomorphism;
begin
  Result := FEndomorphism;
end;

procedure TEndoPreCompInfo.SetEndomorphism(const AValue: IECEndomorphism);
begin
  FEndomorphism := AValue;
end;

function TEndoPreCompInfo.GetMappedPoint: IECPoint;
begin
  Result := FMappedPoint;
end;

procedure TEndoPreCompInfo.SetMappedPoint(const AValue: IECPoint);
begin
  FMappedPoint := AValue;
end;

end.
