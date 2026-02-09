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

unit ClpFixedPointPreCompInfo;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpIECCommon,
  ClpIPreCompInfo,
  ClpIFixedPointPreCompInfo;

type
  TFixedPointPreCompInfo = class sealed(TInterfacedObject, IPreCompInfo,
    IFixedPointPreCompInfo)
  strict private
    FLookupTable: IECLookupTable;
    FOffset: IECPoint;
    FWidth: Int32;
    function GetLookupTable: IECLookupTable;
  public
    constructor Create;
    procedure SetLookupTable(const AValue: IECLookupTable);
    function GetOffset: IECPoint;
    procedure SetOffset(const AValue: IECPoint);
    function GetWidth: Int32;
    procedure SetWidth(AValue: Int32);
  public
    property LookupTable: IECLookupTable read GetLookupTable write SetLookupTable;
    property Offset: IECPoint read GetOffset write SetOffset;
    property Width: Int32 read GetWidth write SetWidth;
  end;

implementation

constructor TFixedPointPreCompInfo.Create;
begin
  Inherited Create;
  FWidth := -1;
end;

function TFixedPointPreCompInfo.GetLookupTable: IECLookupTable;
begin
  Result := FLookupTable;
end;

procedure TFixedPointPreCompInfo.SetLookupTable(const AValue: IECLookupTable);
begin
  FLookupTable := AValue;
end;

function TFixedPointPreCompInfo.GetOffset: IECPoint;
begin
  Result := FOffset;
end;

procedure TFixedPointPreCompInfo.SetOffset(const AValue: IECPoint);
begin
  FOffset := AValue;
end;

function TFixedPointPreCompInfo.GetWidth: Int32;
begin
  Result := FWidth;
end;

procedure TFixedPointPreCompInfo.SetWidth(AValue: Int32);
begin
  FWidth := AValue;
end;

end.
