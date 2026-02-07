{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                Copyright (c) 2018 - 20XX Ugochukwu Mmaduekwe                    * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }

{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }

{ * ******************************************************************************* * }

unit ClpScaleXPointMap;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpIECCore,
  ClpIECFieldElement;

type
  TScaleXPointMap = class(TInterfacedObject, IECPointMap)
  strict protected
    FScale: IECFieldElement;
  public
    constructor Create(const AScale: IECFieldElement);
    function Map(const AP: IECPoint): IECPoint; virtual;
  end;

implementation

constructor TScaleXPointMap.Create(const AScale: IECFieldElement);
begin
  Inherited Create;
  FScale := AScale;
end;

function TScaleXPointMap.Map(const AP: IECPoint): IECPoint;
begin
  Result := AP.ScaleX(FScale);
end;

end.
