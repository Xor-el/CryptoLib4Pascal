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

unit ClpScaleYNegateXPointMap;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpIECCore,
  ClpIECFieldElement;

type
  TScaleYNegateXPointMap = class(TInterfacedObject, IECPointMap)
  strict protected
    FScale: IECFieldElement;
  public
    constructor Create(const AScale: IECFieldElement);
    function Map(const AP: IECPoint): IECPoint; virtual;
  end;

implementation

{ TScaleYNegateXPointMap }

constructor TScaleYNegateXPointMap.Create(const AScale: IECFieldElement);
begin
  Inherited Create;
  FScale := AScale;
end;

function TScaleYNegateXPointMap.Map(const AP: IECPoint): IECPoint;
begin
  Result := AP.ScaleYNegateX(FScale);
end;

end.
