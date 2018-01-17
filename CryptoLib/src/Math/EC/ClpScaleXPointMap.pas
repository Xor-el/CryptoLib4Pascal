{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                    Copyright (c) 2018 Ugochukwu Mmaduekwe                       * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }

{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }

{ *                              Acknowledgements:                                  * }
{ *                                                                                 * }
{ *        Thanks to Sphere 10 Software (http://sphere10.com) for sponsoring        * }
{ *                        the development of this library                          * }

{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit ClpScaleXPointMap;

interface

uses
  ClpIECInterface,
  ClpIECFieldElement,
  ClpIScaleXPointMap;

type
  TScaleXPointMap = class(TInterfacedObject, IECPointMap, IScaleXPointMap)

  strict protected
  var
    Fscale: IECFieldElement;

  public
    constructor Create(scale: IECFieldElement);
    function Map(p: IECPoint): IECPoint; virtual;
  end;

implementation

{ TScaleXPointMap }

constructor TScaleXPointMap.Create(scale: IECFieldElement);
begin
  Fscale := scale;
end;

function TScaleXPointMap.Map(p: IECPoint): IECPoint;
begin
  Result := p.ScaleX(Fscale);
end;

end.
