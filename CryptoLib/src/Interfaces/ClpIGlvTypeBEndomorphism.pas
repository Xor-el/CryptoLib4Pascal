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

unit ClpIGlvTypeBEndomorphism;

{$I ..\Include\CryptoLib.inc}

interface

uses
  ClpBigInteger,
  ClpCryptoLibTypes,
  ClpIECInterface,
  ClpIGlvEndomorphism;

type
  IGlvTypeBEndomorphism = interface(IGlvEndomorphism)
    ['{4F285F6A-F627-4873-9F4C-FBC7A7B83A9C}']

    function GetHasEfficientPointMap: Boolean;
    function GetPointMap: IECPointMap;

    function CalculateB(const k, g: TBigInteger; t: Int32): TBigInteger;

    function DecomposeScalar(const k: TBigInteger)
      : TCryptoLibGenericArray<TBigInteger>;

    property PointMap: IECPointMap read GetPointMap;
    property HasEfficientPointMap: Boolean read GetHasEfficientPointMap;

  end;

implementation

end.
