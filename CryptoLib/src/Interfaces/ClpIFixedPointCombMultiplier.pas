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

unit ClpIFixedPointCombMultiplier;

{$I ..\Include\CryptoLib.inc}

interface

uses
  ClpIAbstractECMultiplier;

type
  IFixedPointCombMultiplier = interface(IAbstractECMultiplier)
    ['{A3345E31-4D5C-4442-9C3D-ACC7F6DA4A14}']

    function GetWidthForCombSize(combSize: Int32): Int32;
      deprecated 'Is no longer used; remove any overrides in subclasses.';
  end;

implementation

end.
