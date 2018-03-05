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

unit ClpIAbstractECMultiplier;

{$I ..\Include\CryptoLib.inc}

interface

uses
  ClpBigInteger,
  ClpIECInterface;

type

  IAbstractECMultiplier = interface(IECMultiplier)
    ['{DD63984C-7D4D-46DE-9004-20FD909C2EFB}']

    function MultiplyPositive(const p: IECPoint; const k: TBigInteger)
      : IECPoint;

  end;

implementation

end.
