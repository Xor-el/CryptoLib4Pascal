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

unit ClpIECPrivateKeyParameters;

{$I ..\Include\CryptoLib.inc}

interface

uses
  ClpBigInteger,
  ClpIECKeyParameters;

type

  IECPrivateKeyParameters = interface(IECKeyParameters)
    ['{49066428-4021-4E3C-A9F5-AB2127289A67}']

    function GetD: TBigInteger;
    property D: TBigInteger read GetD;
  end;

implementation

end.
