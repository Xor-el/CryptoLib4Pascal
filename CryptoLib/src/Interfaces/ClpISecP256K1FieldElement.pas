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

unit ClpISecP256K1FieldElement;

{$I ..\Include\CryptoLib.inc}

interface

uses
  ClpIECFieldElement,
  ClpCryptoLibTypes;

type
  ISecP256K1FieldElement = Interface(IAbstractFpFieldElement)
    ['{F283DDDA-CB65-45E0-9239-2A202F2F1462}']

    function GetX: TCryptoLibUInt32Array;
    property X: TCryptoLibUInt32Array read GetX;
  end;

implementation

end.
