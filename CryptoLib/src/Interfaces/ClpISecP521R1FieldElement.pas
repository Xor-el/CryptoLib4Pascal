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

unit ClpISecP521R1FieldElement;

{$I ..\Include\CryptoLib.inc}

interface

uses
  ClpIECFieldElement,
  ClpCryptoLibTypes;

type
  ISecP521R1FieldElement = Interface(IAbstractFpFieldElement)
    ['{30C8C42B-5099-4387-BEC9-66D6D8901BB4}']

    function GetX: TCryptoLibUInt32Array;
    property X: TCryptoLibUInt32Array read GetX;
  end;

implementation

end.
