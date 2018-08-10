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

unit ClpISecT283FieldElement;

{$I ..\Include\CryptoLib.inc}

interface

uses
  ClpIECFieldElement,
  ClpCryptoLibTypes;

type
  ISecT283FieldElement = Interface(IAbstractF2mFieldElement)
    ['{8DD5CFAF-D879-4FC2-93D7-3C2D5D49E8D1}']

    function GetM: Int32;
    property M: Int32 read GetM;

    function GetRepresentation: Int32;
    property Representation: Int32 read GetRepresentation;

    function GetK1: Int32;
    property k1: Int32 read GetK1;
    function GetK2: Int32;
    property k2: Int32 read GetK2;
    function GetK3: Int32;
    property k3: Int32 read GetK3;

    function GetX: TCryptoLibUInt64Array;
    property X: TCryptoLibUInt64Array read GetX;
  end;

implementation

end.
