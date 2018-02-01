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

unit ClpIDerIA5String;

{$I ..\Include\CryptoLib.inc}

interface

uses
  ClpIProxiedInterface,
  ClpCryptoLibTypes,
  ClpIDerStringBase;

type
  IDerIA5String = interface(IDerStringBase)

    ['{F7BAC857-74F7-4660-95E1-F849B5D77F6C}']

    function GetStr: String;

    function Asn1GetHashCode(): Int32;
    function Asn1Equals(const asn1Object: IAsn1Object): Boolean;

    property Str: String read GetStr;

    function GetString(): String;

    function GetOctets(): TCryptoLibByteArray;

    procedure Encode(const derOut: IDerOutputStream);

  end;

implementation

end.
