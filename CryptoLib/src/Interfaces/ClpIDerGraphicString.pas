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

unit ClpIDerGraphicString;

{$I ..\Include\CryptoLib.inc}

interface

uses
  ClpCryptoLibTypes,
  ClpIProxiedInterface,
  ClpIDerStringBase;

type
  IDerGraphicString = interface(IDerStringBase)
    ['{582F6117-BFE1-47A2-BFD5-DC5C83E43985}']

    function GetmString: TCryptoLibByteArray;

    function Asn1GetHashCode(): Int32;
    function Asn1Equals(asn1Object: IAsn1Object): Boolean;

    property mString: TCryptoLibByteArray read GetmString;

    function GetString(): String;

    function GetOctets(): TCryptoLibByteArray;

    procedure Encode(derOut: IDerOutputStream);

  end;

implementation

end.
