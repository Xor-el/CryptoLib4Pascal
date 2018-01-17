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

unit ClpIDerUniversalString;

{$I ..\Include\CryptoLib.inc}

interface

uses
  ClpIProxiedInterface,
  ClpCryptoLibTypes,
  ClpIDerStringBase;

type
  IDerUniversalString = interface(IDerStringBase)

    ['{60EC8C9A-B672-44E4-9C5B-B4022D937002}']

    function GetStr: TCryptoLibByteArray;

    function Asn1Equals(asn1Object: IAsn1Object): Boolean;

    property Str: TCryptoLibByteArray read GetStr;

    function GetString(): String;

    function GetOctets(): TCryptoLibByteArray;

    procedure Encode(derOut: IDerOutputStream);

  end;

implementation

end.
