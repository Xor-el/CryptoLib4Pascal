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

unit ClpIDerVisibleString;

{$I ..\Include\CryptoLib.inc}

interface

uses
  ClpIProxiedInterface,
  ClpCryptoLibTypes,
  ClpIDerStringBase;

type
  IDerVisibleString = interface(IDerStringBase)

    ['{0540C649-B50B-45DA-9FC9-1248BD3F73F1}']

    function GetStr: String;

    function Asn1GetHashCode(): Int32;
    function Asn1Equals(asn1Object: IAsn1Object): Boolean;

    property Str: String read GetStr;

    function GetString(): String;

    function GetOctets(): TCryptoLibByteArray;

    procedure Encode(derOut: IDerOutputStream);

  end;

implementation

end.
