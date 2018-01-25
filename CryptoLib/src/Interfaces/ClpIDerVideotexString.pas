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

unit ClpIDerVideotexString;

{$I ..\Include\CryptoLib.inc}

interface

uses
  ClpCryptoLibTypes,
  ClpIProxiedInterface,
  ClpIDerStringBase;

type
  IDerVideotexString = interface(IDerStringBase)
    ['{9484AEC5-5667-4C14-8441-4447B0B29F1B}']

    function GetmString: TCryptoLibByteArray;

    function Asn1GetHashCode(): Int32;
    function Asn1Equals(const asn1Object: IAsn1Object): Boolean;

    property mString: TCryptoLibByteArray read GetmString;

    function GetString(): String;

    function GetOctets(): TCryptoLibByteArray;

    procedure Encode(const derOut: IDerOutputStream);

  end;

implementation

end.
