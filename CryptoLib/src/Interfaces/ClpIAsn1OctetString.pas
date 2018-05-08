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

unit ClpIAsn1OctetString;

{$I ..\Include\CryptoLib.inc}

interface

uses
  Classes,
  ClpCryptoLibTypes,
  ClpIAsn1OctetStringParser,
  ClpIProxiedInterface;

type
  IAsn1OctetString = interface(IAsn1Object)
    ['{7F7FE981-DD88-4076-8A99-F24DA1005475}']

    function GetStr: TCryptoLibByteArray;
    function GetParser: IAsn1OctetStringParser;

    property Str: TCryptoLibByteArray read GetStr;
    property Parser: IAsn1OctetStringParser read GetParser;

    function GetOctetStream(): TStream;

    function GetOctets(): TCryptoLibByteArray;

    function ToString(): String;

  end;

implementation

end.
