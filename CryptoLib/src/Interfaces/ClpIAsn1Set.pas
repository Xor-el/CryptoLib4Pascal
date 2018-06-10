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

unit ClpIAsn1Set;

{$I ..\Include\CryptoLib.inc}

interface

uses
  ClpCryptoLibTypes,
  ClpIProxiedInterface,
  ClpIAsn1SetParser;

type
  IAsn1Set = interface(IAsn1Object)
    ['{0BA9633A-73D2-4F5E-A1C0-0FCF2623847C}']

    function GetCount: Int32;
    function GetParser: IAsn1SetParser;
    function GetSelf(Index: Integer): IAsn1Encodable;
    function GetCurrent(const e: IAsn1Encodable): IAsn1Encodable;

    function ToString(): String;

    function ToArray(): TCryptoLibGenericArray<IAsn1Encodable>;

    function GetEnumerable: TCryptoLibGenericArray<IAsn1Encodable>;

    property Self[Index: Int32]: IAsn1Encodable read GetSelf; default;

    property Parser: IAsn1SetParser read GetParser;
    property Count: Int32 read GetCount;

  end;

type
  IAsn1SetParserImpl = interface(IAsn1SetParser)

    ['{23EAFC37-244E-42D7-89A8-1740B12656C1}']

  end;

implementation

end.
