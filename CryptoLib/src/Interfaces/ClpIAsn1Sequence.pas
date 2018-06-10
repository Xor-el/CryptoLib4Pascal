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

unit ClpIAsn1Sequence;

{$I ..\Include\CryptoLib.inc}

interface

uses
  ClpIProxiedInterface,
  ClpIAsn1SequenceParser,
  ClpCryptoLibTypes;

type
  IAsn1Sequence = interface(IAsn1Object)

    ['{37A263B7-6724-422B-9B4C-08EBA272045F}']

    function GetCount: Int32;
    function GetParser: IAsn1SequenceParser;
    function GetSelf(Index: Integer): IAsn1Encodable;
    function GetCurrent(const e: IAsn1Encodable): IAsn1Encodable;

    procedure AddObject(const obj: IAsn1Encodable);

    function ToString(): String;

    function GetEnumerable: TCryptoLibGenericArray<IAsn1Encodable>;

    property Self[Index: Int32]: IAsn1Encodable read GetSelf; default;

    property Parser: IAsn1SequenceParser read GetParser;
    property Count: Int32 read GetCount;

  end;

type
  IAsn1SequenceParserImpl = interface(IAsn1SequenceParser)

    ['{B986EDD8-A7F3-4E9C-9D5B-2FF9120D9A91}']

  end;

implementation

end.
