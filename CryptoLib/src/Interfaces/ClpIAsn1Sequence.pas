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

unit ClpIAsn1Sequence;

{$I ..\Include\CryptoLib.inc}

interface

uses
  Generics.Collections,
  ClpIProxiedInterface,
  ClpIAsn1SequenceParser;

type
  IAsn1Sequence = interface(IAsn1Object)

    ['{37A263B7-6724-422B-9B4C-08EBA272045F}']

    function GetCount: Int32;
    function GetParser: IAsn1SequenceParser;
    function GetSelf(Index: Integer): IAsn1Encodable;
    function GetCurrent(e: TEnumerator<IAsn1Encodable>): IAsn1Encodable;

    procedure AddObject(const obj: IAsn1Encodable);

    function ToString(): String;

    function GetEnumerator: TEnumerator<IAsn1Encodable>;

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
