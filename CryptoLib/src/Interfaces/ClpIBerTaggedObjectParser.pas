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

unit ClpIBerTaggedObjectParser;

{$I ..\Include\CryptoLib.inc}

interface

uses
  ClpIProxiedInterface,
  ClpIAsn1TaggedObjectParser;

type
  IBerTaggedObjectParser = interface(IAsn1TaggedObjectParser)

    ['{F1E974C6-6C98-448D-945B-077E63ACB66F}']

    function GetIsConstructed: Boolean;
    function GetTagNo: Int32;

    function GetObjectParser(tag: Int32; isExplicit: Boolean): IAsn1Convertible;

    function ToAsn1Object(): IAsn1Object;

    property IsConstructed: Boolean read GetIsConstructed;
    property TagNo: Int32 read GetTagNo;

  end;

implementation

end.
