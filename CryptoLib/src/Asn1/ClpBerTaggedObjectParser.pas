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

unit ClpBerTaggedObjectParser;

{$I ..\Include\CryptoLib.inc}

interface

uses
  ClpCryptoLibTypes,
  ClpIProxiedInterface,
  ClpIAsn1StreamParser,
  ClpIBerTaggedObjectParser,
  ClpIAsn1TaggedObjectParser;

resourcestring
  SUnConstructedTag = 'Explicit Tags Must be Constructed (see X.690 8.14.2)';
  SParsingError = '%s';

type
  TBerTaggedObjectParser = class(TInterfacedObject, IAsn1TaggedObjectParser,
    IAsn1Convertible, IBerTaggedObjectParser)

  strict private
  var
    F_constructed: Boolean;
    F_tagNumber: Int32;
    F_parser: IAsn1StreamParser;

    function GetIsConstructed: Boolean; inline;
    function GetTagNo: Int32; inline;

  public
    constructor Create(constructed: Boolean; tagNumber: Int32;
      const parser: IAsn1StreamParser);

    destructor Destroy; override;

    function GetObjectParser(tag: Int32; isExplicit: Boolean)
      : IAsn1Convertible; inline;

    function ToAsn1Object(): IAsn1Object;

    property IsConstructed: Boolean read GetIsConstructed;
    property TagNo: Int32 read GetTagNo;

  end;

implementation

{ TBerTaggedObjectParser }

constructor TBerTaggedObjectParser.Create(constructed: Boolean;
  tagNumber: Int32; const parser: IAsn1StreamParser);
begin
  F_constructed := constructed;
  F_tagNumber := tagNumber;
  F_parser := parser;
end;

destructor TBerTaggedObjectParser.Destroy;
begin
  F_parser := Nil;
  inherited Destroy;
end;

function TBerTaggedObjectParser.GetIsConstructed: Boolean;
begin
  result := F_constructed;
end;

function TBerTaggedObjectParser.GetObjectParser(tag: Int32; isExplicit: Boolean)
  : IAsn1Convertible;
begin
  if (isExplicit) then
  begin
    if (not F_constructed) then
    begin
      raise EIOCryptoLibException.CreateRes(@SUnConstructedTag);
    end;

    result := F_parser.ReadObject();
    Exit;
  end;

  result := F_parser.ReadImplicit(F_constructed, tag);
end;

function TBerTaggedObjectParser.GetTagNo: Int32;
begin
  result := F_tagNumber;
end;

function TBerTaggedObjectParser.ToAsn1Object: IAsn1Object;
begin
  try
    result := F_parser.ReadTaggedObject(F_constructed, F_tagNumber);
  except
    on e: EIOCryptoLibException do
    begin
      raise EAsn1ParsingCryptoLibException.CreateResFmt(@SParsingError,
        [e.Message]);
    end;

  end;
end;

end.
