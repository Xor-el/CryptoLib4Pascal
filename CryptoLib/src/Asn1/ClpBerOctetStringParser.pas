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

unit ClpBerOctetStringParser;

{$I ..\Include\CryptoLib.inc}

interface

uses
  Classes,
  ClpStreams,
  ClpCryptoLibTypes,
  ClpBerOctetString,
  ClpConstructedOctetStream,
  ClpIAsn1StreamParser,
  ClpIProxiedInterface,
  ClpIBerOctetStringParser,
  ClpIAsn1OctetStringParser;

resourcestring
  SConvertError = 'EIOCryptoLibException Converting Stream to Byte Array: %s';

type
  TBerOctetStringParser = class(TInterfacedObject, IAsn1OctetStringParser,
    IAsn1Convertible, IBerOctetStringParser)

  strict private
  var
    F_parser: IAsn1StreamParser;

  public

    constructor Create(const parser: IAsn1StreamParser);
    function GetOctetStream(): TStream; inline;
    function ToAsn1Object(): IAsn1Object;

  end;

implementation

{ TBerOctetStringParser }

constructor TBerOctetStringParser.Create(const parser: IAsn1StreamParser);
begin
  Inherited Create();
  F_parser := parser;
end;

function TBerOctetStringParser.GetOctetStream: TStream;
begin
  result := TConstructedOctetStream.Create(F_parser);
end;

function TBerOctetStringParser.ToAsn1Object: IAsn1Object;
var
  LStream: TStream;
begin
  try
    LStream := GetOctetStream();

    try
      result := TBerOctetString.Create(TStreams.ReadAll(LStream));
    finally
      LStream.Free;
    end;

  except
    on e: EIOCryptoLibException do
    begin
      raise EAsn1ParsingCryptoLibException.CreateResFmt(@SConvertError,
        [e.Message]);
    end;

  end;
end;

end.
