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

unit ClpBerApplicationSpecificParser;

{$I ..\Include\CryptoLib.inc}

interface

uses
  ClpIAsn1StreamParser,
  ClpBerApplicationSpecific,
  ClpIBerApplicationSpecificParser,
  ClpIAsn1ApplicationSpecificParser,
  ClpIProxiedInterface;

type
  TBerApplicationSpecificParser = class(TInterfacedObject,
    IAsn1ApplicationSpecificParser, IAsn1Convertible,
    IBerApplicationSpecificParser)

  strict private
  var
    F_tag: Int32;
    F_parser: IAsn1StreamParser;

  public

    constructor Create(tag: Int32; const parser: IAsn1StreamParser);
    function ReadObject(): IAsn1Convertible; inline;
    function ToAsn1Object(): IAsn1Object; inline;

  end;

implementation

{ TBerApplicationSpecificParser }

constructor TBerApplicationSpecificParser.Create(tag: Int32;
  const parser: IAsn1StreamParser);
begin
  F_tag := tag;
  F_parser := parser;
end;

function TBerApplicationSpecificParser.ReadObject: IAsn1Convertible;
begin
  result := F_parser.ReadObject();
end;

function TBerApplicationSpecificParser.ToAsn1Object: IAsn1Object;
begin
  result := TBerApplicationSpecific.Create(F_tag, F_parser.ReadVector());
end;

end.
