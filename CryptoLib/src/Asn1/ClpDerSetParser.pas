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

unit ClpDerSetParser;

{$I ..\Include\CryptoLib.inc}

interface

uses
  ClpIAsn1StreamParser,
  ClpDerSet,
  ClpIAsn1SetParser,
  ClpIDerSetParser,
  ClpIProxiedInterface;

type
  TDerSetParser = class(TInterfacedObject, IAsn1SetParser, IAsn1Convertible,
    IDerSetParser)

  strict private
  var
    F_parser: IAsn1StreamParser;

  public

    constructor Create(const parser: IAsn1StreamParser);
    function ReadObject(): IAsn1Convertible; inline;
    function ToAsn1Object(): IAsn1Object; inline;

  end;

implementation

{ TDerSetParser }

constructor TDerSetParser.Create(const parser: IAsn1StreamParser);
begin
  F_parser := parser;
end;

function TDerSetParser.ReadObject: IAsn1Convertible;
begin
  result := F_parser.ReadObject();
end;

function TDerSetParser.ToAsn1Object: IAsn1Object;
begin
  result := TDerSet.Create(F_parser.ReadVector(), false);
end;

end.
