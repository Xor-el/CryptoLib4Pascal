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

unit ClpDerExternalParser;

{$I ..\Include\CryptoLib.inc}

interface

uses
  ClpIAsn1StreamParser,
  ClpDerExternal,
  ClpIProxiedInterface,
  ClpIDerExternalParser,
  ClpAsn1Encodable;

type
  TDerExternalParser = class(TAsn1Encodable, IDerExternalParser)

  strict private
  var
    F_parser: IAsn1StreamParser;

  public

    constructor Create(const parser: IAsn1StreamParser);
    function ReadObject(): IAsn1Convertible; inline;
    function ToAsn1Object(): IAsn1Object; override;

  end;

implementation

{ TDerExternalParser }

constructor TDerExternalParser.Create(const parser: IAsn1StreamParser);
begin
  Inherited Create();
  F_parser := parser;
end;

function TDerExternalParser.ReadObject: IAsn1Convertible;
begin
  result := F_parser.ReadObject();
end;

function TDerExternalParser.ToAsn1Object: IAsn1Object;
begin
  result := TDerExternal.Create(F_parser.ReadVector());
end;

end.
