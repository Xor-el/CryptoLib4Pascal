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

unit ClpDerSequenceParser;

{$I ..\Include\CryptoLib.inc}

interface

uses
  ClpIAsn1StreamParser,
  ClpIAsn1SequenceParser,
  ClpIProxiedInterface,
  ClpIDerSequenceParser,
  ClpDerSequence;

type
  TDerSequenceParser = class(TInterfacedObject, IAsn1SequenceParser,
    IAsn1Convertible, IDerSequenceParser)

  strict private
  var
    F_parser: IAsn1StreamParser;

  public

    constructor Create(const parser: IAsn1StreamParser);
    function ReadObject(): IAsn1Convertible; inline;
    function ToAsn1Object(): IAsn1Object; inline;

  end;

implementation

{ TDerSequenceParser }

constructor TDerSequenceParser.Create(const parser: IAsn1StreamParser);
begin
  F_parser := parser;
end;

function TDerSequenceParser.ReadObject: IAsn1Convertible;
begin
  result := F_parser.ReadObject();
end;

function TDerSequenceParser.ToAsn1Object: IAsn1Object;
begin
  result := TDerSequence.Create(F_parser.ReadVector());
end;

end.
