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

unit ClpDerOctetStringParser;

{$I ..\Include\CryptoLib.inc}

interface

uses
  Classes,
  ClpCryptoLibTypes,
  ClpDerOctetString,
  ClpDefiniteLengthInputStream,
  ClpIProxiedInterface,
  ClpIDerOctetStringParser,
  ClpIAsn1OctetStringParser;

resourcestring
  SConvertError = 'EIOCryptoLibException Converting Stream to Byte Array: %s';

type
  TDerOctetStringParser = class(TInterfacedObject, IAsn1OctetStringParser,
    IAsn1Convertible, IDerOctetStringParser)

  strict private
  var
    Fstream: TDefiniteLengthInputStream;

  public

    constructor Create(stream: TDefiniteLengthInputStream);
    destructor Destroy(); override;
    function GetOctetStream(): TStream; inline;
    function ToAsn1Object(): IAsn1Object;

  end;

implementation

{ TDerOctetStringParser }

constructor TDerOctetStringParser.Create(stream: TDefiniteLengthInputStream);
begin
  Fstream := stream;
end;

destructor TDerOctetStringParser.Destroy;
begin
  Fstream.Free;
  inherited Destroy;
end;

function TDerOctetStringParser.GetOctetStream: TStream;
begin
  result := Fstream;
end;

function TDerOctetStringParser.ToAsn1Object: IAsn1Object;
begin
  try
    result := TDerOctetString.Create(Fstream.ToArray());
  except
    on e: EIOCryptoLibException do
    begin
      raise EInvalidOperationCryptoLibException.CreateResFmt(@SConvertError,
        [e.Message]);
    end;
  end;
end;

end.
