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

unit ClpECIESPublicKeyParser;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  Classes,
  ClpIECParameters,
  ClpECParameters,
  ClpIKeyParser,
  ClpIAsymmetricKeyParameter,
  ClpIECIESPublicKeyParser,
  ClpStreamUtilities,
  ClpCryptoLibTypes;

resourcestring
  SSenderPublicKeyInvalid = 'Sender''s Public Key Invalid.';
  SSenderPublicKeyInvalidPointEncoding =
    'Sender''s Public Key has Invalid Point Encoding "%x"';

type
  TECIESPublicKeyParser = class sealed(TInterfacedObject, IECIESPublicKeyParser,
    IKeyParser)

  strict private
  var
    FECParams: IECDomainParameters;

  public
    function ReadKey(const AStream: TStream): IAsymmetricKeyParameter;
    constructor Create(const AECParams: IECDomainParameters);

  end;

implementation

{ TECIESPublicKeyParser }

constructor TECIESPublicKeyParser.Create(const AECParams: IECDomainParameters);
begin
  Inherited Create();
  FECParams := AECParams;
end;

function TECIESPublicKeyParser.ReadKey(const AStream: TStream)
  : IAsymmetricKeyParameter;
var
  LV: TCryptoLibByteArray;
  LFirst: Int32;
begin
  LFirst := AStream.ReadByte;
  // Decode the public ephemeral key
  case LFirst of
    $00: // infinity
      begin
        raise EIOCryptoLibException.CreateRes(@SSenderPublicKeyInvalid);
      end;

    $02, // compressed
    $03: // Byte length calculated as in ECPoint.getEncoded();
      begin
        System.SetLength(LV, 1 + FECParams.Curve.FieldElementEncodingLength);
      end;

    $04, // uncompressed or
    $06, // hybrid
    $07: // Byte length calculated as in ECPoint.getEncoded();
      begin
        System.SetLength(LV, 1 + (2 * FECParams.Curve.FieldElementEncodingLength));
      end
  else
    begin
      raise EIOCryptoLibException.CreateResFmt
        (@SSenderPublicKeyInvalidPointEncoding, [LFirst]);
    end;

  end;

  LV[0] := Byte(LFirst);
  TStreamUtilities.ReadFully(AStream, LV, 1, System.Length(LV) - 1);

  Result := TECPublicKeyParameters.Create(FECParams.Curve.DecodePoint(LV),
    FECParams);
end;

end.
