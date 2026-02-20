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
    FEcParams: IECDomainParameters;

  public
    function ReadKey(const AStream: TStream): IAsymmetricKeyParameter;
    constructor Create(const AEcParams: IECDomainParameters);

  end;

implementation

{ TECIESPublicKeyParser }

constructor TECIESPublicKeyParser.Create(const AEcParams: IECDomainParameters);
begin
  Inherited Create();
  FEcParams := AEcParams;
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
        System.SetLength(LV, 1 + (FEcParams.Curve.FieldSize + 7) div 8);
      end;

    $04, // uncompressed or
    $06, // hybrid
    $07: // Byte length calculated as in ECPoint.getEncoded();
      begin
        System.SetLength(LV, 1 + (2 * ((FEcParams.Curve.FieldSize + 7) div 8)));
      end
  else
    begin
      raise EIOCryptoLibException.CreateResFmt
        (@SSenderPublicKeyInvalidPointEncoding, [LFirst]);
    end;

  end;

  LV[0] := Byte(LFirst);
  TStreamUtilities.ReadFully(AStream, LV, 1, System.length(LV) - 1);

  result := TECPublicKeyParameters.Create(FEcParams.Curve.DecodePoint(LV),
    FEcParams);
end;

end.
