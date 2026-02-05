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

unit ClpPascalCoinECIESKdfBytesGenerator;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpIDigest,
  ClpBaseKdfBytesGenerator,
  ClpIDerivationParameters,
  ClpIKdfParameters,
  ClpIPascalCoinECIESKdfBytesGenerator,
  ClpCryptoLibTypes;

resourcestring
  SOutputBufferTooSmall = 'Output Buffer too Small';
  SKDFParameterNotFound = 'KDF Parameters Required For KDF Generator';
  SHashCannotNotProduceSufficientData =
    'Specified Hash Cannot Produce Sufficient Data for the Specified Operation.';

type

  /// <summary>
  /// <para>
  /// KDF generator for compatibility with existing PascalCoin Implementation
  /// </para>
  /// </summary>
  TPascalCoinECIESKdfBytesGenerator = class(TBaseKdfBytesGenerator,
    IPascalCoinECIESKdfBytesGenerator)

  public

    /// <summary>
    /// Construct a PascalCoin compatible bytes generator.
    /// </summary>
    /// <param name="digest">
    /// the digest to be used as the source of derived keys.
    /// </param>
    constructor Create(const ADigest: IDigest);

    procedure Init(const AParameters: IDerivationParameters); override;

    /// <summary>
    /// fill len bytes of the output buffer with bytes generated from the
    /// derivation function.
    /// </summary>
    /// <exception cref="EArgumentCryptoLibException">
    /// if the size of the request will cause an overflow.
    /// </exception>
    /// <exception cref="EDataLengthCryptoLibException">
    /// if the out buffer is too small.
    /// </exception>
    function GenerateBytes(const AOutput: TCryptoLibByteArray;
      AOutOff, ALength: Int32): Int32; override;

  end;

implementation

{ TPascalCoinECIESKdfBytesGenerator }

constructor TPascalCoinECIESKdfBytesGenerator.Create(const ADigest: IDigest);
begin
  inherited Create(0, ADigest);
end;

function TPascalCoinECIESKdfBytesGenerator.GenerateBytes(
  const AOutput: TCryptoLibByteArray; AOutOff, ALength: Int32): Int32;
var
  LOutLen: Int32;
  LTemp: TCryptoLibByteArray;
begin
  if (System.Length(AOutput) - ALength) < AOutOff then
    raise EDataLengthCryptoLibException.CreateRes(@SOutputBufferTooSmall);

  LOutLen := GetDigest().GetDigestSize();

  if ALength > LOutLen then
    raise EDataLengthCryptoLibException.CreateRes(@SHashCannotNotProduceSufficientData);

  System.SetLength(LTemp, GetDigest().GetDigestSize());
  GetDigest().BlockUpdate(FShared, 0, System.Length(FShared));
  GetDigest().DoFinal(LTemp, 0);

  System.Move(LTemp[0], AOutput[AOutOff], ALength * System.SizeOf(Byte));

  GetDigest().Reset();

  Result := ALength;
end;

procedure TPascalCoinECIESKdfBytesGenerator.Init(const AParameters: IDerivationParameters);
var
  LParameters: IDerivationParameters;
  LP1: IKdfParameters;
begin
  LParameters := AParameters;

  if Supports(LParameters, IKdfParameters, LP1) then
    FShared := LP1.GetSharedSecret()
  else
    raise EArgumentCryptoLibException.CreateRes(@SKDFParameterNotFound);
end;

end.
