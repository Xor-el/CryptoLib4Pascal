{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                           Author - Ugochukwu Mmaduekwe                          * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }

{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }

{ *                              Acknowledgements:                                  * }
{ *                                                                                 * }
{ *      Thanks to Sphere 10 Software (http://www.sphere10.com/) for sponsoring     * }
{ *                           development of this library                           * }

{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit ClpConcatenationKdfGenerator;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpIDigest,
  ClpIDerivationFunction,
  ClpIDerivationParameters,
  ClpIConcatenationKdfGenerator,
  ClpIKdfParameters,
  ClpCheck,
  ClpPack,
  ClpCryptoLibTypes;

resourcestring
  SKdfParametersRequired =
    'KDF parameters required for ConcatenationKdfGenerator';
  SOutputBufferTooShort = 'Output buffer too short';

type
  /// <summary>
  /// Generator for Concatenation Key Derivation Function defined in
  /// NIST SP 800-56A, Sect 5.8.1
  /// </summary>
  TConcatenationKdfGenerator = class sealed(TInterfacedObject,
    IConcatenationKdfGenerator, IDerivationFunction)

  strict private
  var
    FDigest: IDigest;
    FHLen: Int32;
    FBuffer: TCryptoLibByteArray;

    function GetDigest(): IDigest;

  public
    constructor Create(const ADigest: IDigest);

    procedure Init(const AParameters: IDerivationParameters);

    function GenerateBytes(const AOutput: TCryptoLibByteArray;
      AOutOff, ALength: Int32): Int32;

    property Digest: IDigest read GetDigest;
  end;

implementation

{ TConcatenationKdfGenerator }

constructor TConcatenationKdfGenerator.Create(const ADigest: IDigest);
begin
  inherited Create();
  FDigest := ADigest;
  FHLen := ADigest.GetDigestSize();
end;

function TConcatenationKdfGenerator.GetDigest: IDigest;
begin
  Result := FDigest;
end;

procedure TConcatenationKdfGenerator.Init(
  const AParameters: IDerivationParameters);
var
  LKdfParams: IKdfParameters;
  LSharedSecret, LOtherInfo: TCryptoLibByteArray;
  LOtherInfoLen: Int32;
begin
  if not Supports(AParameters, IKdfParameters, LKdfParams) then
    raise EArgumentCryptoLibException.CreateRes(@SKdfParametersRequired);

  LSharedSecret := LKdfParams.GetSharedSecret();
  LOtherInfo := LKdfParams.GetIV();

  if LOtherInfo = nil then
    LOtherInfoLen := 0
  else
    LOtherInfoLen := System.Length(LOtherInfo);

  System.SetLength(FBuffer, 4 + System.Length(LSharedSecret) +
    LOtherInfoLen + FHLen);

  if System.Length(LSharedSecret) > 0 then
    System.Move(LSharedSecret[0], FBuffer[4],
      System.Length(LSharedSecret) * System.SizeOf(Byte));

  if (LOtherInfo <> nil) and (LOtherInfoLen > 0) then
    System.Move(LOtherInfo[0], FBuffer[4 + System.Length(LSharedSecret)],
      LOtherInfoLen * System.SizeOf(Byte));
end;

function TConcatenationKdfGenerator.GenerateBytes(
  const AOutput: TCryptoLibByteArray; AOutOff, ALength: Int32): Int32;
var
  LHashPos, LEnd, LLimit, LOutOff: Int32;
  LCounter: UInt32;
begin
  TCheck.OutputLength(AOutput, AOutOff, ALength, SOutputBufferTooShort);

  LHashPos := System.Length(FBuffer) - FHLen;
  LCounter := 1;
  LOutOff := AOutOff;

  FDigest.Reset();

  LEnd := LOutOff + ALength;
  LLimit := LEnd - FHLen;

  while LOutOff <= LLimit do
  begin
    TPack.UInt32_To_BE(LCounter, FBuffer, 0);
    Inc(LCounter);

    FDigest.BlockUpdate(FBuffer, 0, LHashPos);
    FDigest.DoFinal(AOutput, LOutOff);

    LOutOff := LOutOff + FHLen;
  end;

  if LOutOff < LEnd then
  begin
    TPack.UInt32_To_BE(LCounter, FBuffer, 0);

    FDigest.BlockUpdate(FBuffer, 0, LHashPos);
    FDigest.DoFinal(FBuffer, LHashPos);

    System.Move(FBuffer[LHashPos], AOutput[LOutOff],
      (LEnd - LOutOff) * System.SizeOf(Byte));
  end;

  Result := ALength;
end;

end.
