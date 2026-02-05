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

unit ClpBaseKdfBytesGenerator;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpIDigest,
  ClpIKdfParameters,
  ClpIIso18033KdfParameters,
  ClpIDerivationFunction,
  ClpIDerivationParameters,
  ClpIBaseKdfBytesGenerator,
  ClpPack,
  ClpCryptoLibTypes;

resourcestring
  SOutputBufferTooSmall = 'Output Buffer too Small';
  SOutputLengthTooLarge = 'Output Length too Large';
  SKDFParameterNotFound = 'KDF Parameters Required For KDF Generator';

type

  /// <summary>
  /// <para>
  /// Basic KDF generator for derived keys and ivs as defined by IEEE
  /// P1363a/ISO 18033
  /// </para>
  /// <para>
  /// This implementation is based on ISO 18033/P1363a.
  /// </para>
  /// </summary>
  TBaseKdfBytesGenerator = class(TInterfacedObject, IBaseKdfBytesGenerator,
    IDerivationFunction)

  strict protected
  var
    FDigest: IDigest;
    FCounterStart: Int32;
    FShared, FIv: TCryptoLibByteArray;

    function GetDigest(): IDigest; virtual;

  public

    /// <summary>
    /// Construct a KDF Parameters generator.
    /// </summary>
    /// <param name="counterStart">
    /// value of counter.
    /// </param>
    /// <param name="digest">
    /// the digest to be used as the source of derived keys.
    /// </param>
    constructor Create(ACounterStart: Int32; const ADigest: IDigest);

    procedure Init(const AParameters: IDerivationParameters); virtual;

    /// <summary>
    /// return the underlying digest.
    /// </summary>
    property Digest: IDigest read GetDigest;

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
      AOutOff, ALength: Int32): Int32; virtual;

  end;

implementation

{ TBaseKdfBytesGenerator }

constructor TBaseKdfBytesGenerator.Create(ACounterStart: Int32;
  const ADigest: IDigest);
begin
  inherited Create();
  FCounterStart := ACounterStart;
  FDigest := ADigest;
end;

function TBaseKdfBytesGenerator.GenerateBytes(const AOutput: TCryptoLibByteArray;
  AOutOff, ALength: Int32): Int32;
var
  LOutLen, LCThreshold, LI, LOutOff, LLength: Int32;
  LOBytes: Int64;
  LCounterBase: UInt32;
  LDig, LC: TCryptoLibByteArray;
begin
  if (System.Length(AOutput) - ALength) < AOutOff then
  begin
    raise EDataLengthCryptoLibException.CreateRes(@SOutputBufferTooSmall);
  end;

  LOBytes := ALength;
  LOutLen := FDigest.GetDigestSize;
  LOutOff := AOutOff;
  LLength := ALength;

  //
  // this is at odds with the standard implementation, the
  // maximum value should be hBits * (2^32 - 1) where hBits
  // is the digest output size in bits. We can't have an
  // array with a long index at the moment...
  //

  if LOBytes > ((Int64(2) shl 32) - 1) then
  begin
    raise EArgumentCryptoLibException.CreateRes(@SOutputLengthTooLarge);
  end;

  LCThreshold := Int32((LOBytes + LOutLen - 1) div LOutLen);

  System.SetLength(LDig, FDigest.GetDigestSize);

  System.SetLength(LC, 4);

  TPack.UInt32_To_BE(UInt32(FCounterStart), LC, 0);

  LCounterBase := UInt32(FCounterStart and (not $FF));

  LI := 0;
  while LI < LCThreshold do
  begin
    FDigest.BlockUpdate(FShared, 0, System.Length(FShared));
    FDigest.BlockUpdate(LC, 0, 4);

    if FIv <> nil then
    begin
      FDigest.BlockUpdate(FIv, 0, System.Length(FIv));
    end;

    FDigest.DoFinal(LDig, 0);

    if LLength > LOutLen then
    begin
      System.Move(LDig[0], AOutput[LOutOff], LOutLen * System.SizeOf(Byte));
      LOutOff := LOutOff + LOutLen;
      LLength := LLength - LOutLen;
    end
    else
    begin
      System.Move(LDig[0], AOutput[LOutOff], LLength * System.SizeOf(Byte));
    end;

    System.Inc(LC[3]);
    if LC[3] = 0 then
    begin
      LCounterBase := LCounterBase + $100;
      TPack.UInt32_To_BE(LCounterBase, LC, 0);
    end;

    System.Inc(LI);
  end;

  FDigest.Reset();

  Result := Int32(LOBytes);
end;

function TBaseKdfBytesGenerator.GetDigest: IDigest;
begin
  Result := FDigest;
end;

procedure TBaseKdfBytesGenerator.Init(const AParameters: IDerivationParameters);
var
  LParameters: IDerivationParameters;
  LP1: IKdfParameters;
  LP2: IIso18033KdfParameters;
begin
  LParameters := AParameters;

  if Supports(LParameters, IKdfParameters, LP1) then
  begin
    FShared := LP1.GetSharedSecret();
    FIv := LP1.GetIV();
  end
  else if Supports(LParameters, IIso18033KdfParameters, LP2) then
  begin
    FShared := LP2.GetSeed();
    FIv := nil;
  end
  else
  begin
    raise EArgumentCryptoLibException.CreateRes(@SKDFParameterNotFound);
  end;

end;

end.
