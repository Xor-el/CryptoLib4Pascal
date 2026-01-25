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

unit ClpBufferedAsymmetricBlockCipher;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  Classes,
  SysUtils,
  ClpICipherParameters,
  ClpIAsymmetricBlockCipher,
  ClpIBufferedCipher,
  ClpIBufferedAsymmetricBlockCipher,
  ClpCryptoLibTypes;

resourcestring
  SOutputBufferTooShort = 'Output buffer too short';
  SDataTooLongForCipher = 'Attempt to process message too long for cipher';

type
  /// <summary>
  /// A buffer wrapper for an asymmetric block cipher, allowing input
  /// to be accumulated in a piecemeal fashion until final processing.
  /// </summary>
  TBufferedAsymmetricBlockCipher = class(TInterfacedObject, IBufferedCipher, IBufferedAsymmetricBlockCipher)

  strict private
    FCipher: IAsymmetricBlockCipher;
    FBuffer: TCryptoLibByteArray;
    FBufOff: Int32;
    FBufferSize: Int32;
    FOnProgress: TBufferedCipherProgressEvent;

  strict protected
    function GetAlgorithmName: String;
    function GetBlockSize: Int32;
    function GetBufferSize: Int32;
    procedure SetBufferSize(value: Int32);
    function GetOnProgress: TBufferedCipherProgressEvent;
    procedure SetOnProgress(const value: TBufferedCipherProgressEvent);

  public
    constructor Create(const cipher: IAsymmetricBlockCipher);

    procedure Init(forEncryption: Boolean; const parameters: ICipherParameters);
    function GetOutputSize(inputLen: Int32): Int32;
    function GetUpdateOutputSize(inputLen: Int32): Int32;

    procedure ProcessStream(const inputStream, outputStream: TStream;
      Length: Int64); overload;
    procedure ProcessStream(const inputStream: TStream; inOff: Int64;
      const outputStream: TStream; outOff: Int64; Length: Int64); overload;

    function ProcessByte(input: Byte): TCryptoLibByteArray; overload;
    function ProcessByte(input: Byte; const output: TCryptoLibByteArray;
      outOff: Int32): Int32; overload;
    function ProcessBytes(const input: TCryptoLibByteArray; inOff,
      length: Int32): TCryptoLibByteArray; overload;
    function ProcessBytes(const input: TCryptoLibByteArray)
      : TCryptoLibByteArray; overload;
    function ProcessBytes(const input, output: TCryptoLibByteArray;
      outOff: Int32): Int32; overload;
    function ProcessBytes(const input: TCryptoLibByteArray; inOff, length: Int32;
      const output: TCryptoLibByteArray; outOff: Int32): Int32; overload;
    function DoFinal(): TCryptoLibByteArray; overload;
    function DoFinal(const input: TCryptoLibByteArray): TCryptoLibByteArray; overload;
    function DoFinal(const input: TCryptoLibByteArray; inOff, inLen: Int32)
      : TCryptoLibByteArray; overload;
    function DoFinal(const output: TCryptoLibByteArray; outOff: Int32)
      : Int32; overload;
    function DoFinal(const input: TCryptoLibByteArray;
      const output: TCryptoLibByteArray; outOff: Int32): Int32; overload;
    function DoFinal(const input: TCryptoLibByteArray; inOff, length: Int32;
      const output: TCryptoLibByteArray; outOff: Int32): Int32; overload;
    procedure Reset();

    property AlgorithmName: String read GetAlgorithmName;
    property BlockSize: Int32 read GetBlockSize;
    property BufferSize: Int32 read GetBufferSize write SetBufferSize;
    property OnProgress: TBufferedCipherProgressEvent read GetOnProgress write SetOnProgress;

  end;

implementation

{ TBufferedAsymmetricBlockCipher }

constructor TBufferedAsymmetricBlockCipher.Create(const cipher: IAsymmetricBlockCipher);
begin
  inherited Create();
  FCipher := cipher;
  FBufferSize := 4096;
end;

function TBufferedAsymmetricBlockCipher.GetAlgorithmName: String;
begin
  Result := FCipher.AlgorithmName;
end;

function TBufferedAsymmetricBlockCipher.GetBlockSize: Int32;
begin
  Result := FCipher.InputBlockSize;
end;

function TBufferedAsymmetricBlockCipher.GetBufferSize: Int32;
begin
  Result := FBufferSize;
end;

procedure TBufferedAsymmetricBlockCipher.SetBufferSize(value: Int32);
begin
  FBufferSize := value;
end;

function TBufferedAsymmetricBlockCipher.GetOnProgress: TBufferedCipherProgressEvent;
begin
  Result := FOnProgress;
end;

procedure TBufferedAsymmetricBlockCipher.SetOnProgress(const value: TBufferedCipherProgressEvent);
begin
  FOnProgress := value;
end;

procedure TBufferedAsymmetricBlockCipher.Init(forEncryption: Boolean;
  const parameters: ICipherParameters);
begin
  Reset();
  FCipher.Init(forEncryption, parameters);
  // Allow for an extra byte where people are using their own padding
  // mechanisms on a raw cipher.
  if forEncryption then
    SetLength(FBuffer, FCipher.InputBlockSize + 1)
  else
    SetLength(FBuffer, FCipher.InputBlockSize);
  FBufOff := 0;
end;

function TBufferedAsymmetricBlockCipher.GetOutputSize(inputLen: Int32): Int32;
begin
  Result := FCipher.OutputBlockSize;
end;

function TBufferedAsymmetricBlockCipher.GetUpdateOutputSize(inputLen: Int32): Int32;
begin
  Result := 0;
end;

procedure TBufferedAsymmetricBlockCipher.ProcessStream(const inputStream,
  outputStream: TStream; Length: Int64);
begin
  ProcessStream(inputStream, inputStream.Position, outputStream, outputStream.Position, Length);
end;

procedure TBufferedAsymmetricBlockCipher.ProcessStream(const inputStream: TStream;
  inOff: Int64; const outputStream: TStream; outOff: Int64; Length: Int64);
var
  inputData, outputData: TCryptoLibByteArray;
begin
  // For asymmetric ciphers, we read the whole input, process, and write
  inputStream.Position := inOff;
  SetLength(inputData, Length);
  inputStream.ReadBuffer(inputData[0], Length);

  outputData := DoFinal(inputData, 0, Length);

  outputStream.Position := outOff;
  if outputData <> nil then
    outputStream.WriteBuffer(outputData[0], System.Length(outputData));
end;

function TBufferedAsymmetricBlockCipher.ProcessByte(input: Byte): TCryptoLibByteArray;
begin
  if FBufOff >= System.Length(FBuffer) then
    raise EDataLengthCryptoLibException.CreateRes(@SDataTooLongForCipher);

  FBuffer[FBufOff] := input;
  Inc(FBufOff);
  Result := nil;
end;

function TBufferedAsymmetricBlockCipher.ProcessByte(input: Byte;
  const output: TCryptoLibByteArray; outOff: Int32): Int32;
begin
  if FBufOff >= System.Length(FBuffer) then
    raise EDataLengthCryptoLibException.CreateRes(@SDataTooLongForCipher);

  FBuffer[FBufOff] := input;
  Inc(FBufOff);
  Result := 0;
end;

function TBufferedAsymmetricBlockCipher.ProcessBytes(const input: TCryptoLibByteArray;
  inOff, length: Int32): TCryptoLibByteArray;
begin
  if length < 1 then
  begin
    Result := nil;
    Exit;
  end;

  if input = nil then
    raise EArgumentNilCryptoLibException.Create('input');

  if length > System.Length(FBuffer) - FBufOff then
    raise EDataLengthCryptoLibException.CreateRes(@SDataTooLongForCipher);

  System.Move(input[inOff], FBuffer[FBufOff], length);
  Inc(FBufOff, length);
  Result := nil;
end;

function TBufferedAsymmetricBlockCipher.ProcessBytes(const input: TCryptoLibByteArray)
  : TCryptoLibByteArray;
begin
  Result := ProcessBytes(input, 0, System.Length(input));
end;

function TBufferedAsymmetricBlockCipher.ProcessBytes(const input, output: TCryptoLibByteArray;
  outOff: Int32): Int32;
begin
  ProcessBytes(input, 0, System.Length(input));
  Result := 0;
end;

function TBufferedAsymmetricBlockCipher.ProcessBytes(const input: TCryptoLibByteArray;
  inOff, length: Int32; const output: TCryptoLibByteArray; outOff: Int32): Int32;
begin
  ProcessBytes(input, inOff, length);
  Result := 0;
end;

function TBufferedAsymmetricBlockCipher.DoFinal: TCryptoLibByteArray;
begin
  if FBufOff > 0 then
    Result := FCipher.ProcessBlock(FBuffer, 0, FBufOff)
  else
    Result := nil;
  Reset();
end;

function TBufferedAsymmetricBlockCipher.DoFinal(const input: TCryptoLibByteArray)
  : TCryptoLibByteArray;
begin
  ProcessBytes(input, 0, System.Length(input));
  Result := DoFinal();
end;

function TBufferedAsymmetricBlockCipher.DoFinal(const input: TCryptoLibByteArray;
  inOff, inLen: Int32): TCryptoLibByteArray;
begin
  ProcessBytes(input, inOff, inLen);
  Result := DoFinal();
end;

function TBufferedAsymmetricBlockCipher.DoFinal(const output: TCryptoLibByteArray;
  outOff: Int32): Int32;
var
  outBytes: TCryptoLibByteArray;
begin
  outBytes := DoFinal();
  if outBytes <> nil then
  begin
    if (System.Length(output) - outOff) < System.Length(outBytes) then
      raise EDataLengthCryptoLibException.CreateRes(@SOutputBufferTooShort);
    System.Move(outBytes[0], output[outOff], System.Length(outBytes));
    Result := System.Length(outBytes);
  end
  else
    Result := 0;
end;

function TBufferedAsymmetricBlockCipher.DoFinal(const input: TCryptoLibByteArray;
  const output: TCryptoLibByteArray; outOff: Int32): Int32;
begin
  ProcessBytes(input, 0, System.Length(input));
  Result := DoFinal(output, outOff);
end;

function TBufferedAsymmetricBlockCipher.DoFinal(const input: TCryptoLibByteArray;
  inOff, length: Int32; const output: TCryptoLibByteArray; outOff: Int32): Int32;
begin
  ProcessBytes(input, inOff, length);
  Result := DoFinal(output, outOff);
end;

procedure TBufferedAsymmetricBlockCipher.Reset;
begin
  if FBuffer <> nil then
  begin
    FillChar(FBuffer[0], System.Length(FBuffer), 0);
    FBufOff := 0;
  end;
end;

end.

