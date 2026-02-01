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

  strict protected
    function GetAlgorithmName: String;
    function GetBlockSize: Int32;

  public
    constructor Create(const ACipher: IAsymmetricBlockCipher);

    procedure Init(AForEncryption: Boolean; const AParameters: ICipherParameters);
    function GetOutputSize(AInputLen: Int32): Int32;
    function GetUpdateOutputSize(AInputLen: Int32): Int32;

    function ProcessByte(AInput: Byte): TCryptoLibByteArray; overload;
    function ProcessByte(AInput: Byte; const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32; overload;
    function ProcessBytes(const AInput: TCryptoLibByteArray; AInOff, ALength: Int32): TCryptoLibByteArray; overload;
    function ProcessBytes(const AInput: TCryptoLibByteArray): TCryptoLibByteArray; overload;
    function ProcessBytes(const AInput, AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32; overload;
    function ProcessBytes(const AInput: TCryptoLibByteArray; AInOff, ALength: Int32; const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32; overload;
    function DoFinal(): TCryptoLibByteArray; overload;
    function DoFinal(const AInput: TCryptoLibByteArray): TCryptoLibByteArray; overload;
    function DoFinal(const AInput: TCryptoLibByteArray; AInOff, AInLen: Int32): TCryptoLibByteArray; overload;
    function DoFinal(const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32; overload;
    function DoFinal(const AInput: TCryptoLibByteArray; const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32; overload;
    function DoFinal(const AInput: TCryptoLibByteArray; AInOff, ALength: Int32; const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32; overload;

    procedure Reset();

    property AlgorithmName: String read GetAlgorithmName;
    property BlockSize: Int32 read GetBlockSize;

  end;

implementation

{ TBufferedAsymmetricBlockCipher }

constructor TBufferedAsymmetricBlockCipher.Create(const ACipher: IAsymmetricBlockCipher);
begin
  inherited Create();
  FCipher := ACipher;
end;

function TBufferedAsymmetricBlockCipher.GetAlgorithmName: String;
begin
  Result := FCipher.AlgorithmName;
end;

function TBufferedAsymmetricBlockCipher.GetBlockSize: Int32;
begin
  Result := FCipher.InputBlockSize;
end;

procedure TBufferedAsymmetricBlockCipher.Init(AForEncryption: Boolean; const AParameters: ICipherParameters);
begin
  Reset();
  FCipher.Init(AForEncryption, AParameters);
  // Allow for an extra byte where people are using their own padding
  // mechanisms on a raw cipher.
  if AForEncryption then
    System.SetLength(FBuffer, FCipher.InputBlockSize + 1)
  else
    System.SetLength(FBuffer, FCipher.InputBlockSize);
  FBufOff := 0;
end;

function TBufferedAsymmetricBlockCipher.GetOutputSize(AInputLen: Int32): Int32;
begin
  Result := FCipher.OutputBlockSize;
end;

function TBufferedAsymmetricBlockCipher.GetUpdateOutputSize(AInputLen: Int32): Int32;
begin
  Result := 0;
end;

function TBufferedAsymmetricBlockCipher.ProcessByte(AInput: Byte): TCryptoLibByteArray;
begin
  if FBufOff >= System.Length(FBuffer) then
    raise EDataLengthCryptoLibException.CreateRes(@SDataTooLongForCipher);

  FBuffer[FBufOff] := AInput;
  System.Inc(FBufOff);
  Result := nil;
end;

function TBufferedAsymmetricBlockCipher.ProcessByte(AInput: Byte; const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32;
begin
  if FBufOff >= System.Length(FBuffer) then
    raise EDataLengthCryptoLibException.CreateRes(@SDataTooLongForCipher);

  FBuffer[FBufOff] := AInput;
  System.Inc(FBufOff);
  Result := 0;
end;

function TBufferedAsymmetricBlockCipher.ProcessBytes(const AInput: TCryptoLibByteArray; AInOff, ALength: Int32): TCryptoLibByteArray;
begin
  if ALength < 1 then
  begin
    Result := nil;
    Exit;
  end;

  if AInput = nil then
    raise EArgumentNilCryptoLibException.Create('input');

  if ALength > System.Length(FBuffer) - FBufOff then
    raise EDataLengthCryptoLibException.CreateRes(@SDataTooLongForCipher);

  System.Move(AInput[AInOff], FBuffer[FBufOff], ALength);
  System.Inc(FBufOff, ALength);
  Result := nil;
end;

function TBufferedAsymmetricBlockCipher.ProcessBytes(const AInput: TCryptoLibByteArray): TCryptoLibByteArray;
begin
  Result := ProcessBytes(AInput, 0, System.Length(AInput));
end;

function TBufferedAsymmetricBlockCipher.ProcessBytes(const AInput, AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32;
begin
  ProcessBytes(AInput, 0, System.Length(AInput));
  Result := 0;
end;

function TBufferedAsymmetricBlockCipher.ProcessBytes(const AInput: TCryptoLibByteArray; AInOff, ALength: Int32; const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32;
begin
  ProcessBytes(AInput, AInOff, ALength);
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

function TBufferedAsymmetricBlockCipher.DoFinal(const AInput: TCryptoLibByteArray): TCryptoLibByteArray;
begin
  ProcessBytes(AInput, 0, System.Length(AInput));
  Result := DoFinal();
end;

function TBufferedAsymmetricBlockCipher.DoFinal(const AInput: TCryptoLibByteArray; AInOff, AInLen: Int32): TCryptoLibByteArray;
begin
  ProcessBytes(AInput, AInOff, AInLen);
  Result := DoFinal();
end;

function TBufferedAsymmetricBlockCipher.DoFinal(const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32;
var
  LOutBytes: TCryptoLibByteArray;
begin
  LOutBytes := DoFinal();
  if LOutBytes <> nil then
  begin
    if (System.Length(AOutput) - AOutOff) < System.Length(LOutBytes) then
      raise EDataLengthCryptoLibException.CreateRes(@SOutputBufferTooShort);
    System.Move(LOutBytes[0], AOutput[AOutOff], System.Length(LOutBytes));
    Result := System.Length(LOutBytes);
  end
  else
    Result := 0;
end;

function TBufferedAsymmetricBlockCipher.DoFinal(const AInput: TCryptoLibByteArray; const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32;
begin
  ProcessBytes(AInput, 0, System.Length(AInput));
  Result := DoFinal(AOutput, AOutOff);
end;

function TBufferedAsymmetricBlockCipher.DoFinal(const AInput: TCryptoLibByteArray; AInOff, ALength: Int32; const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32;
begin
  ProcessBytes(AInput, AInOff, ALength);
  Result := DoFinal(AOutput, AOutOff);
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
