{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                           Author - Ugochukwu Mmaduekwe                          * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ *                                                                                 * }
{ *                              Acknowledgements:                                  * }
{ *                                                                                 * }
{ *      Thanks to Sphere 10 Software (http://www.sphere10.com/) for sponsoring     * }
{ *                         the development of this library                         * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit ClpCbcBlockCipher;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpIBlockCipher,
  ClpIBlockCipherMode,
  ClpIBulkBlockCipherMode,
  ClpICbcBlockCipher,
  ClpICipherParameters,
  ClpIParametersWithIV,
{$IFDEF CRYPTOLIB_X86_SIMD}
  ClpIAesEngineX86,
  ClpAesEngineX86,
{$ENDIF CRYPTOLIB_X86_SIMD}
  ClpArrayUtilities,
  ClpCryptoLibTypes;

resourcestring
  SInvalidIVLength =
    'Initialisation Vector Must be the Same Length as Block Size';
  SInvalidChangeState = 'Cannot Change Encrypting State Without Providing Key.';
  SInputBufferTooShort = 'Input Buffer too Short';
  SOutputBufferTooShort = 'Output Buffer too Short';

type
  TCbcBlockCipher = class sealed(TInterfacedObject, ICbcBlockCipher,
    IBlockCipherMode, IBlockCipher, IBulkBlockCipherMode)

  strict private
  var
    FIV, FCbcV, FCbcNextV: TCryptoLibByteArray;
    FBlockSize: Int32;
    FCipher: IBlockCipher;
    FEncrypting: Boolean;
{$IFDEF CRYPTOLIB_X86_SIMD}
    // Cached on Init; non-nil only when the underlying block cipher is
    // TAesEngineX86. Lets the bulk path call the engine's concrete
    // ProcessBlock / ProcessFourBlocks / ProcessEightBlocks without a
    // per-call virtual dispatch or Supports() probe. CBC decrypt is the
    // big win here (independent block decrypts pipelined 8-way); CBC
    // encrypt stays serial but saves roughly one interface call per block.
    FAesEngineX86: TAesEngineX86;
{$ENDIF CRYPTOLIB_X86_SIMD}

    function EncryptBlock(const AInput: TCryptoLibByteArray; AInOff: Int32;
      const AOutBytes: TCryptoLibByteArray; AOutOff: Int32): Int32;
    function DecryptBlock(const AInput: TCryptoLibByteArray; AInOff: Int32;
      const AOutBytes: TCryptoLibByteArray; AOutOff: Int32): Int32;

{$IFDEF CRYPTOLIB_X86_SIMD}
    // Bulk encrypt via cached AES-NI engine. Serial by definition (each
    // ciphertext block feeds the next XOR), but we skip the IBlockCipher
    // interface call and the polymorphic AlgorithmName lookup.
    procedure CbcEncryptBulkX86(const AInBuf: TCryptoLibByteArray;
      AInOff, ABlockCount: Int32; const AOutBuf: TCryptoLibByteArray;
      AOutOff: Int32);
    // Bulk decrypt via cached AES-NI engine. Decrypts in 8- then 4-block
    // batches with alias-safe ciphertext staging, then chain-XORs against
    // FCbcV + staged ciphertext so output matches sequential DecryptBlock.
    procedure CbcDecryptBulkX86(const AInBuf: TCryptoLibByteArray;
      AInOff, ABlockCount: Int32; const AOutBuf: TCryptoLibByteArray;
      AOutOff: Int32);
{$ENDIF CRYPTOLIB_X86_SIMD}

  strict protected
    function GetAlgorithmName: String; inline;
    function GetIsPartialBlockOkay: Boolean; inline;
    function GetUnderlyingCipher(): IBlockCipher; inline;

  public
    constructor Create(const ACipher: IBlockCipher);
    procedure Init(AForEncryption: Boolean; const AParameters: ICipherParameters);
    function GetBlockSize(): Int32; inline;
    function ProcessBlock(const AInput: TCryptoLibByteArray; AInOff: Int32;
      const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32;

    /// <summary>
    /// IBulkBlockCipherMode: process ABlockCount consecutive CBC blocks.
    /// Output is byte-identical to ABlockCount sequential ProcessBlock
    /// calls and the chaining state (FCbcV) is left exactly as if those
    /// calls had been made. When the underlying engine exposes an
    /// accelerated multi-block path, batches are dispatched through it;
    /// otherwise the implementation falls back to the per-block
    /// ProcessBlock loop with no change in semantics.
    /// </summary>
    function ProcessBlocks(const AInBuf: TCryptoLibByteArray;
      AInOff, ABlockCount: Int32; const AOutBuf: TCryptoLibByteArray;
      AOutOff: Int32): Int32;

    procedure Reset(); inline;

    property UnderlyingCipher: IBlockCipher read GetUnderlyingCipher;
    property AlgorithmName: String read GetAlgorithmName;
    property IsPartialBlockOkay: Boolean read GetIsPartialBlockOkay;
  end;

implementation

{ TCbcBlockCipher }

constructor TCbcBlockCipher.Create(const ACipher: IBlockCipher);
begin
  inherited Create();
  FCipher := ACipher;
  FBlockSize := ACipher.GetBlockSize();
  System.SetLength(FIV, FBlockSize);
  System.SetLength(FCbcV, FBlockSize);
  System.SetLength(FCbcNextV, FBlockSize);
{$IFDEF CRYPTOLIB_X86_SIMD}
  FAesEngineX86 := nil;
{$ENDIF CRYPTOLIB_X86_SIMD}
end;

function TCbcBlockCipher.DecryptBlock(const AInput: TCryptoLibByteArray;
  AInOff: Int32; const AOutBytes: TCryptoLibByteArray; AOutOff: Int32): Int32;
var
  LLength, LI: Int32;
  LTmp: TCryptoLibByteArray;
begin
  if ((AInOff + FBlockSize) > System.Length(AInput)) then
    raise EDataLengthCryptoLibException.CreateRes(@SInputBufferTooShort);
  System.Move(AInput[AInOff], FCbcNextV[0], FBlockSize * System.SizeOf(Byte));
  LLength := FCipher.ProcessBlock(AInput, AInOff, AOutBytes, AOutOff);
  for LI := 0 to System.Pred(FBlockSize) do
    AOutBytes[AOutOff + LI] := AOutBytes[AOutOff + LI] xor FCbcV[LI];
  LTmp := FCbcV;
  FCbcV := FCbcNextV;
  FCbcNextV := LTmp;
  Result := LLength;
end;

function TCbcBlockCipher.EncryptBlock(const AInput: TCryptoLibByteArray;
  AInOff: Int32; const AOutBytes: TCryptoLibByteArray; AOutOff: Int32): Int32;
var
  LI, LLen: Int32;
begin
  if ((AInOff + FBlockSize) > System.Length(AInput)) then
    raise EDataLengthCryptoLibException.CreateRes(@SInputBufferTooShort);
  for LI := 0 to System.Pred(FBlockSize) do
    FCbcV[LI] := FCbcV[LI] xor AInput[AInOff + LI];
  LLen := FCipher.ProcessBlock(FCbcV, 0, AOutBytes, AOutOff);
  System.Move(AOutBytes[AOutOff], FCbcV[0], System.Length(FCbcV) * System.SizeOf(Byte));
  Result := LLen;
end;

{$IFDEF CRYPTOLIB_X86_SIMD}
procedure TCbcBlockCipher.CbcEncryptBulkX86(const AInBuf: TCryptoLibByteArray;
  AInOff, ABlockCount: Int32; const AOutBuf: TCryptoLibByteArray;
  AOutOff: Int32);
var
  LPCbcV, LPIn, LPOut: PByte;
  LI: Int32;
begin
  // 16-byte CBC encryption: C[i] = AES_ENC(P[i] XOR C[i-1]). Serial chain.
  // We mutate FCbcV in place across the batch; the final value equals the
  // last produced ciphertext block, exactly matching sequential EncryptBlock.
  LPCbcV := @FCbcV[0];
  while ABlockCount > 0 do
  begin
    LPIn := @AInBuf[AInOff];
    LPOut := @AOutBuf[AOutOff];
    for LI := 0 to 15 do
      LPCbcV[LI] := LPCbcV[LI] xor LPIn[LI];
    FAesEngineX86.ProcessBlock(FCbcV, 0, AOutBuf, AOutOff);
    System.Move(LPOut^, LPCbcV^, 16);
    System.Inc(AInOff, 16);
    System.Inc(AOutOff, 16);
    System.Dec(ABlockCount);
  end;
end;

procedure TCbcBlockCipher.CbcDecryptBulkX86(const AInBuf: TCryptoLibByteArray;
  AInOff, ABlockCount: Int32; const AOutBuf: TCryptoLibByteArray;
  AOutOff: Int32);
var
  LCtStage: array [0 .. 127] of Byte;
  LPOut, LPStage, LPCbcV: PByte;
  LI, LJ: Int32;
begin
  // 16-byte CBC decryption: P[i] = AES_DEC(C[i]) XOR C[i-1] (with C[-1] = IV
  // carried in FCbcV). AES_DEC calls across i are independent, so we batch
  // 8 (and then 4) through the AES-NI pipelined kernels, stage the raw
  // ciphertext up front (so in-place aliasing cannot corrupt the XOR feed),
  // and then apply the chain XOR.
  while ABlockCount >= 8 do
  begin
    // Snapshot ciphertext so the engine can safely run in-place, then the
    // chain XOR has guaranteed access to the original bytes.
    System.Move(AInBuf[AInOff], LCtStage[0], 128);
    FAesEngineX86.ProcessEightBlocks(@AInBuf[AInOff], @AOutBuf[AOutOff]);

    LPOut := @AOutBuf[AOutOff];
    LPCbcV := @FCbcV[0];
    // First block XORs against the previous-batch chain state (FCbcV = IV
    // on the very first batch, or the last ciphertext of the prior batch).
    for LI := 0 to 15 do
      LPOut[LI] := LPOut[LI] xor LPCbcV[LI];
    // Blocks 1..7 XOR against the staged ciphertext of the previous block
    // within this batch.
    LPStage := @LCtStage[0];
    for LJ := 1 to 7 do
      for LI := 0 to 15 do
        LPOut[LJ * 16 + LI] := LPOut[LJ * 16 + LI] xor
          LPStage[(LJ - 1) * 16 + LI];

    // Chain state -> last ciphertext block of this batch.
    System.Move(LCtStage[7 * 16], FCbcV[0], 16);
    System.Inc(AInOff, 128);
    System.Inc(AOutOff, 128);
    System.Dec(ABlockCount, 8);
  end;

  if ABlockCount >= 4 then
  begin
    System.Move(AInBuf[AInOff], LCtStage[0], 64);
    FAesEngineX86.ProcessFourBlocks(@AInBuf[AInOff], @AOutBuf[AOutOff]);

    LPOut := @AOutBuf[AOutOff];
    LPCbcV := @FCbcV[0];
    for LI := 0 to 15 do
      LPOut[LI] := LPOut[LI] xor LPCbcV[LI];
    LPStage := @LCtStage[0];
    for LJ := 1 to 3 do
      for LI := 0 to 15 do
        LPOut[LJ * 16 + LI] := LPOut[LJ * 16 + LI] xor
          LPStage[(LJ - 1) * 16 + LI];

    System.Move(LCtStage[3 * 16], FCbcV[0], 16);
    System.Inc(AInOff, 64);
    System.Inc(AOutOff, 64);
    System.Dec(ABlockCount, 4);
  end;

  // Tail 1..3 blocks fall through to per-block DecryptBlock below.
  while ABlockCount > 0 do
  begin
    DecryptBlock(AInBuf, AInOff, AOutBuf, AOutOff);
    System.Inc(AInOff, 16);
    System.Inc(AOutOff, 16);
    System.Dec(ABlockCount);
  end;
end;
{$ENDIF CRYPTOLIB_X86_SIMD}

procedure TCbcBlockCipher.Reset;
begin
  System.Move(FIV[0], FCbcV[0], System.Length(FIV));
  TArrayUtilities.Fill<Byte>(FCbcNextV, 0, System.Length(FCbcNextV), Byte(0));
end;

function TCbcBlockCipher.GetAlgorithmName: String;
begin
  Result := FCipher.AlgorithmName + '/CBC';
end;

function TCbcBlockCipher.GetBlockSize: Int32;
begin
  Result := FCipher.GetBlockSize();
end;

function TCbcBlockCipher.GetIsPartialBlockOkay: Boolean;
begin
  Result := False;
end;

function TCbcBlockCipher.GetUnderlyingCipher: IBlockCipher;
begin
  Result := FCipher;
end;

procedure TCbcBlockCipher.Init(AForEncryption: Boolean;
  const AParameters: ICipherParameters);
var
  LOldEncrypting: Boolean;
  LIvParam: IParametersWithIV;
  LIv: TCryptoLibByteArray;
  LParameters: ICipherParameters;
{$IFDEF CRYPTOLIB_X86_SIMD}
  LAesEngineX86: IAesEngineX86;
{$ENDIF CRYPTOLIB_X86_SIMD}
begin
  LOldEncrypting := FEncrypting;
  FEncrypting := AForEncryption;
  LParameters := AParameters;
  if Supports(LParameters, IParametersWithIV, LIvParam) then
  begin
    LIv := LIvParam.GetIV();
    if (System.Length(LIv) <> FBlockSize) then
      raise EArgumentCryptoLibException.CreateRes(@SInvalidIVLength);
    System.Move(LIv[0], FIV[0], System.Length(LIv) * System.SizeOf(Byte));
    LParameters := LIvParam.Parameters;
  end;
  Reset();
  if (LParameters <> nil) then
    FCipher.Init(FEncrypting, LParameters)
  else if (LOldEncrypting <> FEncrypting) then
    raise EArgumentCryptoLibException.CreateRes(@SInvalidChangeState);

{$IFDEF CRYPTOLIB_X86_SIMD}
  // Re-probe every Init: a user can re-key the same TCbcBlockCipher with a
  // different underlying cipher reference (rare but allowed).
  if (FBlockSize = 16) and Supports(FCipher, IAesEngineX86, LAesEngineX86) then
    FAesEngineX86 := LAesEngineX86 as TAesEngineX86
  else
    FAesEngineX86 := nil;
{$ENDIF CRYPTOLIB_X86_SIMD}
end;

function TCbcBlockCipher.ProcessBlock(const AInput: TCryptoLibByteArray;
  AInOff: Int32; const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32;
begin
  if FEncrypting then
    Result := EncryptBlock(AInput, AInOff, AOutput, AOutOff)
  else
    Result := DecryptBlock(AInput, AInOff, AOutput, AOutOff);
end;

function TCbcBlockCipher.ProcessBlocks(const AInBuf: TCryptoLibByteArray;
  AInOff, ABlockCount: Int32; const AOutBuf: TCryptoLibByteArray;
  AOutOff: Int32): Int32;
var
  LTotalBytes: Int32;
begin
  if ABlockCount <= 0 then
  begin
    Result := 0;
    Exit;
  end;

  LTotalBytes := ABlockCount * FBlockSize;

  if ((AInOff < 0) or ((AInOff + LTotalBytes) > System.Length(AInBuf))) then
    raise EDataLengthCryptoLibException.CreateRes(@SInputBufferTooShort);

  if ((AOutOff < 0) or ((AOutOff + LTotalBytes) > System.Length(AOutBuf))) then
    raise EDataLengthCryptoLibException.CreateRes(@SOutputBufferTooShort);

{$IFDEF CRYPTOLIB_X86_SIMD}
  if FAesEngineX86 <> nil then
  begin
    if FEncrypting then
      CbcEncryptBulkX86(AInBuf, AInOff, ABlockCount, AOutBuf, AOutOff)
    else
      CbcDecryptBulkX86(AInBuf, AInOff, ABlockCount, AOutBuf, AOutOff);
    Result := LTotalBytes;
    Exit;
  end;
{$ENDIF CRYPTOLIB_X86_SIMD}

  // Fallback: whenever no accelerated multi-block path is wired up, we
  // go through the existing per-block logic, which is byte-identical to
  // the pre-bulk implementation by construction.
  while ABlockCount > 0 do
  begin
    if FEncrypting then
      EncryptBlock(AInBuf, AInOff, AOutBuf, AOutOff)
    else
      DecryptBlock(AInBuf, AInOff, AOutBuf, AOutOff);
    System.Inc(AInOff, FBlockSize);
    System.Inc(AOutOff, FBlockSize);
    System.Dec(ABlockCount);
  end;

  Result := LTotalBytes;
end;

end.
