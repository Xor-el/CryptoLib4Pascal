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
  ClpIBulkBlockCipher,
  ClpIBulkBlockCipherMode,
  ClpICbcBlockCipher,
  ClpICipherParameters,
  ClpIParametersWithIV,
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
    // Cached on Init. Non-nil only when the underlying engine implements
    // IBulkBlockCipher. CBC decrypt exposes 8 independent inverse
    // transforms per call, which a parallel-capable engine can pipeline;
    // CBC encrypt stays serial (C[i] depends on C[i-1]) but still saves
    // one interface dispatch per block. Any bulk-capable block cipher
    // lights up both paths automatically by implementing the interface.
    FBulkCipher: IBulkBlockCipher;

    function EncryptBlock(const AInput: TCryptoLibByteArray; AInOff: Int32;
      const AOutBytes: TCryptoLibByteArray; AOutOff: Int32): Int32;
    function DecryptBlock(const AInput: TCryptoLibByteArray; AInOff: Int32;
      const AOutBytes: TCryptoLibByteArray; AOutOff: Int32): Int32;

    // Bulk encrypt via cached bulk engine. Serial by definition (each
    // ciphertext block feeds the next XOR), but dispatches through the
    // engine's IBlockCipher.ProcessBlock, inherited from the same vtable
    // as IBulkBlockCipher so there's no extra probe.
    procedure CbcEncryptBulk(const AInBuf: TCryptoLibByteArray;
      AInOff, ABlockCount: Int32; const AOutBuf: TCryptoLibByteArray;
      AOutOff: Int32);
    // Bulk decrypt via cached bulk engine. Decrypts in 8-block batches
    // with ciphertext staging (so in-place aliasing cannot corrupt the
    // chain XOR), then applies FCbcV + staged ciphertext. 1..7 block
    // residue goes through per-block DecryptBlock -- engine-owned
    // batch ladder handles anything smaller internally if needed.
    procedure CbcDecryptBulk(const AInBuf: TCryptoLibByteArray;
      AInOff, ABlockCount: Int32; const AOutBuf: TCryptoLibByteArray;
      AOutOff: Int32);

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
    /// accelerated IBulkBlockCipher path and the block size is 16 bytes,
    /// batches are dispatched through it; otherwise the implementation
    /// falls back to the per-block ProcessBlock loop with no change in
    /// semantics.
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
  FBulkCipher := nil;
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

procedure TCbcBlockCipher.CbcEncryptBulk(const AInBuf: TCryptoLibByteArray;
  AInOff, ABlockCount: Int32; const AOutBuf: TCryptoLibByteArray;
  AOutOff: Int32);
var
  LPCbcV, LPIn, LPOut: PByte;
  LI: Int32;
begin
  // 16-byte CBC encryption: C[i] = ENC(P[i] XOR C[i-1]). Serial chain.
  // We mutate FCbcV in place across the batch; the final value equals the
  // last produced ciphertext block, exactly matching sequential EncryptBlock.
  // Dispatches via FBulkCipher.ProcessBlock (inherited from IBlockCipher);
  // this is the same vtable entry the engine already services for single-
  // block calls, so no extra probe per iteration.
  LPCbcV := @FCbcV[0];
  while ABlockCount > 0 do
  begin
    LPIn := @AInBuf[AInOff];
    LPOut := @AOutBuf[AOutOff];
    for LI := 0 to 15 do
      LPCbcV[LI] := LPCbcV[LI] xor LPIn[LI];
    FBulkCipher.ProcessBlock(FCbcV, 0, AOutBuf, AOutOff);
    System.Move(LPOut^, LPCbcV^, 16);
    System.Inc(AInOff, 16);
    System.Inc(AOutOff, 16);
    System.Dec(ABlockCount);
  end;
end;

procedure TCbcBlockCipher.CbcDecryptBulk(const AInBuf: TCryptoLibByteArray;
  AInOff, ABlockCount: Int32; const AOutBuf: TCryptoLibByteArray;
  AOutOff: Int32);
var
  LCtStage: array [0 .. 127] of Byte;
  LPOut, LPStage, LPCbcV: PByte;
  LI, LJ: Int32;
begin
  // 16-byte CBC decryption: P[i] = DEC(C[i]) XOR C[i-1] (with C[-1] = IV
  // carried in FCbcV). The inverse calls across i are independent, so we
  // batch 8 through the engine's bulk path, stage the raw ciphertext up
  // front (so in-place aliasing cannot corrupt the XOR feed), then apply
  // the chain XOR. 1..7 block residue goes per-block below -- the
  // engine's internal 4/1 ladder would kick in if we routed residue
  // through it too, but per-block is already engine-fast and the residue
  // is <= 112 bytes per message so the lost 4-wide parallelism is sub-
  // noise.
  while ABlockCount >= 8 do
  begin
    // Snapshot ciphertext so the engine can safely run in-place; the
    // chain XOR then has guaranteed access to the original bytes.
    System.Move(AInBuf[AInOff], LCtStage[0], 128);
    FBulkCipher.ProcessBlocks(AInBuf, AInOff, 8, AOutBuf, AOutOff);

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

  // Tail 1..7 blocks fall through to per-block DecryptBlock.
  while ABlockCount > 0 do
  begin
    DecryptBlock(AInBuf, AInOff, AOutBuf, AOutOff);
    System.Inc(AInOff, 16);
    System.Inc(AOutOff, 16);
    System.Dec(ABlockCount);
  end;
end;

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

  // Re-probe every Init: a user can re-key the same TCbcBlockCipher with a
  // different underlying cipher reference. The runtime (FBlockSize = 16)
  // guard in ProcessBlocks keeps us correct if a future non-16-byte bulk
  // engine ever surfaces.
  FBulkCipher := nil;
  Supports(FCipher, IBulkBlockCipher, FBulkCipher);
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

  // Fast path: bulk engine available AND classic 16-byte block size. The
  // block-size guard matches the 16-byte-specific strides inside CbcEncryptBulk
  // (per-byte XOR over 0..15) and CbcDecryptBulk (128-byte stage buffer).
  if (FBulkCipher <> nil) and (FBlockSize = 16) then
  begin
    if FEncrypting then
      CbcEncryptBulk(AInBuf, AInOff, ABlockCount, AOutBuf, AOutOff)
    else
      CbcDecryptBulk(AInBuf, AInOff, ABlockCount, AOutBuf, AOutOff);
    Result := LTotalBytes;
    Exit;
  end;

  // Fallback: no bulk capability wired up (or non-16-byte block). Byte-
  // identical to the pre-bulk implementation by construction.
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
