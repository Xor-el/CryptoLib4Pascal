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

unit ClpCfbBlockCipher;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpIBlockCipher,
  ClpIBlockCipherMode,
  ClpIBulkBlockCipher,
  ClpIBulkBlockCipherMode,
  ClpICfbBlockCipher,
  ClpICipherParameters,
  ClpIParametersWithIV,
  ClpArrayUtilities,
  ClpBlockCipherBulkUtilities,
  ClpCryptoLibTypes;

resourcestring
  SInputBufferTooShort = 'Input Buffer Too Short';
  SOutputBufferTooShort = 'Output Buffer Too Short';

type
  TCfbBlockCipher = class sealed(TInterfacedObject, ICfbBlockCipher,
    IBlockCipherMode, IBlockCipher, IBulkBlockCipherMode)

  strict private
  var
    FIV, FCfbV, FCfbOutV: TCryptoLibByteArray;
    FBlockSize: Int32;
    FCipher: IBlockCipher;
    // Cached bulk-capable view of FCipher. Populated in the constructor only
    // when the CFB mode's feedback-register width equals the underlying
    // cipher block size (i.e. full-block CFB-N, which is the only shape
    // where the N cipher inputs for a decrypt batch are all available up
    // front). Left nil for sub-block CFB widths (e.g. CFB-8 / CFB-64 over
    // a 128-bit cipher), encryption-only flows, or engines that do not
    // expose IBulkBlockCipher; ProcessBlocks then falls back to the
    // per-block loop.
    FBulkCipher: IBulkBlockCipher;
    FEncrypting: Boolean;

    function EncryptBlock(const AInput: TCryptoLibByteArray; AInOff: Int32;
      const AOutBytes: TCryptoLibByteArray; AOutOff: Int32): Int32;
    function DecryptBlock(const AInput: TCryptoLibByteArray; AInOff: Int32;
      const AOutBytes: TCryptoLibByteArray; AOutOff: Int32): Int32;

  strict protected
    function GetAlgorithmName: String; inline;
    function GetIsPartialBlockOkay: Boolean; inline;
    function GetUnderlyingCipher(): IBlockCipher; inline;

  public
    constructor Create(const ACipher: IBlockCipher; ABitBlockSize: Int32);
    procedure Init(AForEncryption: Boolean; const AParameters: ICipherParameters);
    function GetBlockSize(): Int32; inline;
    function ProcessBlock(const AInput: TCryptoLibByteArray; AInOff: Int32;
      const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32;
    function ProcessBlocks(const AInBuf: TCryptoLibByteArray;
      AInOff, ABlockCount: Int32; const AOutBuf: TCryptoLibByteArray;
      AOutOff: Int32): Int32;
    procedure Reset(); inline;

    property UnderlyingCipher: IBlockCipher read GetUnderlyingCipher;
    property AlgorithmName: String read GetAlgorithmName;
    property IsPartialBlockOkay: Boolean read GetIsPartialBlockOkay;
  end;

implementation

{ TCfbBlockCipher }

constructor TCfbBlockCipher.Create(const ACipher: IBlockCipher;
  ABitBlockSize: Int32);
begin
  inherited Create();
  FCipher := ACipher;
  FBlockSize := ABitBlockSize div 8;

  System.SetLength(FIV, FCipher.GetBlockSize());
  System.SetLength(FCfbV, FCipher.GetBlockSize());
  System.SetLength(FCfbOutV, FCipher.GetBlockSize());

  // Enable the bulk decrypt path only when the feedback register width
  // matches the underlying block size. Otherwise (sub-block CFB widths
  // such as CFB-8 / CFB-64 over a 128-bit cipher) the cipher inputs are
  // interleaved with per-block shifts of FCfbV and cannot be pre-staged
  // into one contiguous batch.
  FBulkCipher := nil;
  if FBlockSize = FCipher.GetBlockSize() then
    TBlockCipherBulkUtilities.TryResolveBulkCipher(FCipher, FBulkCipher);
end;

function TCfbBlockCipher.DecryptBlock(const AInput: TCryptoLibByteArray;
  AInOff: Int32; const AOutBytes: TCryptoLibByteArray; AOutOff: Int32): Int32;
var
  LI, LCount: Int32;
begin
  if ((AInOff + FBlockSize) > System.Length(AInput)) then
    raise EDataLengthCryptoLibException.CreateRes(@SInputBufferTooShort);

  if ((AOutOff + FBlockSize) > System.Length(AOutBytes)) then
    raise EDataLengthCryptoLibException.CreateRes(@SOutputBufferTooShort);

  FCipher.ProcessBlock(FCfbV, 0, FCfbOutV, 0);

  LCount := (System.Length(FCfbV) - FBlockSize) * System.SizeOf(Byte);
  if LCount > 0 then
    System.Move(FCfbV[FBlockSize], FCfbV[0], LCount);

  System.Move(AInput[AInOff], FCfbV[(System.Length(FCfbV) - FBlockSize)],
    FBlockSize * System.SizeOf(Byte));

  for LI := 0 to System.Pred(FBlockSize) do
    AOutBytes[AOutOff + LI] := Byte(FCfbOutV[LI] xor AInput[AInOff + LI]);

  Result := FBlockSize;
end;

function TCfbBlockCipher.EncryptBlock(const AInput: TCryptoLibByteArray;
  AInOff: Int32; const AOutBytes: TCryptoLibByteArray; AOutOff: Int32): Int32;
var
  LI, LCount: Int32;
begin
  if ((AInOff + FBlockSize) > System.Length(AInput)) then
    raise EDataLengthCryptoLibException.CreateRes(@SInputBufferTooShort);

  if ((AOutOff + FBlockSize) > System.Length(AOutBytes)) then
    raise EDataLengthCryptoLibException.CreateRes(@SOutputBufferTooShort);

  FCipher.ProcessBlock(FCfbV, 0, FCfbOutV, 0);

  for LI := 0 to System.Pred(FBlockSize) do
    AOutBytes[AOutOff + LI] := Byte(FCfbOutV[LI] xor AInput[AInOff + LI]);

  LCount := (System.Length(FCfbV) - FBlockSize) * System.SizeOf(Byte);
  if LCount > 0 then
    System.Move(FCfbV[FBlockSize], FCfbV[0], LCount);

  System.Move(AOutBytes[AOutOff], FCfbV[(System.Length(FCfbV) - FBlockSize)],
    FBlockSize * System.SizeOf(Byte));

  Result := FBlockSize;
end;

procedure TCfbBlockCipher.Reset;
begin
  System.Move(FIV[0], FCfbV[0], System.Length(FIV));
end;

function TCfbBlockCipher.GetAlgorithmName: String;
begin
  Result := FCipher.AlgorithmName + '/CFB' + IntToStr(FBlockSize * 8);
end;

function TCfbBlockCipher.GetBlockSize: Int32;
begin
  Result := FBlockSize;
end;

function TCfbBlockCipher.GetIsPartialBlockOkay: Boolean;
begin
  Result := True;
end;

function TCfbBlockCipher.GetUnderlyingCipher: IBlockCipher;
begin
  Result := FCipher;
end;

procedure TCfbBlockCipher.Init(AForEncryption: Boolean;
  const AParameters: ICipherParameters);
var
  LIvParam: IParametersWithIV;
  LIv: TCryptoLibByteArray;
  LParameters: ICipherParameters;
  LDiff: Int32;
begin
  FEncrypting := AForEncryption;
  LParameters := AParameters;

  if Supports(LParameters, IParametersWithIV, LIvParam) then
  begin
    LIv := LIvParam.GetIV();
    LDiff := System.Length(FIV) - System.Length(LIv);
    System.Move(LIv[0], FIV[LDiff], System.Length(LIv) * System.SizeOf(Byte));
    TArrayUtilities.Fill<Byte>(FIV, 0, LDiff, Byte(0));
    LParameters := LIvParam.Parameters;
  end;

  Reset();
  if (LParameters <> nil) then
    FCipher.Init(True, LParameters);
end;

function TCfbBlockCipher.ProcessBlock(const AInput: TCryptoLibByteArray;
  AInOff: Int32; const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32;
begin
  if FEncrypting then
    Result := EncryptBlock(AInput, AInOff, AOutput, AOutOff)
  else
    Result := DecryptBlock(AInput, AInOff, AOutput, AOutOff);
end;

function TCfbBlockCipher.ProcessBlocks(const AInBuf: TCryptoLibByteArray;
  AInOff, ABlockCount: Int32; const AOutBuf: TCryptoLibByteArray;
  AOutOff: Int32): Int32;
var
  LI, LBS, LTotalBytes, LK: Int32;
  LScratch: TCryptoLibByteArray;
begin
  LBS := FBlockSize;
  LTotalBytes := ABlockCount * LBS;

  if (ABlockCount <= 0) then
  begin
    Result := 0;
    Exit;
  end;

  // Fall back to the per-block path when:
  //   * we are encrypting (CFB encrypt has a true serial feedback chain:
  //     C_k feeds FCfbV for step k+1, so cipher calls cannot be batched);
  //   * the underlying engine did not expose IBulkBlockCipher (e.g. a
  //     scalar-only cipher engine, or the feedback width differs from
  //     the block size -- both detected at construction time);
  // This keeps byte-for-byte parity with the pre-bulk code in every
  // unsupported configuration.
  if FEncrypting or (FBulkCipher = nil) then
  begin
    for LI := 0 to ABlockCount - 1 do
      ProcessBlock(AInBuf, AInOff + LI * LBS, AOutBuf, AOutOff + LI * LBS);
    Result := LTotalBytes;
    Exit;
  end;

  // Full-block CFB-N decrypt in bulk. The cipher inputs for the N blocks
  // are (FCfbV, C_0, C_1, ..., C_{N-2}) -- every cipher call depends only
  // on previously-seen ciphertext, never on the not-yet-produced plaintext,
  // so we can stage them contiguously and let the bulk engine encrypt
  // them all in one SIMD-accelerated call. Plaintext is then
  // P_k = E_K(FCfbV_k) xor C_k, done via the 128 / 64-byte triple-XOR
  // primitives in TBlockCipherBulkUtilities.
  System.SetLength(LScratch, LTotalBytes);
  System.Move(FCfbV[0], LScratch[0], LBS);
  if ABlockCount > 1 then
    System.Move(AInBuf[AInOff], LScratch[LBS], (ABlockCount - 1) * LBS);

  // Save the last ciphertext block to FCfbV BEFORE the XOR pass, since
  // the XOR may overwrite AInBuf[] in the in-place case (AInBuf aliases
  // AOutBuf). After this point FCfbV is the feedback register for the
  // NEXT call to ProcessBlock / ProcessBlocks.
  System.Move(AInBuf[AInOff + LTotalBytes - LBS], FCfbV[0], LBS);

  FBulkCipher.ProcessBlocks(LScratch, 0, ABlockCount, LScratch, 0);

  LK := 0;
  while LK + 128 <= LTotalBytes do
  begin
    TBlockCipherBulkUtilities.Xor128Bytes(
      PByte(@AOutBuf[AOutOff + LK]),
      PByte(@LScratch[LK]),
      PByte(@AInBuf[AInOff + LK]));
    LK := LK + 128;
  end;
  while LK + 64 <= LTotalBytes do
  begin
    TBlockCipherBulkUtilities.Xor64Bytes(
      PByte(@AOutBuf[AOutOff + LK]),
      PByte(@LScratch[LK]),
      PByte(@AInBuf[AInOff + LK]));
    LK := LK + 64;
  end;
  for LI := LK to LTotalBytes - 1 do
    AOutBuf[AOutOff + LI] := LScratch[LI] xor AInBuf[AInOff + LI];

  Result := LTotalBytes;
end;

end.
