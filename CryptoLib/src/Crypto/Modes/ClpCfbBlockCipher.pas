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
  ClpIBulkBlockCipher,
  ClpIBulkBlockCipherMode,
  ClpICfbBlockCipher,
  ClpICipherParameters,
  ClpAbstractBlockCipherMode,
  ClpCipherModeParameterUtilities,
  ClpBlockCipherBulkUtilities,
  ClpByteUtilities,
  ClpCryptoLibTypes,
  ClpCryptoLibExceptions;

resourcestring
  SInputBufferTooShort = 'input buffer too short';
  SOutputBufferTooShort = 'output buffer too short';

type
  /// <summary>
  /// Implements Cipher-FeedBack (CFB) mode on top of a <see cref="IBlockCipher"/>.
  /// </summary>
  /// <remarks>
  /// <see cref="IsPartialBlockOkay"/> is True: the feedback width may be smaller than the cipher block size
  /// (e.g. CFB-8).
  /// </remarks>
  TCfbBlockCipher = class sealed(TAbstractBlockCipherMode, ICfbBlockCipher,
    IBulkBlockCipherMode)

  strict private
  var
    FIV, FCfbV, FCfbOutV: TCryptoLibByteArray;
    // Cached bulk-capable view of FCipher. Populated in the constructor only
    // when the CFB mode's feedback-register width equals the underlying
    // cipher block size (i.e. full-block CFB-N, which is the only shape
    // where the N cipher inputs for a decrypt batch are all available up
    // front). Left nil for sub-block CFB widths (e.g. CFB-8 / CFB-64 over
    // a 128-bit cipher), encryption-only flows, or engines that do not
    // expose IBulkBlockCipher; ProcessBlocks then falls back to the
    // per-block loop.
    FBulkCipher: IBulkBlockCipher;

    function EncryptBlock(const AInput: TCryptoLibByteArray; AInOff: Int32;
      const AOutBytes: TCryptoLibByteArray; AOutOff: Int32): Int32;
    function DecryptBlock(const AInput: TCryptoLibByteArray; AInOff: Int32;
      const AOutBytes: TCryptoLibByteArray; AOutOff: Int32): Int32;

  strict protected
    function GetModeName: String; override;
    function GetIsPartialBlockOkay: Boolean; override;

  public
    /// <summary>
    /// Basic constructor.
    /// </summary>
    /// <param name="ACipher">Block cipher forming the keystream generator inside CFB.</param>
    /// <param name="ABitBlockSize">CFB segment size in bits (must be a multiple of 8).</param>
    constructor Create(const ACipher: IBlockCipher; ABitBlockSize: Int32);
    /// <summary>
    /// Initialise CFB state and optionally the IV via <see cref="IParametersWithIV"/>.
    /// </summary>
    /// <param name="AForEncryption">Encrypt or decrypt pathway (selects keystream XOR direction).</param>
    /// <param name="AParameters">Typically <see cref="IParametersWithIV"/> wrapping a <see cref="IKeyParameter"/>.</param>
    /// <remarks>
    /// If an IV is supplied and shorter than the cipher block length, leading bytes are zero-padded FIPS-style
    /// (short IV right-aligned).
    /// </remarks>
    /// <exception cref="EArgumentCryptoLibException">If parameters are incompatible.</exception>
    procedure Init(AForEncryption: Boolean; const AParameters: ICipherParameters); override;
    /// <summary>Xor one CFB segment of input into output.</summary>
    /// <exception cref="EDataLengthCryptoLibException">If input/output buffers are too short.</exception>
    function ProcessBlock(const AInput: TCryptoLibByteArray; AInOff: Int32;
      const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32; override;
    /// <summary>Process multiple contiguous CFB segments.</summary>
    function ProcessBlocks(const AInBuf: TCryptoLibByteArray;
      AInOff, ABlockCount: Int32; const AOutBuf: TCryptoLibByteArray;
      AOutOff: Int32): Int32;
    /// <summary>Reset the chaining register to the IV and leave key schedule intact.</summary>
    procedure Reset(); override;
  end;

implementation

{ TCfbBlockCipher }

constructor TCfbBlockCipher.Create(const ACipher: IBlockCipher;
  ABitBlockSize: Int32);
begin
  inherited Create(ACipher);
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
  LCount: Int32;
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

  TByteUtilities.&Xor(FBlockSize, PByte(@FCfbOutV[0]), PByte(@AInput[AInOff]),
    PByte(@AOutBytes[AOutOff]));

  Result := FBlockSize;
end;

function TCfbBlockCipher.EncryptBlock(const AInput: TCryptoLibByteArray;
  AInOff: Int32; const AOutBytes: TCryptoLibByteArray; AOutOff: Int32): Int32;
var
  LCount: Int32;
begin
  if ((AInOff + FBlockSize) > System.Length(AInput)) then
    raise EDataLengthCryptoLibException.CreateRes(@SInputBufferTooShort);

  if ((AOutOff + FBlockSize) > System.Length(AOutBytes)) then
    raise EDataLengthCryptoLibException.CreateRes(@SOutputBufferTooShort);

  FCipher.ProcessBlock(FCfbV, 0, FCfbOutV, 0);

  TByteUtilities.&Xor(FBlockSize, PByte(@FCfbOutV[0]), PByte(@AInput[AInOff]),
    PByte(@AOutBytes[AOutOff]));

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

function TCfbBlockCipher.GetModeName: String;
begin
  Result := '/CFB' + IntToStr(FBlockSize * 8);
end;

function TCfbBlockCipher.GetIsPartialBlockOkay: Boolean;
begin
  Result := True;
end;

procedure TCfbBlockCipher.Init(AForEncryption: Boolean;
  const AParameters: ICipherParameters);
var
  LParameters: ICipherParameters;
begin
  FForEncryption := AForEncryption;

  // Right-align / zero-pad a short IV into FIV; overflow-safe for over-long IVs.
  TCipherModeParameterUtilities.TryUnwrapIv(AParameters, FIV, LParameters);

  Reset();
  if (LParameters <> nil) then
    FCipher.Init(True, LParameters);
end;

function TCfbBlockCipher.ProcessBlock(const AInput: TCryptoLibByteArray;
  AInOff: Int32; const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32;
begin
  if FForEncryption then
    Result := EncryptBlock(AInput, AInOff, AOutput, AOutOff)
  else
    Result := DecryptBlock(AInput, AInOff, AOutput, AOutOff);
end;

function TCfbBlockCipher.ProcessBlocks(const AInBuf: TCryptoLibByteArray;
  AInOff, ABlockCount: Int32; const AOutBuf: TCryptoLibByteArray;
  AOutOff: Int32): Int32;
var
  LI, LBS, LTotalBytes: Int32;
  LScratch: TCryptoLibByteArray;
begin
  LTotalBytes := CheckBlockBuffers(AInBuf, AInOff, ABlockCount, AOutBuf, AOutOff);
  if LTotalBytes = 0 then
  begin
    Result := 0;
    Exit;
  end;
  LBS := FBlockSize;

  // Fall back to the per-block path when:
  //   * we are encrypting (CFB encrypt has a true serial feedback chain:
  //     C_k feeds FCfbV for step k+1, so cipher calls cannot be batched);
  //   * the underlying engine did not expose IBulkBlockCipher (e.g. a
  //     scalar-only cipher engine, or the feedback width differs from
  //     the block size -- both detected at construction time);
  // This keeps byte-for-byte parity with the pre-bulk code in every
  // unsupported configuration.
  if FForEncryption or (FBulkCipher = nil) then
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
  // P_k = E_K(FCfbV_k) xor C_k, applied over the whole run by TByteUtilities.
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

  TByteUtilities.&Xor(LTotalBytes, PByte(LScratch), PByte(AInBuf) + AInOff,
    PByte(AOutBuf) + AOutOff);

  Result := LTotalBytes;
end;

end.
