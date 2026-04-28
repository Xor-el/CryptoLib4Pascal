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

unit ClpPoly1305;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpIPoly1305,
  ClpIMac,
  ClpMac,
  ClpIBlockCipher,
  ClpICipherParameters,
  ClpIParametersWithIV,
  ClpIKeyParameter,
  ClpKeyParameter,
  ClpCheck,
  ClpPack,
  ClpBitOperations,
  ClpArrayUtilities,
  ClpCpuFeatures,
  ClpCryptoLibTypes;

resourcestring
  SCipherBlockSizeMismatch =
    'Poly1305 requires a 128-bit block cipher.';
  SParametersWithIVRequired =
    'Poly1305 requires parameters of type IParametersWithIV when used with a cipher.';
  SKeyParameterRequired =
    'Poly1305 requires a key parameter.';
  SInvalidKeyLength =
    'Poly1305 key must be 256 bits.';
  SInvalidNonce =
    'Poly1305 requires a 128-bit IV when used with a cipher.';

type
  /// <summary>
  /// Poly1305 algorithm state in radix-2^26 form (72 bytes; same layout on
  /// every architecture).
  /// <list type="bullet">
  /// <item>R0..R4 - clamped 130-bit r split into five 26-bit limbs</item>
  /// <item>S1..S4 - precomputed 5 * R1..R4 wraparound multipliers</item>
  /// <item>H0..H4 - 130-bit accumulator in five 26-bit limbs (plus a few carry bits)</item>
  /// <item>K0..K3 - the Poly1305 "s" key (second half of the 32-byte key)</item>
  /// </list>
  /// </summary>
  TPoly1305State = record
    R0, R1, R2, R3, R4: UInt32;
    S1, S2, S3, S4: UInt32;
    H0, H1, H2, H3, H4: UInt32;
    K0, K1, K2, K3: UInt32;
  end;

  TPoly1305 = class sealed(TMac, IPoly1305, IMac)

  strict private
  const
    BlockSize = Int32(16);

  var
    FCipher: IBlockCipher;
    FState: TPoly1305State;
    // Power table consumed by a SIMD 4-way bulk kernel; nil whenever the
    // scalar path is in use. Lazily allocated by SetKey to the size needed
    // by whichever SIMD variant the CPU picks. Doubles as the dispatch flag
    // read by BlockUpdate (FPowTable <> nil iff a SIMD path is selected).
    FPowTable: TCryptoLibByteArray;
    FCurrentBlock: TCryptoLibByteArray;
    FCurrentBlockOffset: Int32;

    procedure SetKey(const AKeyParameter: IKeyParameter;
      const ANonce: TCryptoLibByteArray);
    procedure ProcessBlock(const ABuf: TCryptoLibByteArray; AOff: Int32);

  strict protected
    function GetAlgorithmName: String; override;

  public
    constructor Create(); overload;
    constructor Create(const ACipher: IBlockCipher); overload;

    function GetMacSize: Int32; override;

    procedure Update(AInput: Byte); override;
    procedure BlockUpdate(const AInput: TCryptoLibByteArray;
      AInOff, ALen: Int32); override;
    procedure Init(const AParameters: ICipherParameters); override;
    function DoFinal(const AOutput: TCryptoLibByteArray; AOutOff: Int32)
      : Int32; overload; override;

    procedure Reset(); override;

    property AlgorithmName: String read GetAlgorithmName;

  end;

implementation

{ Scalar primitives -------------------------------------------------------- }

const
  // Bit masks applied to the four little-endian 32-bit words of the first
  // half of the Poly1305 key to derive r in canonical clamped form
  // (RFC 7539 section 2.5: "clamp r"). Index k corresponds to the k-th
  // 32-bit word LE_To_UInt32(LKey, 4*k).
  Poly1305RClampMask: array[0..3] of UInt32 = (
    UInt32($03FFFFFF),
    UInt32($03FFFF03),
    UInt32($03FFC0FF),
    UInt32($03F03FFF)
  );

  // Mask for the high (limb-4) word of r after the 8-bit shift; isolates
  // the 20 bits that fit into the radix-2^26 layout.
  Poly1305R4HighMask = UInt32($000FFFFF);

procedure Poly1305StateReset(var AState: TPoly1305State); inline;
begin
  AState.H0 := 0;
  AState.H1 := 0;
  AState.H2 := 0;
  AState.H3 := 0;
  AState.H4 := 0;
end;

// Clamp r and pre-scale s = 5*r from the first 16 bytes of AKey, writing
// the result into AState.R0..R4 / AState.S1..S4. Caller is responsible
// for key length validation; this routine does not bounds-check AKey.
procedure Poly1305StateAbsorbR(var AState: TPoly1305State;
  const AKey: TCryptoLibByteArray);
var
  LT0, LT1, LT2, LT3: UInt32;
begin
  LT0 := TPack.LE_To_UInt32(AKey, 0);
  LT1 := TPack.LE_To_UInt32(AKey, 4);
  LT2 := TPack.LE_To_UInt32(AKey, 8);
  LT3 := TPack.LE_To_UInt32(AKey, 12);

  AState.R0 := LT0 and Poly1305RClampMask[0];
  AState.R1 := ((LT0 shr 26) or (LT1 shl 6)) and Poly1305RClampMask[1];
  AState.R2 := ((LT1 shr 20) or (LT2 shl 12)) and Poly1305RClampMask[2];
  AState.R3 := ((LT2 shr 14) or (LT3 shl 18)) and Poly1305RClampMask[3];
  AState.R4 := (LT3 shr 8) and Poly1305R4HighMask;

  AState.S1 := AState.R1 * 5;
  AState.S2 := AState.R2 * 5;
  AState.S3 := AState.R3 * 5;
  AState.S4 := AState.R4 * 5;
end;

// Pack the Poly1305 "s" key (k0..k3) from 16 bytes starting at ABytes[AOff].
procedure Poly1305StateAbsorbS(var AState: TPoly1305State;
  const ABytes: TCryptoLibByteArray; AOff: Int32);
begin
  AState.K0 := TPack.LE_To_UInt32(ABytes, AOff + 0);
  AState.K1 := TPack.LE_To_UInt32(ABytes, AOff + 4);
  AState.K2 := TPack.LE_To_UInt32(ABytes, AOff + 8);
  AState.K3 := TPack.LE_To_UInt32(ABytes, AOff + 12);
end;

// Process one 16-byte Poly1305 block in scalar form: H = (H + M) * r mod p.
// Used both as the per-byte step (TPoly1305.Update) and as the per-block
// fallback for SIMD variants' tail handling.
procedure Poly1305StateProcessBlock(var AState: TPoly1305State;
  const ABuf: TCryptoLibByteArray; AOff: Int32);
var
  LT0, LT1, LT2, LT3: UInt32;
  LTp0, LTp1, LTp2, LTp3, LTp4: UInt64;
begin
  LT0 := TPack.LE_To_UInt32(ABuf, AOff + 0);
  LT1 := TPack.LE_To_UInt32(ABuf, AOff + 4);
  LT2 := TPack.LE_To_UInt32(ABuf, AOff + 8);
  LT3 := TPack.LE_To_UInt32(ABuf, AOff + 12);

  AState.H0 := AState.H0 + (LT0 and $3FFFFFF);
  AState.H1 := AState.H1 + (((LT1 shl 6) or (LT0 shr 26)) and $3FFFFFF);
  AState.H2 := AState.H2 + (((LT2 shl 12) or (LT1 shr 20)) and $3FFFFFF);
  AState.H3 := AState.H3 + (((LT3 shl 18) or (LT2 shr 14)) and $3FFFFFF);
  AState.H4 := AState.H4 + ((UInt32(1) shl 24) or (LT3 shr 8));

  LTp0 := UInt64(AState.H0) * AState.R0 + UInt64(AState.H1) * AState.S4 +
    UInt64(AState.H2) * AState.S3 + UInt64(AState.H3) * AState.S2 +
    UInt64(AState.H4) * AState.S1;
  LTp1 := UInt64(AState.H0) * AState.R1 + UInt64(AState.H1) * AState.R0 +
    UInt64(AState.H2) * AState.S4 + UInt64(AState.H3) * AState.S3 +
    UInt64(AState.H4) * AState.S2;
  LTp2 := UInt64(AState.H0) * AState.R2 + UInt64(AState.H1) * AState.R1 +
    UInt64(AState.H2) * AState.R0 + UInt64(AState.H3) * AState.S4 +
    UInt64(AState.H4) * AState.S3;
  LTp3 := UInt64(AState.H0) * AState.R3 + UInt64(AState.H1) * AState.R2 +
    UInt64(AState.H2) * AState.R1 + UInt64(AState.H3) * AState.R0 +
    UInt64(AState.H4) * AState.S4;
  LTp4 := UInt64(AState.H0) * AState.R4 + UInt64(AState.H1) * AState.R3 +
    UInt64(AState.H2) * AState.R2 + UInt64(AState.H3) * AState.R1 +
    UInt64(AState.H4) * AState.R0;

  AState.H0 := UInt32(LTp0) and $3FFFFFF;
  LTp1 := LTp1 + (LTp0 shr 26);
  AState.H1 := UInt32(LTp1) and $3FFFFFF;
  LTp2 := LTp2 + (LTp1 shr 26);
  AState.H2 := UInt32(LTp2) and $3FFFFFF;
  LTp3 := LTp3 + (LTp2 shr 26);
  AState.H3 := UInt32(LTp3) and $3FFFFFF;
  LTp4 := LTp4 + (LTp3 shr 26);
  AState.H4 := UInt32(LTp4) and $3FFFFFF;
  AState.H0 := AState.H0 + UInt32(LTp4 shr 26) * 5;
  AState.H1 := AState.H1 + (AState.H0 shr 26);
  AState.H0 := AState.H0 and $3FFFFFF;
end;

// Plain scalar bulk path; iterates Poly1305StateProcessBlock ANumBlocks
// times. Used directly when no SIMD variant is available, and as the
// 0..3-block tail handler for SIMD bulk paths.
procedure Poly1305StateProcessBlocksScalar(var AState: TPoly1305State;
  const ABuf: TCryptoLibByteArray; AOff, ANumBlocks: Int32);
var
  LIdx: Int32;
begin
  for LIdx := 1 to ANumBlocks do
  begin
    Poly1305StateProcessBlock(AState, ABuf, AOff);
    AOff := AOff + 16;
  end;
end;

{ AVX2 helpers ------------------------------------------------------------- }

{$IFDEF CRYPTOLIB_X86_SIMD}

// Multiply two 5-limb radix-2^26 numbers ALhs, ARhs modulo 2^130-5,
// returning the 5-limb result in AProduct. Same field arithmetic as the
// inner step of Poly1305StateProcessBlock; used here at SetKey time to
// derive r^2..r^4 for the AVX2 power table. Kept private to this unit
// since it has no caller outside the AVX2 setup path.
procedure Poly1305MulLimbs(out AProduct: array of UInt32;
  const ALhs, ARhs: array of UInt32);
var
  LS1, LS2, LS3, LS4: UInt32;
  LD0, LD1, LD2, LD3, LD4: UInt64;
begin
  LS1 := ARhs[1] * 5;
  LS2 := ARhs[2] * 5;
  LS3 := ARhs[3] * 5;
  LS4 := ARhs[4] * 5;

  LD0 := UInt64(ALhs[0]) * ARhs[0] + UInt64(ALhs[1]) * LS4 +
    UInt64(ALhs[2]) * LS3 + UInt64(ALhs[3]) * LS2 + UInt64(ALhs[4]) * LS1;
  LD1 := UInt64(ALhs[0]) * ARhs[1] + UInt64(ALhs[1]) * ARhs[0] +
    UInt64(ALhs[2]) * LS4 + UInt64(ALhs[3]) * LS3 + UInt64(ALhs[4]) * LS2;
  LD2 := UInt64(ALhs[0]) * ARhs[2] + UInt64(ALhs[1]) * ARhs[1] +
    UInt64(ALhs[2]) * ARhs[0] + UInt64(ALhs[3]) * LS4 + UInt64(ALhs[4]) * LS3;
  LD3 := UInt64(ALhs[0]) * ARhs[3] + UInt64(ALhs[1]) * ARhs[2] +
    UInt64(ALhs[2]) * ARhs[1] + UInt64(ALhs[3]) * ARhs[0] +
    UInt64(ALhs[4]) * LS4;
  LD4 := UInt64(ALhs[0]) * ARhs[4] + UInt64(ALhs[1]) * ARhs[3] +
    UInt64(ALhs[2]) * ARhs[2] + UInt64(ALhs[3]) * ARhs[1] +
    UInt64(ALhs[4]) * ARhs[0];

  AProduct[0] := UInt32(LD0) and $3FFFFFF;
  LD1 := LD1 + (LD0 shr 26);
  AProduct[1] := UInt32(LD1) and $3FFFFFF;
  LD2 := LD2 + (LD1 shr 26);
  AProduct[2] := UInt32(LD2) and $3FFFFFF;
  LD3 := LD3 + (LD2 shr 26);
  AProduct[3] := UInt32(LD3) and $3FFFFFF;
  LD4 := LD4 + (LD3 shr 26);
  AProduct[4] := UInt32(LD4) and $3FFFFFF;
  AProduct[0] := AProduct[0] + UInt32(LD4 shr 26) * 5;
  AProduct[1] := AProduct[1] + (AProduct[0] shr 26);
  AProduct[0] := AProduct[0] and $3FFFFFF;
end;

// (Re)allocate APowTable to the byte size required by the AVX2 4-way
// bulk kernel and pack the precomputed powers r^1..r^4 of AState.R0..R4
// into it, in the post-VPERMD layout the kernel expects. Must be called
// once after Poly1305StateAbsorbR has populated AState.R0..R4 and before
// the first invocation of Poly1305ProcessBlocksAvx2 for the same key.
// The exact buffer size and limb layout are private to this routine.
procedure Poly1305Avx2InitPowerTable(var APowTable: TCryptoLibByteArray;
  const AState: TPoly1305State);
const
  // 10 rows x 8 lanes x 4 bytes = 320. Rows 0..4 hold the limbs of
  // r^4|r^4|r^4|r^3 | r^4|r^2|r^4|r^1 across the 8 ymm lanes (post-VPERMD
  // layout); rows 5..8 hold the 5x wraparound multipliers; row 9 is
  // padding for the +4 over-read of the last shifted load.
  TableSize = Int32(320);
type
  TPowTableLayout = array[0..9, 0..7] of UInt32;
  PPowTableLayout = ^TPowTableLayout;
var
  LTbl: PPowTableLayout;
  Lr1, Lr2, Lr3, Lr4: array[0..4] of UInt32;
  LIdx, LRow, LJ: Int32;
begin
  System.SetLength(APowTable, TableSize);
  LTbl := PPowTableLayout(APowTable);

  Lr1[0] := AState.R0;
  Lr1[1] := AState.R1;
  Lr1[2] := AState.R2;
  Lr1[3] := AState.R3;
  Lr1[4] := AState.R4;

  Poly1305MulLimbs(Lr2, Lr1, Lr1);
  Poly1305MulLimbs(Lr3, Lr2, Lr1);
  Poly1305MulLimbs(Lr4, Lr2, Lr2);

  // Rows 0..4: limbs of r^k for the 4 powers, post-VPERMD layout.
  for LIdx := 0 to 4 do
  begin
    LTbl^[LIdx, 0] := Lr4[LIdx];
    LTbl^[LIdx, 1] := Lr4[LIdx];
    LTbl^[LIdx, 2] := Lr4[LIdx];
    LTbl^[LIdx, 3] := Lr3[LIdx];
    LTbl^[LIdx, 4] := Lr4[LIdx];
    LTbl^[LIdx, 5] := Lr2[LIdx];
    LTbl^[LIdx, 6] := Lr4[LIdx];
    LTbl^[LIdx, 7] := Lr1[LIdx];
  end;

  // Rows 5..8: 5 * limbs[1..4] of r^k (wraparound multipliers).
  for LRow := 5 to 8 do
  begin
    LJ := LRow - 4; // 1..4
    LTbl^[LRow, 0] := Lr4[LJ] * 5;
    LTbl^[LRow, 1] := Lr4[LJ] * 5;
    LTbl^[LRow, 2] := Lr4[LJ] * 5;
    LTbl^[LRow, 3] := Lr3[LJ] * 5;
    LTbl^[LRow, 4] := Lr4[LJ] * 5;
    LTbl^[LRow, 5] := Lr2[LJ] * 5;
    LTbl^[LRow, 6] := Lr4[LJ] * 5;
    LTbl^[LRow, 7] := Lr1[LJ] * 5;
  end;

  // Row 9 is unused padding for the +4 over-read of the last shifted load.
  for LIdx := 0 to 7 do
    LTbl^[9, LIdx] := 0;
end;

// Asm wrapper around the architecture-specific 4-way bulk kernel. The .inc
// files contain pure assembly (db-encoded VEX with mnemonic comments); the
// Pascal layer below is just the procedure header + the SimdProc5Begin ABI
// glue + the kernel body include. ACtx points at the 72-byte R/S/H/K
// portion of TPoly1305State; APowTable points at the separate 320-byte
// power table buffer; the kernel never reads the K limbs.
procedure Poly1305BlocksBulkAvx2Core(ACtx, APowTable, AInp: PByte;
  ALen: NativeUInt; APad: Int32);
{$IFDEF CRYPTOLIB_X86_64_ASM}
{$I ..\..\Include\Simd\Common\SimdProc5Begin_x86_64.inc}
{$I ..\..\Include\Simd\Poly1305\Poly1305BlocksBulkAvx2Core_x86_64.inc}
{$ENDIF}
{$IFDEF CRYPTOLIB_I386_ASM}
{$I ..\..\Include\Simd\Common\SimdProc5Begin_i386.inc}
{$I ..\..\Include\Simd\Poly1305\Poly1305BlocksBulkAvx2Core_i386.inc}
{$ENDIF}
end;

// Bulk-processing variant for AVX2-capable CPUs. Rounds ANumBlocks down
// to a multiple of the AVX2 lane count (4) and dispatches the AVX2 kernel
// for that bulk; the 0..3 leftover blocks are forwarded to
// Poly1305StateProcessBlocksScalar. When fewer than 4 blocks are
// available the entire batch is handled by the scalar path. APowTable
// must point at a buffer already populated by Poly1305Avx2InitPowerTable
// for the same r as currently in AState.
procedure Poly1305ProcessBlocksAvx2(var AState: TPoly1305State;
  APowTable: PByte;
  const ABuf: TCryptoLibByteArray; AOff, ANumBlocks: Int32);
const
  // Minimum number of 16-byte blocks before the AVX2 4-way kernel pays off
  // over the scalar block step; smaller batches go straight to the scalar
  // tail handler below.
  LMinBlocks = Int32(4);
  // Number of 16-byte blocks consumed per AVX2 kernel iteration (one block
  // per 64-bit lane of a 256-bit ymm); used to round the dispatch count
  // down to a multiple supported by the kernel.
  LLaneCount = Int32(4);
var
  LSimdBlocks: Int32;
begin
  if ANumBlocks >= LMinBlocks then
  begin
    LSimdBlocks := ANumBlocks and not (LLaneCount - 1);
    Poly1305BlocksBulkAvx2Core(@AState, APowTable, @ABuf[AOff],
      NativeUInt(LSimdBlocks) * 16, 1);
    AOff := AOff + LSimdBlocks * 16;
    ANumBlocks := ANumBlocks - LSimdBlocks;
  end;
  if ANumBlocks > 0 then
    Poly1305StateProcessBlocksScalar(AState, ABuf, AOff, ANumBlocks);
end;

{$ENDIF CRYPTOLIB_X86_SIMD}

{ TPoly1305 ---------------------------------------------------------------- }

constructor TPoly1305.Create();
begin
  inherited Create();
  FCipher := nil;
  FPowTable := nil;
  System.SetLength(FCurrentBlock, BlockSize);
end;

constructor TPoly1305.Create(const ACipher: IBlockCipher);
begin
  inherited Create();
  if ACipher.GetBlockSize() <> BlockSize then
    raise EArgumentCryptoLibException.CreateRes(@SCipherBlockSizeMismatch);
  FCipher := ACipher;
  FPowTable := nil;
  System.SetLength(FCurrentBlock, BlockSize);
end;

procedure TPoly1305.Init(const AParameters: ICipherParameters);
var
  LNonce: TCryptoLibByteArray;
  LIvParams: IParametersWithIV;
  LKeyParameter: IKeyParameter;
  LParams: ICipherParameters;
begin
  LNonce := nil;
  LParams := AParameters;

  if FCipher <> nil then
  begin
    if not Supports(LParams, IParametersWithIV, LIvParams) then
      raise EArgumentCryptoLibException.CreateRes(@SParametersWithIVRequired);
    LNonce := LIvParams.GetIV();
    LParams := LIvParams.Parameters;
  end;

  if not Supports(LParams, IKeyParameter, LKeyParameter) then
    raise EArgumentCryptoLibException.CreateRes(@SKeyParameterRequired);

  SetKey(LKeyParameter, LNonce);
  Reset();
end;

procedure TPoly1305.SetKey(const AKeyParameter: IKeyParameter;
  const ANonce: TCryptoLibByteArray);
var
  LKey, LKBytes: TCryptoLibByteArray;
begin
  LKey := AKeyParameter.GetKey();
  if System.Length(LKey) <> 32 then
    raise EArgumentCryptoLibException.CreateRes(@SInvalidKeyLength);

  if (FCipher <> nil) and
    ((ANonce = nil) or (System.Length(ANonce) <> BlockSize)) then
    raise EArgumentCryptoLibException.CreateRes(@SInvalidNonce);

  Poly1305StateAbsorbR(FState, LKey);

  if FCipher = nil then
    Poly1305StateAbsorbS(FState, LKey, BlockSize)
  else
  begin
    System.SetLength(LKBytes, BlockSize);
    FCipher.Init(True, TKeyParameter.Create(LKey, BlockSize, BlockSize)
      as IKeyParameter);
    FCipher.ProcessBlock(ANonce, 0, LKBytes, 0);
    Poly1305StateAbsorbS(FState, LKBytes, 0);
  end;

  // Pre-build any SIMD-specific lookup tables for this key, and use the
  // (non-)allocation of FPowTable as the dispatch flag for BlockUpdate.
  // Reset to nil first so the scalar path is the postcondition when no
  // SIMD branch matches. To add a new SIMD variant: add a parallel
  // `if Has<Feature>()` branch here that delegates to its initializer
  // (which owns sizing + layout), ordered most-capable first.
  FPowTable := nil;
{$IFDEF CRYPTOLIB_X86_SIMD}
  if TCpuFeatures.X86.HasAVX2() then
    Poly1305Avx2InitPowerTable(FPowTable, FState);
{$ENDIF}
end;

function TPoly1305.GetAlgorithmName: String;
begin
  if FCipher = nil then
    Result := 'Poly1305'
  else
    Result := 'Poly1305-' + FCipher.AlgorithmName;
end;

function TPoly1305.GetMacSize: Int32;
begin
  Result := BlockSize;
end;

procedure TPoly1305.Update(AInput: Byte);
begin
  FCurrentBlock[FCurrentBlockOffset] := AInput;
  System.Inc(FCurrentBlockOffset);
  if FCurrentBlockOffset = BlockSize then
  begin
    Poly1305StateProcessBlock(FState, FCurrentBlock, 0);
    FCurrentBlockOffset := 0;
  end;
end;

procedure TPoly1305.BlockUpdate(const AInput: TCryptoLibByteArray;
  AInOff, ALen: Int32);
var
  LAvailable, LPos, LRemaining, LNb, LBulkBytes: Int32;
begin
  TCheck.DataLength(AInput, AInOff, ALen, 'input buffer too short');

  LAvailable := BlockSize - FCurrentBlockOffset;
  if ALen < LAvailable then
  begin
    System.Move(AInput[AInOff], FCurrentBlock[FCurrentBlockOffset],
      ALen * System.SizeOf(Byte));
    FCurrentBlockOffset := FCurrentBlockOffset + ALen;
    Exit;
  end;

  LPos := 0;
  if FCurrentBlockOffset > 0 then
  begin
    System.Move(AInput[AInOff], FCurrentBlock[FCurrentBlockOffset],
      LAvailable * System.SizeOf(Byte));
    LPos := LAvailable;
    Poly1305StateProcessBlock(FState, FCurrentBlock, 0);
    FCurrentBlockOffset := 0;
  end;

  LRemaining := ALen - LPos;
  LNb := LRemaining shr 4;

  if LNb > 0 then
  begin
    LBulkBytes := LNb shl 4;
  {$IFDEF CRYPTOLIB_X86_SIMD}
    if (FPowTable <> nil) and TCpuFeatures.X86.HasAVX2() then
      Poly1305ProcessBlocksAvx2(FState, PByte(FPowTable), AInput,
        AInOff + LPos, LNb)
    else
  {$ENDIF}
      Poly1305StateProcessBlocksScalar(FState, AInput, AInOff + LPos, LNb);
    LPos := LPos + LBulkBytes;
    LRemaining := ALen - LPos;
  end;

  System.Move(AInput[AInOff + LPos], FCurrentBlock[0],
    LRemaining * System.SizeOf(Byte));
  FCurrentBlockOffset := LRemaining;
end;

procedure TPoly1305.ProcessBlock(const ABuf: TCryptoLibByteArray; AOff: Int32);
begin
  Poly1305StateProcessBlock(FState, ABuf, AOff);
end;

function TPoly1305.DoFinal(const AOutput: TCryptoLibByteArray;
  AOutOff: Int32): Int32;
var
  LC: Int64;
begin
  TCheck.OutputLength(AOutput, AOutOff, BlockSize, 'output buffer too short');

  if FCurrentBlockOffset > 0 then
  begin
    if FCurrentBlockOffset < BlockSize then
    begin
      FCurrentBlock[FCurrentBlockOffset] := 1;
      System.Inc(FCurrentBlockOffset);
      while FCurrentBlockOffset < BlockSize do
      begin
        FCurrentBlock[FCurrentBlockOffset] := 0;
        System.Inc(FCurrentBlockOffset);
      end;
      FState.H4 := FState.H4 - (UInt32(1) shl 24);
    end;
    Poly1305StateProcessBlock(FState, FCurrentBlock, 0);
  end;

  FState.H0 := FState.H0 + 5;
  FState.H1 := FState.H1 + (FState.H0 shr 26);
  FState.H0 := FState.H0 and $3FFFFFF;
  FState.H2 := FState.H2 + (FState.H1 shr 26);
  FState.H1 := FState.H1 and $3FFFFFF;
  FState.H3 := FState.H3 + (FState.H2 shr 26);
  FState.H2 := FState.H2 and $3FFFFFF;
  FState.H4 := FState.H4 + (FState.H3 shr 26);
  FState.H3 := FState.H3 and $3FFFFFF;

  LC := Int64(Int32(FState.H4 shr 26) - 1) * 5;
  LC := LC + Int64(FState.K0) + Int64(FState.H0 or (FState.H1 shl 26));
  TPack.UInt32_To_LE(UInt32(LC), AOutput, AOutOff);
  LC := TBitOperations.Asr64(LC, 32);
  LC := LC + Int64(FState.K1) + Int64((FState.H1 shr 6) or (FState.H2 shl 20));
  TPack.UInt32_To_LE(UInt32(LC), AOutput, AOutOff + 4);
  LC := TBitOperations.Asr64(LC, 32);
  LC := LC + Int64(FState.K2) + Int64((FState.H2 shr 12) or (FState.H3 shl 14));
  TPack.UInt32_To_LE(UInt32(LC), AOutput, AOutOff + 8);
  LC := TBitOperations.Asr64(LC, 32);
  LC := LC + Int64(FState.K3) + Int64((FState.H3 shr 18) or (FState.H4 shl 8));
  TPack.UInt32_To_LE(UInt32(LC), AOutput, AOutOff + 12);

  Reset();
  Result := BlockSize;
end;

procedure TPoly1305.Reset();
begin
  FCurrentBlockOffset := 0;
  TArrayUtilities.Fill<Byte>(FCurrentBlock, 0, System.Length(FCurrentBlock), Byte(0));
  Poly1305StateReset(FState);
end;

end.
