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

unit ClpPoly1305X86Backend;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpPoly1305State,
  ClpCpuFeatures,
  ClpSimdLevels,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// x86 SIMD backend for Poly1305: owns the AVX2 power-table builder and the
  /// 4-way bulk kernel (body in <c>Include\Simd\Poly1305\</c>) plus the runtime
  /// tier selection via <c>TCpuFeatures.X86.SelectSlot</c>. Compiles on every
  /// target - when built without x86 SIMD <c>TryInitPowerTable</c> returns
  /// <c>False</c> (leaving the caller on the scalar path) and <c>ProcessBulk</c>
  /// consumes zero blocks.
  /// </summary>
  TPoly1305X86Backend = class sealed
  public
    /// <summary>
    /// If a SIMD tier is available, (re)allocate and populate <paramref name="APowTable"/>
    /// with the precomputed power table for the r currently in
    /// <paramref name="AState"/>, and return True. Otherwise leave
    /// <paramref name="APowTable"/> untouched and return False.
    /// </summary>
    class function TryInitPowerTable(var APowTable: TCryptoLibByteArray;
      const AState: TPoly1305State): Boolean; static;
    /// <summary>
    /// Process the leading lane-multiple of <paramref name="ANumBlocks"/> 16-byte
    /// blocks with the AVX2 kernel and return the number of blocks consumed
    /// (a multiple of the lane count). Returns 0 - leaving the whole batch to the
    /// caller's scalar path - when no power table is present, fewer than one lane
    /// of blocks is available, or the build has no x86 SIMD.
    /// </summary>
    class function ProcessBulk(var AState: TPoly1305State; APowTable: PByte;
      const ABuf: TCryptoLibByteArray; AOff, ANumBlocks: Int32): Int32; static;
  end;

implementation

{$IFDEF CRYPTOLIB_X86_SIMD}

// Multiply two 5-limb radix-2^26 numbers ALhs, ARhs modulo 2^130-5,
// returning the 5-limb result in AProduct. Same field arithmetic as the
// inner step of Poly1305StateProcessBlock; used here at SetKey time to
// derive r^2..r^4 for the AVX2 power table.
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
// once after AState.R0..R4 is populated and before the first invocation of
// the bulk kernel for the same key. The exact buffer size and limb layout
// are private to this routine.
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

// (Re)allocate APowTable and pack r^1, r^2 for the 2-way SSE2 bulk kernel.
// 160 bytes = 10 rows x 4 dwords. Rows 0..4 hold limbs of [r^2, r^2, r^2, r^1]
// (so a broadcast load gives r^2 in both 64-bit lanes and a +4 shifted load
// gives [r^2, r^1]); rows 5..8 hold the 5x wraparound multipliers; row 9 is
// padding for the +4 over-read of the last shifted load.
procedure Poly1305Sse2InitPowerTable(var APowTable: TCryptoLibByteArray;
  const AState: TPoly1305State);
const
  TableSize = Int32(160);
type
  TPowTableLayout = array[0..9, 0..3] of UInt32;
  PPowTableLayout = ^TPowTableLayout;
var
  LTbl: PPowTableLayout;
  Lr1, Lr2: array[0..4] of UInt32;
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

  for LIdx := 0 to 4 do
  begin
    LTbl^[LIdx, 0] := Lr2[LIdx];
    LTbl^[LIdx, 1] := Lr2[LIdx];
    LTbl^[LIdx, 2] := Lr2[LIdx];
    LTbl^[LIdx, 3] := Lr1[LIdx];
  end;

  for LRow := 5 to 8 do
  begin
    LJ := LRow - 4; // 1..4
    LTbl^[LRow, 0] := Lr2[LJ] * 5;
    LTbl^[LRow, 1] := Lr2[LJ] * 5;
    LTbl^[LRow, 2] := Lr2[LJ] * 5;
    LTbl^[LRow, 3] := Lr1[LJ] * 5;
  end;

  for LIdx := 0 to 3 do
    LTbl^[9, LIdx] := 0;
end;

// AVX2 4-way bulk kernel (r^1..r^4 power table, 64-byte stride).
procedure Poly1305BlocksBulkAvx2Core(ACtx, APowTable, AInp: PByte;
  ALen: NativeUInt; APad: Int32);
{$IFDEF CRYPTOLIB_X86_64_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc5Begin_x86_64.inc}
{$I ..\..\Include\Simd\Poly1305\Poly1305BlocksBulkAvx2Core_x86_64.inc}
{$ENDIF}
{$IFDEF CRYPTOLIB_I386_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc5Begin_i386.inc}
{$I ..\..\Include\Simd\Poly1305\Poly1305BlocksBulkAvx2Core_i386.inc}
{$ENDIF}
end;

// SSE2 2-way bulk kernel (r/r^2 power table, 32-byte stride).
procedure Poly1305BlocksBulkSse2Core(ACtx, APowTable, AInp: PByte;
  ALen: NativeUInt; APad: Int32);
{$IFDEF CRYPTOLIB_X86_64_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc5Begin_x86_64.inc}
{$I ..\..\Include\Simd\Poly1305\Poly1305BlocksBulkSse2Core_x86_64.inc}
{$ENDIF}
{$IFDEF CRYPTOLIB_I386_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc5Begin_i386.inc}
{$I ..\..\Include\Simd\Poly1305\Poly1305BlocksBulkSse2Core_i386.inc}
{$ENDIF}
end;

{$ENDIF CRYPTOLIB_X86_SIMD}

{ TPoly1305X86Backend }

class function TPoly1305X86Backend.TryInitPowerTable(var APowTable: TCryptoLibByteArray;
  const AState: TPoly1305State): Boolean;
begin
{$IFDEF CRYPTOLIB_X86_SIMD}
  case TCpuFeatures.X86.SelectSlot([TX86SimdLevel.AVX2, TX86SimdLevel.SSE2]) of
    TX86SimdLevel.AVX2:
    begin
      Poly1305Avx2InitPowerTable(APowTable, AState);
      Exit(True);
    end;
    TX86SimdLevel.SSE2:
    begin
      Poly1305Sse2InitPowerTable(APowTable, AState);
      Exit(True);
    end;
  end;
{$ENDIF}
  Result := False;
end;

class function TPoly1305X86Backend.ProcessBulk(var AState: TPoly1305State; APowTable: PByte;
  const ABuf: TCryptoLibByteArray; AOff, ANumBlocks: Int32): Int32;
{$IFDEF CRYPTOLIB_X86_SIMD}
var
  LSimdBlocks: Int32;
{$ENDIF}
begin
{$IFDEF CRYPTOLIB_X86_SIMD}
  if (APowTable = nil) then
    Exit(0);
  // The tier is re-selected here; SelectSlot is deterministic, so it matches the
  // one TryInitPowerTable built the power table for. AVX2 consumes 4 blocks per
  // iteration, SSE2 2; both need at least one lane's worth to pay off.
  case TCpuFeatures.X86.SelectSlot([TX86SimdLevel.AVX2, TX86SimdLevel.SSE2]) of
    TX86SimdLevel.AVX2:
    begin
      if ANumBlocks < 4 then
        Exit(0);
      LSimdBlocks := ANumBlocks and not 3;
      Poly1305BlocksBulkAvx2Core(@AState, APowTable, @ABuf[AOff],
        NativeUInt(LSimdBlocks) * 16, 1);
      Exit(LSimdBlocks);
    end;
    TX86SimdLevel.SSE2:
    begin
      if ANumBlocks < 2 then
        Exit(0);
      LSimdBlocks := ANumBlocks and not 1;
      Poly1305BlocksBulkSse2Core(@AState, APowTable, @ABuf[AOff],
        NativeUInt(LSimdBlocks) * 16, 1);
      Exit(LSimdBlocks);
    end;
  end;
{$ENDIF}
  Result := 0;
end;

end.
