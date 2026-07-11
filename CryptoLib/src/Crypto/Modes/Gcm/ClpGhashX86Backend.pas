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

unit ClpGhashX86Backend;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpCpuFeatures,
  ClpIntrinsicsVector,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// x86 SIMD backend for the GHASH / GF(2^128) field operations behind
  /// <c>TGcmUtilities</c>: owns the SIMD GHASH kernels (bodies in
  /// <c>Include\Simd\Gcm\</c>) and the runtime capability gates. Compiles on
  /// every target - every entry point returns <c>False</c> (leaving the caller on
  /// its scalar reference path) when built without x86 SIMD or on a CPU lacking
  /// the required instruction set. All entry points work on raw pointers (the
  /// kernel ABI), so this unit carries no dependency on the field-element record.
  /// </summary>
  TGhashX86Backend = class sealed
  public
    /// <summary>PCLMULQDQ carryless multiply-reduce: <c>PX := PX * PY</c> in GF(2^128).</summary>
    class function TryMultiply(PX, PY: Pointer): Boolean; static;
    /// <summary>PCLMULQDQ carryless multiply to three 128-bit limbs (48 bytes).</summary>
    class function TryMultiplyExt(PX, PY, POut48: PByte): Boolean; static;
    /// <summary>SIMD fold + reduce of three 128-bit limbs into one block.</summary>
    class function TryReduce3(PZ0, PZ1, PZ2, PSVector16: PByte): Boolean; static;
    /// <summary>SIMD xor of three 16-byte limbs with three slices of a 48-byte MultiplyExt output.</summary>
    class function TryXorMultiplyExtLimbs48(PA0, PA1, PA2, PSrc48: PByte): Boolean; static;
    /// <summary>PCLMULQDQ fused 4-way GHASH over ABatchCount 64-byte batches (requires packed vector layout). Uses the backend's own byte-reverse mask.</summary>
    class function TryFusedFourShuffledGhash(PFS, PC0, PHPow64: PByte;
      ABatchCount: NativeInt): Boolean; static;
    /// <summary>PCLMULQDQ fused 8-way GHASH over ABatchCount 128-byte batches (requires packed vector layout). Uses the backend's own byte-reverse mask.</summary>
    class function TryFusedEightShuffledGhash(PFS, PC0, PHPow128: PByte;
      ABatchCount: NativeInt): Boolean; static;

    /// <summary>True when the fused shuffled-GHASH path is usable on this CPU (needs packed vector layout). Gates the 4-/8-way batch dispatch and the H-power precompute.</summary>
    class function IsShuffledGhashSupported: Boolean; static;
    /// <summary>True when the PCLMULQDQ carryless multiply is available (selects the carryless-multiply GCM multiplier over the 4K-table one).</summary>
    class function HasCarrylessMultiply: Boolean; static;
    /// <summary>Full byte-reverse of one 128-bit block from PSrc into PDst; returns False when unavailable on this CPU.</summary>
    class function TryBlockReverse128(PDst, PSrc: PByte): Boolean; static;
  end;

implementation

{$IFDEF CRYPTOLIB_X86_SIMD}
type
  TGcmPartial128 = record
    T3, T2, T1, T0: UInt64;
  end;

  // Raw two-limb GF(2^128) field element, layout-compatible with the caller's
  // field-element record (N0 at offset 0, N1 at offset 8). Used only to write the
  // reduced product back through the caller-supplied pointer without depending on
  // the field-element type declared in ClpGcmUtilities.
  TGcmFieldRaw = record
    N0, N1: UInt64;
  end;
  PGcmFieldRaw = ^TGcmFieldRaw;

procedure GcmPclmulFieldPartial(PX, PY, POut: Pointer);
{$IFDEF CRYPTOLIB_X86_64_ASM}
{$I ..\..\..\Include\Simd\Common\ClpSimdProc3Begin_x86_64.inc}
{$I ..\..\..\Include\Simd\Gcm\GcmPclmulPartial_x86_64.inc}
{$ENDIF}
{$IFDEF CRYPTOLIB_I386_ASM}
{$I ..\..\..\Include\Simd\Common\ClpSimdProc3Begin_i386.inc}
{$I ..\..\..\Include\Simd\Gcm\GcmPclmulPartial_i386.inc}
{$ENDIF}
end;

procedure GcmPclmulMultiplyExtBytes(PX, PY, POut48: Pointer);
{$IFDEF CRYPTOLIB_X86_64_ASM}
{$I ..\..\..\Include\Simd\Common\ClpSimdProc3Begin_x86_64.inc}
{$I ..\..\..\Include\Simd\Gcm\GcmPclmulMultiplyExt_x86_64.inc}
{$ENDIF}
{$IFDEF CRYPTOLIB_I386_ASM}
{$I ..\..\..\Include\Simd\Common\ClpSimdProc3Begin_i386.inc}
{$I ..\..\..\Include\Simd\Gcm\GcmPclmulMultiplyExt_i386.inc}
{$ENDIF}
end;

procedure GcmReduce3FoldSse2(PZ0, PZ1, PZ2, POut: Pointer);
{$IFDEF CRYPTOLIB_X86_64_ASM}
{$I ..\..\..\Include\Simd\Common\ClpSimdProc4Begin_x86_64.inc}
{$I ..\..\..\Include\Simd\Gcm\GcmReduce3FoldSse2_x86_64.inc}
{$ENDIF}
{$IFDEF CRYPTOLIB_I386_ASM}
{$I ..\..\..\Include\Simd\Common\ClpSimdProc4Begin_i386.inc}
{$I ..\..\..\Include\Simd\Gcm\GcmReduce3FoldSse2_i386.inc}
{$ENDIF}
end;

procedure GcmXorMultiplyExtLimbs48Sse2(PA0, PA1, PA2, PSrc48: Pointer);
{$IFDEF CRYPTOLIB_X86_64_ASM}
{$I ..\..\..\Include\Simd\Common\ClpSimdProc4Begin_x86_64.inc}
{$I ..\..\..\Include\Simd\Gcm\GcmXorMultiplyExtLimbs48Sse2_x86_64.inc}
{$ENDIF}
{$IFDEF CRYPTOLIB_I386_ASM}
{$I ..\..\..\Include\Simd\Common\ClpSimdProc4Begin_i386.inc}
{$I ..\..\..\Include\Simd\Gcm\GcmXorMultiplyExtLimbs48Sse2_i386.inc}
{$ENDIF}
end;

procedure GcmGhashFourFull(PFS, PC0, PHPow64, PMask: Pointer; ABatchCount: NativeInt);
{$DEFINE GCM_GHASH_FULL_BLOCKS_4}
{$IFDEF CRYPTOLIB_X86_64_ASM}
{$I ..\..\..\Include\Simd\Common\ClpSimdProc5Begin_x86_64.inc}
{$I ..\..\..\Include\Simd\Gcm\GcmGhashFull_x86_64.inc}
{$ENDIF}
{$IFDEF CRYPTOLIB_I386_ASM}
{$I ..\..\..\Include\Simd\Common\ClpSimdProc5Begin_i386.inc}
{$I ..\..\..\Include\Simd\Gcm\GcmGhashFull_i386.inc}
{$ENDIF}
{$UNDEF GCM_GHASH_FULL_BLOCKS_4}
end;

procedure GcmGhashEightFull(PFS, PC0, PHPow128, PMask: Pointer; ABatchCount: NativeInt);
{$DEFINE GCM_GHASH_FULL_BLOCKS_8}
{$IFDEF CRYPTOLIB_X86_64_ASM}
{$I ..\..\..\Include\Simd\Common\ClpSimdProc5Begin_x86_64.inc}
{$I ..\..\..\Include\Simd\Gcm\GcmGhashFull_x86_64.inc}
{$ENDIF}
{$IFDEF CRYPTOLIB_I386_ASM}
{$I ..\..\..\Include\Simd\Common\ClpSimdProc5Begin_i386.inc}
{$I ..\..\..\Include\Simd\Gcm\GcmGhashFull_i386.inc}
{$ENDIF}
{$UNDEF GCM_GHASH_FULL_BLOCKS_8}
end;

const
  // Byte-reverse shuffle control shared by the block byte-reverse and the fused
  // shuffled-GHASH kernels. Owned here (not by the mode) - it is a SIMD
  // implementation detail.
  ReverseBytesMask: packed array[0..15] of Byte = (
    $0F, $0E, $0D, $0C, $0B, $0A, $09, $08, $07, $06, $05, $04, $03, $02, $01, $00);

procedure GcmBlockReverse128Ssse3(PDst, PSrc, PMask: PByte);
{$IFDEF CRYPTOLIB_X86_64_ASM}
{$I ..\..\..\Include\Simd\Common\ClpSimdProc3Begin_x86_64.inc}
{$I ..\..\..\Include\Simd\Gcm\GcmBlockReverse128Ssse3_x86_64.inc}
{$ENDIF}
{$IFDEF CRYPTOLIB_I386_ASM}
{$I ..\..\..\Include\Simd\Common\ClpSimdProc3Begin_i386.inc}
{$I ..\..\..\Include\Simd\Gcm\GcmBlockReverse128Ssse3_i386.inc}
{$ENDIF}
end;

// Scalar reduction of the 256-bit carryless product produced by
// GcmPclmulFieldPartial into a 128-bit field element (radix-free bit reflection
// reduction modulo the GCM polynomial). Pure UInt64 arithmetic.
procedure GcmPclmulReducePartial(const APartial: TGcmPartial128; var AZ: TGcmFieldRaw);
var
  LT3, LT2, LT1, LT0: UInt64;
  LZ0, LZ1, LZ2: UInt64;
begin
  LT3 := APartial.T3;
  LT2 := APartial.T2;
  LT1 := APartial.T1;
  LT0 := APartial.T0;
  LT1 := LT1 xor LT3 xor (LT3 shr 1) xor (LT3 shr 2) xor (LT3 shr 7);
  LT2 := LT2 xor (LT3 shl 63) xor (LT3 shl 62) xor (LT3 shl 57);
  LZ0 := (LT0 shl 1) or (LT1 shr 63);
  LZ1 := (LT1 shl 1) or (LT2 shr 63);
  LZ2 := LT2 shl 1;
  LZ0 := LZ0 xor LZ2 xor (LZ2 shr 1) xor (LZ2 shr 2) xor (LZ2 shr 7);
  LZ1 := LZ1 xor (LT2 shl 63) xor (LT2 shl 58);
  AZ.N0 := LZ0;
  AZ.N1 := LZ1;
end;
{$ENDIF CRYPTOLIB_X86_SIMD}

{ TGhashX86Backend }

class function TGhashX86Backend.TryMultiply(PX, PY: Pointer): Boolean;
{$IFDEF CRYPTOLIB_X86_SIMD}
var
  LPartial: TGcmPartial128;
{$ENDIF}
begin
{$IFDEF CRYPTOLIB_X86_SIMD}
  if TCpuFeatures.X86.HasPCLMULQDQ then
  begin
    GcmPclmulFieldPartial(PX, PY, @LPartial);
    GcmPclmulReducePartial(LPartial, PGcmFieldRaw(PX)^);
    Exit(True);
  end;
{$ENDIF}
  Result := False;
end;

class function TGhashX86Backend.TryMultiplyExt(PX, PY, POut48: PByte): Boolean;
begin
{$IFDEF CRYPTOLIB_X86_SIMD}
  if TCpuFeatures.X86.HasPCLMULQDQ then
  begin
    GcmPclmulMultiplyExtBytes(PX, PY, POut48);
    Exit(True);
  end;
{$ENDIF}
  Result := False;
end;

class function TGhashX86Backend.TryReduce3(PZ0, PZ1, PZ2, PSVector16: PByte): Boolean;
begin
{$IFDEF CRYPTOLIB_X86_SIMD}
  if TCpuFeatures.X86.HasSSE2 then
  begin
    GcmReduce3FoldSse2(PZ0, PZ1, PZ2, PSVector16);
    Exit(True);
  end;
{$ENDIF}
  Result := False;
end;

class function TGhashX86Backend.TryXorMultiplyExtLimbs48(PA0, PA1, PA2, PSrc48: PByte): Boolean;
begin
{$IFDEF CRYPTOLIB_X86_SIMD}
  if TCpuFeatures.X86.HasSSE2 then
  begin
    GcmXorMultiplyExtLimbs48Sse2(PA0, PA1, PA2, PSrc48);
    Exit(True);
  end;
{$ENDIF}
  Result := False;
end;

class function TGhashX86Backend.TryFusedFourShuffledGhash(PFS, PC0, PHPow64: PByte;
  ABatchCount: NativeInt): Boolean;
begin
{$IFDEF CRYPTOLIB_X86_SIMD}
  if TCpuFeatures.X86.HasSSSE3 and TCpuFeatures.X86.HasPCLMULQDQ and TIntrinsicsVector.IsPacked then
  begin
    // Monolithic kernel: the whole ABatchCount-batch run - byte-reverse, state
    // fold, 4-way multiply-accumulate and folding reduction per batch - in a
    // single assembly body (one call boundary).
    GcmGhashFourFull(PFS, PC0, PHPow64, @ReverseBytesMask[0], ABatchCount);
    Exit(True);
  end;
{$ENDIF}
  Result := False;
end;

class function TGhashX86Backend.TryFusedEightShuffledGhash(PFS, PC0, PHPow128: PByte;
  ABatchCount: NativeInt): Boolean;
begin
{$IFDEF CRYPTOLIB_X86_SIMD}
  if TCpuFeatures.X86.HasSSSE3 and TCpuFeatures.X86.HasPCLMULQDQ and TIntrinsicsVector.IsPacked then
  begin
    // Monolithic kernel: the whole ABatchCount-batch run - byte-reverse, state
    // fold, 8-way multiply-accumulate and folding reduction per batch - in a
    // single assembly body (one call boundary).
    GcmGhashEightFull(PFS, PC0, PHPow128, @ReverseBytesMask[0], ABatchCount);
    Exit(True);
  end;
{$ENDIF}
  Result := False;
end;

class function TGhashX86Backend.IsShuffledGhashSupported: Boolean;
begin
{$IFDEF CRYPTOLIB_X86_SIMD}
  Result := TCpuFeatures.X86.HasPCLMULQDQ and TCpuFeatures.X86.HasSSSE3 and
    TIntrinsicsVector.IsPacked;
{$ELSE}
  Result := False;
{$ENDIF}
end;

class function TGhashX86Backend.HasCarrylessMultiply: Boolean;
begin
{$IFDEF CRYPTOLIB_X86_SIMD}
  Result := TCpuFeatures.X86.HasPCLMULQDQ;
{$ELSE}
  Result := False;
{$ENDIF}
end;

class function TGhashX86Backend.TryBlockReverse128(PDst, PSrc: PByte): Boolean;
begin
{$IFDEF CRYPTOLIB_X86_SIMD}
  if TCpuFeatures.X86.HasSSSE3 then
  begin
    GcmBlockReverse128Ssse3(PDst, PSrc, @ReverseBytesMask[0]);
    Exit(True);
  end;
{$ENDIF}
  Result := False;
end;

end.
