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

unit ClpGhashArmBackend;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpCpuFeatures,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// AArch64 SIMD backend for the GHASH / GF(2^128) field operations behind
  /// <c>TGcmUtilities</c>: owns the PMULL GHASH kernels (bodies in
  /// <c>Include\Simd\Gcm\</c>) and the runtime capability gates. Compiles on
  /// every target - every entry point returns <c>False</c> (leaving the caller on
  /// its scalar reference path) when built without AArch64 SIMD or on a CPU
  /// lacking the Crypto Extensions. All entry points work on raw pointers (the
  /// kernel ABI), so this unit carries no dependency on the field-element record.
  /// Byte-compatible with the x86 backend: same state, limb and table formats.
  /// </summary>
  TGhashArmBackend = class sealed
  public
    /// <summary>PMULL carryless multiply-reduce: <c>PX := PX * PY</c> in GF(2^128).</summary>
    class function TryMultiply(PX, PY: Pointer): Boolean; static;
    /// <summary>PMULL carryless multiply to three 128-bit limbs (48 bytes).</summary>
    class function TryMultiplyExt(PX, PY, POut48: PByte): Boolean; static;
    /// <summary>SIMD fold + reduce of three 128-bit limbs into one block.</summary>
    class function TryReduce3(PZ0, PZ1, PZ2, PSVector16: PByte): Boolean; static;
    /// <summary>SIMD xor of three 16-byte limbs with three slices of a 48-byte MultiplyExt output.</summary>
    class function TryXorMultiplyExtLimbs48(PA0, PA1, PA2, PSrc48: PByte): Boolean; static;
    /// <summary>PMULL fused 4-way GHASH over ABatchCount 64-byte batches.</summary>
    class function TryFusedFourShuffledGhash(PFS, PC0, PHPow64: PByte;
      ABatchCount: NativeInt): Boolean; static;
    /// <summary>PMULL fused 8-way GHASH over ABatchCount 128-byte batches.</summary>
    class function TryFusedEightShuffledGhash(PFS, PC0, PHPow128: PByte;
      ABatchCount: NativeInt): Boolean; static;

    /// <summary>True when the fused shuffled-GHASH path is usable on this CPU. Gates the 4-/8-way batch dispatch and the H-power precompute.</summary>
    class function IsShuffledGhashSupported: Boolean; static;
    /// <summary>True when the PMULL carryless multiply is available (selects the carryless-multiply GCM multiplier over the 4K-table one).</summary>
    class function HasCarrylessMultiply: Boolean; static;
    /// <summary>Full byte-reverse of one 128-bit block from PSrc into PDst; returns False when unavailable on this CPU.</summary>
    class function TryBlockReverse128(PDst, PSrc: PByte): Boolean; static;
  end;

implementation

{$IFDEF CRYPTOLIB_AARCH64_ASM}
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

procedure GcmPmullFieldPartial(PX, PY, POut: Pointer);
{$DEFINE CRYPTOLIB_GCMFIELD_PARTIAL}
{$I ..\..\Include\Simd\Common\ClpSimdProc3Begin_aarch64.inc}
{$I ..\..\Include\Simd\Gcm\GcmFieldOps_aarch64.inc}
{$UNDEF CRYPTOLIB_GCMFIELD_PARTIAL}
end;

procedure GcmPmullMultiplyExtBytes(PX, PY, POut48: Pointer);
{$DEFINE CRYPTOLIB_GCMFIELD_MULTIPLY_EXT}
{$I ..\..\Include\Simd\Common\ClpSimdProc3Begin_aarch64.inc}
{$I ..\..\Include\Simd\Gcm\GcmFieldOps_aarch64.inc}
{$UNDEF CRYPTOLIB_GCMFIELD_MULTIPLY_EXT}
end;

procedure GcmReduce3FoldNeon(PZ0, PZ1, PZ2, POut: Pointer);
{$DEFINE CRYPTOLIB_GCMFIELD_REDUCE3}
{$I ..\..\Include\Simd\Common\ClpSimdProc4Begin_aarch64.inc}
{$I ..\..\Include\Simd\Gcm\GcmFieldOps_aarch64.inc}
{$UNDEF CRYPTOLIB_GCMFIELD_REDUCE3}
end;

procedure GcmXorMultiplyExtLimbs48Neon(PA0, PA1, PA2, PSrc48: Pointer);
{$DEFINE CRYPTOLIB_GCMFIELD_XOR_LIMBS48}
{$I ..\..\Include\Simd\Common\ClpSimdProc4Begin_aarch64.inc}
{$I ..\..\Include\Simd\Gcm\GcmFieldOps_aarch64.inc}
{$UNDEF CRYPTOLIB_GCMFIELD_XOR_LIMBS48}
end;

procedure GcmGhashFourFull(PFS, PC0, PHPow64: Pointer; ABatchCount: NativeInt);
{$DEFINE GCM_GHASH_FULL_BLOCKS_4}
{$I ..\..\Include\Simd\Common\ClpSimdProc4Begin_aarch64.inc}
{$I ..\..\Include\Simd\Gcm\GcmGhashFull_aarch64.inc}
{$UNDEF GCM_GHASH_FULL_BLOCKS_4}
end;

procedure GcmGhashEightFull(PFS, PC0, PHPow128: Pointer; ABatchCount: NativeInt);
{$DEFINE GCM_GHASH_FULL_BLOCKS_8}
{$I ..\..\Include\Simd\Common\ClpSimdProc4Begin_aarch64.inc}
{$I ..\..\Include\Simd\Gcm\GcmGhashFull_aarch64.inc}
{$UNDEF GCM_GHASH_FULL_BLOCKS_8}
end;

procedure GcmBlockReverse128Neon(PDst, PSrc: PByte);
{$DEFINE CRYPTOLIB_GCMFIELD_BLOCK_REVERSE}
{$I ..\..\Include\Simd\Common\ClpSimdProc2Begin_aarch64.inc}
{$I ..\..\Include\Simd\Gcm\GcmFieldOps_aarch64.inc}
{$UNDEF CRYPTOLIB_GCMFIELD_BLOCK_REVERSE}
end;

// Scalar reduction of the 256-bit carryless product produced by
// GcmPmullFieldPartial into a 128-bit field element (radix-free bit reflection
// reduction modulo the GCM polynomial). Pure UInt64 arithmetic; identical to
// the x86 backend's reduction.
procedure GcmPmullReducePartial(const APartial: TGcmPartial128; var AZ: TGcmFieldRaw);
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
{$ENDIF CRYPTOLIB_AARCH64_ASM}

{ TGhashArmBackend }

class function TGhashArmBackend.TryMultiply(PX, PY: Pointer): Boolean;
{$IFDEF CRYPTOLIB_AARCH64_ASM}
var
  LPartial: TGcmPartial128;
{$ENDIF}
begin
{$IFDEF CRYPTOLIB_AARCH64_ASM}
  if TCpuFeatures.Arm.HasPMULL() then
  begin
    GcmPmullFieldPartial(PX, PY, @LPartial);
    GcmPmullReducePartial(LPartial, PGcmFieldRaw(PX)^);
    Exit(True);
  end;
{$ENDIF}
  Result := False;
end;

class function TGhashArmBackend.TryMultiplyExt(PX, PY, POut48: PByte): Boolean;
begin
{$IFDEF CRYPTOLIB_AARCH64_ASM}
  if TCpuFeatures.Arm.HasPMULL() then
  begin
    GcmPmullMultiplyExtBytes(PX, PY, POut48);
    Exit(True);
  end;
{$ENDIF}
  Result := False;
end;

class function TGhashArmBackend.TryReduce3(PZ0, PZ1, PZ2, PSVector16: PByte): Boolean;
begin
{$IFDEF CRYPTOLIB_AARCH64_ASM}
  if TCpuFeatures.Arm.HasNEON() then
  begin
    GcmReduce3FoldNeon(PZ0, PZ1, PZ2, PSVector16);
    Exit(True);
  end;
{$ENDIF}
  Result := False;
end;

class function TGhashArmBackend.TryXorMultiplyExtLimbs48(PA0, PA1, PA2, PSrc48: PByte): Boolean;
begin
{$IFDEF CRYPTOLIB_AARCH64_ASM}
  if TCpuFeatures.Arm.HasNEON() then
  begin
    GcmXorMultiplyExtLimbs48Neon(PA0, PA1, PA2, PSrc48);
    Exit(True);
  end;
{$ENDIF}
  Result := False;
end;

class function TGhashArmBackend.TryFusedFourShuffledGhash(PFS, PC0, PHPow64: PByte;
  ABatchCount: NativeInt): Boolean;
begin
{$IFDEF CRYPTOLIB_AARCH64_ASM}
  if TCpuFeatures.Arm.HasPMULL() then
  begin
    // Monolithic kernel: the whole ABatchCount-batch run - byte-reverse, state
    // fold, 4-way multiply-accumulate and folding reduction per batch - in a
    // single assembly body (one call boundary).
    GcmGhashFourFull(PFS, PC0, PHPow64, ABatchCount);
    Exit(True);
  end;
{$ENDIF}
  Result := False;
end;

class function TGhashArmBackend.TryFusedEightShuffledGhash(PFS, PC0, PHPow128: PByte;
  ABatchCount: NativeInt): Boolean;
begin
{$IFDEF CRYPTOLIB_AARCH64_ASM}
  if TCpuFeatures.Arm.HasPMULL() then
  begin
    // Monolithic kernel: the whole ABatchCount-batch run - byte-reverse, state
    // fold, 8-way multiply-accumulate and folding reduction per batch - in a
    // single assembly body (one call boundary).
    GcmGhashEightFull(PFS, PC0, PHPow128, ABatchCount);
    Exit(True);
  end;
{$ENDIF}
  Result := False;
end;

class function TGhashArmBackend.IsShuffledGhashSupported: Boolean;
begin
{$IFDEF CRYPTOLIB_AARCH64_ASM}
  Result := TCpuFeatures.Arm.HasPMULL();
{$ELSE}
  Result := False;
{$ENDIF}
end;

class function TGhashArmBackend.HasCarrylessMultiply: Boolean;
begin
{$IFDEF CRYPTOLIB_AARCH64_ASM}
  Result := TCpuFeatures.Arm.HasPMULL();
{$ELSE}
  Result := False;
{$ENDIF}
end;

class function TGhashArmBackend.TryBlockReverse128(PDst, PSrc: PByte): Boolean;
begin
{$IFDEF CRYPTOLIB_AARCH64_ASM}
  if TCpuFeatures.Arm.HasNEON() then
  begin
    GcmBlockReverse128Neon(PDst, PSrc);
    Exit(True);
  end;
{$ENDIF}
  Result := False;
end;

end.
