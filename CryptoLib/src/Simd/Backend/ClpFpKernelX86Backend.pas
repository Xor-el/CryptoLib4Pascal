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

unit ClpFpKernelX86Backend;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
{$IFDEF CRYPTOLIB_X86_SIMD}
  ClpCpuFeatures,
  ClpSimdLevels,
  ClpX86SimdFeatures,
{$ENDIF}
  ClpCryptoLibTypes;

type
  /// <summary>
  /// x86 (i386 + x86-64) big-integer kernel backend for prime-field (Fp)
  /// multiplication/square. A leaf: capability probe plus the hot schoolbook
  /// multiply/square. The arch-neutral dispatch and the scalar fallback live in
  /// <c>TFpKernelSimd</c> / the field units. Hot paths are in
  /// <c>Include/Simd/FpKernel/</c>.
  /// </summary>
  TFpKernelX86Backend = class sealed
  public
    class function IsSupported: Boolean; static; inline;
    class procedure Mul(PX, PY, PZ: PUInt64; ALimbs64: NativeInt); static;
    class procedure Sqr(PX, PZ: PUInt64; ALimbs64: NativeInt); static;
    /// <summary>Fused CIOS Montgomery multiply PR := PA*PB*R^-1 mod p. PCtx =
    /// [n0', N, p[0..N-1]]; PR is the N+2-limb scratch and receives the reduced
    /// N-limb result. Returns False on an arch without the kernel yet (i386).</summary>
    class function MontMul(PR, PA, PB, PCtx: PUInt64): Boolean; static;
    /// <summary>P-256 special-prime Montgomery multiply PR := PA*PB*R^-1 mod p, with
    /// the folded (shift/add) reduction. PCtx = the P-256 [n0'=1, N=4, p0..p3]. Returns
    /// False when BMI2+ADX absent or not x86-64 (caller falls back to generic CIOS).</summary>
    class function MontMulP256(PR, PA, PB, PCtx: PUInt64): Boolean; static;
    /// <summary>Fused P-256 RCB PointDouble PR := 2*PA over homogeneous coords
    /// (PR/PA are TFePoint bases; PCtx = [n0', N, p0..p3] with Fb at a fixed
    /// offset). Returns False when BMI2+ADX absent or not x86-64 (caller falls
    /// back to the generic per-op RCB doubling).</summary>
    class function PointDoubleP256(PR, PA, PCtx: PUInt64): Boolean; static;
    /// <summary>Fused P-256 RCB PointAdd PR := PA + PQ over homogeneous coords
    /// (PR/PA/PQ are TFePoint bases; PCtx = [n0', N, p0..p3] with Fb at a fixed
    /// offset). Returns False when BMI2+ADX absent or not x86-64 (caller falls
    /// back to the generic per-op RCB addition).</summary>
    class function PointAddP256(PR, PA, PQ, PCtx: PUInt64): Boolean; static;
    /// <summary>Fused P-256 RCB PointAddMixed PR := PA + PQ where PQ is a TFeAffine
    /// base (implicit Z2=1, from PCtx.MontOne). False when BMI2+ADX absent or not
    /// x86-64.</summary>
    class function PointAddMixedP256(PR, PA, PQ, PCtx: PUInt64): Boolean; static;
    /// <summary>Constant-time modular add/sub PR := (PA +/- PB) mod p. PCtx =
    /// [n0'(unused), N, p[0..N-1]]; inputs assumed < p. False on arch without it.</summary>
    class function ModAdd(PR, PA, PB, PCtx: PUInt64): Boolean; static;
    class function ModSub(PR, PA, PB, PCtx: PUInt64): Boolean; static;
  end;

implementation

{$IFDEF CRYPTOLIB_X86_SIMD}

procedure FpKernelMulAsm(PX, PY, PZ: PUInt64; ALimbs64: NativeInt);
{$DEFINE CRYPTOLIB_FP_MUL}
{$IFDEF CRYPTOLIB_X86_64_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc4Begin_x86_64.inc}
{$I ..\..\Include\Simd\FpKernel\FpKernel_x86_64.inc}
{$ENDIF}
{$IFDEF CRYPTOLIB_I386_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc4Begin_i386.inc}
{$I ..\..\Include\Simd\FpKernel\FpKernel_i386.inc}
{$ENDIF}
{$UNDEF CRYPTOLIB_FP_MUL}
end;

// Square Z := X^2 (FP_SQR selector).
procedure FpKernelSqrAsm(PX, PZ: PUInt64; ALimbs64: NativeInt);
{$DEFINE CRYPTOLIB_FP_SQR}
{$IFDEF CRYPTOLIB_X86_64_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc3Begin_x86_64.inc}
{$I ..\..\Include\Simd\FpKernel\FpKernel_x86_64.inc}
{$ENDIF}
{$IFDEF CRYPTOLIB_I386_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc3Begin_i386.inc}
{$I ..\..\Include\Simd\FpKernel\FpKernel_i386.inc}
{$ENDIF}
{$UNDEF CRYPTOLIB_FP_SQR}
end;

// Fused CIOS Montgomery multiply (FP_MONTMUL selector), width-general: x86-64 (radix
// 2^64) and i386 (radix 2^32).
procedure FpKernelMontMulAsm(PR, PA, PB, PCtx: PUInt64);
{$DEFINE CRYPTOLIB_FP_MONTMUL}
{$IFDEF CRYPTOLIB_X86_64_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc4Begin_x86_64.inc}
{$I ..\..\Include\Simd\FpKernel\FpKernel_x86_64.inc}
{$ENDIF}
{$IFDEF CRYPTOLIB_I386_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc4Begin_i386.inc}
{$I ..\..\Include\Simd\FpKernel\FpKernel_i386.inc}
{$ENDIF}
{$UNDEF CRYPTOLIB_FP_MONTMUL}
end;

// MULX/ADCX/ADOX register-resident fast paths (x86-64 only).
{$IFDEF CRYPTOLIB_X86_64_ASM}
// MULX/ADCX/ADOX register-resident N=4 fast path (gated on BMI2+ADX below).
procedure FpKernelMontMulMulx4Asm(PR, PA, PB, PCtx: PUInt64);
{$DEFINE CRYPTOLIB_FP_MONTMUL_MULX4}
{$I ..\..\Include\Simd\Common\ClpSimdProc4Begin_x86_64.inc}
{$I ..\..\Include\Simd\FpKernel\FpKernel_x86_64.inc}
{$UNDEF CRYPTOLIB_FP_MONTMUL_MULX4}
end;

// MULX/ADCX/ADOX register-resident N=5 fast path (320-bit; gated on BMI2+ADX below).
procedure FpKernelMontMulMulx5Asm(PR, PA, PB, PCtx: PUInt64);
{$DEFINE CRYPTOLIB_FP_MONTMUL_MULX5}
{$I ..\..\Include\Simd\Common\ClpSimdProc4Begin_x86_64.inc}
{$I ..\..\Include\Simd\FpKernel\FpKernel_x86_64.inc}
{$UNDEF CRYPTOLIB_FP_MONTMUL_MULX5}
end;

// MULX/ADCX/ADOX fully-unrolled N=6 fast path (P-384; gated on BMI2+ADX below).
procedure FpKernelMontMulMulx6Asm(PR, PA, PB, PCtx: PUInt64);
{$DEFINE CRYPTOLIB_FP_MONTMUL_MULX6}
{$I ..\..\Include\Simd\Common\ClpSimdProc4Begin_x86_64.inc}
{$I ..\..\Include\Simd\FpKernel\FpKernel_x86_64.inc}
{$UNDEF CRYPTOLIB_FP_MONTMUL_MULX6}
end;

// MULX/ADCX/ADOX fully-unrolled N=9 fast path (P-521; PB spilled so 9 of 11 t-words
// stay in registers; gated on BMI2+ADX below).
procedure FpKernelMontMulMulx9Asm(PR, PA, PB, PCtx: PUInt64);
{$DEFINE CRYPTOLIB_FP_MONTMUL_MULX9}
{$I ..\..\Include\Simd\Common\ClpSimdProc4Begin_x86_64.inc}
{$I ..\..\Include\Simd\FpKernel\FpKernel_x86_64.inc}
{$UNDEF CRYPTOLIB_FP_MONTMUL_MULX9}
end;

// MULX/ADCX/ADOX fully-unrolled N=7 fast path (448-bit; PB spilled, all 9 t-words in
// registers; gated on BMI2+ADX below).
procedure FpKernelMontMulMulx7Asm(PR, PA, PB, PCtx: PUInt64);
{$DEFINE CRYPTOLIB_FP_MONTMUL_MULX7}
{$I ..\..\Include\Simd\Common\ClpSimdProc4Begin_x86_64.inc}
{$I ..\..\Include\Simd\FpKernel\FpKernel_x86_64.inc}
{$UNDEF CRYPTOLIB_FP_MONTMUL_MULX7}
end;

// MULX/ADCX/ADOX fully-unrolled N=8 fast path (512-bit; PB spilled + 1 stack word;
// gated on BMI2+ADX below).
procedure FpKernelMontMulMulx8Asm(PR, PA, PB, PCtx: PUInt64);
{$DEFINE CRYPTOLIB_FP_MONTMUL_MULX8}
{$I ..\..\Include\Simd\Common\ClpSimdProc4Begin_x86_64.inc}
{$I ..\..\Include\Simd\FpKernel\FpKernel_x86_64.inc}
{$UNDEF CRYPTOLIB_FP_MONTMUL_MULX8}
end;

// P-256 special-prime N=4 fast path: MULX product + folded shift/add reduction
// (gated on BMI2+ADX below). x86-64 only; i386 falls back to generic CIOS (its
// memory-resident kernel is not in-place safe for the aliased Mul/Sqr calls).
procedure FpKernelMontMulP256Asm(PR, PA, PB, PCtx: PUInt64);
{$DEFINE CRYPTOLIB_FP_MONTMUL_P256}
{$I ..\..\Include\Simd\Common\ClpSimdProc4Begin_x86_64.inc}
{$I ..\..\Include\Simd\FpKernel\FpKernel_x86_64.inc}
{$UNDEF CRYPTOLIB_FP_MONTMUL_P256}
end;

// Fused P-256 RCB PointDouble (a=-3): one straight-line, stack-framed doubling
// over a homogeneous point, inlining the special-prime field multiply. PR/PA are
// TFePoint bases, PCtx = [n0', N, p0..p3] (with Fb at a fixed offset). Gated on
// BMI2+ADX below; x86-64 only.
procedure FpKernelP256PointDoubleAsm(PR, PA, PCtx: PUInt64);
{$DEFINE CRYPTOLIB_FP_P256_POINTDOUBLE}
{$I ..\..\Include\Simd\Common\ClpSimdProc3Begin_x86_64.inc}
{$I ..\..\Include\Simd\FpKernel\FpKernelP256Point_x86_64.inc}
{$UNDEF CRYPTOLIB_FP_P256_POINTDOUBLE}
end;

// Fused P-256 RCB PointAdd (a=-3): one straight-line, stack-framed complete
// addition over two homogeneous points, inlining the special-prime field
// multiply. PR/PA/PQ are TFePoint bases, PCtx = [n0', N, p0..p3] (with Fb at a
// fixed offset). Gated on BMI2+ADX below; x86-64 only.
procedure FpKernelP256PointAddAsm(PR, PA, PQ, PCtx: PUInt64);
{$DEFINE CRYPTOLIB_FP_P256_POINTADD}
{$I ..\..\Include\Simd\Common\ClpSimdProc4Begin_x86_64.inc}
{$I ..\..\Include\Simd\FpKernel\FpKernelP256Point_x86_64.inc}
{$UNDEF CRYPTOLIB_FP_P256_POINTADD}
end;

// Fused P-256 RCB PointAddMixed (a=-3): the complete addition with PQ an affine
// (TFeAffine) point; the unit Z2 is supplied from PCtx.MontOne. Gated on BMI2+ADX
// below; x86-64 only.
procedure FpKernelP256PointAddMixedAsm(PR, PA, PQ, PCtx: PUInt64);
{$DEFINE CRYPTOLIB_FP_P256_POINTADDMIXED}
{$I ..\..\Include\Simd\Common\ClpSimdProc4Begin_x86_64.inc}
{$I ..\..\Include\Simd\FpKernel\FpKernelP256Point_x86_64.inc}
{$UNDEF CRYPTOLIB_FP_P256_POINTADDMIXED}
end;

{$ENDIF}

// Constant-time modular add/sub (FP_MODADD / FP_MODSUB selectors), width-general:
// x86-64 (radix 2^64) and i386 (radix 2^32).
procedure FpKernelModAddAsm(PR, PA, PB, PCtx: PUInt64);
{$DEFINE CRYPTOLIB_FP_MODADD}
{$IFDEF CRYPTOLIB_X86_64_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc4Begin_x86_64.inc}
{$I ..\..\Include\Simd\FpKernel\FpKernel_x86_64.inc}
{$ENDIF}
{$IFDEF CRYPTOLIB_I386_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc4Begin_i386.inc}
{$I ..\..\Include\Simd\FpKernel\FpKernel_i386.inc}
{$ENDIF}
{$UNDEF CRYPTOLIB_FP_MODADD}
end;

procedure FpKernelModSubAsm(PR, PA, PB, PCtx: PUInt64);
{$DEFINE CRYPTOLIB_FP_MODSUB}
{$IFDEF CRYPTOLIB_X86_64_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc4Begin_x86_64.inc}
{$I ..\..\Include\Simd\FpKernel\FpKernel_x86_64.inc}
{$ENDIF}
{$IFDEF CRYPTOLIB_I386_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc4Begin_i386.inc}
{$I ..\..\Include\Simd\FpKernel\FpKernel_i386.inc}
{$ENDIF}
{$UNDEF CRYPTOLIB_FP_MODSUB}
end;

{$ENDIF}

{ TFpKernelX86Backend }

class function TFpKernelX86Backend.IsSupported: Boolean;
begin
{$IFDEF CRYPTOLIB_X86_SIMD}
  Result := TCpuFeatures.X86.GetActiveSimdLevel() <> TX86SimdLevel.Scalar;
{$ELSE}
  Result := False;
{$ENDIF}
end;

class procedure TFpKernelX86Backend.Mul(PX, PY, PZ: PUInt64; ALimbs64: NativeInt);
begin
{$IFDEF CRYPTOLIB_X86_SIMD}
  FpKernelMulAsm(PX, PY, PZ, ALimbs64);
{$ENDIF}
end;

class procedure TFpKernelX86Backend.Sqr(PX, PZ: PUInt64; ALimbs64: NativeInt);
begin
{$IFDEF CRYPTOLIB_X86_SIMD}
  FpKernelSqrAsm(PX, PZ, ALimbs64);
{$ENDIF}
end;

class function TFpKernelX86Backend.MontMul(PR, PA, PB, PCtx: PUInt64): Boolean;
begin
{$IFDEF CRYPTOLIB_X86_64_ASM}
  // CtxData[1] = N (uint64 limbs). With BMI2+ADX every width N=4..9 takes a
  // two-carry-chain MULX kernel (contiguous coverage: any value-type Fp curve up to
  // 576-bit auto-benefits); anything outside 4..9 uses the plain-MUL kernel.
  if TX86SimdFeatures.HasBMI2() and TX86SimdFeatures.HasADX() then
  begin
    case PUInt64(PByte(PCtx) + 8)^ of
      4: FpKernelMontMulMulx4Asm(PR, PA, PB, PCtx);
      5: FpKernelMontMulMulx5Asm(PR, PA, PB, PCtx);
      6: FpKernelMontMulMulx6Asm(PR, PA, PB, PCtx);
      7: FpKernelMontMulMulx7Asm(PR, PA, PB, PCtx);
      8: FpKernelMontMulMulx8Asm(PR, PA, PB, PCtx);
      9: FpKernelMontMulMulx9Asm(PR, PA, PB, PCtx);
    else
      FpKernelMontMulAsm(PR, PA, PB, PCtx);
    end;
  end
  else
    FpKernelMontMulAsm(PR, PA, PB, PCtx);
  Result := True;
{$ELSE}
  {$IFDEF CRYPTOLIB_I386_ASM}
  FpKernelMontMulAsm(PR, PA, PB, PCtx);
  Result := True;
  {$ELSE}
  Result := False;
  {$ENDIF}
{$ENDIF}
end;

class function TFpKernelX86Backend.MontMulP256(PR, PA, PB, PCtx: PUInt64): Boolean;
begin
{$IFDEF CRYPTOLIB_X86_64_ASM}
  if TX86SimdFeatures.HasBMI2() and TX86SimdFeatures.HasADX() then
  begin
    FpKernelMontMulP256Asm(PR, PA, PB, PCtx);
    Result := True;
  end
  else
    Result := False;
{$ELSE}
  Result := False; // i386: generic CIOS (kernel not in-place safe)
{$ENDIF}
end;

class function TFpKernelX86Backend.PointDoubleP256(PR, PA, PCtx: PUInt64): Boolean;
begin
{$IFDEF CRYPTOLIB_X86_64_ASM}
  if TX86SimdFeatures.HasBMI2() and TX86SimdFeatures.HasADX() then
  begin
    FpKernelP256PointDoubleAsm(PR, PA, PCtx);
    Result := True;
  end
  else
    Result := False;
{$ELSE}
  Result := False; // i386: generic per-op RCB doubling
{$ENDIF}
end;

class function TFpKernelX86Backend.PointAddP256(PR, PA, PQ, PCtx: PUInt64): Boolean;
begin
{$IFDEF CRYPTOLIB_X86_64_ASM}
  if TX86SimdFeatures.HasBMI2() and TX86SimdFeatures.HasADX() then
  begin
    FpKernelP256PointAddAsm(PR, PA, PQ, PCtx);
    Result := True;
  end
  else
    Result := False;
{$ELSE}
  Result := False; // i386: generic per-op RCB addition
{$ENDIF}
end;

class function TFpKernelX86Backend.PointAddMixedP256(PR, PA, PQ, PCtx: PUInt64): Boolean;
begin
{$IFDEF CRYPTOLIB_X86_64_ASM}
  if TX86SimdFeatures.HasBMI2() and TX86SimdFeatures.HasADX() then
  begin
    FpKernelP256PointAddMixedAsm(PR, PA, PQ, PCtx);
    Result := True;
  end
  else
    Result := False;
{$ELSE}
  Result := False; // i386: generic per-op RCB addition
{$ENDIF}
end;

class function TFpKernelX86Backend.ModAdd(PR, PA, PB, PCtx: PUInt64): Boolean;
begin
{$IF DEFINED(CRYPTOLIB_X86_64_ASM) OR DEFINED(CRYPTOLIB_I386_ASM)}
  FpKernelModAddAsm(PR, PA, PB, PCtx);
  Result := True;
{$ELSE}
  Result := False;
{$IFEND}
end;

class function TFpKernelX86Backend.ModSub(PR, PA, PB, PCtx: PUInt64): Boolean;
begin
{$IF DEFINED(CRYPTOLIB_X86_64_ASM) OR DEFINED(CRYPTOLIB_I386_ASM)}
  FpKernelModSubAsm(PR, PA, PB, PCtx);
  Result := True;
{$ELSE}
  Result := False;
{$IFEND}
end;

end.
