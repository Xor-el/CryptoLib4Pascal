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

unit ClpMontKernelX86Backend;

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
  /// X86 kernel backend for prime-field (Fp) arithmetic. A leaf:
  /// capability probe plus the hot unreduced schoolbook multiply/square and the
  /// Montgomery multiply. The arch-neutral dispatch and the scalar fallback live in
  /// <c>TMontKernelSimd</c> / the field units. Hot paths are in
  /// <c>Include/Simd/MontKernel/</c>.
  /// </summary>
  TMontKernelX86Backend = class sealed
  public
    class function IsSupported: Boolean; static; inline;
    class procedure Mul(PX, PY, PZ: PUInt64; ALimbs64: NativeInt); static;
    class procedure Sqr(PX, PZ: PUInt64; ALimbs64: NativeInt); static;
    /// <summary>Fused CIOS Montgomery multiply PR := PA*PB*R^-1 mod p. PCtx =
    /// [n0', N, p[0..N-1]]; PR is the N+2-limb scratch and receives the reduced
    /// N-limb result. Returns False on an arch without the kernel.</summary>
    class function MontMul(PR, PA, PB, PCtx: PUInt64): Boolean; static;
    /// <summary>Constant-time modular add/sub PR := (PA +/- PB) mod p. PCtx =
    /// [n0'(unused), N, p[0..N-1]]; inputs assumed < p. False on arch without it.</summary>
    class function ModAdd(PR, PA, PB, PCtx: PUInt64): Boolean; static;
    class function ModSub(PR, PA, PB, PCtx: PUInt64): Boolean; static;
  end;

implementation

{$IFDEF CRYPTOLIB_X86_SIMD}

procedure FpKernelMul(PX, PY, PZ: PUInt64; ALimbs64: NativeInt);
{$DEFINE CRYPTOLIB_FP_MUL}
{$IFDEF CRYPTOLIB_X86_64_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc4Begin_x86_64.inc}
{$I ..\..\Include\Simd\MontKernel\MontKernel_x86_64.inc}
{$ENDIF}
{$IFDEF CRYPTOLIB_I386_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc4Begin_i386.inc}
{$I ..\..\Include\Simd\MontKernel\MontKernel_i386.inc}
{$ENDIF}
{$UNDEF CRYPTOLIB_FP_MUL}
end;

// Square Z := X^2 (FP_SQR selector).
procedure FpKernelSqr(PX, PZ: PUInt64; ALimbs64: NativeInt);
{$DEFINE CRYPTOLIB_FP_SQR}
{$IFDEF CRYPTOLIB_X86_64_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc3Begin_x86_64.inc}
{$I ..\..\Include\Simd\MontKernel\MontKernel_x86_64.inc}
{$ENDIF}
{$IFDEF CRYPTOLIB_I386_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc3Begin_i386.inc}
{$I ..\..\Include\Simd\MontKernel\MontKernel_i386.inc}
{$ENDIF}
{$UNDEF CRYPTOLIB_FP_SQR}
end;

// Fused CIOS Montgomery multiply (FP_MONTMUL selector), width-general: x86-64 (radix
// 2^64) and i386 (radix 2^32).
procedure FpKernelMontMul(PR, PA, PB, PCtx: PUInt64);
{$DEFINE CRYPTOLIB_FP_MONTMUL}
{$IFDEF CRYPTOLIB_X86_64_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc4Begin_x86_64.inc}
{$I ..\..\Include\Simd\MontKernel\MontKernel_x86_64.inc}
{$ENDIF}
{$IFDEF CRYPTOLIB_I386_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc4Begin_i386.inc}
{$I ..\..\Include\Simd\MontKernel\MontKernel_i386.inc}
{$ENDIF}
{$UNDEF CRYPTOLIB_FP_MONTMUL}
end;

// MULX/ADCX/ADOX register-resident fast paths (x86-64 only).
{$IFDEF CRYPTOLIB_X86_64_ASM}
// MULX/ADCX/ADOX register-resident N=4 fast path (gated on BMI2+ADX below).
procedure FpKernelMontMulMulx4(PR, PA, PB, PCtx: PUInt64);
{$DEFINE CRYPTOLIB_FP_MONTMUL_MULX4}
{$I ..\..\Include\Simd\Common\ClpSimdProc4Begin_x86_64.inc}
{$I ..\..\Include\Simd\MontKernel\MontKernel_x86_64.inc}
{$UNDEF CRYPTOLIB_FP_MONTMUL_MULX4}
end;

// MULX/ADCX/ADOX register-resident N=5 fast path (320-bit; gated on BMI2+ADX below).
procedure FpKernelMontMulMulx5(PR, PA, PB, PCtx: PUInt64);
{$DEFINE CRYPTOLIB_FP_MONTMUL_MULX5}
{$I ..\..\Include\Simd\Common\ClpSimdProc4Begin_x86_64.inc}
{$I ..\..\Include\Simd\MontKernel\MontKernel_x86_64.inc}
{$UNDEF CRYPTOLIB_FP_MONTMUL_MULX5}
end;

// MULX/ADCX/ADOX fully-unrolled N=6 fast path (P-384; gated on BMI2+ADX below).
procedure FpKernelMontMulMulx6(PR, PA, PB, PCtx: PUInt64);
{$DEFINE CRYPTOLIB_FP_MONTMUL_MULX6}
{$I ..\..\Include\Simd\Common\ClpSimdProc4Begin_x86_64.inc}
{$I ..\..\Include\Simd\MontKernel\MontKernel_x86_64.inc}
{$UNDEF CRYPTOLIB_FP_MONTMUL_MULX6}
end;

// MULX/ADCX/ADOX fully-unrolled N=9 fast path (P-521; PB spilled so 9 of 11 t-words
// stay in registers; gated on BMI2+ADX below).
procedure FpKernelMontMulMulx9(PR, PA, PB, PCtx: PUInt64);
{$DEFINE CRYPTOLIB_FP_MONTMUL_MULX9}
{$I ..\..\Include\Simd\Common\ClpSimdProc4Begin_x86_64.inc}
{$I ..\..\Include\Simd\MontKernel\MontKernel_x86_64.inc}
{$UNDEF CRYPTOLIB_FP_MONTMUL_MULX9}
end;

// MULX/ADCX/ADOX fully-unrolled N=7 fast path (448-bit; PB spilled, all 9 t-words in
// registers; gated on BMI2+ADX below).
procedure FpKernelMontMulMulx7(PR, PA, PB, PCtx: PUInt64);
{$DEFINE CRYPTOLIB_FP_MONTMUL_MULX7}
{$I ..\..\Include\Simd\Common\ClpSimdProc4Begin_x86_64.inc}
{$I ..\..\Include\Simd\MontKernel\MontKernel_x86_64.inc}
{$UNDEF CRYPTOLIB_FP_MONTMUL_MULX7}
end;

// MULX/ADCX/ADOX fully-unrolled N=8 fast path (512-bit; PB spilled + 1 stack word;
// gated on BMI2+ADX below).
procedure FpKernelMontMulMulx8(PR, PA, PB, PCtx: PUInt64);
{$DEFINE CRYPTOLIB_FP_MONTMUL_MULX8}
{$I ..\..\Include\Simd\Common\ClpSimdProc4Begin_x86_64.inc}
{$I ..\..\Include\Simd\MontKernel\MontKernel_x86_64.inc}
{$UNDEF CRYPTOLIB_FP_MONTMUL_MULX8}
end;

{$ENDIF}

{$IFDEF CRYPTOLIB_X86_64_ASM}
// Dedicated unrolled N=4 modular add/sub: one add/adc (sub/sbb) pass,
// speculative subtract (masked add-back) of p in registers, masked select,
// one store pass. Plain ops only (no BMI2/ADX gate).
procedure FpKernelModAdd4(PR, PA, PB, PCtx: PUInt64);
{$DEFINE CRYPTOLIB_FP_MODADD4}
{$I ..\..\Include\Simd\Common\ClpSimdProc4Begin_x86_64.inc}
{$I ..\..\Include\Simd\MontKernel\MontKernel_x86_64.inc}
{$UNDEF CRYPTOLIB_FP_MODADD4}
end;

procedure FpKernelModSub4(PR, PA, PB, PCtx: PUInt64);
{$DEFINE CRYPTOLIB_FP_MODSUB4}
{$I ..\..\Include\Simd\Common\ClpSimdProc4Begin_x86_64.inc}
{$I ..\..\Include\Simd\MontKernel\MontKernel_x86_64.inc}
{$UNDEF CRYPTOLIB_FP_MODSUB4}
end;
{$ENDIF}

// Constant-time modular add/sub (FP_MODADD / FP_MODSUB selectors), width-general:
// x86-64 (radix 2^64) and i386 (radix 2^32).
procedure FpKernelModAdd(PR, PA, PB, PCtx: PUInt64);
{$DEFINE CRYPTOLIB_FP_MODADD}
{$IFDEF CRYPTOLIB_X86_64_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc4Begin_x86_64.inc}
{$I ..\..\Include\Simd\MontKernel\MontKernel_x86_64.inc}
{$ENDIF}
{$IFDEF CRYPTOLIB_I386_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc4Begin_i386.inc}
{$I ..\..\Include\Simd\MontKernel\MontKernel_i386.inc}
{$ENDIF}
{$UNDEF CRYPTOLIB_FP_MODADD}
end;

procedure FpKernelModSub(PR, PA, PB, PCtx: PUInt64);
{$DEFINE CRYPTOLIB_FP_MODSUB}
{$IFDEF CRYPTOLIB_X86_64_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc4Begin_x86_64.inc}
{$I ..\..\Include\Simd\MontKernel\MontKernel_x86_64.inc}
{$ENDIF}
{$IFDEF CRYPTOLIB_I386_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc4Begin_i386.inc}
{$I ..\..\Include\Simd\MontKernel\MontKernel_i386.inc}
{$ENDIF}
{$UNDEF CRYPTOLIB_FP_MODSUB}
end;

{$ENDIF}

{ TMontKernelX86Backend }

class function TMontKernelX86Backend.IsSupported: Boolean;
begin
{$IFDEF CRYPTOLIB_X86_SIMD}
  Result := TCpuFeatures.X86.GetActiveSimdLevel() <> TX86SimdLevel.Scalar;
{$ELSE}
  Result := False;
{$ENDIF}
end;

class procedure TMontKernelX86Backend.Mul(PX, PY, PZ: PUInt64; ALimbs64: NativeInt);
begin
{$IFDEF CRYPTOLIB_X86_SIMD}
  FpKernelMul(PX, PY, PZ, ALimbs64);
{$ENDIF}
end;

class procedure TMontKernelX86Backend.Sqr(PX, PZ: PUInt64; ALimbs64: NativeInt);
begin
{$IFDEF CRYPTOLIB_X86_SIMD}
  FpKernelSqr(PX, PZ, ALimbs64);
{$ENDIF}
end;

class function TMontKernelX86Backend.MontMul(PR, PA, PB, PCtx: PUInt64): Boolean;
begin
{$IFDEF CRYPTOLIB_X86_64_ASM}
  // CtxData[1] = N (uint64 limbs). With BMI2+ADX every width N=4..9 takes a
  // two-carry-chain MULX kernel (contiguous coverage: any value-type Fp curve up to
  // 576-bit auto-benefits); anything outside 4..9 uses the plain-MUL kernel.
  if TX86SimdFeatures.HasBMI2ADX() then
  begin
    case PUInt64(PByte(PCtx) + 8)^ of
      4: FpKernelMontMulMulx4(PR, PA, PB, PCtx);
      5: FpKernelMontMulMulx5(PR, PA, PB, PCtx);
      6: FpKernelMontMulMulx6(PR, PA, PB, PCtx);
      7: FpKernelMontMulMulx7(PR, PA, PB, PCtx);
      8: FpKernelMontMulMulx8(PR, PA, PB, PCtx);
      9: FpKernelMontMulMulx9(PR, PA, PB, PCtx);
    else
      FpKernelMontMul(PR, PA, PB, PCtx);
    end;
  end
  else
    FpKernelMontMul(PR, PA, PB, PCtx);
  Result := True;
{$ELSE}
  {$IFDEF CRYPTOLIB_I386_ASM}
  FpKernelMontMul(PR, PA, PB, PCtx);
  Result := True;
  {$ELSE}
  Result := False;
  {$ENDIF}
{$ENDIF}
end;

class function TMontKernelX86Backend.ModAdd(PR, PA, PB, PCtx: PUInt64): Boolean;
begin
{$IFDEF CRYPTOLIB_X86_64_ASM}
  // CtxData[1] = N (public curve width, not secret-dependent).
  if PUInt64(PByte(PCtx) + 8)^ = 4 then
    FpKernelModAdd4(PR, PA, PB, PCtx)
  else
    FpKernelModAdd(PR, PA, PB, PCtx);
  Result := True;
{$ELSE}
  {$IFDEF CRYPTOLIB_I386_ASM}
  FpKernelModAdd(PR, PA, PB, PCtx);
  Result := True;
  {$ELSE}
  Result := False;
  {$ENDIF}
{$ENDIF}
end;

class function TMontKernelX86Backend.ModSub(PR, PA, PB, PCtx: PUInt64): Boolean;
begin
{$IFDEF CRYPTOLIB_X86_64_ASM}
  if PUInt64(PByte(PCtx) + 8)^ = 4 then
    FpKernelModSub4(PR, PA, PB, PCtx)
  else
    FpKernelModSub(PR, PA, PB, PCtx);
  Result := True;
{$ELSE}
  {$IFDEF CRYPTOLIB_I386_ASM}
  FpKernelModSub(PR, PA, PB, PCtx);
  Result := True;
  {$ELSE}
  Result := False;
  {$ENDIF}
{$ENDIF}
end;

end.
