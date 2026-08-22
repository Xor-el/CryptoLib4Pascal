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
