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
  /// X86 kernel backend for prime-field (Fp) arithmetic. A leaf:
  /// capability probe plus the hot unreduced schoolbook multiply/square and the
  /// Montgomery multiply. The arch-neutral dispatch and the scalar fallback live in
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
    /// N-limb result. Returns False on an arch without the kernel.</summary>
    class function MontMul(PR, PA, PB, PCtx: PUInt64): Boolean; static;
    /// <summary>P-256 special-prime Montgomery multiply PR := PA*PB*R^-1 mod p, with
    /// the folded (shift/add) reduction. PCtx = the P-256 [n0'=1, N=4, p0..p3]. Returns
    /// False when BMI2+ADX absent or not x86-64 (caller falls back to generic CIOS).</summary>
    class function MontMulP256(PR, PA, PB, PCtx: PUInt64): Boolean; static;
    /// <summary>Fused P-256 incomplete-Jacobian doubling PR := 2*PA (Jacobian). False
    /// when BMI2+ADX absent or not x86-64.</summary>
    class function JacPointDoubleP256(PR, PA, PCtx: PUInt64): Boolean; static;
    /// <summary>Fused P-256 incomplete-Jacobian addition; PScratch = TJacAddScratch
    /// base. False when BMI2+ADX absent or not x86-64.</summary>
    class function JacPointAddP256(PScratch, PA, PQ, PCtx: PUInt64): Boolean; static;
    /// <summary>Fused P-256 incomplete-Jacobian mixed addition (PQ a TFeAffine base).
    /// False when BMI2+ADX absent or not x86-64.</summary>
    class function JacPointAddMixedP256(PScratch, PA, PQ, PCtx: PUInt64): Boolean; static;
    /// <summary>Fused secp256k1 (a=0) incomplete-Jacobian doubling PR := 2*PA. False
    /// when BMI2+ADX absent or not x86-64.</summary>
    class function JacPointDoubleK256(PR, PA, PCtx: PUInt64): Boolean; static;
    /// <summary>Fused secp256k1 incomplete-Jacobian addition; PScratch = TJacAddScratch
    /// base. False when BMI2+ADX absent or not x86-64.</summary>
    class function JacPointAddK256(PScratch, PA, PQ, PCtx: PUInt64): Boolean; static;
    /// <summary>Fused secp256k1 incomplete-Jacobian mixed addition (PQ a TFeAffine base).
    /// False when BMI2+ADX absent or not x86-64.</summary>
    class function JacPointAddMixedK256(PScratch, PA, PQ, PCtx: PUInt64): Boolean; static;
    /// <summary>Constant-time modular add/sub PR := (PA +/- PB) mod p. PCtx =
    /// [n0'(unused), N, p[0..N-1]]; inputs assumed < p. False on arch without it.</summary>
    class function ModAdd(PR, PA, PB, PCtx: PUInt64): Boolean; static;
    class function ModSub(PR, PA, PB, PCtx: PUInt64): Boolean; static;
    /// <summary>Constant-time gather: PDst := the AIndex-th of ACount entries (each
    /// AEntryBytes wide), with index-independent access.</summary>
    class function Gather(PDst, PTable: PByte; AEntryBytes, ACount, AIndex: NativeInt): Boolean; static;
  end;

implementation

{$IFDEF CRYPTOLIB_X86_SIMD}

procedure FpKernelMul(PX, PY, PZ: PUInt64; ALimbs64: NativeInt);
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
procedure FpKernelSqr(PX, PZ: PUInt64; ALimbs64: NativeInt);
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
procedure FpKernelMontMul(PR, PA, PB, PCtx: PUInt64);
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
procedure FpKernelMontMulMulx4(PR, PA, PB, PCtx: PUInt64);
{$DEFINE CRYPTOLIB_FP_MONTMUL_MULX4}
{$I ..\..\Include\Simd\Common\ClpSimdProc4Begin_x86_64.inc}
{$I ..\..\Include\Simd\FpKernel\FpKernel_x86_64.inc}
{$UNDEF CRYPTOLIB_FP_MONTMUL_MULX4}
end;

// MULX/ADCX/ADOX register-resident N=5 fast path (320-bit; gated on BMI2+ADX below).
procedure FpKernelMontMulMulx5(PR, PA, PB, PCtx: PUInt64);
{$DEFINE CRYPTOLIB_FP_MONTMUL_MULX5}
{$I ..\..\Include\Simd\Common\ClpSimdProc4Begin_x86_64.inc}
{$I ..\..\Include\Simd\FpKernel\FpKernel_x86_64.inc}
{$UNDEF CRYPTOLIB_FP_MONTMUL_MULX5}
end;

// MULX/ADCX/ADOX fully-unrolled N=6 fast path (P-384; gated on BMI2+ADX below).
procedure FpKernelMontMulMulx6(PR, PA, PB, PCtx: PUInt64);
{$DEFINE CRYPTOLIB_FP_MONTMUL_MULX6}
{$I ..\..\Include\Simd\Common\ClpSimdProc4Begin_x86_64.inc}
{$I ..\..\Include\Simd\FpKernel\FpKernel_x86_64.inc}
{$UNDEF CRYPTOLIB_FP_MONTMUL_MULX6}
end;

// MULX/ADCX/ADOX fully-unrolled N=9 fast path (P-521; PB spilled so 9 of 11 t-words
// stay in registers; gated on BMI2+ADX below).
procedure FpKernelMontMulMulx9(PR, PA, PB, PCtx: PUInt64);
{$DEFINE CRYPTOLIB_FP_MONTMUL_MULX9}
{$I ..\..\Include\Simd\Common\ClpSimdProc4Begin_x86_64.inc}
{$I ..\..\Include\Simd\FpKernel\FpKernel_x86_64.inc}
{$UNDEF CRYPTOLIB_FP_MONTMUL_MULX9}
end;

// MULX/ADCX/ADOX fully-unrolled N=7 fast path (448-bit; PB spilled, all 9 t-words in
// registers; gated on BMI2+ADX below).
procedure FpKernelMontMulMulx7(PR, PA, PB, PCtx: PUInt64);
{$DEFINE CRYPTOLIB_FP_MONTMUL_MULX7}
{$I ..\..\Include\Simd\Common\ClpSimdProc4Begin_x86_64.inc}
{$I ..\..\Include\Simd\FpKernel\FpKernel_x86_64.inc}
{$UNDEF CRYPTOLIB_FP_MONTMUL_MULX7}
end;

// MULX/ADCX/ADOX fully-unrolled N=8 fast path (512-bit; PB spilled + 1 stack word;
// gated on BMI2+ADX below).
procedure FpKernelMontMulMulx8(PR, PA, PB, PCtx: PUInt64);
{$DEFINE CRYPTOLIB_FP_MONTMUL_MULX8}
{$I ..\..\Include\Simd\Common\ClpSimdProc4Begin_x86_64.inc}
{$I ..\..\Include\Simd\FpKernel\FpKernel_x86_64.inc}
{$UNDEF CRYPTOLIB_FP_MONTMUL_MULX8}
end;

// P-256 special-prime N=4 fast path: MULX product + folded shift/add reduction
// (gated on BMI2+ADX below). x86-64 only; i386 falls back to generic CIOS (its
// memory-resident kernel is not in-place safe for the aliased Mul/Sqr calls).
procedure FpKernelMontMulP256(PR, PA, PB, PCtx: PUInt64);
{$DEFINE CRYPTOLIB_FP_MONTMUL_P256}
{$I ..\..\Include\Simd\Common\ClpSimdProc4Begin_x86_64.inc}
{$I ..\..\Include\Simd\FpKernel\FpKernel_x86_64.inc}
{$UNDEF CRYPTOLIB_FP_MONTMUL_P256}
end;

// Fused P-256 incomplete-Jacobian doubling (a=-3): straight-line, stack-framed,
// inlining the special-prime field multiply. PR/PA are TFePoint bases. Gated on
// BMI2+ADX below; x86-64 only.
procedure FpKernelP256JacPointDouble(PR, PA, PCtx: PUInt64);
{$DEFINE CRYPTOLIB_FP_P256_JACPOINTDOUBLE}
{$I ..\..\Include\Simd\Common\ClpSimdProc3Begin_x86_64.inc}
{$I ..\..\Include\Simd\FpKernel\FpKernelP256JacPoint_x86_64.inc}
{$UNDEF CRYPTOLIB_FP_P256_JACPOINTDOUBLE}
end;

// Fused P-256 incomplete-Jacobian addition (add-2007-bl): masked-infinity
// completion inside; predicate operands H/RS exposed for the caller's P=Q
// detect-and-double. PScratch = TJacAddScratch, PA/PQ = TFePoint bases.
procedure FpKernelP256JacPointAdd(PScratch, PA, PQ, PCtx: PUInt64);
{$DEFINE CRYPTOLIB_FP_P256_JACPOINTADD}
{$I ..\..\Include\Simd\Common\ClpSimdProc4Begin_x86_64.inc}
{$I ..\..\Include\Simd\FpKernel\FpKernelP256JacPoint_x86_64.inc}
{$UNDEF CRYPTOLIB_FP_P256_JACPOINTADD}
end;

// Fused P-256 incomplete-Jacobian mixed addition: PQ affine (Z2=1 from MontOne).
procedure FpKernelP256JacPointAddMixed(PScratch, PA, PQ, PCtx: PUInt64);
{$DEFINE CRYPTOLIB_FP_P256_JACPOINTADDMIXED}
{$I ..\..\Include\Simd\Common\ClpSimdProc4Begin_x86_64.inc}
{$I ..\..\Include\Simd\FpKernel\FpKernelP256JacPoint_x86_64.inc}
{$UNDEF CRYPTOLIB_FP_P256_JACPOINTADDMIXED}
end;

// Fused secp256k1 incomplete-Jacobian doubling (a=0, dbl-2009-l): straight-line,
// stack-framed, inlining the generic MULX4 multiply / dedicated square (k1's prime
// is pseudo-Mersenne, so no folded reduction). PR/PA are TFePoint bases. Gated on
// BMI2+ADX below; x86-64 only.
procedure FpKernelK1JacPointDouble(PR, PA, PCtx: PUInt64);
{$DEFINE CRYPTOLIB_FP_K256_POINTDOUBLE}
{$I ..\..\Include\Simd\Common\ClpSimdProc3Begin_x86_64.inc}
{$I ..\..\Include\Simd\FpKernel\FpKernelK256JacPoint_x86_64.inc}
{$UNDEF CRYPTOLIB_FP_K256_POINTDOUBLE}
end;

// Fused secp256k1 incomplete-Jacobian addition (add-2007-bl): masked-infinity
// completion inside; predicate operands H/RS exposed for the caller's P=Q
// detect-and-double. PScratch = TJacAddScratch, PA/PQ = TFePoint bases.
procedure FpKernelK1JacPointAdd(PScratch, PA, PQ, PCtx: PUInt64);
{$DEFINE CRYPTOLIB_FP_K256_POINTADD}
{$I ..\..\Include\Simd\Common\ClpSimdProc4Begin_x86_64.inc}
{$I ..\..\Include\Simd\FpKernel\FpKernelK256JacPoint_x86_64.inc}
{$UNDEF CRYPTOLIB_FP_K256_POINTADD}
end;

// Fused secp256k1 incomplete-Jacobian mixed addition: PQ affine (Z2=1 from MontOne).
procedure FpKernelK1JacPointAddMixed(PScratch, PA, PQ, PCtx: PUInt64);
{$DEFINE CRYPTOLIB_FP_K256_POINTADDMIXED}
{$I ..\..\Include\Simd\Common\ClpSimdProc4Begin_x86_64.inc}
{$I ..\..\Include\Simd\FpKernel\FpKernelK256JacPoint_x86_64.inc}
{$UNDEF CRYPTOLIB_FP_K256_POINTADDMIXED}
end;

{$ENDIF}

// Constant-time table gather (SSE2), x86-64 + i386: PDst := the AIndex-th entry
// out of ACount, each AEntryBytes wide, masked-accumulated in constant time.
// The SSE2 path (pre-AVX2 x86-64 and i386).
procedure FpKernelGatherSse2(PDst, PTable: PByte; AEntryBytes, ACount, AIndex: NativeInt);
{$IFDEF CRYPTOLIB_X86_64_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc5Begin_x86_64.inc}
{$I ..\..\Include\Simd\FpKernel\FpKernelGatherSse2_x86_64.inc}
{$ENDIF}
{$IFDEF CRYPTOLIB_I386_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc5Begin_i386.inc}
{$I ..\..\Include\Simd\FpKernel\FpKernelGatherSse2_i386.inc}
{$ENDIF}
end;

// Constant-time table gather (AVX2), x86-64 + i386: 32-byte ymm chunks. The
// caller (Gather) picks this over SSE2 when AVX2 is present.
procedure FpKernelGatherAvx2(PDst, PTable: PByte; AEntryBytes, ACount, AIndex: NativeInt);
{$IFDEF CRYPTOLIB_X86_64_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc5Begin_x86_64.inc}
{$I ..\..\Include\Simd\FpKernel\FpKernelGatherAvx2_x86_64.inc}
{$ENDIF}
{$IFDEF CRYPTOLIB_I386_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc5Begin_i386.inc}
{$I ..\..\Include\Simd\FpKernel\FpKernelGatherAvx2_i386.inc}
{$ENDIF}
end;

// Constant-time modular add/sub (FP_MODADD / FP_MODSUB selectors), width-general:
// x86-64 (radix 2^64) and i386 (radix 2^32).
procedure FpKernelModAdd(PR, PA, PB, PCtx: PUInt64);
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

procedure FpKernelModSub(PR, PA, PB, PCtx: PUInt64);
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
  FpKernelMul(PX, PY, PZ, ALimbs64);
{$ENDIF}
end;

class procedure TFpKernelX86Backend.Sqr(PX, PZ: PUInt64; ALimbs64: NativeInt);
begin
{$IFDEF CRYPTOLIB_X86_SIMD}
  FpKernelSqr(PX, PZ, ALimbs64);
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

class function TFpKernelX86Backend.MontMulP256(PR, PA, PB, PCtx: PUInt64): Boolean;
begin
{$IFDEF CRYPTOLIB_X86_64_ASM}
  if TX86SimdFeatures.HasBMI2() and TX86SimdFeatures.HasADX() then
  begin
    FpKernelMontMulP256(PR, PA, PB, PCtx);
    Result := True;
  end
  else
    Result := False;
{$ELSE}
  Result := False;
{$ENDIF}
end;

class function TFpKernelX86Backend.JacPointDoubleP256(PR, PA, PCtx: PUInt64): Boolean;
begin
{$IFDEF CRYPTOLIB_X86_64_ASM}
  if TX86SimdFeatures.HasBMI2() and TX86SimdFeatures.HasADX() then
  begin
    FpKernelP256JacPointDouble(PR, PA, PCtx);
    Result := True;
  end
  else
    Result := False;
{$ELSE}
  Result := False;
{$ENDIF}
end;

class function TFpKernelX86Backend.JacPointAddP256(PScratch, PA, PQ, PCtx: PUInt64): Boolean;
begin
{$IFDEF CRYPTOLIB_X86_64_ASM}
  if TX86SimdFeatures.HasBMI2() and TX86SimdFeatures.HasADX() then
  begin
    FpKernelP256JacPointAdd(PScratch, PA, PQ, PCtx);
    Result := True;
  end
  else
    Result := False;
{$ELSE}
  Result := False;
{$ENDIF}
end;

class function TFpKernelX86Backend.JacPointAddMixedP256(PScratch, PA, PQ, PCtx: PUInt64): Boolean;
begin
{$IFDEF CRYPTOLIB_X86_64_ASM}
  if TX86SimdFeatures.HasBMI2() and TX86SimdFeatures.HasADX() then
  begin
    FpKernelP256JacPointAddMixed(PScratch, PA, PQ, PCtx);
    Result := True;
  end
  else
    Result := False;
{$ELSE}
  Result := False;
{$ENDIF}
end;

class function TFpKernelX86Backend.JacPointDoubleK256(PR, PA, PCtx: PUInt64): Boolean;
begin
{$IFDEF CRYPTOLIB_X86_64_ASM}
  if TX86SimdFeatures.HasBMI2() and TX86SimdFeatures.HasADX() then
  begin
    FpKernelK1JacPointDouble(PR, PA, PCtx);
    Result := True;
  end
  else
    Result := False;
{$ELSE}
  Result := False;
{$ENDIF}
end;

class function TFpKernelX86Backend.JacPointAddK256(PScratch, PA, PQ, PCtx: PUInt64): Boolean;
begin
{$IFDEF CRYPTOLIB_X86_64_ASM}
  if TX86SimdFeatures.HasBMI2() and TX86SimdFeatures.HasADX() then
  begin
    FpKernelK1JacPointAdd(PScratch, PA, PQ, PCtx);
    Result := True;
  end
  else
    Result := False;
{$ELSE}
  Result := False;
{$ENDIF}
end;

class function TFpKernelX86Backend.JacPointAddMixedK256(PScratch, PA, PQ, PCtx: PUInt64): Boolean;
begin
{$IFDEF CRYPTOLIB_X86_64_ASM}
  if TX86SimdFeatures.HasBMI2() and TX86SimdFeatures.HasADX() then
  begin
    FpKernelK1JacPointAddMixed(PScratch, PA, PQ, PCtx);
    Result := True;
  end
  else
    Result := False;
{$ELSE}
  Result := False;
{$ENDIF}
end;

class function TFpKernelX86Backend.ModAdd(PR, PA, PB, PCtx: PUInt64): Boolean;
begin
{$IF DEFINED(CRYPTOLIB_X86_64_ASM) OR DEFINED(CRYPTOLIB_I386_ASM)}
  FpKernelModAdd(PR, PA, PB, PCtx);
  Result := True;
{$ELSE}
  Result := False;
{$IFEND}
end;

class function TFpKernelX86Backend.ModSub(PR, PA, PB, PCtx: PUInt64): Boolean;
begin
{$IF DEFINED(CRYPTOLIB_X86_64_ASM) OR DEFINED(CRYPTOLIB_I386_ASM)}
  FpKernelModSub(PR, PA, PB, PCtx);
  Result := True;
{$ELSE}
  Result := False;
{$IFEND}
end;

class function TFpKernelX86Backend.Gather(PDst, PTable: PByte; AEntryBytes, ACount, AIndex: NativeInt): Boolean;
begin
{$IFDEF CRYPTOLIB_X86_SIMD}
  if TCpuFeatures.X86.HasAVX2() then
    FpKernelGatherAvx2(PDst, PTable, AEntryBytes, ACount, AIndex)
  else
    FpKernelGatherSse2(PDst, PTable, AEntryBytes, ACount, AIndex);
  Exit(True);
{$ENDIF}
  Result := False;
end;

end.
