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

unit ClpPointKernelX86Backend;

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
  /// X86 kernel backend for the fused special-prime kernels. A leaf:
  /// capability probe plus the P-256 special-prime Montgomery multiply/square and
  /// the fused P-256/secp256k1 incomplete-Jacobian point operations. The
  /// arch-neutral dispatch and the scalar fallback live in
  /// <c>TPointKernelSimd</c> / the field units. Hot paths are in
  /// <c>Include/Simd/PointKernel/</c>.
  /// </summary>
  TPointKernelX86Backend = class sealed
  public
    class function IsSupported: Boolean; static; inline;
    /// <summary>P-256 special-prime Montgomery multiply PR := PA*PB*R^-1 mod p, with
    /// the folded (shift/add) reduction. PCtx = the P-256 [n0'=1, N=4, p0..p3]. Returns
    /// False when BMI2+ADX absent or not x86-64 (caller falls back to generic CIOS).</summary>
    class function MontMulP256(PR, PA, PB, PCtx: PUInt64): Boolean; static;
    /// <summary>P-256 dedicated Montgomery square PR := PA^2 * R^-1 mod p (dual-chain
    /// SOS square + folded reduction). PCtx = the P-256 [n0'=1, N=4, p0..p3]. Returns
    /// False when BMI2+ADX absent or not x86-64 (caller falls back to the multiply).</summary>
    class function MontSqrP256(PR, PA, PCtx: PUInt64): Boolean; static;
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
  end;

implementation

{$IFDEF CRYPTOLIB_X86_SIMD}

{$IFDEF CRYPTOLIB_X86_64_ASM}
// P-256 special-prime N=4 fast path: MULX product + folded shift/add reduction
// (gated on BMI2+ADX below). x86-64 only; i386 falls back to generic CIOS (its
// memory-resident kernel is not in-place safe for the aliased Mul/Sqr calls).
procedure FpKernelMontMulP256(PR, PA, PB, PCtx: PUInt64);
{$DEFINE CRYPTOLIB_FP_MONTMUL_P256}
{$I ..\..\Include\Simd\Common\ClpSimdProc4Begin_x86_64.inc}
{$I ..\..\Include\Simd\PointKernel\PointKernelP256Jac_x86_64.inc}
{$UNDEF CRYPTOLIB_FP_MONTMUL_P256}
end;

// P-256 dedicated Montgomery square: dual-chain SOS square (10 MULX vs the
// multiply's 16) + the same folded special-prime reduction (gated on BMI2+ADX
// below). x86-64 only.
procedure FpKernelMontSqrP256(PR, PA, PCtx: PUInt64);
{$DEFINE CRYPTOLIB_FP_MONTSQR_P256}
{$I ..\..\Include\Simd\Common\ClpSimdProc3Begin_x86_64.inc}
{$I ..\..\Include\Simd\PointKernel\PointKernelP256Jac_x86_64.inc}
{$UNDEF CRYPTOLIB_FP_MONTSQR_P256}
end;

// Fused P-256 incomplete-Jacobian doubling (a=-3): straight-line, stack-framed,
// inlining the special-prime field multiply. PR/PA are TFePoint bases. Gated on
// BMI2+ADX below; x86-64 only.
procedure FpKernelP256JacPointDouble(PR, PA, PCtx: PUInt64);
{$DEFINE CRYPTOLIB_FP_P256_JACPOINTDOUBLE}
{$I ..\..\Include\Simd\Common\ClpSimdProc3Begin_x86_64.inc}
{$I ..\..\Include\Simd\PointKernel\PointKernelP256Jac_x86_64.inc}
{$UNDEF CRYPTOLIB_FP_P256_JACPOINTDOUBLE}
end;

// Fused P-256 incomplete-Jacobian addition (add-2007-bl): masked-infinity
// completion inside; predicate operands H/RS exposed for the caller's P=Q
// detect-and-double. PScratch = TJacAddScratch, PA/PQ = TFePoint bases.
procedure FpKernelP256JacPointAdd(PScratch, PA, PQ, PCtx: PUInt64);
{$DEFINE CRYPTOLIB_FP_P256_JACPOINTADD}
{$I ..\..\Include\Simd\Common\ClpSimdProc4Begin_x86_64.inc}
{$I ..\..\Include\Simd\PointKernel\PointKernelP256Jac_x86_64.inc}
{$UNDEF CRYPTOLIB_FP_P256_JACPOINTADD}
end;

// Fused P-256 incomplete-Jacobian mixed addition: PQ affine (Z2=1 from MontOne).
procedure FpKernelP256JacPointAddMixed(PScratch, PA, PQ, PCtx: PUInt64);
{$DEFINE CRYPTOLIB_FP_P256_JACPOINTADDMIXED}
{$I ..\..\Include\Simd\Common\ClpSimdProc4Begin_x86_64.inc}
{$I ..\..\Include\Simd\PointKernel\PointKernelP256Jac_x86_64.inc}
{$UNDEF CRYPTOLIB_FP_P256_JACPOINTADDMIXED}
end;

// Fused secp256k1 incomplete-Jacobian doubling (a=0, dbl-2009-l): straight-line,
// stack-framed, inlining the generic MULX4 multiply / dedicated square (k1's prime
// is pseudo-Mersenne, so no folded reduction). PR/PA are TFePoint bases. Gated on
// BMI2+ADX below; x86-64 only.
procedure FpKernelK1JacPointDouble(PR, PA, PCtx: PUInt64);
{$DEFINE CRYPTOLIB_FP_K256_POINTDOUBLE}
{$I ..\..\Include\Simd\Common\ClpSimdProc3Begin_x86_64.inc}
{$I ..\..\Include\Simd\PointKernel\PointKernelK256Jac_x86_64.inc}
{$UNDEF CRYPTOLIB_FP_K256_POINTDOUBLE}
end;

// Fused secp256k1 incomplete-Jacobian addition (add-2007-bl): masked-infinity
// completion inside; predicate operands H/RS exposed for the caller's P=Q
// detect-and-double. PScratch = TJacAddScratch, PA/PQ = TFePoint bases.
procedure FpKernelK1JacPointAdd(PScratch, PA, PQ, PCtx: PUInt64);
{$DEFINE CRYPTOLIB_FP_K256_POINTADD}
{$I ..\..\Include\Simd\Common\ClpSimdProc4Begin_x86_64.inc}
{$I ..\..\Include\Simd\PointKernel\PointKernelK256Jac_x86_64.inc}
{$UNDEF CRYPTOLIB_FP_K256_POINTADD}
end;

// Fused secp256k1 incomplete-Jacobian mixed addition: PQ affine (Z2=1 from MontOne).
procedure FpKernelK1JacPointAddMixed(PScratch, PA, PQ, PCtx: PUInt64);
{$DEFINE CRYPTOLIB_FP_K256_POINTADDMIXED}
{$I ..\..\Include\Simd\Common\ClpSimdProc4Begin_x86_64.inc}
{$I ..\..\Include\Simd\PointKernel\PointKernelK256Jac_x86_64.inc}
{$UNDEF CRYPTOLIB_FP_K256_POINTADDMIXED}
end;

{$ENDIF}

{$ENDIF}

{ TPointKernelX86Backend }

class function TPointKernelX86Backend.IsSupported: Boolean;
begin
{$IFDEF CRYPTOLIB_X86_SIMD}
  Result := TCpuFeatures.X86.GetActiveSimdLevel() <> TX86SimdLevel.Scalar;
{$ELSE}
  Result := False;
{$ENDIF}
end;

class function TPointKernelX86Backend.MontMulP256(PR, PA, PB, PCtx: PUInt64): Boolean;
begin
{$IFDEF CRYPTOLIB_X86_64_ASM}
  if TX86SimdFeatures.HasBMI2ADX() then
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

class function TPointKernelX86Backend.MontSqrP256(PR, PA, PCtx: PUInt64): Boolean;
begin
{$IFDEF CRYPTOLIB_X86_64_ASM}
  if TX86SimdFeatures.HasBMI2ADX() then
  begin
    FpKernelMontSqrP256(PR, PA, PCtx);
    Result := True;
  end
  else
    Result := False;
{$ELSE}
  Result := False;
{$ENDIF}
end;

class function TPointKernelX86Backend.JacPointDoubleP256(PR, PA, PCtx: PUInt64): Boolean;
begin
{$IFDEF CRYPTOLIB_X86_64_ASM}
  if TX86SimdFeatures.HasBMI2ADX() then
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

class function TPointKernelX86Backend.JacPointAddP256(PScratch, PA, PQ, PCtx: PUInt64): Boolean;
begin
{$IFDEF CRYPTOLIB_X86_64_ASM}
  if TX86SimdFeatures.HasBMI2ADX() then
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

class function TPointKernelX86Backend.JacPointAddMixedP256(PScratch, PA, PQ, PCtx: PUInt64): Boolean;
begin
{$IFDEF CRYPTOLIB_X86_64_ASM}
  if TX86SimdFeatures.HasBMI2ADX() then
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

class function TPointKernelX86Backend.JacPointDoubleK256(PR, PA, PCtx: PUInt64): Boolean;
begin
{$IFDEF CRYPTOLIB_X86_64_ASM}
  if TX86SimdFeatures.HasBMI2ADX() then
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

class function TPointKernelX86Backend.JacPointAddK256(PScratch, PA, PQ, PCtx: PUInt64): Boolean;
begin
{$IFDEF CRYPTOLIB_X86_64_ASM}
  if TX86SimdFeatures.HasBMI2ADX() then
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

class function TPointKernelX86Backend.JacPointAddMixedK256(PScratch, PA, PQ, PCtx: PUInt64): Boolean;
begin
{$IFDEF CRYPTOLIB_X86_64_ASM}
  if TX86SimdFeatures.HasBMI2ADX() then
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

end.
