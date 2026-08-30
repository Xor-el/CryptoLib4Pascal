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

unit ClpPointKernelArmBackend;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
{$IFDEF CRYPTOLIB_AARCH64_ASM}
  ClpCpuFeatures,
  ClpSimdLevels,
{$ENDIF}
  ClpCryptoLibTypes;

type
  /// <summary>
  /// Arm kernel backend for the fused special-prime kernels. A leaf: capability
  /// probe plus the P-256 special-prime Montgomery multiply and the fused
  /// P-256/secp256k1 incomplete-Jacobian point operations. The arch-neutral
  /// dispatch and the scalar fallback live in <c>TPointKernelSimd</c> / the field
  /// units. Hot paths are in <c>Include/Simd/PointKernel/</c>.
  /// </summary>
  TPointKernelArmBackend = class sealed
  public
    class function IsSupported: Boolean; static; inline;
    /// <summary>P-256 special-prime Montgomery multiply PR := PA*PB*R^-1 mod p, with the
    /// folded (shift/add) reduction. PCtx = the P-256 [n0'=1, N=4, p0..p3]. Returns False
    /// when not aarch64 or no SIMD (caller falls back to generic CIOS).</summary>
    class function MontMulP256(PR, PA, PB, PCtx: PUInt64): Boolean; static;
    /// <summary>Fused P-256 incomplete-Jacobian doubling PR := 2*PA (Jacobian).</summary>
    class function JacPointDoubleP256(PR, PA, PCtx: PUInt64): Boolean; static;
    /// <summary>Fused P-256 incomplete-Jacobian addition; PScratch = TJacAddScratch.</summary>
    class function JacPointAddP256(PScratch, PA, PQ, PCtx: PUInt64): Boolean; static;
    /// <summary>Fused P-256 incomplete-Jacobian mixed addition (PQ a TFeAffine).</summary>
    class function JacPointAddMixedP256(PScratch, PA, PQ, PCtx: PUInt64): Boolean; static;
    /// <summary>Fused secp256k1 (a=0) incomplete-Jacobian doubling PR := 2*PA (Jacobian).</summary>
    class function JacPointDoubleK256(PR, PA, PCtx: PUInt64): Boolean; static;
    /// <summary>Fused secp256k1 incomplete-Jacobian addition; PScratch = TJacAddScratch.</summary>
    class function JacPointAddK256(PScratch, PA, PQ, PCtx: PUInt64): Boolean; static;
    /// <summary>Fused secp256k1 incomplete-Jacobian mixed addition (PQ a TFeAffine).</summary>
    class function JacPointAddMixedK256(PScratch, PA, PQ, PCtx: PUInt64): Boolean; static;
  end;

implementation

{$IFDEF CRYPTOLIB_AARCH64_ASM}

// P-256 special-prime N=4 fast path: mul/umulh product + folded shift/add reduction.
procedure FpKernelMontMulP256(PR, PA, PB, PCtx: PUInt64);
{$DEFINE CRYPTOLIB_FP_MONTMUL_P256}
{$I ..\..\Include\Simd\Common\ClpSimdProc4Begin_aarch64.inc}
{$I ..\..\Include\Simd\PointKernel\PointKernelP256Jac_aarch64.inc}
{$UNDEF CRYPTOLIB_FP_MONTMUL_P256}
end;

// Fused P-256 incomplete-Jacobian doubling (a=-3). PR/PA are TFePoint bases.
procedure FpKernelP256JacPointDouble(PR, PA, PCtx: PUInt64);
{$DEFINE CRYPTOLIB_FP_P256_JACPOINTDOUBLE}
{$I ..\..\Include\Simd\Common\ClpSimdProc3Begin_aarch64.inc}
{$I ..\..\Include\Simd\PointKernel\PointKernelP256Jac_aarch64.inc}
{$UNDEF CRYPTOLIB_FP_P256_JACPOINTDOUBLE}
end;

// Fused P-256 incomplete-Jacobian addition (add-2007-bl): masked-infinity inside;
// H/RS predicate exposed. PScratch = TJacAddScratch, PA/PQ = TFePoint bases.
procedure FpKernelP256JacPointAdd(PScratch, PA, PQ, PCtx: PUInt64);
{$DEFINE CRYPTOLIB_FP_P256_JACPOINTADD}
{$I ..\..\Include\Simd\Common\ClpSimdProc4Begin_aarch64.inc}
{$I ..\..\Include\Simd\PointKernel\PointKernelP256Jac_aarch64.inc}
{$UNDEF CRYPTOLIB_FP_P256_JACPOINTADD}
end;

// Fused P-256 incomplete-Jacobian mixed addition: PQ affine (Z2=1 from MontOne).
procedure FpKernelP256JacPointAddMixed(PScratch, PA, PQ, PCtx: PUInt64);
{$DEFINE CRYPTOLIB_FP_P256_JACPOINTADDMIXED}
{$I ..\..\Include\Simd\Common\ClpSimdProc4Begin_aarch64.inc}
{$I ..\..\Include\Simd\PointKernel\PointKernelP256Jac_aarch64.inc}
{$UNDEF CRYPTOLIB_FP_P256_JACPOINTADDMIXED}
end;

// Fused secp256k1 incomplete-Jacobian doubling (a=0, dbl-2009-l): straight-line,
// stack-framed, inlining the generic register montmul (k1's prime is pseudo-
// Mersenne, so no folded reduction; the square is that montmul with operands
// aliased). PR/PA are TFePoint bases.
procedure FpKernelK1JacPointDouble(PR, PA, PCtx: PUInt64);
{$DEFINE CRYPTOLIB_FP_K256_POINTDOUBLE}
{$I ..\..\Include\Simd\Common\ClpSimdProc3Begin_aarch64.inc}
{$I ..\..\Include\Simd\PointKernel\PointKernelK256Jac_aarch64.inc}
{$UNDEF CRYPTOLIB_FP_K256_POINTDOUBLE}
end;

// Fused secp256k1 incomplete-Jacobian addition (add-2007-bl): masked-infinity
// completion inside; predicate operands H/RS exposed for the caller's P=Q
// detect-and-double. PScratch = TJacAddScratch, PA/PQ = TFePoint bases.
procedure FpKernelK1JacPointAdd(PScratch, PA, PQ, PCtx: PUInt64);
{$DEFINE CRYPTOLIB_FP_K256_POINTADD}
{$I ..\..\Include\Simd\Common\ClpSimdProc4Begin_aarch64.inc}
{$I ..\..\Include\Simd\PointKernel\PointKernelK256Jac_aarch64.inc}
{$UNDEF CRYPTOLIB_FP_K256_POINTADD}
end;

// Fused secp256k1 incomplete-Jacobian mixed addition: PQ affine (Z2=1 from MontOne).
procedure FpKernelK1JacPointAddMixed(PScratch, PA, PQ, PCtx: PUInt64);
{$DEFINE CRYPTOLIB_FP_K256_POINTADDMIXED}
{$I ..\..\Include\Simd\Common\ClpSimdProc4Begin_aarch64.inc}
{$I ..\..\Include\Simd\PointKernel\PointKernelK256Jac_aarch64.inc}
{$UNDEF CRYPTOLIB_FP_K256_POINTADDMIXED}
end;

{$ENDIF}

{ TPointKernelArmBackend }

class function TPointKernelArmBackend.IsSupported: Boolean;
begin
{$IFDEF CRYPTOLIB_AARCH64_ASM}
  Result := TCpuFeatures.Arm.GetActiveSimdLevel() <> TArmSimdLevel.Scalar;
{$ELSE}
  Result := False;
{$ENDIF}
end;

class function TPointKernelArmBackend.MontMulP256(PR, PA, PB, PCtx: PUInt64): Boolean;
begin
{$IFDEF CRYPTOLIB_AARCH64_ASM}
  FpKernelMontMulP256(PR, PA, PB, PCtx);
  Result := True;
{$ELSE}
  Result := False;
{$ENDIF}
end;

class function TPointKernelArmBackend.JacPointDoubleP256(PR, PA, PCtx: PUInt64): Boolean;
begin
{$IFDEF CRYPTOLIB_AARCH64_ASM}
  FpKernelP256JacPointDouble(PR, PA, PCtx);
  Result := True;
{$ELSE}
  Result := False;
{$ENDIF}
end;

class function TPointKernelArmBackend.JacPointAddP256(PScratch, PA, PQ, PCtx: PUInt64): Boolean;
begin
{$IFDEF CRYPTOLIB_AARCH64_ASM}
  FpKernelP256JacPointAdd(PScratch, PA, PQ, PCtx);
  Result := True;
{$ELSE}
  Result := False;
{$ENDIF}
end;

class function TPointKernelArmBackend.JacPointAddMixedP256(PScratch, PA, PQ, PCtx: PUInt64): Boolean;
begin
{$IFDEF CRYPTOLIB_AARCH64_ASM}
  FpKernelP256JacPointAddMixed(PScratch, PA, PQ, PCtx);
  Result := True;
{$ELSE}
  Result := False;
{$ENDIF}
end;

class function TPointKernelArmBackend.JacPointDoubleK256(PR, PA, PCtx: PUInt64): Boolean;
begin
{$IFDEF CRYPTOLIB_AARCH64_ASM}
  FpKernelK1JacPointDouble(PR, PA, PCtx);
  Result := True;
{$ELSE}
  Result := False;
{$ENDIF}
end;

class function TPointKernelArmBackend.JacPointAddK256(PScratch, PA, PQ, PCtx: PUInt64): Boolean;
begin
{$IFDEF CRYPTOLIB_AARCH64_ASM}
  FpKernelK1JacPointAdd(PScratch, PA, PQ, PCtx);
  Result := True;
{$ELSE}
  Result := False;
{$ENDIF}
end;

class function TPointKernelArmBackend.JacPointAddMixedK256(PScratch, PA, PQ, PCtx: PUInt64): Boolean;
begin
{$IFDEF CRYPTOLIB_AARCH64_ASM}
  FpKernelK1JacPointAddMixed(PScratch, PA, PQ, PCtx);
  Result := True;
{$ELSE}
  Result := False;
{$ENDIF}
end;

end.
