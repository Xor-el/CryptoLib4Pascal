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

unit ClpFpKernelArmBackend;

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
  /// AArch64 big-integer kernel backend for prime-field (Fp) multiplication/
  /// square. A leaf: capability probe plus the hot schoolbook multiply/square.
  /// The arch-neutral dispatch and the scalar fallback live in
  /// <c>TFpKernelSimd</c> / the field units. Hot paths are in
  /// <c>Include/Simd/FpKernel/</c>.
  /// </summary>
  TFpKernelArmBackend = class sealed
  public
    class function IsSupported: Boolean; static; inline;
    /// <summary>Z[0..2N-1] := X * Y, ALimbs64 = uint64 limb count N.</summary>
    class procedure Mul(PX, PY, PZ: PUInt64; ALimbs64: NativeInt); static;
    /// <summary>Z[0..2N-1] := X^2.</summary>
    class procedure Sqr(PX, PZ: PUInt64; ALimbs64: NativeInt); static;
    /// <summary>Fused CIOS Montgomery multiply PR := PA*PB*R^-1 mod p. PCtx =
    /// [n0', N, p[0..N-1]]; PR is the N+2-limb scratch and receives the reduced
    /// N-limb result. Returns False on an arch without the kernel.</summary>
    class function MontMul(PR, PA, PB, PCtx: PUInt64): Boolean; static;
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
    /// <summary>Constant-time modular add/sub PR := (PA +/- PB) mod p. PCtx =
    /// [n0'(unused), N, p[0..N-1]]; inputs assumed < p. False on arch without it.</summary>
    class function ModAdd(PR, PA, PB, PCtx: PUInt64): Boolean; static;
    class function ModSub(PR, PA, PB, PCtx: PUInt64): Boolean; static;
  end;

implementation

{$IFDEF CRYPTOLIB_AARCH64_ASM}

// Z[0..2N-1] := X[0..N-1] * Y[0..N-1].
procedure FpKernelMulAsm(PX, PY, PZ: PUInt64; ALimbs64: NativeInt);
{$DEFINE CRYPTOLIB_FP_MUL}
{$I ..\..\Include\Simd\Common\ClpSimdProc4Begin_aarch64.inc}
{$I ..\..\Include\Simd\FpKernel\FpKernel_aarch64.inc}
{$UNDEF CRYPTOLIB_FP_MUL}
end;

// Z[0..2N-1] := X[0..N-1]^2.
procedure FpKernelSqrAsm(PX, PZ: PUInt64; ALimbs64: NativeInt);
{$DEFINE CRYPTOLIB_FP_SQR}
{$I ..\..\Include\Simd\Common\ClpSimdProc3Begin_aarch64.inc}
{$I ..\..\Include\Simd\FpKernel\FpKernel_aarch64.inc}
{$UNDEF CRYPTOLIB_FP_SQR}
end;

// Fused CIOS Montgomery multiply (FP_MONTMUL selector), width-general fallback.
procedure FpKernelMontMulAsm(PR, PA, PB, PCtx: PUInt64);
{$DEFINE CRYPTOLIB_FP_MONTMUL}
{$I ..\..\Include\Simd\Common\ClpSimdProc4Begin_aarch64.inc}
{$I ..\..\Include\Simd\FpKernel\FpKernel_aarch64.inc}
{$UNDEF CRYPTOLIB_FP_MONTMUL}
end;

// Fully-unrolled register-resident Montgomery multiply per width N=4..9,
// dispatched by N below.
procedure FpKernelMontMulReg4Asm(PR, PA, PB, PCtx: PUInt64);
{$DEFINE CRYPTOLIB_FP_MONTMUL_REG4}
{$I ..\..\Include\Simd\Common\ClpSimdProc4Begin_aarch64.inc}
{$I ..\..\Include\Simd\FpKernel\FpKernel_aarch64.inc}
{$UNDEF CRYPTOLIB_FP_MONTMUL_REG4}
end;

procedure FpKernelMontMulReg5Asm(PR, PA, PB, PCtx: PUInt64);
{$DEFINE CRYPTOLIB_FP_MONTMUL_REG5}
{$I ..\..\Include\Simd\Common\ClpSimdProc4Begin_aarch64.inc}
{$I ..\..\Include\Simd\FpKernel\FpKernel_aarch64.inc}
{$UNDEF CRYPTOLIB_FP_MONTMUL_REG5}
end;

procedure FpKernelMontMulReg6Asm(PR, PA, PB, PCtx: PUInt64);
{$DEFINE CRYPTOLIB_FP_MONTMUL_REG6}
{$I ..\..\Include\Simd\Common\ClpSimdProc4Begin_aarch64.inc}
{$I ..\..\Include\Simd\FpKernel\FpKernel_aarch64.inc}
{$UNDEF CRYPTOLIB_FP_MONTMUL_REG6}
end;

procedure FpKernelMontMulReg7Asm(PR, PA, PB, PCtx: PUInt64);
{$DEFINE CRYPTOLIB_FP_MONTMUL_REG7}
{$I ..\..\Include\Simd\Common\ClpSimdProc4Begin_aarch64.inc}
{$I ..\..\Include\Simd\FpKernel\FpKernel_aarch64.inc}
{$UNDEF CRYPTOLIB_FP_MONTMUL_REG7}
end;

procedure FpKernelMontMulReg8Asm(PR, PA, PB, PCtx: PUInt64);
{$DEFINE CRYPTOLIB_FP_MONTMUL_REG8}
{$I ..\..\Include\Simd\Common\ClpSimdProc4Begin_aarch64.inc}
{$I ..\..\Include\Simd\FpKernel\FpKernel_aarch64.inc}
{$UNDEF CRYPTOLIB_FP_MONTMUL_REG8}
end;

procedure FpKernelMontMulReg9Asm(PR, PA, PB, PCtx: PUInt64);
{$DEFINE CRYPTOLIB_FP_MONTMUL_REG9}
{$I ..\..\Include\Simd\Common\ClpSimdProc4Begin_aarch64.inc}
{$I ..\..\Include\Simd\FpKernel\FpKernel_aarch64.inc}
{$UNDEF CRYPTOLIB_FP_MONTMUL_REG9}
end;

// P-256 special-prime N=4 fast path: mul/umulh product + folded shift/add reduction.
procedure FpKernelMontMulP256Asm(PR, PA, PB, PCtx: PUInt64);
{$DEFINE CRYPTOLIB_FP_MONTMUL_P256}
{$I ..\..\Include\Simd\Common\ClpSimdProc4Begin_aarch64.inc}
{$I ..\..\Include\Simd\FpKernel\FpKernel_aarch64.inc}
{$UNDEF CRYPTOLIB_FP_MONTMUL_P256}
end;

// Fused P-256 incomplete-Jacobian doubling (a=-3). PR/PA are TFePoint bases.
procedure FpKernelP256JacPointDoubleAsm(PR, PA, PCtx: PUInt64);
{$DEFINE CRYPTOLIB_FP_P256_JACPOINTDOUBLE}
{$I ..\..\Include\Simd\Common\ClpSimdProc3Begin_aarch64.inc}
{$I ..\..\Include\Simd\FpKernel\FpKernelP256JacPoint_aarch64.inc}
{$UNDEF CRYPTOLIB_FP_P256_JACPOINTDOUBLE}
end;

// Fused P-256 incomplete-Jacobian addition (add-2007-bl): masked-infinity inside;
// H/RS predicate exposed. PScratch = TJacAddScratch, PA/PQ = TFePoint bases.
procedure FpKernelP256JacPointAddAsm(PScratch, PA, PQ, PCtx: PUInt64);
{$DEFINE CRYPTOLIB_FP_P256_JACPOINTADD}
{$I ..\..\Include\Simd\Common\ClpSimdProc4Begin_aarch64.inc}
{$I ..\..\Include\Simd\FpKernel\FpKernelP256JacPoint_aarch64.inc}
{$UNDEF CRYPTOLIB_FP_P256_JACPOINTADD}
end;

// Fused P-256 incomplete-Jacobian mixed addition: PQ affine (Z2=1 from MontOne).
procedure FpKernelP256JacPointAddMixedAsm(PScratch, PA, PQ, PCtx: PUInt64);
{$DEFINE CRYPTOLIB_FP_P256_JACPOINTADDMIXED}
{$I ..\..\Include\Simd\Common\ClpSimdProc4Begin_aarch64.inc}
{$I ..\..\Include\Simd\FpKernel\FpKernelP256JacPoint_aarch64.inc}
{$UNDEF CRYPTOLIB_FP_P256_JACPOINTADDMIXED}
end;

// Constant-time modular add/sub (FP_MODADD / FP_MODSUB selectors), width-general.
procedure FpKernelModAddAsm(PR, PA, PB, PCtx: PUInt64);
{$DEFINE CRYPTOLIB_FP_MODADD}
{$I ..\..\Include\Simd\Common\ClpSimdProc4Begin_aarch64.inc}
{$I ..\..\Include\Simd\FpKernel\FpKernel_aarch64.inc}
{$UNDEF CRYPTOLIB_FP_MODADD}
end;

procedure FpKernelModSubAsm(PR, PA, PB, PCtx: PUInt64);
{$DEFINE CRYPTOLIB_FP_MODSUB}
{$I ..\..\Include\Simd\Common\ClpSimdProc4Begin_aarch64.inc}
{$I ..\..\Include\Simd\FpKernel\FpKernel_aarch64.inc}
{$UNDEF CRYPTOLIB_FP_MODSUB}
end;

{$ENDIF}

{ TFpKernelArmBackend }

class function TFpKernelArmBackend.IsSupported: Boolean;
begin
{$IFDEF CRYPTOLIB_AARCH64_ASM}
  Result := TCpuFeatures.Arm.GetActiveSimdLevel() <> TArmSimdLevel.Scalar;
{$ELSE}
  Result := False;
{$ENDIF}
end;

class procedure TFpKernelArmBackend.Mul(PX, PY, PZ: PUInt64; ALimbs64: NativeInt);
begin
{$IFDEF CRYPTOLIB_AARCH64_ASM}
  FpKernelMulAsm(PX, PY, PZ, ALimbs64);
{$ENDIF}
end;

class procedure TFpKernelArmBackend.Sqr(PX, PZ: PUInt64; ALimbs64: NativeInt);
begin
{$IFDEF CRYPTOLIB_AARCH64_ASM}
  FpKernelSqrAsm(PX, PZ, ALimbs64);
{$ENDIF}
end;

class function TFpKernelArmBackend.MontMul(PR, PA, PB, PCtx: PUInt64): Boolean;
begin
{$IFDEF CRYPTOLIB_AARCH64_ASM}
  // CtxData[1] = N (uint64 limbs). N=4..9 take a fully-unrolled register-resident
  // kernel; any other width uses the width-general loop.
  case PUInt64(PByte(PCtx) + 8)^ of
    4: FpKernelMontMulReg4Asm(PR, PA, PB, PCtx);
    5: FpKernelMontMulReg5Asm(PR, PA, PB, PCtx);
    6: FpKernelMontMulReg6Asm(PR, PA, PB, PCtx);
    7: FpKernelMontMulReg7Asm(PR, PA, PB, PCtx);
    8: FpKernelMontMulReg8Asm(PR, PA, PB, PCtx);
    9: FpKernelMontMulReg9Asm(PR, PA, PB, PCtx);
  else
    FpKernelMontMulAsm(PR, PA, PB, PCtx);
  end;
  Result := True;
{$ELSE}
  Result := False;
{$ENDIF}
end;

class function TFpKernelArmBackend.MontMulP256(PR, PA, PB, PCtx: PUInt64): Boolean;
begin
{$IFDEF CRYPTOLIB_AARCH64_ASM}
  FpKernelMontMulP256Asm(PR, PA, PB, PCtx);
  Result := True;
{$ELSE}
  Result := False;
{$ENDIF}
end;

class function TFpKernelArmBackend.JacPointDoubleP256(PR, PA, PCtx: PUInt64): Boolean;
begin
{$IFDEF CRYPTOLIB_AARCH64_ASM}
  FpKernelP256JacPointDoubleAsm(PR, PA, PCtx);
  Result := True;
{$ELSE}
  Result := False;
{$ENDIF}
end;

class function TFpKernelArmBackend.JacPointAddP256(PScratch, PA, PQ, PCtx: PUInt64): Boolean;
begin
{$IFDEF CRYPTOLIB_AARCH64_ASM}
  FpKernelP256JacPointAddAsm(PScratch, PA, PQ, PCtx);
  Result := True;
{$ELSE}
  Result := False;
{$ENDIF}
end;

class function TFpKernelArmBackend.JacPointAddMixedP256(PScratch, PA, PQ, PCtx: PUInt64): Boolean;
begin
{$IFDEF CRYPTOLIB_AARCH64_ASM}
  FpKernelP256JacPointAddMixedAsm(PScratch, PA, PQ, PCtx);
  Result := True;
{$ELSE}
  Result := False;
{$ENDIF}
end;

class function TFpKernelArmBackend.ModAdd(PR, PA, PB, PCtx: PUInt64): Boolean;
begin
{$IFDEF CRYPTOLIB_AARCH64_ASM}
  FpKernelModAddAsm(PR, PA, PB, PCtx);
  Result := True;
{$ELSE}
  Result := False;
{$ENDIF}
end;

class function TFpKernelArmBackend.ModSub(PR, PA, PB, PCtx: PUInt64): Boolean;
begin
{$IFDEF CRYPTOLIB_AARCH64_ASM}
  FpKernelModSubAsm(PR, PA, PB, PCtx);
  Result := True;
{$ELSE}
  Result := False;
{$ENDIF}
end;

end.
