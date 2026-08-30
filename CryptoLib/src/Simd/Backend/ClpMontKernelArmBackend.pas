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

unit ClpMontKernelArmBackend;

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
  /// Arm kernel backend for prime-field (Fp) arithmetic. A leaf: capability
  /// probe plus the hot unreduced schoolbook multiply/square and the Montgomery
  /// multiply. The arch-neutral dispatch and the scalar fallback live in
  /// <c>TMontKernelSimd</c> / the field units. Hot paths are in
  /// <c>Include/Simd/MontKernel/</c>.
  /// </summary>
  TMontKernelArmBackend = class sealed
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
    /// <summary>Constant-time modular add/sub PR := (PA +/- PB) mod p. PCtx =
    /// [n0'(unused), N, p[0..N-1]]; inputs assumed < p. False on arch without it.</summary>
    class function ModAdd(PR, PA, PB, PCtx: PUInt64): Boolean; static;
    class function ModSub(PR, PA, PB, PCtx: PUInt64): Boolean; static;
  end;

implementation

{$IFDEF CRYPTOLIB_AARCH64_ASM}

// Z[0..2N-1] := X[0..N-1] * Y[0..N-1].
procedure FpKernelMul(PX, PY, PZ: PUInt64; ALimbs64: NativeInt);
{$DEFINE CRYPTOLIB_FP_MUL}
{$I ..\..\Include\Simd\Common\ClpSimdProc4Begin_aarch64.inc}
{$I ..\..\Include\Simd\MontKernel\MontKernel_aarch64.inc}
{$UNDEF CRYPTOLIB_FP_MUL}
end;

// Z[0..2N-1] := X[0..N-1]^2.
procedure FpKernelSqr(PX, PZ: PUInt64; ALimbs64: NativeInt);
{$DEFINE CRYPTOLIB_FP_SQR}
{$I ..\..\Include\Simd\Common\ClpSimdProc3Begin_aarch64.inc}
{$I ..\..\Include\Simd\MontKernel\MontKernel_aarch64.inc}
{$UNDEF CRYPTOLIB_FP_SQR}
end;

// Fused CIOS Montgomery multiply (FP_MONTMUL selector), width-general fallback.
procedure FpKernelMontMul(PR, PA, PB, PCtx: PUInt64);
{$DEFINE CRYPTOLIB_FP_MONTMUL}
{$I ..\..\Include\Simd\Common\ClpSimdProc4Begin_aarch64.inc}
{$I ..\..\Include\Simd\MontKernel\MontKernel_aarch64.inc}
{$UNDEF CRYPTOLIB_FP_MONTMUL}
end;

// Fully-unrolled register-resident Montgomery multiply per width N=4..9,
// dispatched by N below.
procedure FpKernelMontMulReg4(PR, PA, PB, PCtx: PUInt64);
{$DEFINE CRYPTOLIB_FP_MONTMUL_REG4}
{$I ..\..\Include\Simd\Common\ClpSimdProc4Begin_aarch64.inc}
{$I ..\..\Include\Simd\MontKernel\MontKernel_aarch64.inc}
{$UNDEF CRYPTOLIB_FP_MONTMUL_REG4}
end;

procedure FpKernelMontMulReg5(PR, PA, PB, PCtx: PUInt64);
{$DEFINE CRYPTOLIB_FP_MONTMUL_REG5}
{$I ..\..\Include\Simd\Common\ClpSimdProc4Begin_aarch64.inc}
{$I ..\..\Include\Simd\MontKernel\MontKernel_aarch64.inc}
{$UNDEF CRYPTOLIB_FP_MONTMUL_REG5}
end;

procedure FpKernelMontMulReg6(PR, PA, PB, PCtx: PUInt64);
{$DEFINE CRYPTOLIB_FP_MONTMUL_REG6}
{$I ..\..\Include\Simd\Common\ClpSimdProc4Begin_aarch64.inc}
{$I ..\..\Include\Simd\MontKernel\MontKernel_aarch64.inc}
{$UNDEF CRYPTOLIB_FP_MONTMUL_REG6}
end;

procedure FpKernelMontMulReg7(PR, PA, PB, PCtx: PUInt64);
{$DEFINE CRYPTOLIB_FP_MONTMUL_REG7}
{$I ..\..\Include\Simd\Common\ClpSimdProc4Begin_aarch64.inc}
{$I ..\..\Include\Simd\MontKernel\MontKernel_aarch64.inc}
{$UNDEF CRYPTOLIB_FP_MONTMUL_REG7}
end;

procedure FpKernelMontMulReg8(PR, PA, PB, PCtx: PUInt64);
{$DEFINE CRYPTOLIB_FP_MONTMUL_REG8}
{$I ..\..\Include\Simd\Common\ClpSimdProc4Begin_aarch64.inc}
{$I ..\..\Include\Simd\MontKernel\MontKernel_aarch64.inc}
{$UNDEF CRYPTOLIB_FP_MONTMUL_REG8}
end;

procedure FpKernelMontMulReg9(PR, PA, PB, PCtx: PUInt64);
{$DEFINE CRYPTOLIB_FP_MONTMUL_REG9}
{$I ..\..\Include\Simd\Common\ClpSimdProc4Begin_aarch64.inc}
{$I ..\..\Include\Simd\MontKernel\MontKernel_aarch64.inc}
{$UNDEF CRYPTOLIB_FP_MONTMUL_REG9}
end;

// Constant-time modular add/sub (FP_MODADD / FP_MODSUB selectors), width-general.
procedure FpKernelModAdd(PR, PA, PB, PCtx: PUInt64);
{$DEFINE CRYPTOLIB_FP_MODADD}
{$I ..\..\Include\Simd\Common\ClpSimdProc4Begin_aarch64.inc}
{$I ..\..\Include\Simd\MontKernel\MontKernel_aarch64.inc}
{$UNDEF CRYPTOLIB_FP_MODADD}
end;

procedure FpKernelModSub(PR, PA, PB, PCtx: PUInt64);
{$DEFINE CRYPTOLIB_FP_MODSUB}
{$I ..\..\Include\Simd\Common\ClpSimdProc4Begin_aarch64.inc}
{$I ..\..\Include\Simd\MontKernel\MontKernel_aarch64.inc}
{$UNDEF CRYPTOLIB_FP_MODSUB}
end;

{$ENDIF}

{ TMontKernelArmBackend }

class function TMontKernelArmBackend.IsSupported: Boolean;
begin
{$IFDEF CRYPTOLIB_AARCH64_ASM}
  Result := TCpuFeatures.Arm.GetActiveSimdLevel() <> TArmSimdLevel.Scalar;
{$ELSE}
  Result := False;
{$ENDIF}
end;

class procedure TMontKernelArmBackend.Mul(PX, PY, PZ: PUInt64; ALimbs64: NativeInt);
begin
{$IFDEF CRYPTOLIB_AARCH64_ASM}
  FpKernelMul(PX, PY, PZ, ALimbs64);
{$ENDIF}
end;

class procedure TMontKernelArmBackend.Sqr(PX, PZ: PUInt64; ALimbs64: NativeInt);
begin
{$IFDEF CRYPTOLIB_AARCH64_ASM}
  FpKernelSqr(PX, PZ, ALimbs64);
{$ENDIF}
end;

class function TMontKernelArmBackend.MontMul(PR, PA, PB, PCtx: PUInt64): Boolean;
begin
{$IFDEF CRYPTOLIB_AARCH64_ASM}
  // CtxData[1] = N (uint64 limbs). N=4..9 take a fully-unrolled register-resident
  // kernel; any other width uses the width-general loop.
  case PUInt64(PByte(PCtx) + 8)^ of
    4: FpKernelMontMulReg4(PR, PA, PB, PCtx);
    5: FpKernelMontMulReg5(PR, PA, PB, PCtx);
    6: FpKernelMontMulReg6(PR, PA, PB, PCtx);
    7: FpKernelMontMulReg7(PR, PA, PB, PCtx);
    8: FpKernelMontMulReg8(PR, PA, PB, PCtx);
    9: FpKernelMontMulReg9(PR, PA, PB, PCtx);
  else
    FpKernelMontMul(PR, PA, PB, PCtx);
  end;
  Result := True;
{$ELSE}
  Result := False;
{$ENDIF}
end;

class function TMontKernelArmBackend.ModAdd(PR, PA, PB, PCtx: PUInt64): Boolean;
begin
{$IFDEF CRYPTOLIB_AARCH64_ASM}
  FpKernelModAdd(PR, PA, PB, PCtx);
  Result := True;
{$ELSE}
  Result := False;
{$ENDIF}
end;

class function TMontKernelArmBackend.ModSub(PR, PA, PB, PCtx: PUInt64): Boolean;
begin
{$IFDEF CRYPTOLIB_AARCH64_ASM}
  FpKernelModSub(PR, PA, PB, PCtx);
  Result := True;
{$ELSE}
  Result := False;
{$ENDIF}
end;

end.
