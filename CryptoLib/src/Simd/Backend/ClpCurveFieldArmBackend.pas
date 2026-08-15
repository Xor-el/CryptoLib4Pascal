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

unit ClpCurveFieldArmBackend;

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
  /// AArch64 kernel backend for the reduced-radix curve fields (RFC 7748/8032).
  /// A leaf: capability probe plus the hot signed operand-scanning multiply/
  /// square. The arch-neutral dispatch and the scalar fallback live in
  /// <c>TCurveFieldSimd</c> / the field units. Hot paths are in
  /// <c>Include/Simd/Curve25519/</c>.
  /// </summary>
  TCurveFieldArmBackend = class sealed
  public
    class function IsSupported: Boolean; static;
    class procedure Mul25519(PF, PG, PH: Pointer); static;
    class procedure Sqr25519(PX, PZ: Pointer); static;
    class procedure Add25519(PX, PY, PZ: Pointer); static;
    class procedure Sub25519(PX, PY, PZ: Pointer); static;
    class procedure Apm25519(PX, PY, PZp, PZm: Pointer); static;
    class procedure CSwap25519(ASwap: NativeInt; PA, PB: Pointer); static;
    class procedure Carry25519(PZ: Pointer); static;
    class procedure MulWord25519(PX: Pointer; AY: NativeInt; PZ: Pointer); static;
  end;

implementation

{$IFDEF CRYPTOLIB_AARCH64_ASM}

// PH[0..9] := PF[0..9] * PG[0..9] (mod 2^255-19), ten signed Int32 limbs.
procedure FeMul25519Asm(PF, PG, PH: Pointer);
{$DEFINE CRYPTOLIB_CURVE25519_MUL}
{$I ..\..\Include\Simd\Common\ClpSimdProc3Begin_aarch64.inc}
{$I ..\..\Include\Simd\Curve25519\X25519Field_aarch64.inc}
{$UNDEF CRYPTOLIB_CURVE25519_MUL}
end;

// PZ[0..9] := PX[0..9]^2 (mod 2^255-19), ten signed Int32 limbs.
procedure FeSqr25519Asm(PX, PZ: Pointer);
{$DEFINE CRYPTOLIB_CURVE25519_SQR}
{$I ..\..\Include\Simd\Common\ClpSimdProc2Begin_aarch64.inc}
{$I ..\..\Include\Simd\Curve25519\X25519Field_aarch64.inc}
{$UNDEF CRYPTOLIB_CURVE25519_SQR}
end;

// 25519 small-op kernels (branch-free).
procedure FeAdd25519Asm(PX, PY, PZ: Pointer);
{$DEFINE CRYPTOLIB_CURVE25519_ADD}
{$I ..\..\Include\Simd\Common\ClpSimdProc3Begin_aarch64.inc}
{$I ..\..\Include\Simd\Curve25519\X25519Field_aarch64.inc}
{$UNDEF CRYPTOLIB_CURVE25519_ADD}
end;

procedure FeSub25519Asm(PX, PY, PZ: Pointer);
{$DEFINE CRYPTOLIB_CURVE25519_SUB}
{$I ..\..\Include\Simd\Common\ClpSimdProc3Begin_aarch64.inc}
{$I ..\..\Include\Simd\Curve25519\X25519Field_aarch64.inc}
{$UNDEF CRYPTOLIB_CURVE25519_SUB}
end;

procedure FeApm25519Asm(PX, PY, PZp, PZm: Pointer);
{$DEFINE CRYPTOLIB_CURVE25519_APM}
{$I ..\..\Include\Simd\Common\ClpSimdProc4Begin_aarch64.inc}
{$I ..\..\Include\Simd\Curve25519\X25519Field_aarch64.inc}
{$UNDEF CRYPTOLIB_CURVE25519_APM}
end;

procedure FeCSwap25519Asm(ASwap: NativeInt; PA, PB: Pointer);
{$DEFINE CRYPTOLIB_CURVE25519_CSWAP}
{$I ..\..\Include\Simd\Common\ClpSimdProc3Begin_aarch64.inc}
{$I ..\..\Include\Simd\Curve25519\X25519Field_aarch64.inc}
{$UNDEF CRYPTOLIB_CURVE25519_CSWAP}
end;

procedure FeCarry25519Asm(PZ: Pointer);
{$DEFINE CRYPTOLIB_CURVE25519_CARRY}
{$I ..\..\Include\Simd\Common\ClpSimdProc1Begin_aarch64.inc}
{$I ..\..\Include\Simd\Curve25519\X25519Field_aarch64.inc}
{$UNDEF CRYPTOLIB_CURVE25519_CARRY}
end;

procedure FeMulWord25519Asm(PX: Pointer; AY: NativeInt; PZ: Pointer);
{$DEFINE CRYPTOLIB_CURVE25519_MULWORD}
{$I ..\..\Include\Simd\Common\ClpSimdProc3Begin_aarch64.inc}
{$I ..\..\Include\Simd\Curve25519\X25519Field_aarch64.inc}
{$UNDEF CRYPTOLIB_CURVE25519_MULWORD}
end;

{$ENDIF}

{ TCurveFieldArmBackend }

class function TCurveFieldArmBackend.IsSupported: Boolean;
begin
{$IFDEF CRYPTOLIB_AARCH64_ASM}
  // Kernels use plain integer ops (no CPU-feature dependency); gate only on
  // "not forced scalar" so a CRYPTOLIB_FORCE_SCALAR build (which pins the active
  // level to Scalar) falls back to the scalar path.
  Result := TCpuFeatures.Arm.GetActiveSimdLevel() <> TArmSimdLevel.Scalar;
{$ELSE}
  Result := False;
{$ENDIF}
end;

class procedure TCurveFieldArmBackend.Mul25519(PF, PG, PH: Pointer);
begin
{$IFDEF CRYPTOLIB_AARCH64_ASM}
  FeMul25519Asm(PF, PG, PH);
{$ENDIF}
end;

class procedure TCurveFieldArmBackend.Add25519(PX, PY, PZ: Pointer);
begin
{$IFDEF CRYPTOLIB_AARCH64_ASM}
  FeAdd25519Asm(PX, PY, PZ);
{$ENDIF}
end;

class procedure TCurveFieldArmBackend.Sub25519(PX, PY, PZ: Pointer);
begin
{$IFDEF CRYPTOLIB_AARCH64_ASM}
  FeSub25519Asm(PX, PY, PZ);
{$ENDIF}
end;

class procedure TCurveFieldArmBackend.Apm25519(PX, PY, PZp, PZm: Pointer);
begin
{$IFDEF CRYPTOLIB_AARCH64_ASM}
  FeApm25519Asm(PX, PY, PZp, PZm);
{$ENDIF}
end;

class procedure TCurveFieldArmBackend.CSwap25519(ASwap: NativeInt; PA, PB: Pointer);
begin
{$IFDEF CRYPTOLIB_AARCH64_ASM}
  FeCSwap25519Asm(ASwap, PA, PB);
{$ENDIF}
end;

class procedure TCurveFieldArmBackend.Carry25519(PZ: Pointer);
begin
{$IFDEF CRYPTOLIB_AARCH64_ASM}
  FeCarry25519Asm(PZ);
{$ENDIF}
end;

class procedure TCurveFieldArmBackend.MulWord25519(PX: Pointer; AY: NativeInt; PZ: Pointer);
begin
{$IFDEF CRYPTOLIB_AARCH64_ASM}
  FeMulWord25519Asm(PX, AY, PZ);
{$ENDIF}
end;

class procedure TCurveFieldArmBackend.Sqr25519(PX, PZ: Pointer);
begin
{$IFDEF CRYPTOLIB_AARCH64_ASM}
  FeSqr25519Asm(PX, PZ);
{$ENDIF}
end;

end.
