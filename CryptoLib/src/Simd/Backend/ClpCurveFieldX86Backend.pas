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

unit ClpCurveFieldX86Backend;

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
  /// X86 kernel backend for the radix-2^51 curve25519 field.
  /// A leaf: capability probe plus the hot multiply/square. The arch-neutral
  /// dispatch and the Pascal fallback live in <c>TCurveFieldSimd</c> / the field
  /// unit. Kernels are in <c>Include/Simd/Curve25519/</c>. <c>Mul25519</c> /
  /// <c>Sqr25519</c> return <c>False</c> on an arch without a kernel.
  /// </summary>
  TCurveFieldX86Backend = class sealed
  public
    class function IsSupported: Boolean; static; inline;
    class function Mul25519(PF, PG, PH: PUInt64): Boolean; static;
    class function Sqr25519(PX, PZ: PUInt64): Boolean; static;
    class function Mul448(PF, PG, PH: PUInt64): Boolean; static;
    class function Sqr448(PX, PZ: PUInt64): Boolean; static;

    // radix-2^32 saturated MULX alternative to the plain-mul fe51 kernel
    // (i386 + BMI2 + ADX). Same fe51 5x51 interface (drop-in tier).
    class function Adx32Supported: Boolean; static; inline;
    class function Adx32Mul25519(PF, PG, PH: PUInt64): Boolean; static;
    class function Adx32Sqr25519(PX, PZ: PUInt64): Boolean; static;

    // radix-2^64 (saturated) curve25519 ADX tier (x86-64 + BMI2 + ADX).
    class function Fe64Supported: Boolean; static; inline;
    class procedure Fe64Mul25519(PF, PG, PH: PUInt64); static;
    class procedure Fe64Sqr25519(PX, PZ: PUInt64); static;
    class procedure Fe64Add(PA, PB, PR: PUInt64); static;
    class procedure Fe64Sub(PA, PB, PR: PUInt64); static;
    class procedure Fe64Mul121666(PF, PH: PUInt64); static;
    class procedure Fe64SqrN(PF, PH: PUInt64; AN: NativeInt); static;
    class procedure Fe64LadderStep25519(PState: PUInt64; AMask: UInt64); static;
  end;

implementation

{$IFDEF CRYPTOLIB_X86_SIMD}

// PH := PF * PG mod (2^255-19), five 64-bit limbs.
procedure Curve25519Fe51Mul(PH, PF, PG: PUInt64);
{$DEFINE CRYPTOLIB_CURVE25519_FE51MUL}
{$IFDEF CRYPTOLIB_X86_64_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc3Begin_x86_64.inc}
{$I ..\..\Include\Simd\Curve25519\X25519Field_Fe51_x86_64.inc}
{$ENDIF}
{$IFDEF CRYPTOLIB_I386_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc3Begin_i386.inc}
{$I ..\..\Include\Simd\Curve25519\X25519Field_Fe51_i386.inc}
{$ENDIF}
{$UNDEF CRYPTOLIB_CURVE25519_FE51MUL}
end;

// PH := PF^2 mod (2^255-19).
procedure Curve25519Fe51Sqr(PH, PF: PUInt64);
{$DEFINE CRYPTOLIB_CURVE25519_FE51SQR}
{$IFDEF CRYPTOLIB_X86_64_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc2Begin_x86_64.inc}
{$I ..\..\Include\Simd\Curve25519\X25519Field_Fe51_x86_64.inc}
{$ENDIF}
{$IFDEF CRYPTOLIB_I386_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc2Begin_i386.inc}
{$I ..\..\Include\Simd\Curve25519\X25519Field_Fe51_i386.inc}
{$ENDIF}
{$UNDEF CRYPTOLIB_CURVE25519_FE51SQR}
end;

// PH := PF * PG mod (2^448-2^224-1), eight 64-bit limbs.
procedure Curve448Fe56Mul(PH, PF, PG: PUInt64);
{$DEFINE CRYPTOLIB_CURVE448_FE56MUL}
{$IFDEF CRYPTOLIB_X86_64_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc3Begin_x86_64.inc}
{$I ..\..\Include\Simd\Curve448\X448Field_Fe56_x86_64.inc}
{$ENDIF}
{$IFDEF CRYPTOLIB_I386_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc3Begin_i386.inc}
{$I ..\..\Include\Simd\Curve448\X448Field_Fe56_i386.inc}
{$ENDIF}
{$UNDEF CRYPTOLIB_CURVE448_FE56MUL}
end;

// PH := PF^2 mod (2^448-2^224-1).
procedure Curve448Fe56Sqr(PH, PF: PUInt64);
{$DEFINE CRYPTOLIB_CURVE448_FE56SQR}
{$IFDEF CRYPTOLIB_X86_64_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc2Begin_x86_64.inc}
{$I ..\..\Include\Simd\Curve448\X448Field_Fe56_x86_64.inc}
{$ENDIF}
{$IFDEF CRYPTOLIB_I386_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc2Begin_i386.inc}
{$I ..\..\Include\Simd\Curve448\X448Field_Fe56_i386.inc}
{$ENDIF}
{$UNDEF CRYPTOLIB_CURVE448_FE56SQR}
end;

{$IFDEF CRYPTOLIB_I386_ASM}
// radix-2^32 saturated MULX curve25519 kernels (i386, BMI2 + ADX), fe51 interface.
procedure Curve25519Adx32Mul(PH, PF, PG: PUInt64);
{$DEFINE CRYPTOLIB_CURVE25519_ADX32MUL}
{$I ..\..\Include\Simd\Common\ClpSimdProc3Begin_i386.inc}
{$I ..\..\Include\Simd\Curve25519\X25519Field_Adx32_i386.inc}
{$UNDEF CRYPTOLIB_CURVE25519_ADX32MUL}
end;

procedure Curve25519Adx32Sqr(PH, PF: PUInt64);
{$DEFINE CRYPTOLIB_CURVE25519_ADX32SQR}
{$I ..\..\Include\Simd\Common\ClpSimdProc2Begin_i386.inc}
{$I ..\..\Include\Simd\Curve25519\X25519Field_Adx32_i386.inc}
{$UNDEF CRYPTOLIB_CURVE25519_ADX32SQR}
end;
{$ENDIF}

{$IFDEF CRYPTOLIB_X86_64_ASM}
// radix-2^64 (saturated) curve25519 ADX kernels. PH := PF * PG mod (2^255-19).
procedure Curve25519Fe64Mul(PH, PF, PG: PUInt64);
{$DEFINE CRYPTOLIB_CURVE25519_SAT64MUL}
{$I ..\..\Include\Simd\Common\ClpSimdProc3Begin_x86_64.inc}
{$I ..\..\Include\Simd\Curve25519\X25519Field_Sat64Adx_x86_64.inc}
{$UNDEF CRYPTOLIB_CURVE25519_SAT64MUL}
end;

// PH := PF^2 mod (2^255-19).
procedure Curve25519Fe64Sqr(PH, PF: PUInt64);
{$DEFINE CRYPTOLIB_CURVE25519_SAT64SQR}
{$I ..\..\Include\Simd\Common\ClpSimdProc2Begin_x86_64.inc}
{$I ..\..\Include\Simd\Curve25519\X25519Field_Sat64Adx_x86_64.inc}
{$UNDEF CRYPTOLIB_CURVE25519_SAT64SQR}
end;

// PH := PF + PG mod (2^255-19).
procedure Curve25519Fe64Add(PH, PF, PG: PUInt64);
{$DEFINE CRYPTOLIB_CURVE25519_SAT64ADD}
{$I ..\..\Include\Simd\Common\ClpSimdProc3Begin_x86_64.inc}
{$I ..\..\Include\Simd\Curve25519\X25519Field_Sat64Adx_x86_64.inc}
{$UNDEF CRYPTOLIB_CURVE25519_SAT64ADD}
end;

// PH := PF - PG mod (2^255-19).
procedure Curve25519Fe64Sub(PH, PF, PG: PUInt64);
{$DEFINE CRYPTOLIB_CURVE25519_SAT64SUB}
{$I ..\..\Include\Simd\Common\ClpSimdProc3Begin_x86_64.inc}
{$I ..\..\Include\Simd\Curve25519\X25519Field_Sat64Adx_x86_64.inc}
{$UNDEF CRYPTOLIB_CURVE25519_SAT64SUB}
end;

// PH := PF * 121666 mod (2^255-19).
procedure Curve25519Fe64Mul121666(PH, PF: PUInt64);
{$DEFINE CRYPTOLIB_CURVE25519_SAT64M121666}
{$I ..\..\Include\Simd\Common\ClpSimdProc2Begin_x86_64.inc}
{$I ..\..\Include\Simd\Curve25519\X25519Field_Sat64Adx_x86_64.inc}
{$UNDEF CRYPTOLIB_CURVE25519_SAT64M121666}
end;

// PH := PF^(2^AN) mod (2^255-19), AN >= 1 (AN is a public count, not a secret).
procedure Curve25519Fe64SqrN(PH, PF: PUInt64; AN: NativeInt);
{$DEFINE CRYPTOLIB_CURVE25519_SAT64SQRN}
{$I ..\..\Include\Simd\Common\ClpSimdProc3Begin_x86_64.inc}
{$I ..\..\Include\Simd\Curve25519\X25519Field_Sat64Adx_x86_64.inc}
{$UNDEF CRYPTOLIB_CURVE25519_SAT64SQRN}
end;

// One Montgomery ladder step + cswap over PState (x1,x2,z2,x3,z3, 4 limbs each).
procedure Curve25519Fe64LadderStep(PState: PUInt64; AMask: UInt64);
{$DEFINE CRYPTOLIB_CURVE25519_SAT64LADDER}
{$I ..\..\Include\Simd\Common\ClpSimdProc2Begin_x86_64.inc}
{$I ..\..\Include\Simd\Curve25519\X25519Field_Sat64Adx_x86_64.inc}
{$UNDEF CRYPTOLIB_CURVE25519_SAT64LADDER}
end;
{$ENDIF}

{$ENDIF}

class function TCurveFieldX86Backend.IsSupported: Boolean;
begin
{$IFDEF CRYPTOLIB_X86_SIMD}
  Result := TCpuFeatures.X86.GetActiveSimdLevel() <> TX86SimdLevel.Scalar;
{$ELSE}
  Result := False;
{$ENDIF}
end;

class function TCurveFieldX86Backend.Mul25519(PF, PG, PH: PUInt64): Boolean;
begin
{$IFDEF CRYPTOLIB_X86_SIMD}
  Curve25519Fe51Mul(PH, PF, PG);
  Result := True;
{$ELSE}
  Result := False;
{$ENDIF}
end;

class function TCurveFieldX86Backend.Sqr25519(PX, PZ: PUInt64): Boolean;
begin
{$IFDEF CRYPTOLIB_X86_SIMD}
  Curve25519Fe51Sqr(PZ, PX);
  Result := True;
{$ELSE}
  Result := False;
{$ENDIF}
end;

class function TCurveFieldX86Backend.Mul448(PF, PG, PH: PUInt64): Boolean;
begin
{$IFDEF CRYPTOLIB_X86_SIMD}
  Curve448Fe56Mul(PH, PF, PG);
  Result := True;
{$ELSE}
  Result := False;
{$ENDIF}
end;

class function TCurveFieldX86Backend.Sqr448(PX, PZ: PUInt64): Boolean;
begin
{$IFDEF CRYPTOLIB_X86_SIMD}
  Curve448Fe56Sqr(PZ, PX);
  Result := True;
{$ELSE}
  Result := False;
{$ENDIF}
end;

class function TCurveFieldX86Backend.Adx32Supported: Boolean;
begin
{$IFDEF CRYPTOLIB_I386_ASM}
  Result := IsSupported and TX86SimdFeatures.HasBMI2ADX();
{$ELSE}
  Result := False;
{$ENDIF}
end;

class function TCurveFieldX86Backend.Adx32Mul25519(PF, PG, PH: PUInt64): Boolean;
begin
{$IFDEF CRYPTOLIB_I386_ASM}
  Curve25519Adx32Mul(PH, PF, PG);
  Result := True;
{$ELSE}
  Result := False;
{$ENDIF}
end;

class function TCurveFieldX86Backend.Adx32Sqr25519(PX, PZ: PUInt64): Boolean;
begin
{$IFDEF CRYPTOLIB_I386_ASM}
  Curve25519Adx32Sqr(PZ, PX);
  Result := True;
{$ELSE}
  Result := False;
{$ENDIF}
end;

class function TCurveFieldX86Backend.Fe64Supported: Boolean;
begin
{$IFDEF CRYPTOLIB_X86_64_ASM}
  Result := IsSupported and TX86SimdFeatures.HasBMI2ADX();
{$ELSE}
  Result := False;
{$ENDIF}
end;

class procedure TCurveFieldX86Backend.Fe64Mul25519(PF, PG, PH: PUInt64);
begin
{$IFDEF CRYPTOLIB_X86_64_ASM}
  Curve25519Fe64Mul(PH, PF, PG);
{$ENDIF}
end;

class procedure TCurveFieldX86Backend.Fe64Sqr25519(PX, PZ: PUInt64);
begin
{$IFDEF CRYPTOLIB_X86_64_ASM}
  Curve25519Fe64Sqr(PZ, PX);
{$ENDIF}
end;

class procedure TCurveFieldX86Backend.Fe64Add(PA, PB, PR: PUInt64);
begin
{$IFDEF CRYPTOLIB_X86_64_ASM}
  Curve25519Fe64Add(PR, PA, PB);
{$ENDIF}
end;

class procedure TCurveFieldX86Backend.Fe64Sub(PA, PB, PR: PUInt64);
begin
{$IFDEF CRYPTOLIB_X86_64_ASM}
  Curve25519Fe64Sub(PR, PA, PB);
{$ENDIF}
end;

class procedure TCurveFieldX86Backend.Fe64Mul121666(PF, PH: PUInt64);
begin
{$IFDEF CRYPTOLIB_X86_64_ASM}
  Curve25519Fe64Mul121666(PH, PF);
{$ENDIF}
end;

class procedure TCurveFieldX86Backend.Fe64SqrN(PF, PH: PUInt64; AN: NativeInt);
begin
{$IFDEF CRYPTOLIB_X86_64_ASM}
  Curve25519Fe64SqrN(PH, PF, AN);
{$ENDIF}
end;

class procedure TCurveFieldX86Backend.Fe64LadderStep25519(PState: PUInt64; AMask: UInt64);
begin
{$IFDEF CRYPTOLIB_X86_64_ASM}
  Curve25519Fe64LadderStep(PState, AMask);
{$ENDIF}
end;

end.
