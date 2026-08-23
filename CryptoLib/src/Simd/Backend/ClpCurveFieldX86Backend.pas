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
{$ENDIF}
  ClpCryptoLibTypes;

type
  /// <summary>
  /// x86 (i386 + x86-64) kernel backend for the radix-2^51 curve25519 field.
  /// A leaf: capability probe plus the hot multiply/square. The arch-neutral
  /// dispatch and the Pascal fallback live in <c>TCurveFieldSimd</c> / the field
  /// unit. Kernels are in <c>Include/Simd/Curve25519/</c>. <c>Mul25519</c> /
  /// <c>Sqr25519</c> return <c>False</c> on an arch without a kernel yet (i386).
  /// </summary>
  TCurveFieldX86Backend = class sealed
  public
    class function IsSupported: Boolean; static; inline;
    class function Mul25519(PF, PG, PH: PUInt64): Boolean; static;
    class function Sqr25519(PX, PZ: PUInt64): Boolean; static;
    class function Mul448(PF, PG, PH: PUInt64): Boolean; static;
    class function Sqr448(PX, PZ: PUInt64): Boolean; static;
  end;

implementation

{$IFDEF CRYPTOLIB_X86_SIMD}

// PH := PF * PG mod (2^255-19), five 64-bit limbs.
procedure Curve25519Fe51MulAsm(PH, PF, PG: PUInt64);
{$DEFINE CRYPTOLIB_CURVE25519_FE64MUL}
{$IFDEF CRYPTOLIB_X86_64_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc3Begin_x86_64.inc}
{$I ..\..\Include\Simd\Curve25519\X25519Field_Fe64_x86_64.inc}
{$ENDIF}
{$IFDEF CRYPTOLIB_I386_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc3Begin_i386.inc}
{$I ..\..\Include\Simd\Curve25519\X25519Field_Fe64_i386.inc}
{$ENDIF}
{$UNDEF CRYPTOLIB_CURVE25519_FE64MUL}
end;

// PH := PF^2 mod (2^255-19).
procedure Curve25519Fe51SqrAsm(PH, PF: PUInt64);
{$DEFINE CRYPTOLIB_CURVE25519_FE64SQR}
{$IFDEF CRYPTOLIB_X86_64_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc2Begin_x86_64.inc}
{$I ..\..\Include\Simd\Curve25519\X25519Field_Fe64_x86_64.inc}
{$ENDIF}
{$IFDEF CRYPTOLIB_I386_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc2Begin_i386.inc}
{$I ..\..\Include\Simd\Curve25519\X25519Field_Fe64_i386.inc}
{$ENDIF}
{$UNDEF CRYPTOLIB_CURVE25519_FE64SQR}
end;

// PH := PF * PG mod (2^448-2^224-1), eight 64-bit limbs.
procedure Curve448Fe56MulAsm(PH, PF, PG: PUInt64);
{$DEFINE CRYPTOLIB_CURVE448_FE64MUL}
{$IFDEF CRYPTOLIB_X86_64_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc3Begin_x86_64.inc}
{$I ..\..\Include\Simd\Curve448\X448Field_Fe64_x86_64.inc}
{$ENDIF}
{$IFDEF CRYPTOLIB_I386_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc3Begin_i386.inc}
{$I ..\..\Include\Simd\Curve448\X448Field_Fe64_i386.inc}
{$ENDIF}
{$UNDEF CRYPTOLIB_CURVE448_FE64MUL}
end;

// PH := PF^2 mod (2^448-2^224-1).
procedure Curve448Fe56SqrAsm(PH, PF: PUInt64);
{$DEFINE CRYPTOLIB_CURVE448_FE64SQR}
{$IFDEF CRYPTOLIB_X86_64_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc2Begin_x86_64.inc}
{$I ..\..\Include\Simd\Curve448\X448Field_Fe64_x86_64.inc}
{$ENDIF}
{$IFDEF CRYPTOLIB_I386_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc2Begin_i386.inc}
{$I ..\..\Include\Simd\Curve448\X448Field_Fe64_i386.inc}
{$ENDIF}
{$UNDEF CRYPTOLIB_CURVE448_FE64SQR}
end;

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
  Curve25519Fe51MulAsm(PH, PF, PG);
  Result := True;
{$ELSE}
  Result := False;
{$ENDIF}
end;

class function TCurveFieldX86Backend.Sqr25519(PX, PZ: PUInt64): Boolean;
begin
{$IFDEF CRYPTOLIB_X86_SIMD}
  Curve25519Fe51SqrAsm(PZ, PX);
  Result := True;
{$ELSE}
  Result := False;
{$ENDIF}
end;

class function TCurveFieldX86Backend.Mul448(PF, PG, PH: PUInt64): Boolean;
begin
{$IFDEF CRYPTOLIB_X86_SIMD}
  Curve448Fe56MulAsm(PH, PF, PG);
  Result := True;
{$ELSE}
  Result := False;
{$ENDIF}
end;

class function TCurveFieldX86Backend.Sqr448(PX, PZ: PUInt64): Boolean;
begin
{$IFDEF CRYPTOLIB_X86_SIMD}
  Curve448Fe56SqrAsm(PZ, PX);
  Result := True;
{$ELSE}
  Result := False;
{$ENDIF}
end;

end.
