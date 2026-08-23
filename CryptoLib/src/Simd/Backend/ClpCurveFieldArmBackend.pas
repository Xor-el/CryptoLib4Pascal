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
  /// AArch64 kernel backend for the radix-2^51 curve25519 field. A leaf: capability
  /// probe plus the hot multiply/square. Kernels are in
  /// <c>Include/Simd/Curve25519/</c>.
  /// </summary>
  TCurveFieldArmBackend = class sealed
  public
    class function IsSupported: Boolean; static; inline;
    class function Mul25519(PF, PG, PH: PUInt64): Boolean; static;
    class function Sqr25519(PX, PZ: PUInt64): Boolean; static;
    class function Mul448(PF, PG, PH: PUInt64): Boolean; static;
    class function Sqr448(PX, PZ: PUInt64): Boolean; static;

    // radix-2^64 (saturated) curve25519 tier.
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

{$IFDEF CRYPTOLIB_AARCH64_ASM}

// PH := PF * PG mod (2^255-19), five 64-bit limbs.
procedure Curve25519Fe51MulAsm(PH, PF, PG: PUInt64);
{$DEFINE CRYPTOLIB_CURVE25519_FE51MUL}
{$I ..\..\Include\Simd\Common\ClpSimdProc3Begin_aarch64.inc}
{$I ..\..\Include\Simd\Curve25519\X25519Field_Fe51_aarch64.inc}
{$UNDEF CRYPTOLIB_CURVE25519_FE51MUL}
end;

// PH := PF^2 mod (2^255-19).
procedure Curve25519Fe51SqrAsm(PH, PF: PUInt64);
{$DEFINE CRYPTOLIB_CURVE25519_FE51SQR}
{$I ..\..\Include\Simd\Common\ClpSimdProc2Begin_aarch64.inc}
{$I ..\..\Include\Simd\Curve25519\X25519Field_Fe51_aarch64.inc}
{$UNDEF CRYPTOLIB_CURVE25519_FE51SQR}
end;

// PH := PF * PG mod (2^448-2^224-1), eight 64-bit limbs.
procedure Curve448Fe56MulAsm(PH, PF, PG: PUInt64);
{$DEFINE CRYPTOLIB_CURVE448_FE56MUL}
{$I ..\..\Include\Simd\Common\ClpSimdProc3Begin_aarch64.inc}
{$I ..\..\Include\Simd\Curve448\X448Field_Fe56_aarch64.inc}
{$UNDEF CRYPTOLIB_CURVE448_FE56MUL}
end;

// PH := PF^2 mod (2^448-2^224-1).
procedure Curve448Fe56SqrAsm(PH, PF: PUInt64);
{$DEFINE CRYPTOLIB_CURVE448_FE56SQR}
{$I ..\..\Include\Simd\Common\ClpSimdProc2Begin_aarch64.inc}
{$I ..\..\Include\Simd\Curve448\X448Field_Fe56_aarch64.inc}
{$UNDEF CRYPTOLIB_CURVE448_FE56SQR}
end;

// radix-2^64 (saturated) curve25519 kernels. PH := PF * PG mod (2^255-19).
procedure Curve25519Fe64MulAsm(PH, PF, PG: PUInt64);
{$DEFINE CRYPTOLIB_CURVE25519_SAT64MUL}
{$I ..\..\Include\Simd\Common\ClpSimdProc3Begin_aarch64.inc}
{$I ..\..\Include\Simd\Curve25519\X25519Field_Sat64_aarch64.inc}
{$UNDEF CRYPTOLIB_CURVE25519_SAT64MUL}
end;

// PH := PF^2 mod (2^255-19).
procedure Curve25519Fe64SqrAsm(PH, PF: PUInt64);
{$DEFINE CRYPTOLIB_CURVE25519_SAT64SQR}
{$I ..\..\Include\Simd\Common\ClpSimdProc2Begin_aarch64.inc}
{$I ..\..\Include\Simd\Curve25519\X25519Field_Sat64_aarch64.inc}
{$UNDEF CRYPTOLIB_CURVE25519_SAT64SQR}
end;

// PH := PF + PG mod (2^255-19).
procedure Curve25519Fe64AddAsm(PH, PF, PG: PUInt64);
{$DEFINE CRYPTOLIB_CURVE25519_SAT64ADD}
{$I ..\..\Include\Simd\Common\ClpSimdProc3Begin_aarch64.inc}
{$I ..\..\Include\Simd\Curve25519\X25519Field_Sat64_aarch64.inc}
{$UNDEF CRYPTOLIB_CURVE25519_SAT64ADD}
end;

// PH := PF - PG mod (2^255-19).
procedure Curve25519Fe64SubAsm(PH, PF, PG: PUInt64);
{$DEFINE CRYPTOLIB_CURVE25519_SAT64SUB}
{$I ..\..\Include\Simd\Common\ClpSimdProc3Begin_aarch64.inc}
{$I ..\..\Include\Simd\Curve25519\X25519Field_Sat64_aarch64.inc}
{$UNDEF CRYPTOLIB_CURVE25519_SAT64SUB}
end;

// PH := PF * 121666 mod (2^255-19).
procedure Curve25519Fe64Mul121666Asm(PH, PF: PUInt64);
{$DEFINE CRYPTOLIB_CURVE25519_SAT64M121666}
{$I ..\..\Include\Simd\Common\ClpSimdProc2Begin_aarch64.inc}
{$I ..\..\Include\Simd\Curve25519\X25519Field_Sat64_aarch64.inc}
{$UNDEF CRYPTOLIB_CURVE25519_SAT64M121666}
end;

// PH := PF^(2^AN) mod (2^255-19), AN >= 1 (AN is a public count, not a secret).
procedure Curve25519Fe64SqrNAsm(PH, PF: PUInt64; AN: NativeInt);
{$DEFINE CRYPTOLIB_CURVE25519_SAT64SQRN}
{$I ..\..\Include\Simd\Common\ClpSimdProc3Begin_aarch64.inc}
{$I ..\..\Include\Simd\Curve25519\X25519Field_Sat64_aarch64.inc}
{$UNDEF CRYPTOLIB_CURVE25519_SAT64SQRN}
end;

// One Montgomery ladder step + cswap over PState (x1,x2,z2,x3,z3, 4 limbs each).
procedure Curve25519Fe64LadderStepAsm(PState: PUInt64; AMask: UInt64);
{$DEFINE CRYPTOLIB_CURVE25519_SAT64LADDER}
{$I ..\..\Include\Simd\Common\ClpSimdProc2Begin_aarch64.inc}
{$I ..\..\Include\Simd\Curve25519\X25519Field_Sat64_aarch64.inc}
{$UNDEF CRYPTOLIB_CURVE25519_SAT64LADDER}
end;

{$ENDIF}

class function TCurveFieldArmBackend.IsSupported: Boolean;
begin
{$IFDEF CRYPTOLIB_AARCH64_ASM}
  Result := TCpuFeatures.Arm.GetActiveSimdLevel() <> TArmSimdLevel.Scalar;
{$ELSE}
  Result := False;
{$ENDIF}
end;

class function TCurveFieldArmBackend.Mul25519(PF, PG, PH: PUInt64): Boolean;
begin
{$IFDEF CRYPTOLIB_AARCH64_ASM}
  Curve25519Fe51MulAsm(PH, PF, PG);
  Result := True;
{$ELSE}
  Result := False;
{$ENDIF}
end;

class function TCurveFieldArmBackend.Sqr25519(PX, PZ: PUInt64): Boolean;
begin
{$IFDEF CRYPTOLIB_AARCH64_ASM}
  Curve25519Fe51SqrAsm(PZ, PX);
  Result := True;
{$ELSE}
  Result := False;
{$ENDIF}
end;

class function TCurveFieldArmBackend.Mul448(PF, PG, PH: PUInt64): Boolean;
begin
{$IFDEF CRYPTOLIB_AARCH64_ASM}
  Curve448Fe56MulAsm(PH, PF, PG);
  Result := True;
{$ELSE}
  Result := False;
{$ENDIF}
end;

class function TCurveFieldArmBackend.Sqr448(PX, PZ: PUInt64): Boolean;
begin
{$IFDEF CRYPTOLIB_AARCH64_ASM}
  Curve448Fe56SqrAsm(PZ, PX);
  Result := True;
{$ELSE}
  Result := False;
{$ENDIF}
end;

class function TCurveFieldArmBackend.Fe64Supported: Boolean;
begin
{$IFDEF CRYPTOLIB_AARCH64_ASM}
  Result := IsSupported;
{$ELSE}
  Result := False;
{$ENDIF}
end;

class procedure TCurveFieldArmBackend.Fe64Mul25519(PF, PG, PH: PUInt64);
begin
{$IFDEF CRYPTOLIB_AARCH64_ASM}
  Curve25519Fe64MulAsm(PH, PF, PG);
{$ENDIF}
end;

class procedure TCurveFieldArmBackend.Fe64Sqr25519(PX, PZ: PUInt64);
begin
{$IFDEF CRYPTOLIB_AARCH64_ASM}
  Curve25519Fe64SqrAsm(PZ, PX);
{$ENDIF}
end;

class procedure TCurveFieldArmBackend.Fe64Add(PA, PB, PR: PUInt64);
begin
{$IFDEF CRYPTOLIB_AARCH64_ASM}
  Curve25519Fe64AddAsm(PR, PA, PB);
{$ENDIF}
end;

class procedure TCurveFieldArmBackend.Fe64Sub(PA, PB, PR: PUInt64);
begin
{$IFDEF CRYPTOLIB_AARCH64_ASM}
  Curve25519Fe64SubAsm(PR, PA, PB);
{$ENDIF}
end;

class procedure TCurveFieldArmBackend.Fe64Mul121666(PF, PH: PUInt64);
begin
{$IFDEF CRYPTOLIB_AARCH64_ASM}
  Curve25519Fe64Mul121666Asm(PH, PF);
{$ENDIF}
end;

class procedure TCurveFieldArmBackend.Fe64SqrN(PF, PH: PUInt64; AN: NativeInt);
begin
{$IFDEF CRYPTOLIB_AARCH64_ASM}
  Curve25519Fe64SqrNAsm(PH, PF, AN);
{$ENDIF}
end;

class procedure TCurveFieldArmBackend.Fe64LadderStep25519(PState: PUInt64; AMask: UInt64);
begin
{$IFDEF CRYPTOLIB_AARCH64_ASM}
  Curve25519Fe64LadderStepAsm(PState, AMask);
{$ENDIF}
end;

end.
