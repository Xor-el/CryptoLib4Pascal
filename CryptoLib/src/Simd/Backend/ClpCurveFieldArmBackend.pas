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
  end;

implementation

{$IFDEF CRYPTOLIB_AARCH64_ASM}

// PH := PF * PG mod (2^255-19), five 64-bit limbs.
procedure Curve25519Fe51MulAsm(PH, PF, PG: PUInt64);
{$DEFINE CRYPTOLIB_CURVE25519_FE64MUL}
{$I ..\..\Include\Simd\Common\ClpSimdProc3Begin_aarch64.inc}
{$I ..\..\Include\Simd\Curve25519\X25519Field_Fe64_aarch64.inc}
{$UNDEF CRYPTOLIB_CURVE25519_FE64MUL}
end;

// PH := PF^2 mod (2^255-19).
procedure Curve25519Fe51SqrAsm(PH, PF: PUInt64);
{$DEFINE CRYPTOLIB_CURVE25519_FE64SQR}
{$I ..\..\Include\Simd\Common\ClpSimdProc2Begin_aarch64.inc}
{$I ..\..\Include\Simd\Curve25519\X25519Field_Fe64_aarch64.inc}
{$UNDEF CRYPTOLIB_CURVE25519_FE64SQR}
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

end.
