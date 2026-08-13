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
    class function IsSupported: Boolean; static;
    /// <summary>Z[0..2N-1] := X * Y, ALimbs64 = uint64 limb count N.</summary>
    class procedure Mul(PX, PY, PZ: PUInt64; ALimbs64: NativeInt); static;
    /// <summary>Z[0..2N-1] := X^2.</summary>
    class procedure Sqr(PX, PZ: PUInt64; ALimbs64: NativeInt); static;
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

{$ENDIF}

{ TFpKernelArmBackend }

class function TFpKernelArmBackend.IsSupported: Boolean;
begin
{$IFDEF CRYPTOLIB_AARCH64_ASM}
  // Base kernel uses plain integer ops (no CPU-feature dependency); gate only on
  // "not forced scalar" so a CRYPTOLIB_FORCE_SCALAR build (which pins the active
  // level to Scalar) falls back to the scalar path.
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

end.
