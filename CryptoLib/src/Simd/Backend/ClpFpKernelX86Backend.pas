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

unit ClpFpKernelX86Backend;

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
  /// x86 (i386 + x86-64) big-integer kernel backend for prime-field (Fp)
  /// multiplication/square. A leaf: capability probe plus the hot schoolbook
  /// multiply/square. The arch-neutral dispatch and the scalar fallback live in
  /// <c>TFpKernelSimd</c> / the field units. Hot paths are in
  /// <c>Include/Simd/FpKernel/</c>.
  /// </summary>
  TFpKernelX86Backend = class sealed
  public
    class function IsSupported: Boolean; static;
    class procedure Mul(PX, PY, PZ: PUInt64; ALimbs64: NativeInt); static;
    class procedure Sqr(PX, PZ: PUInt64; ALimbs64: NativeInt); static;
  end;

implementation

{$IFDEF CRYPTOLIB_X86_SIMD}

procedure FpKernelMulAsm(PX, PY, PZ: PUInt64; ALimbs64: NativeInt);
{$DEFINE CRYPTOLIB_FP_MUL}
{$IFDEF CRYPTOLIB_X86_64_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc4Begin_x86_64.inc}
{$I ..\..\Include\Simd\FpKernel\FpKernel_x86_64.inc}
{$ENDIF}
{$IFDEF CRYPTOLIB_I386_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc4Begin_i386.inc}
{$I ..\..\Include\Simd\FpKernel\FpKernel_i386.inc}
{$ENDIF}
{$UNDEF CRYPTOLIB_FP_MUL}
end;

// Square Z := X^2 (FP_SQR selector).
procedure FpKernelSqrAsm(PX, PZ: PUInt64; ALimbs64: NativeInt);
{$DEFINE CRYPTOLIB_FP_SQR}
{$IFDEF CRYPTOLIB_X86_64_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc3Begin_x86_64.inc}
{$I ..\..\Include\Simd\FpKernel\FpKernel_x86_64.inc}
{$ENDIF}
{$IFDEF CRYPTOLIB_I386_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc3Begin_i386.inc}
{$I ..\..\Include\Simd\FpKernel\FpKernel_i386.inc}
{$ENDIF}
{$UNDEF CRYPTOLIB_FP_SQR}
end;

{$ENDIF}

{ TFpKernelX86Backend }

class function TFpKernelX86Backend.IsSupported: Boolean;
begin
{$IFDEF CRYPTOLIB_X86_SIMD}
  // Base kernel uses plain integer ops (no CPU-feature dependency); gate only on
  // "not forced scalar" so a CRYPTOLIB_FORCE_SCALAR build (which pins the active
  // level to Scalar) falls back to the scalar path.
  Result := TCpuFeatures.X86.GetActiveSimdLevel() <> TX86SimdLevel.Scalar;
{$ELSE}
  Result := False;
{$ENDIF}
end;

class procedure TFpKernelX86Backend.Mul(PX, PY, PZ: PUInt64; ALimbs64: NativeInt);
begin
{$IFDEF CRYPTOLIB_X86_SIMD}
  FpKernelMulAsm(PX, PY, PZ, ALimbs64);
{$ENDIF}
end;

class procedure TFpKernelX86Backend.Sqr(PX, PZ: PUInt64; ALimbs64: NativeInt);
begin
{$IFDEF CRYPTOLIB_X86_SIMD}
  FpKernelSqrAsm(PX, PZ, ALimbs64);
{$ENDIF}
end;

end.
