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

unit ClpBinPolyX86Backend;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpCpuFeatures,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// x86 carryless-multiply (PCLMULQDQ, 128-bit) kernel backend for
  /// binary-polynomial multiplication. A leaf: it exposes only the capability
  /// probe and the hot leaf kernels. The arch-neutral size dispatch and the
  /// scalar fallback live in <c>TBinPolySimd</c> / <c>TBinPolys</c>; the
  /// arch-neutral multiplier classes reach these kernels through the
  /// <c>TBinPolySimd</c> facade. Hot paths are implemented in
  /// <c>Include/Simd/BinPoly/</c>.
  /// </summary>
  TBinPolyX86Backend = class sealed
  public
    class function IsSupported: Boolean; static;
    class procedure ImplMulSmall(ALen: Int32; PX, PY, PZz: PUInt64); static;
    class procedure ImplMulEven(ALen: Int32; PX, PY, PZz: PUInt64); static;
    class procedure ImplMulOdd(ALen: Int32; PX, PY, PZz: PUInt64); static;
    class procedure ImplSquare(ALen: Int32; PX, PZz: PUInt64); static;
  end;

implementation

{$IFDEF CRYPTOLIB_X86_SIMD}
procedure BinPolyPclmulImplMulSmall(ALen: Int32; PX, PY, PZz: Pointer);
{$DEFINE CRYPTOLIB_BINPOLY_SMALL}
{$IFDEF CRYPTOLIB_X86_64_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc4Begin_x86_64.inc}
{$I ..\..\Include\Simd\BinPoly\BinPolyMul_x86_64.inc}
{$ENDIF}
{$IFDEF CRYPTOLIB_I386_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc4Begin_i386.inc}
{$I ..\..\Include\Simd\BinPoly\BinPolyMul_i386.inc}
{$ENDIF}
{$UNDEF CRYPTOLIB_BINPOLY_SMALL}
end;

procedure BinPolyPclmulImplMulEven(ALen: Int32; PX, PY, PZz: Pointer);
{$DEFINE CRYPTOLIB_BINPOLY_EVEN}
{$IFDEF CRYPTOLIB_X86_64_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc4Begin_x86_64.inc}
{$I ..\..\Include\Simd\BinPoly\BinPolyMul_x86_64.inc}
{$ENDIF}
{$IFDEF CRYPTOLIB_I386_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc4Begin_i386.inc}
{$I ..\..\Include\Simd\BinPoly\BinPolyMul_i386.inc}
{$ENDIF}
{$UNDEF CRYPTOLIB_BINPOLY_EVEN}
end;

procedure BinPolyPclmulImplMulOdd(ALen: Int32; PX, PY, PZz: Pointer);
{$DEFINE CRYPTOLIB_BINPOLY_ODD}
{$IFDEF CRYPTOLIB_X86_64_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc4Begin_x86_64.inc}
{$I ..\..\Include\Simd\BinPoly\BinPolyMul_x86_64.inc}
{$ENDIF}
{$IFDEF CRYPTOLIB_I386_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc4Begin_i386.inc}
{$I ..\..\Include\Simd\BinPoly\BinPolyMul_i386.inc}
{$ENDIF}
{$UNDEF CRYPTOLIB_BINPOLY_ODD}
end;

procedure BinPolyPclmulImplSquare(ALen: Int32; PX, PZz: Pointer);
{$DEFINE CRYPTOLIB_BINPOLY_SQUARE}
{$IFDEF CRYPTOLIB_X86_64_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc3Begin_x86_64.inc}
{$I ..\..\Include\Simd\BinPoly\BinPolyMul_x86_64.inc}
{$ENDIF}
{$IFDEF CRYPTOLIB_I386_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc3Begin_i386.inc}
{$I ..\..\Include\Simd\BinPoly\BinPolyMul_i386.inc}
{$ENDIF}
{$UNDEF CRYPTOLIB_BINPOLY_SQUARE}
end;
{$ENDIF CRYPTOLIB_X86_SIMD}

{ TBinPolyX86Backend }

class function TBinPolyX86Backend.IsSupported: Boolean;
begin
{$IFDEF CRYPTOLIB_X86_SIMD}
  Result := TCpuFeatures.X86.HasPCLMULQDQ();
{$ELSE}
  Result := False;
{$ENDIF}
end;

class procedure TBinPolyX86Backend.ImplMulSmall(ALen: Int32; PX, PY, PZz: PUInt64);
begin
{$IFDEF CRYPTOLIB_X86_SIMD}
{$IFDEF DEBUG}
  System.Assert((ALen >= 1) and (ALen <= 10));
{$ENDIF}
  BinPolyPclmulImplMulSmall(ALen, PX, PY, PZz);
{$ELSE}
  raise ENotImplemented.Create('x86 ImplMulSmall is not available on this target');
{$ENDIF}
end;

class procedure TBinPolyX86Backend.ImplMulEven(ALen: Int32; PX, PY, PZz: PUInt64);
begin
{$IFDEF CRYPTOLIB_X86_SIMD}
{$IFDEF DEBUG}
  System.Assert((ALen and 1) = 0);
  System.Assert(ALen >= 2);
{$ENDIF}
  BinPolyPclmulImplMulEven(ALen, PX, PY, PZz);
{$ELSE}
  raise ENotImplemented.Create('x86 ImplMulEven is not available on this target');
{$ENDIF}
end;

class procedure TBinPolyX86Backend.ImplMulOdd(ALen: Int32; PX, PY, PZz: PUInt64);
begin
{$IFDEF CRYPTOLIB_X86_SIMD}
{$IFDEF DEBUG}
  System.Assert((ALen and 1) = 1);
  System.Assert(ALen >= 1);
{$ENDIF}
  BinPolyPclmulImplMulOdd(ALen, PX, PY, PZz);
{$ELSE}
  raise ENotImplemented.Create('x86 ImplMulOdd is not available on this target');
{$ENDIF}
end;

class procedure TBinPolyX86Backend.ImplSquare(ALen: Int32; PX, PZz: PUInt64);
begin
{$IFDEF CRYPTOLIB_X86_SIMD}
{$IFDEF DEBUG}
  System.Assert(ALen >= 1);
{$ENDIF}
  BinPolyPclmulImplSquare(ALen, PX, PZz);
{$ELSE}
  raise ENotImplemented.Create('x86 ImplSquare is not available on this target');
{$ENDIF}
end;

end.
