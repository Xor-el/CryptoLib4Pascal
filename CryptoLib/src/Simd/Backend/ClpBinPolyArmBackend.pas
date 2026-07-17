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

unit ClpBinPolyArmBackend;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpCpuFeatures,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// ARM carryless-multiply (PMULL, 128-bit) kernel backend for
  /// binary-polynomial multiplication. A leaf: it exposes only the capability
  /// probe and the hot leaf kernels. The arch-neutral size dispatch and the
  /// scalar fallback live in <c>TBinPolySimd</c> / <c>TBinPolys</c>; the
  /// arch-neutral multiplier classes reach these kernels through the
  /// <c>TBinPolySimd</c> facade. Hot paths are implemented in
  /// <c>Include/Simd/BinPoly/</c>.
  /// </summary>
  TBinPolyArmBackend = class sealed
  public
    class function IsSupported: Boolean; static;
    class procedure ImplMulSmall(ALen: Int32; PX, PY, PZz: PUInt64); static;
    class procedure ImplMulEven(ALen: Int32; PX, PY, PZz: PUInt64); static;
    class procedure ImplMulOdd(ALen: Int32; PX, PY, PZz: PUInt64); static;
    class procedure ImplSquare(ALen: Int32; PX, PZz: PUInt64); static;
  end;

implementation

{$IFDEF CRYPTOLIB_AARCH64_ASM}
procedure BinPolyPmullImplMulSmall(ALen: Int32; PX, PY, PZz: Pointer);
{$DEFINE CRYPTOLIB_BINPOLY_SMALL}
{$I ..\..\Include\Simd\Common\ClpSimdProc4Begin_aarch64.inc}
{$I ..\..\Include\Simd\BinPoly\BinPolyMul_aarch64.inc}
{$UNDEF CRYPTOLIB_BINPOLY_SMALL}
end;

procedure BinPolyPmullImplMulEven(ALen: Int32; PX, PY, PZz: Pointer);
{$DEFINE CRYPTOLIB_BINPOLY_EVEN}
{$I ..\..\Include\Simd\Common\ClpSimdProc4Begin_aarch64.inc}
{$I ..\..\Include\Simd\BinPoly\BinPolyMul_aarch64.inc}
{$UNDEF CRYPTOLIB_BINPOLY_EVEN}
end;

procedure BinPolyPmullImplMulOdd(ALen: Int32; PX, PY, PZz: Pointer);
{$DEFINE CRYPTOLIB_BINPOLY_ODD}
{$I ..\..\Include\Simd\Common\ClpSimdProc4Begin_aarch64.inc}
{$I ..\..\Include\Simd\BinPoly\BinPolyMul_aarch64.inc}
{$UNDEF CRYPTOLIB_BINPOLY_ODD}
end;

procedure BinPolyPmullImplSquare(ALen: Int32; PX, PZz: Pointer);
{$DEFINE CRYPTOLIB_BINPOLY_SQUARE}
{$I ..\..\Include\Simd\Common\ClpSimdProc3Begin_aarch64.inc}
{$I ..\..\Include\Simd\BinPoly\BinPolyMul_aarch64.inc}
{$UNDEF CRYPTOLIB_BINPOLY_SQUARE}
end;
{$ENDIF CRYPTOLIB_AARCH64_ASM}

{ TBinPolyArmBackend }

class function TBinPolyArmBackend.IsSupported: Boolean;
begin
{$IFDEF CRYPTOLIB_AARCH64_ASM}
  // The feature layer reports AES only when the PMULL half of the crypto
  // extensions agrees, so HasAES is the PMULL gate (same as the GHASH
  // backend).
  Result := TCpuFeatures.Arm.HasAES();
{$ELSE}
  Result := False;
{$ENDIF}
end;

class procedure TBinPolyArmBackend.ImplMulSmall(ALen: Int32;
  PX, PY, PZz: PUInt64);
begin
{$IFDEF CRYPTOLIB_AARCH64_ASM}
{$IFDEF DEBUG}
  System.Assert((ALen >= 1) and (ALen <= 10));
{$ENDIF}
  BinPolyPmullImplMulSmall(ALen, PX, PY, PZz);
{$ELSE}
  raise ENotImplemented.Create('ARM ImplMulSmall is not available on this target');
{$ENDIF}
end;

class procedure TBinPolyArmBackend.ImplMulEven(ALen: Int32;
  PX, PY, PZz: PUInt64);
begin
{$IFDEF CRYPTOLIB_AARCH64_ASM}
{$IFDEF DEBUG}
  System.Assert((ALen and 1) = 0);
  System.Assert(ALen >= 2);
{$ENDIF}
  BinPolyPmullImplMulEven(ALen, PX, PY, PZz);
{$ELSE}
  raise ENotImplemented.Create('ARM ImplMulEven is not available on this target');
{$ENDIF}
end;

class procedure TBinPolyArmBackend.ImplMulOdd(ALen: Int32;
  PX, PY, PZz: PUInt64);
begin
{$IFDEF CRYPTOLIB_AARCH64_ASM}
{$IFDEF DEBUG}
  System.Assert((ALen and 1) = 1);
{$ENDIF}
  BinPolyPmullImplMulOdd(ALen, PX, PY, PZz);
{$ELSE}
  raise ENotImplemented.Create('ARM ImplMulOdd is not available on this target');
{$ENDIF}
end;

class procedure TBinPolyArmBackend.ImplSquare(ALen: Int32; PX, PZz: PUInt64);
begin
{$IFDEF CRYPTOLIB_AARCH64_ASM}
{$IFDEF DEBUG}
  System.Assert(ALen >= 1);
{$ENDIF}
  BinPolyPmullImplSquare(ALen, PX, PZz);
{$ELSE}
  raise ENotImplemented.Create('ARM ImplSquare is not available on this target');
{$ENDIF}
end;

end.
