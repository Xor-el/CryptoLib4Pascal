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

unit ClpBinPolyX86V128Kernels;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// x86/V128 binary-polynomial multiply kernels. Hot paths are implemented in
  /// <c>Include/Simd/BinPoly/</c>.
  /// </summary>
  TBinPolyX86V128Kernels = class sealed
  public
    class procedure ImplMulSmall(ALen: Int32; const AX: TCryptoLibUInt64Array; AXOff: Int32;
      const AY: TCryptoLibUInt64Array; AYOff: Int32;
      const AZz: TCryptoLibUInt64Array; AZzOff: Int32); static;
    class procedure ImplMulEven(ALen: Int32; const AX: TCryptoLibUInt64Array; AXOff: Int32;
      const AY: TCryptoLibUInt64Array; AYOff: Int32;
      const AZz: TCryptoLibUInt64Array; AZzOff: Int32); static;
    class procedure ImplMulOdd(ALen: Int32; const AX: TCryptoLibUInt64Array; AXOff: Int32;
      const AY: TCryptoLibUInt64Array; AYOff: Int32;
      const AZz: TCryptoLibUInt64Array; AZzOff: Int32); static;
  end;

implementation

{$IFDEF CRYPTOLIB_X86_SIMD}
procedure BinPolyPclmulImplMulSmall(ALen: Int32; PX, PY, PZz: Pointer);
{$IFDEF CRYPTOLIB_X86_64_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc4Begin_x86_64.inc}
{$I ..\..\Include\Simd\BinPoly\BinPolyPclmulImplMulSmall_x86_64.inc}
{$ENDIF}
{$IFDEF CRYPTOLIB_I386_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc4Begin_i386.inc}
{$I ..\..\Include\Simd\BinPoly\BinPolyPclmulImplMulSmall_i386.inc}
{$ENDIF}
end;

procedure BinPolyPclmulImplMulEven(ALen: Int32; PX, PY, PZz: Pointer);
{$IFDEF CRYPTOLIB_X86_64_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc4Begin_x86_64.inc}
{$I ..\..\Include\Simd\BinPoly\BinPolyPclmulImplMulEven_x86_64.inc}
{$ENDIF}
{$IFDEF CRYPTOLIB_I386_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc4Begin_i386.inc}
{$I ..\..\Include\Simd\BinPoly\BinPolyPclmulImplMulEven_i386.inc}
{$ENDIF}
end;

procedure BinPolyPclmulImplMulOdd(ALen: Int32; PX, PY, PZz: Pointer);
{$IFDEF CRYPTOLIB_X86_64_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc4Begin_x86_64.inc}
{$I ..\..\Include\Simd\BinPoly\BinPolyPclmulImplMulOdd_x86_64.inc}
{$ENDIF}
{$IFDEF CRYPTOLIB_I386_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc4Begin_i386.inc}
{$I ..\..\Include\Simd\BinPoly\BinPolyPclmulImplMulOdd_i386.inc}
{$ENDIF}
end;
{$ENDIF CRYPTOLIB_X86_SIMD}

class procedure TBinPolyX86V128Kernels.ImplMulSmall(ALen: Int32; const AX: TCryptoLibUInt64Array; AXOff: Int32;
  const AY: TCryptoLibUInt64Array; AYOff: Int32; const AZz: TCryptoLibUInt64Array; AZzOff: Int32);
begin
{$IFDEF CRYPTOLIB_X86_SIMD}
{$IFDEF DEBUG}
  System.Assert((ALen >= 1) and (ALen <= 10));
{$ENDIF}
  BinPolyPclmulImplMulSmall(ALen, @AX[AXOff], @AY[AYOff], @AZz[AZzOff]);
{$ELSE}
  raise ENotImplemented.Create('x86/V128 ImplMulSmall is not available on this target');
{$ENDIF}
end;

class procedure TBinPolyX86V128Kernels.ImplMulEven(ALen: Int32; const AX: TCryptoLibUInt64Array; AXOff: Int32;
  const AY: TCryptoLibUInt64Array; AYOff: Int32; const AZz: TCryptoLibUInt64Array; AZzOff: Int32);
begin
{$IFDEF CRYPTOLIB_X86_SIMD}
{$IFDEF DEBUG}
  System.Assert((ALen and 1) = 0);
  System.Assert(ALen >= 2);
{$ENDIF}
  BinPolyPclmulImplMulEven(ALen, @AX[AXOff], @AY[AYOff], @AZz[AZzOff]);
{$ELSE}
  raise ENotImplemented.Create('x86/V128 ImplMulEven is not available on this target');
{$ENDIF}
end;

class procedure TBinPolyX86V128Kernels.ImplMulOdd(ALen: Int32; const AX: TCryptoLibUInt64Array; AXOff: Int32;
  const AY: TCryptoLibUInt64Array; AYOff: Int32; const AZz: TCryptoLibUInt64Array; AZzOff: Int32);
begin
{$IFDEF CRYPTOLIB_X86_SIMD}
{$IFDEF DEBUG}
  System.Assert((ALen and 1) = 1);
  System.Assert(ALen >= 1);
{$ENDIF}
  BinPolyPclmulImplMulOdd(ALen, @AX[AXOff], @AY[AYOff], @AZz[AZzOff]);
{$ELSE}
  raise ENotImplemented.Create('x86/V128 ImplMulOdd is not available on this target');
{$ENDIF}
end;

end.
