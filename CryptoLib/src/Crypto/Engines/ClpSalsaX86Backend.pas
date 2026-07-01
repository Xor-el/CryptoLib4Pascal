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

unit ClpSalsaX86Backend;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpCpuFeatures,
  ClpSimdLevels,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// x86 SIMD backend for the Salsa20 family: owns the SIMD keystream kernels
  /// (bodies in <c>Include\Simd\Salsa\</c>) and the runtime tier selection via
  /// <c>TCpuFeatures.X86.SelectSlot</c>. Compiles on every target - when built
  /// without x86 SIMD the <c>Try*</c> entry points return <c>False</c> and the
  /// callers fall back to their scalar reference path.
  /// </summary>
  TSalsaX86Backend = class sealed
  public
    /// <summary>SIMD single-block Salsa20 core.</summary>
    class function TryCore(ARounds: Int32; AInput, AOut: Pointer): Boolean; static;
    /// <summary>SIMD two-block Salsa20 keystream (128 bytes).</summary>
    class function TryProcessBlocks2(ARounds: Int32; AState, AIn, AOut: PByte): Boolean; static;
  end;

implementation

{$IFDEF CRYPTOLIB_X86_SIMD}
procedure Salsa20BlockSse41(ARounds: Int32; AInput, AOut: Pointer);
{$IFDEF CRYPTOLIB_X86_64_ASM}
{$I ..\..\Include\Simd\Common\SimdProc3Begin_x86_64.inc}
{$I ..\..\Include\Simd\Salsa\Salsa20BlockSse41_x86_64.inc}
{$ENDIF}
{$IFDEF CRYPTOLIB_I386_ASM}
{$I ..\..\Include\Simd\Common\SimdProc3Begin_i386.inc}
{$I ..\..\Include\Simd\Salsa\Salsa20BlockSse41_i386.inc}
{$ENDIF}
end;

procedure Salsa20ProcessBlocks2Sse41(ARounds: Int32; AState, AIn, AOut: PByte);
{$IFDEF CRYPTOLIB_X86_64_ASM}
{$I ..\..\Include\Simd\Common\SimdProc4Begin_x86_64.inc}
{$I ..\..\Include\Simd\Salsa\Salsa20ProcessBlocks2Sse41_x86_64.inc}
{$ENDIF}
{$IFDEF CRYPTOLIB_I386_ASM}
{$I ..\..\Include\Simd\Common\SimdProc4Begin_i386.inc}
{$I ..\..\Include\Simd\Salsa\Salsa20ProcessBlocks2Sse41_i386.inc}
{$ENDIF}
end;
{$ENDIF CRYPTOLIB_X86_SIMD}

{ TSalsaX86Backend }

class function TSalsaX86Backend.TryCore(ARounds: Int32; AInput, AOut: Pointer): Boolean;
begin
{$IFDEF CRYPTOLIB_X86_SIMD}
  case TCpuFeatures.X86.SelectSlot([TX86SimdLevel.SSE41]) of
    TX86SimdLevel.SSE41:
    begin
      Salsa20BlockSse41(ARounds, AInput, AOut);
      Exit(True);
    end;
  end;
{$ENDIF}
  Result := False;
end;

class function TSalsaX86Backend.TryProcessBlocks2(ARounds: Int32; AState, AIn, AOut: PByte): Boolean;
begin
{$IFDEF CRYPTOLIB_X86_SIMD}
  case TCpuFeatures.X86.SelectSlot([TX86SimdLevel.SSE41]) of
    TX86SimdLevel.SSE41:
    begin
      Salsa20ProcessBlocks2Sse41(ARounds, AState, AIn, AOut);
      Exit(True);
    end;
  end;
{$ENDIF}
  Result := False;
end;

end.
