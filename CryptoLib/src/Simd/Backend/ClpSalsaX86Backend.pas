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
    /// <summary>SIMD 4-way vertical streaming kernel: AGroups x 256 bytes.
    /// The caller must pre-clamp AGroups so the low counter word (state
    /// word 8) does not wrap inside the span.</summary>
    class function TryProcessBlocks4(ARounds: Int32; AState, AIn, AOut: PByte;
      AGroups: Int32): Boolean; static;
    /// <summary>SIMD 8-way vertical streaming kernel: AGroups x 512 bytes.
    /// Same counter pre-clamp contract as the 4-way kernel.</summary>
    class function TryProcessBlocks8(ARounds: Int32; AState, AIn, AOut: PByte;
      AGroups: Int32): Boolean; static;
  end;

implementation

{$IFDEF CRYPTOLIB_X86_SIMD}
procedure Salsa20BlockSse2(ARounds: Int32; AInput, AOut: Pointer);
{$IFDEF CRYPTOLIB_X86_64_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc3Begin_x86_64.inc}
{$I ..\..\Include\Simd\Salsa\Salsa20BlockSse2_x86_64.inc}
{$ENDIF}
{$IFDEF CRYPTOLIB_I386_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc3Begin_i386.inc}
{$I ..\..\Include\Simd\Salsa\Salsa20BlockSse2_i386.inc}
{$ENDIF}
end;

procedure Salsa20ProcessBlocks2Sse2(ARounds: Int32; AState, AIn, AOut: PByte);
{$IFDEF CRYPTOLIB_X86_64_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc4Begin_x86_64.inc}
{$I ..\..\Include\Simd\Salsa\Salsa20Blocks2Sse2_x86_64.inc}
{$ENDIF}
{$IFDEF CRYPTOLIB_I386_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc4Begin_i386.inc}
{$I ..\..\Include\Simd\Salsa\Salsa20Blocks2Sse2_i386.inc}
{$ENDIF}
end;

procedure Salsa20ProcessBlocks4Sse2(ARounds: Int32; AState, AIn, AOut: PByte;
  AGroups: Int32);
{$IFDEF CRYPTOLIB_X86_64_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc5Begin_x86_64.inc}
{$I ..\..\Include\Simd\Salsa\Salsa20Blocks4Sse2_x86_64.inc}
{$ENDIF}
{$IFDEF CRYPTOLIB_I386_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc5Begin_i386.inc}
{$I ..\..\Include\Simd\Salsa\Salsa20Blocks4Sse2_i386.inc}
{$ENDIF}
end;

procedure Salsa20ProcessBlocks8Avx2(ARounds: Int32; AState, AIn, AOut: PByte;
  AGroups: Int32);
{$IFDEF CRYPTOLIB_X86_64_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc5Begin_x86_64.inc}
{$I ..\..\Include\Simd\Salsa\Salsa20Blocks8Avx2_x86_64.inc}
{$ENDIF}
{$IFDEF CRYPTOLIB_I386_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc5Begin_i386.inc}
{$I ..\..\Include\Simd\Salsa\Salsa20Blocks8Avx2_i386.inc}
{$ENDIF}
end;
{$ENDIF CRYPTOLIB_X86_SIMD}

{ TSalsaX86Backend }

class function TSalsaX86Backend.TryCore(ARounds: Int32; AInput, AOut: Pointer): Boolean;
begin
{$IFDEF CRYPTOLIB_X86_SIMD}
  if TCpuFeatures.X86.HasSSE2() then
  begin
    Salsa20BlockSse2(ARounds, AInput, AOut);
    Exit(True);
  end;
{$ENDIF}
  Result := False;
end;

class function TSalsaX86Backend.TryProcessBlocks2(ARounds: Int32; AState, AIn, AOut: PByte): Boolean;
begin
{$IFDEF CRYPTOLIB_X86_SIMD}
  if TCpuFeatures.X86.HasSSE2() then
  begin
    Salsa20ProcessBlocks2Sse2(ARounds, AState, AIn, AOut);
    Exit(True);
  end;
{$ENDIF}
  Result := False;
end;

class function TSalsaX86Backend.TryProcessBlocks4(ARounds: Int32;
  AState, AIn, AOut: PByte; AGroups: Int32): Boolean;
begin
{$IFDEF CRYPTOLIB_X86_SIMD}
  if TCpuFeatures.X86.HasSSE2() then
  begin
    Salsa20ProcessBlocks4Sse2(ARounds, AState, AIn, AOut, AGroups);
    Exit(True);
  end;
{$ENDIF}
  Result := False;
end;

class function TSalsaX86Backend.TryProcessBlocks8(ARounds: Int32;
  AState, AIn, AOut: PByte; AGroups: Int32): Boolean;
begin
{$IFDEF CRYPTOLIB_X86_SIMD}
  if TCpuFeatures.X86.HasAVX2() then
  begin
    Salsa20ProcessBlocks8Avx2(ARounds, AState, AIn, AOut, AGroups);
    Exit(True);
  end;
{$ENDIF}
  Result := False;
end;

end.
