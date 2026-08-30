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

unit ClpGatherKernelX86Backend;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
{$IFDEF CRYPTOLIB_X86_SIMD}
  ClpCpuFeatures,
  ClpSimdLevels,
  ClpX86SimdFeatures,
{$ENDIF}
  ClpCryptoLibTypes;

type
  /// <summary>
  /// X86 kernel backend for the constant-time table gather. A leaf:
  /// capability probe plus the SSE2/AVX2 masked-accumulate gather. The
  /// arch-neutral dispatch and the scalar fallback live in
  /// <c>TGatherKernelSimd</c> / the field units. Hot paths are in
  /// <c>Include/Simd/GatherKernel/</c>.
  /// </summary>
  TGatherKernelX86Backend = class sealed
  public
    class function IsSupported: Boolean; static; inline;
    /// <summary>Constant-time gather: PDst := the AIndex-th of ACount entries (each
    /// AEntryBytes wide), with index-independent access.</summary>
    class function Gather(PDst, PTable: PByte; AEntryBytes, ACount, AIndex: NativeInt): Boolean; static;
  end;

implementation

{$IFDEF CRYPTOLIB_X86_SIMD}

// Constant-time table gather (SSE2), x86-64 + i386: PDst := the AIndex-th entry
// out of ACount, each AEntryBytes wide, masked-accumulated in constant time.
// The SSE2 path (pre-AVX2 x86-64 and i386).
procedure FpKernelGatherSse2(PDst, PTable: PByte; AEntryBytes, ACount, AIndex: NativeInt);
{$IFDEF CRYPTOLIB_X86_64_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc5Begin_x86_64.inc}
{$I ..\..\Include\Simd\GatherKernel\GatherKernelSse2_x86_64.inc}
{$ENDIF}
{$IFDEF CRYPTOLIB_I386_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc5Begin_i386.inc}
{$I ..\..\Include\Simd\GatherKernel\GatherKernelSse2_i386.inc}
{$ENDIF}
end;

// Constant-time table gather (AVX2), x86-64 + i386: 32-byte ymm chunks. The
// caller (Gather) picks this over SSE2 when AVX2 is present.
procedure FpKernelGatherAvx2(PDst, PTable: PByte; AEntryBytes, ACount, AIndex: NativeInt);
{$IFDEF CRYPTOLIB_X86_64_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc5Begin_x86_64.inc}
{$I ..\..\Include\Simd\GatherKernel\GatherKernelAvx2_x86_64.inc}
{$ENDIF}
{$IFDEF CRYPTOLIB_I386_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc5Begin_i386.inc}
{$I ..\..\Include\Simd\GatherKernel\GatherKernelAvx2_i386.inc}
{$ENDIF}
end;

{$ENDIF}

{ TGatherKernelX86Backend }

class function TGatherKernelX86Backend.IsSupported: Boolean;
begin
{$IFDEF CRYPTOLIB_X86_SIMD}
  Result := TCpuFeatures.X86.GetActiveSimdLevel() <> TX86SimdLevel.Scalar;
{$ELSE}
  Result := False;
{$ENDIF}
end;

class function TGatherKernelX86Backend.Gather(PDst, PTable: PByte; AEntryBytes, ACount, AIndex: NativeInt): Boolean;
begin
{$IFDEF CRYPTOLIB_X86_SIMD}
  if TCpuFeatures.X86.HasAVX2() then
    FpKernelGatherAvx2(PDst, PTable, AEntryBytes, ACount, AIndex)
  else
    FpKernelGatherSse2(PDst, PTable, AEntryBytes, ACount, AIndex);
  Exit(True);
{$ENDIF}
  Result := False;
end;

end.
