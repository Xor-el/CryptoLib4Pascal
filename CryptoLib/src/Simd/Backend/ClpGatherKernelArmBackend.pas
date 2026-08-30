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

unit ClpGatherKernelArmBackend;

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
  /// Arm kernel backend for the constant-time table gather. A leaf: capability
  /// probe plus the NEON masked-accumulate gather. The arch-neutral dispatch and
  /// the scalar fallback live in <c>TGatherKernelSimd</c> / the field units. Hot
  /// paths are in <c>Include/Simd/GatherKernel/</c>.
  /// </summary>
  TGatherKernelArmBackend = class sealed
  public
    class function IsSupported: Boolean; static; inline;
    /// <summary>Constant-time gather: PDst := the AIndex-th of ACount entries (each
    /// AEntryBytes wide), with index-independent access.</summary>
    class function Gather(PDst, PTable: PByte; AEntryBytes, ACount, AIndex: NativeInt): Boolean; static;
  end;

implementation

{$IFDEF CRYPTOLIB_AARCH64_ASM}

// Constant-time table gather (NEON): PDst := the AIndex-th entry out of ACount,
// each AEntryBytes wide, masked-accumulated in constant time.
procedure FpKernelGatherNeon(PDst, PTable: PByte; AEntryBytes, ACount, AIndex: NativeInt);
{$I ..\..\Include\Simd\Common\ClpSimdProc5Begin_aarch64.inc}
{$I ..\..\Include\Simd\GatherKernel\GatherKernelNeon_aarch64.inc}
end;

{$ENDIF}

{ TGatherKernelArmBackend }

class function TGatherKernelArmBackend.IsSupported: Boolean;
begin
{$IFDEF CRYPTOLIB_AARCH64_ASM}
  Result := TCpuFeatures.Arm.GetActiveSimdLevel() <> TArmSimdLevel.Scalar;
{$ELSE}
  Result := False;
{$ENDIF}
end;

class function TGatherKernelArmBackend.Gather(PDst, PTable: PByte; AEntryBytes, ACount, AIndex: NativeInt): Boolean;
begin
{$IFDEF CRYPTOLIB_AARCH64_ASM}
  FpKernelGatherNeon(PDst, PTable, AEntryBytes, ACount, AIndex);
  Result := True;
{$ELSE}
  Result := False;
{$ENDIF}
end;

end.
