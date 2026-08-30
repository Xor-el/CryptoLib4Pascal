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

unit ClpGatherKernelSimd;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
{$IFDEF CRYPTOLIB_X86_SIMD}
  ClpGatherKernelX86Backend,
{$ENDIF}
{$IFDEF CRYPTOLIB_AARCH64_ASM}
  ClpGatherKernelArmBackend,
{$ENDIF}
  ClpCryptoLibTypes;

type
  /// <summary>
  /// Arch-neutral facade over the constant-time table-gather kernel.
  /// <c>TryGather</c> returns <c>False</c> when no fast path applies
  /// (unsupported arch or a forced-scalar build); the caller then uses its
  /// scalar masked-accumulate path.
  /// </summary>
  TGatherKernelSimd = class sealed
  public
    /// <summary>Constant-time gather: APDst := the AIndex-th of ACount entries (each
    /// AEntryBytes wide), with index-independent access. False when force-scalar.</summary>
    class function TryGather(APDst, APTable: PByte; AEntryBytes, ACount, AIndex: NativeInt): Boolean; static; inline;
  end;

implementation

{ TGatherKernelSimd }

class function TGatherKernelSimd.TryGather(APDst, APTable: PByte; AEntryBytes, ACount, AIndex: NativeInt): Boolean;
begin
{$IF DEFINED(CRYPTOLIB_X86_SIMD) OR DEFINED(CRYPTOLIB_AARCH64_ASM)}
  {$IFDEF CRYPTOLIB_X86_SIMD}
  if not TGatherKernelX86Backend.IsSupported then
    Exit(False);
  Result := TGatherKernelX86Backend.Gather(APDst, APTable, AEntryBytes, ACount, AIndex);
  {$ELSE}
  if not TGatherKernelArmBackend.IsSupported then
    Exit(False);
  Result := TGatherKernelArmBackend.Gather(APDst, APTable, AEntryBytes, ACount, AIndex);
  {$ENDIF}
{$ELSE}
  Result := False;
{$IFEND}
end;

end.
