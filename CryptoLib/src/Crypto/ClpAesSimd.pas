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

unit ClpAesSimd;

{$I ..\Include\CryptoLib.inc}

interface

uses
  ClpIBlockCipher
{$IF DEFINED(CRYPTOLIB_X86_SIMD)}
  , ClpAesEngineX86
{$IFEND}
  ;

type
  /// <summary>
  /// Arch-neutral SIMD dispatch facade for hardware-accelerated AES engines.
  /// SIMD-only by contract: it produces the per-arch hardware engine (e.g.
  /// AES-NI via <c>TAesEngineX86</c> on x86)
  /// when available, or reports "not handled" - it never returns the portable
  /// scalar engine. The scalar fallback belongs to the caller
  /// (<c>TAesUtilities</c>), matching the Try*-then-scalar shape used across the
  /// other SIMD families. Selects the per-arch backend at compile time.
  /// </summary>
  TAesSimd = class sealed
  public
    /// <summary>True when a hardware AES engine is available on this build/CPU.</summary>
    class function IsSupported: Boolean; static;
    /// <summary>
    /// Create the per-arch hardware AES engine when available (returns True with
    /// <paramref name="AEngine"/> set); otherwise <paramref name="AEngine"/> is nil
    /// and the caller runs its scalar path (returns False).
    /// </summary>
    class function TryCreateHardwareEngine(out AEngine: IBlockCipher): Boolean; static;
  end;

implementation

{ TAesSimd }

class function TAesSimd.IsSupported: Boolean;
begin
{$IF DEFINED(CRYPTOLIB_X86_SIMD)}
  Result := TAesEngineX86.IsSupported;
{$ELSE}
  Result := False;
{$IFEND}
end;

class function TAesSimd.TryCreateHardwareEngine(out AEngine: IBlockCipher): Boolean;
begin
  AEngine := nil;
{$IF DEFINED(CRYPTOLIB_X86_SIMD)}
  if TAesEngineX86.IsSupported then
  begin
    AEngine := TAesEngineX86.Create();
    Exit(True);
  end;
{$IFEND}
  Result := False;
end;

end.
