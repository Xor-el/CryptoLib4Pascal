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

unit ClpAesFusedAeadSimd;

{$I ..\..\Include\CryptoLib.inc}

interface

{$IF DEFINED(CRYPTOLIB_X86_SIMD)}
uses
  ClpAesNiFusedX86Backend;
{$IFEND}

type
  /// <summary>
  /// Arch-neutral capability gate for the fused hardware-AES AEAD pipeline
  /// (e.g. AES-NI on x86). Selects the per-arch
  /// backend at compile time and answers only the genuinely arch-neutral question
  /// - "is a fused hardware-AES path available on this build/CPU?".
  /// </summary>
  /// <remarks>
  /// Engine resolution deliberately does NOT live here: it hands back an
  /// instruction-set-specific round-key schedule (see <c>IAesEngineX86</c>), so it
  /// belongs on the per-arch backend (<c>TAesNiFusedX86Backend.TryResolveEngine</c>)
  /// that the matching per-arch kernels call. Not exported via the public
  /// interface surface and never imported by mode units, which stay
  /// cipher-agnostic.
  /// </remarks>
  TAesFusedAeadSimd = class sealed
  public
    /// <summary>CPU + build-time gate for the fused hardware-AES AEAD pipeline on this arch.</summary>
    class function CpuSupports: Boolean; static;
  end;

implementation

{ TAesFusedAeadSimd }

class function TAesFusedAeadSimd.CpuSupports: Boolean;
begin
{$IF DEFINED(CRYPTOLIB_X86_SIMD)}
  Result := TAesNiFusedX86Backend.CpuSupports;
{$ELSE}
  Result := False;
{$IFEND}
end;

end.
