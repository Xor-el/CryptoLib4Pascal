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

unit ClpGcmSivSimd;

{$I ..\..\..\Include\CryptoLib.inc}

interface

{$IF DEFINED(CRYPTOLIB_X86_SIMD)}
uses
  ClpGcmSivX86Backend;
{$IFEND}

type
  /// <summary>
  /// Arch-neutral SIMD dispatch facade for the AES-GCM-SIV POLYVAL batch kernel.
  /// Selects the per-arch backend at compile time; on a
  /// build with no SIMD backend <c>IsSupported</c> is <c>False</c> (so the fused
  /// GCM-SIV kernel factory declines) and <c>ProcessPolyvalBatch</c> is a no-op.
  /// The kernel unit calls only this facade and stays free of any
  /// <c>TCpuFeatures</c> / <c>CRYPTOLIB_*_ASM</c> knowledge.
  /// </summary>
  TGcmSivSimd = class sealed
  public
    /// <summary>True when a POLYVAL batch kernel is usable on this CPU.</summary>
    class function IsSupported: Boolean; static;
    /// <summary>Eight-block POLYVAL Horner batch. Precondition: <c>IsSupported</c>.</summary>
    class procedure ProcessPolyvalBatch(PFS, PC0, PHPow128, PMask: Pointer); static;
  end;

implementation

{ TGcmSivSimd }

class function TGcmSivSimd.IsSupported: Boolean;
begin
{$IF DEFINED(CRYPTOLIB_X86_SIMD)}
  Result := TGcmSivX86Backend.IsSupported;
{$ELSE}
  Result := False;
{$IFEND}
end;

class procedure TGcmSivSimd.ProcessPolyvalBatch(PFS, PC0, PHPow128, PMask: Pointer);
begin
{$IF DEFINED(CRYPTOLIB_X86_SIMD)}
  TGcmSivX86Backend.ProcessPolyvalBatch(PFS, PC0, PHPow128, PMask);
{$IFEND}
end;

end.
