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

unit ClpGcmSivArmBackend;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpCpuFeatures;

type
  /// <summary>
  /// AArch64 SIMD backend for the AES-GCM-SIV POLYVAL batch kernel: owns the
  /// PMULL 8-block Horner kernel (the raw-input variant of the GHASH batch
  /// body in <c>Include\Simd\Gcm\</c>) and the runtime capability gate.
  /// Compiles on every target - <c>IsSupported</c> returns <c>False</c> off aarch64
  /// (so the fused-kernel factory declines to build a kernel) and
  /// <c>ProcessPolyvalBatch</c> is a no-op there. PMask is accepted for facade
  /// parity but unused (rev64 replaces the shuffle mask on AArch64).
  /// </summary>
  TGcmSivArmBackend = class sealed
  public
    /// <summary>True when the PMULL POLYVAL kernel is usable on this CPU.</summary>
    class function IsSupported: Boolean; static;
    /// <summary>ABatchCount eight-block POLYVAL Horner batches. Precondition: <c>IsSupported</c>.</summary>
    class procedure ProcessPolyvalBatch(PFS, PC0, PHPow128, PMask: Pointer;
      ABatchCount: NativeInt); static;
  end;

implementation

{$IFDEF CRYPTOLIB_AARCH64_ASM}
procedure GcmSivPolyvalHornerEight(PFS, PC0, PHPow128: Pointer;
  ABatchCount: NativeInt);
{$I ..\..\Include\Simd\Common\ClpSimdProc4Begin_aarch64.inc}
{$I ..\..\Include\Simd\GcmSiv\PolyvalHornerEight_aarch64.inc}
end;
{$ENDIF CRYPTOLIB_AARCH64_ASM}

{ TGcmSivArmBackend }

class function TGcmSivArmBackend.IsSupported: Boolean;
begin
{$IFDEF CRYPTOLIB_AARCH64_ASM}
  Result := TCpuFeatures.Arm.HasPMULL();
{$ELSE}
  Result := False;
{$ENDIF}
end;

class procedure TGcmSivArmBackend.ProcessPolyvalBatch(PFS, PC0, PHPow128, PMask: Pointer;
  ABatchCount: NativeInt);
begin
{$IFDEF CRYPTOLIB_AARCH64_ASM}
  GcmSivPolyvalHornerEight(PFS, PC0, PHPow128, ABatchCount);
{$ENDIF}
end;

end.
