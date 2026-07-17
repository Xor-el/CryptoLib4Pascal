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

unit ClpGcmSivX86Backend;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpCpuFeatures;

type
  /// <summary>
  /// x86 SIMD backend for the AES-GCM-SIV POLYVAL batch kernel: owns the
  /// PCLMULQDQ 8-block Horner kernel (body in <c>Include\Simd\GcmSiv\</c>)
  /// and the runtime capability gate. Compiles on every target - <c>IsSupported</c>
  /// returns <c>False</c> off x86 (so the fused-kernel factory declines to build a
  /// kernel) and <c>ProcessPolyvalBatch</c> is a no-op there.
  /// </summary>
  TGcmSivX86Backend = class sealed
  public
    /// <summary>True when the PCLMULQDQ POLYVAL kernel is usable on this CPU.</summary>
    class function IsSupported: Boolean; static;
    /// <summary>ABatchCount eight-block POLYVAL Horner batches. Precondition: <c>IsSupported</c>.</summary>
    class procedure ProcessPolyvalBatch(PFS, PC0, PHPow128, PMask: Pointer;
      ABatchCount: NativeInt); static;
  end;

implementation

{$IFDEF CRYPTOLIB_X86_SIMD}
procedure GcmSivPolyvalHornerEight(PFS, PC0, PHPow128, PMask: Pointer;
  ABatchCount: NativeInt);
{$IFDEF CRYPTOLIB_X86_64_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc5Begin_x86_64.inc}
{$I ..\..\Include\Simd\GcmSiv\PolyvalHornerEight_x86_64.inc}
{$ENDIF}
{$IFDEF CRYPTOLIB_I386_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc5Begin_i386.inc}
{$I ..\..\Include\Simd\GcmSiv\PolyvalHornerEight_i386.inc}
{$ENDIF}
end;
{$ENDIF CRYPTOLIB_X86_SIMD}

{ TGcmSivX86Backend }

class function TGcmSivX86Backend.IsSupported: Boolean;
begin
{$IFDEF CRYPTOLIB_X86_SIMD}
  Result := TCpuFeatures.X86.HasPCLMULQDQ() and TCpuFeatures.X86.HasSSSE3();
{$ELSE}
  Result := False;
{$ENDIF}
end;

class procedure TGcmSivX86Backend.ProcessPolyvalBatch(PFS, PC0, PHPow128, PMask: Pointer;
  ABatchCount: NativeInt);
begin
{$IFDEF CRYPTOLIB_X86_SIMD}
  GcmSivPolyvalHornerEight(PFS, PC0, PHPow128, PMask, ABatchCount);
{$ENDIF}
end;

end.
