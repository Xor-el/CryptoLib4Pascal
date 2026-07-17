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

unit ClpByteXorX86Backend;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpCpuFeatures,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// x86 SIMD backend for the byte-array XOR primitives behind
  /// <c>TByteUtilities</c>: an SSE2 <c>movdqu</c>/<c>pxor</c> kernel (body in
  /// <c>Include\Simd\ByteXor\</c>) plus the runtime capability gate.
  /// Compiles on every target - the entry points return <c>False</c> (leaving the
  /// caller on its scalar qword/byte path) when built without x86 SIMD or when
  /// the active SIMD level is below SSE2 (e.g. CRYPTOLIB_FORCE_SCALAR). Works on
  /// raw pointers only; unaligned operands are handled by <c>movdqu</c>.
  /// </summary>
  TByteXorX86Backend = class sealed
  public
    /// <summary>AZ[i] := AX[i] xor AY[i] over ALen bytes; AZ may alias AX or AY
    /// (so the in-place XorTo case is TryXor with AY = AZ). False if unavailable.</summary>
    class function TryXor(ALen: NativeInt; AX, AY, AZ: PByte): Boolean; static;
  end;

implementation

{$IFDEF CRYPTOLIB_X86_SIMD}
procedure ByteXorSse2(ALen: NativeInt; AX, AY, AZ: Pointer);
{$IFDEF CRYPTOLIB_X86_64_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc4Begin_x86_64.inc}
{$I ..\..\Include\Simd\ByteXor\ByteXorSse2_x86_64.inc}
{$ENDIF}
{$IFDEF CRYPTOLIB_I386_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc4Begin_i386.inc}
{$I ..\..\Include\Simd\ByteXor\ByteXorSse2_i386.inc}
{$ENDIF}
end;
{$ENDIF CRYPTOLIB_X86_SIMD}

{ TByteXorX86Backend }

class function TByteXorX86Backend.TryXor(ALen: NativeInt; AX, AY, AZ: PByte): Boolean;
begin
{$IFDEF CRYPTOLIB_X86_SIMD}
  if TCpuFeatures.X86.HasSSE2() then
  begin
    ByteXorSse2(ALen, AX, AY, AZ);
    Exit(True);
  end;
{$ENDIF}
  Result := False;
end;

end.
