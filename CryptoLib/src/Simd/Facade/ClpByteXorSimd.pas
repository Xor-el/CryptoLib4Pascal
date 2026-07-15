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

unit ClpByteXorSimd;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
{$IFDEF CRYPTOLIB_X86_SIMD}
  ClpByteXorX86Backend,
{$ENDIF}
  ClpCryptoLibTypes;

type
  /// <summary>
  /// Arch-agnostic SIMD facade for the byte-array XOR primitives behind
  /// <c>TByteUtilities</c>. Selects the per-arch backend at compile time; on a
  /// build with no SIMD backend (or when the active SIMD level is too low) every
  /// entry point returns <c>False</c>, leaving the caller on its scalar
  /// qword/byte path.
  /// </summary>
  TByteXorSimd = class sealed
  public
    /// <summary>AZ[i] := AX[i] xor AY[i] over ALen bytes; AZ may alias AX/AY
    /// (so the in-place XorTo case is TryXor with AY = AZ). False if unavailable.</summary>
    class function TryXor(ALen: NativeInt; AX, AY, AZ: PByte): Boolean; static;
  end;

implementation

class function TByteXorSimd.TryXor(ALen: NativeInt; AX, AY, AZ: PByte): Boolean;
begin
{$IFDEF CRYPTOLIB_X86_SIMD}
  Result := TByteXorX86Backend.TryXor(ALen, AX, AY, AZ);
{$ELSE}
  Result := False;
{$ENDIF}
end;

end.
