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

unit ClpByteXorArmBackend;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpCpuFeatures,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// ARM (NEON) backend for the variable-length XOR utility (body in
  /// <c>Include\Simd\ByteXor\</c>). Compiles on every target - when built
  /// without AArch64 SIMD <c>TryXor</c> returns <c>False</c> and the caller
  /// runs its scalar path.
  /// </summary>
  TByteXorArmBackend = class sealed
  public
    /// <summary>PZ[i] := PX[i] xor PY[i] for i in [0, ALen); PZ may alias
    /// PX or PY.</summary>
    class function TryXor(ALen: NativeInt; AX, AY, AZ: PByte): Boolean; static;
  end;

implementation

{$IFDEF CRYPTOLIB_AARCH64_ASM}
procedure ByteXorNeon(ALen: NativeInt; AX, AY, AZ: Pointer);
{$I ..\..\Include\Simd\Common\ClpSimdProc4Begin_aarch64.inc}
{$I ..\..\Include\Simd\ByteXor\ByteXorNeon_aarch64.inc}
end;
{$ENDIF CRYPTOLIB_AARCH64_ASM}

{ TByteXorArmBackend }

class function TByteXorArmBackend.TryXor(ALen: NativeInt;
  AX, AY, AZ: PByte): Boolean;
begin
{$IFDEF CRYPTOLIB_AARCH64_ASM}
  if TCpuFeatures.Arm.HasNEON() then
  begin
    ByteXorNeon(ALen, AX, AY, AZ);
    Exit(True);
  end;
{$ENDIF}
  Result := False;
end;

end.
