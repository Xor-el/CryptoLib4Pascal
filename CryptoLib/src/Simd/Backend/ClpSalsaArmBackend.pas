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

unit ClpSalsaArmBackend;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpCpuFeatures,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// ARM (NEON) SIMD backend for the Salsa20 family: owns the NEON kernels
  /// (bodies in <c>Include\Simd\Salsa\</c>): the 1-block core and the
  /// 2-block fused-I/O kernel. Compiles on every target - when built
  /// without AArch64 SIMD the <c>Try*</c> entry points return <c>False</c>
  /// and the callers fall back to their scalar reference path.
  /// </summary>
  TSalsaArmBackend = class sealed
  public
    /// <summary>NEON single-block Salsa20 core.</summary>
    class function TryCore(ARounds: Int32; AInput, AOut: Pointer): Boolean; static;
    /// <summary>NEON two-block Salsa20 keystream (128 bytes), fused I/O.</summary>
    class function TryProcessBlocks2(ARounds: Int32; AState, AIn, AOut: PByte): Boolean; static;
  end;

implementation

{$IFDEF CRYPTOLIB_AARCH64_ASM}
procedure Salsa20BlockNeon(ARounds: Int32; AInput, AOut: Pointer);
{$I ..\..\Include\Simd\Common\ClpSimdProc3Begin_aarch64.inc}
{$I ..\..\Include\Simd\Salsa\Salsa20BlockNeon_aarch64.inc}
end;

procedure Salsa20ProcessBlocks2Neon(ARounds: Int32; AState, AIn, AOut: PByte);
{$I ..\..\Include\Simd\Common\ClpSimdProc4Begin_aarch64.inc}
{$I ..\..\Include\Simd\Salsa\Salsa20Blocks2Neon_aarch64.inc}
end;
{$ENDIF CRYPTOLIB_AARCH64_ASM}

{ TSalsaArmBackend }

class function TSalsaArmBackend.TryCore(ARounds: Int32;
  AInput, AOut: Pointer): Boolean;
begin
{$IFDEF CRYPTOLIB_AARCH64_ASM}
  if TCpuFeatures.Arm.HasNEON() then
  begin
    Salsa20BlockNeon(ARounds, AInput, AOut);
    Exit(True);
  end;
{$ENDIF}
  Result := False;
end;

class function TSalsaArmBackend.TryProcessBlocks2(ARounds: Int32;
  AState, AIn, AOut: PByte): Boolean;
begin
{$IFDEF CRYPTOLIB_AARCH64_ASM}
  if TCpuFeatures.Arm.HasNEON() then
  begin
    Salsa20ProcessBlocks2Neon(ARounds, AState, AIn, AOut);
    Exit(True);
  end;
{$ENDIF}
  Result := False;
end;

end.
