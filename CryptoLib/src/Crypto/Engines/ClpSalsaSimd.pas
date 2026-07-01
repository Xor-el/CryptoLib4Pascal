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

unit ClpSalsaSimd;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpCryptoLibTypes
{$IF DEFINED(CRYPTOLIB_X86_SIMD)}
  , ClpSalsaX86Backend
{$ELSEIF DEFINED(CRYPTOLIB_ARM_SIMD)}
  , ClpSalsaArmBackend
{$IFEND}
  ;

type
  /// <summary>
  /// Arch-neutral SIMD dispatch facade for the Salsa20 family. Selects the
  /// per-arch backend at compile time; on a build with no
  /// SIMD backend every entry point degrades to "not handled" so callers run
  /// their scalar reference path. The Salsa20 engine calls only this facade and
  /// stays free of any <c>TCpuFeatures</c> / <c>CRYPTOLIB_*_ASM</c> knowledge.
  /// </summary>
  TSalsaSimd = class sealed
  public
    /// <summary>Single-block Salsa20 core.</summary>
    class function TryCore(ARounds: Int32; AInput, AOut: Pointer): Boolean; static;
    /// <summary>Two-block Salsa20 keystream (128 bytes).</summary>
    class function TryProcessBlocks2(ARounds: Int32; AState, AIn, AOut: PByte): Boolean; static;
  end;

implementation

{ TSalsaSimd }

class function TSalsaSimd.TryCore(ARounds: Int32; AInput, AOut: Pointer): Boolean;
begin
{$IF DEFINED(CRYPTOLIB_X86_SIMD)}
  Result := TSalsaX86Backend.TryCore(ARounds, AInput, AOut);
{$ELSEIF DEFINED(CRYPTOLIB_ARM_SIMD)}
  Result := TSalsaArmBackend.TryCore(ARounds, AInput, AOut);
{$ELSE}
  Result := False;
{$IFEND}
end;

class function TSalsaSimd.TryProcessBlocks2(ARounds: Int32; AState, AIn, AOut: PByte): Boolean;
begin
{$IF DEFINED(CRYPTOLIB_X86_SIMD)}
  Result := TSalsaX86Backend.TryProcessBlocks2(ARounds, AState, AIn, AOut);
{$ELSEIF DEFINED(CRYPTOLIB_ARM_SIMD)}
  Result := TSalsaArmBackend.TryProcessBlocks2(ARounds, AState, AIn, AOut);
{$ELSE}
  Result := False;
{$IFEND}
end;

end.
