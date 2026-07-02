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

unit ClpChaChaSimd;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpCryptoLibTypes
{$IF DEFINED(CRYPTOLIB_X86_SIMD)}
  , ClpChaChaX86Backend
{$IFEND}
  ;

type
  /// <summary>
  /// Arch-neutral SIMD dispatch facade for the ChaCha family. Selects the
  /// per-arch backend at compile time; on a build with no
  /// SIMD backend every entry point degrades to "not handled" so callers run
  /// their scalar reference path. The ChaCha engines call only this facade and
  /// stay free of any <c>TCpuFeatures</c> / <c>CRYPTOLIB_*_ASM</c> knowledge.
  /// </summary>
  TChaChaSimd = class sealed
  public
    /// <summary>Single-block ChaCha core (ChaCha20 keystream block).</summary>
    class function TryCore(ARounds: Int32; AInput, AOut: PByte): Boolean; static;
    /// <summary>Two-block ChaCha7539 keystream (128 bytes).</summary>
    class function TryProcessBlocks2(ARounds: Int32; AState, AIn, AOut: PByte): Boolean; static;
    /// <summary>Four-block ChaCha7539 keystream (256 bytes).</summary>
    class function TryProcessBlocks4(ARounds: Int32; AState, AIn, AOut: PByte): Boolean; static;
  end;

implementation

{ TChaChaSimd }

class function TChaChaSimd.TryCore(ARounds: Int32; AInput, AOut: PByte): Boolean;
begin
{$IF DEFINED(CRYPTOLIB_X86_SIMD)}
  Result := TChaChaX86Backend.TryCore(ARounds, AInput, AOut);
{$ELSE}
  Result := False;
{$IFEND}
end;

class function TChaChaSimd.TryProcessBlocks2(ARounds: Int32; AState, AIn, AOut: PByte): Boolean;
begin
{$IF DEFINED(CRYPTOLIB_X86_SIMD)}
  Result := TChaChaX86Backend.TryProcessBlocks2(ARounds, AState, AIn, AOut);
{$ELSE}
  Result := False;
{$IFEND}
end;

class function TChaChaSimd.TryProcessBlocks4(ARounds: Int32; AState, AIn, AOut: PByte): Boolean;
begin
{$IF DEFINED(CRYPTOLIB_X86_SIMD)}
  Result := TChaChaX86Backend.TryProcessBlocks4(ARounds, AState, AIn, AOut);
{$ELSE}
  Result := False;
{$IFEND}
end;

end.
