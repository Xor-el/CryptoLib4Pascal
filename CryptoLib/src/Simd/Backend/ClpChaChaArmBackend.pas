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

unit ClpChaChaArmBackend;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpCpuFeatures,
  ClpCryptoLibTypes;

resourcestring
  SCounterExceeded = 'attempt to increase counter past 2^32';

type
  /// <summary>
  /// ARM (NEON) SIMD backend for the ChaCha family: owns the NEON keystream
  /// kernels (bodies in <c>Include\Simd\ChaCha\</c>): the 4-way vertical
  /// streaming kernel plus the horizontal 1-block core and 2-block fused-I/O
  /// kernel. Compiles on every target - when built without AArch64 SIMD the
  /// <c>Try*</c> entry points return <c>False</c> and the callers fall back
  /// to their scalar reference path. There is no NEON 8-block kernel (NEON
  /// is fixed at four 32-bit lanes); that tier returns False and the engine
  /// ladder runs the streaming 4-block tier instead.
  /// </summary>
  TChaChaArmBackend = class sealed
  public
    /// <summary>NEON single-block ChaCha core (ChaCha20 keystream block).</summary>
    class function TryCore(ARounds: Int32; AInput, AOut: PByte): Boolean; static;
    /// <summary>NEON two-block ChaCha keystream (128 bytes), fused I/O.
    /// ACtr64 selects the DJB 64-bit-counter variant (no wrap check);
    /// the RFC-7539 variant raises when the 32-bit counter wraps, matching
    /// the x86 kernel.</summary>
    class function TryProcessBlocks2(ARounds: Int32; AState, AIn, AOut: PByte; ACtr64: Boolean = False): Boolean; static;
    /// <summary>Four-block ChaCha keystream, streaming AGroups consecutive
    /// 256-byte groups (AGroups >= 1) in one call. ACtr64 selects the DJB
    /// 64-bit-counter write-back; the caller must guarantee the counter low
    /// word does not wrap inside the 4*AGroups-block span.</summary>
    class function TryProcessBlocks4(ARounds: Int32; AState, AIn, AOut: PByte; AGroups: Int32; ACtr64: Boolean = False): Boolean; static;
    /// <summary>No NEON eight-block kernel; returns False.</summary>
    class function TryProcessBlocks8(ARounds: Int32; AState, AIn, AOut: PByte; AGroups: Int32; ACtr64: Boolean = False): Boolean; static;
  end;

implementation

{$IFDEF CRYPTOLIB_AARCH64_ASM}

procedure ChaChaArmRaiseCounter7539;
begin
  raise EInvalidOperationCryptoLibException.CreateRes(@SCounterExceeded);
end;

procedure ChaCha20BlockNeon(ARounds: Int32; AInput, AOut: PByte);
{$I ..\..\Include\Simd\Common\ClpSimdProc3Begin_aarch64.inc}
{$I ..\..\Include\Simd\ChaCha\ChaCha20BlockNeon_aarch64.inc}
end;

procedure ChaCha7539ProcessBlocks2Neon(ARounds: Int32; AState, AIn, AOut: PByte);
{$I ..\..\Include\Simd\Common\ClpSimdProc4Begin_aarch64.inc}
{$I ..\..\Include\Simd\ChaCha\ChaCha7539Blocks2Neon_aarch64.inc}
end;

procedure ChaChaProcessBlocks2Neon(ARounds: Int32; AState, AIn, AOut: PByte);
{$DEFINE CHACHA_CTR64}
{$I ..\..\Include\Simd\Common\ClpSimdProc4Begin_aarch64.inc}
{$I ..\..\Include\Simd\ChaCha\ChaCha7539Blocks2Neon_aarch64.inc}
{$UNDEF CHACHA_CTR64}
end;

procedure ChaCha7539ProcessBlocks4Neon(ARounds: Int32; AState, AIn, AOut: PByte; AGroups: Int32);
{$I ..\..\Include\Simd\Common\ClpSimdProc5Begin_aarch64.inc}
{$I ..\..\Include\Simd\ChaCha\ChaCha7539Blocks4Neon_aarch64.inc}
end;

procedure ChaChaProcessBlocks4Neon(ARounds: Int32; AState, AIn, AOut: PByte; AGroups: Int32);
{$DEFINE CHACHA_CTR64}
{$I ..\..\Include\Simd\Common\ClpSimdProc5Begin_aarch64.inc}
{$I ..\..\Include\Simd\ChaCha\ChaCha7539Blocks4Neon_aarch64.inc}
{$UNDEF CHACHA_CTR64}
end;

{$ENDIF CRYPTOLIB_AARCH64_ASM}

{ TChaChaArmBackend }

class function TChaChaArmBackend.TryCore(ARounds: Int32;
  AInput, AOut: PByte): Boolean;
begin
{$IFDEF CRYPTOLIB_AARCH64_ASM}
  if TCpuFeatures.Arm.HasNEON() then
  begin
    ChaCha20BlockNeon(ARounds, AInput, AOut);
    Exit(True);
  end;
{$ENDIF}
  Result := False;
end;

class function TChaChaArmBackend.TryProcessBlocks2(ARounds: Int32;
  AState, AIn, AOut: PByte; ACtr64: Boolean): Boolean;
begin
{$IFDEF CRYPTOLIB_AARCH64_ASM}
  if TCpuFeatures.Arm.HasNEON() then
  begin
    if ACtr64 then
      ChaChaProcessBlocks2Neon(ARounds, AState, AIn, AOut)
    else
      ChaCha7539ProcessBlocks2Neon(ARounds, AState, AIn, AOut);
    Exit(True);
  end;
{$ENDIF}
  Result := False;
end;

class function TChaChaArmBackend.TryProcessBlocks4(ARounds: Int32;
  AState, AIn, AOut: PByte; AGroups: Int32; ACtr64: Boolean): Boolean;
begin
{$IFDEF CRYPTOLIB_AARCH64_ASM}
  if TCpuFeatures.Arm.HasNEON() then
  begin
    if ACtr64 then
      ChaChaProcessBlocks4Neon(ARounds, AState, AIn, AOut, AGroups)
    else
      ChaCha7539ProcessBlocks4Neon(ARounds, AState, AIn, AOut, AGroups);
    Exit(True);
  end;
{$ENDIF}
  Result := False;
end;

class function TChaChaArmBackend.TryProcessBlocks8(ARounds: Int32;
  AState, AIn, AOut: PByte; AGroups: Int32; ACtr64: Boolean): Boolean;
begin
  Result := False;
end;

end.
