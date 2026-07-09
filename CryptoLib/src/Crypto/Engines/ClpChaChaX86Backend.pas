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

unit ClpChaChaX86Backend;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpCpuFeatures,
  ClpSimdLevels,
  ClpCryptoLibTypes;

resourcestring
  SCounterExceeded = 'attempt to increase counter past 2^32';

type
  /// <summary>
  /// x86 SIMD backend for the ChaCha family: owns the SIMD keystream kernels
  /// (bodies in <c>Include\Simd\ChaCha\</c>) and the runtime tier selection via
  /// <c>TCpuFeatures.X86.SelectSlot</c>. Compiles on every target - when built
  /// without x86 SIMD the <c>Try*</c> entry points return <c>False</c> and the
  /// callers fall back to their scalar reference path.
  /// </summary>
  TChaChaX86Backend = class sealed
  public
    /// <summary>SIMD single-block ChaCha core (ChaCha20 keystream block).</summary>
    class function TryCore(ARounds: Int32; AInput, AOut: PByte): Boolean; static;
    /// <summary>SIMD two-block ChaCha keystream (128 bytes). ACtr64 selects the
    /// 64-bit-counter (DJB) variant; no SIMD 2-block kernel exists for it, so it
    /// returns False and the caller runs its scalar path.</summary>
    class function TryProcessBlocks2(ARounds: Int32; AState, AIn, AOut: PByte; ACtr64: Boolean = False): Boolean; static;
    /// <summary>Four-block ChaCha keystream (256 bytes). ACtr64 selects the DJB
    /// 64-bit-counter kernel.</summary>
    class function TryProcessBlocks4(ARounds: Int32; AState, AIn, AOut: PByte; ACtr64: Boolean = False): Boolean; static;
    /// <summary>AVX2 eight-block ChaCha keystream (512 bytes). ACtr64 selects the
    /// DJB 64-bit-counter kernel.</summary>
    class function TryProcessBlocks8(ARounds: Int32; AState, AIn, AOut: PByte; ACtr64: Boolean = False): Boolean; static;
  end;

implementation

{$IFDEF CRYPTOLIB_X86_SIMD}
procedure ChaCha20BlockSse2(ARounds: Int32; AInput, AOut: PByte);
{$IFDEF CRYPTOLIB_X86_64_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc3Begin_x86_64.inc}
{$I ..\..\Include\Simd\ChaCha\ChaCha20BlockSse2_x86_64.inc}
{$ENDIF}
{$IFDEF CRYPTOLIB_I386_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc3Begin_i386.inc}
{$I ..\..\Include\Simd\ChaCha\ChaCha20BlockSse2_i386.inc}
{$ENDIF}
end;

procedure ChaCha7539RaiseCounter7539;
begin
  raise EInvalidOperationCryptoLibException.CreateRes(@SCounterExceeded);
end;

procedure ChaCha7539ProcessBlocks2Sse2(ARounds: Int32; AState, AIn, AOut: PByte);
{$IFDEF CRYPTOLIB_X86_64_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc4Begin_x86_64.inc}
{$I ..\..\Include\Simd\ChaCha\ChaCha7539ProcessBlocks2Sse2_x86_64.inc}
{$ENDIF}
{$IFDEF CRYPTOLIB_I386_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc4Begin_i386.inc}
{$I ..\..\Include\Simd\ChaCha\ChaCha7539ProcessBlocks2Sse2_i386.inc}
{$ENDIF}
end;

procedure ChaCha7539ProcessBlocks4Sse2(ARounds: Int32; AState, AIn, AOut: PByte);
{$IFDEF CRYPTOLIB_X86_64_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc4Begin_x86_64.inc}
{$I ..\..\Include\Simd\ChaCha\ChaCha7539Blocks4Sse2_x86_64.inc}
{$ENDIF}
{$IFDEF CRYPTOLIB_I386_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc4Begin_i386.inc}
{$I ..\..\Include\Simd\ChaCha\ChaCha7539Blocks4Sse2_i386.inc}
{$ENDIF}
end;

procedure ChaCha7539ProcessBlocks4Ssse3(ARounds: Int32; AState, AIn, AOut: PByte);
{$IFDEF CRYPTOLIB_X86_64_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc4Begin_x86_64.inc}
{$I ..\..\Include\Simd\ChaCha\ChaCha7539Blocks4Ssse3_x86_64.inc}
{$ENDIF}
{$IFDEF CRYPTOLIB_I386_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc4Begin_i386.inc}
{$I ..\..\Include\Simd\ChaCha\ChaCha7539Blocks4Ssse3_i386.inc}
{$ENDIF}
end;

// AVX2 8-way (512B): x86_64 only (needs 16 ymm; i386 has 8, so it falls back to
// two 256B ProcessBlocks4 in the engine).
{$IFDEF CRYPTOLIB_X86_64_ASM}
procedure ChaCha7539ProcessBlocks8Avx2(ARounds: Int32; AState, AIn, AOut: PByte);
{$I ..\..\Include\Simd\Common\ClpSimdProc4Begin_x86_64.inc}
{$I ..\..\Include\Simd\ChaCha\ChaCha7539Blocks8Avx2_x86_64.inc}
end;
{$ENDIF}

// DJB ChaCha (64-bit counter, words 12-13): the vertical kernels are identical to
// the 7539 ones except the counter advance carries into word 13, which the shared
// includes emit under CHACHA_CTR64. Callers guard against a low-word wrap across the
// lanes before invoking these (see the engine's WideBlocksSafe).
procedure ChaChaProcessBlocks4Sse2(ARounds: Int32; AState, AIn, AOut: PByte);
{$IFDEF CRYPTOLIB_X86_64_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc4Begin_x86_64.inc}
{$DEFINE CHACHA_CTR64}
{$I ..\..\Include\Simd\ChaCha\ChaCha7539Blocks4Sse2_x86_64.inc}
{$UNDEF CHACHA_CTR64}
{$ENDIF}
{$IFDEF CRYPTOLIB_I386_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc4Begin_i386.inc}
{$DEFINE CHACHA_CTR64}
{$I ..\..\Include\Simd\ChaCha\ChaCha7539Blocks4Sse2_i386.inc}
{$UNDEF CHACHA_CTR64}
{$ENDIF}
end;

procedure ChaChaProcessBlocks4Ssse3(ARounds: Int32; AState, AIn, AOut: PByte);
{$IFDEF CRYPTOLIB_X86_64_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc4Begin_x86_64.inc}
{$DEFINE CHACHA_CTR64}
{$I ..\..\Include\Simd\ChaCha\ChaCha7539Blocks4Ssse3_x86_64.inc}
{$UNDEF CHACHA_CTR64}
{$ENDIF}
{$IFDEF CRYPTOLIB_I386_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc4Begin_i386.inc}
{$DEFINE CHACHA_CTR64}
{$I ..\..\Include\Simd\ChaCha\ChaCha7539Blocks4Ssse3_i386.inc}
{$UNDEF CHACHA_CTR64}
{$ENDIF}
end;

{$IFDEF CRYPTOLIB_X86_64_ASM}
procedure ChaChaProcessBlocks8Avx2(ARounds: Int32; AState, AIn, AOut: PByte);
{$I ..\..\Include\Simd\Common\ClpSimdProc4Begin_x86_64.inc}
{$DEFINE CHACHA_CTR64}
{$I ..\..\Include\Simd\ChaCha\ChaCha7539Blocks8Avx2_x86_64.inc}
{$UNDEF CHACHA_CTR64}
end;
{$ENDIF}
{$ENDIF CRYPTOLIB_X86_SIMD}

{ TChaChaX86Backend }

class function TChaChaX86Backend.TryCore(ARounds: Int32; AInput, AOut: PByte): Boolean;
begin
{$IFDEF CRYPTOLIB_X86_SIMD}
  case TCpuFeatures.X86.SelectSlot([TX86SimdLevel.SSE2]) of
    TX86SimdLevel.SSE2:
    begin
      ChaCha20BlockSse2(ARounds, AInput, AOut);
      Exit(True);
    end;
  end;
{$ENDIF}
  Result := False;
end;

class function TChaChaX86Backend.TryProcessBlocks2(ARounds: Int32; AState, AIn, AOut: PByte; ACtr64: Boolean): Boolean;
begin
{$IFDEF CRYPTOLIB_X86_SIMD}
  // 2-block (128B) tier: AVX2 adds nothing at this width, so the SSE2 body serves
  // every SIMD CPU (the vertical 4-way/8-way kernels handle the larger tiers). The
  // 2-block kernel is 7539-only (32-bit counter with raise-on-wrap), so DJB
  // (ACtr64) has no SIMD body here and runs scalar.
  if not ACtr64 then
    case TCpuFeatures.X86.SelectSlot([TX86SimdLevel.SSE2]) of
      TX86SimdLevel.SSE2:
      begin
        ChaCha7539ProcessBlocks2Sse2(ARounds, AState, AIn, AOut);
        Exit(True);
      end;
    end;
{$ENDIF}
  Result := False;
end;

class function TChaChaX86Backend.TryProcessBlocks4(ARounds: Int32; AState, AIn, AOut: PByte; ACtr64: Boolean): Boolean;
begin
{$IFDEF CRYPTOLIB_X86_SIMD}
  // 4-block (256B) tier: AVX2 gives no extra lanes at 4-way, and AVX2 CPUs run the
  // 8-way kernel for the bulk (512B) tier, so SSSE3/SSE2 cover every CPU here.
  case TCpuFeatures.X86.SelectSlot([TX86SimdLevel.SSSE3, TX86SimdLevel.SSE2]) of
    TX86SimdLevel.SSSE3:
    begin
      if ACtr64 then
        ChaChaProcessBlocks4Ssse3(ARounds, AState, AIn, AOut)
      else
        ChaCha7539ProcessBlocks4Ssse3(ARounds, AState, AIn, AOut);
      Exit(True);
    end;
    TX86SimdLevel.SSE2:
    begin
      if ACtr64 then
        ChaChaProcessBlocks4Sse2(ARounds, AState, AIn, AOut)
      else
        ChaCha7539ProcessBlocks4Sse2(ARounds, AState, AIn, AOut);
      Exit(True);
    end;
  end;
{$ENDIF}
  Result := False;
end;

class function TChaChaX86Backend.TryProcessBlocks8(ARounds: Int32; AState, AIn, AOut: PByte; ACtr64: Boolean): Boolean;
begin
{$IFDEF CRYPTOLIB_X86_64_ASM}
  case TCpuFeatures.X86.SelectSlot([TX86SimdLevel.AVX2]) of
    TX86SimdLevel.AVX2:
    begin
      if ACtr64 then
        ChaChaProcessBlocks8Avx2(ARounds, AState, AIn, AOut)
      else
        ChaCha7539ProcessBlocks8Avx2(ARounds, AState, AIn, AOut);
      Exit(True);
    end;
  end;
{$ENDIF}
  Result := False;
end;

end.
