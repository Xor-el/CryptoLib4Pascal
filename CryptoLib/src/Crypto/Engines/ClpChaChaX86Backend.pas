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
    /// <summary>SIMD two-block ChaCha7539 keystream (128 bytes).</summary>
    class function TryProcessBlocks2(ARounds: Int32; AState, AIn, AOut: PByte): Boolean; static;
    /// <summary>AVX2 four-block ChaCha7539 keystream (256 bytes).</summary>
    class function TryProcessBlocks4(ARounds: Int32; AState, AIn, AOut: PByte): Boolean; static;
  end;

implementation

{$IFDEF CRYPTOLIB_X86_SIMD}
procedure ChaCha20BlockSse2(ARounds: Int32; AInput, AOut: PByte);
{$IFDEF CRYPTOLIB_X86_64_ASM}
{$I ..\..\Include\Simd\Common\SimdProc3Begin_x86_64.inc}
{$I ..\..\Include\Simd\ChaCha\ChaCha20BlockSse2_x86_64.inc}
{$ENDIF}
{$IFDEF CRYPTOLIB_I386_ASM}
{$I ..\..\Include\Simd\Common\SimdProc3Begin_i386.inc}
{$I ..\..\Include\Simd\ChaCha\ChaCha20BlockSse2_i386.inc}
{$ENDIF}
end;

procedure ChaCha7539RaiseCounter7539;
begin
  raise EInvalidOperationCryptoLibException.CreateRes(@SCounterExceeded);
end;

procedure ChaCha7539ProcessBlocks2Sse2(ARounds: Int32; AState, AIn, AOut: PByte);
{$IFDEF CRYPTOLIB_X86_64_ASM}
{$I ..\..\Include\Simd\Common\SimdProc4Begin_x86_64.inc}
{$I ..\..\Include\Simd\ChaCha\ChaCha7539ProcessBlocks2Sse2_x86_64.inc}
{$ENDIF}
{$IFDEF CRYPTOLIB_I386_ASM}
{$I ..\..\Include\Simd\Common\SimdProc4Begin_i386.inc}
{$I ..\..\Include\Simd\ChaCha\ChaCha7539ProcessBlocks2Sse2_i386.inc}
{$ENDIF}
end;

procedure ChaCha7539ProcessBlocks2Avx2(ARounds: Int32; AState, AIn, AOut: PByte);
{$IFDEF CRYPTOLIB_X86_64_ASM}
{$I ..\..\Include\Simd\Common\SimdProc4Begin_x86_64.inc}
{$I ..\..\Include\Simd\ChaCha\ChaCha7539ProcessBlocks2Avx2_x86_64.inc}
{$ENDIF}
{$IFDEF CRYPTOLIB_I386_ASM}
{$I ..\..\Include\Simd\Common\SimdProc4Begin_i386.inc}
{$I ..\..\Include\Simd\ChaCha\ChaCha7539ProcessBlocks2Avx2_i386.inc}
{$ENDIF}
end;

procedure ChaCha7539ProcessBlocks4Avx2(ARounds: Int32; AState, AIn, AOut: PByte);
{$IFDEF CRYPTOLIB_X86_64_ASM}
{$I ..\..\Include\Simd\Common\SimdProc4Begin_x86_64.inc}
{$I ..\..\Include\Simd\ChaCha\ChaCha7539ProcessBlocks4Avx2_x86_64.inc}
{$ENDIF}
{$IFDEF CRYPTOLIB_I386_ASM}
{$I ..\..\Include\Simd\Common\SimdProc4Begin_i386.inc}
{$I ..\..\Include\Simd\ChaCha\ChaCha7539ProcessBlocks4Avx2_i386.inc}
{$ENDIF}
end;
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

class function TChaChaX86Backend.TryProcessBlocks2(ARounds: Int32; AState, AIn, AOut: PByte): Boolean;
begin
{$IFDEF CRYPTOLIB_X86_SIMD}
  case TCpuFeatures.X86.SelectSlot([TX86SimdLevel.AVX2, TX86SimdLevel.SSE2]) of
    TX86SimdLevel.AVX2:
    begin
      ChaCha7539ProcessBlocks2Avx2(ARounds, AState, AIn, AOut);
      Exit(True);
    end;
    TX86SimdLevel.SSE2:
    begin
      ChaCha7539ProcessBlocks2Sse2(ARounds, AState, AIn, AOut);
      Exit(True);
    end;
  end;
{$ENDIF}
  Result := False;
end;

class function TChaChaX86Backend.TryProcessBlocks4(ARounds: Int32; AState, AIn, AOut: PByte): Boolean;
begin
{$IFDEF CRYPTOLIB_X86_SIMD}
  case TCpuFeatures.X86.SelectSlot([TX86SimdLevel.AVX2]) of
    TX86SimdLevel.AVX2:
    begin
      ChaCha7539ProcessBlocks4Avx2(ARounds, AState, AIn, AOut);
      Exit(True);
    end;
  end;
{$ENDIF}
  Result := False;
end;

end.
