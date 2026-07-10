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

unit ClpAesEngineX86;

{$I ..\..\Include\CryptoLib.inc}

interface

{$IFDEF CRYPTOLIB_X86_SIMD}

uses
  SysUtils,
  ClpIAesEngineX86,
  ClpIAesHardwareEngine,
  ClpIBulkBlockCipher,
  ClpIBlockCipher,
  ClpICipherParameters,
  ClpIKeyParameter,
  ClpCpuFeatures,
  ClpCheck,
  ClpArrayUtilities,
  ClpBitOperations,
  ClpCryptoLibTypes,
  ClpPlatformUtilities;

resourcestring
  SInputBufferTooShort = 'input buffer too short';
  SOutputBufferTooShort = 'output buffer too short';
  SAesEngineX86NotSupported = 'AES hardware engine not supported on this platform';
  SInvalidParameterAESX86Init = 'invalid parameter passed to AES init: %s';
  SInvalidKeyLength = 'key length not 128/192/256 bits';
  SAesEngineX86NotInitialised = 'AES engine not initialized';
  SNilPointerBuffer = 'input or output pointer is nil';

type
  /// <summary>
  /// AES using AES-NI when supported (see <see cref="IsSupported" />).
  /// </summary>
  TAesEngineX86 = class sealed(TInterfacedObject, IAesEngineX86, IAesHardwareEngine,
    IBulkBlockCipher, IBlockCipher)
  strict private
  type
    TAesX86Mode = (Uninitialized, Dec128, Dec192, Dec256, Enc128, Enc192, Enc256);
    TAesNiCipherProc = procedure(State, Keys: PByte);
    TAesNiCipherInOutProc = procedure(RIn, ROut, Keys: PByte);
  strict private
    FMode: TAesX86Mode;
    FNRounds: Int32;
    FRawAlloc: Pointer;
    FKeys: PByte;
    FAesNiCipherOne: TAesNiCipherProc;
    FAesNiCipherFour: TAesNiCipherProc;
    FAesNiCipherEight: TAesNiCipherProc;
    FAesNiCipherOneInOut: TAesNiCipherInOutProc;
    FAesNiCipherFourInOut: TAesNiCipherInOutProc;
    FAesNiCipherEightInOut: TAesNiCipherInOutProc;
    procedure FreeAlignedKeys;
    procedure AllocAlignedKeys(AKeyBytes: Int32);
    procedure CreateRoundKeys(AForEncryption: Boolean; const AKey: TCryptoLibByteArray);
    procedure PrepareDecryptRoundKeys;
    procedure BindCipherPointers;
    function GetAlgorithmName: String;

    // ===== Internal fast-path helpers (engine's own ProcessBlocks ladder) =====
    // The 4/8-wide inner steps of the IBulkBlockCipher ProcessBlocks ladder.
    // Only ProcessBlocks (PByte overload) drives these: it has already honoured
    // the IBulkBlockCipher aliasing contract (identical-or-fully-disjoint) for
    // the whole batch, so each slice inherits it. Strict private so no external
    // caller can reach them and skip that check.
    /// <summary>Four consecutive 16-byte blocks (64 bytes) via pointers.
    /// Identical-or-fully-disjoint buffers only.</summary>
    function ProcessFourBlocksFast(AInput, AOutput: PByte): Int32; inline;
    /// <summary>Eight consecutive 16-byte blocks (128 bytes) via pointers.
    /// Identical-or-fully-disjoint buffers only.</summary>
    function ProcessEightBlocksFast(AInput, AOutput: PByte): Int32; inline;
  public
    class function IsSupported: Boolean; static;
    constructor Create();
    destructor Destroy(); override;
    procedure Init(AForEncryption: Boolean; const AParameters: ICipherParameters);
    function GetBlockSize(): Int32;
    function ProcessBlock(const AInput: TCryptoLibByteArray; AInOff: Int32;
      const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32; overload;
    function ProcessBlock(AInput, AOutput: PByte): Int32; overload;

    // ===== IBulkBlockCipher =====
    // Generic multi-block fast path exposed as a cipher-agnostic capability
    // to upstream block-cipher modes (CBC / CTR / ECB / GCM non-fused path).
    // The engine owns the 8-then-4-then-1 batch ladder internally; modes no
    // longer need to know about specific batch sizes. Aliasing contract per
    // IBulkBlockCipher: AInput and AOutput MUST be either identical pointers
    // (in-place) or reference fully disjoint ranges. Partial overlap is NOT
    // supported; this is the same contract as the *Fast inner helpers these
    // overloads delegate to.
    function ProcessBlocks(const AInBuf: TCryptoLibByteArray;
      AInOff, ABlockCount: Int32; const AOutBuf: TCryptoLibByteArray;
      AOutOff: Int32): Int32; overload;
    function ProcessBlocks(AInput, AOutput: PByte;
      ABlockCount: Int32): Int32; overload;

    /// <summary>
    /// Internal fast-path accessor for the AES-NI encrypt round-key schedule
    /// used by the AES-NI fused cipher kernels. Returns True (and sets AKeysPtr
    /// to the aligned key-schedule buffer plus ANumRounds to the AES round
    /// count) only when the engine is currently initialized for AES encryption
    /// in any supported key size (AForEncryption=True; ANumRounds in {10, 12,
    /// 14} for AES-128 / AES-192 / AES-256 respectively). Returns False in every
    /// other state (including all decrypt-direction inits). Note: the fused
    /// modes built on this accessor drive AES in encrypt mode for keystream
    /// generation regardless of the AEAD direction, so it rejects decrypt inits;
    /// kernels needing the decrypt schedule use TryGetDecKeysPtr instead.
    /// Callers MUST NOT retain the pointer beyond the lifetime of the current
    /// engine init; reinit / free invalidates it.
    /// </summary>
    function TryGetEncKeysPtr(out AKeysPtr: PByte; out ANumRounds: Int32): Boolean;

    /// <summary>
    /// Decrypt-direction counterpart of TryGetEncKeysPtr. Returns the
    /// inverse-MixColumns schedule when the engine is initialized for
    /// decryption; False otherwise. Same lifetime contract as
    /// TryGetEncKeysPtr.
    /// </summary>
    function TryGetDecKeysPtr(out AKeysPtr: PByte; out ANumRounds: Int32): Boolean;
    property AlgorithmName: String read GetAlgorithmName;
  end;

{$ENDIF}

implementation

{$IFDEF CRYPTOLIB_X86_SIMD}

procedure AesNiExpandRoundKeys128(Key, KeysOut: PByte);
{$DEFINE CRYPTOLIB_AESNI_KEY128}
{$IFDEF CRYPTOLIB_X86_64_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc2Begin_x86_64.inc}
{$I ..\..\Include\Simd\Aes\AesNiExpandRoundKeys_x86_64.inc}
{$ENDIF}
{$IFDEF CRYPTOLIB_I386_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc2Begin_i386.inc}
{$I ..\..\Include\Simd\Aes\AesNiExpandRoundKeys_i386.inc}
{$ENDIF}
{$UNDEF CRYPTOLIB_AESNI_KEY128}
end;

procedure AesNiExpandRoundKeys192(Key, KeysOut: PByte);
{$DEFINE CRYPTOLIB_AESNI_KEY192}
{$IFDEF CRYPTOLIB_X86_64_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc2Begin_x86_64.inc}
{$I ..\..\Include\Simd\Aes\AesNiExpandRoundKeys_x86_64.inc}
{$ENDIF}
{$IFDEF CRYPTOLIB_I386_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc2Begin_i386.inc}
{$I ..\..\Include\Simd\Aes\AesNiExpandRoundKeys_i386.inc}
{$ENDIF}
{$UNDEF CRYPTOLIB_AESNI_KEY192}
end;

procedure AesNiExpandRoundKeys256(Key, KeysOut: PByte);
{$DEFINE CRYPTOLIB_AESNI_KEY256}
{$IFDEF CRYPTOLIB_X86_64_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc2Begin_x86_64.inc}
{$I ..\..\Include\Simd\Aes\AesNiExpandRoundKeys_x86_64.inc}
{$ENDIF}
{$IFDEF CRYPTOLIB_I386_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc2Begin_i386.inc}
{$I ..\..\Include\Simd\Aes\AesNiExpandRoundKeys_i386.inc}
{$ENDIF}
{$UNDEF CRYPTOLIB_AESNI_KEY256}
end;

procedure AesNiPrepareDecryptRoundKeys(Keys: PByte; NRounds: Int32);
{$IFDEF CRYPTOLIB_X86_64_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc2Begin_x86_64.inc}
{$I ..\..\Include\Simd\Aes\AesNiPrepareDecryptRoundKeys_x86_64.inc}
{$ENDIF}
{$IFDEF CRYPTOLIB_I386_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc2Begin_i386.inc}
{$I ..\..\Include\Simd\Aes\AesNiPrepareDecryptRoundKeys_i386.inc}
{$ENDIF}
end;

procedure AesNiOneEnc128(State, Keys: PByte);
{$DEFINE CRYPTOLIB_AESNI_KEY128}
{$IFDEF CRYPTOLIB_X86_64_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc2Begin_x86_64.inc}
{$I ..\..\Include\Simd\Aes\AesNiOneCipher_x86_64.inc}
{$ENDIF}
{$IFDEF CRYPTOLIB_I386_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc2Begin_i386.inc}
{$I ..\..\Include\Simd\Aes\AesNiOneCipher_i386.inc}
{$ENDIF}
{$UNDEF CRYPTOLIB_AESNI_KEY128}
end;

procedure AesNiOneEnc192(State, Keys: PByte);
{$DEFINE CRYPTOLIB_AESNI_KEY192}
{$IFDEF CRYPTOLIB_X86_64_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc2Begin_x86_64.inc}
{$I ..\..\Include\Simd\Aes\AesNiOneCipher_x86_64.inc}
{$ENDIF}
{$IFDEF CRYPTOLIB_I386_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc2Begin_i386.inc}
{$I ..\..\Include\Simd\Aes\AesNiOneCipher_i386.inc}
{$ENDIF}
{$UNDEF CRYPTOLIB_AESNI_KEY192}
end;

procedure AesNiOneEnc256(State, Keys: PByte);
{$DEFINE CRYPTOLIB_AESNI_KEY256}
{$IFDEF CRYPTOLIB_X86_64_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc2Begin_x86_64.inc}
{$I ..\..\Include\Simd\Aes\AesNiOneCipher_x86_64.inc}
{$ENDIF}
{$IFDEF CRYPTOLIB_I386_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc2Begin_i386.inc}
{$I ..\..\Include\Simd\Aes\AesNiOneCipher_i386.inc}
{$ENDIF}
{$UNDEF CRYPTOLIB_AESNI_KEY256}
end;

procedure AesNiOneDec128(State, Keys: PByte);
{$DEFINE CRYPTOLIB_AESNI_KEY128}
{$DEFINE CRYPTOLIB_AESNI_DECRYPT}
{$IFDEF CRYPTOLIB_X86_64_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc2Begin_x86_64.inc}
{$I ..\..\Include\Simd\Aes\AesNiOneCipher_x86_64.inc}
{$ENDIF}
{$IFDEF CRYPTOLIB_I386_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc2Begin_i386.inc}
{$I ..\..\Include\Simd\Aes\AesNiOneCipher_i386.inc}
{$ENDIF}
{$UNDEF CRYPTOLIB_AESNI_DECRYPT}
{$UNDEF CRYPTOLIB_AESNI_KEY128}
end;

procedure AesNiOneDec192(State, Keys: PByte);
{$DEFINE CRYPTOLIB_AESNI_KEY192}
{$DEFINE CRYPTOLIB_AESNI_DECRYPT}
{$IFDEF CRYPTOLIB_X86_64_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc2Begin_x86_64.inc}
{$I ..\..\Include\Simd\Aes\AesNiOneCipher_x86_64.inc}
{$ENDIF}
{$IFDEF CRYPTOLIB_I386_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc2Begin_i386.inc}
{$I ..\..\Include\Simd\Aes\AesNiOneCipher_i386.inc}
{$ENDIF}
{$UNDEF CRYPTOLIB_AESNI_DECRYPT}
{$UNDEF CRYPTOLIB_AESNI_KEY192}
end;

procedure AesNiOneDec256(State, Keys: PByte);
{$DEFINE CRYPTOLIB_AESNI_KEY256}
{$DEFINE CRYPTOLIB_AESNI_DECRYPT}
{$IFDEF CRYPTOLIB_X86_64_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc2Begin_x86_64.inc}
{$I ..\..\Include\Simd\Aes\AesNiOneCipher_x86_64.inc}
{$ENDIF}
{$IFDEF CRYPTOLIB_I386_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc2Begin_i386.inc}
{$I ..\..\Include\Simd\Aes\AesNiOneCipher_i386.inc}
{$ENDIF}
{$UNDEF CRYPTOLIB_AESNI_DECRYPT}
{$UNDEF CRYPTOLIB_AESNI_KEY256}
end;

procedure AesNiFourEnc128(State, Keys: PByte);
{$DEFINE CRYPTOLIB_AESNI_KEY128}
{$IFDEF CRYPTOLIB_X86_64_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc2Begin_x86_64.inc}
{$I ..\..\Include\Simd\Aes\AesNiFourCipher_x86_64.inc}
{$ENDIF}
{$IFDEF CRYPTOLIB_I386_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc2Begin_i386.inc}
{$I ..\..\Include\Simd\Aes\AesNiFourCipher_i386.inc}
{$ENDIF}
{$UNDEF CRYPTOLIB_AESNI_KEY128}
end;

procedure AesNiFourEnc192(State, Keys: PByte);
{$DEFINE CRYPTOLIB_AESNI_KEY192}
{$IFDEF CRYPTOLIB_X86_64_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc2Begin_x86_64.inc}
{$I ..\..\Include\Simd\Aes\AesNiFourCipher_x86_64.inc}
{$ENDIF}
{$IFDEF CRYPTOLIB_I386_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc2Begin_i386.inc}
{$I ..\..\Include\Simd\Aes\AesNiFourCipher_i386.inc}
{$ENDIF}
{$UNDEF CRYPTOLIB_AESNI_KEY192}
end;

procedure AesNiFourEnc256(State, Keys: PByte);
{$DEFINE CRYPTOLIB_AESNI_KEY256}
{$IFDEF CRYPTOLIB_X86_64_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc2Begin_x86_64.inc}
{$I ..\..\Include\Simd\Aes\AesNiFourCipher_x86_64.inc}
{$ENDIF}
{$IFDEF CRYPTOLIB_I386_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc2Begin_i386.inc}
{$I ..\..\Include\Simd\Aes\AesNiFourCipher_i386.inc}
{$ENDIF}
{$UNDEF CRYPTOLIB_AESNI_KEY256}
end;

procedure AesNiFourDec128(State, Keys: PByte);
{$DEFINE CRYPTOLIB_AESNI_KEY128}
{$DEFINE CRYPTOLIB_AESNI_DECRYPT}
{$IFDEF CRYPTOLIB_X86_64_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc2Begin_x86_64.inc}
{$I ..\..\Include\Simd\Aes\AesNiFourCipher_x86_64.inc}
{$ENDIF}
{$IFDEF CRYPTOLIB_I386_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc2Begin_i386.inc}
{$I ..\..\Include\Simd\Aes\AesNiFourCipher_i386.inc}
{$ENDIF}
{$UNDEF CRYPTOLIB_AESNI_DECRYPT}
{$UNDEF CRYPTOLIB_AESNI_KEY128}
end;

procedure AesNiFourDec192(State, Keys: PByte);
{$DEFINE CRYPTOLIB_AESNI_KEY192}
{$DEFINE CRYPTOLIB_AESNI_DECRYPT}
{$IFDEF CRYPTOLIB_X86_64_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc2Begin_x86_64.inc}
{$I ..\..\Include\Simd\Aes\AesNiFourCipher_x86_64.inc}
{$ENDIF}
{$IFDEF CRYPTOLIB_I386_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc2Begin_i386.inc}
{$I ..\..\Include\Simd\Aes\AesNiFourCipher_i386.inc}
{$ENDIF}
{$UNDEF CRYPTOLIB_AESNI_DECRYPT}
{$UNDEF CRYPTOLIB_AESNI_KEY192}
end;

procedure AesNiFourDec256(State, Keys: PByte);
{$DEFINE CRYPTOLIB_AESNI_KEY256}
{$DEFINE CRYPTOLIB_AESNI_DECRYPT}
{$IFDEF CRYPTOLIB_X86_64_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc2Begin_x86_64.inc}
{$I ..\..\Include\Simd\Aes\AesNiFourCipher_x86_64.inc}
{$ENDIF}
{$IFDEF CRYPTOLIB_I386_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc2Begin_i386.inc}
{$I ..\..\Include\Simd\Aes\AesNiFourCipher_i386.inc}
{$ENDIF}
{$UNDEF CRYPTOLIB_AESNI_DECRYPT}
{$UNDEF CRYPTOLIB_AESNI_KEY256}
end;

procedure AesNiEightEnc128(State, Keys: PByte);
{$DEFINE CRYPTOLIB_AESNI_KEY128}
{$IFDEF CRYPTOLIB_X86_64_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc2Begin_x86_64.inc}
{$I ..\..\Include\Simd\Aes\AesNiEightCipher_x86_64.inc}
{$ENDIF}
{$IFDEF CRYPTOLIB_I386_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc2Begin_i386.inc}
{$I ..\..\Include\Simd\Aes\AesNiEightCipher_i386.inc}
{$ENDIF}
{$UNDEF CRYPTOLIB_AESNI_KEY128}
end;

procedure AesNiEightEnc192(State, Keys: PByte);
{$DEFINE CRYPTOLIB_AESNI_KEY192}
{$IFDEF CRYPTOLIB_X86_64_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc2Begin_x86_64.inc}
{$I ..\..\Include\Simd\Aes\AesNiEightCipher_x86_64.inc}
{$ENDIF}
{$IFDEF CRYPTOLIB_I386_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc2Begin_i386.inc}
{$I ..\..\Include\Simd\Aes\AesNiEightCipher_i386.inc}
{$ENDIF}
{$UNDEF CRYPTOLIB_AESNI_KEY192}
end;

procedure AesNiEightEnc256(State, Keys: PByte);
{$DEFINE CRYPTOLIB_AESNI_KEY256}
{$IFDEF CRYPTOLIB_X86_64_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc2Begin_x86_64.inc}
{$I ..\..\Include\Simd\Aes\AesNiEightCipher_x86_64.inc}
{$ENDIF}
{$IFDEF CRYPTOLIB_I386_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc2Begin_i386.inc}
{$I ..\..\Include\Simd\Aes\AesNiEightCipher_i386.inc}
{$ENDIF}
{$UNDEF CRYPTOLIB_AESNI_KEY256}
end;

procedure AesNiEightDec128(State, Keys: PByte);
{$DEFINE CRYPTOLIB_AESNI_KEY128}
{$DEFINE CRYPTOLIB_AESNI_DECRYPT}
{$IFDEF CRYPTOLIB_X86_64_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc2Begin_x86_64.inc}
{$I ..\..\Include\Simd\Aes\AesNiEightCipher_x86_64.inc}
{$ENDIF}
{$IFDEF CRYPTOLIB_I386_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc2Begin_i386.inc}
{$I ..\..\Include\Simd\Aes\AesNiEightCipher_i386.inc}
{$ENDIF}
{$UNDEF CRYPTOLIB_AESNI_DECRYPT}
{$UNDEF CRYPTOLIB_AESNI_KEY128}
end;

procedure AesNiEightDec192(State, Keys: PByte);
{$DEFINE CRYPTOLIB_AESNI_KEY192}
{$DEFINE CRYPTOLIB_AESNI_DECRYPT}
{$IFDEF CRYPTOLIB_X86_64_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc2Begin_x86_64.inc}
{$I ..\..\Include\Simd\Aes\AesNiEightCipher_x86_64.inc}
{$ENDIF}
{$IFDEF CRYPTOLIB_I386_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc2Begin_i386.inc}
{$I ..\..\Include\Simd\Aes\AesNiEightCipher_i386.inc}
{$ENDIF}
{$UNDEF CRYPTOLIB_AESNI_DECRYPT}
{$UNDEF CRYPTOLIB_AESNI_KEY192}
end;

procedure AesNiEightDec256(State, Keys: PByte);
{$DEFINE CRYPTOLIB_AESNI_KEY256}
{$DEFINE CRYPTOLIB_AESNI_DECRYPT}
{$IFDEF CRYPTOLIB_X86_64_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc2Begin_x86_64.inc}
{$I ..\..\Include\Simd\Aes\AesNiEightCipher_x86_64.inc}
{$ENDIF}
{$IFDEF CRYPTOLIB_I386_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc2Begin_i386.inc}
{$I ..\..\Include\Simd\Aes\AesNiEightCipher_i386.inc}
{$ENDIF}
{$UNDEF CRYPTOLIB_AESNI_DECRYPT}
{$UNDEF CRYPTOLIB_AESNI_KEY256}
end;

procedure AesNiOneEnc128InOut(RIn, ROut, Keys: PByte);
{$DEFINE CRYPTOLIB_AESNI_KEY128}
{$DEFINE CRYPTOLIB_AESNI_INOUT}
{$IFDEF CRYPTOLIB_X86_64_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc3Begin_x86_64.inc}
{$I ..\..\Include\Simd\Aes\AesNiOneCipher_x86_64.inc}
{$ENDIF}
{$IFDEF CRYPTOLIB_I386_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc3Begin_i386.inc}
{$I ..\..\Include\Simd\Aes\AesNiOneCipher_i386.inc}
{$ENDIF}
{$UNDEF CRYPTOLIB_AESNI_INOUT}
{$UNDEF CRYPTOLIB_AESNI_KEY128}
end;

procedure AesNiOneEnc192InOut(RIn, ROut, Keys: PByte);
{$DEFINE CRYPTOLIB_AESNI_KEY192}
{$DEFINE CRYPTOLIB_AESNI_INOUT}
{$IFDEF CRYPTOLIB_X86_64_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc3Begin_x86_64.inc}
{$I ..\..\Include\Simd\Aes\AesNiOneCipher_x86_64.inc}
{$ENDIF}
{$IFDEF CRYPTOLIB_I386_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc3Begin_i386.inc}
{$I ..\..\Include\Simd\Aes\AesNiOneCipher_i386.inc}
{$ENDIF}
{$UNDEF CRYPTOLIB_AESNI_INOUT}
{$UNDEF CRYPTOLIB_AESNI_KEY192}
end;

procedure AesNiOneEnc256InOut(RIn, ROut, Keys: PByte);
{$DEFINE CRYPTOLIB_AESNI_KEY256}
{$DEFINE CRYPTOLIB_AESNI_INOUT}
{$IFDEF CRYPTOLIB_X86_64_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc3Begin_x86_64.inc}
{$I ..\..\Include\Simd\Aes\AesNiOneCipher_x86_64.inc}
{$ENDIF}
{$IFDEF CRYPTOLIB_I386_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc3Begin_i386.inc}
{$I ..\..\Include\Simd\Aes\AesNiOneCipher_i386.inc}
{$ENDIF}
{$UNDEF CRYPTOLIB_AESNI_INOUT}
{$UNDEF CRYPTOLIB_AESNI_KEY256}
end;

procedure AesNiOneDec128InOut(RIn, ROut, Keys: PByte);
{$DEFINE CRYPTOLIB_AESNI_KEY128}
{$DEFINE CRYPTOLIB_AESNI_INOUT}
{$DEFINE CRYPTOLIB_AESNI_DECRYPT}
{$IFDEF CRYPTOLIB_X86_64_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc3Begin_x86_64.inc}
{$I ..\..\Include\Simd\Aes\AesNiOneCipher_x86_64.inc}
{$ENDIF}
{$IFDEF CRYPTOLIB_I386_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc3Begin_i386.inc}
{$I ..\..\Include\Simd\Aes\AesNiOneCipher_i386.inc}
{$ENDIF}
{$UNDEF CRYPTOLIB_AESNI_DECRYPT}
{$UNDEF CRYPTOLIB_AESNI_INOUT}
{$UNDEF CRYPTOLIB_AESNI_KEY128}
end;

procedure AesNiOneDec192InOut(RIn, ROut, Keys: PByte);
{$DEFINE CRYPTOLIB_AESNI_KEY192}
{$DEFINE CRYPTOLIB_AESNI_INOUT}
{$DEFINE CRYPTOLIB_AESNI_DECRYPT}
{$IFDEF CRYPTOLIB_X86_64_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc3Begin_x86_64.inc}
{$I ..\..\Include\Simd\Aes\AesNiOneCipher_x86_64.inc}
{$ENDIF}
{$IFDEF CRYPTOLIB_I386_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc3Begin_i386.inc}
{$I ..\..\Include\Simd\Aes\AesNiOneCipher_i386.inc}
{$ENDIF}
{$UNDEF CRYPTOLIB_AESNI_DECRYPT}
{$UNDEF CRYPTOLIB_AESNI_INOUT}
{$UNDEF CRYPTOLIB_AESNI_KEY192}
end;

procedure AesNiOneDec256InOut(RIn, ROut, Keys: PByte);
{$DEFINE CRYPTOLIB_AESNI_KEY256}
{$DEFINE CRYPTOLIB_AESNI_INOUT}
{$DEFINE CRYPTOLIB_AESNI_DECRYPT}
{$IFDEF CRYPTOLIB_X86_64_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc3Begin_x86_64.inc}
{$I ..\..\Include\Simd\Aes\AesNiOneCipher_x86_64.inc}
{$ENDIF}
{$IFDEF CRYPTOLIB_I386_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc3Begin_i386.inc}
{$I ..\..\Include\Simd\Aes\AesNiOneCipher_i386.inc}
{$ENDIF}
{$UNDEF CRYPTOLIB_AESNI_DECRYPT}
{$UNDEF CRYPTOLIB_AESNI_INOUT}
{$UNDEF CRYPTOLIB_AESNI_KEY256}
end;

procedure AesNiFourEnc128InOut(RIn, ROut, Keys: PByte);
{$DEFINE CRYPTOLIB_AESNI_KEY128}
{$DEFINE CRYPTOLIB_AESNI_INOUT}
{$IFDEF CRYPTOLIB_X86_64_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc3Begin_x86_64.inc}
{$I ..\..\Include\Simd\Aes\AesNiFourCipher_x86_64.inc}
{$ENDIF}
{$IFDEF CRYPTOLIB_I386_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc3Begin_i386.inc}
{$I ..\..\Include\Simd\Aes\AesNiFourCipher_i386.inc}
{$ENDIF}
{$UNDEF CRYPTOLIB_AESNI_INOUT}
{$UNDEF CRYPTOLIB_AESNI_KEY128}
end;

procedure AesNiFourEnc192InOut(RIn, ROut, Keys: PByte);
{$DEFINE CRYPTOLIB_AESNI_KEY192}
{$DEFINE CRYPTOLIB_AESNI_INOUT}
{$IFDEF CRYPTOLIB_X86_64_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc3Begin_x86_64.inc}
{$I ..\..\Include\Simd\Aes\AesNiFourCipher_x86_64.inc}
{$ENDIF}
{$IFDEF CRYPTOLIB_I386_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc3Begin_i386.inc}
{$I ..\..\Include\Simd\Aes\AesNiFourCipher_i386.inc}
{$ENDIF}
{$UNDEF CRYPTOLIB_AESNI_INOUT}
{$UNDEF CRYPTOLIB_AESNI_KEY192}
end;

procedure AesNiFourEnc256InOut(RIn, ROut, Keys: PByte);
{$DEFINE CRYPTOLIB_AESNI_KEY256}
{$DEFINE CRYPTOLIB_AESNI_INOUT}
{$IFDEF CRYPTOLIB_X86_64_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc3Begin_x86_64.inc}
{$I ..\..\Include\Simd\Aes\AesNiFourCipher_x86_64.inc}
{$ENDIF}
{$IFDEF CRYPTOLIB_I386_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc3Begin_i386.inc}
{$I ..\..\Include\Simd\Aes\AesNiFourCipher_i386.inc}
{$ENDIF}
{$UNDEF CRYPTOLIB_AESNI_INOUT}
{$UNDEF CRYPTOLIB_AESNI_KEY256}
end;

procedure AesNiFourDec128InOut(RIn, ROut, Keys: PByte);
{$DEFINE CRYPTOLIB_AESNI_KEY128}
{$DEFINE CRYPTOLIB_AESNI_INOUT}
{$DEFINE CRYPTOLIB_AESNI_DECRYPT}
{$IFDEF CRYPTOLIB_X86_64_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc3Begin_x86_64.inc}
{$I ..\..\Include\Simd\Aes\AesNiFourCipher_x86_64.inc}
{$ENDIF}
{$IFDEF CRYPTOLIB_I386_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc3Begin_i386.inc}
{$I ..\..\Include\Simd\Aes\AesNiFourCipher_i386.inc}
{$ENDIF}
{$UNDEF CRYPTOLIB_AESNI_DECRYPT}
{$UNDEF CRYPTOLIB_AESNI_INOUT}
{$UNDEF CRYPTOLIB_AESNI_KEY128}
end;

procedure AesNiFourDec192InOut(RIn, ROut, Keys: PByte);
{$DEFINE CRYPTOLIB_AESNI_KEY192}
{$DEFINE CRYPTOLIB_AESNI_INOUT}
{$DEFINE CRYPTOLIB_AESNI_DECRYPT}
{$IFDEF CRYPTOLIB_X86_64_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc3Begin_x86_64.inc}
{$I ..\..\Include\Simd\Aes\AesNiFourCipher_x86_64.inc}
{$ENDIF}
{$IFDEF CRYPTOLIB_I386_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc3Begin_i386.inc}
{$I ..\..\Include\Simd\Aes\AesNiFourCipher_i386.inc}
{$ENDIF}
{$UNDEF CRYPTOLIB_AESNI_DECRYPT}
{$UNDEF CRYPTOLIB_AESNI_INOUT}
{$UNDEF CRYPTOLIB_AESNI_KEY192}
end;

procedure AesNiFourDec256InOut(RIn, ROut, Keys: PByte);
{$DEFINE CRYPTOLIB_AESNI_KEY256}
{$DEFINE CRYPTOLIB_AESNI_INOUT}
{$DEFINE CRYPTOLIB_AESNI_DECRYPT}
{$IFDEF CRYPTOLIB_X86_64_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc3Begin_x86_64.inc}
{$I ..\..\Include\Simd\Aes\AesNiFourCipher_x86_64.inc}
{$ENDIF}
{$IFDEF CRYPTOLIB_I386_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc3Begin_i386.inc}
{$I ..\..\Include\Simd\Aes\AesNiFourCipher_i386.inc}
{$ENDIF}
{$UNDEF CRYPTOLIB_AESNI_DECRYPT}
{$UNDEF CRYPTOLIB_AESNI_INOUT}
{$UNDEF CRYPTOLIB_AESNI_KEY256}
end;

procedure AesNiEightEnc128InOut(RIn, ROut, Keys: PByte);
{$DEFINE CRYPTOLIB_AESNI_KEY128}
{$DEFINE CRYPTOLIB_AESNI_INOUT}
{$IFDEF CRYPTOLIB_X86_64_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc3Begin_x86_64.inc}
{$I ..\..\Include\Simd\Aes\AesNiEightCipher_x86_64.inc}
{$ENDIF}
{$IFDEF CRYPTOLIB_I386_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc3Begin_i386.inc}
{$I ..\..\Include\Simd\Aes\AesNiEightCipher_i386.inc}
{$ENDIF}
{$UNDEF CRYPTOLIB_AESNI_INOUT}
{$UNDEF CRYPTOLIB_AESNI_KEY128}
end;

procedure AesNiEightEnc192InOut(RIn, ROut, Keys: PByte);
{$DEFINE CRYPTOLIB_AESNI_KEY192}
{$DEFINE CRYPTOLIB_AESNI_INOUT}
{$IFDEF CRYPTOLIB_X86_64_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc3Begin_x86_64.inc}
{$I ..\..\Include\Simd\Aes\AesNiEightCipher_x86_64.inc}
{$ENDIF}
{$IFDEF CRYPTOLIB_I386_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc3Begin_i386.inc}
{$I ..\..\Include\Simd\Aes\AesNiEightCipher_i386.inc}
{$ENDIF}
{$UNDEF CRYPTOLIB_AESNI_INOUT}
{$UNDEF CRYPTOLIB_AESNI_KEY192}
end;

procedure AesNiEightEnc256InOut(RIn, ROut, Keys: PByte);
{$DEFINE CRYPTOLIB_AESNI_KEY256}
{$DEFINE CRYPTOLIB_AESNI_INOUT}
{$IFDEF CRYPTOLIB_X86_64_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc3Begin_x86_64.inc}
{$I ..\..\Include\Simd\Aes\AesNiEightCipher_x86_64.inc}
{$ENDIF}
{$IFDEF CRYPTOLIB_I386_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc3Begin_i386.inc}
{$I ..\..\Include\Simd\Aes\AesNiEightCipher_i386.inc}
{$ENDIF}
{$UNDEF CRYPTOLIB_AESNI_INOUT}
{$UNDEF CRYPTOLIB_AESNI_KEY256}
end;

procedure AesNiEightDec128InOut(RIn, ROut, Keys: PByte);
{$DEFINE CRYPTOLIB_AESNI_KEY128}
{$DEFINE CRYPTOLIB_AESNI_INOUT}
{$DEFINE CRYPTOLIB_AESNI_DECRYPT}
{$IFDEF CRYPTOLIB_X86_64_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc3Begin_x86_64.inc}
{$I ..\..\Include\Simd\Aes\AesNiEightCipher_x86_64.inc}
{$ENDIF}
{$IFDEF CRYPTOLIB_I386_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc3Begin_i386.inc}
{$I ..\..\Include\Simd\Aes\AesNiEightCipher_i386.inc}
{$ENDIF}
{$UNDEF CRYPTOLIB_AESNI_DECRYPT}
{$UNDEF CRYPTOLIB_AESNI_INOUT}
{$UNDEF CRYPTOLIB_AESNI_KEY128}
end;

procedure AesNiEightDec192InOut(RIn, ROut, Keys: PByte);
{$DEFINE CRYPTOLIB_AESNI_KEY192}
{$DEFINE CRYPTOLIB_AESNI_INOUT}
{$DEFINE CRYPTOLIB_AESNI_DECRYPT}
{$IFDEF CRYPTOLIB_X86_64_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc3Begin_x86_64.inc}
{$I ..\..\Include\Simd\Aes\AesNiEightCipher_x86_64.inc}
{$ENDIF}
{$IFDEF CRYPTOLIB_I386_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc3Begin_i386.inc}
{$I ..\..\Include\Simd\Aes\AesNiEightCipher_i386.inc}
{$ENDIF}
{$UNDEF CRYPTOLIB_AESNI_DECRYPT}
{$UNDEF CRYPTOLIB_AESNI_INOUT}
{$UNDEF CRYPTOLIB_AESNI_KEY192}
end;

procedure AesNiEightDec256InOut(RIn, ROut, Keys: PByte);
{$DEFINE CRYPTOLIB_AESNI_KEY256}
{$DEFINE CRYPTOLIB_AESNI_INOUT}
{$DEFINE CRYPTOLIB_AESNI_DECRYPT}
{$IFDEF CRYPTOLIB_X86_64_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc3Begin_x86_64.inc}
{$I ..\..\Include\Simd\Aes\AesNiEightCipher_x86_64.inc}
{$ENDIF}
{$IFDEF CRYPTOLIB_I386_ASM}
{$I ..\..\Include\Simd\Common\ClpSimdProc3Begin_i386.inc}
{$I ..\..\Include\Simd\Aes\AesNiEightCipher_i386.inc}
{$ENDIF}
{$UNDEF CRYPTOLIB_AESNI_DECRYPT}
{$UNDEF CRYPTOLIB_AESNI_INOUT}
{$UNDEF CRYPTOLIB_AESNI_KEY256}
end;

{ TAesEngineX86 }

// =====================================================================
// Feature detection and lifecycle (class-level + constructor / destructor).
// =====================================================================

class function TAesEngineX86.IsSupported: Boolean;
begin
  Result := TCpuFeatures.X86.HasAESNI();
end;

constructor TAesEngineX86.Create();
begin
  inherited Create();
  if not IsSupported then
    raise EInvalidOperationCryptoLibException.CreateRes(@SAesEngineX86NotSupported);
  FRawAlloc := nil;
  FKeys := nil;
  FNRounds := 0;
  FMode := TAesX86Mode.Uninitialized;
  FAesNiCipherOne := nil;
  FAesNiCipherFour := nil;
  FAesNiCipherEight := nil;
  FAesNiCipherOneInOut := nil;
  FAesNiCipherFourInOut := nil;
  FAesNiCipherEightInOut := nil;
end;

destructor TAesEngineX86.Destroy();
begin
  FreeAlignedKeys;
  inherited;
end;

// =====================================================================
// 16-byte aligned round-key buffer management. AES-NI loads expect the
// key schedule at a 16-byte aligned address; we over-allocate by 16
// bytes and align the usable pointer.
// =====================================================================

procedure TAesEngineX86.FreeAlignedKeys;
var
  LKeyBytes: Int32;
begin
  if FRawAlloc <> nil then
  begin
    if (FKeys <> nil) and (FNRounds > 0) then
    begin
      LKeyBytes := (FNRounds + 1) * 16;
      FillChar(FKeys^, LKeyBytes, 0);
    end;
    FreeMem(FRawAlloc);
  end;
  FRawAlloc := nil;
  FKeys := nil;
  FNRounds := 0;
  FMode := TAesX86Mode.Uninitialized;
  FAesNiCipherOne := nil;
  FAesNiCipherFour := nil;
  FAesNiCipherEight := nil;
  FAesNiCipherOneInOut := nil;
  FAesNiCipherFourInOut := nil;
  FAesNiCipherEightInOut := nil;
end;

procedure TAesEngineX86.AllocAlignedKeys(AKeyBytes: Int32);
var
  LPtr: NativeUInt;
begin
  FreeAlignedKeys;
  if AKeyBytes <= 0 then
    Exit;
  GetMem(FRawAlloc, NativeUInt(AKeyBytes) + 16);
  LPtr := NativeUInt(FRawAlloc);
  LPtr := (LPtr + 15) and not NativeUInt(15);
  FKeys := PByte(LPtr);
  FillChar(FKeys^, AKeyBytes, 0);
end;

// =====================================================================
// Simple IBlockCipher descriptors.
// =====================================================================

function TAesEngineX86.GetAlgorithmName: String;
begin
  Result := 'AES';
end;

function TAesEngineX86.GetBlockSize(): Int32;
begin
  Result := 16;
end;

// =====================================================================
// Round-key schedule setup (encrypt expansion + decrypt InvMixColumns)
// and per-mode function-pointer binding. These three procedures form the
// rekey / direction-change contract used by Init.
// =====================================================================

procedure TAesEngineX86.CreateRoundKeys(AForEncryption: Boolean;
  const AKey: TCryptoLibByteArray);
var
  LK: PByte;
  LKeyLen: Int32;
begin
  LKeyLen := System.Length(AKey);
  if ((LKeyLen < 16) or (LKeyLen > 32) or ((LKeyLen and 7) <> 0)) then
  begin
    TArrayUtilities.Fill(AKey, 0, LKeyLen, Byte(0));
    raise EArgumentCryptoLibException.CreateRes(@SInvalidKeyLength);
  end;

  LK := FKeys;

  case LKeyLen of
    16:
      begin
        FNRounds := 10;
        AesNiExpandRoundKeys128(@AKey[0], LK);
      end;
    24:
      begin
        FNRounds := 12;
        AesNiExpandRoundKeys192(@AKey[0], LK);
      end;
    32:
      begin
        FNRounds := 14;
        AesNiExpandRoundKeys256(@AKey[0], LK);
      end;
  else
    TArrayUtilities.Fill(AKey, 0, LKeyLen, Byte(0));
    raise EArgumentCryptoLibException.CreateRes(@SInvalidKeyLength);
  end;

  if not AForEncryption then
    PrepareDecryptRoundKeys;
end;

procedure TAesEngineX86.PrepareDecryptRoundKeys;
begin
  AesNiPrepareDecryptRoundKeys(FKeys, FNRounds);
end;

procedure TAesEngineX86.BindCipherPointers;
begin
  FAesNiCipherOne := nil;
  FAesNiCipherFour := nil;
  FAesNiCipherEight := nil;
  FAesNiCipherOneInOut := nil;
  FAesNiCipherFourInOut := nil;
  FAesNiCipherEightInOut := nil;

  case FMode of
    TAesX86Mode.Enc128:
      begin
        FAesNiCipherOne := @AesNiOneEnc128;
        FAesNiCipherFour := @AesNiFourEnc128;
        FAesNiCipherOneInOut := @AesNiOneEnc128InOut;
        FAesNiCipherFourInOut := @AesNiFourEnc128InOut;
        FAesNiCipherEight := @AesNiEightEnc128;
        FAesNiCipherEightInOut := @AesNiEightEnc128InOut;
      end;
    TAesX86Mode.Enc192:
      begin
        FAesNiCipherOne := @AesNiOneEnc192;
        FAesNiCipherFour := @AesNiFourEnc192;
        FAesNiCipherOneInOut := @AesNiOneEnc192InOut;
        FAesNiCipherFourInOut := @AesNiFourEnc192InOut;
        FAesNiCipherEight := @AesNiEightEnc192;
        FAesNiCipherEightInOut := @AesNiEightEnc192InOut;
      end;
    TAesX86Mode.Enc256:
      begin
        FAesNiCipherOne := @AesNiOneEnc256;
        FAesNiCipherFour := @AesNiFourEnc256;
        FAesNiCipherOneInOut := @AesNiOneEnc256InOut;
        FAesNiCipherFourInOut := @AesNiFourEnc256InOut;
        FAesNiCipherEight := @AesNiEightEnc256;
        FAesNiCipherEightInOut := @AesNiEightEnc256InOut;
      end;
    TAesX86Mode.Dec128:
      begin
        FAesNiCipherOne := @AesNiOneDec128;
        FAesNiCipherFour := @AesNiFourDec128;
        FAesNiCipherOneInOut := @AesNiOneDec128InOut;
        FAesNiCipherFourInOut := @AesNiFourDec128InOut;
        FAesNiCipherEight := @AesNiEightDec128;
        FAesNiCipherEightInOut := @AesNiEightDec128InOut;
      end;
    TAesX86Mode.Dec192:
      begin
        FAesNiCipherOne := @AesNiOneDec192;
        FAesNiCipherFour := @AesNiFourDec192;
        FAesNiCipherOneInOut := @AesNiOneDec192InOut;
        FAesNiCipherFourInOut := @AesNiFourDec192InOut;
        FAesNiCipherEight := @AesNiEightDec192;
        FAesNiCipherEightInOut := @AesNiEightDec192InOut;
      end;
    TAesX86Mode.Dec256:
      begin
        FAesNiCipherOne := @AesNiOneDec256;
        FAesNiCipherFour := @AesNiFourDec256;
        FAesNiCipherOneInOut := @AesNiOneDec256InOut;
        FAesNiCipherFourInOut := @AesNiFourDec256InOut;
        FAesNiCipherEight := @AesNiEightDec256;
        FAesNiCipherEightInOut := @AesNiEightDec256InOut;
      end;
  else
    // stay nil
  end;
end;

// =====================================================================
// Per-call Init (validate parameters, rekey, bind fast-path pointers).
// =====================================================================

procedure TAesEngineX86.Init(AForEncryption: Boolean;
  const AParameters: ICipherParameters);
var
  LKeyParameter: IKeyParameter;
  LKeyCopy: TCryptoLibByteArray;
  LKeyLen: Int32;
begin
  if not Supports(AParameters, IKeyParameter, LKeyParameter) then
    raise EArgumentCryptoLibException.CreateResFmt(@SInvalidParameterAESX86Init,
      [TPlatformUtilities.GetTypeName(AParameters as TObject)]);

  LKeyCopy := System.Copy(LKeyParameter.GetKey());
  try
    LKeyLen := System.Length(LKeyCopy);
    if not (LKeyLen in [16, 24, 32]) then
      raise EArgumentCryptoLibException.CreateRes(@SInvalidKeyLength);

    AllocAlignedKeys((TBitOperations.Asr32(LKeyLen, 2) + 6 + 1) * 16);

    case LKeyLen of
      16:
        if AForEncryption then
          FMode := TAesX86Mode.Enc128
        else
          FMode := TAesX86Mode.Dec128;
      24:
        if AForEncryption then
          FMode := TAesX86Mode.Enc192
        else
          FMode := TAesX86Mode.Dec192;
      32:
        if AForEncryption then
          FMode := TAesX86Mode.Enc256
        else
          FMode := TAesX86Mode.Dec256;
    end;

    CreateRoundKeys(AForEncryption, LKeyCopy);
    BindCipherPointers;
  finally
    TArrayUtilities.Fill(LKeyCopy, 0, System.Length(LKeyCopy), Byte(0));
  end;
end;

// =====================================================================
// Public block processing - array overloads (safety-checked, nil-safe).
// These perform TCheck validation then delegate to the pointer overloads.
// =====================================================================

function TAesEngineX86.ProcessBlock(const AInput: TCryptoLibByteArray;
  AInOff: Int32; const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32;
begin
  if FKeys = nil then
    raise EInvalidOperationCryptoLibException.CreateRes(@SAesEngineX86NotInitialised);

  TCheck.DataLength(AInput, AInOff, 16, SInputBufferTooShort);
  TCheck.OutputLength(AOutput, AOutOff, 16, SOutputBufferTooShort);

  Result := ProcessBlock(@AInput[AInOff], @AOutput[AOutOff]);
end;

// =====================================================================
// Pointer-overload single-block processing - defense-in-depth version
// that guards against overlapping in/out ranges by staging through a
// stack buffer, plus nil-pointer and binding checks.
// =====================================================================

function TAesEngineX86.ProcessBlock(AInput, AOutput: PByte): Int32;
var
  LBuf: array [0 .. 15] of Byte;
begin
  if FKeys = nil then
    raise EInvalidOperationCryptoLibException.CreateRes(@SAesEngineX86NotInitialised);
  if (AInput = nil) or (AOutput = nil) then
    raise EArgumentCryptoLibException.CreateRes(@SNilPointerBuffer);

  if not Assigned(FAesNiCipherOne) or not Assigned(FAesNiCipherOneInOut) then
    raise EInvalidOperationCryptoLibException.CreateRes(@SAesEngineX86NotInitialised);

  if AInput = AOutput then
  begin
    FAesNiCipherOne(AOutput, FKeys);
    Result := 16;
    Exit;
  end;

  if ((AOutput >= AInput) and (AOutput < AInput + 16)) or
    ((AInput >= AOutput) and (AInput < AOutput + 16)) then
  begin
    System.Move(AInput^, LBuf[0], 16);
    FAesNiCipherOne(@LBuf[0], FKeys);
    System.Move(LBuf[0], AOutput^, 16);
    FillChar(LBuf, SizeOf(LBuf), 0);
  end
  else
    FAesNiCipherOneInOut(AInput, AOutput, FKeys);
  Result := 16;
end;

// =====================================================================
// "Fast" pointer overloads - no validation, no overlap staging. Only
// callable from code paths that have already proven their preconditions
// (disjoint buffers, non-nil pointers, engine initialized). These are
// used by the inner GCM pipeline loops, where the per-iteration checks
// would otherwise be hot-path overhead.
// =====================================================================

function TAesEngineX86.ProcessFourBlocksFast(AInput, AOutput: PByte): Int32;
begin
  if AInput = AOutput then
    FAesNiCipherFour(AOutput, FKeys)
  else
    FAesNiCipherFourInOut(AInput, AOutput, FKeys);
  Result := 64;
end;

function TAesEngineX86.ProcessEightBlocksFast(AInput, AOutput: PByte): Int32;
begin
  if AInput = AOutput then
    FAesNiCipherEight(AOutput, FKeys)
  else
    FAesNiCipherEightInOut(AInput, AOutput, FKeys);
  Result := 128;
end;

// =====================================================================
// IBulkBlockCipher implementation. Engine-owned 8-then-4-then-1 ladder
// over the existing *Fast inner helpers. Array overload validates then
// delegates to the PByte overload. The aliasing contract is the same as
// the *Fast helpers: AInput / AOutput MUST be identical or fully
// disjoint. The checks on FKeys / FAesNiCipher* assignment live in
// ProcessBlock for the 1-wide tail and are paid once per batch at most.
// =====================================================================

function TAesEngineX86.ProcessBlocks(const AInBuf: TCryptoLibByteArray;
  AInOff, ABlockCount: Int32; const AOutBuf: TCryptoLibByteArray;
  AOutOff: Int32): Int32;
var
  LBytes: Int32;
begin
  if ABlockCount <= 0 then
  begin
    Result := 0;
    Exit;
  end;

  if FKeys = nil then
    raise EInvalidOperationCryptoLibException.CreateRes(@SAesEngineX86NotInitialised);

  LBytes := ABlockCount * 16;
  TCheck.DataLength(AInBuf, AInOff, LBytes, SInputBufferTooShort);
  TCheck.OutputLength(AOutBuf, AOutOff, LBytes, SOutputBufferTooShort);

  Result := ProcessBlocks(@AInBuf[AInOff], @AOutBuf[AOutOff], ABlockCount);
end;

function TAesEngineX86.ProcessBlocks(AInput, AOutput: PByte;
  ABlockCount: Int32): Int32;
var
  LBytes: Int32;
begin
  if ABlockCount <= 0 then
  begin
    Result := 0;
    Exit;
  end;
  LBytes := ABlockCount * 16;
  while ABlockCount >= 8 do
  begin
    ProcessEightBlocksFast(AInput, AOutput);
    System.Inc(AInput, 128);
    System.Inc(AOutput, 128);
    System.Dec(ABlockCount, 8);
  end;
  if ABlockCount >= 4 then
  begin
    ProcessFourBlocksFast(AInput, AOutput);
    System.Inc(AInput, 64);
    System.Inc(AOutput, 64);
    System.Dec(ABlockCount, 4);
  end;
  while ABlockCount > 0 do
  begin
    ProcessBlock(AInput, AOutput);
    System.Inc(AInput, 16);
    System.Inc(AOutput, 16);
    System.Dec(ABlockCount);
  end;
  Result := LBytes;
end;

// =====================================================================
// Key-schedule accessors used by the AES-NI fused cipher kernels. Return a
// pointer to the round-key schedule only when the engine is in the requested
// direction with a matching round count.
// =====================================================================

function TAesEngineX86.TryGetEncKeysPtr(out AKeysPtr: PByte; out ANumRounds: Int32): Boolean;
begin
  AKeysPtr := nil;
  ANumRounds := 0;
  if FKeys = nil then
  begin
    Result := False;
    Exit;
  end;
  case FMode of
    TAesX86Mode.Enc128:
      if FNRounds <> 10 then begin Result := False; Exit; end;
    TAesX86Mode.Enc192:
      if FNRounds <> 12 then begin Result := False; Exit; end;
    TAesX86Mode.Enc256:
      if FNRounds <> 14 then begin Result := False; Exit; end;
  else
    Result := False;
    Exit;
  end;
  AKeysPtr := FKeys;
  ANumRounds := FNRounds;
  Result := True;
end;

function TAesEngineX86.TryGetDecKeysPtr(out AKeysPtr: PByte; out ANumRounds: Int32): Boolean;
begin
  AKeysPtr := nil;
  ANumRounds := 0;
  if FKeys = nil then
  begin
    Result := False;
    Exit;
  end;
  case FMode of
    TAesX86Mode.Dec128:
      if FNRounds <> 10 then begin Result := False; Exit; end;
    TAesX86Mode.Dec192:
      if FNRounds <> 12 then begin Result := False; Exit; end;
    TAesX86Mode.Dec256:
      if FNRounds <> 14 then begin Result := False; Exit; end;
  else
    Result := False;
    Exit;
  end;
  AKeysPtr := FKeys;
  ANumRounds := FNRounds;
  Result := True;
end;

{$ENDIF}

end.
