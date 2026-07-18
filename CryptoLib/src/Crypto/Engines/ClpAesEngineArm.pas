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

unit ClpAesEngineArm;

{$I ..\..\Include\CryptoLib.inc}

interface

{$IFDEF CRYPTOLIB_AARCH64_ASM}

uses
  SysUtils,
  ClpIAesEngineArm,
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
  SAesEngineArmNotSupported = 'AES hardware engine not supported on this platform';
  SInvalidParameterAESArmInit = 'invalid parameter passed to AES init: %s';
  SInvalidKeyLength = 'key length not 128/192/256 bits';
  SAesEngineArmNotInitialised = 'AES engine not initialized';
  SNilPointerBuffer = 'input or output pointer is nil';

type
  /// <summary>
  /// AES using the ARMv8 Crypto Extensions when supported (see
  /// <see cref="IsSupported" />).
  /// </summary>
  TAesEngineArm = class sealed(TInterfacedObject, IAesEngineArm, IAesHardwareEngine,
    IBulkBlockCipher, IBlockCipher)
  strict private
  type
    TAesArmMode = (Uninitialized, Dec128, Dec192, Dec256, Enc128, Enc192, Enc256);
    // RIn = ROut (in-place) or fully disjoint; partial overlap unsupported.
    TAesCryptoExtCipherProc = procedure(RIn, ROut, Keys: PByte);
  strict private
    FMode: TAesArmMode;
    FNRounds: Int32;
    FRawAlloc: Pointer;
    FKeys: PByte;
    FAesCipherOne: TAesCryptoExtCipherProc;
    FAesCipherFour: TAesCryptoExtCipherProc;
    FAesCipherEight: TAesCryptoExtCipherProc;
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
    /// Internal fast-path accessor for the encrypt round-key schedule used by
    /// the fused AES cipher kernels. Returns True (and sets AKeysPtr to the
    /// aligned key-schedule buffer plus ANumRounds to the AES round count)
    /// only when the engine is currently initialized for AES encryption in
    /// any supported key size (AForEncryption=True; ANumRounds in {10, 12,
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

{$IFDEF CRYPTOLIB_AARCH64_ASM}

procedure AesCryptoExtExpandRoundKeys128(Key, KeysOut: PByte);
{$DEFINE CRYPTOLIB_AESCRYPTOEXT_KEY128}
{$I ..\..\Include\Simd\Common\ClpSimdProc2Begin_aarch64.inc}
{$I ..\..\Include\Simd\Aes\AesCryptoExtKeySchedule_aarch64.inc}
{$UNDEF CRYPTOLIB_AESCRYPTOEXT_KEY128}
end;

procedure AesCryptoExtExpandRoundKeys192(Key, KeysOut: PByte);
{$DEFINE CRYPTOLIB_AESCRYPTOEXT_KEY192}
{$I ..\..\Include\Simd\Common\ClpSimdProc2Begin_aarch64.inc}
{$I ..\..\Include\Simd\Aes\AesCryptoExtKeySchedule_aarch64.inc}
{$UNDEF CRYPTOLIB_AESCRYPTOEXT_KEY192}
end;

procedure AesCryptoExtExpandRoundKeys256(Key, KeysOut: PByte);
{$DEFINE CRYPTOLIB_AESCRYPTOEXT_KEY256}
{$I ..\..\Include\Simd\Common\ClpSimdProc2Begin_aarch64.inc}
{$I ..\..\Include\Simd\Aes\AesCryptoExtKeySchedule_aarch64.inc}
{$UNDEF CRYPTOLIB_AESCRYPTOEXT_KEY256}
end;

procedure AesCryptoExtPrepareDecryptRoundKeys(Keys: PByte; NRounds: Int32);
{$DEFINE CRYPTOLIB_AESCRYPTOEXT_KEYSCHEDULE_INVERT}
{$I ..\..\Include\Simd\Common\ClpSimdProc2Begin_aarch64.inc}
{$I ..\..\Include\Simd\Aes\AesCryptoExtKeySchedule_aarch64.inc}
{$UNDEF CRYPTOLIB_AESCRYPTOEXT_KEYSCHEDULE_INVERT}
end;

procedure AesCryptoExtOneEnc128(RIn, ROut, Keys: PByte);
{$DEFINE CRYPTOLIB_AESCRYPTOEXT_ONE}
{$DEFINE CRYPTOLIB_AESCRYPTOEXT_KEY128}
{$I ..\..\Include\Simd\Common\ClpSimdProc3Begin_aarch64.inc}
{$I ..\..\Include\Simd\Aes\AesCryptoExtCipher_aarch64.inc}
{$UNDEF CRYPTOLIB_AESCRYPTOEXT_KEY128}
{$UNDEF CRYPTOLIB_AESCRYPTOEXT_ONE}
end;

procedure AesCryptoExtOneEnc192(RIn, ROut, Keys: PByte);
{$DEFINE CRYPTOLIB_AESCRYPTOEXT_ONE}
{$DEFINE CRYPTOLIB_AESCRYPTOEXT_KEY192}
{$I ..\..\Include\Simd\Common\ClpSimdProc3Begin_aarch64.inc}
{$I ..\..\Include\Simd\Aes\AesCryptoExtCipher_aarch64.inc}
{$UNDEF CRYPTOLIB_AESCRYPTOEXT_KEY192}
{$UNDEF CRYPTOLIB_AESCRYPTOEXT_ONE}
end;

procedure AesCryptoExtOneEnc256(RIn, ROut, Keys: PByte);
{$DEFINE CRYPTOLIB_AESCRYPTOEXT_ONE}
{$DEFINE CRYPTOLIB_AESCRYPTOEXT_KEY256}
{$I ..\..\Include\Simd\Common\ClpSimdProc3Begin_aarch64.inc}
{$I ..\..\Include\Simd\Aes\AesCryptoExtCipher_aarch64.inc}
{$UNDEF CRYPTOLIB_AESCRYPTOEXT_KEY256}
{$UNDEF CRYPTOLIB_AESCRYPTOEXT_ONE}
end;

procedure AesCryptoExtOneDec128(RIn, ROut, Keys: PByte);
{$DEFINE CRYPTOLIB_AESCRYPTOEXT_ONE}
{$DEFINE CRYPTOLIB_AESCRYPTOEXT_KEY128}
{$DEFINE CRYPTOLIB_AESCRYPTOEXT_DECRYPT}
{$I ..\..\Include\Simd\Common\ClpSimdProc3Begin_aarch64.inc}
{$I ..\..\Include\Simd\Aes\AesCryptoExtCipher_aarch64.inc}
{$UNDEF CRYPTOLIB_AESCRYPTOEXT_DECRYPT}
{$UNDEF CRYPTOLIB_AESCRYPTOEXT_KEY128}
{$UNDEF CRYPTOLIB_AESCRYPTOEXT_ONE}
end;

procedure AesCryptoExtOneDec192(RIn, ROut, Keys: PByte);
{$DEFINE CRYPTOLIB_AESCRYPTOEXT_ONE}
{$DEFINE CRYPTOLIB_AESCRYPTOEXT_KEY192}
{$DEFINE CRYPTOLIB_AESCRYPTOEXT_DECRYPT}
{$I ..\..\Include\Simd\Common\ClpSimdProc3Begin_aarch64.inc}
{$I ..\..\Include\Simd\Aes\AesCryptoExtCipher_aarch64.inc}
{$UNDEF CRYPTOLIB_AESCRYPTOEXT_DECRYPT}
{$UNDEF CRYPTOLIB_AESCRYPTOEXT_KEY192}
{$UNDEF CRYPTOLIB_AESCRYPTOEXT_ONE}
end;

procedure AesCryptoExtOneDec256(RIn, ROut, Keys: PByte);
{$DEFINE CRYPTOLIB_AESCRYPTOEXT_ONE}
{$DEFINE CRYPTOLIB_AESCRYPTOEXT_KEY256}
{$DEFINE CRYPTOLIB_AESCRYPTOEXT_DECRYPT}
{$I ..\..\Include\Simd\Common\ClpSimdProc3Begin_aarch64.inc}
{$I ..\..\Include\Simd\Aes\AesCryptoExtCipher_aarch64.inc}
{$UNDEF CRYPTOLIB_AESCRYPTOEXT_DECRYPT}
{$UNDEF CRYPTOLIB_AESCRYPTOEXT_KEY256}
{$UNDEF CRYPTOLIB_AESCRYPTOEXT_ONE}
end;

procedure AesCryptoExtFourEnc128(RIn, ROut, Keys: PByte);
{$DEFINE CRYPTOLIB_AESCRYPTOEXT_FOUR}
{$DEFINE CRYPTOLIB_AESCRYPTOEXT_KEY128}
{$I ..\..\Include\Simd\Common\ClpSimdProc3Begin_aarch64.inc}
{$I ..\..\Include\Simd\Aes\AesCryptoExtCipher_aarch64.inc}
{$UNDEF CRYPTOLIB_AESCRYPTOEXT_KEY128}
{$UNDEF CRYPTOLIB_AESCRYPTOEXT_FOUR}
end;

procedure AesCryptoExtFourEnc192(RIn, ROut, Keys: PByte);
{$DEFINE CRYPTOLIB_AESCRYPTOEXT_FOUR}
{$DEFINE CRYPTOLIB_AESCRYPTOEXT_KEY192}
{$I ..\..\Include\Simd\Common\ClpSimdProc3Begin_aarch64.inc}
{$I ..\..\Include\Simd\Aes\AesCryptoExtCipher_aarch64.inc}
{$UNDEF CRYPTOLIB_AESCRYPTOEXT_KEY192}
{$UNDEF CRYPTOLIB_AESCRYPTOEXT_FOUR}
end;

procedure AesCryptoExtFourEnc256(RIn, ROut, Keys: PByte);
{$DEFINE CRYPTOLIB_AESCRYPTOEXT_FOUR}
{$DEFINE CRYPTOLIB_AESCRYPTOEXT_KEY256}
{$I ..\..\Include\Simd\Common\ClpSimdProc3Begin_aarch64.inc}
{$I ..\..\Include\Simd\Aes\AesCryptoExtCipher_aarch64.inc}
{$UNDEF CRYPTOLIB_AESCRYPTOEXT_KEY256}
{$UNDEF CRYPTOLIB_AESCRYPTOEXT_FOUR}
end;

procedure AesCryptoExtFourDec128(RIn, ROut, Keys: PByte);
{$DEFINE CRYPTOLIB_AESCRYPTOEXT_FOUR}
{$DEFINE CRYPTOLIB_AESCRYPTOEXT_KEY128}
{$DEFINE CRYPTOLIB_AESCRYPTOEXT_DECRYPT}
{$I ..\..\Include\Simd\Common\ClpSimdProc3Begin_aarch64.inc}
{$I ..\..\Include\Simd\Aes\AesCryptoExtCipher_aarch64.inc}
{$UNDEF CRYPTOLIB_AESCRYPTOEXT_DECRYPT}
{$UNDEF CRYPTOLIB_AESCRYPTOEXT_KEY128}
{$UNDEF CRYPTOLIB_AESCRYPTOEXT_FOUR}
end;

procedure AesCryptoExtFourDec192(RIn, ROut, Keys: PByte);
{$DEFINE CRYPTOLIB_AESCRYPTOEXT_FOUR}
{$DEFINE CRYPTOLIB_AESCRYPTOEXT_KEY192}
{$DEFINE CRYPTOLIB_AESCRYPTOEXT_DECRYPT}
{$I ..\..\Include\Simd\Common\ClpSimdProc3Begin_aarch64.inc}
{$I ..\..\Include\Simd\Aes\AesCryptoExtCipher_aarch64.inc}
{$UNDEF CRYPTOLIB_AESCRYPTOEXT_DECRYPT}
{$UNDEF CRYPTOLIB_AESCRYPTOEXT_KEY192}
{$UNDEF CRYPTOLIB_AESCRYPTOEXT_FOUR}
end;

procedure AesCryptoExtFourDec256(RIn, ROut, Keys: PByte);
{$DEFINE CRYPTOLIB_AESCRYPTOEXT_FOUR}
{$DEFINE CRYPTOLIB_AESCRYPTOEXT_KEY256}
{$DEFINE CRYPTOLIB_AESCRYPTOEXT_DECRYPT}
{$I ..\..\Include\Simd\Common\ClpSimdProc3Begin_aarch64.inc}
{$I ..\..\Include\Simd\Aes\AesCryptoExtCipher_aarch64.inc}
{$UNDEF CRYPTOLIB_AESCRYPTOEXT_DECRYPT}
{$UNDEF CRYPTOLIB_AESCRYPTOEXT_KEY256}
{$UNDEF CRYPTOLIB_AESCRYPTOEXT_FOUR}
end;

procedure AesCryptoExtEightEnc128(RIn, ROut, Keys: PByte);
{$DEFINE CRYPTOLIB_AESCRYPTOEXT_EIGHT}
{$DEFINE CRYPTOLIB_AESCRYPTOEXT_KEY128}
{$I ..\..\Include\Simd\Common\ClpSimdProc3Begin_aarch64.inc}
{$I ..\..\Include\Simd\Aes\AesCryptoExtCipher_aarch64.inc}
{$UNDEF CRYPTOLIB_AESCRYPTOEXT_KEY128}
{$UNDEF CRYPTOLIB_AESCRYPTOEXT_EIGHT}
end;

procedure AesCryptoExtEightEnc192(RIn, ROut, Keys: PByte);
{$DEFINE CRYPTOLIB_AESCRYPTOEXT_EIGHT}
{$DEFINE CRYPTOLIB_AESCRYPTOEXT_KEY192}
{$I ..\..\Include\Simd\Common\ClpSimdProc3Begin_aarch64.inc}
{$I ..\..\Include\Simd\Aes\AesCryptoExtCipher_aarch64.inc}
{$UNDEF CRYPTOLIB_AESCRYPTOEXT_KEY192}
{$UNDEF CRYPTOLIB_AESCRYPTOEXT_EIGHT}
end;

procedure AesCryptoExtEightEnc256(RIn, ROut, Keys: PByte);
{$DEFINE CRYPTOLIB_AESCRYPTOEXT_EIGHT}
{$DEFINE CRYPTOLIB_AESCRYPTOEXT_KEY256}
{$I ..\..\Include\Simd\Common\ClpSimdProc3Begin_aarch64.inc}
{$I ..\..\Include\Simd\Aes\AesCryptoExtCipher_aarch64.inc}
{$UNDEF CRYPTOLIB_AESCRYPTOEXT_KEY256}
{$UNDEF CRYPTOLIB_AESCRYPTOEXT_EIGHT}
end;

procedure AesCryptoExtEightDec128(RIn, ROut, Keys: PByte);
{$DEFINE CRYPTOLIB_AESCRYPTOEXT_EIGHT}
{$DEFINE CRYPTOLIB_AESCRYPTOEXT_KEY128}
{$DEFINE CRYPTOLIB_AESCRYPTOEXT_DECRYPT}
{$I ..\..\Include\Simd\Common\ClpSimdProc3Begin_aarch64.inc}
{$I ..\..\Include\Simd\Aes\AesCryptoExtCipher_aarch64.inc}
{$UNDEF CRYPTOLIB_AESCRYPTOEXT_DECRYPT}
{$UNDEF CRYPTOLIB_AESCRYPTOEXT_KEY128}
{$UNDEF CRYPTOLIB_AESCRYPTOEXT_EIGHT}
end;

procedure AesCryptoExtEightDec192(RIn, ROut, Keys: PByte);
{$DEFINE CRYPTOLIB_AESCRYPTOEXT_EIGHT}
{$DEFINE CRYPTOLIB_AESCRYPTOEXT_KEY192}
{$DEFINE CRYPTOLIB_AESCRYPTOEXT_DECRYPT}
{$I ..\..\Include\Simd\Common\ClpSimdProc3Begin_aarch64.inc}
{$I ..\..\Include\Simd\Aes\AesCryptoExtCipher_aarch64.inc}
{$UNDEF CRYPTOLIB_AESCRYPTOEXT_DECRYPT}
{$UNDEF CRYPTOLIB_AESCRYPTOEXT_KEY192}
{$UNDEF CRYPTOLIB_AESCRYPTOEXT_EIGHT}
end;

procedure AesCryptoExtEightDec256(RIn, ROut, Keys: PByte);
{$DEFINE CRYPTOLIB_AESCRYPTOEXT_EIGHT}
{$DEFINE CRYPTOLIB_AESCRYPTOEXT_KEY256}
{$DEFINE CRYPTOLIB_AESCRYPTOEXT_DECRYPT}
{$I ..\..\Include\Simd\Common\ClpSimdProc3Begin_aarch64.inc}
{$I ..\..\Include\Simd\Aes\AesCryptoExtCipher_aarch64.inc}
{$UNDEF CRYPTOLIB_AESCRYPTOEXT_DECRYPT}
{$UNDEF CRYPTOLIB_AESCRYPTOEXT_KEY256}
{$UNDEF CRYPTOLIB_AESCRYPTOEXT_EIGHT}
end;

{ TAesEngineArm }

// =====================================================================
// Feature detection and lifecycle (class-level + constructor / destructor).
// =====================================================================

class function TAesEngineArm.IsSupported: Boolean;
begin
  Result := TCpuFeatures.Arm.HasAES();
end;

constructor TAesEngineArm.Create();
begin
  inherited Create();
  if not IsSupported then
    raise EInvalidOperationCryptoLibException.CreateRes(@SAesEngineArmNotSupported);
  FRawAlloc := nil;
  FKeys := nil;
  FNRounds := 0;
  FMode := TAesArmMode.Uninitialized;
  FAesCipherOne := nil;
  FAesCipherFour := nil;
  FAesCipherEight := nil;
end;

destructor TAesEngineArm.Destroy();
begin
  FreeAlignedKeys;
  inherited;
end;

// =====================================================================
// 16-byte aligned round-key buffer management. Alignment is kept for
// layout parity with the other hardware engines (AArch64 vector loads
// tolerate unaligned addresses); we over-allocate by 16 bytes and align
// the usable pointer.
// =====================================================================

procedure TAesEngineArm.FreeAlignedKeys;
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
  FMode := TAesArmMode.Uninitialized;
  FAesCipherOne := nil;
  FAesCipherFour := nil;
  FAesCipherEight := nil;
end;

procedure TAesEngineArm.AllocAlignedKeys(AKeyBytes: Int32);
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

function TAesEngineArm.GetAlgorithmName: String;
begin
  Result := 'AES';
end;

function TAesEngineArm.GetBlockSize(): Int32;
begin
  Result := 16;
end;

// =====================================================================
// Round-key schedule setup (encrypt expansion + decrypt InvMixColumns)
// and per-mode function-pointer binding. These three procedures form the
// rekey / direction-change contract used by Init.
// =====================================================================

procedure TAesEngineArm.CreateRoundKeys(AForEncryption: Boolean;
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
        AesCryptoExtExpandRoundKeys128(@AKey[0], LK);
      end;
    24:
      begin
        FNRounds := 12;
        AesCryptoExtExpandRoundKeys192(@AKey[0], LK);
      end;
    32:
      begin
        FNRounds := 14;
        AesCryptoExtExpandRoundKeys256(@AKey[0], LK);
      end;
  else
    TArrayUtilities.Fill(AKey, 0, LKeyLen, Byte(0));
    raise EArgumentCryptoLibException.CreateRes(@SInvalidKeyLength);
  end;

  if not AForEncryption then
    PrepareDecryptRoundKeys;
end;

procedure TAesEngineArm.PrepareDecryptRoundKeys;
begin
  AesCryptoExtPrepareDecryptRoundKeys(FKeys, FNRounds);
end;

procedure TAesEngineArm.BindCipherPointers;
begin
  FAesCipherOne := nil;
  FAesCipherFour := nil;
  FAesCipherEight := nil;

  case FMode of
    TAesArmMode.Enc128:
      begin
        FAesCipherOne := @AesCryptoExtOneEnc128;
        FAesCipherFour := @AesCryptoExtFourEnc128;
        FAesCipherEight := @AesCryptoExtEightEnc128;
      end;
    TAesArmMode.Enc192:
      begin
        FAesCipherOne := @AesCryptoExtOneEnc192;
        FAesCipherFour := @AesCryptoExtFourEnc192;
        FAesCipherEight := @AesCryptoExtEightEnc192;
      end;
    TAesArmMode.Enc256:
      begin
        FAesCipherOne := @AesCryptoExtOneEnc256;
        FAesCipherFour := @AesCryptoExtFourEnc256;
        FAesCipherEight := @AesCryptoExtEightEnc256;
      end;
    TAesArmMode.Dec128:
      begin
        FAesCipherOne := @AesCryptoExtOneDec128;
        FAesCipherFour := @AesCryptoExtFourDec128;
        FAesCipherEight := @AesCryptoExtEightDec128;
      end;
    TAesArmMode.Dec192:
      begin
        FAesCipherOne := @AesCryptoExtOneDec192;
        FAesCipherFour := @AesCryptoExtFourDec192;
        FAesCipherEight := @AesCryptoExtEightDec192;
      end;
    TAesArmMode.Dec256:
      begin
        FAesCipherOne := @AesCryptoExtOneDec256;
        FAesCipherFour := @AesCryptoExtFourDec256;
        FAesCipherEight := @AesCryptoExtEightDec256;
      end;
  else
    // stay nil
  end;
end;

// =====================================================================
// Per-call Init (validate parameters, rekey, bind fast-path pointers).
// =====================================================================

procedure TAesEngineArm.Init(AForEncryption: Boolean;
  const AParameters: ICipherParameters);
var
  LKeyParameter: IKeyParameter;
  LKeyCopy: TCryptoLibByteArray;
  LKeyLen: Int32;
begin
  if not Supports(AParameters, IKeyParameter, LKeyParameter) then
    raise EArgumentCryptoLibException.CreateResFmt(@SInvalidParameterAESArmInit,
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
          FMode := TAesArmMode.Enc128
        else
          FMode := TAesArmMode.Dec128;
      24:
        if AForEncryption then
          FMode := TAesArmMode.Enc192
        else
          FMode := TAesArmMode.Dec192;
      32:
        if AForEncryption then
          FMode := TAesArmMode.Enc256
        else
          FMode := TAesArmMode.Dec256;
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

function TAesEngineArm.ProcessBlock(const AInput: TCryptoLibByteArray;
  AInOff: Int32; const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32;
begin
  if FKeys = nil then
    raise EInvalidOperationCryptoLibException.CreateRes(@SAesEngineArmNotInitialised);

  TCheck.DataLength(AInput, AInOff, 16, SInputBufferTooShort);
  TCheck.OutputLength(AOutput, AOutOff, 16, SOutputBufferTooShort);

  Result := ProcessBlock(@AInput[AInOff], @AOutput[AOutOff]);
end;

// =====================================================================
// Pointer-overload single-block processing - defense-in-depth version
// that guards against overlapping in/out ranges by staging through a
// stack buffer, plus nil-pointer and binding checks.
// =====================================================================

function TAesEngineArm.ProcessBlock(AInput, AOutput: PByte): Int32;
var
  LBuf: array [0 .. 15] of Byte;
begin
  if FKeys = nil then
    raise EInvalidOperationCryptoLibException.CreateRes(@SAesEngineArmNotInitialised);
  if (AInput = nil) or (AOutput = nil) then
    raise EArgumentCryptoLibException.CreateRes(@SNilPointerBuffer);

  if not Assigned(FAesCipherOne) then
    raise EInvalidOperationCryptoLibException.CreateRes(@SAesEngineArmNotInitialised);

  if ((AInput <> AOutput) and (AOutput >= AInput) and (AOutput < AInput + 16)) or
    ((AInput > AOutput) and (AInput < AOutput + 16)) then
  begin
    FAesCipherOne(AInput, @LBuf[0], FKeys);
    System.Move(LBuf[0], AOutput^, 16);
    FillChar(LBuf, SizeOf(LBuf), 0);
  end
  else
    FAesCipherOne(AInput, AOutput, FKeys);
  Result := 16;
end;

// =====================================================================
// "Fast" pointer overloads - no validation, no overlap staging. Only
// callable from code paths that have already proven their preconditions
// (disjoint buffers, non-nil pointers, engine initialized).
// =====================================================================

function TAesEngineArm.ProcessFourBlocksFast(AInput, AOutput: PByte): Int32;
begin
  FAesCipherFour(AInput, AOutput, FKeys);
  Result := 64;
end;

function TAesEngineArm.ProcessEightBlocksFast(AInput, AOutput: PByte): Int32;
begin
  FAesCipherEight(AInput, AOutput, FKeys);
  Result := 128;
end;

// =====================================================================
// IBulkBlockCipher implementation. Engine-owned 8-then-4-then-1 ladder
// over the existing *Fast inner helpers. Array overload validates then
// delegates to the PByte overload. The aliasing contract is the same as
// the *Fast helpers: AInput / AOutput MUST be identical or fully
// disjoint. The checks on FKeys / FAesCipher* assignment live in
// ProcessBlock for the 1-wide tail and are paid once per batch at most.
// =====================================================================

function TAesEngineArm.ProcessBlocks(const AInBuf: TCryptoLibByteArray;
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
    raise EInvalidOperationCryptoLibException.CreateRes(@SAesEngineArmNotInitialised);

  LBytes := ABlockCount * 16;
  TCheck.DataLength(AInBuf, AInOff, LBytes, SInputBufferTooShort);
  TCheck.OutputLength(AOutBuf, AOutOff, LBytes, SOutputBufferTooShort);

  Result := ProcessBlocks(@AInBuf[AInOff], @AOutBuf[AOutOff], ABlockCount);
end;

function TAesEngineArm.ProcessBlocks(AInput, AOutput: PByte;
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
// Key-schedule accessors used by the fused AES cipher kernels. Return a
// pointer to the round-key schedule only when the engine is in the requested
// direction with a matching round count.
// =====================================================================

function TAesEngineArm.TryGetEncKeysPtr(out AKeysPtr: PByte; out ANumRounds: Int32): Boolean;
begin
  AKeysPtr := nil;
  ANumRounds := 0;
  if FKeys = nil then
  begin
    Result := False;
    Exit;
  end;
  case FMode of
    TAesArmMode.Enc128:
      if FNRounds <> 10 then begin Result := False; Exit; end;
    TAesArmMode.Enc192:
      if FNRounds <> 12 then begin Result := False; Exit; end;
    TAesArmMode.Enc256:
      if FNRounds <> 14 then begin Result := False; Exit; end;
  else
    Result := False;
    Exit;
  end;
  AKeysPtr := FKeys;
  ANumRounds := FNRounds;
  Result := True;
end;

function TAesEngineArm.TryGetDecKeysPtr(out AKeysPtr: PByte; out ANumRounds: Int32): Boolean;
begin
  AKeysPtr := nil;
  ANumRounds := 0;
  if FKeys = nil then
  begin
    Result := False;
    Exit;
  end;
  case FMode of
    TAesArmMode.Dec128:
      if FNRounds <> 10 then begin Result := False; Exit; end;
    TAesArmMode.Dec192:
      if FNRounds <> 12 then begin Result := False; Exit; end;
    TAesArmMode.Dec256:
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
