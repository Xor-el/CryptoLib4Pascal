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

unit ClpAesNiGcmKernel;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpCryptoLibTypes,
  ClpIBlockCipher,
  ClpIAesEngineX86,
  ClpCipherKernelTypes,
  ClpIGcmKernel,
  ClpCipherKernelFactoryBase,
  ClpCipherKernelRegistry,
  ClpAesFusedAeadSimd,
  ClpAesNiFusedX86Backend;

type
  /// <summary>
  ///   AES-NI + PCLMULQDQ implementation of IGcmKernel.
  ///   Available on x86_64 (CRYPTOLIB_X86_64_ASM) and i386
  ///   (CRYPTOLIB_I386_ASM); both arms gated collectively by
  ///   CRYPTOLIB_X86_SIMD.
  ///   Direction-independent: the fused AES-CTR keystream is identical
  ///   for GCM encrypt and decrypt; ProcessCtrGhashBatches supplies the
  ///   direction via AForEncrypt (which buffer feeds GHASH).
  ///   The kernel loops over a whole run of 8-block (128-byte) batches in
  ///   one call, generating the GCM counters and rotating the GHASH
  ///   pipeline internally; the mode primes the first batch and drains the
  ///   last.
  /// </summary>
  TAesNiGcmKernel = class sealed(TInterfacedObject, IGcmKernel)
  strict private
  const
    FUSED_GCM_MIN_BLOCKS = 8;
  strict private
    FEngine: IAesEngineX86;
    FKeys: Pointer;
    FRounds: Int32;
    FHPow128: Pointer;
    FMask: Pointer;
    // Kernel-owned copy of the mode's H^8..H^1 table (already x-pre-multiplied
    // by TGcmUtilities.InitEightWayHPowFromH, matching the carry-less-multiply
    // folding reduction inside the fused kernel). FHPow128 points at it.
    FHPowShifted: TCryptoLibByteArray;
  public
    constructor Create(const AEngine: IAesEngineX86; AKeys: Pointer;
      ARounds: Int32; AHPow128, AMask: Pointer);
    function MinimumBlockCount: Int32;
    function ProcessCtrGhashBatches(AInPtr, AOutPtr, APrevInit, AGhashState,
      AJ0Template: Pointer; ACounter32: UInt32; ABatchCount: NativeInt;
      AForEncrypt: Boolean): UInt32;
  end;

  TAesNiGcmKernelFactory = class sealed(TCipherKernelFactoryBase,
    IGcmKernelFactory)
  public
    function ProviderName: String; override;
    function TryCreate(const ACipher: IBlockCipher;
      ADirection: TCipherKernelDirection; AHPowers: Pointer;
      out AKernel: IGcmKernel): Boolean;
  end;

implementation

{$IFDEF CRYPTOLIB_X86_SIMD}

type
  // Context handed to the fused AES-NI CTR keystream + 8-way GHASH loop kernel.
  // Natural pointer-sized alignment, no padding: the field offsets match the
  // [rcx + N] / [ebx + N] accesses in AesGcmFusedCtrGhashEight_x86_64.inc and
  // AesGcmFusedCtrGhashEight_i386.inc (they differ with pointer / NativeUInt
  // width: 8-byte fields on x86_64, 4-byte on i386). The kernel holds the loop
  // state in registers across the batch run, writing only Counter32 back, and
  // builds each batch's counter blocks in-register from Counter32 + PJ0Template
  // (both arches); the GHASH-from-output flag is 1 for encrypt (fold the output
  // ciphertext) and 0 for decrypt (fold the input). PHPow128 points at the
  // kernel-owned x-pre-multiplied H-power table (see TAesNiGcmKernel.Create).
  TGcmFusedCtx = record
    PXorIn: Pointer;
    POut: Pointer;
    PPrevCipher: Pointer;
    PRoundKeys: Pointer;
    PHPow128: Pointer;
    PFS: Pointer;
    PMask: Pointer;
    Counter32: NativeUInt;
    PJ0Template: Pointer;
    BatchCount: NativeUInt;
    GhashFromOutput: NativeUInt;
  end;

procedure GcmFusedAesEnc128GhashEight(PCtx: Pointer);
{$DEFINE GCM_FUSED_AES_ROUNDS_10}
{$IFDEF CRYPTOLIB_X86_64_ASM}
{$I ..\..\..\Include\Simd\Common\ClpSimdProc1Begin_x86_64.inc}
{$I ..\..\..\Include\Simd\Aes\Gcm\AesGcmFusedCtrGhashEight_x86_64.inc}
{$ENDIF}
{$IFDEF CRYPTOLIB_I386_ASM}
{$I ..\..\..\Include\Simd\Common\ClpSimdProc1Begin_i386.inc}
{$I ..\..\..\Include\Simd\Aes\Gcm\AesGcmFusedCtrGhashEight_i386.inc}
{$ENDIF}
{$UNDEF GCM_FUSED_AES_ROUNDS_10}
end;

procedure GcmFusedAesEnc192GhashEight(PCtx: Pointer);
{$DEFINE GCM_FUSED_AES_ROUNDS_12}
{$IFDEF CRYPTOLIB_X86_64_ASM}
{$I ..\..\..\Include\Simd\Common\ClpSimdProc1Begin_x86_64.inc}
{$I ..\..\..\Include\Simd\Aes\Gcm\AesGcmFusedCtrGhashEight_x86_64.inc}
{$ENDIF}
{$IFDEF CRYPTOLIB_I386_ASM}
{$I ..\..\..\Include\Simd\Common\ClpSimdProc1Begin_i386.inc}
{$I ..\..\..\Include\Simd\Aes\Gcm\AesGcmFusedCtrGhashEight_i386.inc}
{$ENDIF}
{$UNDEF GCM_FUSED_AES_ROUNDS_12}
end;

procedure GcmFusedAesEnc256GhashEight(PCtx: Pointer);
{$DEFINE GCM_FUSED_AES_ROUNDS_14}
{$IFDEF CRYPTOLIB_X86_64_ASM}
{$I ..\..\..\Include\Simd\Common\ClpSimdProc1Begin_x86_64.inc}
{$I ..\..\..\Include\Simd\Aes\Gcm\AesGcmFusedCtrGhashEight_x86_64.inc}
{$ENDIF}
{$IFDEF CRYPTOLIB_I386_ASM}
{$I ..\..\..\Include\Simd\Common\ClpSimdProc1Begin_i386.inc}
{$I ..\..\..\Include\Simd\Aes\Gcm\AesGcmFusedCtrGhashEight_i386.inc}
{$ENDIF}
{$UNDEF GCM_FUSED_AES_ROUNDS_14}
end;

{$ENDIF CRYPTOLIB_X86_SIMD}

const
  // PSHUFB full-reverse control.
  GcmKernelReverseMask: packed array[0..15] of Byte = (
    $0F, $0E, $0D, $0C, $0B, $0A, $09, $08,
    $07, $06, $05, $04, $03, $02, $01, $00);

{ TAesNiGcmKernel }

constructor TAesNiGcmKernel.Create(const AEngine: IAesEngineX86;
  AKeys: Pointer; ARounds: Int32; AHPow128, AMask: Pointer);
begin
  inherited Create;
  FEngine := AEngine;
  FKeys := AKeys;
  FRounds := ARounds;
  FMask := AMask;
  // The mode's table already holds the powers pre-multiplied by x (see
  // TGcmUtilities.InitEightWayHPowFromH); keep a kernel-owned copy so the
  // pointer stays valid for the kernel's lifetime.
  System.SetLength(FHPowShifted, 128);
  System.Move(AHPow128^, FHPowShifted[0], 128);
  FHPow128 := @FHPowShifted[0];
end;

function TAesNiGcmKernel.MinimumBlockCount: Int32;
begin
  Result := FUSED_GCM_MIN_BLOCKS;
end;

function TAesNiGcmKernel.ProcessCtrGhashBatches(AInPtr, AOutPtr, APrevInit,
  AGhashState, AJ0Template: Pointer; ACounter32: UInt32; ABatchCount: NativeInt;
  AForEncrypt: Boolean): UInt32;
{$IFDEF CRYPTOLIB_X86_SIMD}
var
  LCtx: TGcmFusedCtx;
{$ENDIF CRYPTOLIB_X86_SIMD}
begin
{$IFDEF CRYPTOLIB_X86_SIMD}
  LCtx.PXorIn := AInPtr;
  LCtx.POut := AOutPtr;
  LCtx.PPrevCipher := APrevInit;
  LCtx.PRoundKeys := FKeys;
  LCtx.PHPow128 := FHPow128;
  LCtx.PFS := AGhashState;
  LCtx.PMask := FMask;
  LCtx.Counter32 := ACounter32;
  LCtx.PJ0Template := AJ0Template;
  LCtx.BatchCount := NativeUInt(ABatchCount);
  LCtx.GhashFromOutput := NativeUInt(Ord(AForEncrypt));
  case FRounds of
    10: GcmFusedAesEnc128GhashEight(@LCtx);
    12: GcmFusedAesEnc192GhashEight(@LCtx);
  else
    GcmFusedAesEnc256GhashEight(@LCtx);
  end;
  Exit(UInt32(LCtx.Counter32));
{$ENDIF CRYPTOLIB_X86_SIMD}
  Result := 0;
end;

{ TAesNiGcmKernelFactory }

function TAesNiGcmKernelFactory.ProviderName: String;
begin
  Result := 'AES-NI';
end;

function TAesNiGcmKernelFactory.TryCreate(const ACipher: IBlockCipher;
  ADirection: TCipherKernelDirection; AHPowers: Pointer;
  out AKernel: IGcmKernel): Boolean;
var
  LEngine: IAesEngineX86;
  LKeys: PByte;
  LRounds: Int32;
begin
  AKernel := nil;
  Result := False;
  try
    if AHPowers = nil then
      Exit;
{$IFDEF CRYPTOLIB_X86_SIMD}
    if not TAesFusedAeadSimd.CpuSupports then
      Exit;
    if not TAesNiFusedX86Backend.TryResolveEngine(ACipher, LEngine) then
      Exit;
    if not LEngine.TryGetEncKeysPtr(LKeys, LRounds) then
      Exit;
    if not (LRounds in [10, 12, 14]) then
      Exit;
    AKernel := TAesNiGcmKernel.Create(LEngine, LKeys, LRounds, AHPowers,
      @GcmKernelReverseMask[0]);
    Result := True;
{$ENDIF CRYPTOLIB_X86_SIMD}
  except
    AKernel := nil;
    Result := False;
  end;
end;

initialization
  TCipherKernelRegistry.Register(
    TAesNiGcmKernelFactory.Create() as IGcmKernelFactory);

end.
