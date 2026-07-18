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

unit ClpAesCryptoExtGcmKernel;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpIBlockCipher,
  ClpIAesEngineArm,
  ClpCipherKernelTypes,
  ClpIGcmKernel,
  ClpCipherKernelFactoryBase,
  ClpCipherKernelRegistry,
  ClpAesFusedAeadSimd,
  ClpAesCryptoExtFusedArmBackend,
  ClpCryptoLibTypes;

type
  /// <summary>
  ///   AES CryptoExt (ARMv8) implementation of IGcmKernel: the fused AES CTR
  ///   keystream + 8-way PMULL GHASH body used by TGcmBlockCipher's bulk
  ///   path. Byte-compatible with the x86 kernel: same context layout, same
  ///   x-premultiplied H^8..H^1 table and reflected-state reduction.
  ///   Available on aarch64 (CRYPTOLIB_AARCH64_ASM). When unavailable the
  ///   factory returns nil and TGcmBlockCipher keeps its pipelined path.
  /// </summary>
  TAesCryptoExtGcmKernel = class sealed(TInterfacedObject, IGcmKernel)
  strict private
  const
    FUSED_GCM_MIN_BLOCKS = 8;
  strict private
    // FEngine is retained so the round-key buffer FKeys points into stays alive
    // for the kernel's lifetime.
    FEngine: IAesEngineArm;
    FKeys: Pointer;
    FRounds: Int32;
    FHPow128: Pointer;
    FHPowShifted: TCryptoLibByteArray;
  public
    constructor Create(const AEngine: IAesEngineArm; AKeys: Pointer;
      ARounds: Int32; AHPow128: Pointer);
    function MinimumBlockCount: Int32;
    function ProcessCtrGhashBatches(AInPtr, AOutPtr, APrevInit, AGhashState,
      AJ0Template: Pointer; ACounter32: UInt32; ABatchCount: NativeInt;
      AForEncrypt: Boolean): UInt32;
  end;

  TAesCryptoExtGcmKernelFactory = class sealed(TCipherKernelFactoryBase, IGcmKernelFactory)
  public
    function ProviderName: String; override;
    function TryCreate(const ACipher: IBlockCipher;
      ADirection: TCipherKernelDirection; AHPowers: Pointer;
      out AKernel: IGcmKernel): Boolean;
  end;

implementation

{$IFDEF CRYPTOLIB_AARCH64_ASM}

type
  // Context handed to the fused AES CryptoExt CTR + GHASH kernel. Field
  // offsets match the [x0 + N] accesses in AesGcmFusedCtrGhashEight_aarch64.inc
  // (all 8-byte fields; identical layout to the x86_64 kernel). PMask is
  // unused on AArch64 (rev64 replaces the shuffle mask) and kept for layout
  // parity. The kernel loops internally over BatchCount 8-block batches,
  // GHASHing the previous batch's ciphertext (pipeline lags by one batch)
  // and writes the advanced Counter32 back.
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
{$I ..\..\..\Include\Simd\Common\ClpSimdProc1Begin_aarch64.inc}
{$I ..\..\..\Include\Simd\Aes\Gcm\AesGcmFusedCtrGhashEight_aarch64.inc}
{$UNDEF GCM_FUSED_AES_ROUNDS_10}
end;

procedure GcmFusedAesEnc192GhashEight(PCtx: Pointer);
{$DEFINE GCM_FUSED_AES_ROUNDS_12}
{$I ..\..\..\Include\Simd\Common\ClpSimdProc1Begin_aarch64.inc}
{$I ..\..\..\Include\Simd\Aes\Gcm\AesGcmFusedCtrGhashEight_aarch64.inc}
{$UNDEF GCM_FUSED_AES_ROUNDS_12}
end;

procedure GcmFusedAesEnc256GhashEight(PCtx: Pointer);
{$DEFINE GCM_FUSED_AES_ROUNDS_14}
{$I ..\..\..\Include\Simd\Common\ClpSimdProc1Begin_aarch64.inc}
{$I ..\..\..\Include\Simd\Aes\Gcm\AesGcmFusedCtrGhashEight_aarch64.inc}
{$UNDEF GCM_FUSED_AES_ROUNDS_14}
end;

{$ENDIF CRYPTOLIB_AARCH64_ASM}

{ TAesCryptoExtGcmKernel }

constructor TAesCryptoExtGcmKernel.Create(const AEngine: IAesEngineArm;
  AKeys: Pointer; ARounds: Int32; AHPow128: Pointer);
begin
  inherited Create;
  FEngine := AEngine;
  FKeys := AKeys;
  FRounds := ARounds;
  // Kernel-owned copy of the mode's x-premultiplied H^8..H^1 table so the
  // pointer stays valid for the kernel's lifetime.
  System.SetLength(FHPowShifted, 128);
  System.Move(AHPow128^, FHPowShifted[0], 128);
  FHPow128 := @FHPowShifted[0];
end;

function TAesCryptoExtGcmKernel.MinimumBlockCount: Int32;
begin
  Result := FUSED_GCM_MIN_BLOCKS;
end;

function TAesCryptoExtGcmKernel.ProcessCtrGhashBatches(AInPtr, AOutPtr,
  APrevInit, AGhashState, AJ0Template: Pointer; ACounter32: UInt32;
  ABatchCount: NativeInt; AForEncrypt: Boolean): UInt32;
{$IFDEF CRYPTOLIB_AARCH64_ASM}
var
  LCtx: TGcmFusedCtx;
{$ENDIF CRYPTOLIB_AARCH64_ASM}
begin
{$IFDEF CRYPTOLIB_AARCH64_ASM}
  LCtx.PXorIn := AInPtr;
  LCtx.POut := AOutPtr;
  LCtx.PPrevCipher := APrevInit;
  LCtx.PRoundKeys := FKeys;
  LCtx.PHPow128 := FHPow128;
  LCtx.PFS := AGhashState;
  LCtx.PMask := nil;
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
  Result := UInt32(LCtx.Counter32);
{$ELSE}
  Result := ACounter32;
{$ENDIF CRYPTOLIB_AARCH64_ASM}
end;

{ TAesCryptoExtGcmKernelFactory }

function TAesCryptoExtGcmKernelFactory.ProviderName: String;
begin
  Result := 'AES-CryptoExt';
end;

function TAesCryptoExtGcmKernelFactory.TryCreate(const ACipher: IBlockCipher;
  ADirection: TCipherKernelDirection; AHPowers: Pointer;
  out AKernel: IGcmKernel): Boolean;
var
  LEngine: IAesEngineArm;
  LKeys: PByte;
  LRounds: Int32;
begin
  AKernel := nil;
  Result := False;
  try
{$IFDEF CRYPTOLIB_AARCH64_ASM}
    if AHPowers = nil then
      Exit;
    if not TAesFusedAeadSimd.CpuSupports then
      Exit;
    if not TAesCryptoExtFusedArmBackend.TryResolveEngine(ACipher, LEngine) then
      Exit;
    if not LEngine.TryGetEncKeysPtr(LKeys, LRounds) then
      Exit;
    if not (LRounds in [10, 12, 14]) then
      Exit;
    AKernel := TAesCryptoExtGcmKernel.Create(LEngine, LKeys, LRounds, AHPowers);
    Result := True;
{$ENDIF CRYPTOLIB_AARCH64_ASM}
  except
    AKernel := nil;
    Result := False;
  end;
end;

initialization
  TCipherKernelRegistry.Register(
    TAesCryptoExtGcmKernelFactory.Create() as IGcmKernelFactory);

end.
