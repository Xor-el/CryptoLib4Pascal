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
  ClpIBlockCipher,
  ClpIAesEngineX86,
  ClpFusedKernelTypes,
  ClpIFusedGcmKernel,
  ClpFusedKernelRegistry,
  ClpAesNiAeadResolver;

type
  /// <summary>
  ///   AES-NI + PCLMULQDQ + SSSE3 implementation of IFusedGcmKernel.
  ///   x86_64 only (gated behind CRYPTOLIB_X86_64_ASM).
  /// </summary>
  TAesNiGcmKernel = class sealed(TInterfacedObject, IFusedGcmKernel)
  strict private
  const
    FUSED_GCM_MIN_BLOCKS = 8;
  strict private
    FEngine: IAesEngineX86;
    FKeys: Pointer;
    FRounds: Int32;
    FHPow128: Pointer;
    FMask: Pointer;
  public
    constructor Create(const AEngine: IAesEngineX86; AKeys: Pointer;
      ARounds: Int32; AHPow128, AMask: Pointer);
    function MinimumBlockCount: Int32;
    procedure ProcessCtrGhashBatch(AInPtr, AOutPtr, ARawCtrs, APrevCipher,
      AGhashState: Pointer; ABlockCount: Int32);
  end;

  TAesNiGcmKernelFactory = class sealed(TInterfacedObject,
    IFusedGcmKernelFactory)
  public
    function ProviderName: String;
    function Priority: TFusedKernelPriority;
    function TryCreate(const ACipher: IBlockCipher;
      ADirection: TFusedModeDirection; AHPowers: Pointer;
      out AKernel: IFusedGcmKernel): Boolean;
  end;

implementation

{$IFDEF CRYPTOLIB_X86_64_ASM}
type
  // Context handed to the fused AES-NI keystream + 8-way GHASH kernel.
  // Natural 8-byte alignment, no padding: matches the [rcx+offset]
  // accesses in GcmFusedCtrGhashEight_x86_64.inc.
  TGcmFusedBatchCtx = record
    PXorIn: Pointer;
    POut: Pointer;
    PCtrCurr: Pointer;
    PPrevCipher: Pointer;
    PRoundKeys: Pointer;
    PHPow128: Pointer;
    PFS: Pointer;
    PMask: Pointer;
  end;

procedure GcmFusedAesEnc128GhashEight(PCtx: Pointer);
{$DEFINE GCM_FUSED_AES_ROUNDS_10}
{$I ..\..\..\Include\Simd\Common\SimdProc1Begin_x86_64.inc}
{$I ..\..\..\Include\Simd\Aes\Gcm\GcmFusedCtrGhashEight_x86_64.inc}
{$UNDEF GCM_FUSED_AES_ROUNDS_10}
end;

procedure GcmFusedAesEnc192GhashEight(PCtx: Pointer);
{$DEFINE GCM_FUSED_AES_ROUNDS_12}
{$I ..\..\..\Include\Simd\Common\SimdProc1Begin_x86_64.inc}
{$I ..\..\..\Include\Simd\Aes\Gcm\GcmFusedCtrGhashEight_x86_64.inc}
{$UNDEF GCM_FUSED_AES_ROUNDS_12}
end;

procedure GcmFusedAesEnc256GhashEight(PCtx: Pointer);
{$DEFINE GCM_FUSED_AES_ROUNDS_14}
{$I ..\..\..\Include\Simd\Common\SimdProc1Begin_x86_64.inc}
{$I ..\..\..\Include\Simd\Aes\Gcm\GcmFusedCtrGhashEight_x86_64.inc}
{$UNDEF GCM_FUSED_AES_ROUNDS_14}
end;
{$ENDIF CRYPTOLIB_X86_64_ASM}

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
  FHPow128 := AHPow128;
  FMask := AMask;
end;

function TAesNiGcmKernel.MinimumBlockCount: Int32;
begin
  Result := FUSED_GCM_MIN_BLOCKS;
end;

procedure TAesNiGcmKernel.ProcessCtrGhashBatch(AInPtr, AOutPtr, ARawCtrs,
  APrevCipher, AGhashState: Pointer; ABlockCount: Int32);
{$IFDEF CRYPTOLIB_X86_64_ASM}
var
  LCtx: TGcmFusedBatchCtx;
{$ENDIF CRYPTOLIB_X86_64_ASM}
begin
{$IFDEF CRYPTOLIB_X86_64_ASM}
  if ABlockCount <> FUSED_GCM_MIN_BLOCKS then
    Exit;
  LCtx.PXorIn := AInPtr;
  LCtx.POut := AOutPtr;
  LCtx.PCtrCurr := ARawCtrs;
  LCtx.PPrevCipher := APrevCipher;
  LCtx.PRoundKeys := FKeys;
  LCtx.PHPow128 := FHPow128;
  LCtx.PFS := AGhashState;
  LCtx.PMask := FMask;
  case FRounds of
    10: GcmFusedAesEnc128GhashEight(@LCtx);
    12: GcmFusedAesEnc192GhashEight(@LCtx);
  else
    GcmFusedAesEnc256GhashEight(@LCtx);
  end;
{$ENDIF CRYPTOLIB_X86_64_ASM}
end;

{ TAesNiGcmKernelFactory }

function TAesNiGcmKernelFactory.ProviderName: String;
begin
  Result := 'AES-NI';
end;

function TAesNiGcmKernelFactory.Priority: TFusedKernelPriority;
begin
  Result := TFusedKernelPriority.Baseline;
end;

function TAesNiGcmKernelFactory.TryCreate(const ACipher: IBlockCipher;
  ADirection: TFusedModeDirection; AHPowers: Pointer;
  out AKernel: IFusedGcmKernel): Boolean;
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
{$IFDEF CRYPTOLIB_X86_64_ASM}
    if not TAesNiAeadResolver.CpuSupports then
      Exit;
    if not TAesNiAeadResolver.TryResolveEngine(ACipher, LEngine) then
      Exit;
    if not LEngine.TryGetEncKeysPtr(LKeys, LRounds) then
      Exit;
    if not (LRounds in [10, 12, 14]) then
      Exit;
    AKernel := TAesNiGcmKernel.Create(LEngine, LKeys, LRounds, AHPowers,
      @GcmKernelReverseMask[0]);
    Result := True;
{$ENDIF CRYPTOLIB_X86_64_ASM}
  except
    AKernel := nil;
    Result := False;
  end;
end;

initialization
  TFusedKernelRegistry.RegisterGcmFactory(
    TAesNiGcmKernelFactory.Create() as IFusedGcmKernelFactory);

end.
