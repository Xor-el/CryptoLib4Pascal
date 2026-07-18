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

unit ClpAesCryptoExtCcmKernel;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpIBlockCipher,
  ClpIAesEngineArm,
  ClpCipherKernelTypes,
  ClpICcmKernel,
  ClpCipherKernelFactoryBase,
  ClpCipherKernelRegistry,
  ClpAesFusedAeadSimd,
  ClpAesCryptoExtFusedArmBackend;

type
  /// <summary>
  ///   AES CryptoExt (ARMv8) implementation of ICcmKernel: the fused
  ///   two-lane CTR + CBC-MAC body used by TCcmBlockCipher's bulk path.
  ///   Byte-compatible with the x86 kernel (same context layout and
  ///   counter/MAC state contract).
  ///   Available on aarch64 (CRYPTOLIB_AARCH64_ASM). When unavailable the
  ///   factory returns nil and TCcmBlockCipher keeps its block path.
  ///   Both directions consume the forward (encrypt) schedule.
  ///   The kernel loops internally over ABlockCount body blocks; the
  ///   mode invokes ProcessBody once per Init cycle.
  /// </summary>
  TAesCryptoExtCcmKernel = class sealed(TInterfacedObject, ICcmKernel)
  strict private
  const
    FUSED_CCM_MIN_BLOCKS = 1;
  strict private
    // Strong ref pins the engine (and therefore the round-key buffer's
    // owner) for the kernel's lifetime. The round-key pointer itself is
    // NOT cached here: TAesEngineArm.Init free-and-reallocates the
    // aligned key-schedule buffer, so a pointer captured at TryCreate
    // time can dangle after any subsequent re-Init (e.g. CCM's
    // per-packet SIC wrapper re-keying). ProcessBody re-resolves it on
    // every call; cost is one virtual dispatch amortised over a
    // multi-block SIMD loop.
    FEngine: IAesEngineArm;
    FRounds: Int32;
    FDirection: TCipherKernelDirection;
    FIncrement: Pointer;
  public
    constructor Create(const AEngine: IAesEngineArm; ARounds: Int32;
      ADirection: TCipherKernelDirection; AIncrement: Pointer);
    function MinimumBlockCount: Int32;
    procedure ProcessBody(AInPtr, AOutPtr, ACtrState, ACbcMacState: Pointer;
      ABlockCount: Int32);
  end;

  TAesCryptoExtCcmKernelFactory = class sealed(TCipherKernelFactoryBase,
    ICcmKernelFactory)
  public
    function ProviderName: String; override;
    function TryCreate(const ACipher: IBlockCipher;
      ADirection: TCipherKernelDirection;
      out AKernel: ICcmKernel): Boolean;
  end;

implementation

{$IFDEF CRYPTOLIB_AARCH64_ASM}
type
  // Context handed to the 2-wide fused AES CryptoExt CCM CTR+CBC-MAC
  // kernel. OutPtr may alias InPtr. Seven pointers + NativeUInt; field
  // offsets match the kernel's [x0 + N] accesses (identical layout to
  // the x86_64 kernel's). PMask is unused on AArch64 (rev64 + ext
  // replaces the shuffle mask) and kept for layout parity.
  TCcmFusedTwoCtx = record
    InPtr: Pointer;
    OutPtr: Pointer;
    Keys: Pointer;
    CtrState: Pointer;
    MacState: Pointer;
    PMask: Pointer;
    PIncrement: Pointer;
    BlockCount: NativeUInt;
  end;

procedure CcmFusedCtrCbcMacEnc128(PCtx: Pointer);
{$DEFINE CRYPTOLIB_AESCRYPTOEXT_KEY128}
{$I ..\..\..\Include\Simd\Common\ClpSimdProc1Begin_aarch64.inc}
{$I ..\..\..\Include\Simd\Aes\Ccm\AesCcmFusedCtrCbcMacTwo_aarch64.inc}
{$UNDEF CRYPTOLIB_AESCRYPTOEXT_KEY128}
end;

procedure CcmFusedCtrCbcMacEnc192(PCtx: Pointer);
{$DEFINE CRYPTOLIB_AESCRYPTOEXT_KEY192}
{$I ..\..\..\Include\Simd\Common\ClpSimdProc1Begin_aarch64.inc}
{$I ..\..\..\Include\Simd\Aes\Ccm\AesCcmFusedCtrCbcMacTwo_aarch64.inc}
{$UNDEF CRYPTOLIB_AESCRYPTOEXT_KEY192}
end;

procedure CcmFusedCtrCbcMacEnc256(PCtx: Pointer);
{$DEFINE CRYPTOLIB_AESCRYPTOEXT_KEY256}
{$I ..\..\..\Include\Simd\Common\ClpSimdProc1Begin_aarch64.inc}
{$I ..\..\..\Include\Simd\Aes\Ccm\AesCcmFusedCtrCbcMacTwo_aarch64.inc}
{$UNDEF CRYPTOLIB_AESCRYPTOEXT_KEY256}
end;

procedure CcmFusedCtrCbcMacDec128(PCtx: Pointer);
{$DEFINE CRYPTOLIB_AESCRYPTOEXT_KEY128}
{$DEFINE CRYPTOLIB_CCM_DECRYPT}
{$I ..\..\..\Include\Simd\Common\ClpSimdProc1Begin_aarch64.inc}
{$I ..\..\..\Include\Simd\Aes\Ccm\AesCcmFusedCtrCbcMacTwo_aarch64.inc}
{$UNDEF CRYPTOLIB_CCM_DECRYPT}
{$UNDEF CRYPTOLIB_AESCRYPTOEXT_KEY128}
end;

procedure CcmFusedCtrCbcMacDec192(PCtx: Pointer);
{$DEFINE CRYPTOLIB_AESCRYPTOEXT_KEY192}
{$DEFINE CRYPTOLIB_CCM_DECRYPT}
{$I ..\..\..\Include\Simd\Common\ClpSimdProc1Begin_aarch64.inc}
{$I ..\..\..\Include\Simd\Aes\Ccm\AesCcmFusedCtrCbcMacTwo_aarch64.inc}
{$UNDEF CRYPTOLIB_CCM_DECRYPT}
{$UNDEF CRYPTOLIB_AESCRYPTOEXT_KEY192}
end;

procedure CcmFusedCtrCbcMacDec256(PCtx: Pointer);
{$DEFINE CRYPTOLIB_AESCRYPTOEXT_KEY256}
{$DEFINE CRYPTOLIB_CCM_DECRYPT}
{$I ..\..\..\Include\Simd\Common\ClpSimdProc1Begin_aarch64.inc}
{$I ..\..\..\Include\Simd\Aes\Ccm\AesCcmFusedCtrCbcMacTwo_aarch64.inc}
{$UNDEF CRYPTOLIB_CCM_DECRYPT}
{$UNDEF CRYPTOLIB_AESCRYPTOEXT_KEY256}
end;

const
  // CTR +1 in the low 64-bit LE limb (applied after the rev64 + ext
  // byte-reverse then undone). Sufficient for CCM's <= 8-byte counter
  // field.
  CcmKernelCtrIncrement: packed array[0..15] of Byte = (
    $01, $00, $00, $00, $00, $00, $00, $00,
    $00, $00, $00, $00, $00, $00, $00, $00);

{$ENDIF CRYPTOLIB_AARCH64_ASM}

{ TAesCryptoExtCcmKernel }

constructor TAesCryptoExtCcmKernel.Create(const AEngine: IAesEngineArm;
  ARounds: Int32; ADirection: TCipherKernelDirection; AIncrement: Pointer);
begin
  inherited Create;
  FEngine := AEngine;
  FRounds := ARounds;
  FDirection := ADirection;
  FIncrement := AIncrement;
end;

function TAesCryptoExtCcmKernel.MinimumBlockCount: Int32;
begin
  Result := FUSED_CCM_MIN_BLOCKS;
end;

procedure TAesCryptoExtCcmKernel.ProcessBody(AInPtr, AOutPtr, ACtrState,
  ACbcMacState: Pointer; ABlockCount: Int32);
{$IFDEF CRYPTOLIB_AARCH64_ASM}
var
  LCtx: TCcmFusedTwoCtx;
  LKeys: PByte;
  LRounds: Int32;
{$ENDIF CRYPTOLIB_AARCH64_ASM}
begin
{$IFDEF CRYPTOLIB_AARCH64_ASM}
  if ABlockCount < FUSED_CCM_MIN_BLOCKS then
    Exit;
  // Resolve the live key-schedule pointer on every call: the engine
  // may re-key (and therefore move its aligned key buffer) between
  // TryCreate and ProcessBody, notably via CCM's per-packet SIC
  // wrapper. Round count is revalidated against the snapshot taken
  // at TryCreate to catch any direction/key-size change.
  if not FEngine.TryGetEncKeysPtr(LKeys, LRounds) then
    Exit;
  if LRounds <> FRounds then
    Exit;
  LCtx.InPtr := AInPtr;
  LCtx.OutPtr := AOutPtr;
  LCtx.Keys := LKeys;
  LCtx.CtrState := ACtrState;
  LCtx.MacState := ACbcMacState;
  LCtx.PMask := nil;
  LCtx.PIncrement := FIncrement;
  LCtx.BlockCount := NativeUInt(ABlockCount);
  if FDirection = TCipherKernelDirection.Encrypt then
  begin
    case FRounds of
      10: CcmFusedCtrCbcMacEnc128(@LCtx);
      12: CcmFusedCtrCbcMacEnc192(@LCtx);
    else
      CcmFusedCtrCbcMacEnc256(@LCtx);
    end;
  end
  else
  begin
    case FRounds of
      10: CcmFusedCtrCbcMacDec128(@LCtx);
      12: CcmFusedCtrCbcMacDec192(@LCtx);
    else
      CcmFusedCtrCbcMacDec256(@LCtx);
    end;
  end;
{$ENDIF CRYPTOLIB_AARCH64_ASM}
end;

{ TAesCryptoExtCcmKernelFactory }

function TAesCryptoExtCcmKernelFactory.ProviderName: String;
begin
  Result := 'AES-CryptoExt';
end;

function TAesCryptoExtCcmKernelFactory.TryCreate(const ACipher: IBlockCipher;
  ADirection: TCipherKernelDirection; out AKernel: ICcmKernel): Boolean;
var
  LEngine: IAesEngineArm;
  LKeys: PByte;
  LRounds: Int32;
begin
  AKernel := nil;
  Result := False;
  try
{$IFDEF CRYPTOLIB_AARCH64_ASM}
    if not TAesFusedAeadSimd.CpuSupports then
      Exit;
    if not TAesCryptoExtFusedArmBackend.TryResolveEngine(ACipher, LEngine) then
      Exit;
    // CCM drives CTR and CBC-MAC lanes from the same forward-encrypt
    // schedule for both directions. LKeys is consumed only to probe
    // that the engine currently holds a usable encrypt schedule and to
    // read the round count; the pointer itself is intentionally not
    // handed to the kernel -- ProcessBody re-resolves it per call to
    // stay correct across engine re-keys.
    if not LEngine.TryGetEncKeysPtr(LKeys, LRounds) then
      Exit;
    if not (LRounds in [10, 12, 14]) then
      Exit;
    AKernel := TAesCryptoExtCcmKernel.Create(LEngine, LRounds, ADirection,
      @CcmKernelCtrIncrement[0]);
    Result := True;
{$ENDIF CRYPTOLIB_AARCH64_ASM}
  except
    AKernel := nil;
    Result := False;
  end;
end;

initialization
  TCipherKernelRegistry.Register(
    TAesCryptoExtCcmKernelFactory.Create() as ICcmKernelFactory);

end.
