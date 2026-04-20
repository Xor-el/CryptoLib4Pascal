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

unit ClpAesNiCcmKernel;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpIBlockCipher,
  ClpIAesEngineX86,
  ClpFusedModeDirection,
  ClpIFusedCcmKernel,
  ClpFusedKernelRegistry,
  ClpAesNiAeadResolver;

type
  /// <summary>
  ///   AES-NI / SSSE3 implementation of IFusedCcmKernel. Loops
  ///   internally over ABlockCount body blocks; the mode invokes
  ///   ProcessBody once per Init cycle.
  /// </summary>
  TAesNiCcmKernel = class sealed(TInterfacedObject, IFusedCcmKernel)
  strict private
  const
    FUSED_CCM_MIN_BLOCKS = 1;
  strict private
    FEngine: IAesEngineX86;
    FKeys: Pointer;
    FRounds: Int32;
    FDirection: TFusedModeDirection;
    FMask: Pointer;
    FIncrement: Pointer;
  public
    constructor Create(const AEngine: IAesEngineX86; AKeys: Pointer;
      ARounds: Int32; ADirection: TFusedModeDirection; AMask, AIncrement: Pointer);
    function MinimumBlockCount: Int32;
    procedure ProcessBody(AInPtr, AOutPtr, ACtrState, ACbcMacState: Pointer;
      ABlockCount: Int32);
  end;

  TAesNiCcmKernelFactory = class sealed(TInterfacedObject,
    IFusedCcmKernelFactory)
  public
    function ProviderName: String;
    function Priority: TFusedKernelPriority;
    function TryCreate(const ACipher: IBlockCipher;
      ADirection: TFusedModeDirection;
      out AKernel: IFusedCcmKernel): Boolean;
  end;

implementation

{$IFDEF CRYPTOLIB_X86_SIMD}
type
  // Context handed to the 2-wide fused AES-NI CCM CTR+CBC-MAC kernel.
  // OutPtr may alias InPtr. Seven pointers + NativeUInt; natural
  // alignment matches the kernel's [rcx+offset] accesses.
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
{$ENDIF CRYPTOLIB_X86_SIMD}

{$IFDEF CRYPTOLIB_X86_64_ASM}

procedure CcmFusedCtrCbcMacEnc128(PCtx: Pointer);
{$DEFINE CRYPTOLIB_AESNI_KEY128}
{$I ..\..\..\Include\Simd\Common\SimdProc1Begin_x86_64.inc}
{$I ..\..\..\Include\Simd\Aes\Ccm\CcmFusedCtrCbcMacTwo_x86_64.inc}
{$UNDEF CRYPTOLIB_AESNI_KEY128}
end;

procedure CcmFusedCtrCbcMacEnc192(PCtx: Pointer);
{$DEFINE CRYPTOLIB_AESNI_KEY192}
{$I ..\..\..\Include\Simd\Common\SimdProc1Begin_x86_64.inc}
{$I ..\..\..\Include\Simd\Aes\Ccm\CcmFusedCtrCbcMacTwo_x86_64.inc}
{$UNDEF CRYPTOLIB_AESNI_KEY192}
end;

procedure CcmFusedCtrCbcMacEnc256(PCtx: Pointer);
{$DEFINE CRYPTOLIB_AESNI_KEY256}
{$I ..\..\..\Include\Simd\Common\SimdProc1Begin_x86_64.inc}
{$I ..\..\..\Include\Simd\Aes\Ccm\CcmFusedCtrCbcMacTwo_x86_64.inc}
{$UNDEF CRYPTOLIB_AESNI_KEY256}
end;

procedure CcmFusedCtrCbcMacDec128(PCtx: Pointer);
{$DEFINE CRYPTOLIB_AESNI_KEY128}
{$DEFINE CRYPTOLIB_CCM_DECRYPT}
{$I ..\..\..\Include\Simd\Common\SimdProc1Begin_x86_64.inc}
{$I ..\..\..\Include\Simd\Aes\Ccm\CcmFusedCtrCbcMacTwo_x86_64.inc}
{$UNDEF CRYPTOLIB_CCM_DECRYPT}
{$UNDEF CRYPTOLIB_AESNI_KEY128}
end;

procedure CcmFusedCtrCbcMacDec192(PCtx: Pointer);
{$DEFINE CRYPTOLIB_AESNI_KEY192}
{$DEFINE CRYPTOLIB_CCM_DECRYPT}
{$I ..\..\..\Include\Simd\Common\SimdProc1Begin_x86_64.inc}
{$I ..\..\..\Include\Simd\Aes\Ccm\CcmFusedCtrCbcMacTwo_x86_64.inc}
{$UNDEF CRYPTOLIB_CCM_DECRYPT}
{$UNDEF CRYPTOLIB_AESNI_KEY192}
end;

procedure CcmFusedCtrCbcMacDec256(PCtx: Pointer);
{$DEFINE CRYPTOLIB_AESNI_KEY256}
{$DEFINE CRYPTOLIB_CCM_DECRYPT}
{$I ..\..\..\Include\Simd\Common\SimdProc1Begin_x86_64.inc}
{$I ..\..\..\Include\Simd\Aes\Ccm\CcmFusedCtrCbcMacTwo_x86_64.inc}
{$UNDEF CRYPTOLIB_CCM_DECRYPT}
{$UNDEF CRYPTOLIB_AESNI_KEY256}
end;

{$ENDIF CRYPTOLIB_X86_64_ASM}

{$IFDEF CRYPTOLIB_I386_ASM}

procedure CcmFusedCtrCbcMacEnc128(PCtx: Pointer);
{$DEFINE CRYPTOLIB_AESNI_KEY128}
{$I ..\..\..\Include\Simd\Common\SimdProc1Begin_i386.inc}
{$I ..\..\..\Include\Simd\Aes\Ccm\CcmFusedCtrCbcMacTwo_i386.inc}
{$UNDEF CRYPTOLIB_AESNI_KEY128}
end;

procedure CcmFusedCtrCbcMacEnc192(PCtx: Pointer);
{$DEFINE CRYPTOLIB_AESNI_KEY192}
{$I ..\..\..\Include\Simd\Common\SimdProc1Begin_i386.inc}
{$I ..\..\..\Include\Simd\Aes\Ccm\CcmFusedCtrCbcMacTwo_i386.inc}
{$UNDEF CRYPTOLIB_AESNI_KEY192}
end;

procedure CcmFusedCtrCbcMacEnc256(PCtx: Pointer);
{$DEFINE CRYPTOLIB_AESNI_KEY256}
{$I ..\..\..\Include\Simd\Common\SimdProc1Begin_i386.inc}
{$I ..\..\..\Include\Simd\Aes\Ccm\CcmFusedCtrCbcMacTwo_i386.inc}
{$UNDEF CRYPTOLIB_AESNI_KEY256}
end;

procedure CcmFusedCtrCbcMacDec128(PCtx: Pointer);
{$DEFINE CRYPTOLIB_AESNI_KEY128}
{$DEFINE CRYPTOLIB_CCM_DECRYPT}
{$I ..\..\..\Include\Simd\Common\SimdProc1Begin_i386.inc}
{$I ..\..\..\Include\Simd\Aes\Ccm\CcmFusedCtrCbcMacTwo_i386.inc}
{$UNDEF CRYPTOLIB_CCM_DECRYPT}
{$UNDEF CRYPTOLIB_AESNI_KEY128}
end;

procedure CcmFusedCtrCbcMacDec192(PCtx: Pointer);
{$DEFINE CRYPTOLIB_AESNI_KEY192}
{$DEFINE CRYPTOLIB_CCM_DECRYPT}
{$I ..\..\..\Include\Simd\Common\SimdProc1Begin_i386.inc}
{$I ..\..\..\Include\Simd\Aes\Ccm\CcmFusedCtrCbcMacTwo_i386.inc}
{$UNDEF CRYPTOLIB_CCM_DECRYPT}
{$UNDEF CRYPTOLIB_AESNI_KEY192}
end;

procedure CcmFusedCtrCbcMacDec256(PCtx: Pointer);
{$DEFINE CRYPTOLIB_AESNI_KEY256}
{$DEFINE CRYPTOLIB_CCM_DECRYPT}
{$I ..\..\..\Include\Simd\Common\SimdProc1Begin_i386.inc}
{$I ..\..\..\Include\Simd\Aes\Ccm\CcmFusedCtrCbcMacTwo_i386.inc}
{$UNDEF CRYPTOLIB_CCM_DECRYPT}
{$UNDEF CRYPTOLIB_AESNI_KEY256}
end;

{$ENDIF CRYPTOLIB_I386_ASM}

const
  // PSHUFB full-reverse control: flips a BE counter to LE for paddq
  // then back.
  CcmKernelReverseMask: packed array[0..15] of Byte = (
    $0F, $0E, $0D, $0C, $0B, $0A, $09, $08,
    $07, $06, $05, $04, $03, $02, $01, $00);
  // CTR +1 in the low 64-bit LE limb (applied after PSHUFB byte-reverse
  // then undone). Sufficient for CCM's <= 8-byte counter field.
  CcmKernelCtrIncrement: packed array[0..15] of Byte = (
    $01, $00, $00, $00, $00, $00, $00, $00,
    $00, $00, $00, $00, $00, $00, $00, $00);

{ TAesNiCcmKernel }

constructor TAesNiCcmKernel.Create(const AEngine: IAesEngineX86;
  AKeys: Pointer; ARounds: Int32; ADirection: TFusedModeDirection;
  AMask, AIncrement: Pointer);
begin
  inherited Create;
  FEngine := AEngine;
  FKeys := AKeys;
  FRounds := ARounds;
  FDirection := ADirection;
  FMask := AMask;
  FIncrement := AIncrement;
end;

function TAesNiCcmKernel.MinimumBlockCount: Int32;
begin
  Result := FUSED_CCM_MIN_BLOCKS;
end;

procedure TAesNiCcmKernel.ProcessBody(AInPtr, AOutPtr, ACtrState,
  ACbcMacState: Pointer; ABlockCount: Int32);
{$IFDEF CRYPTOLIB_X86_SIMD}
var
  LCtx: TCcmFusedTwoCtx;
{$ENDIF CRYPTOLIB_X86_SIMD}
begin
{$IFDEF CRYPTOLIB_X86_SIMD}
  if ABlockCount < FUSED_CCM_MIN_BLOCKS then
    Exit;
  LCtx.InPtr := AInPtr;
  LCtx.OutPtr := AOutPtr;
  LCtx.Keys := FKeys;
  LCtx.CtrState := ACtrState;
  LCtx.MacState := ACbcMacState;
  LCtx.PMask := FMask;
  LCtx.PIncrement := FIncrement;
  LCtx.BlockCount := NativeUInt(ABlockCount);
  if FDirection = TFusedModeDirection.Encrypt then
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
{$ENDIF CRYPTOLIB_X86_SIMD}
end;

{ TAesNiCcmKernelFactory }

function TAesNiCcmKernelFactory.ProviderName: String;
begin
  Result := 'AES-NI';
end;

function TAesNiCcmKernelFactory.Priority: TFusedKernelPriority;
begin
  Result := TFusedKernelPriority.Baseline;
end;

function TAesNiCcmKernelFactory.TryCreate(const ACipher: IBlockCipher;
  ADirection: TFusedModeDirection; out AKernel: IFusedCcmKernel): Boolean;
var
  LEngine: IAesEngineX86;
  LKeys: PByte;
  LRounds: Int32;
begin
  AKernel := nil;
  Result := False;
  try
    if not TAesNiAeadResolver.CpuSupports then
      Exit;
    if not TAesNiAeadResolver.TryResolveEngine(ACipher, LEngine) then
      Exit;
    // CCM drives CTR and CBC-MAC lanes from the same forward-encrypt
    // schedule for both directions.
    if not LEngine.TryGetEncKeysPtr(LKeys, LRounds) then
      Exit;
    if not (LRounds in [10, 12, 14]) then
      Exit;
    AKernel := TAesNiCcmKernel.Create(LEngine, LKeys, LRounds, ADirection,
      @CcmKernelReverseMask[0], @CcmKernelCtrIncrement[0]);
    Result := True;
  except
    AKernel := nil;
    Result := False;
  end;
end;

initialization
  TFusedKernelRegistry.RegisterCcmFactory(
    TAesNiCcmKernelFactory.Create() as IFusedCcmKernelFactory);

end.
