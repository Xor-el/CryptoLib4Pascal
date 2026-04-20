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

unit ClpAesNiEaxKernel;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpIBlockCipher,
  ClpIAesEngineX86,
  ClpFusedKernelTypes,
  ClpIFusedEaxKernel,
  ClpFusedKernelRegistry,
  ClpAesNiAeadResolver;

type
  /// <summary>
  ///   AES-NI + SSSE3 implementation of IFusedEaxKernel.
  ///   Available on x86_64 (CRYPTOLIB_X86_64_ASM) and i386
  ///   (CRYPTOLIB_I386_ASM); both arms gated collectively by
  ///   CRYPTOLIB_X86_SIMD.
  ///   Direction-bound at construction: an encrypt kernel captures the
  ///   forward AES schedule, a decrypt kernel the inverse-MixColumns
  ///   schedule.
  ///   The kernel loops internally over ABlockCount body blocks in a
  ///   2-wide CTR + OMAC (CBC-MAC variant) interleave; the mode invokes
  ///   ProcessBody once per Init cycle.
  ///   Novel work in CryptoLib: no mainstream cryptographic library
  ///   ships a fused EAX kernel (OpenSSL, BoringSSL, AWS-LC, Botan all
  ///   scalar).
  /// </summary>
  TAesNiEaxKernel = class sealed(TInterfacedObject, IFusedEaxKernel)
  strict private
  const
    FUSED_EAX_MIN_BLOCKS = 2;
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
    procedure ProcessBody(AInPtr, AOutPtr, ACtrState, AOmacState: Pointer;
      ABlockCount: Int32);
  end;

  TAesNiEaxKernelFactory = class sealed(TInterfacedObject,
    IFusedEaxKernelFactory)
  public
    function ProviderName: String;
    function Priority: TFusedKernelPriority;
    function TryCreate(const ACipher: IBlockCipher;
      ADirection: TFusedModeDirection;
      out AKernel: IFusedEaxKernel): Boolean;
  end;

implementation

{$IFDEF CRYPTOLIB_X86_SIMD}
type
  // Context handed to the 2-wide fused AES-NI EAX CTR+OMAC kernel.
  // OutPtr may alias InPtr. Seven pointers + NativeUInt; natural
  // alignment matches the kernel's [rcx+offset] / [ebx+offset]
  // accesses on x86_64 and i386 respectively.
  TEaxFusedTwoCtx = record
    InPtr: Pointer;
    OutPtr: Pointer;
    Keys: Pointer;
    CtrState: Pointer;
    OmacState: Pointer;
    PMask: Pointer;
    PIncrement: Pointer;
    BlockCount: NativeUInt;
  end;
{$ENDIF CRYPTOLIB_X86_SIMD}

{$IFDEF CRYPTOLIB_X86_64_ASM}

procedure EaxFusedCtrOmacEnc128(PCtx: Pointer);
{$DEFINE CRYPTOLIB_AESNI_KEY128}
{$I ..\..\..\Include\Simd\Common\SimdProc1Begin_x86_64.inc}
{$I ..\..\..\Include\Simd\Aes\Eax\EaxFusedCtrOmacTwo_x86_64.inc}
{$UNDEF CRYPTOLIB_AESNI_KEY128}
end;

procedure EaxFusedCtrOmacEnc192(PCtx: Pointer);
{$DEFINE CRYPTOLIB_AESNI_KEY192}
{$I ..\..\..\Include\Simd\Common\SimdProc1Begin_x86_64.inc}
{$I ..\..\..\Include\Simd\Aes\Eax\EaxFusedCtrOmacTwo_x86_64.inc}
{$UNDEF CRYPTOLIB_AESNI_KEY192}
end;

procedure EaxFusedCtrOmacEnc256(PCtx: Pointer);
{$DEFINE CRYPTOLIB_AESNI_KEY256}
{$I ..\..\..\Include\Simd\Common\SimdProc1Begin_x86_64.inc}
{$I ..\..\..\Include\Simd\Aes\Eax\EaxFusedCtrOmacTwo_x86_64.inc}
{$UNDEF CRYPTOLIB_AESNI_KEY256}
end;

procedure EaxFusedCtrOmacDec128(PCtx: Pointer);
{$DEFINE CRYPTOLIB_AESNI_KEY128}
{$DEFINE CRYPTOLIB_EAX_DECRYPT}
{$I ..\..\..\Include\Simd\Common\SimdProc1Begin_x86_64.inc}
{$I ..\..\..\Include\Simd\Aes\Eax\EaxFusedCtrOmacTwo_x86_64.inc}
{$UNDEF CRYPTOLIB_EAX_DECRYPT}
{$UNDEF CRYPTOLIB_AESNI_KEY128}
end;

procedure EaxFusedCtrOmacDec192(PCtx: Pointer);
{$DEFINE CRYPTOLIB_AESNI_KEY192}
{$DEFINE CRYPTOLIB_EAX_DECRYPT}
{$I ..\..\..\Include\Simd\Common\SimdProc1Begin_x86_64.inc}
{$I ..\..\..\Include\Simd\Aes\Eax\EaxFusedCtrOmacTwo_x86_64.inc}
{$UNDEF CRYPTOLIB_EAX_DECRYPT}
{$UNDEF CRYPTOLIB_AESNI_KEY192}
end;

procedure EaxFusedCtrOmacDec256(PCtx: Pointer);
{$DEFINE CRYPTOLIB_AESNI_KEY256}
{$DEFINE CRYPTOLIB_EAX_DECRYPT}
{$I ..\..\..\Include\Simd\Common\SimdProc1Begin_x86_64.inc}
{$I ..\..\..\Include\Simd\Aes\Eax\EaxFusedCtrOmacTwo_x86_64.inc}
{$UNDEF CRYPTOLIB_EAX_DECRYPT}
{$UNDEF CRYPTOLIB_AESNI_KEY256}
end;

{$ENDIF CRYPTOLIB_X86_64_ASM}

{$IFDEF CRYPTOLIB_I386_ASM}

procedure EaxFusedCtrOmacEnc128(PCtx: Pointer);
{$DEFINE CRYPTOLIB_AESNI_KEY128}
{$I ..\..\..\Include\Simd\Common\SimdProc1Begin_i386.inc}
{$I ..\..\..\Include\Simd\Aes\Eax\EaxFusedCtrOmacTwo_i386.inc}
{$UNDEF CRYPTOLIB_AESNI_KEY128}
end;

procedure EaxFusedCtrOmacEnc192(PCtx: Pointer);
{$DEFINE CRYPTOLIB_AESNI_KEY192}
{$I ..\..\..\Include\Simd\Common\SimdProc1Begin_i386.inc}
{$I ..\..\..\Include\Simd\Aes\Eax\EaxFusedCtrOmacTwo_i386.inc}
{$UNDEF CRYPTOLIB_AESNI_KEY192}
end;

procedure EaxFusedCtrOmacEnc256(PCtx: Pointer);
{$DEFINE CRYPTOLIB_AESNI_KEY256}
{$I ..\..\..\Include\Simd\Common\SimdProc1Begin_i386.inc}
{$I ..\..\..\Include\Simd\Aes\Eax\EaxFusedCtrOmacTwo_i386.inc}
{$UNDEF CRYPTOLIB_AESNI_KEY256}
end;

procedure EaxFusedCtrOmacDec128(PCtx: Pointer);
{$DEFINE CRYPTOLIB_AESNI_KEY128}
{$DEFINE CRYPTOLIB_EAX_DECRYPT}
{$I ..\..\..\Include\Simd\Common\SimdProc1Begin_i386.inc}
{$I ..\..\..\Include\Simd\Aes\Eax\EaxFusedCtrOmacTwo_i386.inc}
{$UNDEF CRYPTOLIB_EAX_DECRYPT}
{$UNDEF CRYPTOLIB_AESNI_KEY128}
end;

procedure EaxFusedCtrOmacDec192(PCtx: Pointer);
{$DEFINE CRYPTOLIB_AESNI_KEY192}
{$DEFINE CRYPTOLIB_EAX_DECRYPT}
{$I ..\..\..\Include\Simd\Common\SimdProc1Begin_i386.inc}
{$I ..\..\..\Include\Simd\Aes\Eax\EaxFusedCtrOmacTwo_i386.inc}
{$UNDEF CRYPTOLIB_EAX_DECRYPT}
{$UNDEF CRYPTOLIB_AESNI_KEY192}
end;

procedure EaxFusedCtrOmacDec256(PCtx: Pointer);
{$DEFINE CRYPTOLIB_AESNI_KEY256}
{$DEFINE CRYPTOLIB_EAX_DECRYPT}
{$I ..\..\..\Include\Simd\Common\SimdProc1Begin_i386.inc}
{$I ..\..\..\Include\Simd\Aes\Eax\EaxFusedCtrOmacTwo_i386.inc}
{$UNDEF CRYPTOLIB_EAX_DECRYPT}
{$UNDEF CRYPTOLIB_AESNI_KEY256}
end;

{$ENDIF CRYPTOLIB_I386_ASM}

const
  // PSHUFB full-reverse control: flips a BE counter to LE for paddq
  // then back.
  EaxKernelReverseMask: packed array[0..15] of Byte = (
    $0F, $0E, $0D, $0C, $0B, $0A, $09, $08,
    $07, $06, $05, $04, $03, $02, $01, $00);
  // CTR +1 in the low 64-bit LE limb (applied after PSHUFB byte-reverse
  // then undone). EAX's counter is a full 128-bit BE integer seeded to
  // OMAC_K^0(N); 64-bit arithmetic is sufficient in practice -- the
  // counter only needs to cover at most ceil(body_bytes / 16) steps
  // before the stream would exceed 2^64 blocks.
  EaxKernelCtrIncrement: packed array[0..15] of Byte = (
    $01, $00, $00, $00, $00, $00, $00, $00,
    $00, $00, $00, $00, $00, $00, $00, $00);

{ TAesNiEaxKernel }

constructor TAesNiEaxKernel.Create(const AEngine: IAesEngineX86;
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

function TAesNiEaxKernel.MinimumBlockCount: Int32;
begin
  Result := FUSED_EAX_MIN_BLOCKS;
end;

procedure TAesNiEaxKernel.ProcessBody(AInPtr, AOutPtr, ACtrState,
  AOmacState: Pointer; ABlockCount: Int32);
{$IFDEF CRYPTOLIB_X86_SIMD}
var
  LCtx: TEaxFusedTwoCtx;
{$ENDIF CRYPTOLIB_X86_SIMD}
begin
{$IFDEF CRYPTOLIB_X86_SIMD}
  if ABlockCount < FUSED_EAX_MIN_BLOCKS then
    Exit;
  LCtx.InPtr := AInPtr;
  LCtx.OutPtr := AOutPtr;
  LCtx.Keys := FKeys;
  LCtx.CtrState := ACtrState;
  LCtx.OmacState := AOmacState;
  LCtx.PMask := FMask;
  LCtx.PIncrement := FIncrement;
  LCtx.BlockCount := NativeUInt(ABlockCount);
  if FDirection = TFusedModeDirection.Encrypt then
  begin
    case FRounds of
      10: EaxFusedCtrOmacEnc128(@LCtx);
      12: EaxFusedCtrOmacEnc192(@LCtx);
    else
      EaxFusedCtrOmacEnc256(@LCtx);
    end;
  end
  else
  begin
    case FRounds of
      10: EaxFusedCtrOmacDec128(@LCtx);
      12: EaxFusedCtrOmacDec192(@LCtx);
    else
      EaxFusedCtrOmacDec256(@LCtx);
    end;
  end;
{$ENDIF CRYPTOLIB_X86_SIMD}
end;

{ TAesNiEaxKernelFactory }

function TAesNiEaxKernelFactory.ProviderName: String;
begin
  Result := 'AES-NI';
end;

function TAesNiEaxKernelFactory.Priority: TFusedKernelPriority;
begin
  Result := TFusedKernelPriority.Baseline;
end;

function TAesNiEaxKernelFactory.TryCreate(const ACipher: IBlockCipher;
  ADirection: TFusedModeDirection; out AKernel: IFusedEaxKernel): Boolean;
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
    // EAX drives CTR and OMAC lanes from the same forward-encrypt
    // schedule for both directions.
    if not LEngine.TryGetEncKeysPtr(LKeys, LRounds) then
      Exit;
    if not (LRounds in [10, 12, 14]) then
      Exit;
    AKernel := TAesNiEaxKernel.Create(LEngine, LKeys, LRounds, ADirection,
      @EaxKernelReverseMask[0], @EaxKernelCtrIncrement[0]);
    Result := True;
  except
    AKernel := nil;
    Result := False;
  end;
end;

initialization
  TFusedKernelRegistry.RegisterEaxFactory(
    TAesNiEaxKernelFactory.Create() as IFusedEaxKernelFactory);

end.
