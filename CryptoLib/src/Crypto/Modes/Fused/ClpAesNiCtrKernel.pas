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

unit ClpAesNiCtrKernel;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpIBlockCipher,
  ClpIAesEngineX86,
  ClpFusedKernelTypes,
  ClpIFusedCtrKernel,
  ClpFusedKernelRegistry,
  ClpAesNiFusedX86Backend;

type
  /// <summary>
  ///   AES-NI implementation of IFusedCtrKernel: the fused counter-mode
  ///   keystream + XOR body used by TSicBlockCipher's bulk path. The MAC-free
  ///   base of the fused-kernel family; reuses the plain 8-wide AES round chain
  ///   (AesNiEightRoundsOnly) since CTR has no extra per-block state.
  ///   Available on x86_64 (CRYPTOLIB_X86_64_ASM) and i386 (CRYPTOLIB_I386_ASM);
  ///   both arms gated collectively by CRYPTOLIB_X86_SIMD. When unavailable the
  ///   factory returns nil and TSicBlockCipher keeps its existing bulk path.
  /// </summary>
  TAesNiCtrKernel = class sealed(TInterfacedObject, IFusedCtrKernel)
  strict private
  const
    FUSED_CTR_BATCH_BLOCKS = 8;
  strict private
    // FEngine is retained so the round-key buffer FKeys points into stays alive
    // for the kernel's lifetime.
    FEngine: IAesEngineX86;
    FKeys: Pointer;
    FRounds: Int32;
  public
    constructor Create(const AEngine: IAesEngineX86; AKeys: Pointer;
      ARounds: Int32);
    function BatchBlockCount: Int32;
    procedure ProcessCtrBlocks(AInPtr, AOutPtr, ACounter: Pointer;
      ABlockCount: NativeInt);
  end;

  TAesNiCtrKernelFactory = class sealed(TInterfacedObject, IFusedCtrKernelFactory)
  public
    function ProviderName: String;
    function Priority: TFusedKernelPriority;
    function TryCreate(const ACipher: IBlockCipher;
      ADirection: TFusedModeDirection;
      out AKernel: IFusedCtrKernel): Boolean;
  end;

implementation

{$IFDEF CRYPTOLIB_X86_SIMD}

// Fused AES-NI CTR keystream + XOR (encrypt-only; CTR keystream is the same for
// encrypt and decrypt). Each proc processes ABlkCount blocks (a multiple of 8),
// looping internally, and advances the 16-byte big-endian counter in place.
procedure AesNiCtrEnc128(AIn, AOut, AKeys, ACounter: PByte; ABlkCount: NativeInt);
{$DEFINE CRYPTOLIB_AESNI_KEY128}
{$IFDEF CRYPTOLIB_X86_64_ASM}
{$I ..\..\..\Include\Simd\Common\SimdProc5Begin_x86_64.inc}
{$I ..\..\..\Include\Simd\Aes\Ctr\AesNiCtrEight_x86_64.inc}
{$ENDIF}
{$IFDEF CRYPTOLIB_I386_ASM}
{$I ..\..\..\Include\Simd\Common\SimdProc5Begin_i386.inc}
{$I ..\..\..\Include\Simd\Aes\Ctr\AesNiCtrEight_i386.inc}
{$ENDIF}
{$UNDEF CRYPTOLIB_AESNI_KEY128}
end;

procedure AesNiCtrEnc192(AIn, AOut, AKeys, ACounter: PByte; ABlkCount: NativeInt);
{$DEFINE CRYPTOLIB_AESNI_KEY192}
{$IFDEF CRYPTOLIB_X86_64_ASM}
{$I ..\..\..\Include\Simd\Common\SimdProc5Begin_x86_64.inc}
{$I ..\..\..\Include\Simd\Aes\Ctr\AesNiCtrEight_x86_64.inc}
{$ENDIF}
{$IFDEF CRYPTOLIB_I386_ASM}
{$I ..\..\..\Include\Simd\Common\SimdProc5Begin_i386.inc}
{$I ..\..\..\Include\Simd\Aes\Ctr\AesNiCtrEight_i386.inc}
{$ENDIF}
{$UNDEF CRYPTOLIB_AESNI_KEY192}
end;

procedure AesNiCtrEnc256(AIn, AOut, AKeys, ACounter: PByte; ABlkCount: NativeInt);
{$DEFINE CRYPTOLIB_AESNI_KEY256}
{$IFDEF CRYPTOLIB_X86_64_ASM}
{$I ..\..\..\Include\Simd\Common\SimdProc5Begin_x86_64.inc}
{$I ..\..\..\Include\Simd\Aes\Ctr\AesNiCtrEight_x86_64.inc}
{$ENDIF}
{$IFDEF CRYPTOLIB_I386_ASM}
{$I ..\..\..\Include\Simd\Common\SimdProc5Begin_i386.inc}
{$I ..\..\..\Include\Simd\Aes\Ctr\AesNiCtrEight_i386.inc}
{$ENDIF}
{$UNDEF CRYPTOLIB_AESNI_KEY256}
end;

{$ENDIF CRYPTOLIB_X86_SIMD}

{ TAesNiCtrKernel }

constructor TAesNiCtrKernel.Create(const AEngine: IAesEngineX86; AKeys: Pointer;
  ARounds: Int32);
begin
  inherited Create;
  FEngine := AEngine;
  FKeys := AKeys;
  FRounds := ARounds;
end;

function TAesNiCtrKernel.BatchBlockCount: Int32;
begin
  Result := FUSED_CTR_BATCH_BLOCKS;
end;

procedure TAesNiCtrKernel.ProcessCtrBlocks(AInPtr, AOutPtr, ACounter: Pointer;
  ABlockCount: NativeInt);
begin
{$IFDEF CRYPTOLIB_X86_SIMD}
  case FRounds of
    10:
      AesNiCtrEnc128(PByte(AInPtr), PByte(AOutPtr), PByte(FKeys),
        PByte(ACounter), ABlockCount);
    12:
      AesNiCtrEnc192(PByte(AInPtr), PByte(AOutPtr), PByte(FKeys),
        PByte(ACounter), ABlockCount);
  else
    AesNiCtrEnc256(PByte(AInPtr), PByte(AOutPtr), PByte(FKeys),
      PByte(ACounter), ABlockCount);
  end;
{$ENDIF CRYPTOLIB_X86_SIMD}
end;

{ TAesNiCtrKernelFactory }

function TAesNiCtrKernelFactory.ProviderName: String;
begin
  Result := 'AES-NI';
end;

function TAesNiCtrKernelFactory.Priority: TFusedKernelPriority;
begin
  Result := TFusedKernelPriority.Baseline;
end;

function TAesNiCtrKernelFactory.TryCreate(const ACipher: IBlockCipher;
  ADirection: TFusedModeDirection; out AKernel: IFusedCtrKernel): Boolean;
var
  LEngine: IAesEngineX86;
  LKeys: PByte;
  LRounds: Int32;
begin
  AKernel := nil;
  Result := False;
  try
{$IFDEF CRYPTOLIB_X86_SIMD}
    if not TAesNiFusedX86Backend.TryResolveEngine(ACipher, LEngine) then
      Exit;
    if not LEngine.TryGetEncKeysPtr(LKeys, LRounds) then
      Exit;
    if not (LRounds in [10, 12, 14]) then
      Exit;
    AKernel := TAesNiCtrKernel.Create(LEngine, LKeys, LRounds);
    Result := True;
{$ENDIF CRYPTOLIB_X86_SIMD}
  except
    AKernel := nil;
    Result := False;
  end;
end;

initialization
  TFusedKernelRegistry.RegisterCtrFactory(
    TAesNiCtrKernelFactory.Create() as IFusedCtrKernelFactory);

end.
