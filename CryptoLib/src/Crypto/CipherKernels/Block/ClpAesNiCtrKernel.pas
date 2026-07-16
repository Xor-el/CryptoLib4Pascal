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
  ClpCipherKernelTypes,
  ClpICtrKernel,
  ClpCipherKernelFactoryBase,
  ClpCipherKernelRegistry,
  ClpAesNiFusedX86Backend;

type
  /// <summary>
  ///   AES-NI implementation of ICtrKernel: the fused counter-mode
  ///   keystream + XOR body used by TSicBlockCipher's bulk path. The MAC-free
  ///   base of the fused-kernel family; runs a plain 8-wide AES round chain
  ///   since CTR has no extra per-block state.
  ///   Available on x86_64 (CRYPTOLIB_X86_64_ASM) and i386 (CRYPTOLIB_I386_ASM);
  ///   both arms gated collectively by CRYPTOLIB_X86_SIMD. When unavailable the
  ///   factory returns nil and TSicBlockCipher keeps its existing bulk path.
  /// </summary>
  TAesNiCtrKernel = class sealed(TInterfacedObject, ICtrKernel)
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

  TAesNiCtrKernelFactory = class sealed(TCipherKernelFactoryBase, ICtrKernelFactory)
  public
    function ProviderName: String; override;
    function TryCreate(const ACipher: IBlockCipher;
      ADirection: TCipherKernelDirection;
      out AKernel: ICtrKernel): Boolean;
  end;

implementation

{$IFDEF CRYPTOLIB_X86_SIMD}

type
  // Context handed to the fused AES-NI CTR keystream + XOR kernel. Field offsets
  // match the [rcx + N] / [ebx + N] accesses in AesNiCtrEight_x86_64.inc and
  // AesNiCtrEight_i386.inc (8-byte fields on x86_64, 4-byte on i386). The kernel
  // loops internally over BlockCount blocks, advancing InPtr/OutPtr and the
  // 16-byte big-endian counter at CounterPtr in place.
  TCtrFusedCtx = record
    InPtr: Pointer;
    OutPtr: Pointer;
    KeysPtr: Pointer;
    CounterPtr: Pointer;
    BlockCount: NativeUInt;
  end;

// Fused AES-NI CTR keystream + XOR (encrypt-only; CTR keystream is the same for
// encrypt and decrypt). Each proc processes BlockCount blocks (a multiple of 8),
// looping internally, and advances the 16-byte big-endian counter in place.
procedure AesNiCtrEnc128(PCtx: Pointer);
{$DEFINE CRYPTOLIB_AESNI_KEY128}
{$IFDEF CRYPTOLIB_X86_64_ASM}
{$I ..\..\..\Include\Simd\Common\ClpSimdProc1Begin_x86_64.inc}
{$I ..\..\..\Include\Simd\Aes\Ctr\AesNiCtrEight_x86_64.inc}
{$ENDIF}
{$IFDEF CRYPTOLIB_I386_ASM}
{$I ..\..\..\Include\Simd\Common\ClpSimdProc1Begin_i386.inc}
{$I ..\..\..\Include\Simd\Aes\Ctr\AesNiCtrEight_i386.inc}
{$ENDIF}
{$UNDEF CRYPTOLIB_AESNI_KEY128}
end;

procedure AesNiCtrEnc192(PCtx: Pointer);
{$DEFINE CRYPTOLIB_AESNI_KEY192}
{$IFDEF CRYPTOLIB_X86_64_ASM}
{$I ..\..\..\Include\Simd\Common\ClpSimdProc1Begin_x86_64.inc}
{$I ..\..\..\Include\Simd\Aes\Ctr\AesNiCtrEight_x86_64.inc}
{$ENDIF}
{$IFDEF CRYPTOLIB_I386_ASM}
{$I ..\..\..\Include\Simd\Common\ClpSimdProc1Begin_i386.inc}
{$I ..\..\..\Include\Simd\Aes\Ctr\AesNiCtrEight_i386.inc}
{$ENDIF}
{$UNDEF CRYPTOLIB_AESNI_KEY192}
end;

procedure AesNiCtrEnc256(PCtx: Pointer);
{$DEFINE CRYPTOLIB_AESNI_KEY256}
{$IFDEF CRYPTOLIB_X86_64_ASM}
{$I ..\..\..\Include\Simd\Common\ClpSimdProc1Begin_x86_64.inc}
{$I ..\..\..\Include\Simd\Aes\Ctr\AesNiCtrEight_x86_64.inc}
{$ENDIF}
{$IFDEF CRYPTOLIB_I386_ASM}
{$I ..\..\..\Include\Simd\Common\ClpSimdProc1Begin_i386.inc}
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
{$IFDEF CRYPTOLIB_X86_SIMD}
var
  LCtx: TCtrFusedCtx;
{$ENDIF CRYPTOLIB_X86_SIMD}
begin
{$IFDEF CRYPTOLIB_X86_SIMD}
  LCtx.InPtr := AInPtr;
  LCtx.OutPtr := AOutPtr;
  LCtx.KeysPtr := FKeys;
  LCtx.CounterPtr := ACounter;
  LCtx.BlockCount := NativeUInt(ABlockCount);
  case FRounds of
    10: AesNiCtrEnc128(@LCtx);
    12: AesNiCtrEnc192(@LCtx);
  else
    AesNiCtrEnc256(@LCtx);
  end;
{$ENDIF CRYPTOLIB_X86_SIMD}
end;

{ TAesNiCtrKernelFactory }

function TAesNiCtrKernelFactory.ProviderName: String;
begin
  Result := 'AES-NI';
end;

function TAesNiCtrKernelFactory.TryCreate(const ACipher: IBlockCipher;
  ADirection: TCipherKernelDirection; out AKernel: ICtrKernel): Boolean;
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
  TCipherKernelRegistry.Register(
    TAesNiCtrKernelFactory.Create() as ICtrKernelFactory);

end.
