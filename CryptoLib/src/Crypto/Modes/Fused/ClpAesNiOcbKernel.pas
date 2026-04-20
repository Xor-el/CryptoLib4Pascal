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

unit ClpAesNiOcbKernel;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpIBlockCipher,
  ClpIAesEngineX86,
  ClpFusedKernelTypes,
  ClpIFusedOcbKernel,
  ClpFusedKernelRegistry,
  ClpAesNiAeadResolver;

type
  /// <summary>
  ///   AES-NI + SSSE3 implementation of IFusedOcbKernel.
  ///   Available on x86_64 (CRYPTOLIB_X86_64_ASM) and i386
  ///   (CRYPTOLIB_I386_ASM); both arms gated collectively by
  ///   CRYPTOLIB_X86_SIMD.
  ///   Direction-bound at construction: an encrypt kernel captures the
  ///   forward AES schedule, a decrypt kernel the inverse-MixColumns
  ///   schedule.
  ///   The kernel processes ABlockCount blocks in a single invocation,
  ///   looping internally over a fixed stride (8 blocks on x86_64,
  ///   4 blocks on i386) so the mode layer can amortise call-site
  ///   overhead across large batches.
  /// </summary>
  TAesNiOcbKernel = class sealed(TInterfacedObject, IFusedOcbKernel)
  strict private
  const
{$IFDEF CRYPTOLIB_X86_64_ASM}
    FUSED_OCB_MIN_BLOCKS = 8;
{$ELSE}
    FUSED_OCB_MIN_BLOCKS = 4;
{$ENDIF}
  strict private
    FEngine: IAesEngineX86;
    FKeys: Pointer;
    FRounds: Int32;
    FDirection: TFusedModeDirection;
  public
    constructor Create(const AEngine: IAesEngineX86; AKeys: Pointer;
      ARounds: Int32; ADirection: TFusedModeDirection);
    function MinimumBlockCount: Int32;
    procedure ProcessBlocks(AInPtr, AOutPtr, AOffsetPtr, AChecksumPtr,
      ALTablePtr, ANtzPtr, ABlock0Ptr: Pointer; ABlockCount: Int32);
  end;

  TAesNiOcbKernelFactory = class sealed(TInterfacedObject,
    IFusedOcbKernelFactory)
  public
    function ProviderName: String;
    function Priority: TFusedKernelPriority;
    function TryCreate(const ACipher: IBlockCipher;
      ADirection: TFusedModeDirection;
      out AKernel: IFusedOcbKernel): Boolean;
  end;

implementation

{$IFDEF CRYPTOLIB_X86_SIMD}

type
  /// <summary>
  ///   Context record shared with the assembly body. All live OCB state
  ///   the kernel touches is addressed through this record: seven
  ///   pointers (Keys, In, Out, OffsetState, ChecksumState, LTable,
  ///   NtzArray, Block0) plus the NativeUInt BlockCount. Field offsets
  ///   match the kernel's displacement accesses documented in
  ///   AesOcbFusedWide_x86_64.inc and AesOcbFusedWide_i386.inc.
  /// </summary>
  TOcbFusedKernelCtx = record
    Keys: Pointer;         // AES expanded schedule (enc / dec+invMC)
    InPtr: Pointer;        // ABlockCount * 16 bytes (advances per-iter)
    OutPtr: Pointer;       // ABlockCount * 16 bytes (advances per-iter)
    OffsetPtr: Pointer;    // 16-byte live FOffsetMAIN state (r/w)
    ChecksumPtr: Pointer;  // 16-byte live FChecksum state (r/w)
    LTablePtr: Pointer;    // flat L[0..LMax] * 16 bytes (read-only)
    NtzPtr: Pointer;       // ABlockCount bytes of pre-computed ntz
    Block0Ptr: Pointer;    // 16-byte source of iter-0 block 0 (may
                           // alias InPtr or point at an unrelated
                           // 16-byte buffer such as FMainBlock)
    BlockCount: NativeUInt; // positive multiple of MinimumBlockCount
  end;

procedure OcbFusedEncWide128(PCtx: Pointer);
{$DEFINE CRYPTOLIB_AESNI_KEY128}
{$IFDEF CRYPTOLIB_X86_64_ASM}
{$I ..\..\..\Include\Simd\Common\SimdProc1Begin_x86_64.inc}
{$I ..\..\..\Include\Simd\Aes\Ocb\AesOcbFusedWide_x86_64.inc}
{$ENDIF}
{$IFDEF CRYPTOLIB_I386_ASM}
{$I ..\..\..\Include\Simd\Common\SimdProc1Begin_i386.inc}
{$I ..\..\..\Include\Simd\Aes\Ocb\AesOcbFusedWide_i386.inc}
{$ENDIF}
{$UNDEF CRYPTOLIB_AESNI_KEY128}
end;

procedure OcbFusedEncWide192(PCtx: Pointer);
{$DEFINE CRYPTOLIB_AESNI_KEY192}
{$IFDEF CRYPTOLIB_X86_64_ASM}
{$I ..\..\..\Include\Simd\Common\SimdProc1Begin_x86_64.inc}
{$I ..\..\..\Include\Simd\Aes\Ocb\AesOcbFusedWide_x86_64.inc}
{$ENDIF}
{$IFDEF CRYPTOLIB_I386_ASM}
{$I ..\..\..\Include\Simd\Common\SimdProc1Begin_i386.inc}
{$I ..\..\..\Include\Simd\Aes\Ocb\AesOcbFusedWide_i386.inc}
{$ENDIF}
{$UNDEF CRYPTOLIB_AESNI_KEY192}
end;

procedure OcbFusedEncWide256(PCtx: Pointer);
{$DEFINE CRYPTOLIB_AESNI_KEY256}
{$IFDEF CRYPTOLIB_X86_64_ASM}
{$I ..\..\..\Include\Simd\Common\SimdProc1Begin_x86_64.inc}
{$I ..\..\..\Include\Simd\Aes\Ocb\AesOcbFusedWide_x86_64.inc}
{$ENDIF}
{$IFDEF CRYPTOLIB_I386_ASM}
{$I ..\..\..\Include\Simd\Common\SimdProc1Begin_i386.inc}
{$I ..\..\..\Include\Simd\Aes\Ocb\AesOcbFusedWide_i386.inc}
{$ENDIF}
{$UNDEF CRYPTOLIB_AESNI_KEY256}
end;

procedure OcbFusedDecWide128(PCtx: Pointer);
{$DEFINE CRYPTOLIB_AESNI_KEY128}
{$DEFINE CRYPTOLIB_AESNI_DECRYPT}
{$IFDEF CRYPTOLIB_X86_64_ASM}
{$I ..\..\..\Include\Simd\Common\SimdProc1Begin_x86_64.inc}
{$I ..\..\..\Include\Simd\Aes\Ocb\AesOcbFusedWide_x86_64.inc}
{$ENDIF}
{$IFDEF CRYPTOLIB_I386_ASM}
{$I ..\..\..\Include\Simd\Common\SimdProc1Begin_i386.inc}
{$I ..\..\..\Include\Simd\Aes\Ocb\AesOcbFusedWide_i386.inc}
{$ENDIF}
{$UNDEF CRYPTOLIB_AESNI_DECRYPT}
{$UNDEF CRYPTOLIB_AESNI_KEY128}
end;

procedure OcbFusedDecWide192(PCtx: Pointer);
{$DEFINE CRYPTOLIB_AESNI_KEY192}
{$DEFINE CRYPTOLIB_AESNI_DECRYPT}
{$IFDEF CRYPTOLIB_X86_64_ASM}
{$I ..\..\..\Include\Simd\Common\SimdProc1Begin_x86_64.inc}
{$I ..\..\..\Include\Simd\Aes\Ocb\AesOcbFusedWide_x86_64.inc}
{$ENDIF}
{$IFDEF CRYPTOLIB_I386_ASM}
{$I ..\..\..\Include\Simd\Common\SimdProc1Begin_i386.inc}
{$I ..\..\..\Include\Simd\Aes\Ocb\AesOcbFusedWide_i386.inc}
{$ENDIF}
{$UNDEF CRYPTOLIB_AESNI_DECRYPT}
{$UNDEF CRYPTOLIB_AESNI_KEY192}
end;

procedure OcbFusedDecWide256(PCtx: Pointer);
{$DEFINE CRYPTOLIB_AESNI_KEY256}
{$DEFINE CRYPTOLIB_AESNI_DECRYPT}
{$IFDEF CRYPTOLIB_X86_64_ASM}
{$I ..\..\..\Include\Simd\Common\SimdProc1Begin_x86_64.inc}
{$I ..\..\..\Include\Simd\Aes\Ocb\AesOcbFusedWide_x86_64.inc}
{$ENDIF}
{$IFDEF CRYPTOLIB_I386_ASM}
{$I ..\..\..\Include\Simd\Common\SimdProc1Begin_i386.inc}
{$I ..\..\..\Include\Simd\Aes\Ocb\AesOcbFusedWide_i386.inc}
{$ENDIF}
{$UNDEF CRYPTOLIB_AESNI_DECRYPT}
{$UNDEF CRYPTOLIB_AESNI_KEY256}
end;

{$ENDIF CRYPTOLIB_X86_SIMD}

{ TAesNiOcbKernel }

constructor TAesNiOcbKernel.Create(const AEngine: IAesEngineX86;
  AKeys: Pointer; ARounds: Int32; ADirection: TFusedModeDirection);
begin
  inherited Create;
  FEngine := AEngine;
  FKeys := AKeys;
  FRounds := ARounds;
  FDirection := ADirection;
end;

function TAesNiOcbKernel.MinimumBlockCount: Int32;
begin
  Result := FUSED_OCB_MIN_BLOCKS;
end;

procedure TAesNiOcbKernel.ProcessBlocks(AInPtr, AOutPtr, AOffsetPtr,
  AChecksumPtr, ALTablePtr, ANtzPtr, ABlock0Ptr: Pointer; ABlockCount: Int32);
{$IFDEF CRYPTOLIB_X86_SIMD}
var
  LCtx: TOcbFusedKernelCtx;
{$ENDIF CRYPTOLIB_X86_SIMD}
begin
{$IFDEF CRYPTOLIB_X86_SIMD}
  if (ABlockCount < FUSED_OCB_MIN_BLOCKS) or
    (ABlockCount mod FUSED_OCB_MIN_BLOCKS <> 0) then
    Exit;
  LCtx.Keys := FKeys;
  LCtx.InPtr := AInPtr;
  LCtx.OutPtr := AOutPtr;
  LCtx.OffsetPtr := AOffsetPtr;
  LCtx.ChecksumPtr := AChecksumPtr;
  LCtx.LTablePtr := ALTablePtr;
  LCtx.NtzPtr := ANtzPtr;
  LCtx.Block0Ptr := ABlock0Ptr;
  LCtx.BlockCount := NativeUInt(ABlockCount);
  if FDirection = TFusedModeDirection.Encrypt then
  begin
    case FRounds of
      10: OcbFusedEncWide128(@LCtx);
      12: OcbFusedEncWide192(@LCtx);
    else
      OcbFusedEncWide256(@LCtx);
    end;
  end
  else
  begin
    case FRounds of
      10: OcbFusedDecWide128(@LCtx);
      12: OcbFusedDecWide192(@LCtx);
    else
      OcbFusedDecWide256(@LCtx);
    end;
  end;
{$ENDIF CRYPTOLIB_X86_SIMD}
end;

{ TAesNiOcbKernelFactory }

function TAesNiOcbKernelFactory.ProviderName: String;
begin
  Result := 'AES-NI';
end;

function TAesNiOcbKernelFactory.Priority: TFusedKernelPriority;
begin
  Result := TFusedKernelPriority.Baseline;
end;

function TAesNiOcbKernelFactory.TryCreate(const ACipher: IBlockCipher;
  ADirection: TFusedModeDirection; out AKernel: IFusedOcbKernel): Boolean;
var
  LEngine: IAesEngineX86;
  LKeys: PByte;
  LRounds: Int32;
  LHasSchedule: Boolean;
begin
  AKernel := nil;
  Result := False;
  try
    if not TAesNiAeadResolver.CpuSupports then
      Exit;
    if not TAesNiAeadResolver.TryResolveEngine(ACipher, LEngine) then
      Exit;
    if ADirection = TFusedModeDirection.Encrypt then
      LHasSchedule := LEngine.TryGetEncKeysPtr(LKeys, LRounds)
    else
      LHasSchedule := LEngine.TryGetDecKeysPtr(LKeys, LRounds);
    if not LHasSchedule then
      Exit;
    if not (LRounds in [10, 12, 14]) then
      Exit;
    AKernel := TAesNiOcbKernel.Create(LEngine, LKeys, LRounds, ADirection);
    Result := True;
  except
    AKernel := nil;
    Result := False;
  end;
end;

initialization
  TFusedKernelRegistry.RegisterOcbFactory(
    TAesNiOcbKernelFactory.Create() as IFusedOcbKernelFactory);

end.
