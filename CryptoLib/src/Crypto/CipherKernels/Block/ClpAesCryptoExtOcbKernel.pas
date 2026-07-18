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

unit ClpAesCryptoExtOcbKernel;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpIBlockCipher,
  ClpIAesEngineArm,
  ClpCipherKernelTypes,
  ClpIOcbKernel,
  ClpCipherKernelFactoryBase,
  ClpCipherKernelRegistry,
  ClpAesFusedAeadSimd,
  ClpAesCryptoExtFusedArmBackend;

type
  /// <summary>
  ///   AES CryptoExt (ARMv8) implementation of IOcbKernel: the fused 8-wide
  ///   OCB body with a round-interleaved offset ladder used by
  ///   TOcbBlockCipher's bulk path. Byte-compatible with the x86 kernel
  ///   (same context layout and L-table / accumulator contract).
  ///   Available on aarch64 (CRYPTOLIB_AARCH64_ASM). When unavailable the
  ///   factory returns nil and TOcbBlockCipher keeps its block path.
  ///   Direction-bound at construction: an encrypt kernel captures the
  ///   forward AES schedule, a decrypt kernel the inverse-MixColumns
  ///   schedule.
  ///   The kernel processes ABlockCount blocks in a single invocation,
  ///   looping internally over a fixed 16-block stride so the mode layer
  ///   can amortise call-site overhead across large batches.
  /// </summary>
  TAesCryptoExtOcbKernel = class sealed(TInterfacedObject, IOcbKernel)
  strict private
  const
    FUSED_OCB_MIN_BLOCKS = 16;
  strict private
    // FEngine is retained so the round-key buffer FKeys points into stays alive
    // for the kernel's lifetime.
    FEngine: IAesEngineArm;
    FKeys: Pointer;
    FRounds: Int32;
    FDirection: TCipherKernelDirection;
  public
    constructor Create(const AEngine: IAesEngineArm; AKeys: Pointer;
      ARounds: Int32; ADirection: TCipherKernelDirection);
    function MinimumBlockCount: Int32;
    procedure ProcessBlocks(AInPtr, AOutPtr, AOffsetPtr, AChecksumPtr,
      ALTablePtr, ABlock0Ptr: Pointer; ABlockCount: Int32;
      AStartBlockCount: UInt64);
  end;

  TAesCryptoExtOcbKernelFactory = class sealed(TCipherKernelFactoryBase,
    IOcbKernelFactory)
  public
    function ProviderName: String; override;
    function TryCreate(const ACipher: IBlockCipher;
      ADirection: TCipherKernelDirection;
      out AKernel: IOcbKernel): Boolean;
  end;

implementation

{$IFDEF CRYPTOLIB_AARCH64_ASM}

type
  /// <summary>
  ///   Context record shared with the assembly body. All live OCB state
  ///   the kernel touches is addressed through this record: seven
  ///   pointers (Keys, In, Out, OffsetState, ChecksumState, LTable,
  ///   Block0) plus the NativeUInt BlockCount and the UInt64
  ///   StartBlockCount. Field offsets match the kernel's [x0 + N]
  ///   accesses documented in AesOcbFusedWide_aarch64.inc (identical
  ///   layout to the x86_64 kernel's).
  /// </summary>
  TOcbFusedKernelCtx = record
    Keys: Pointer;         // AES expanded schedule (enc / dec+invMC)
    InPtr: Pointer;        // ABlockCount * 16 bytes (advances per-iter)
    OutPtr: Pointer;       // ABlockCount * 16 bytes (advances per-iter)
    OffsetPtr: Pointer;    // 16-byte live FOffsetMAIN state (r/w)
    ChecksumPtr: Pointer;  // 16-byte live FChecksum state (r/w)
    LTablePtr: Pointer;    // flat L[0..LMax] * 16 bytes (read-only)
    Block0Ptr: Pointer;    // 16-byte source of iter-0 block 0 (may
                           // alias InPtr or point at an unrelated
                           // 16-byte buffer such as FMainBlock)
    BlockCount: NativeUInt;   // positive multiple of MinimumBlockCount
    StartBlockCount: UInt64;  // OCB block count before this span; the kernel
                              // seeds a running counter here and derives ntz
                              // per block in-asm (rbit + clz).
  end;

procedure OcbFusedEncWide128(PCtx: Pointer);
{$DEFINE CRYPTOLIB_AESCRYPTOEXT_KEY128}
{$I ..\..\..\Include\Simd\Common\ClpSimdProc1Begin_aarch64.inc}
{$I ..\..\..\Include\Simd\Aes\Ocb\AesOcbFusedWide_aarch64.inc}
{$UNDEF CRYPTOLIB_AESCRYPTOEXT_KEY128}
end;

procedure OcbFusedEncWide192(PCtx: Pointer);
{$DEFINE CRYPTOLIB_AESCRYPTOEXT_KEY192}
{$I ..\..\..\Include\Simd\Common\ClpSimdProc1Begin_aarch64.inc}
{$I ..\..\..\Include\Simd\Aes\Ocb\AesOcbFusedWide_aarch64.inc}
{$UNDEF CRYPTOLIB_AESCRYPTOEXT_KEY192}
end;

procedure OcbFusedEncWide256(PCtx: Pointer);
{$DEFINE CRYPTOLIB_AESCRYPTOEXT_KEY256}
{$I ..\..\..\Include\Simd\Common\ClpSimdProc1Begin_aarch64.inc}
{$I ..\..\..\Include\Simd\Aes\Ocb\AesOcbFusedWide_aarch64.inc}
{$UNDEF CRYPTOLIB_AESCRYPTOEXT_KEY256}
end;

procedure OcbFusedDecWide128(PCtx: Pointer);
{$DEFINE CRYPTOLIB_AESCRYPTOEXT_KEY128}
{$DEFINE CRYPTOLIB_AESCRYPTOEXT_DECRYPT}
{$I ..\..\..\Include\Simd\Common\ClpSimdProc1Begin_aarch64.inc}
{$I ..\..\..\Include\Simd\Aes\Ocb\AesOcbFusedWide_aarch64.inc}
{$UNDEF CRYPTOLIB_AESCRYPTOEXT_DECRYPT}
{$UNDEF CRYPTOLIB_AESCRYPTOEXT_KEY128}
end;

procedure OcbFusedDecWide192(PCtx: Pointer);
{$DEFINE CRYPTOLIB_AESCRYPTOEXT_KEY192}
{$DEFINE CRYPTOLIB_AESCRYPTOEXT_DECRYPT}
{$I ..\..\..\Include\Simd\Common\ClpSimdProc1Begin_aarch64.inc}
{$I ..\..\..\Include\Simd\Aes\Ocb\AesOcbFusedWide_aarch64.inc}
{$UNDEF CRYPTOLIB_AESCRYPTOEXT_DECRYPT}
{$UNDEF CRYPTOLIB_AESCRYPTOEXT_KEY192}
end;

procedure OcbFusedDecWide256(PCtx: Pointer);
{$DEFINE CRYPTOLIB_AESCRYPTOEXT_KEY256}
{$DEFINE CRYPTOLIB_AESCRYPTOEXT_DECRYPT}
{$I ..\..\..\Include\Simd\Common\ClpSimdProc1Begin_aarch64.inc}
{$I ..\..\..\Include\Simd\Aes\Ocb\AesOcbFusedWide_aarch64.inc}
{$UNDEF CRYPTOLIB_AESCRYPTOEXT_DECRYPT}
{$UNDEF CRYPTOLIB_AESCRYPTOEXT_KEY256}
end;

{$ENDIF CRYPTOLIB_AARCH64_ASM}

{ TAesCryptoExtOcbKernel }

constructor TAesCryptoExtOcbKernel.Create(const AEngine: IAesEngineArm;
  AKeys: Pointer; ARounds: Int32; ADirection: TCipherKernelDirection);
begin
  inherited Create;
  FEngine := AEngine;
  FKeys := AKeys;
  FRounds := ARounds;
  FDirection := ADirection;
end;

function TAesCryptoExtOcbKernel.MinimumBlockCount: Int32;
begin
  Result := FUSED_OCB_MIN_BLOCKS;
end;

procedure TAesCryptoExtOcbKernel.ProcessBlocks(AInPtr, AOutPtr, AOffsetPtr,
  AChecksumPtr, ALTablePtr, ABlock0Ptr: Pointer; ABlockCount: Int32;
  AStartBlockCount: UInt64);
{$IFDEF CRYPTOLIB_AARCH64_ASM}
var
  LCtx: TOcbFusedKernelCtx;
{$ENDIF CRYPTOLIB_AARCH64_ASM}
begin
{$IFDEF CRYPTOLIB_AARCH64_ASM}
  if (ABlockCount < FUSED_OCB_MIN_BLOCKS) or
    (ABlockCount mod FUSED_OCB_MIN_BLOCKS <> 0) then
    Exit;
  LCtx.Keys := FKeys;
  LCtx.InPtr := AInPtr;
  LCtx.OutPtr := AOutPtr;
  LCtx.OffsetPtr := AOffsetPtr;
  LCtx.ChecksumPtr := AChecksumPtr;
  LCtx.LTablePtr := ALTablePtr;
  LCtx.Block0Ptr := ABlock0Ptr;
  LCtx.BlockCount := NativeUInt(ABlockCount);
  LCtx.StartBlockCount := AStartBlockCount;
  if FDirection = TCipherKernelDirection.Encrypt then
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
{$ENDIF CRYPTOLIB_AARCH64_ASM}
end;

{ TAesCryptoExtOcbKernelFactory }

function TAesCryptoExtOcbKernelFactory.ProviderName: String;
begin
  Result := 'AES-CryptoExt';
end;

function TAesCryptoExtOcbKernelFactory.TryCreate(const ACipher: IBlockCipher;
  ADirection: TCipherKernelDirection; out AKernel: IOcbKernel): Boolean;
var
  LEngine: IAesEngineArm;
  LKeys: PByte;
  LRounds: Int32;
  LHasSchedule: Boolean;
begin
  AKernel := nil;
  Result := False;
  try
{$IFDEF CRYPTOLIB_AARCH64_ASM}
    if not TAesFusedAeadSimd.CpuSupports then
      Exit;
    if not TAesCryptoExtFusedArmBackend.TryResolveEngine(ACipher, LEngine) then
      Exit;
    if ADirection = TCipherKernelDirection.Encrypt then
      LHasSchedule := LEngine.TryGetEncKeysPtr(LKeys, LRounds)
    else
      LHasSchedule := LEngine.TryGetDecKeysPtr(LKeys, LRounds);
    if not LHasSchedule then
      Exit;
    if not (LRounds in [10, 12, 14]) then
      Exit;
    AKernel := TAesCryptoExtOcbKernel.Create(LEngine, LKeys, LRounds,
      ADirection);
    Result := True;
{$ENDIF CRYPTOLIB_AARCH64_ASM}
  except
    AKernel := nil;
    Result := False;
  end;
end;

initialization
  TCipherKernelRegistry.Register(
    TAesCryptoExtOcbKernelFactory.Create() as IOcbKernelFactory);

end.
