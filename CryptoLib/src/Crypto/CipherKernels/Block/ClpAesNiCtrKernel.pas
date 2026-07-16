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
  // loops internally over BlockCount blocks, advancing InPtr/OutPtr and the low
  // dword of the 16-byte big-endian counter at CounterPtr in place. The counters
  // are staged pre-whitened (K_0 folded into the scalar counter build), so the
  // kernel requires the low-32 counter dword not to wrap within one call;
  // ProcessCtrBlocks enforces that by splitting runs at the 2^32 boundary.
  TCtrFusedCtx = record
    InPtr: Pointer;
    OutPtr: Pointer;
    KeysPtr: Pointer;
    CounterPtr: Pointer;
    BlockCount: NativeUInt;
  end;

// Fused AES-NI CTR keystream + XOR (encrypt-only; CTR keystream is the same for
// encrypt and decrypt). Each proc processes BlockCount blocks (a positive
// multiple of 8 with ctr32 + BlockCount <= 2^32), looping internally; only the
// counter's low dword is advanced in place.
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

{$IFDEF CRYPTOLIB_X86_SIMD}
// Big-endian +1 over ACounter[AHigh..ALow], dropping any carry out of ALow.
// AHigh=15/ALow=0 is the SIC whole-counter increment; AHigh=11/ALow=0 is the
// upper-bytes carry after the kernel consumed a run up to the 2^32 boundary.
procedure CtrIncrementBigEndian(ACounter: PByte; AHigh, ALow: Int32); inline;
var
  LJ: Int32;
begin
  LJ := AHigh;
  repeat
    System.Inc(ACounter[LJ]);
    if ACounter[LJ] <> 0 then
      Break;
    System.Dec(LJ);
  until LJ < ALow;
end;
{$ENDIF CRYPTOLIB_X86_SIMD}

procedure TAesNiCtrKernel.ProcessCtrBlocks(AInPtr, AOutPtr, ACounter: Pointer;
  ABlockCount: NativeInt);
{$IFDEF CRYPTOLIB_X86_SIMD}
var
  LCtx: TCtrFusedCtx;
  LIn, LOut, LCtr: PByte;
  LRemaining, LChunk: NativeInt;
  LUntilWrap: UInt64;
  LCtr32: Cardinal;
  LKs: array [0 .. 15] of Byte;
  LI, LJ: Int32;
{$ENDIF CRYPTOLIB_X86_SIMD}
begin
{$IFDEF CRYPTOLIB_X86_SIMD}
  LIn := AInPtr;
  LOut := AOutPtr;
  LCtr := ACounter;
  LRemaining := ABlockCount;
  while LRemaining > 0 do
  begin
    // The kernel stages counters pre-whitened and carries no in-loop carry
    // logic, so a single call must not cross the 2^32 boundary of the low
    // counter dword. Split the run there and apply the (rare) carry here.
    LCtr32 := (Cardinal(LCtr[12]) shl 24) or (Cardinal(LCtr[13]) shl 16) or
      (Cardinal(LCtr[14]) shl 8) or Cardinal(LCtr[15]);
    LUntilWrap := UInt64($100000000) - LCtr32;
    if UInt64(LRemaining) <= LUntilWrap then
      LChunk := LRemaining
    else
      LChunk := NativeInt(LUntilWrap) and not NativeInt(7);

    if LChunk > 0 then
    begin
      LCtx.InPtr := LIn;
      LCtx.OutPtr := LOut;
      LCtx.KeysPtr := FKeys;
      LCtx.CounterPtr := LCtr;
      LCtx.BlockCount := NativeUInt(LChunk);
      case FRounds of
        10: AesNiCtrEnc128(@LCtx);
        12: AesNiCtrEnc192(@LCtx);
      else
        AesNiCtrEnc256(@LCtx);
      end;
      if UInt64(LChunk) = LUntilWrap then
        CtrIncrementBigEndian(LCtr, 11, 0); // low dword wrapped to 0 in the kernel
      System.Inc(LIn, LChunk * 16);
      System.Inc(LOut, LChunk * 16);
      System.Dec(LRemaining, LChunk);
    end
    else
    begin
      // Fewer than 8 blocks left before the boundary: bridge one batch a
      // block at a time with full big-endian carry (at most once per 2^32
      // blocks, or when the initial counter starts near the wrap).
      for LI := 1 to 8 do
      begin
        FEngine.ProcessBlock(LCtr, @LKs[0]);
        for LJ := 0 to 15 do
          LOut[LJ] := LIn[LJ] xor LKs[LJ];
        CtrIncrementBigEndian(LCtr, 15, 0);
        System.Inc(LIn, 16);
        System.Inc(LOut, 16);
      end;
      FillChar(LKs, SizeOf(LKs), 0);
      System.Dec(LRemaining, 8);
    end;
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
