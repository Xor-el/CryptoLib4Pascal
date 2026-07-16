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

unit ClpAesCryptoExtCtrKernel;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpIBlockCipher,
  ClpIAesEngineArm,
  ClpCipherKernelTypes,
  ClpICtrKernel,
  ClpCipherKernelFactoryBase,
  ClpCipherKernelRegistry,
  ClpAesCryptoExtFusedArmBackend;

type
  /// <summary>
  ///   AES CryptoExt (ARMv8) implementation of ICtrKernel: the fused
  ///   counter-mode keystream + XOR body used by TSicBlockCipher's bulk path.
  ///   The MAC-free base of the fused-kernel family; runs a plain 8-wide AES
  ///   round chain since CTR has no extra per-block state.
  ///   Available on aarch64 (CRYPTOLIB_AARCH64_ASM). When unavailable the
  ///   factory returns nil and TSicBlockCipher keeps its existing bulk path.
  /// </summary>
  TAesCryptoExtCtrKernel = class sealed(TInterfacedObject, ICtrKernel)
  strict private
  const
    FUSED_CTR_BATCH_BLOCKS = 8;
  strict private
    // FEngine is retained so the round-key buffer FKeys points into stays alive
    // for the kernel's lifetime.
    FEngine: IAesEngineArm;
    FKeys: Pointer;
    FRounds: Int32;
  public
    constructor Create(const AEngine: IAesEngineArm; AKeys: Pointer;
      ARounds: Int32);
    function BatchBlockCount: Int32;
    procedure ProcessCtrBlocks(AInPtr, AOutPtr, ACounter: Pointer;
      ABlockCount: NativeInt);
  end;

  TAesCryptoExtCtrKernelFactory = class sealed(TCipherKernelFactoryBase, ICtrKernelFactory)
  public
    function ProviderName: String; override;
    function TryCreate(const ACipher: IBlockCipher;
      ADirection: TCipherKernelDirection;
      out AKernel: ICtrKernel): Boolean;
  end;

implementation

{$IFDEF CRYPTOLIB_AARCH64_ASM}

type
  // Context handed to the fused AES CryptoExt CTR keystream + XOR kernel.
  // Field offsets match the [x0 + N] accesses in AesCryptoExtCtrEight_aarch64.inc
  // (all 8-byte fields). The kernel loops internally over BlockCount blocks,
  // advancing InPtr/OutPtr and the low dword of the 16-byte big-endian counter
  // at CounterPtr in place. The kernel carries no in-loop carry logic, so the
  // low-32 counter dword must not wrap within one call; ProcessCtrBlocks
  // enforces that by splitting runs at the 2^32 boundary.
  TCtrFusedCtx = record
    InPtr: Pointer;
    OutPtr: Pointer;
    KeysPtr: Pointer;
    CounterPtr: Pointer;
    BlockCount: NativeUInt;
  end;

// Fused AES CryptoExt CTR keystream + XOR (encrypt-only; CTR keystream is the
// same for encrypt and decrypt). Each proc processes BlockCount blocks (a
// positive multiple of 8 with ctr32 + BlockCount <= 2^32), looping internally;
// only the counter's low dword is advanced in place.
procedure AesCryptoExtCtrEnc128(PCtx: Pointer);
{$DEFINE CRYPTOLIB_AESCRYPTOEXT_KEY128}
{$I ..\..\..\Include\Simd\Common\ClpSimdProc1Begin_aarch64.inc}
{$I ..\..\..\Include\Simd\Aes\Ctr\AesCryptoExtCtrEight_aarch64.inc}
{$UNDEF CRYPTOLIB_AESCRYPTOEXT_KEY128}
end;

procedure AesCryptoExtCtrEnc192(PCtx: Pointer);
{$DEFINE CRYPTOLIB_AESCRYPTOEXT_KEY192}
{$I ..\..\..\Include\Simd\Common\ClpSimdProc1Begin_aarch64.inc}
{$I ..\..\..\Include\Simd\Aes\Ctr\AesCryptoExtCtrEight_aarch64.inc}
{$UNDEF CRYPTOLIB_AESCRYPTOEXT_KEY192}
end;

procedure AesCryptoExtCtrEnc256(PCtx: Pointer);
{$DEFINE CRYPTOLIB_AESCRYPTOEXT_KEY256}
{$I ..\..\..\Include\Simd\Common\ClpSimdProc1Begin_aarch64.inc}
{$I ..\..\..\Include\Simd\Aes\Ctr\AesCryptoExtCtrEight_aarch64.inc}
{$UNDEF CRYPTOLIB_AESCRYPTOEXT_KEY256}
end;

{$ENDIF CRYPTOLIB_AARCH64_ASM}

{ TAesCryptoExtCtrKernel }

constructor TAesCryptoExtCtrKernel.Create(const AEngine: IAesEngineArm; AKeys: Pointer;
  ARounds: Int32);
begin
  inherited Create;
  FEngine := AEngine;
  FKeys := AKeys;
  FRounds := ARounds;
end;

function TAesCryptoExtCtrKernel.BatchBlockCount: Int32;
begin
  Result := FUSED_CTR_BATCH_BLOCKS;
end;

{$IFDEF CRYPTOLIB_AARCH64_ASM}
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
{$ENDIF CRYPTOLIB_AARCH64_ASM}

procedure TAesCryptoExtCtrKernel.ProcessCtrBlocks(AInPtr, AOutPtr, ACounter: Pointer;
  ABlockCount: NativeInt);
{$IFDEF CRYPTOLIB_AARCH64_ASM}
var
  LCtx: TCtrFusedCtx;
  LIn, LOut, LCtr: PByte;
  LRemaining, LChunk: NativeInt;
  LUntilWrap: UInt64;
  LCtr32: Cardinal;
  LKs: array [0 .. 15] of Byte;
  LI, LJ: Int32;
{$ENDIF CRYPTOLIB_AARCH64_ASM}
begin
{$IFDEF CRYPTOLIB_AARCH64_ASM}
  LIn := AInPtr;
  LOut := AOutPtr;
  LCtr := ACounter;
  LRemaining := ABlockCount;
  while LRemaining > 0 do
  begin
    // The kernel advances the counter low dword mod 2^32 and carries no
    // in-loop carry logic, so a single call must not cross the 2^32 boundary
    // of the low counter dword. Split the run there and apply the (rare)
    // carry here.
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
        10: AesCryptoExtCtrEnc128(@LCtx);
        12: AesCryptoExtCtrEnc192(@LCtx);
      else
        AesCryptoExtCtrEnc256(@LCtx);
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
{$ENDIF CRYPTOLIB_AARCH64_ASM}
end;

{ TAesCryptoExtCtrKernelFactory }

function TAesCryptoExtCtrKernelFactory.ProviderName: String;
begin
  Result := 'AES-CryptoExt';
end;

function TAesCryptoExtCtrKernelFactory.TryCreate(const ACipher: IBlockCipher;
  ADirection: TCipherKernelDirection; out AKernel: ICtrKernel): Boolean;
var
  LEngine: IAesEngineArm;
  LKeys: PByte;
  LRounds: Int32;
begin
  AKernel := nil;
  Result := False;
  try
{$IFDEF CRYPTOLIB_AARCH64_ASM}
    if not TAesCryptoExtFusedArmBackend.TryResolveEngine(ACipher, LEngine) then
      Exit;
    if not LEngine.TryGetEncKeysPtr(LKeys, LRounds) then
      Exit;
    if not (LRounds in [10, 12, 14]) then
      Exit;
    AKernel := TAesCryptoExtCtrKernel.Create(LEngine, LKeys, LRounds);
    Result := True;
{$ENDIF CRYPTOLIB_AARCH64_ASM}
  except
    AKernel := nil;
    Result := False;
  end;
end;

initialization
  TCipherKernelRegistry.Register(
    TAesCryptoExtCtrKernelFactory.Create() as ICtrKernelFactory);

end.
