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

unit ClpChaCha20Poly1305ArmKernel;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpCryptoLibTypes,
  ClpIStreamCipher,
  ClpIChaCha7539Engine,
  ClpCipherKernelTypes,
  ClpIChaCha20Poly1305Kernel,
  ClpCipherKernelFactoryBase,
  ClpCipherKernelRegistry,
  ClpBinaryPrimitives,
  ClpCpuFeatures,
  ClpChaCha20Poly1305PolyOps,
  ClpArrayUtilities;

type
  /// <summary>
  ///   AArch64 implementation of IChaCha20Poly1305Kernel. ProcessStrides drives
  ///   a fused NEON ChaCha20 + radix-2^64 Poly1305 kernel in one asm frame per
  ///   stride run, interleaving the scalar poly multiply into the NEON vector
  ///   rounds; encrypt folds the produced ciphertext (lagged one group), decrypt
  ///   folds the input ciphertext. InitPoly/UpdatePoly/FinishPoly carry the AAD
  ///   and length-block tail in the same accumulator. Gated by
  ///   CRYPTOLIB_AARCH64_ASM plus a runtime NEON probe.
  /// </summary>
  TChaCha20Poly1305ArmKernel = class sealed(TInterfacedObject,
    IChaCha20Poly1305Kernel)
  strict private
  const
    // NEON is four 32-bit lanes: a stride is one 4-block (256-byte) group.
    STRIDE_BYTES = Int32(256);
  strict private
    FEngine: IChaCha7539Engine;
    FEngineState: PUInt32;
    FState: TChaCha20Poly1305PolyState;
    FLenBlock: TCryptoLibByteArray;
  public
    constructor Create(const AEngine: IChaCha7539Engine;
      AEngineState: PUInt32);
    destructor Destroy; override;
    function StrideBytes: Int32;
    procedure InitPoly(APolyKey: PByte);
    procedure UpdatePoly(ASrc: PByte; ABlockCount: NativeInt);
    procedure ProcessStrides(AInPtr, AOutPtr: PByte;
      AStrideCount: NativeInt; AForEncrypt: Boolean);
    procedure FinishPoly(AAadLen, ADataLen: UInt64; ATagOut: PByte);
  end;

  TChaCha20Poly1305ArmKernelFactory = class sealed(TCipherKernelFactoryBase,
    IChaCha20Poly1305KernelFactory)
  public
    function ProviderName: String; override;
    function TryCreate(const ACipher: IStreamCipher;
      ADirection: TCipherKernelDirection;
      out AKernel: IChaCha20Poly1305Kernel): Boolean;
  end;

implementation

{$IFDEF CRYPTOLIB_AARCH64_ASM}
// Scalar radix-2^64 Poly1305 block loop. x0=@State, x1=ASrc, x2=ABlockCount.
procedure PolyBlocksR64Neon(AState, ASrc: Pointer; ABlockCount: NativeInt);
{$DEFINE CRYPTOLIB_CHACHAPOLY_POLY_ONLY}
{$I ..\..\..\Include\Simd\Common\ClpSimdProc3Begin_aarch64.inc}
{$I ..\..\..\Include\Simd\ChaCha\Poly1305\ChaCha20Poly1305Fused_aarch64.inc}
{$UNDEF CRYPTOLIB_CHACHAPOLY_POLY_ONLY}
end;

// Fused NEON ChaCha20 keystream + radix-2^64 Poly1305 (interleaved). x0=ARounds
// (ChaCha20, ignored), x1=AState, x2=AIn, x3=AOut, x4=AGroups, x5=APolyState.
procedure ChaChaPolyFusedNeon(ARounds: Int32; AState, AIn, AOut: PByte;
  AGroups: Int32; APolyState: Pointer);
{$DEFINE CRYPTOLIB_CHACHAPOLY_FUSED}
{$I ..\..\..\Include\Simd\Common\ClpSimdProc6Begin_aarch64.inc}
{$I ..\..\..\Include\Simd\ChaCha\Poly1305\ChaCha20Poly1305Fused_aarch64.inc}
{$UNDEF CRYPTOLIB_CHACHAPOLY_FUSED}
end;
{$ENDIF CRYPTOLIB_AARCH64_ASM}

{ TChaCha20Poly1305ArmKernel }

constructor TChaCha20Poly1305ArmKernel.Create(const AEngine: IChaCha7539Engine;
  AEngineState: PUInt32);
begin
  inherited Create;
  // FEngine anchors the engine's lifetime so FEngineState stays valid.
  FEngine := AEngine;
  FEngineState := AEngineState;
  System.SetLength(FLenBlock, 16);
end;

destructor TChaCha20Poly1305ArmKernel.Destroy;
begin
  // Wipe the key-derived poly state and the residual length block.
  System.FillChar(FState, System.SizeOf(FState), 0);
  TArrayUtilities.Fill(FLenBlock, 0, System.Length(FLenBlock), Byte(0));
  inherited Destroy;
end;

function TChaCha20Poly1305ArmKernel.StrideBytes: Int32;
begin
  Result := STRIDE_BYTES;
end;

procedure TChaCha20Poly1305ArmKernel.InitPoly(APolyKey: PByte);
begin
  TChaCha20Poly1305PolyOps.ClampInit(FState, APolyKey);
end;

procedure TChaCha20Poly1305ArmKernel.UpdatePoly(ASrc: PByte;
  ABlockCount: NativeInt);
begin
  if ABlockCount <= 0 then
    Exit;
{$IFDEF CRYPTOLIB_AARCH64_ASM}
  PolyBlocksR64Neon(@FState, ASrc, ABlockCount);
{$ENDIF CRYPTOLIB_AARCH64_ASM}
end;

procedure TChaCha20Poly1305ArmKernel.ProcessStrides(AInPtr, AOutPtr: PByte;
  AStrideCount: NativeInt; AForEncrypt: Boolean);
begin
  if AStrideCount <= 0 then
    Exit;
  // Decrypt folds the input ciphertext; encrypt folds the produced ciphertext.
  FState.FoldFromInput := Ord(not AForEncrypt);
{$IFDEF CRYPTOLIB_AARCH64_ASM}
  ChaChaPolyFusedNeon(20, PByte(FEngineState), AInPtr, AOutPtr,
    Int32(AStrideCount), @FState);
{$ENDIF CRYPTOLIB_AARCH64_ASM}
end;

procedure TChaCha20Poly1305ArmKernel.FinishPoly(AAadLen, ADataLen: UInt64;
  ATagOut: PByte);
begin
  // Absorb the length block LE(aad) || LE(data) as one full poly block, then
  // reduce + tag.
  TBinaryPrimitives.WriteUInt64LittleEndian(FLenBlock, 0, AAadLen);
  TBinaryPrimitives.WriteUInt64LittleEndian(FLenBlock, 8, ADataLen);
  UpdatePoly(@FLenBlock[0], 1);
  TChaCha20Poly1305PolyOps.ReduceAndTag(FState, ATagOut);
end;

{ TChaCha20Poly1305ArmKernelFactory }

function TChaCha20Poly1305ArmKernelFactory.ProviderName: String;
begin
  Result := 'ChaCha20Poly1305-NEON';
end;

function TChaCha20Poly1305ArmKernelFactory.TryCreate(
  const ACipher: IStreamCipher; ADirection: TCipherKernelDirection;
  out AKernel: IChaCha20Poly1305Kernel): Boolean;
{$IFDEF CRYPTOLIB_AARCH64_ASM}
var
  LEngine: IChaCha7539Engine;
{$ENDIF CRYPTOLIB_AARCH64_ASM}
begin
  AKernel := nil;
  Result := False;
  try
{$IFDEF CRYPTOLIB_AARCH64_ASM}
    // mul/umulh is base ARMv8-A; only NEON is probed.
    if not TCpuFeatures.Arm.HasNEON() then
      Exit;
    if not Supports(ACipher, IChaCha7539Engine, LEngine) then
      Exit;
    AKernel := TChaCha20Poly1305ArmKernel.Create(LEngine,
      LEngine.GetEngineStatePtr);
    Result := True;
{$ENDIF CRYPTOLIB_AARCH64_ASM}
  except
    AKernel := nil;
    Result := False;
  end;
end;

initialization
  TCipherKernelRegistry.Register(
    TChaCha20Poly1305ArmKernelFactory.Create()
    as IChaCha20Poly1305KernelFactory);

end.
