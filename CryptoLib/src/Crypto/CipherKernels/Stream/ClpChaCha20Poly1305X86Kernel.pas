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

unit ClpChaCha20Poly1305X86Kernel;

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
  ClpX86SimdFeatures,
  ClpChaCha20Poly1305PolyOps,
  ClpArrayUtilities;

type
  /// <summary>
  ///   x86 implementation of IChaCha20Poly1305Kernel. ProcessStrides drives a
  ///   fused ChaCha20 + Poly1305 kernel in one asm frame per stride run,
  ///   interleaving the scalar poly multiply into the ChaCha vector rounds;
  ///   encrypt folds the produced ciphertext (lagged one group), decrypt folds
  ///   the input ciphertext. Gated collectively by CRYPTOLIB_X86_SIMD: the
  ///   x86-64 arm (CRYPTOLIB_X86_64_ASM) runs AVX2 ChaCha20 + a radix-2^64
  ///   Poly1305 (mulx) and needs runtime AVX2 + BMI2; the i386 arm
  ///   (CRYPTOLIB_I386_ASM) runs SSE2 ChaCha20 + a radix-2^26 Poly1305 and needs
  ///   runtime SSE2.
  /// </summary>
  TChaCha20Poly1305X86Kernel = class sealed(TInterfacedObject,
    IChaCha20Poly1305Kernel)
  strict private
  const
{$IFDEF CRYPTOLIB_I386_ASM}
    // SSE2 is four 32-bit lanes: a stride is one 4-block (256-byte) group.
    STRIDE_BYTES = Int32(256);
{$ELSE}
    // AVX2 does eight blocks: a stride is one 8-block (512-byte) group.
    STRIDE_BYTES = Int32(512);
{$ENDIF}
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

  TChaCha20Poly1305X86KernelFactory = class sealed(TCipherKernelFactoryBase,
    IChaCha20Poly1305KernelFactory)
  public
    function ProviderName: String; override;
    function TryCreate(const ACipher: IStreamCipher;
      ADirection: TCipherKernelDirection;
      out AKernel: IChaCha20Poly1305Kernel): Boolean;
  end;

implementation

{$IFDEF CRYPTOLIB_X86_SIMD}

{$IFDEF CRYPTOLIB_X86_64_ASM}
// Scalar radix-2^64 Poly1305 block loop. rcx=@State, rdx=ASrc, r8=ABlockCount.
procedure PolyBlocksR64(AState, ASrc: Pointer; ABlockCount: NativeInt);
{$DEFINE CRYPTOLIB_CHACHAPOLY_POLY_ONLY}
{$I ..\..\..\Include\Simd\Common\ClpSimdProc3Begin_x86_64.inc}
{$I ..\..\..\Include\Simd\ChaCha\Poly1305\ChaCha20Poly1305Fused_x86_64.inc}
{$UNDEF CRYPTOLIB_CHACHAPOLY_POLY_ONLY}
end;

// Fused AVX2 ChaCha20 keystream + radix-2^64 Poly1305 (interleaved). rcx=ARounds
// (ChaCha20, ignored), rdx=AState, r8=AIn, r9=AOut, r10=AGroups, r11=APolyState.
procedure ChaChaPolyFusedAvx2(ARounds: Int32; AState, AIn, AOut: PByte;
  AGroups: Int32; APolyState: Pointer);
{$DEFINE CRYPTOLIB_CHACHAPOLY_FUSED}
{$I ..\..\..\Include\Simd\Common\ClpSimdProc6Begin_x86_64.inc}
{$I ..\..\..\Include\Simd\ChaCha\Poly1305\ChaCha20Poly1305Fused_x86_64.inc}
{$UNDEF CRYPTOLIB_CHACHAPOLY_FUSED}
end;
{$ENDIF CRYPTOLIB_X86_64_ASM}

{$IFDEF CRYPTOLIB_I386_ASM}
// Scalar radix-2^26 Poly1305 block loop. ebx=@State, esi=ASrc, edi=ABlockCount.
procedure PolyBlocksR26(AState, ASrc: Pointer; ABlockCount: NativeInt);
{$DEFINE CRYPTOLIB_CHACHAPOLY_POLY_ONLY}
{$I ..\..\..\Include\Simd\Common\ClpSimdProc3Begin_i386.inc}
{$I ..\..\..\Include\Simd\ChaCha\Poly1305\ChaCha20Poly1305Fused_i386.inc}
{$UNDEF CRYPTOLIB_CHACHAPOLY_POLY_ONLY}
end;

// Fused SSE2 ChaCha20 keystream + radix-2^26 Poly1305 (interleaved). The
// ClpSimdProc5Begin_i386.inc prologue normalizes the args: ebx=APolyState,
// esi=AState, edi=AIn, eax=AOut, ecx=AGroups. The ChaCha round count is
// unrolled, so there is no ARounds arg on i386.
procedure ChaCha20Poly1305FusedSse2(APolyState, AState, AIn, AOut: Pointer;
  AGroups: Int32);
{$DEFINE CRYPTOLIB_CHACHAPOLY_FUSED}
{$I ..\..\..\Include\Simd\Common\ClpSimdProc5Begin_i386.inc}
{$I ..\..\..\Include\Simd\ChaCha\Poly1305\ChaCha20Poly1305Fused_i386.inc}
{$UNDEF CRYPTOLIB_CHACHAPOLY_FUSED}
end;
{$ENDIF CRYPTOLIB_I386_ASM}

{$ENDIF CRYPTOLIB_X86_SIMD}

{ TChaCha20Poly1305X86Kernel }

constructor TChaCha20Poly1305X86Kernel.Create(const AEngine: IChaCha7539Engine;
  AEngineState: PUInt32);
begin
  inherited Create;
  // FEngine anchors the engine's lifetime so FEngineState stays valid.
  FEngine := AEngine;
  FEngineState := AEngineState;
  System.SetLength(FLenBlock, 16);
end;

destructor TChaCha20Poly1305X86Kernel.Destroy;
begin
  // Wipe the key-derived poly state and the residual length block.
  System.FillChar(FState, System.SizeOf(FState), 0);
  TArrayUtilities.Fill(FLenBlock, 0, System.Length(FLenBlock), Byte(0));
  inherited Destroy;
end;

function TChaCha20Poly1305X86Kernel.StrideBytes: Int32;
begin
  Result := STRIDE_BYTES;
end;

procedure TChaCha20Poly1305X86Kernel.InitPoly(APolyKey: PByte);
begin
  TChaCha20Poly1305PolyOps.ClampInit(FState, APolyKey);
end;

procedure TChaCha20Poly1305X86Kernel.UpdatePoly(ASrc: PByte;
  ABlockCount: NativeInt);
begin
  if ABlockCount <= 0 then
    Exit;
{$IFDEF CRYPTOLIB_X86_SIMD}
{$IFDEF CRYPTOLIB_X86_64_ASM}
  PolyBlocksR64(@FState, ASrc, ABlockCount);
{$ENDIF CRYPTOLIB_X86_64_ASM}
{$IFDEF CRYPTOLIB_I386_ASM}
  PolyBlocksR26(@FState, ASrc, ABlockCount);
{$ENDIF CRYPTOLIB_I386_ASM}
{$ENDIF CRYPTOLIB_X86_SIMD}
end;

procedure TChaCha20Poly1305X86Kernel.ProcessStrides(AInPtr, AOutPtr: PByte;
  AStrideCount: NativeInt; AForEncrypt: Boolean);
begin
  if AStrideCount <= 0 then
    Exit;
  // Decrypt folds the input ciphertext; encrypt folds the produced ciphertext.
  FState.FoldFromInput := Ord(not AForEncrypt);
{$IFDEF CRYPTOLIB_X86_SIMD}
{$IFDEF CRYPTOLIB_X86_64_ASM}
  ChaChaPolyFusedAvx2(20, PByte(FEngineState), AInPtr, AOutPtr,
    Int32(AStrideCount), @FState);
{$ENDIF CRYPTOLIB_X86_64_ASM}
{$IFDEF CRYPTOLIB_I386_ASM}
  ChaCha20Poly1305FusedSse2(@FState, PByte(FEngineState), AInPtr, AOutPtr,
    Int32(AStrideCount));
{$ENDIF CRYPTOLIB_I386_ASM}
{$ENDIF CRYPTOLIB_X86_SIMD}
end;

procedure TChaCha20Poly1305X86Kernel.FinishPoly(AAadLen, ADataLen: UInt64;
  ATagOut: PByte);
begin
  // Absorb the length block LE(aad) || LE(data) as one full poly block, then
  // reduce + tag.
  TBinaryPrimitives.WriteUInt64LittleEndian(FLenBlock, 0, AAadLen);
  TBinaryPrimitives.WriteUInt64LittleEndian(FLenBlock, 8, ADataLen);
  UpdatePoly(@FLenBlock[0], 1);
  TChaCha20Poly1305PolyOps.ReduceAndTag(FState, ATagOut);
end;

{ TChaCha20Poly1305X86KernelFactory }

function TChaCha20Poly1305X86KernelFactory.ProviderName: String;
begin
{$IFDEF CRYPTOLIB_I386_ASM}
  Result := 'ChaCha20Poly1305-SSE2';
{$ELSE}
  Result := 'ChaCha20Poly1305-AVX2';
{$ENDIF}
end;

function TChaCha20Poly1305X86KernelFactory.TryCreate(
  const ACipher: IStreamCipher; ADirection: TCipherKernelDirection;
  out AKernel: IChaCha20Poly1305Kernel): Boolean;
{$IFDEF CRYPTOLIB_X86_SIMD}
var
  LEngine: IChaCha7539Engine;
{$ENDIF CRYPTOLIB_X86_SIMD}
begin
  AKernel := nil;
  Result := False;
  try
{$IFDEF CRYPTOLIB_X86_SIMD}
{$IFDEF CRYPTOLIB_X86_64_ASM}
    // The fused kernel needs AVX2 (ChaCha) + BMI2 (mulx).
    if not (TX86SimdFeatures.HasAVX2() and TX86SimdFeatures.HasBMI2()) then
      Exit;
{$ENDIF CRYPTOLIB_X86_64_ASM}
{$IFDEF CRYPTOLIB_I386_ASM}
    // SSE2 drives the ChaCha side; the radix-2^26 mul is base ISA.
    if not TX86SimdFeatures.HasSSE2() then
      Exit;
{$ENDIF CRYPTOLIB_I386_ASM}
    if not Supports(ACipher, IChaCha7539Engine, LEngine) then
      Exit;
    AKernel := TChaCha20Poly1305X86Kernel.Create(LEngine,
      LEngine.GetEngineStatePtr);
    Result := True;
{$ENDIF CRYPTOLIB_X86_SIMD}
  except
    AKernel := nil;
    Result := False;
  end;
end;

initialization
  TCipherKernelRegistry.Register(
    TChaCha20Poly1305X86KernelFactory.Create()
    as IChaCha20Poly1305KernelFactory);

end.
