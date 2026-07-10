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

unit ClpAesNiCbcKernel;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpIBlockCipher,
  ClpIAesEngineX86,
  ClpCipherKernelTypes,
  ClpICbcKernel,
  ClpCipherKernelFactoryBase,
  ClpCipherKernelRegistry,
  ClpAesNiFusedX86Backend;

type
  /// <summary>
  ///   AES-NI implementation of ICbcKernel, applied over a whole run in one
  ///   call (kernel bodies in Include\Simd\Aes\Cbc). Encrypt runs the serial
  ///   chain C_i = E_K(P_i xor C_{i-1}) 1-wide with the chaining value held in
  ///   a register (reusing AesNiOneRoundsOnly). Decrypt runs P_i = D_K(C_i) xor
  ///   C_{i-1}: the inverse transforms are independent, so it decrypts 8-wide
  ///   (x86_64) / 4-wide (i386) and folds the chain XOR into that pass, turning
  ///   the mode's decrypt-then-XOR two passes into one. Direction is fixed at
  ///   construction. Available on x86_64 (CRYPTOLIB_X86_64_ASM) and i386
  ///   (CRYPTOLIB_I386_ASM), gated collectively by CRYPTOLIB_X86_SIMD. When
  ///   unavailable the factory returns nil and TCbcBlockCipher keeps its
  ///   existing per-block / two-pass bulk paths.
  /// </summary>
  TAesNiCbcKernel = class sealed(TInterfacedObject, ICbcKernel)
  strict private
    // FEngine is retained so the round-key buffer FKeys points into stays alive
    // for the kernel's lifetime.
    FEngine: IAesEngineX86;
    FKeys: Pointer;
    FRounds: Int32;
    FDirection: TCipherKernelDirection;
  public
    constructor Create(const AEngine: IAesEngineX86; AKeys: Pointer;
      ARounds: Int32; ADirection: TCipherKernelDirection);
    procedure ProcessCbcBlocks(AInPtr, AOutPtr, AIvPtr: Pointer;
      ABlockCount: NativeInt);
  end;

  TAesNiCbcKernelFactory = class sealed(TCipherKernelFactoryBase, ICbcKernelFactory)
  public
    function ProviderName: String; override;
    function TryCreate(const ACipher: IBlockCipher;
      ADirection: TCipherKernelDirection;
      out AKernel: ICbcKernel): Boolean;
  end;

implementation

{$IFDEF CRYPTOLIB_X86_SIMD}

type
  // Context handed to the fused AES-NI CBC kernels (both directions share the
  // same shape). Field offsets match the [rcx + N] / [ebx + N] accesses in
  // AesNiCbc{Encrypt,Decrypt}*_{x86_64,i386}.inc (8-byte fields on x86_64,
  // 4-byte on i386). Each kernel loops internally over BlockCount blocks,
  // advancing InPtr/OutPtr and updating the 16-byte chaining value at IvPtr in
  // place.
  TCbcFusedCtx = record
    InPtr: Pointer;
    OutPtr: Pointer;
    KeysPtr: Pointer;
    IvPtr: Pointer;
    BlockCount: NativeUInt;
  end;

// Fused AES-NI CBC encryption (C_i = E_K(P_i xor C_{i-1})). Each proc processes
// BlockCount blocks, looping internally, and writes the final ciphertext block
// back to the chaining slot at IvPtr.
procedure AesNiCbcEncrypt128(PCtx: Pointer);
{$DEFINE CRYPTOLIB_AESNI_KEY128}
{$IFDEF CRYPTOLIB_X86_64_ASM}
{$I ..\..\..\Include\Simd\Common\ClpSimdProc1Begin_x86_64.inc}
{$I ..\..\..\Include\Simd\Aes\Cbc\AesNiCbcEncryptSerial_x86_64.inc}
{$ENDIF}
{$IFDEF CRYPTOLIB_I386_ASM}
{$I ..\..\..\Include\Simd\Common\ClpSimdProc1Begin_i386.inc}
{$I ..\..\..\Include\Simd\Aes\Cbc\AesNiCbcEncryptSerial_i386.inc}
{$ENDIF}
{$UNDEF CRYPTOLIB_AESNI_KEY128}
end;

procedure AesNiCbcEncrypt192(PCtx: Pointer);
{$DEFINE CRYPTOLIB_AESNI_KEY192}
{$IFDEF CRYPTOLIB_X86_64_ASM}
{$I ..\..\..\Include\Simd\Common\ClpSimdProc1Begin_x86_64.inc}
{$I ..\..\..\Include\Simd\Aes\Cbc\AesNiCbcEncryptSerial_x86_64.inc}
{$ENDIF}
{$IFDEF CRYPTOLIB_I386_ASM}
{$I ..\..\..\Include\Simd\Common\ClpSimdProc1Begin_i386.inc}
{$I ..\..\..\Include\Simd\Aes\Cbc\AesNiCbcEncryptSerial_i386.inc}
{$ENDIF}
{$UNDEF CRYPTOLIB_AESNI_KEY192}
end;

procedure AesNiCbcEncrypt256(PCtx: Pointer);
{$DEFINE CRYPTOLIB_AESNI_KEY256}
{$IFDEF CRYPTOLIB_X86_64_ASM}
{$I ..\..\..\Include\Simd\Common\ClpSimdProc1Begin_x86_64.inc}
{$I ..\..\..\Include\Simd\Aes\Cbc\AesNiCbcEncryptSerial_x86_64.inc}
{$ENDIF}
{$IFDEF CRYPTOLIB_I386_ASM}
{$I ..\..\..\Include\Simd\Common\ClpSimdProc1Begin_i386.inc}
{$I ..\..\..\Include\Simd\Aes\Cbc\AesNiCbcEncryptSerial_i386.inc}
{$ENDIF}
{$UNDEF CRYPTOLIB_AESNI_KEY256}
end;

// Fused AES-NI CBC decryption (P_i = D_K(C_i) xor C_{i-1}). Each proc processes
// BlockCount blocks in 8-wide (x86_64) / 4-wide (i386) batches with a 1-wide
// tail, looping internally, and writes the final ciphertext block back to the
// chaining slot at IvPtr. Consumes the inverse-MixColumns (decrypt) schedule.
procedure AesNiCbcDecrypt128(PCtx: Pointer);
{$DEFINE CRYPTOLIB_AESNI_KEY128}
{$DEFINE CRYPTOLIB_AESNI_DECRYPT}
{$IFDEF CRYPTOLIB_X86_64_ASM}
{$I ..\..\..\Include\Simd\Common\ClpSimdProc1Begin_x86_64.inc}
{$I ..\..\..\Include\Simd\Aes\Cbc\AesNiCbcDecryptWide_x86_64.inc}
{$ENDIF}
{$IFDEF CRYPTOLIB_I386_ASM}
{$I ..\..\..\Include\Simd\Common\ClpSimdProc1Begin_i386.inc}
{$I ..\..\..\Include\Simd\Aes\Cbc\AesNiCbcDecryptWide_i386.inc}
{$ENDIF}
{$UNDEF CRYPTOLIB_AESNI_DECRYPT}
{$UNDEF CRYPTOLIB_AESNI_KEY128}
end;

procedure AesNiCbcDecrypt192(PCtx: Pointer);
{$DEFINE CRYPTOLIB_AESNI_KEY192}
{$DEFINE CRYPTOLIB_AESNI_DECRYPT}
{$IFDEF CRYPTOLIB_X86_64_ASM}
{$I ..\..\..\Include\Simd\Common\ClpSimdProc1Begin_x86_64.inc}
{$I ..\..\..\Include\Simd\Aes\Cbc\AesNiCbcDecryptWide_x86_64.inc}
{$ENDIF}
{$IFDEF CRYPTOLIB_I386_ASM}
{$I ..\..\..\Include\Simd\Common\ClpSimdProc1Begin_i386.inc}
{$I ..\..\..\Include\Simd\Aes\Cbc\AesNiCbcDecryptWide_i386.inc}
{$ENDIF}
{$UNDEF CRYPTOLIB_AESNI_DECRYPT}
{$UNDEF CRYPTOLIB_AESNI_KEY192}
end;

procedure AesNiCbcDecrypt256(PCtx: Pointer);
{$DEFINE CRYPTOLIB_AESNI_KEY256}
{$DEFINE CRYPTOLIB_AESNI_DECRYPT}
{$IFDEF CRYPTOLIB_X86_64_ASM}
{$I ..\..\..\Include\Simd\Common\ClpSimdProc1Begin_x86_64.inc}
{$I ..\..\..\Include\Simd\Aes\Cbc\AesNiCbcDecryptWide_x86_64.inc}
{$ENDIF}
{$IFDEF CRYPTOLIB_I386_ASM}
{$I ..\..\..\Include\Simd\Common\ClpSimdProc1Begin_i386.inc}
{$I ..\..\..\Include\Simd\Aes\Cbc\AesNiCbcDecryptWide_i386.inc}
{$ENDIF}
{$UNDEF CRYPTOLIB_AESNI_DECRYPT}
{$UNDEF CRYPTOLIB_AESNI_KEY256}
end;

{$ENDIF CRYPTOLIB_X86_SIMD}

{ TAesNiCbcKernel }

constructor TAesNiCbcKernel.Create(const AEngine: IAesEngineX86;
  AKeys: Pointer; ARounds: Int32; ADirection: TCipherKernelDirection);
begin
  inherited Create;
  FEngine := AEngine;
  FKeys := AKeys;
  FRounds := ARounds;
  FDirection := ADirection;
end;

procedure TAesNiCbcKernel.ProcessCbcBlocks(AInPtr, AOutPtr, AIvPtr: Pointer;
  ABlockCount: NativeInt);
{$IFDEF CRYPTOLIB_X86_SIMD}
var
  LCtx: TCbcFusedCtx;
{$ENDIF CRYPTOLIB_X86_SIMD}
begin
{$IFDEF CRYPTOLIB_X86_SIMD}
  if ABlockCount <= 0 then
    Exit;
  LCtx.InPtr := AInPtr;
  LCtx.OutPtr := AOutPtr;
  LCtx.KeysPtr := FKeys;
  LCtx.IvPtr := AIvPtr;
  LCtx.BlockCount := NativeUInt(ABlockCount);
  if FDirection = TCipherKernelDirection.Decrypt then
  begin
    case FRounds of
      10: AesNiCbcDecrypt128(@LCtx);
      12: AesNiCbcDecrypt192(@LCtx);
    else
      AesNiCbcDecrypt256(@LCtx);
    end;
  end
  else
  begin
    case FRounds of
      10: AesNiCbcEncrypt128(@LCtx);
      12: AesNiCbcEncrypt192(@LCtx);
    else
      AesNiCbcEncrypt256(@LCtx);
    end;
  end;
{$ENDIF CRYPTOLIB_X86_SIMD}
end;

{ TAesNiCbcKernelFactory }

function TAesNiCbcKernelFactory.ProviderName: String;
begin
  Result := 'AES-NI';
end;

function TAesNiCbcKernelFactory.TryCreate(const ACipher: IBlockCipher;
  ADirection: TCipherKernelDirection; out AKernel: ICbcKernel): Boolean;
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
    // Encrypt consumes the forward schedule; decrypt the inverse-MixColumns
    // schedule. The relevant accessor only succeeds when the engine is keyed
    // for that direction, so this also validates state.
    if ADirection = TCipherKernelDirection.Decrypt then
    begin
      if not LEngine.TryGetDecKeysPtr(LKeys, LRounds) then
        Exit;
    end
    else if not LEngine.TryGetEncKeysPtr(LKeys, LRounds) then
      Exit;
    if not (LRounds in [10, 12, 14]) then
      Exit;
    AKernel := TAesNiCbcKernel.Create(LEngine, LKeys, LRounds, ADirection);
    Result := True;
{$ENDIF CRYPTOLIB_X86_SIMD}
  except
    AKernel := nil;
    Result := False;
  end;
end;

initialization
  TCipherKernelRegistry.Register(
    TAesNiCbcKernelFactory.Create() as ICbcKernelFactory);

end.
