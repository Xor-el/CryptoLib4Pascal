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

unit ClpAesCryptoExtCbcKernel;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpIBlockCipher,
  ClpIAesEngineArm,
  ClpCipherKernelTypes,
  ClpICbcKernel,
  ClpCipherKernelFactoryBase,
  ClpCipherKernelRegistry,
  ClpAesCryptoExtFusedArmBackend;

type
  /// <summary>
  ///   AES CryptoExt (ARMv8) implementation of ICbcKernel, applied over a
  ///   whole run in one call (kernel bodies in Include\Simd\Aes\Cbc). Encrypt
  ///   runs the serial chain C_i = E_K(P_i xor C_{i-1}) 1-wide with the
  ///   chaining value held in a register. Decrypt runs P_i = D_K(C_i) xor
  ///   C_{i-1}: the inverse transforms are independent, so it decrypts 8-wide
  ///   and folds the chain XOR into that pass, turning the mode's
  ///   decrypt-then-XOR two passes into one. Direction is fixed at
  ///   construction. Available on aarch64 (CRYPTOLIB_AARCH64_ASM). When
  ///   unavailable the factory returns nil and TCbcBlockCipher keeps its
  ///   existing per-block / two-pass bulk paths.
  /// </summary>
  TAesCryptoExtCbcKernel = class sealed(TInterfacedObject, ICbcKernel)
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
    procedure ProcessCbcBlocks(AInPtr, AOutPtr, AIvPtr: Pointer;
      ABlockCount: NativeInt);
  end;

  TAesCryptoExtCbcKernelFactory = class sealed(TCipherKernelFactoryBase, ICbcKernelFactory)
  public
    function ProviderName: String; override;
    function TryCreate(const ACipher: IBlockCipher;
      ADirection: TCipherKernelDirection;
      out AKernel: ICbcKernel): Boolean;
  end;

implementation

{$IFDEF CRYPTOLIB_AARCH64_ASM}

type
  // Context handed to the fused AES CryptoExt CBC kernels (both directions
  // share the same shape). Field offsets match the [x0 + N] accesses in
  // AesCryptoExtCbc{EncryptSerial,DecryptWide}_aarch64.inc (all 8-byte
  // fields). Each kernel loops internally over BlockCount blocks, advancing
  // InPtr/OutPtr and updating the 16-byte chaining value at IvPtr in place.
  TCbcFusedCtx = record
    InPtr: Pointer;
    OutPtr: Pointer;
    KeysPtr: Pointer;
    IvPtr: Pointer;
    BlockCount: NativeUInt;
  end;

// Fused AES CryptoExt CBC encryption (C_i = E_K(P_i xor C_{i-1})). Each proc
// processes BlockCount blocks, looping internally, and writes the final
// ciphertext block back to the chaining slot at IvPtr.
procedure AesCryptoExtCbcEncrypt128(PCtx: Pointer);
{$DEFINE CRYPTOLIB_AESCRYPTOEXT_KEY128}
{$I ..\..\..\Include\Simd\Common\ClpSimdProc1Begin_aarch64.inc}
{$I ..\..\..\Include\Simd\Aes\Cbc\AesCryptoExtCbcEncryptSerial_aarch64.inc}
{$UNDEF CRYPTOLIB_AESCRYPTOEXT_KEY128}
end;

procedure AesCryptoExtCbcEncrypt192(PCtx: Pointer);
{$DEFINE CRYPTOLIB_AESCRYPTOEXT_KEY192}
{$I ..\..\..\Include\Simd\Common\ClpSimdProc1Begin_aarch64.inc}
{$I ..\..\..\Include\Simd\Aes\Cbc\AesCryptoExtCbcEncryptSerial_aarch64.inc}
{$UNDEF CRYPTOLIB_AESCRYPTOEXT_KEY192}
end;

procedure AesCryptoExtCbcEncrypt256(PCtx: Pointer);
{$DEFINE CRYPTOLIB_AESCRYPTOEXT_KEY256}
{$I ..\..\..\Include\Simd\Common\ClpSimdProc1Begin_aarch64.inc}
{$I ..\..\..\Include\Simd\Aes\Cbc\AesCryptoExtCbcEncryptSerial_aarch64.inc}
{$UNDEF CRYPTOLIB_AESCRYPTOEXT_KEY256}
end;

// Fused AES CryptoExt CBC decryption (P_i = D_K(C_i) xor C_{i-1}). Each proc
// processes BlockCount blocks in 8-wide batches with a 1-wide tail, looping
// internally, and writes the final ciphertext block back to the chaining
// slot at IvPtr. Consumes the inverse-MixColumns (decrypt) schedule.
procedure AesCryptoExtCbcDecrypt128(PCtx: Pointer);
{$DEFINE CRYPTOLIB_AESCRYPTOEXT_KEY128}
{$I ..\..\..\Include\Simd\Common\ClpSimdProc1Begin_aarch64.inc}
{$I ..\..\..\Include\Simd\Aes\Cbc\AesCryptoExtCbcDecryptWide_aarch64.inc}
{$UNDEF CRYPTOLIB_AESCRYPTOEXT_KEY128}
end;

procedure AesCryptoExtCbcDecrypt192(PCtx: Pointer);
{$DEFINE CRYPTOLIB_AESCRYPTOEXT_KEY192}
{$I ..\..\..\Include\Simd\Common\ClpSimdProc1Begin_aarch64.inc}
{$I ..\..\..\Include\Simd\Aes\Cbc\AesCryptoExtCbcDecryptWide_aarch64.inc}
{$UNDEF CRYPTOLIB_AESCRYPTOEXT_KEY192}
end;

procedure AesCryptoExtCbcDecrypt256(PCtx: Pointer);
{$DEFINE CRYPTOLIB_AESCRYPTOEXT_KEY256}
{$I ..\..\..\Include\Simd\Common\ClpSimdProc1Begin_aarch64.inc}
{$I ..\..\..\Include\Simd\Aes\Cbc\AesCryptoExtCbcDecryptWide_aarch64.inc}
{$UNDEF CRYPTOLIB_AESCRYPTOEXT_KEY256}
end;

{$ENDIF CRYPTOLIB_AARCH64_ASM}

{ TAesCryptoExtCbcKernel }

constructor TAesCryptoExtCbcKernel.Create(const AEngine: IAesEngineArm;
  AKeys: Pointer; ARounds: Int32; ADirection: TCipherKernelDirection);
begin
  inherited Create;
  FEngine := AEngine;
  FKeys := AKeys;
  FRounds := ARounds;
  FDirection := ADirection;
end;

procedure TAesCryptoExtCbcKernel.ProcessCbcBlocks(AInPtr, AOutPtr, AIvPtr: Pointer;
  ABlockCount: NativeInt);
{$IFDEF CRYPTOLIB_AARCH64_ASM}
var
  LCtx: TCbcFusedCtx;
{$ENDIF CRYPTOLIB_AARCH64_ASM}
begin
{$IFDEF CRYPTOLIB_AARCH64_ASM}
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
      10: AesCryptoExtCbcDecrypt128(@LCtx);
      12: AesCryptoExtCbcDecrypt192(@LCtx);
    else
      AesCryptoExtCbcDecrypt256(@LCtx);
    end;
  end
  else
  begin
    case FRounds of
      10: AesCryptoExtCbcEncrypt128(@LCtx);
      12: AesCryptoExtCbcEncrypt192(@LCtx);
    else
      AesCryptoExtCbcEncrypt256(@LCtx);
    end;
  end;
{$ENDIF CRYPTOLIB_AARCH64_ASM}
end;

{ TAesCryptoExtCbcKernelFactory }

function TAesCryptoExtCbcKernelFactory.ProviderName: String;
begin
  Result := 'AES-CryptoExt';
end;

function TAesCryptoExtCbcKernelFactory.TryCreate(const ACipher: IBlockCipher;
  ADirection: TCipherKernelDirection; out AKernel: ICbcKernel): Boolean;
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
    AKernel := TAesCryptoExtCbcKernel.Create(LEngine, LKeys, LRounds, ADirection);
    Result := True;
{$ENDIF CRYPTOLIB_AARCH64_ASM}
  except
    AKernel := nil;
    Result := False;
  end;
end;

initialization
  TCipherKernelRegistry.Register(
    TAesCryptoExtCbcKernelFactory.Create() as ICbcKernelFactory);

end.
