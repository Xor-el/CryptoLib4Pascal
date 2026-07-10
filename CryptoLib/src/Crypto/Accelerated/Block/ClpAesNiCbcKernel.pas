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
  ClpAcceleratedKernelTypes,
  ClpIAcceleratedCbcKernel,
  ClpAcceleratedKernelFactoryBase,
  ClpAcceleratedKernelRegistry,
  ClpAesNiFusedX86Backend;

type
  /// <summary>
  ///   AES-NI implementation of IAcceleratedCbcKernel: the serial CBC-encrypt chain
  ///   C_i = E_K(P_i xor C_{i-1}) applied over a whole run in one call, with the
  ///   chaining value held in a register between blocks (kernel body in
  ///   Include\Simd\Aes\Cbc). Reuses the shared 1-wide AES round chain
  ///   (AesNiOneRoundsOnly). Available on x86_64 (CRYPTOLIB_X86_64_ASM) and i386
  ///   (CRYPTOLIB_I386_ASM), gated collectively by CRYPTOLIB_X86_SIMD. When
  ///   unavailable the factory returns nil and TCbcBlockCipher keeps its existing
  ///   per-block bulk path.
  /// </summary>
  TAesNiCbcKernel = class sealed(TInterfacedObject, IAcceleratedCbcKernel)
  strict private
    // FEngine is retained so the round-key buffer FKeys points into stays alive
    // for the kernel's lifetime.
    FEngine: IAesEngineX86;
    FKeys: Pointer;
    FRounds: Int32;
  public
    constructor Create(const AEngine: IAesEngineX86; AKeys: Pointer;
      ARounds: Int32);
    procedure ProcessCbcBlocks(AInPtr, AOutPtr, AIvPtr: Pointer;
      ABlockCount: NativeInt);
  end;

  TAesNiCbcKernelFactory = class sealed(TAcceleratedKernelFactoryBase, IAcceleratedCbcKernelFactory)
  public
    function ProviderName: String; override;
    function TryCreate(const ACipher: IBlockCipher;
      ADirection: TAcceleratedKernelDirection;
      out AKernel: IAcceleratedCbcKernel): Boolean;
  end;

implementation

{$IFDEF CRYPTOLIB_X86_SIMD}

type
  // Context handed to the fused AES-NI CBC-encrypt kernel. Field offsets match
  // the [rcx + N] / [ebx + N] accesses in AesNiCbcEncryptSerial_x86_64.inc and
  // AesNiCbcEncryptSerial_i386.inc (8-byte fields on x86_64, 4-byte on i386). The
  // kernel loops internally over BlockCount blocks, advancing InPtr/OutPtr and
  // updating the 16-byte chaining value at IvPtr in place.
  TCbcEncryptFusedCtx = record
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

{$ENDIF CRYPTOLIB_X86_SIMD}

{ TAesNiCbcKernel }

constructor TAesNiCbcKernel.Create(const AEngine: IAesEngineX86;
  AKeys: Pointer; ARounds: Int32);
begin
  inherited Create;
  FEngine := AEngine;
  FKeys := AKeys;
  FRounds := ARounds;
end;

procedure TAesNiCbcKernel.ProcessCbcBlocks(AInPtr, AOutPtr, AIvPtr: Pointer;
  ABlockCount: NativeInt);
{$IFDEF CRYPTOLIB_X86_SIMD}
var
  LCtx: TCbcEncryptFusedCtx;
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
  case FRounds of
    10: AesNiCbcEncrypt128(@LCtx);
    12: AesNiCbcEncrypt192(@LCtx);
  else
    AesNiCbcEncrypt256(@LCtx);
  end;
{$ENDIF CRYPTOLIB_X86_SIMD}
end;

{ TAesNiCbcKernelFactory }

function TAesNiCbcKernelFactory.ProviderName: String;
begin
  Result := 'AES-NI';
end;

function TAesNiCbcKernelFactory.TryCreate(const ACipher: IBlockCipher;
  ADirection: TAcceleratedKernelDirection; out AKernel: IAcceleratedCbcKernel): Boolean;
var
  LEngine: IAesEngineX86;
  LKeys: PByte;
  LRounds: Int32;
begin
  AKernel := nil;
  Result := False;
  if ADirection <> TAcceleratedKernelDirection.Encrypt then
    Exit; // only encrypt is implemented; decrypt not yet supported
  try
{$IFDEF CRYPTOLIB_X86_SIMD}
    if not TAesNiFusedX86Backend.TryResolveEngine(ACipher, LEngine) then
      Exit;
    if not LEngine.TryGetEncKeysPtr(LKeys, LRounds) then
      Exit;
    if not (LRounds in [10, 12, 14]) then
      Exit;
    AKernel := TAesNiCbcKernel.Create(LEngine, LKeys, LRounds);
    Result := True;
{$ENDIF CRYPTOLIB_X86_SIMD}
  except
    AKernel := nil;
    Result := False;
  end;
end;

initialization
  TAcceleratedKernelRegistry.RegisterCbcFactory(
    TAesNiCbcKernelFactory.Create() as IAcceleratedCbcKernelFactory);

end.
