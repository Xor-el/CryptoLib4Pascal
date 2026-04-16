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

unit ClpAesEngineX86;

{$I ..\..\Include\CryptoLib.inc}

interface

{$IFDEF CRYPTOLIB_X86_SIMD}

uses
  SysUtils,
  ClpIAesEngineX86,
  ClpIBlockCipher,
  ClpICipherParameters,
  ClpIKeyParameter,
  ClpCpuFeatures,
  ClpCheck,
  ClpArrayUtilities,
  ClpBitOperations,
  ClpCryptoLibTypes,
  ClpPlatformUtilities;

resourcestring
  SInputBuffertooShort = 'Input Buffer too Short';
  SOutputBufferTooShort = 'Output Buffer too Short';
  SAesEngineX86NotSupported = 'AES hardware engine not supported on this platform.';
  SInvalidParameterAESX86Init = 'Invalid Parameter Passed to AES Init - "%s"';
  SInvalidKeyLength = 'Key Length not 128/192/256 bits.';
  SAesEngineX86NotInitialised = 'AES Engine not Initialised';
  SNilPointerBuffer = 'Input or output pointer is nil.';

type
  /// <summary>
  /// AES using AES-NI when supported (see <see cref="IsSupported" />).
  /// </summary>
  TAesEngineX86 = class sealed(TInterfacedObject, IAesEngineX86, IBlockCipher)
  strict private
  type
    TAesX86Mode = (Uninitialized, Dec128, Dec192, Dec256, Enc128, Enc192, Enc256);
    TAesNiCipherProc = procedure(State, Keys: PByte);
  strict private
    FMode: TAesX86Mode;
    FNRounds: Int32;
    FRawAlloc: Pointer;
    FKeys: PByte;
    FAesNiCipherOne: TAesNiCipherProc;
    FAesNiCipherFour: TAesNiCipherProc;
    procedure FreeAlignedKeys;
    procedure AllocAlignedKeys(AKeyBytes: Int32);
    procedure CreateRoundKeys(AForEncryption: Boolean; const AKey: TCryptoLibByteArray);
    procedure PrepareDecryptRoundKeys;
    procedure BindCipherPointers;
    procedure ImplRounds(AState: PByte);
  strict protected
    function GetAlgorithmName: String;
  public
    class function IsSupported: Boolean; static;
    constructor Create();
    destructor Destroy(); override;
    procedure Init(AForEncryption: Boolean; const AParameters: ICipherParameters);
    function GetBlockSize(): Int32;
    function ProcessBlock(const AInput: TCryptoLibByteArray; AInOff: Int32;
      const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32; overload;
    function ProcessFourBlocks(const AInput: TCryptoLibByteArray; AInOff: Int32;
      const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32; overload;
    /// <summary>
    /// One 16-byte block via pointers (not on IAesEngineX86 — IBlockCipher has no overload slot without
    /// touching every cipher). Same semantics as the PByte path used internally for four blocks.
    /// </summary>
    function ProcessBlock(AInput, AOutput: PByte): Int32; overload;
    function ProcessFourBlocks(AInput, AOutput: PByte): Int32; overload;
    property AlgorithmName: String read GetAlgorithmName;
  end;

{$ENDIF}

implementation

{$IFDEF CRYPTOLIB_X86_SIMD}

{$IFDEF CRYPTOLIB_X86_64_ASM}

procedure AesNiExpandRoundKeys128(Key, KeysOut: PByte);
{$I ..\..\Include\Simd\Common\SimdProc2Begin_x86_64.inc}
{$I ..\..\Include\Simd\Aes\AesNiExpandRoundKeys128_x86_64.inc}
end;

procedure AesNiExpandRoundKeys192(Key, KeysOut: PByte);
{$I ..\..\Include\Simd\Common\SimdProc2Begin_x86_64.inc}
{$I ..\..\Include\Simd\Aes\AesNiExpandRoundKeys192_x86_64.inc}
end;

procedure AesNiExpandRoundKeys256(Key, KeysOut: PByte);
{$I ..\..\Include\Simd\Common\SimdProc2Begin_x86_64.inc}
{$I ..\..\Include\Simd\Aes\AesNiExpandRoundKeys256_x86_64.inc}
end;

procedure AesNiPrepareDecryptRoundKeys(Keys: PByte; NRounds: Int32);
{$I ..\..\Include\Simd\Common\SimdProc2Begin_x86_64.inc}
{$I ..\..\Include\Simd\Aes\AesNiPrepareDecryptRoundKeys_x86_64.inc}
end;

procedure AesNiOneEnc128(State, Keys: PByte);
{$I ..\..\Include\Simd\Common\SimdProc2Begin_x86_64.inc}
{$I ..\..\Include\Simd\Aes\AesNiOneEnc128_x86_64.inc}
end;

procedure AesNiOneEnc192(State, Keys: PByte);
{$I ..\..\Include\Simd\Common\SimdProc2Begin_x86_64.inc}
{$I ..\..\Include\Simd\Aes\AesNiOneEnc192_x86_64.inc}
end;

procedure AesNiOneEnc256(State, Keys: PByte);
{$I ..\..\Include\Simd\Common\SimdProc2Begin_x86_64.inc}
{$I ..\..\Include\Simd\Aes\AesNiOneEnc256_x86_64.inc}
end;

procedure AesNiOneDec128(State, Keys: PByte);
{$I ..\..\Include\Simd\Common\SimdProc2Begin_x86_64.inc}
{$I ..\..\Include\Simd\Aes\AesNiOneDec128_x86_64.inc}
end;

procedure AesNiOneDec192(State, Keys: PByte);
{$I ..\..\Include\Simd\Common\SimdProc2Begin_x86_64.inc}
{$I ..\..\Include\Simd\Aes\AesNiOneDec192_x86_64.inc}
end;

procedure AesNiOneDec256(State, Keys: PByte);
{$I ..\..\Include\Simd\Common\SimdProc2Begin_x86_64.inc}
{$I ..\..\Include\Simd\Aes\AesNiOneDec256_x86_64.inc}
end;

procedure AesNiFourEnc128(State, Keys: PByte);
{$I ..\..\Include\Simd\Common\SimdProc2Begin_x86_64.inc}
{$I ..\..\Include\Simd\Aes\AesNiFourEnc128_x86_64.inc}
end;

procedure AesNiFourEnc192(State, Keys: PByte);
{$I ..\..\Include\Simd\Common\SimdProc2Begin_x86_64.inc}
{$I ..\..\Include\Simd\Aes\AesNiFourEnc192_x86_64.inc}
end;

procedure AesNiFourEnc256(State, Keys: PByte);
{$I ..\..\Include\Simd\Common\SimdProc2Begin_x86_64.inc}
{$I ..\..\Include\Simd\Aes\AesNiFourEnc256_x86_64.inc}
end;

procedure AesNiFourDec128(State, Keys: PByte);
{$I ..\..\Include\Simd\Common\SimdProc2Begin_x86_64.inc}
{$I ..\..\Include\Simd\Aes\AesNiFourDec128_x86_64.inc}
end;

procedure AesNiFourDec192(State, Keys: PByte);
{$I ..\..\Include\Simd\Common\SimdProc2Begin_x86_64.inc}
{$I ..\..\Include\Simd\Aes\AesNiFourDec192_x86_64.inc}
end;

procedure AesNiFourDec256(State, Keys: PByte);
{$I ..\..\Include\Simd\Common\SimdProc2Begin_x86_64.inc}
{$I ..\..\Include\Simd\Aes\AesNiFourDec256_x86_64.inc}
end;

{$ENDIF CRYPTOLIB_X86_64_ASM}

{$IFDEF CRYPTOLIB_I386_ASM}

procedure AesNiExpandRoundKeys128(Key, KeysOut: PByte);
{$I ..\..\Include\Simd\Common\SimdProc2Begin_i386.inc}
{$I ..\..\Include\Simd\Aes\AesNiExpandRoundKeys128_i386.inc}
end;

procedure AesNiExpandRoundKeys192(Key, KeysOut: PByte);
{$I ..\..\Include\Simd\Common\SimdProc2Begin_i386.inc}
{$I ..\..\Include\Simd\Aes\AesNiExpandRoundKeys192_i386.inc}
end;

procedure AesNiExpandRoundKeys256(Key, KeysOut: PByte);
{$I ..\..\Include\Simd\Common\SimdProc2Begin_i386.inc}
{$I ..\..\Include\Simd\Aes\AesNiExpandRoundKeys256_i386.inc}
end;

procedure AesNiPrepareDecryptRoundKeys(Keys: PByte; NRounds: Int32);
{$I ..\..\Include\Simd\Common\SimdProc2Begin_i386.inc}
{$I ..\..\Include\Simd\Aes\AesNiPrepareDecryptRoundKeys_i386.inc}
end;

procedure AesNiOneEnc128(State, Keys: PByte);
{$I ..\..\Include\Simd\Common\SimdProc2Begin_i386.inc}
{$I ..\..\Include\Simd\Aes\AesNiOneEnc128_i386.inc}
end;

procedure AesNiOneEnc192(State, Keys: PByte);
{$I ..\..\Include\Simd\Common\SimdProc2Begin_i386.inc}
{$I ..\..\Include\Simd\Aes\AesNiOneEnc192_i386.inc}
end;

procedure AesNiOneEnc256(State, Keys: PByte);
{$I ..\..\Include\Simd\Common\SimdProc2Begin_i386.inc}
{$I ..\..\Include\Simd\Aes\AesNiOneEnc256_i386.inc}
end;

procedure AesNiOneDec128(State, Keys: PByte);
{$I ..\..\Include\Simd\Common\SimdProc2Begin_i386.inc}
{$I ..\..\Include\Simd\Aes\AesNiOneDec128_i386.inc}
end;

procedure AesNiOneDec192(State, Keys: PByte);
{$I ..\..\Include\Simd\Common\SimdProc2Begin_i386.inc}
{$I ..\..\Include\Simd\Aes\AesNiOneDec192_i386.inc}
end;

procedure AesNiOneDec256(State, Keys: PByte);
{$I ..\..\Include\Simd\Common\SimdProc2Begin_i386.inc}
{$I ..\..\Include\Simd\Aes\AesNiOneDec256_i386.inc}
end;

procedure AesNiFourEnc128(State, Keys: PByte);
{$I ..\..\Include\Simd\Common\SimdProc2Begin_i386.inc}
{$I ..\..\Include\Simd\Aes\AesNiFourEnc128_i386.inc}
end;

procedure AesNiFourEnc192(State, Keys: PByte);
{$I ..\..\Include\Simd\Common\SimdProc2Begin_i386.inc}
{$I ..\..\Include\Simd\Aes\AesNiFourEnc192_i386.inc}
end;

procedure AesNiFourEnc256(State, Keys: PByte);
{$I ..\..\Include\Simd\Common\SimdProc2Begin_i386.inc}
{$I ..\..\Include\Simd\Aes\AesNiFourEnc256_i386.inc}
end;

procedure AesNiFourDec128(State, Keys: PByte);
{$I ..\..\Include\Simd\Common\SimdProc2Begin_i386.inc}
{$I ..\..\Include\Simd\Aes\AesNiFourDec128_i386.inc}
end;

procedure AesNiFourDec192(State, Keys: PByte);
{$I ..\..\Include\Simd\Common\SimdProc2Begin_i386.inc}
{$I ..\..\Include\Simd\Aes\AesNiFourDec192_i386.inc}
end;

procedure AesNiFourDec256(State, Keys: PByte);
{$I ..\..\Include\Simd\Common\SimdProc2Begin_i386.inc}
{$I ..\..\Include\Simd\Aes\AesNiFourDec256_i386.inc}
end;

{$ENDIF CRYPTOLIB_I386_ASM}

{ TAesEngineX86 }

class function TAesEngineX86.IsSupported: Boolean;
begin
  Result := TCpuFeatures.X86.HasAESNI();
end;

constructor TAesEngineX86.Create();
begin
  inherited Create();
  if not IsSupported then
    raise EInvalidOperationCryptoLibException.CreateRes(@SAesEngineX86NotSupported);
  FRawAlloc := nil;
  FKeys := nil;
  FNRounds := 0;
  FMode := TAesX86Mode.Uninitialized;
  FAesNiCipherOne := nil;
  FAesNiCipherFour := nil;
end;

destructor TAesEngineX86.Destroy();
begin
  FreeAlignedKeys;
  inherited;
end;

procedure TAesEngineX86.FreeAlignedKeys;
var
  LKeyBytes: Int32;
begin
  if FRawAlloc <> nil then
  begin
    if (FKeys <> nil) and (FNRounds > 0) then
    begin
      LKeyBytes := (FNRounds + 1) * 16;
      FillChar(FKeys^, LKeyBytes, 0);
    end;
    FreeMem(FRawAlloc);
  end;
  FRawAlloc := nil;
  FKeys := nil;
  FNRounds := 0;
  FMode := TAesX86Mode.Uninitialized;
  FAesNiCipherOne := nil;
  FAesNiCipherFour := nil;
end;

procedure TAesEngineX86.AllocAlignedKeys(AKeyBytes: Int32);
var
  LPtr: NativeUInt;
begin
  FreeAlignedKeys;
  if AKeyBytes <= 0 then
    Exit;
  GetMem(FRawAlloc, NativeUInt(AKeyBytes) + 16);
  LPtr := NativeUInt(FRawAlloc);
  LPtr := (LPtr + 15) and not NativeUInt(15);
  FKeys := PByte(LPtr);
  FillChar(FKeys^, AKeyBytes, 0);
end;

function TAesEngineX86.GetAlgorithmName: String;
begin
  Result := 'AES';
end;

function TAesEngineX86.GetBlockSize(): Int32;
begin
  Result := 16;
end;

procedure TAesEngineX86.PrepareDecryptRoundKeys;
begin
  AesNiPrepareDecryptRoundKeys(FKeys, FNRounds);
end;

procedure TAesEngineX86.CreateRoundKeys(AForEncryption: Boolean;
  const AKey: TCryptoLibByteArray);
var
  LK: PByte;
  LKeyLen: Int32;
begin
  LKeyLen := System.Length(AKey);
  if ((LKeyLen < 16) or (LKeyLen > 32) or ((LKeyLen and 7) <> 0)) then
  begin
    TArrayUtilities.Fill<Byte>(AKey, 0, LKeyLen, Byte(0));
    raise EArgumentCryptoLibException.CreateRes(@SInvalidKeyLength);
  end;

  LK := FKeys;

  case LKeyLen of
    16:
      begin
        FNRounds := 10;
        AesNiExpandRoundKeys128(@AKey[0], LK);
      end;
    24:
      begin
        FNRounds := 12;
        AesNiExpandRoundKeys192(@AKey[0], LK);
      end;
    32:
      begin
        FNRounds := 14;
        AesNiExpandRoundKeys256(@AKey[0], LK);
      end;
  else
    TArrayUtilities.Fill<Byte>(AKey, 0, LKeyLen, Byte(0));
    raise EArgumentCryptoLibException.CreateRes(@SInvalidKeyLength);
  end;

  if not AForEncryption then
    PrepareDecryptRoundKeys;
end;

procedure TAesEngineX86.BindCipherPointers;
begin
  FAesNiCipherOne := nil;
  FAesNiCipherFour := nil;
  // Bind once per Init to straight-line ASM. i386: args in eax/edx at entry; bodies use ebx/esi after SimdProc2Begin. x86_64: rcx/rdx throughout.
{$IF DEFINED(CRYPTOLIB_X86_SIMD)}
  case FMode of
    TAesX86Mode.Enc128:
      begin
        FAesNiCipherOne := @AesNiOneEnc128;
        FAesNiCipherFour := @AesNiFourEnc128;
      end;
    TAesX86Mode.Enc192:
      begin
        FAesNiCipherOne := @AesNiOneEnc192;
        FAesNiCipherFour := @AesNiFourEnc192;
      end;
    TAesX86Mode.Enc256:
      begin
        FAesNiCipherOne := @AesNiOneEnc256;
        FAesNiCipherFour := @AesNiFourEnc256;
      end;
    TAesX86Mode.Dec128:
      begin
        FAesNiCipherOne := @AesNiOneDec128;
        FAesNiCipherFour := @AesNiFourDec128;
      end;
    TAesX86Mode.Dec192:
      begin
        FAesNiCipherOne := @AesNiOneDec192;
        FAesNiCipherFour := @AesNiFourDec192;
      end;
    TAesX86Mode.Dec256:
      begin
        FAesNiCipherOne := @AesNiOneDec256;
        FAesNiCipherFour := @AesNiFourDec256;
      end;
  else
    // stay nil
  end;
{$IFEND}
end;

procedure TAesEngineX86.ImplRounds(AState: PByte);
begin
{$IF DEFINED(CRYPTOLIB_X86_SIMD)}
  if not Assigned(FAesNiCipherOne) then
    raise EInvalidOperationCryptoLibException.CreateRes(@SAesEngineX86NotInitialised);
  FAesNiCipherOne(AState, FKeys);
{$IFEND}
end;

procedure TAesEngineX86.Init(AForEncryption: Boolean;
  const AParameters: ICipherParameters);
var
  LKeyParameter: IKeyParameter;
  LKeyCopy: TCryptoLibByteArray;
  LKeyLen: Int32;
begin
  if not Supports(AParameters, IKeyParameter, LKeyParameter) then
    raise EArgumentCryptoLibException.CreateResFmt(@SInvalidParameterAESX86Init,
      [TPlatformUtilities.GetTypeName(AParameters as TObject)]);

  LKeyCopy := System.Copy(LKeyParameter.GetKey());
  try
    LKeyLen := System.Length(LKeyCopy);
    if not (LKeyLen in [16, 24, 32]) then
      raise EArgumentCryptoLibException.CreateRes(@SInvalidKeyLength);

    AllocAlignedKeys((TBitOperations.Asr32(LKeyLen, 2) + 6 + 1) * 16);

    case LKeyLen of
      16:
        if AForEncryption then
          FMode := TAesX86Mode.Enc128
        else
          FMode := TAesX86Mode.Dec128;
      24:
        if AForEncryption then
          FMode := TAesX86Mode.Enc192
        else
          FMode := TAesX86Mode.Dec192;
      32:
        if AForEncryption then
          FMode := TAesX86Mode.Enc256
        else
          FMode := TAesX86Mode.Dec256;
    end;

    CreateRoundKeys(AForEncryption, LKeyCopy);
    BindCipherPointers;
  finally
    TArrayUtilities.Fill<Byte>(LKeyCopy, 0, System.Length(LKeyCopy), Byte(0));
  end;
end;

function TAesEngineX86.ProcessBlock(const AInput: TCryptoLibByteArray;
  AInOff: Int32; const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32;
var
  LBuf: array [0 .. 15] of Byte;
begin
  if FKeys = nil then
    raise EInvalidOperationCryptoLibException.CreateRes(@SAesEngineX86NotInitialised);

  TCheck.DataLength(AInput, AInOff, 16, SInputBuffertooShort);
  TCheck.OutputLength(AOutput, AOutOff, 16, SOutputBufferTooShort);

  System.Move(AInput[AInOff], LBuf[0], 16);
  ImplRounds(@LBuf[0]);
  System.Move(LBuf[0], AOutput[AOutOff], 16);
  FillChar(LBuf, SizeOf(LBuf), 0);
  Result := 16;
end;

function TAesEngineX86.ProcessFourBlocks(const AInput: TCryptoLibByteArray;
  AInOff: Int32; const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32;
var
  LWork: array [0 .. 63] of Byte;
begin
  if FKeys = nil then
    raise EInvalidOperationCryptoLibException.CreateRes(@SAesEngineX86NotInitialised);
{$IF DEFINED(CRYPTOLIB_X86_SIMD)}
  if not Assigned(FAesNiCipherFour) then
    raise EInvalidOperationCryptoLibException.CreateRes(@SAesEngineX86NotInitialised);
{$IFEND}

  TCheck.DataLength(AInput, AInOff, 64, SInputBuffertooShort);
  TCheck.OutputLength(AOutput, AOutOff, 64, SOutputBufferTooShort);

  System.Move(AInput[AInOff], LWork[0], 64);
{$IF DEFINED(CRYPTOLIB_X86_SIMD)}
  FAesNiCipherFour(@LWork[0], FKeys);
{$IFEND}
  System.Move(LWork[0], AOutput[AOutOff], 64);
  FillChar(LWork, SizeOf(LWork), 0);
  Result := 64;
end;

function TAesEngineX86.ProcessBlock(AInput, AOutput: PByte): Int32;
var
  LBuf: array [0 .. 15] of Byte;
  LSrcAddr, LDstAddr: NativeUInt;
begin
  if FKeys = nil then
    raise EInvalidOperationCryptoLibException.CreateRes(@SAesEngineX86NotInitialised);
  if (AInput = nil) or (AOutput = nil) then
    raise EArgumentCryptoLibException.CreateRes(@SNilPointerBuffer);

{$IF DEFINED(CRYPTOLIB_X86_SIMD)}
  if not Assigned(FAesNiCipherOne) then
    raise EInvalidOperationCryptoLibException.CreateRes(@SAesEngineX86NotInitialised);
{$IFEND}

  if AInput = AOutput then
  begin
    FAesNiCipherOne(AOutput, FKeys);
    Result := 16;
    Exit;
  end;

  LSrcAddr := NativeUInt(AInput);
  LDstAddr := NativeUInt(AOutput);
  if ((LDstAddr >= LSrcAddr) and (LDstAddr < LSrcAddr + 16)) or
    ((LSrcAddr >= LDstAddr) and (LSrcAddr < LDstAddr + 16)) then
  begin
    System.Move(AInput^, LBuf[0], 16);
    FAesNiCipherOne(@LBuf[0], FKeys);
    System.Move(LBuf[0], AOutput^, 16);
    FillChar(LBuf, SizeOf(LBuf), 0);
  end
  else
  begin
    System.Move(AInput^, AOutput^, 16);
    FAesNiCipherOne(AOutput, FKeys);
  end;
  Result := 16;
end;

function TAesEngineX86.ProcessFourBlocks(AInput, AOutput: PByte): Int32;
var
  LWork: array [0 .. 63] of Byte;
  LSrcAddr, LDstAddr: NativeUInt;
begin
  if FKeys = nil then
    raise EInvalidOperationCryptoLibException.CreateRes(@SAesEngineX86NotInitialised);
{$IF DEFINED(CRYPTOLIB_X86_SIMD)}
  if not Assigned(FAesNiCipherFour) then
    raise EInvalidOperationCryptoLibException.CreateRes(@SAesEngineX86NotInitialised);
{$IFEND}
  if (AInput = nil) or (AOutput = nil) then
    raise EArgumentCryptoLibException.CreateRes(@SNilPointerBuffer);

  if AInput = AOutput then
  begin
    FAesNiCipherFour(AOutput, FKeys);
    Result := 64;
    Exit;
  end;

  LSrcAddr := NativeUInt(AInput);
  LDstAddr := NativeUInt(AOutput);
  if ((LDstAddr >= LSrcAddr) and (LDstAddr < LSrcAddr + 64)) or
    ((LSrcAddr >= LDstAddr) and (LSrcAddr < LDstAddr + 64)) then
  begin
    System.Move(AInput^, LWork[0], 64);
    FAesNiCipherFour(@LWork[0], FKeys);
    System.Move(LWork[0], AOutput^, 64);
    FillChar(LWork, SizeOf(LWork), 0);
  end
  else
  begin
    System.Move(AInput^, AOutput^, 64);
    FAesNiCipherFour(AOutput, FKeys);
  end;
  Result := 64;
end;

{$ENDIF}

end.
