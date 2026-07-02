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

unit ClpPoly1305;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpIPoly1305,
  ClpIMac,
  ClpMac,
  ClpIBlockCipher,
  ClpICipherParameters,
  ClpIParametersWithIV,
  ClpIKeyParameter,
  ClpKeyParameter,
  ClpCheck,
  ClpPack,
  ClpBitOperations,
  ClpArrayUtilities,
  ClpPoly1305State,
  ClpPoly1305Simd,
  ClpCryptoLibTypes;

resourcestring
  SCipherBlockSizeMismatch =
    'Poly1305 requires a 128-bit block cipher.';
  SParametersWithIVRequired =
    'Poly1305 requires parameters of type IParametersWithIV when used with a cipher.';
  SKeyParameterRequired =
    'Poly1305 requires a key parameter.';
  SInvalidKeyLength =
    'Poly1305 key must be 256 bits.';
  SInvalidNonce =
    'Poly1305 requires a 128-bit IV when used with a cipher.';

type
  TPoly1305 = class sealed(TMac, IPoly1305, IMac)

  strict private
  const
    BlockSize = Int32(16);

  var
    FCipher: IBlockCipher;
    FState: TPoly1305State;
    // Power table consumed by a SIMD 4-way bulk kernel; nil whenever the
    // scalar path is in use. Lazily allocated by SetKey to the size needed
    // by whichever SIMD variant the CPU picks. Doubles as the dispatch flag
    // read by BlockUpdate (FPowTable <> nil iff a SIMD path is selected).
    FPowTable: TCryptoLibByteArray;
    FCurrentBlock: TCryptoLibByteArray;
    FCurrentBlockOffset: Int32;

    procedure SetKey(const AKeyParameter: IKeyParameter;
      const ANonce: TCryptoLibByteArray);
    procedure ProcessBlock(const ABuf: TCryptoLibByteArray; AOff: Int32);

  strict protected
    function GetAlgorithmName: String; override;

  public
    constructor Create(); overload;
    constructor Create(const ACipher: IBlockCipher); overload;

    function GetMacSize: Int32; override;

    procedure Update(AInput: Byte); override;
    procedure BlockUpdate(const AInput: TCryptoLibByteArray;
      AInOff, ALen: Int32); override;
    procedure Init(const AParameters: ICipherParameters); override;
    function DoFinal(const AOutput: TCryptoLibByteArray; AOutOff: Int32)
      : Int32; overload; override;

    procedure Reset(); override;

    property AlgorithmName: String read GetAlgorithmName;

  end;

implementation

{ Scalar primitives }

const
  // Bit masks applied to the four little-endian 32-bit words of the first
  // half of the Poly1305 key to derive r in canonical clamped form
  // (RFC 7539 section 2.5: "clamp r"). Index k corresponds to the k-th
  // 32-bit word LE_To_UInt32(LKey, 4*k).
  Poly1305RClampMask: array[0..3] of UInt32 = (
    UInt32($03FFFFFF),
    UInt32($03FFFF03),
    UInt32($03FFC0FF),
    UInt32($03F03FFF)
  );

  // Mask for the high (limb-4) word of r after the 8-bit shift; isolates
  // the 20 bits that fit into the radix-2^26 layout.
  Poly1305R4HighMask = UInt32($000FFFFF);

procedure Poly1305StateReset(var AState: TPoly1305State); inline;
begin
  AState.H0 := 0;
  AState.H1 := 0;
  AState.H2 := 0;
  AState.H3 := 0;
  AState.H4 := 0;
end;

// Clamp r and pre-scale s = 5*r from the first 16 bytes of AKey, writing
// the result into AState.R0..R4 / AState.S1..S4. Caller is responsible
// for key length validation; this routine does not bounds-check AKey.
procedure Poly1305StateAbsorbR(var AState: TPoly1305State;
  const AKey: TCryptoLibByteArray);
var
  LT0, LT1, LT2, LT3: UInt32;
begin
  LT0 := TPack.LE_To_UInt32(AKey, 0);
  LT1 := TPack.LE_To_UInt32(AKey, 4);
  LT2 := TPack.LE_To_UInt32(AKey, 8);
  LT3 := TPack.LE_To_UInt32(AKey, 12);

  AState.R0 := LT0 and Poly1305RClampMask[0];
  AState.R1 := ((LT0 shr 26) or (LT1 shl 6)) and Poly1305RClampMask[1];
  AState.R2 := ((LT1 shr 20) or (LT2 shl 12)) and Poly1305RClampMask[2];
  AState.R3 := ((LT2 shr 14) or (LT3 shl 18)) and Poly1305RClampMask[3];
  AState.R4 := (LT3 shr 8) and Poly1305R4HighMask;

  AState.S1 := AState.R1 * 5;
  AState.S2 := AState.R2 * 5;
  AState.S3 := AState.R3 * 5;
  AState.S4 := AState.R4 * 5;
end;

// Pack the Poly1305 "s" key (k0..k3) from 16 bytes starting at ABytes[AOff].
procedure Poly1305StateAbsorbS(var AState: TPoly1305State;
  const ABytes: TCryptoLibByteArray; AOff: Int32);
begin
  AState.K0 := TPack.LE_To_UInt32(ABytes, AOff + 0);
  AState.K1 := TPack.LE_To_UInt32(ABytes, AOff + 4);
  AState.K2 := TPack.LE_To_UInt32(ABytes, AOff + 8);
  AState.K3 := TPack.LE_To_UInt32(ABytes, AOff + 12);
end;

// Process one 16-byte Poly1305 block in scalar form: H = (H + M) * r mod p.
// Used both as the per-byte step (TPoly1305.Update) and as the per-block
// fallback for SIMD variants' tail handling.
procedure Poly1305StateProcessBlock(var AState: TPoly1305State;
  const ABuf: TCryptoLibByteArray; AOff: Int32);
var
  LT0, LT1, LT2, LT3: UInt32;
  LTp0, LTp1, LTp2, LTp3, LTp4: UInt64;
begin
  LT0 := TPack.LE_To_UInt32(ABuf, AOff + 0);
  LT1 := TPack.LE_To_UInt32(ABuf, AOff + 4);
  LT2 := TPack.LE_To_UInt32(ABuf, AOff + 8);
  LT3 := TPack.LE_To_UInt32(ABuf, AOff + 12);

  AState.H0 := AState.H0 + (LT0 and $3FFFFFF);
  AState.H1 := AState.H1 + (((LT1 shl 6) or (LT0 shr 26)) and $3FFFFFF);
  AState.H2 := AState.H2 + (((LT2 shl 12) or (LT1 shr 20)) and $3FFFFFF);
  AState.H3 := AState.H3 + (((LT3 shl 18) or (LT2 shr 14)) and $3FFFFFF);
  AState.H4 := AState.H4 + ((UInt32(1) shl 24) or (LT3 shr 8));

  LTp0 := UInt64(AState.H0) * AState.R0 + UInt64(AState.H1) * AState.S4 +
    UInt64(AState.H2) * AState.S3 + UInt64(AState.H3) * AState.S2 +
    UInt64(AState.H4) * AState.S1;
  LTp1 := UInt64(AState.H0) * AState.R1 + UInt64(AState.H1) * AState.R0 +
    UInt64(AState.H2) * AState.S4 + UInt64(AState.H3) * AState.S3 +
    UInt64(AState.H4) * AState.S2;
  LTp2 := UInt64(AState.H0) * AState.R2 + UInt64(AState.H1) * AState.R1 +
    UInt64(AState.H2) * AState.R0 + UInt64(AState.H3) * AState.S4 +
    UInt64(AState.H4) * AState.S3;
  LTp3 := UInt64(AState.H0) * AState.R3 + UInt64(AState.H1) * AState.R2 +
    UInt64(AState.H2) * AState.R1 + UInt64(AState.H3) * AState.R0 +
    UInt64(AState.H4) * AState.S4;
  LTp4 := UInt64(AState.H0) * AState.R4 + UInt64(AState.H1) * AState.R3 +
    UInt64(AState.H2) * AState.R2 + UInt64(AState.H3) * AState.R1 +
    UInt64(AState.H4) * AState.R0;

  AState.H0 := UInt32(LTp0) and $3FFFFFF;
  LTp1 := LTp1 + (LTp0 shr 26);
  AState.H1 := UInt32(LTp1) and $3FFFFFF;
  LTp2 := LTp2 + (LTp1 shr 26);
  AState.H2 := UInt32(LTp2) and $3FFFFFF;
  LTp3 := LTp3 + (LTp2 shr 26);
  AState.H3 := UInt32(LTp3) and $3FFFFFF;
  LTp4 := LTp4 + (LTp3 shr 26);
  AState.H4 := UInt32(LTp4) and $3FFFFFF;
  AState.H0 := AState.H0 + UInt32(LTp4 shr 26) * 5;
  AState.H1 := AState.H1 + (AState.H0 shr 26);
  AState.H0 := AState.H0 and $3FFFFFF;
end;

// Plain scalar bulk path; iterates Poly1305StateProcessBlock ANumBlocks
// times. Used directly when no SIMD variant is available, and as the
// 0..3-block tail handler for SIMD bulk paths.
procedure Poly1305StateProcessBlocksScalar(var AState: TPoly1305State;
  const ABuf: TCryptoLibByteArray; AOff, ANumBlocks: Int32);
var
  LIdx: Int32;
begin
  for LIdx := 1 to ANumBlocks do
  begin
    Poly1305StateProcessBlock(AState, ABuf, AOff);
    AOff := AOff + 16;
  end;
end;

{ TPoly1305 }

constructor TPoly1305.Create();
begin
  inherited Create();
  FCipher := nil;
  FPowTable := nil;
  System.SetLength(FCurrentBlock, BlockSize);
end;

constructor TPoly1305.Create(const ACipher: IBlockCipher);
begin
  inherited Create();
  if ACipher.GetBlockSize() <> BlockSize then
    raise EArgumentCryptoLibException.CreateRes(@SCipherBlockSizeMismatch);
  FCipher := ACipher;
  FPowTable := nil;
  System.SetLength(FCurrentBlock, BlockSize);
end;

procedure TPoly1305.Init(const AParameters: ICipherParameters);
var
  LNonce: TCryptoLibByteArray;
  LIvParams: IParametersWithIV;
  LKeyParameter: IKeyParameter;
  LParams: ICipherParameters;
begin
  LNonce := nil;
  LParams := AParameters;

  if FCipher <> nil then
  begin
    if not Supports(LParams, IParametersWithIV, LIvParams) then
      raise EArgumentCryptoLibException.CreateRes(@SParametersWithIVRequired);
    LNonce := LIvParams.GetIV();
    LParams := LIvParams.Parameters;
  end;

  if not Supports(LParams, IKeyParameter, LKeyParameter) then
    raise EArgumentCryptoLibException.CreateRes(@SKeyParameterRequired);

  SetKey(LKeyParameter, LNonce);
  Reset();
end;

procedure TPoly1305.SetKey(const AKeyParameter: IKeyParameter;
  const ANonce: TCryptoLibByteArray);
var
  LKey, LKBytes: TCryptoLibByteArray;
begin
  LKey := AKeyParameter.GetKey();
  if System.Length(LKey) <> 32 then
    raise EArgumentCryptoLibException.CreateRes(@SInvalidKeyLength);

  if (FCipher <> nil) and
    ((ANonce = nil) or (System.Length(ANonce) <> BlockSize)) then
    raise EArgumentCryptoLibException.CreateRes(@SInvalidNonce);

  Poly1305StateAbsorbR(FState, LKey);

  if FCipher = nil then
    Poly1305StateAbsorbS(FState, LKey, BlockSize)
  else
  begin
    System.SetLength(LKBytes, BlockSize);
    FCipher.Init(True, TKeyParameter.Create(LKey, BlockSize, BlockSize)
      as IKeyParameter);
    FCipher.ProcessBlock(ANonce, 0, LKBytes, 0);
    Poly1305StateAbsorbS(FState, LKBytes, 0);
  end;

  // Pre-build any SIMD-specific lookup tables for this key, and use the
  // (non-)allocation of FPowTable as the dispatch flag for BlockUpdate.
  // Reset to nil first so the scalar path is the postcondition when no SIMD
  // backend claims the key; the facade fills FPowTable iff a SIMD tier applies.
  FPowTable := nil;
  TPoly1305Simd.TryInitPowerTable(FPowTable, FState);
end;

function TPoly1305.GetAlgorithmName: String;
begin
  if FCipher = nil then
    Result := 'Poly1305'
  else
    Result := 'Poly1305-' + FCipher.AlgorithmName;
end;

function TPoly1305.GetMacSize: Int32;
begin
  Result := BlockSize;
end;

procedure TPoly1305.Update(AInput: Byte);
begin
  FCurrentBlock[FCurrentBlockOffset] := AInput;
  System.Inc(FCurrentBlockOffset);
  if FCurrentBlockOffset = BlockSize then
  begin
    Poly1305StateProcessBlock(FState, FCurrentBlock, 0);
    FCurrentBlockOffset := 0;
  end;
end;

procedure TPoly1305.BlockUpdate(const AInput: TCryptoLibByteArray;
  AInOff, ALen: Int32);
var
  LAvailable, LPos, LRemaining, LNb, LBulkBytes, LSimdBlocks: Int32;
begin
  TCheck.DataLength(AInput, AInOff, ALen, 'input buffer too short');

  LAvailable := BlockSize - FCurrentBlockOffset;
  if ALen < LAvailable then
  begin
    System.Move(AInput[AInOff], FCurrentBlock[FCurrentBlockOffset],
      ALen * System.SizeOf(Byte));
    FCurrentBlockOffset := FCurrentBlockOffset + ALen;
    Exit;
  end;

  LPos := 0;
  if FCurrentBlockOffset > 0 then
  begin
    System.Move(AInput[AInOff], FCurrentBlock[FCurrentBlockOffset],
      LAvailable * System.SizeOf(Byte));
    LPos := LAvailable;
    Poly1305StateProcessBlock(FState, FCurrentBlock, 0);
    FCurrentBlockOffset := 0;
  end;

  LRemaining := ALen - LPos;
  LNb := LRemaining shr 4;

  if LNb > 0 then
  begin
    LBulkBytes := LNb shl 4;
    // The SIMD facade consumes a lane-multiple of the blocks (0 when no SIMD
    // path applies for this key) and the scalar reference handles the tail.
    LSimdBlocks := TPoly1305Simd.ProcessBulk(FState, PByte(FPowTable), AInput,
      AInOff + LPos, LNb);
    if LSimdBlocks < LNb then
      Poly1305StateProcessBlocksScalar(FState, AInput,
        AInOff + LPos + LSimdBlocks * 16, LNb - LSimdBlocks);
    LPos := LPos + LBulkBytes;
    LRemaining := ALen - LPos;
  end;

  System.Move(AInput[AInOff + LPos], FCurrentBlock[0],
    LRemaining * System.SizeOf(Byte));
  FCurrentBlockOffset := LRemaining;
end;

procedure TPoly1305.ProcessBlock(const ABuf: TCryptoLibByteArray; AOff: Int32);
begin
  Poly1305StateProcessBlock(FState, ABuf, AOff);
end;

function TPoly1305.DoFinal(const AOutput: TCryptoLibByteArray;
  AOutOff: Int32): Int32;
var
  LC: Int64;
begin
  TCheck.OutputLength(AOutput, AOutOff, BlockSize, 'output buffer too short');

  if FCurrentBlockOffset > 0 then
  begin
    if FCurrentBlockOffset < BlockSize then
    begin
      FCurrentBlock[FCurrentBlockOffset] := 1;
      System.Inc(FCurrentBlockOffset);
      while FCurrentBlockOffset < BlockSize do
      begin
        FCurrentBlock[FCurrentBlockOffset] := 0;
        System.Inc(FCurrentBlockOffset);
      end;
      FState.H4 := FState.H4 - (UInt32(1) shl 24);
    end;
    Poly1305StateProcessBlock(FState, FCurrentBlock, 0);
  end;

  FState.H0 := FState.H0 + 5;
  FState.H1 := FState.H1 + (FState.H0 shr 26);
  FState.H0 := FState.H0 and $3FFFFFF;
  FState.H2 := FState.H2 + (FState.H1 shr 26);
  FState.H1 := FState.H1 and $3FFFFFF;
  FState.H3 := FState.H3 + (FState.H2 shr 26);
  FState.H2 := FState.H2 and $3FFFFFF;
  FState.H4 := FState.H4 + (FState.H3 shr 26);
  FState.H3 := FState.H3 and $3FFFFFF;

  LC := (Int64(Int32(FState.H4 shr 26)) - 1) * 5;
  LC := LC + Int64(FState.K0) + Int64(FState.H0 or (FState.H1 shl 26));
  TPack.UInt32_To_LE(UInt32(LC), AOutput, AOutOff);
  LC := TBitOperations.Asr64(LC, 32);
  LC := LC + Int64(FState.K1) + Int64((FState.H1 shr 6) or (FState.H2 shl 20));
  TPack.UInt32_To_LE(UInt32(LC), AOutput, AOutOff + 4);
  LC := TBitOperations.Asr64(LC, 32);
  LC := LC + Int64(FState.K2) + Int64((FState.H2 shr 12) or (FState.H3 shl 14));
  TPack.UInt32_To_LE(UInt32(LC), AOutput, AOutOff + 8);
  LC := TBitOperations.Asr64(LC, 32);
  LC := LC + Int64(FState.K3) + Int64((FState.H3 shr 18) or (FState.H4 shl 8));
  TPack.UInt32_To_LE(UInt32(LC), AOutput, AOutOff + 12);

  Reset();
  Result := BlockSize;
end;

procedure TPoly1305.Reset();
begin
  FCurrentBlockOffset := 0;
  TArrayUtilities.Fill<Byte>(FCurrentBlock, 0, System.Length(FCurrentBlock), Byte(0));
  Poly1305StateReset(FState);
end;

end.
