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

unit ClpCtrSP800Drbg;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpCryptoLibTypes,
  ClpCryptoLibExceptions,
  ClpIBlockCipher,
  ClpIKeyParameter,
  ClpKeyParameter,
  ClpPack,
  ClpByteUtilities,
  ClpEncoders,
  ClpArrayUtilities,
  ClpDrbgUtilities,
  ClpIEntropySource,
  ClpISP80090Drbg;

resourcestring
  SRequestedSecurityStrengthNotSupportedByDerivationFunction =
    'Requested security strength is not supported by the derivation function';
  SRequestedSecurityStrengthNotSupportedByBlockCipherAndKeySize =
    'Requested security strength is not supported by block cipher and key size';
  SNotEnoughEntropyForSecurityStrengthRequired =
    'Not enough entropy for security strength required';
  SNumberOfBitsPerRequestLimitedTo = 'Number of bits per request limited to %d';
  SInsufficientEntropyProvidedByEntropySource =
    'Insufficient entropy provided by entropy source';

type
  /// <summary>
  /// SP 800-90A CTR_DRBG implementation. Only AES block ciphers are supported
  /// (TDEA/3DES is not implemented).
  /// </summary>
  TCtrSP800Drbg = class sealed(TInterfacedObject, ISP80090Drbg)
  strict private
  const
    AES_RESEED_MAX = Int64(1) shl 47;
    AES_MAX_BITS_REQUEST = Int32(1) shl 18;
    K_BITS_HEX =
      '000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F';

  class var
    FKBits: TCryptoLibByteArray;

    class constructor Create;
    class destructor Destroy;

  var
    FEntropySource: IEntropySource;
    FEngine: IBlockCipher;
    FKeySizeInBits: Int32;
    FSeedLength: Int32;
    FSecurityStrength: Int32;
    FKey: TCryptoLibByteArray;
    FV: TCryptoLibByteArray;
    FReseedCounter: Int64;

    procedure CtrDrbgInstantiateAlgorithm(const APersonalizationString,
      ANonce: TCryptoLibByteArray);
    procedure CtrDrbgUpdate(const ASeed: TCryptoLibByteArray;
      var AKey, AV: TCryptoLibByteArray);
    procedure CtrDrbgReseedAlgorithm(const AAdditionalInput
      : TCryptoLibByteArray);

    procedure AddOneTo(var ALonger: TCryptoLibByteArray);
    function GetEntropy: TCryptoLibByteArray;
    function BlockCipherDF(const AInput: TCryptoLibByteArray; AN: Int32)
      : TCryptoLibByteArray;
    procedure BCC(const ABccOut: TCryptoLibByteArray; const AIV,
      AData: TCryptoLibByteArray);
    function GetMaxSecurityStrength(const ACipher: IBlockCipher;
      AKeySizeInBits: Int32): Int32;
    function ExpandToKeyParameter(const AKey: TCryptoLibByteArray): IKeyParameter;

    function GetBlockSize: Int32; inline;

  public
    /// <summary>
    /// Instantiate CTR_DRBG (CTR_DRBG_Instantiate_algorithm).
    /// </summary>
    /// <param name="AEngine">AES block cipher engine.</param>
    /// <param name="AKeySizeInBits">Key length in bits (128, 192, or 256 for AES).</param>
    /// <param name="ASecurityStrength">Requested security strength in bits.</param>
    /// <param name="AEntropySource">Entropy source for instantiate and reseed.</param>
    /// <param name="APersonalizationString">Optional personalization string; may be nil.</param>
    /// <param name="ANonce">Nonce from the consuming application; may be nil.</param>
    constructor Create(const AEngine: IBlockCipher; AKeySizeInBits,
      ASecurityStrength: Int32; const AEntropySource: IEntropySource;
      const APersonalizationString, ANonce: TCryptoLibByteArray);

    /// <summary>
    /// Generate pseudorandom bytes (CTR_DRBG_Generate_algorithm).
    /// </summary>
    /// <returns>
    /// Number of bits generated, or <c>-1</c> when reseed is required before further output.
    /// </returns>
    function Generate(const AOutput: TCryptoLibByteArray; AOutputOff, AOutputLen: Int32;
      const AAdditionalInput: TCryptoLibByteArray;
      APredictionResistant: Boolean): Int32;
    /// <summary>
    /// Reseed the internal state (CTR_DRBG_Reseed_algorithm).
    /// </summary>
    procedure Reseed(const AAdditionalInput: TCryptoLibByteArray);

    /// <summary>Block size of the underlying cipher in bits.</summary>
    property BlockSize: Int32 read GetBlockSize;
  end;

implementation

{ TCtrSP800Drbg }

procedure TCtrSP800Drbg.AddOneTo(var ALonger: TCryptoLibByteArray);
var
  LCarry: UInt32;
  LI: Int32;
begin
  LCarry := 1;
  LI := System.Length(ALonger);
  while LI > 0 do
  begin
    Dec(LI);
    LCarry := LCarry + ALonger[LI];
    ALonger[LI] := Byte(LCarry);
    LCarry := LCarry shr 8;
  end;
end;

procedure TCtrSP800Drbg.BCC(const ABccOut: TCryptoLibByteArray;
  const AIV, AData: TCryptoLibByteArray);
var
  LBlockSize, LN, LI: Int32;
  LChainingValue, LInputBlock: TCryptoLibByteArray;
begin
  // BCC: chaining value = E(Key, IV); for each block of data, chaining value = E(Key, chaining_value XOR block)
  LBlockSize := FEngine.GetBlockSize();
  System.SetLength(LChainingValue, LBlockSize);
  System.SetLength(LInputBlock, LBlockSize);

  FEngine.ProcessBlock(AIV, 0, LChainingValue, 0);

  LN := System.Length(AData) div LBlockSize;
  for LI := 0 to System.Pred(LN) do
  begin
    TByteUtilities.&Xor(LBlockSize, LChainingValue, 0, AData,
      LI * LBlockSize, LInputBlock, 0);
    FEngine.ProcessBlock(LInputBlock, 0, LChainingValue, 0);
  end;

  if System.Length(ABccOut) > 0 then
  begin
    System.Move(LChainingValue[0], ABccOut[0],
      System.Length(ABccOut) * System.SizeOf(Byte));
  end;
end;

function TCtrSP800Drbg.BlockCipherDF(const AInput: TCryptoLibByteArray;
  AN: Int32): TCryptoLibByteArray;
var
  LOutLen, LL, LSLen, LBlockLen, LI, LBytesToCopy: Int32;
  LS, LTemp, LBccOut, LIV, LK, LX: TCryptoLibByteArray;
begin
  // Block_Cipher_df: derive N bytes from input_string using BCC and counter-mode expansion
  LOutLen := FEngine.GetBlockSize();
  LL := System.Length(AInput);

  // S = L || N || input_string || 0x80, padded to a multiple of outlen
  LSlen := 4 + 4 + LL + 1;
  LBlockLen := ((LSLen + LOutLen - 1) div LOutLen) * LOutLen;
  System.SetLength(LS, LBlockLen);
  TPack.UInt32_To_BE(UInt32(LL), LS, 0);
  TPack.UInt32_To_BE(UInt32(AN), LS, 4);
  if LL > 0 then
  begin
    System.Move(AInput[0], LS[8], LL * System.SizeOf(Byte));
  end;
  LS[8 + LL] := $80;

  // temp = BCC(K, 0, S) || BCC(K, 1, S) || ... until temp holds key || X
  System.SetLength(LTemp, (FKeySizeInBits div 8) + LOutLen);
  System.SetLength(LBccOut, LOutLen);
  System.SetLength(LIV, LOutLen);
  System.SetLength(LK, FKeySizeInBits div 8);
  if System.Length(LK) > 0 then
  begin
    System.Move(FKBits[0], LK[0], System.Length(LK) * System.SizeOf(Byte));
  end;

  FEngine.Init(True, ExpandToKeyParameter(LK) as IKeyParameter);

  LI := 0;
  while (LI * LOutLen * 8) < (FKeySizeInBits + LOutLen * 8) do
  begin
    TPack.UInt32_To_BE(UInt32(LI), LIV, 0);
    BCC(LBccOut, LIV, LS);

    LBytesToCopy := LOutLen;
    if LBytesToCopy > (System.Length(LTemp) - LI * LOutLen) then
    begin
      LBytesToCopy := System.Length(LTemp) - LI * LOutLen;
    end;

    if LBytesToCopy > 0 then
    begin
      System.Move(LBccOut[0], LTemp[LI * LOutLen],
        LBytesToCopy * System.SizeOf(Byte));
    end;
    Inc(LI);
  end;

  // Split temp into K and X; expand in counter mode to produce requested output
  System.SetLength(LX, LOutLen);
  if System.Length(LK) > 0 then
  begin
    System.Move(LTemp[0], LK[0], System.Length(LK) * System.SizeOf(Byte));
  end;
  if System.Length(LX) > 0 then
  begin
    System.Move(LTemp[System.Length(LK)], LX[0],
      System.Length(LX) * System.SizeOf(Byte));
  end;

  System.SetLength(Result, AN);
  LI := 0;
  FEngine.Init(True, ExpandToKeyParameter(LK) as IKeyParameter);
  while (LI * LOutLen) < System.Length(Result) do
  begin
    FEngine.ProcessBlock(LX, 0, LX, 0);

    LBytesToCopy := LOutLen;
    if LBytesToCopy > (System.Length(Result) - LI * LOutLen) then
    begin
      LBytesToCopy := System.Length(Result) - LI * LOutLen;
    end;

    if LBytesToCopy > 0 then
    begin
      System.Move(LX[0], Result[LI * LOutLen], LBytesToCopy * System.SizeOf(Byte));
    end;
    Inc(LI);
  end;
end;

constructor TCtrSP800Drbg.Create(const AEngine: IBlockCipher; AKeySizeInBits,
  ASecurityStrength: Int32; const AEntropySource: IEntropySource;
  const APersonalizationString, ANonce: TCryptoLibByteArray);
begin
  inherited Create();

  if ASecurityStrength > 256 then
  begin
    raise EArgumentCryptoLibException.CreateRes
      (@SRequestedSecurityStrengthNotSupportedByDerivationFunction);
  end;

  if GetMaxSecurityStrength(AEngine, AKeySizeInBits) < ASecurityStrength then
  begin
    raise EArgumentCryptoLibException.CreateRes
      (@SRequestedSecurityStrengthNotSupportedByBlockCipherAndKeySize);
  end;

  if AEntropySource.EntropySize < ASecurityStrength then
  begin
    raise EArgumentCryptoLibException.CreateRes
      (@SNotEnoughEntropyForSecurityStrengthRequired);
  end;

  FEntropySource := AEntropySource;
  FEngine := AEngine;
  FKeySizeInBits := AKeySizeInBits;
  FSecurityStrength := ASecurityStrength;
  FSeedLength := AKeySizeInBits + AEngine.GetBlockSize() * 8;

  CtrDrbgInstantiateAlgorithm(APersonalizationString, ANonce);
end;

class constructor TCtrSP800Drbg.Create;
begin
  FKBits := THexEncoder.Decode(K_BITS_HEX);
end;

class destructor TCtrSP800Drbg.Destroy;
begin
  FKBits := nil;
end;

procedure TCtrSP800Drbg.CtrDrbgInstantiateAlgorithm(
  const APersonalizationString, ANonce: TCryptoLibByteArray);
var
  LEntropy, LSeedMaterial, LSeed: TCryptoLibByteArray;
  LBlockSize: Int32;
begin
  // 1. seed_material = entropy_input || nonce || personalization_string
  LEntropy := GetEntropy();
  LSeedMaterial := TArrayUtilities.Concatenate<Byte>([LEntropy, ANonce,
    APersonalizationString]);
  // 2. seed = Block_Cipher_df(seed_material, seedlen)
  LSeed := BlockCipherDF(LSeedMaterial, FSeedLength div 8);

  LBlockSize := FEngine.GetBlockSize();
  System.SetLength(FKey, (FKeySizeInBits + 7) div 8);
  System.SetLength(FV, LBlockSize);

  // 3. CTR_DRBG_Update(seed); 4. reseed_counter = 1
  CtrDrbgUpdate(LSeed, FKey, FV);
  FReseedCounter := 1;
end;

procedure TCtrSP800Drbg.CtrDrbgReseedAlgorithm(
  const AAdditionalInput: TCryptoLibByteArray);
var
  LEntropy, LInput, LSeedMaterial: TCryptoLibByteArray;
begin
  // 1. seed_material = entropy_input || additional_input
  LEntropy := GetEntropy();
  LInput := TArrayUtilities.Concatenate<Byte>([LEntropy, AAdditionalInput]);
  // 2. seed = Block_Cipher_df(seed_material, seedlen)
  LSeedMaterial := BlockCipherDF(LInput, FSeedLength div 8);

  // 3. CTR_DRBG_Update(seed); 4. reseed_counter = 1
  CtrDrbgUpdate(LSeedMaterial, FKey, FV);
  FReseedCounter := 1;
end;

procedure TCtrSP800Drbg.CtrDrbgUpdate(const ASeed: TCryptoLibByteArray;
  var AKey, AV: TCryptoLibByteArray);
var
  LSeedLength, LI, LOutLen, LBytesToCopy: Int32;
  LTemp, LOutputBlock: TCryptoLibByteArray;
begin
  // CTR_DRBG_Update: temp = E(Key, V+1) || E(Key, V+2) || ...; (Key, V) = temp XOR provided_data
  LSeedLength := System.Length(ASeed);
  System.SetLength(LTemp, LSeedLength);
  System.SetLength(LOutputBlock, FEngine.GetBlockSize());

  LI := 0;
  LOutLen := FEngine.GetBlockSize();

  FEngine.Init(True, ExpandToKeyParameter(AKey) as IKeyParameter);
  while (LI * LOutLen) < LSeedLength do
  begin
    AddOneTo(AV);
    FEngine.ProcessBlock(AV, 0, LOutputBlock, 0);

    LBytesToCopy := LOutLen;
    if LBytesToCopy > (System.Length(LTemp) - LI * LOutLen) then
    begin
      LBytesToCopy := System.Length(LTemp) - LI * LOutLen;
    end;
    if LBytesToCopy > 0 then
    begin
      System.Move(LOutputBlock[0], LTemp[LI * LOutLen],
        LBytesToCopy * System.SizeOf(Byte));
    end;
    Inc(LI);
  end;

  TByteUtilities.XorTo(LSeedLength, ASeed, LTemp);

  if System.Length(AKey) > 0 then
  begin
    System.Move(LTemp[0], AKey[0], System.Length(AKey) * System.SizeOf(Byte));
  end;
  if System.Length(AV) > 0 then
  begin
    System.Move(LTemp[System.Length(AKey)], AV[0],
      System.Length(AV) * System.SizeOf(Byte));
  end;
end;

function TCtrSP800Drbg.ExpandToKeyParameter(
  const AKey: TCryptoLibByteArray): IKeyParameter;
begin
  Result := TKeyParameter.Create(AKey);
end;

function TCtrSP800Drbg.Generate(const AOutput: TCryptoLibByteArray; AOutputOff,
  AOutputLen: Int32; const AAdditionalInput: TCryptoLibByteArray;
  APredictionResistant: Boolean): Int32;
var
  LAdditionalInput, LTmp: TCryptoLibByteArray;
  LI, LLimit, LBytesToCopy: Int32;
begin
  // 1. If reseed_counter > reseed_interval, return indication that a reseed is required
  if FReseedCounter > AES_RESEED_MAX then
  begin
    Result := -1;
    Exit;
  end;

  if AOutputLen > (AES_MAX_BITS_REQUEST div 8) then
  begin
    raise EArgumentCryptoLibException.CreateResFmt
      (@SNumberOfBitsPerRequestLimitedTo, [AES_MAX_BITS_REQUEST]);
  end;

  LAdditionalInput := AAdditionalInput;
  // 2. If prediction_resistance_request, CTR_DRBG_Reseed with additional_input
  if APredictionResistant then
  begin
    CtrDrbgReseedAlgorithm(LAdditionalInput);
    LAdditionalInput := nil;
  end;

  // 3. If additional_input != Null: additional_input = Block_Cipher_df(...); CTR_DRBG_Update
  if LAdditionalInput <> nil then
  begin
    LAdditionalInput := BlockCipherDF(LAdditionalInput, FSeedLength div 8);
    CtrDrbgUpdate(LAdditionalInput, FKey, FV);
  end
  else
  begin
    System.SetLength(LAdditionalInput, FSeedLength div 8);
  end;

  // 4. returned_bits = empty; while len(returned_bits) < requested_number_of_bits: V = V+1; output block = E(Key, V)
  System.SetLength(LTmp, System.Length(FV));
  FEngine.Init(True, ExpandToKeyParameter(FKey));

  LLimit := AOutputLen div System.Length(LTmp);
  for LI := 0 to LLimit do
  begin
    LBytesToCopy := System.Length(LTmp);
    if LBytesToCopy > (AOutputLen - LI * System.Length(LTmp)) then
    begin
      LBytesToCopy := AOutputLen - LI * System.Length(LTmp);
    end;
    if LBytesToCopy <> 0 then
    begin
      AddOneTo(FV);
      FEngine.ProcessBlock(FV, 0, LTmp, 0);
      System.Move(LTmp[0], AOutput[AOutputOff + LI * System.Length(LTmp)],
        LBytesToCopy * System.SizeOf(Byte));
    end;
  end;

  // 5. CTR_DRBG_Update(additional_input); 6. reseed_counter = reseed_counter + 1
  CtrDrbgUpdate(LAdditionalInput, FKey, FV);
  Inc(FReseedCounter);

  // 7. Return SUCCESS and returned_bits
  Result := AOutputLen * 8;
end;

function TCtrSP800Drbg.GetBlockSize: Int32;
begin
  Result := System.Length(FV) * 8;
end;

function TCtrSP800Drbg.GetEntropy: TCryptoLibByteArray;
begin
  Result := FEntropySource.GetEntropy();
  if (Result = nil) or (System.Length(Result) < ((FSecurityStrength + 7) div 8))
  then
  begin
    raise EInvalidOperationCryptoLibException.CreateRes
      (@SInsufficientEntropyProvidedByEntropySource);
  end;
end;

function TCtrSP800Drbg.GetMaxSecurityStrength(const ACipher: IBlockCipher;
  AKeySizeInBits: Int32): Int32;
begin
  if ACipher.AlgorithmName = 'AES' then
  begin
    Result := AKeySizeInBits;
  end
  else
  begin
    Result := -1;
  end;
end;

procedure TCtrSP800Drbg.Reseed(const AAdditionalInput: TCryptoLibByteArray);
begin
  CtrDrbgReseedAlgorithm(AAdditionalInput);
end;

end.
