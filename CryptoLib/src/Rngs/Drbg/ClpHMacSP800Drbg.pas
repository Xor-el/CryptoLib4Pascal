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

unit ClpHMacSP800Drbg;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpCryptoLibTypes,
  ClpIMac,
  ClpIKeyParameter,
  ClpKeyParameter,
  ClpArrayUtilities,
  ClpDrbgUtilities,
  ClpIEntropySource,
  ClpISP80090Drbg;

resourcestring
  SRequestedSecurityStrengthNotSupportedByDerivationFunction =
    'Requested security strength is not supported by the derivation function';
  SNotEnoughEntropyForSecurityStrengthRequired =
    'Not enough entropy for security strength required';
  SNumberOfBitsPerRequestLimitedTo = 'Number of bits per request limited to %d';
  SInsufficientEntropyProvidedByEntropySource =
    'Insufficient entropy provided by entropy source';

type
  /// <summary>
  /// SP 800-90A HMAC_DRBG implementation using a configurable HMAC function.
  /// </summary>
  THMacSP800Drbg = class sealed(TInterfacedObject, ISP80090Drbg)
  strict private
  const
    RESEED_MAX = Int64(1) shl 47;
    MAX_BITS_REQUEST = Int32(1) shl 18;

  var
    FK: TCryptoLibByteArray;
    FV: TCryptoLibByteArray;
    FEntropySource: IEntropySource;
    FHMac: IMac;
    FSecurityStrength: Int32;
    FReseedCounter: Int64;

    function GetBlockSize: Int32; inline;
    function GetEntropy: TCryptoLibByteArray; inline;
    procedure HmacDrbgUpdate(const ASeedMaterial: TCryptoLibByteArray); inline;
    procedure HmacDrbgUpdateFunc(const ASeedMaterial: TCryptoLibByteArray;
      AVValue: Byte); inline;

  public
    /// <summary>
    /// Instantiate HMAC_DRBG (HMAC_DRBG_Instantiate_algorithm).
    /// </summary>
    /// <param name="AHMac">Approved HMAC instance (underlying digest determines strength).</param>
    /// <param name="ASecurityStrength">Requested security strength in bits.</param>
    /// <param name="AEntropySource">Entropy source for instantiate and reseed.</param>
    /// <param name="APersonalizationString">Optional personalization string; may be nil.</param>
    /// <param name="ANonce">Nonce from the consuming application; may be nil.</param>
    constructor Create(const AHMac: IMac; ASecurityStrength: Int32;
      const AEntropySource: IEntropySource;
      const APersonalizationString, ANonce: TCryptoLibByteArray);

    /// <summary>
    /// Generate pseudorandom bytes (HMAC_DRBG_Generate_algorithm).
    /// </summary>
    /// <returns>
    /// Number of bits generated, or <c>-1</c> when reseed is required before further output.
    /// </returns>
    function Generate(const AOutput: TCryptoLibByteArray; AOutputOff, AOutputLen: Int32;
      const AAdditionalInput: TCryptoLibByteArray;
      APredictionResistant: Boolean): Int32;
    /// <summary>
    /// Reseed the internal state (HMAC_DRBG_Reseed_algorithm).
    /// </summary>
    procedure Reseed(const AAdditionalInput: TCryptoLibByteArray);

    /// <summary>Internal value size in bits (HMAC output length).</summary>
    property BlockSize: Int32 read GetBlockSize;
  end;

implementation

{ THMacSP800Drbg }

constructor THMacSP800Drbg.Create(const AHMac: IMac; ASecurityStrength: Int32;
  const AEntropySource: IEntropySource;
  const APersonalizationString, ANonce: TCryptoLibByteArray);
var
  LEntropy, LSeedMaterial: TCryptoLibByteArray;
  LI: Int32;
begin
  inherited Create();

  if ASecurityStrength > TDrbgUtilities.GetMaxSecurityStrength(AHMac) then
  begin
    raise EArgumentCryptoLibException.CreateRes
      (@SRequestedSecurityStrengthNotSupportedByDerivationFunction);
  end;

  if AEntropySource.EntropySize < ASecurityStrength then
  begin
    raise EArgumentCryptoLibException.CreateRes
      (@SNotEnoughEntropyForSecurityStrengthRequired);
  end;

  FHMac := AHMac;
  FSecurityStrength := ASecurityStrength;
  FEntropySource := AEntropySource;

  // 1. seed_material = entropy_input || nonce || personalization_string
  LEntropy := GetEntropy();
  LSeedMaterial := TArrayUtilities.Concatenate<Byte>([LEntropy, ANonce,
    APersonalizationString]);

  // 2. Key = 0x00...00; V = 0x01...01 (outlen bytes each)
  System.SetLength(FK, AHMac.GetMacSize());
  System.SetLength(FV, System.Length(FK));
  for LI := 0 to System.Pred(System.Length(FV)) do
  begin
    FV[LI] := Byte(1);
  end;

  // 3. HMAC_DRBG_Update(seed_material); 4. reseed_counter = 1
  HmacDrbgUpdate(LSeedMaterial);
  FReseedCounter := 1;
end;

function THMacSP800Drbg.Generate(const AOutput: TCryptoLibByteArray; AOutputOff,
  AOutputLen: Int32; const AAdditionalInput: TCryptoLibByteArray;
  APredictionResistant: Boolean): Int32;
var
  LNumberOfBits, LM, LI, LRemaining, LCopyLen: Int32;
  LAdditionalInput, LRv: TCryptoLibByteArray;
begin
  LNumberOfBits := AOutputLen * 8;
  if LNumberOfBits > MAX_BITS_REQUEST then
  begin
    raise EArgumentCryptoLibException.CreateResFmt
      (@SNumberOfBitsPerRequestLimitedTo, [MAX_BITS_REQUEST]);
  end;

  // 1. If reseed_counter > reseed_interval, return indication that a reseed is required
  if FReseedCounter > RESEED_MAX then
  begin
    Result := -1;
    Exit;
  end;

  LAdditionalInput := AAdditionalInput;
  // 2. If prediction_resistance_request, HMAC_DRBG_Reseed with additional_input
  if APredictionResistant then
  begin
    Reseed(LAdditionalInput);
    LAdditionalInput := nil;
  end;

  // 3. If additional_input != Null: HMAC_DRBG_Update(additional_input)
  if LAdditionalInput <> nil then
  begin
    HmacDrbgUpdate(LAdditionalInput);
  end;

  // 4. returned_bits = empty; while len(returned_bits) < requested_number_of_bits: V = HMAC(Key, V); returned_bits = returned_bits || V
  System.SetLength(LRv, AOutputLen);
  LM := AOutputLen div System.Length(FV);

  FHMac.Init(TKeyParameter.Create(FK) as IKeyParameter);
  for LI := 0 to System.Pred(LM) do
  begin
    FHMac.BlockUpdate(FV, 0, System.Length(FV));
    FHMac.DoFinal(FV, 0);
    System.Move(FV[0], LRv[LI * System.Length(FV)],
      System.Length(FV) * System.SizeOf(Byte));
  end;

  if (LM * System.Length(FV)) < System.Length(LRv) then
  begin
    FHMac.BlockUpdate(FV, 0, System.Length(FV));
    FHMac.DoFinal(FV, 0);
    LRemaining := System.Length(LRv) - (LM * System.Length(FV));
    System.Move(FV[0], LRv[LM * System.Length(FV)],
      LRemaining * System.SizeOf(Byte));
  end;

  // 5. HMAC_DRBG_Update(additional_input); 6. reseed_counter = reseed_counter + 1
  HmacDrbgUpdate(LAdditionalInput);
  Inc(FReseedCounter);

  if AOutputLen > 0 then
  begin
    LCopyLen := AOutputLen * System.SizeOf(Byte);
    System.Move(LRv[0], AOutput[AOutputOff], LCopyLen);
  end;

  // 7. Return SUCCESS and returned_bits
  Result := LNumberOfBits;
end;

function THMacSP800Drbg.GetBlockSize: Int32;
begin
  Result := System.Length(FV) * 8;
end;

function THMacSP800Drbg.GetEntropy: TCryptoLibByteArray;
begin
  Result := FEntropySource.GetEntropy();
  if System.Length(Result) < ((FSecurityStrength + 7) div 8) then
  begin
    raise EInvalidOperationCryptoLibException.CreateRes
      (@SInsufficientEntropyProvidedByEntropySource);
  end;
end;

procedure THMacSP800Drbg.HmacDrbgUpdate(const ASeedMaterial: TCryptoLibByteArray);
begin
  // HMAC_DRBG_Update: Update with 0x00, then with 0x01 when seed material is present
  HmacDrbgUpdateFunc(ASeedMaterial, $00);
  if ASeedMaterial <> nil then
  begin
    HmacDrbgUpdateFunc(ASeedMaterial, $01);
  end;
end;

procedure THMacSP800Drbg.HmacDrbgUpdateFunc(const ASeedMaterial: TCryptoLibByteArray; AVValue: Byte);
begin
  // K = HMAC(K, V || 0x00 [|| provided_data]); V = HMAC(K, V)
  FHMac.Init(TKeyParameter.Create(FK) as IKeyParameter);
  FHMac.BlockUpdate(FV, 0, System.Length(FV));
  FHMac.Update(AVValue);

  if ASeedMaterial <> nil then
  begin
    FHMac.BlockUpdate(ASeedMaterial, 0, System.Length(ASeedMaterial));
  end;

  FHMac.DoFinal(FK, 0);

  FHMac.Init(TKeyParameter.Create(FK) as IKeyParameter);
  FHMac.BlockUpdate(FV, 0, System.Length(FV));
  FHMac.DoFinal(FV, 0);
end;

procedure THMacSP800Drbg.Reseed(const AAdditionalInput: TCryptoLibByteArray);
var
  LEntropy, LSeedMaterial: TCryptoLibByteArray;
begin
  // 1. seed_material = entropy_input || additional_input
  LEntropy := GetEntropy();
  LSeedMaterial := TArrayUtilities.Concatenate<Byte>([LEntropy, AAdditionalInput]);
  // 2. HMAC_DRBG_Update(seed_material); 3. reseed_counter = 1
  HmacDrbgUpdate(LSeedMaterial);
  FReseedCounter := 1;
end;

end.
