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

unit ClpHashSP800Drbg;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  Generics.Collections,
  ClpCryptoLibTypes,
  ClpIDigest,
  ClpPack,
  ClpArrayUtilities,
  ClpDrbgUtilities,
  ClpCryptoLibComparers,
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
  THashSP800Drbg = class sealed(TInterfacedObject, ISP80090Drbg)
  strict private
  const
    RESEED_MAX = Int64(1) shl 47;
    MAX_BITS_REQUEST = Int32(1) shl 18;

  class var
    FSeedLens: TDictionary<string, Int32>;
    FOne: TCryptoLibByteArray;

    class constructor Create;
    class destructor Destroy;

  var
    FDigest: IDigest;
    FEntropySource: IEntropySource;
    FSecurityStrength: Int32;
    FSeedLength: Int32;
    FV: TCryptoLibByteArray;
    FC: TCryptoLibByteArray;
    FReseedCounter: Int64;

    class function GetSeedLength(const AAlgorithmName: string): Int32; static;
    function GetEntropy: TCryptoLibByteArray; inline;
    procedure AddTo(const ALonger, AShorter: TCryptoLibByteArray); inline;
    procedure DoHash(const AInput, AOutput: TCryptoLibByteArray); inline;
    function Hash(const AInput: TCryptoLibByteArray): TCryptoLibByteArray; inline;
    function Hashgen(const AInput: TCryptoLibByteArray;
      ALength: Int32): TCryptoLibByteArray;

    function GetBlockSize: Int32; inline;

  public
    constructor Create(const ADigest: IDigest; ASecurityStrength: Int32;
      const AEntropySource: IEntropySource;
      const APersonalizationString, ANonce: TCryptoLibByteArray);

    function Generate(const AOutput: TCryptoLibByteArray; AOutputOff, AOutputLen: Int32;
      const AAdditionalInput: TCryptoLibByteArray;
      APredictionResistant: Boolean): Int32;
    procedure Reseed(const AAdditionalInput: TCryptoLibByteArray);

    property BlockSize: Int32 read GetBlockSize;
  end;

implementation

{ THashSP800Drbg }

procedure THashSP800Drbg.AddTo(const ALonger, AShorter: TCryptoLibByteArray);
var
  LOff, LI: Int32;
  LCarry: UInt32;
begin
  LOff := System.Length(ALonger) - System.Length(AShorter);
  LCarry := 0;

  LI := System.Length(AShorter);
  while LI > 0 do
  begin
    Dec(LI);
    LCarry := LCarry + UInt32(ALonger[LOff + LI]) + UInt32(AShorter[LI]);
    ALonger[LOff + LI] := Byte(LCarry);
    LCarry := LCarry shr 8;
  end;

  LI := LOff;
  while LI > 0 do
  begin
    Dec(LI);
    LCarry := LCarry + UInt32(ALonger[LI]);
    ALonger[LI] := Byte(LCarry);
    LCarry := LCarry shr 8;
  end;
end;

class constructor THashSP800Drbg.Create;
begin
  FSeedLens := TDictionary<string, Int32>.Create(
    TCryptoLibComparers.OrdinalIgnoreCaseEqualityComparer);
  FSeedLens.Add('SHA-1', 440);
  FSeedLens.Add('SHA-224', 440);
  FSeedLens.Add('SHA-256', 440);
  FSeedLens.Add('SHA-512/256', 440);
  FSeedLens.Add('SHA-512/224', 440);
  FSeedLens.Add('SHA-384', 888);
  FSeedLens.Add('SHA-512', 888);
  FOne := TCryptoLibByteArray.Create($01);
end;

constructor THashSP800Drbg.Create(const ADigest: IDigest;
  ASecurityStrength: Int32; const AEntropySource: IEntropySource;
  const APersonalizationString, ANonce: TCryptoLibByteArray);
var
  LEntropy, LSeedMaterial, LSubV: TCryptoLibByteArray;
begin
  inherited Create();

  if ASecurityStrength > TDrbgUtilities.GetMaxSecurityStrength(ADigest) then
  begin
    raise EArgumentCryptoLibException.CreateRes
      (@SRequestedSecurityStrengthNotSupportedByDerivationFunction);
  end;

  if AEntropySource.EntropySize < ASecurityStrength then
  begin
    raise EArgumentCryptoLibException.CreateRes
      (@SNotEnoughEntropyForSecurityStrengthRequired);
  end;

  FDigest := ADigest;
  FEntropySource := AEntropySource;
  FSecurityStrength := ASecurityStrength;
  FSeedLength := GetSeedLength(ADigest.AlgorithmName);

  LEntropy := GetEntropy();
  LSeedMaterial := TArrayUtilities.Concatenate<Byte>([LEntropy, ANonce,
    APersonalizationString]);

  System.SetLength(FV, (FSeedLength + 7) div 8);
  TDrbgUtilities.HashDF(FDigest, LSeedMaterial, FSeedLength, FV);

  System.SetLength(LSubV, System.Length(FV) + 1);
  if System.Length(FV) > 0 then
  begin
    System.Move(FV[0], LSubV[1], System.Length(FV) * System.SizeOf(Byte));
  end;

  System.SetLength(FC, (FSeedLength + 7) div 8);
  TDrbgUtilities.HashDF(FDigest, LSubV, FSeedLength, FC);

  FReseedCounter := 1;
end;

class destructor THashSP800Drbg.Destroy;
begin
  FSeedLens.Free;
end;

procedure THashSP800Drbg.DoHash(const AInput, AOutput: TCryptoLibByteArray);
begin
  FDigest.BlockUpdate(AInput, 0, System.Length(AInput));
  FDigest.DoFinal(AOutput, 0);
end;

function THashSP800Drbg.Generate(const AOutput: TCryptoLibByteArray; AOutputOff,
  AOutputLen: Int32; const AAdditionalInput: TCryptoLibByteArray;
  APredictionResistant: Boolean): Int32;
var
  LNumberOfBits: Int32;
  LAdditionalInput, LNewInput, LW, LRv, LSubH, LH, LC: TCryptoLibByteArray;
begin
  LNumberOfBits := AOutputLen * 8;
  if LNumberOfBits > MAX_BITS_REQUEST then
  begin
    raise EArgumentCryptoLibException.CreateResFmt
      (@SNumberOfBitsPerRequestLimitedTo, [MAX_BITS_REQUEST]);
  end;

  if FReseedCounter > RESEED_MAX then
  begin
    Result := -1;
    Exit;
  end;

  LAdditionalInput := AAdditionalInput;
  if APredictionResistant then
  begin
    Reseed(LAdditionalInput);
    LAdditionalInput := nil;
  end;

  if LAdditionalInput <> nil then
  begin
    System.SetLength(LNewInput,
      1 + System.Length(FV) + System.Length(LAdditionalInput));
    LNewInput[0] := $02;
    if System.Length(FV) > 0 then
    begin
      System.Move(FV[0], LNewInput[1], System.Length(FV) * System.SizeOf(Byte));
    end;
    if System.Length(LAdditionalInput) > 0 then
    begin
      System.Move(LAdditionalInput[0], LNewInput[1 + System.Length(FV)],
        System.Length(LAdditionalInput) * System.SizeOf(Byte));
    end;
    LW := Hash(LNewInput);
    AddTo(FV, LW);
  end;

  LRv := Hashgen(FV, AOutputLen);

  System.SetLength(LSubH, System.Length(FV) + 1);
  LSubH[0] := $03;
  if System.Length(FV) > 0 then
  begin
    System.Move(FV[0], LSubH[1], System.Length(FV) * System.SizeOf(Byte));
  end;
  LH := Hash(LSubH);

  AddTo(FV, LH);
  AddTo(FV, FC);

  System.SetLength(LC, 4);
  TPack.UInt32_To_BE(UInt32(FReseedCounter), LC);
  AddTo(FV, LC);

  Inc(FReseedCounter);

  if AOutputLen > 0 then
  begin
    System.Move(LRv[0], AOutput[AOutputOff], AOutputLen * System.SizeOf(Byte));
  end;

  Result := LNumberOfBits;
end;

function THashSP800Drbg.GetBlockSize: Int32;
begin
  Result := FDigest.GetDigestSize() * 8;
end;

function THashSP800Drbg.GetEntropy: TCryptoLibByteArray;
begin
  Result := FEntropySource.GetEntropy();
  if System.Length(Result) < ((FSecurityStrength + 7) div 8) then
  begin
    raise EInvalidOperationCryptoLibException.CreateRes
      (@SInsufficientEntropyProvidedByEntropySource);
  end;
end;

class function THashSP800Drbg.GetSeedLength(const AAlgorithmName: string): Int32;
begin
  if not FSeedLens.TryGetValue(UpperCase(AAlgorithmName), Result) then
  begin
    raise EArgumentCryptoLibException.CreateRes
      (@SRequestedSecurityStrengthNotSupportedByDerivationFunction);
  end;
end;

function THashSP800Drbg.Hash(const AInput: TCryptoLibByteArray)
  : TCryptoLibByteArray;
begin
  System.SetLength(Result, FDigest.GetDigestSize());
  DoHash(AInput, Result);
end;

function THashSP800Drbg.Hashgen(const AInput: TCryptoLibByteArray;
  ALength: Int32): TCryptoLibByteArray;
var
  LDigestSize, LM, LI, LBytesToCopy: Int32;
  LData, LDig: TCryptoLibByteArray;
begin
  LDigestSize := FDigest.GetDigestSize();
  LM := ALength div LDigestSize;
  LData := System.Copy(AInput);
  System.SetLength(Result, ALength);
  System.SetLength(LDig, LDigestSize);

  for LI := 0 to LM do
  begin
    DoHash(LData, LDig);
    LBytesToCopy := LDigestSize;
    if LBytesToCopy > (ALength - LI * LDigestSize) then
    begin
      LBytesToCopy := ALength - LI * LDigestSize;
    end;
    if LBytesToCopy > 0 then
    begin
      System.Move(LDig[0], Result[LI * LDigestSize],
        LBytesToCopy * System.SizeOf(Byte));
    end;
    AddTo(LData, FOne);
  end;
end;

procedure THashSP800Drbg.Reseed(const AAdditionalInput: TCryptoLibByteArray);
var
  LEntropy, LSeedMaterial, LSubV: TCryptoLibByteArray;
begin
  LEntropy := GetEntropy();
  LSeedMaterial := TArrayUtilities.Concatenate<Byte>([FOne, FV, LEntropy,
    AAdditionalInput]);
  TDrbgUtilities.HashDF(FDigest, LSeedMaterial, FSeedLength, FV);

  System.SetLength(LSubV, System.Length(FV) + 1);
  LSubV[0] := $00;
  if System.Length(FV) > 0 then
  begin
    System.Move(FV[0], LSubV[1], System.Length(FV) * System.SizeOf(Byte));
  end;
  TDrbgUtilities.HashDF(FDigest, LSubV, FSeedLength, FC);

  FReseedCounter := 1;
end;

end.
