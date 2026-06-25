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

unit DrbgTestVectors;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  SysUtils,
  Generics.Collections,
  ClpCryptoLibTypes,
  ClpCryptoLibComparers,
  ClpEncoders,
  JsonVectorParser;

type
  TDrbgEntropyProviderInfo = record
    PredictionResistant: Boolean;
    Data: TCryptoLibByteArray;
  end;

  TDrbgHashVectorRow = record
    Id: string;
    Digest: string;
    EntropyProvider: string;
    EntropyBits: Int32;
    PredictionResistant: Boolean;
    Nonce: TCryptoLibByteArray;
    SecurityStrength: Int32;
    Personalization: TCryptoLibByteArray;
    AdditionalInputs: TCryptoLibGenericArray<TCryptoLibByteArray>;
    Expected: TCryptoLibGenericArray<TCryptoLibByteArray>;
  end;

  TDrbgHMacVectorRow = record
    Id: string;
    Mac: string;
    EntropyProvider: string;
    EntropyBits: Int32;
    PredictionResistant: Boolean;
    Nonce: TCryptoLibByteArray;
    SecurityStrength: Int32;
    Personalization: TCryptoLibByteArray;
    AdditionalInputs: TCryptoLibGenericArray<TCryptoLibByteArray>;
    Expected: TCryptoLibGenericArray<TCryptoLibByteArray>;
  end;

  TDrbgCtrVectorRow = record
    Id: string;
    Cipher: string;
    KeySizeBits: Int32;
    EntropyProvider: string;
    EntropyBits: Int32;
    PredictionResistant: Boolean;
    Nonce: TCryptoLibByteArray;
    SecurityStrength: Int32;
    Personalization: TCryptoLibByteArray;
    AdditionalInputs: TCryptoLibGenericArray<TCryptoLibByteArray>;
    Expected: TCryptoLibGenericArray<TCryptoLibByteArray>;
  end;

  /// <summary>
  /// Lazy-loaded SP 800-90A DRBG test vectors parsed from JSON under
  /// <c>CryptoLib.Tests/Data/Crypto/Drbg/</c>.
  /// </summary>
  TDrbgTestVectors = class sealed(TObject)
  strict private
    class var
      FEntropyProviders: TDictionary<string, TDrbgEntropyProviderInfo>;
      FHashRows: TCryptoLibGenericArray<TDrbgHashVectorRow>;
      FHMacRows: TCryptoLibGenericArray<TDrbgHMacVectorRow>;
      FCtrRows: TCryptoLibGenericArray<TDrbgCtrVectorRow>;

    class function DecodeOptionalHex(const AHex: string): TCryptoLibByteArray; static;
    class function DecodeHexArray(const AStrings: TCryptoLibStringArray)
      : TCryptoLibGenericArray<TCryptoLibByteArray>; static;
    class function DecodeOptionalHexArray(const AStrings: TCryptoLibStringArray)
      : TCryptoLibGenericArray<TCryptoLibByteArray>; static;
    class procedure LoadEntropyProviders; static;
    class procedure LoadHashRows; static;
    class procedure LoadHMacRows; static;
    class procedure LoadCtrRows; static;
    class function RowFromHashObject(const AObj: TJsonVectorObject)
      : TDrbgHashVectorRow; static;
    class function RowFromHMacObject(const AObj: TJsonVectorObject)
      : TDrbgHMacVectorRow; static;
    class function RowFromCtrObject(const AObj: TJsonVectorObject)
      : TDrbgCtrVectorRow; static;
  public
    class function GetEntropyProvider(const AName: string)
      : TDrbgEntropyProviderInfo; static;
    class function GetHashRows: TCryptoLibGenericArray<TDrbgHashVectorRow>; static;
    class function GetHMacRows: TCryptoLibGenericArray<TDrbgHMacVectorRow>; static;
    class function GetCtrRows: TCryptoLibGenericArray<TDrbgCtrVectorRow>; static;
    class constructor Create;
    class destructor Destroy;
  end;

implementation

{ TDrbgTestVectors }

class constructor TDrbgTestVectors.Create;
begin
  FEntropyProviders := TDictionary<string, TDrbgEntropyProviderInfo>.Create(
    TCryptoLibComparers.OrdinalIgnoreCaseEqualityComparer);
  LoadEntropyProviders;
  LoadHashRows;
  LoadHMacRows;
  LoadCtrRows;
end;

class destructor TDrbgTestVectors.Destroy;
begin
  FEntropyProviders.Free;
end;

class function TDrbgTestVectors.DecodeOptionalHex(const AHex: string)
  : TCryptoLibByteArray;
begin
  if AHex = '' then
    Exit(nil);
  Result := THexEncoder.Decode(AHex);
end;

class function TDrbgTestVectors.DecodeHexArray(const AStrings: TCryptoLibStringArray)
  : TCryptoLibGenericArray<TCryptoLibByteArray>;
var
  LI: Int32;
begin
  System.SetLength(Result, System.Length(AStrings));
  for LI := 0 to System.Length(AStrings) - 1 do
    Result[LI] := THexEncoder.Decode(AStrings[LI]);
end;

class function TDrbgTestVectors.DecodeOptionalHexArray(
  const AStrings: TCryptoLibStringArray): TCryptoLibGenericArray<TCryptoLibByteArray>;
var
  LI: Int32;
begin
  System.SetLength(Result, System.Length(AStrings));
  for LI := 0 to System.Length(AStrings) - 1 do
  begin
    if (AStrings[LI] = '') or SameText(AStrings[LI], 'null') then
      Result[LI] := nil
    else
      Result[LI] := THexEncoder.Decode(AStrings[LI]);
  end;
end;

class procedure TDrbgTestVectors.LoadEntropyProviders;
var
  LDoc: TJsonVectorDocument;
  LObjects: TCryptoLibGenericArray<TJsonVectorObject>;
  LI: Int32;
  LObj: TJsonVectorObject;
  LInfo: TDrbgEntropyProviderInfo;
begin
  LDoc := TJsonVectorDocument.LoadFile('Crypto/Drbg/EntropyProviders.json');
  try
    LObjects := LDoc.Root.GetObjectArray('providers');
    try
      for LI := 0 to System.Length(LObjects) - 1 do
      begin
        LObj := LObjects[LI];
        LInfo.PredictionResistant := LObj.GetBool('predictionResistant');
        LInfo.Data := THexEncoder.Decode(LObj.GetString('hex'));
        FEntropyProviders.Add(LObj.GetString('id'), LInfo);
      end;
    finally
      TJsonVectorObject.FreeOwnedArray(LObjects);
    end;
  finally
    LDoc.Free;
  end;
end;

class function TDrbgTestVectors.RowFromHashObject(const AObj: TJsonVectorObject)
  : TDrbgHashVectorRow;
begin
  Result.Id := AObj.GetString('id');
  Result.Digest := AObj.GetString('digest');
  Result.EntropyProvider := AObj.GetString('entropyProvider');
  Result.EntropyBits := AObj.GetInt('entropyBits');
  Result.PredictionResistant := AObj.GetBool('predictionResistant');
  Result.Nonce := DecodeOptionalHex(AObj.GetString('nonceHex'));
  Result.SecurityStrength := AObj.GetInt('securityStrength');
  if AObj.IsNullField('personalizationHex') then
    Result.Personalization := nil
  else
    Result.Personalization := DecodeOptionalHex(AObj.GetString('personalizationHex'));
  Result.AdditionalInputs := DecodeOptionalHexArray(
    AObj.GetStringArray('additionalInputsHex'));
  Result.Expected := DecodeHexArray(AObj.GetStringArray('expectedHex'));
end;

class function TDrbgTestVectors.RowFromHMacObject(const AObj: TJsonVectorObject)
  : TDrbgHMacVectorRow;
begin
  Result.Id := AObj.GetString('id');
  Result.Mac := AObj.GetString('mac');
  Result.EntropyProvider := AObj.GetString('entropyProvider');
  Result.EntropyBits := AObj.GetInt('entropyBits');
  Result.PredictionResistant := AObj.GetBool('predictionResistant');
  Result.Nonce := DecodeOptionalHex(AObj.GetString('nonceHex'));
  Result.SecurityStrength := AObj.GetInt('securityStrength');
  if AObj.IsNullField('personalizationHex') then
    Result.Personalization := nil
  else
    Result.Personalization := DecodeOptionalHex(AObj.GetString('personalizationHex'));
  Result.AdditionalInputs := DecodeOptionalHexArray(
    AObj.GetStringArray('additionalInputsHex'));
  Result.Expected := DecodeHexArray(AObj.GetStringArray('expectedHex'));
end;

class function TDrbgTestVectors.RowFromCtrObject(const AObj: TJsonVectorObject)
  : TDrbgCtrVectorRow;
begin
  Result.Id := AObj.GetString('id');
  Result.Cipher := AObj.GetString('cipher');
  Result.KeySizeBits := AObj.GetInt('keySizeBits');
  Result.EntropyProvider := AObj.GetString('entropyProvider');
  Result.EntropyBits := AObj.GetInt('entropyBits');
  Result.PredictionResistant := AObj.GetBool('predictionResistant');
  Result.Nonce := DecodeOptionalHex(AObj.GetString('nonceHex'));
  Result.SecurityStrength := AObj.GetInt('securityStrength');
  if AObj.IsNullField('personalizationHex') then
    Result.Personalization := nil
  else
    Result.Personalization := DecodeOptionalHex(AObj.GetString('personalizationHex'));
  Result.AdditionalInputs := DecodeOptionalHexArray(
    AObj.GetStringArray('additionalInputsHex'));
  Result.Expected := DecodeHexArray(AObj.GetStringArray('expectedHex'));
end;

class procedure TDrbgTestVectors.LoadHashRows;
var
  LDoc: TJsonVectorDocument;
  LObjects: TCryptoLibGenericArray<TJsonVectorObject>;
  LI: Int32;
begin
  LDoc := TJsonVectorDocument.LoadFile('Crypto/Drbg/HashDrbgVectors.json');
  try
    LObjects := LDoc.Root.GetObjectArray('vectors');
    try
      System.SetLength(FHashRows, System.Length(LObjects));
      for LI := 0 to System.Length(LObjects) - 1 do
        FHashRows[LI] := RowFromHashObject(LObjects[LI]);
    finally
      TJsonVectorObject.FreeOwnedArray(LObjects);
    end;
  finally
    LDoc.Free;
  end;
end;

class procedure TDrbgTestVectors.LoadHMacRows;
var
  LDoc: TJsonVectorDocument;
  LObjects: TCryptoLibGenericArray<TJsonVectorObject>;
  LI: Int32;
begin
  LDoc := TJsonVectorDocument.LoadFile('Crypto/Drbg/HMacDrbgVectors.json');
  try
    LObjects := LDoc.Root.GetObjectArray('vectors');
    try
      System.SetLength(FHMacRows, System.Length(LObjects));
      for LI := 0 to System.Length(LObjects) - 1 do
        FHMacRows[LI] := RowFromHMacObject(LObjects[LI]);
    finally
      TJsonVectorObject.FreeOwnedArray(LObjects);
    end;
  finally
    LDoc.Free;
  end;
end;

class procedure TDrbgTestVectors.LoadCtrRows;
var
  LDoc: TJsonVectorDocument;
  LObjects: TCryptoLibGenericArray<TJsonVectorObject>;
  LI: Int32;
begin
  LDoc := TJsonVectorDocument.LoadFile('Crypto/Drbg/CtrDrbgAesVectors.json');
  try
    LObjects := LDoc.Root.GetObjectArray('vectors');
    try
      System.SetLength(FCtrRows, System.Length(LObjects));
      for LI := 0 to System.Length(LObjects) - 1 do
        FCtrRows[LI] := RowFromCtrObject(LObjects[LI]);
    finally
      TJsonVectorObject.FreeOwnedArray(LObjects);
    end;
  finally
    LDoc.Free;
  end;
end;

class function TDrbgTestVectors.GetEntropyProvider(const AName: string)
  : TDrbgEntropyProviderInfo;
begin
  Result := FEntropyProviders[AName];
end;

class function TDrbgTestVectors.GetHashRows
  : TCryptoLibGenericArray<TDrbgHashVectorRow>;
begin
  Result := FHashRows;
end;

class function TDrbgTestVectors.GetHMacRows
  : TCryptoLibGenericArray<TDrbgHMacVectorRow>;
begin
  Result := FHMacRows;
end;

class function TDrbgTestVectors.GetCtrRows: TCryptoLibGenericArray<TDrbgCtrVectorRow>;
begin
  Result := FCtrRows;
end;

end.
