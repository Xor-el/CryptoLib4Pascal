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

unit SymmetricBlockVectors;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  SysUtils,
  ClpCryptoLibTypes,
  CsvVectorLoaderBase,
  CsvVectorParser;

type

TNistAesVectorRow = record
    Mode, Key, IV, Input, Output: string;
  end;

  /// <summary>
  /// NIST SP 800-38A AES test vectors loaded from external data files.
  /// </summary>
  TNistSp80038aAesVectors = class sealed
  strict private
    class var
      FTable: TCsvVectorTable;

    class function RowFromCsv(const ARow: TCsvRow): TNistAesVectorRow; static;
    class function KeySizeBits(const AKeyHex: string): Integer; static;
    class function RowsFromCsv(const ACsvRows: TCryptoLibGenericArray<TCsvRow>)
      : TCryptoLibGenericArray<TNistAesVectorRow>; static;
  public
    class function GetRows(const AMode: string): TCryptoLibGenericArray<TNistAesVectorRow>; overload; static;
    class function GetRows(const AMode: string; AKeySizeBits: Integer)
      : TCryptoLibGenericArray<TNistAesVectorRow>; overload; static;
    class constructor Create;
  end;

TSpeckVectorRow = record
    Mode, Key, IV, Input, Output: string;
  end;

  /// <summary>
  /// Speck block cipher test vectors loaded from external data files.
  /// </summary>
  TSpeckVectors = class sealed
  strict private
    class var
      FTable: TCsvVectorTable;

    class function RowFromCsv(const ARow: TCsvRow): TSpeckVectorRow; static;
    class function RowsFromCsv(const ACsvRows: TCryptoLibGenericArray<TCsvRow>)
      : TCryptoLibGenericArray<TSpeckVectorRow>; static;
  public
    class function GetRows(const AMode: string): TCryptoLibGenericArray<TSpeckVectorRow>; static;
    class constructor Create;
  end;

TAeadGcmRow = record
    Name, Key, Plaintext, Aad, Iv, Ciphertext, Tag: string;
  end;

  TGmacVectorRow = record
    Name, Key, Iv, Aad, Tag: string;
  end;

  /// <summary>
  /// GCM / GMAC test vectors loaded from external CSV files.
  /// </summary>
  TGcmVectors = class sealed
  strict private
    class var
      FMcGrewViegaRows: TCryptoLibGenericArray<TAeadGcmRow>;
      FNistGmacRows: TCryptoLibGenericArray<TGmacVectorRow>;
      FMcGrewTable, FNistGmacTable: TCsvVectorTable;

    class function GcmRowFromCsv(const ARow: TCsvRow): TAeadGcmRow; static;
    class function GmacRowFromCsv(const ARow: TCsvRow): TGmacVectorRow; static;
    class procedure LoadMcGrewViegaRows; static;
    class procedure LoadNistGmacRows; static;
  public
    class function GetMcGrewViegaRows: TCryptoLibGenericArray<TAeadGcmRow>; static;
    class function GetNistGmacRows: TCryptoLibGenericArray<TGmacVectorRow>; static;
    class constructor Create;
  end;

TGcmSivRow = record
    SetId, Key, Nonce, Aad, Plaintext, CiphertextTag: string;
  end;

  /// <summary>
  /// AES-GCM-SIV RFC 8452 test vectors loaded from external CSV.
  /// </summary>
  TGcmSivVectors = class sealed
  strict private
    class var
      FAllRows: TCryptoLibGenericArray<TGcmSivRow>;
      FTable: TCsvVectorTable;

    class function RowFromCsv(const ARow: TCsvRow): TGcmSivRow; static;
  public
    class function GetRows(const ASetId: string): TCryptoLibGenericArray<TGcmSivRow>; static;
    class constructor Create;
  end;

implementation
{ TNistSp80038aAesVectors }

class function TNistSp80038aAesVectors.KeySizeBits(const AKeyHex: string): Integer;
begin
  Result := (Length(AKeyHex) div 2) * 8;
end;

class function TNistSp80038aAesVectors.RowFromCsv(const ARow: TCsvRow): TNistAesVectorRow;
begin
  Result.Mode := TCsvVectorParser.GetField(ARow, FTable.Header, 'Mode');
  Result.Key := TCsvVectorParser.GetFieldUpperCase(FTable, ARow, 'Key');
  Result.IV := TCsvVectorParser.GetFieldUpperCase(FTable, ARow, 'IV');
  Result.Input := TCsvVectorParser.GetFieldUpperCase(FTable, ARow, 'Input');
  Result.Output := TCsvVectorParser.GetFieldUpperCase(FTable, ARow, 'Output');
end;

class function TNistSp80038aAesVectors.RowsFromCsv(
  const ACsvRows: TCryptoLibGenericArray<TCsvRow>): TCryptoLibGenericArray<TNistAesVectorRow>;
var
  LI: Integer;
begin
  SetLength(Result, Length(ACsvRows));
  for LI := 0 to High(ACsvRows) do
    Result[LI] := RowFromCsv(ACsvRows[LI]);
end;

class function TNistSp80038aAesVectors.GetRows(const AMode: string): TCryptoLibGenericArray<TNistAesVectorRow>;
begin
  Result := RowsFromCsv(TCsvVectorParser.FilterRows(FTable, 'Mode', AMode));
end;

class function TNistSp80038aAesVectors.GetRows(const AMode: string;
  AKeySizeBits: Integer): TCryptoLibGenericArray<TNistAesVectorRow>;
var
  LModeRows: TCryptoLibGenericArray<TNistAesVectorRow>;
  LI, LCount: Integer;
begin
  LModeRows := GetRows(AMode);
  LCount := 0;
  Result := nil;
  for LI := 0 to High(LModeRows) do
  begin
    if KeySizeBits(LModeRows[LI].Key) = AKeySizeBits then
    begin
      SetLength(Result, LCount + 1);
      Result[LCount] := LModeRows[LI];
      Inc(LCount);
    end;
  end;
end;

class constructor TNistSp80038aAesVectors.Create;
begin
  FTable := TCsvVectorLoaderBase.LoadTable('Crypto/Aes/NistSp80038a.csv');
end;

{ TSpeckVectors }

class function TSpeckVectors.RowFromCsv(const ARow: TCsvRow): TSpeckVectorRow;
begin
  Result.Mode := TCsvVectorParser.GetField(ARow, FTable.Header, 'Mode');
  Result.Key := TCsvVectorParser.GetFieldUpperCase(FTable, ARow, 'Key');
  Result.IV := TCsvVectorParser.GetFieldUpperCase(FTable, ARow, 'IV');
  Result.Input := TCsvVectorParser.GetFieldUpperCase(FTable, ARow, 'Input');
  Result.Output := TCsvVectorParser.GetFieldUpperCase(FTable, ARow, 'Output');
end;

class function TSpeckVectors.RowsFromCsv(const ACsvRows: TCryptoLibGenericArray<TCsvRow>)
  : TCryptoLibGenericArray<TSpeckVectorRow>;
var
  LI: Integer;
begin
  SetLength(Result, Length(ACsvRows));
  for LI := 0 to High(ACsvRows) do
    Result[LI] := RowFromCsv(ACsvRows[LI]);
end;

class function TSpeckVectors.GetRows(const AMode: string): TCryptoLibGenericArray<TSpeckVectorRow>;
begin
  Result := RowsFromCsv(TCsvVectorParser.FilterRows(FTable, 'Mode', AMode));
end;

class constructor TSpeckVectors.Create;
begin
  FTable := TCsvVectorLoaderBase.LoadTable('Crypto/Speck/Speck.csv');
end;

{ TGcmVectors }

class function TGcmVectors.GcmRowFromCsv(const ARow: TCsvRow): TAeadGcmRow;
begin
  Result.Name := TCsvVectorParser.GetField(ARow, FMcGrewTable.Header, 'Name');
  Result.Key := TCsvVectorParser.GetFieldUpperCase(FMcGrewTable, ARow, 'Key');
  Result.Plaintext := TCsvVectorParser.GetFieldUpperCase(FMcGrewTable, ARow, 'Plaintext');
  Result.Aad := TCsvVectorParser.GetFieldUpperCase(FMcGrewTable, ARow, 'Aad');
  Result.Iv := TCsvVectorParser.GetFieldUpperCase(FMcGrewTable, ARow, 'Iv');
  Result.Ciphertext := TCsvVectorParser.GetFieldUpperCase(FMcGrewTable, ARow, 'Ciphertext');
  Result.Tag := TCsvVectorParser.GetFieldUpperCase(FMcGrewTable, ARow, 'Tag');
end;

class function TGcmVectors.GmacRowFromCsv(const ARow: TCsvRow): TGmacVectorRow;
begin
  Result.Name := TCsvVectorParser.GetField(ARow, FNistGmacTable.Header, 'Name');
  Result.Key := TCsvVectorParser.GetFieldUpperCase(FNistGmacTable, ARow, 'Key');
  Result.Iv := TCsvVectorParser.GetFieldUpperCase(FNistGmacTable, ARow, 'Iv');
  Result.Aad := TCsvVectorParser.GetFieldUpperCase(FNistGmacTable, ARow, 'Aad');
  Result.Tag := TCsvVectorParser.GetFieldUpperCase(FNistGmacTable, ARow, 'Tag');
end;

class procedure TGcmVectors.LoadMcGrewViegaRows;
var
  LI: Integer;
begin
  FMcGrewTable := TCsvVectorLoaderBase.LoadTable('Crypto/Gcm/McGrewViega.csv');
  SetLength(FMcGrewViegaRows, Length(FMcGrewTable.Rows));
  for LI := 0 to High(FMcGrewTable.Rows) do
    FMcGrewViegaRows[LI] := GcmRowFromCsv(FMcGrewTable.Rows[LI]);
end;

class procedure TGcmVectors.LoadNistGmacRows;
var
  LI: Integer;
begin
  FNistGmacTable := TCsvVectorLoaderBase.LoadTable('Crypto/Gcm/NistGmac.csv');
  SetLength(FNistGmacRows, Length(FNistGmacTable.Rows));
  for LI := 0 to High(FNistGmacTable.Rows) do
    FNistGmacRows[LI] := GmacRowFromCsv(FNistGmacTable.Rows[LI]);
end;

class function TGcmVectors.GetMcGrewViegaRows: TCryptoLibGenericArray<TAeadGcmRow>;
begin
  Result := FMcGrewViegaRows;
end;

class function TGcmVectors.GetNistGmacRows: TCryptoLibGenericArray<TGmacVectorRow>;
begin
  Result := FNistGmacRows;
end;

class constructor TGcmVectors.Create;
begin
  LoadMcGrewViegaRows;
  LoadNistGmacRows;
end;

{ TGcmSivVectors }

class function TGcmSivVectors.RowFromCsv(const ARow: TCsvRow): TGcmSivRow;
begin
  Result.SetId := TCsvVectorParser.GetField(ARow, FTable.Header, 'SetId');
  Result.Key := TCsvVectorParser.GetFieldUpperCase(FTable, ARow, 'Key');
  Result.Nonce := TCsvVectorParser.GetFieldUpperCase(FTable, ARow, 'Nonce');
  Result.Aad := TCsvVectorParser.GetFieldUpperCase(FTable, ARow, 'Aad');
  Result.Plaintext := TCsvVectorParser.GetFieldUpperCase(FTable, ARow, 'Plaintext');
  Result.CiphertextTag := TCsvVectorParser.GetFieldUpperCase(FTable, ARow, 'CiphertextTag');
end;

class function TGcmSivVectors.GetRows(const ASetId: string)
  : TCryptoLibGenericArray<TGcmSivRow>;
var
  LFiltered: TCryptoLibGenericArray<TCsvRow>;
  LI: Integer;
begin
  LFiltered := TCsvVectorParser.FilterRows(FTable, 'SetId', ASetId);
  SetLength(Result, Length(LFiltered));
  for LI := 0 to High(LFiltered) do
    Result[LI] := RowFromCsv(LFiltered[LI]);
end;

class constructor TGcmSivVectors.Create;
var
  LI: Integer;
begin
  FTable := TCsvVectorLoaderBase.LoadTable('Crypto/GcmSiv/Rfc8452.csv');
  SetLength(FAllRows, Length(FTable.Rows));
  for LI := 0 to High(FTable.Rows) do
    FAllRows[LI] := RowFromCsv(FTable.Rows[LI]);
end;

end.
