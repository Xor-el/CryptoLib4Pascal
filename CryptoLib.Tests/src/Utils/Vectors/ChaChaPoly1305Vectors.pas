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

unit ChaChaPoly1305Vectors;

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
  TChaChaKeystreamRow = record
      Rounds: Integer;
      SetId, Key, Nonce, ExpectedKeystream: string;
      ByteOffset: Integer;
    end;

  TChaChaKeystreamSet = record
    Rounds: Integer;
    SetId, Key, Nonce: string;
    Checkpoints: TCryptoLibGenericArray<TChaChaKeystreamRow>;
  end;

  TChaChaAeadRow = record
    TestId, Key, Nonce, Aad, Plaintext, Ciphertext, Tag: string;
  end;

  TXChaChaStreamRow = record
    TestId, VectorType, Key, Nonce, Plaintext, ExpectedHex: string;
    SkipBytes: Integer;
  end;

  /// <summary>
  /// ChaCha family test vectors: eSTREAM keystream, RFC 7539 AEAD, XChaCha20-Poly1305, XChaCha20 stream.
  /// </summary>
  TChaChaVectors = class sealed
  strict private
    class var
      FKeystreamRows: TCryptoLibGenericArray<TChaChaKeystreamRow>;
      FKeystreamTable: TCsvVectorTable;
      FRfc7539Rows: TCryptoLibGenericArray<TChaChaAeadRow>;
      FRfc7539Table: TCsvVectorTable;
      FXChaChaPoly1305Rows: TCryptoLibGenericArray<TChaChaAeadRow>;
      FXChaChaPoly1305Table: TCsvVectorTable;
      FXChaChaStreamRows: TCryptoLibGenericArray<TXChaChaStreamRow>;
      FXChaChaStreamTable: TCsvVectorTable;

    class function KeystreamRowFromCsv(const ARow: TCsvRow): TChaChaKeystreamRow; static;
    class function AeadRowFromCsv(const ATable: TCsvVectorTable;
      const ARow: TCsvRow): TChaChaAeadRow; static;
    class function XChaChaStreamRowFromCsv(const ARow: TCsvRow): TXChaChaStreamRow; static;
    class procedure LoadKeystreamRows; static;
    class procedure LoadRfc7539Rows; static;
    class procedure LoadXChaChaPoly1305Rows; static;
    class procedure LoadXChaChaStreamRows; static;
  public
    class function GetKeystreamSet(const ASetId: string): TChaChaKeystreamSet; static;
    class function GetKeystreamSets: TCryptoLibGenericArray<TChaChaKeystreamSet>; static;
    class function GetRfc7539Poly1305Rows: TCryptoLibGenericArray<TChaChaAeadRow>; static;
    class function GetXChaCha20Poly1305Row(const ATestId: string): TChaChaAeadRow; static;
    class function GetXChaChaStreamRow(const ATestId: string): TXChaChaStreamRow; static;
    class constructor Create;
  end;

  TPoly1305NaClRow = record
      CaseIndex: Integer;
      ClampKey, UseAesNonce: Boolean;
      Key, Nonce, Message, ExpectedMac: string;
    end;

  TPoly1305Rfc7539Row = record
    TestId, KeyMaterial, Message, ExpectedMac: string;
  end;

  /// <summary>
  /// Poly1305 NaCl and RFC 7539 test vectors from external CSV files.
  /// </summary>
  TPoly1305Vectors = class sealed
  strict private
    class var
      FNaClRows: TCryptoLibGenericArray<TPoly1305NaClRow>;
      FRfc7539Rows: TCryptoLibGenericArray<TPoly1305Rfc7539Row>;
      FNaClTable, FRfc7539Table: TCsvVectorTable;

    class function NaClRowFromCsv(const ARow: TCsvRow): TPoly1305NaClRow; static;
    class function Rfc7539RowFromCsv(const ARow: TCsvRow): TPoly1305Rfc7539Row; static;
    class procedure LoadNaClRows; static;
    class procedure LoadRfc7539Rows; static;
  public
    class function GetNaClRows: TCryptoLibGenericArray<TPoly1305NaClRow>; static;
    class function GetRfc7539Rows: TCryptoLibGenericArray<TPoly1305Rfc7539Row>; static;
    class constructor Create;
  end;

implementation

{ TChaChaVectors }

class function TChaChaVectors.KeystreamRowFromCsv(const ARow: TCsvRow): TChaChaKeystreamRow;
begin
  Result.Rounds := StrToIntDef(
    TCsvVectorParser.GetField(ARow, FKeystreamTable.Header, 'Rounds'), 20);
  Result.SetId := TCsvVectorParser.GetField(ARow, FKeystreamTable.Header, 'SetId');
  Result.Key := TCsvVectorParser.GetFieldUpperCase(FKeystreamTable, ARow, 'Key');
  Result.Nonce := TCsvVectorParser.GetFieldUpperCase(FKeystreamTable, ARow, 'Nonce');
  Result.ByteOffset := StrToIntDef(
    TCsvVectorParser.GetField(ARow, FKeystreamTable.Header, 'ByteOffset'), 0);
  Result.ExpectedKeystream := TCsvVectorParser.GetFieldUpperCase(
    FKeystreamTable, ARow, 'ExpectedKeystream');
end;

class function TChaChaVectors.AeadRowFromCsv(const ATable: TCsvVectorTable;
  const ARow: TCsvRow): TChaChaAeadRow;
begin
  Result.TestId := TCsvVectorParser.GetField(ARow, ATable.Header, 'TestId');
  Result.Key := TCsvVectorParser.GetFieldUpperCase(ATable, ARow, 'Key');
  Result.Nonce := TCsvVectorParser.GetFieldUpperCase(ATable, ARow, 'Nonce');
  Result.Aad := TCsvVectorParser.GetFieldUpperCase(ATable, ARow, 'Aad');
  Result.Plaintext := TCsvVectorParser.GetFieldUpperCase(ATable, ARow, 'Plaintext');
  Result.Ciphertext := TCsvVectorParser.GetFieldUpperCase(ATable, ARow, 'Ciphertext');
  Result.Tag := TCsvVectorParser.GetFieldUpperCase(ATable, ARow, 'Tag');
end;

class function TChaChaVectors.XChaChaStreamRowFromCsv(const ARow: TCsvRow): TXChaChaStreamRow;
var
  LSkipText: string;
begin
  Result.TestId := TCsvVectorParser.GetField(ARow, FXChaChaStreamTable.Header, 'TestId');
  Result.VectorType := TCsvVectorParser.GetField(ARow, FXChaChaStreamTable.Header, 'VectorType');
  Result.Key := TCsvVectorParser.GetFieldUpperCase(FXChaChaStreamTable, ARow, 'Key');
  Result.Nonce := TCsvVectorParser.GetFieldUpperCase(FXChaChaStreamTable, ARow, 'Nonce');
  LSkipText := TCsvVectorParser.GetField(ARow, FXChaChaStreamTable.Header, 'SkipBytes');
  if LSkipText = '' then
    Result.SkipBytes := 0
  else
    Result.SkipBytes := StrToIntDef(LSkipText, 0);
  Result.Plaintext := TCsvVectorParser.GetFieldUpperCase(FXChaChaStreamTable, ARow, 'Plaintext');
  Result.ExpectedHex := TCsvVectorParser.GetFieldUpperCase(FXChaChaStreamTable, ARow, 'ExpectedHex');
end;

class procedure TChaChaVectors.LoadKeystreamRows;
var
  LI: Integer;
begin
  FKeystreamTable := TCsvVectorLoaderBase.LoadTable('Crypto/ChaCha/EstreamKeystream.csv');
  SetLength(FKeystreamRows, Length(FKeystreamTable.Rows));
  for LI := 0 to High(FKeystreamTable.Rows) do
    FKeystreamRows[LI] := KeystreamRowFromCsv(FKeystreamTable.Rows[LI]);
end;

class procedure TChaChaVectors.LoadRfc7539Rows;
var
  LI: Integer;
begin
  FRfc7539Table := TCsvVectorLoaderBase.LoadTable('Crypto/ChaCha/Rfc7539Poly1305.csv');
  SetLength(FRfc7539Rows, Length(FRfc7539Table.Rows));
  for LI := 0 to High(FRfc7539Table.Rows) do
    FRfc7539Rows[LI] := AeadRowFromCsv(FRfc7539Table, FRfc7539Table.Rows[LI]);
end;

class procedure TChaChaVectors.LoadXChaChaPoly1305Rows;
var
  LI: Integer;
begin
  FXChaChaPoly1305Table := TCsvVectorLoaderBase.LoadTable('Crypto/ChaCha/XChaCha20Poly1305.csv');
  SetLength(FXChaChaPoly1305Rows, Length(FXChaChaPoly1305Table.Rows));
  for LI := 0 to High(FXChaChaPoly1305Table.Rows) do
    FXChaChaPoly1305Rows[LI] := AeadRowFromCsv(
      FXChaChaPoly1305Table, FXChaChaPoly1305Table.Rows[LI]);
end;

class procedure TChaChaVectors.LoadXChaChaStreamRows;
var
  LI: Integer;
begin
  FXChaChaStreamTable := TCsvVectorLoaderBase.LoadTable('Crypto/ChaCha/XChaCha20.csv');
  SetLength(FXChaChaStreamRows, Length(FXChaChaStreamTable.Rows));
  for LI := 0 to High(FXChaChaStreamTable.Rows) do
    FXChaChaStreamRows[LI] := XChaChaStreamRowFromCsv(FXChaChaStreamTable.Rows[LI]);
end;

class function TChaChaVectors.GetKeystreamSet(const ASetId: string): TChaChaKeystreamSet;
var
  LI, LCount: Integer;
begin
  LCount := 0;
  SetLength(Result.Checkpoints, 0);
  for LI := 0 to High(FKeystreamRows) do
  begin
    if SameText(FKeystreamRows[LI].SetId, ASetId) then
    begin
      if LCount = 0 then
      begin
        Result.Rounds := FKeystreamRows[LI].Rounds;
        Result.SetId := FKeystreamRows[LI].SetId;
        Result.Key := FKeystreamRows[LI].Key;
        Result.Nonce := FKeystreamRows[LI].Nonce;
      end;
      SetLength(Result.Checkpoints, LCount + 1);
      Result.Checkpoints[LCount] := FKeystreamRows[LI];
      Inc(LCount);
    end;
  end;
end;

class function TChaChaVectors.GetKeystreamSets: TCryptoLibGenericArray<TChaChaKeystreamSet>;
const
  SET_IDS: array [0 .. 5] of string = (
    'set1v0', 'set1v9', 'chacha12_set1v0', 'chacha8_set1v0', 'set6v0', 'set6v1');
var
  LI: Integer;
begin
  SetLength(Result, Length(SET_IDS));
  for LI := 0 to High(SET_IDS) do
    Result[LI] := GetKeystreamSet(SET_IDS[LI]);
end;

class function TChaChaVectors.GetRfc7539Poly1305Rows: TCryptoLibGenericArray<TChaChaAeadRow>;
begin
  Result := FRfc7539Rows;
end;

class function TChaChaVectors.GetXChaCha20Poly1305Row(const ATestId: string): TChaChaAeadRow;
var
  LI: Integer;
begin
  for LI := 0 to High(FXChaChaPoly1305Rows) do
  begin
    if SameText(FXChaChaPoly1305Rows[LI].TestId, ATestId) then
      Exit(FXChaChaPoly1305Rows[LI]);
  end;
  raise Exception.CreateFmt('Unknown XChaCha20-Poly1305 vector: %s', [ATestId]);
end;

class function TChaChaVectors.GetXChaChaStreamRow(const ATestId: string): TXChaChaStreamRow;
var
  LI: Integer;
begin
  for LI := 0 to High(FXChaChaStreamRows) do
  begin
    if SameText(FXChaChaStreamRows[LI].TestId, ATestId) then
      Exit(FXChaChaStreamRows[LI]);
  end;
  raise Exception.CreateFmt('Unknown XChaCha20 vector: %s', [ATestId]);
end;

class constructor TChaChaVectors.Create;
begin
  LoadKeystreamRows;
  LoadRfc7539Rows;
  LoadXChaChaPoly1305Rows;
  LoadXChaChaStreamRows;
end;

{ TPoly1305Vectors }

class function TPoly1305Vectors.NaClRowFromCsv(const ARow: TCsvRow): TPoly1305NaClRow;
begin
  Result.CaseIndex := StrToIntDef(
    TCsvVectorParser.GetField(ARow, FNaClTable.Header, 'CaseIndex'), 0);
  Result.ClampKey := TCsvVectorParser.ParseBoolField(
    TCsvVectorParser.GetField(ARow, FNaClTable.Header, 'ClampKey'));
  Result.UseAesNonce := TCsvVectorParser.ParseBoolField(
    TCsvVectorParser.GetField(ARow, FNaClTable.Header, 'UseAesNonce'));
  Result.Key := TCsvVectorParser.GetFieldUpperCase(FNaClTable, ARow, 'Key');
  Result.Nonce := TCsvVectorParser.GetFieldUpperCase(FNaClTable, ARow, 'Nonce');
  Result.Message := TCsvVectorParser.GetFieldUpperCase(FNaClTable, ARow, 'Message');
  Result.ExpectedMac := TCsvVectorParser.GetFieldUpperCase(FNaClTable, ARow, 'ExpectedMac');
end;

class function TPoly1305Vectors.Rfc7539RowFromCsv(const ARow: TCsvRow): TPoly1305Rfc7539Row;
begin
  Result.TestId := TCsvVectorParser.GetField(ARow, FRfc7539Table.Header, 'TestId');
  Result.KeyMaterial := TCsvVectorParser.GetFieldUpperCase(FRfc7539Table, ARow, 'KeyMaterial');
  Result.Message := TCsvVectorParser.GetFieldUpperCase(FRfc7539Table, ARow, 'Message');
  Result.ExpectedMac := TCsvVectorParser.GetFieldUpperCase(FRfc7539Table, ARow, 'ExpectedMac');
end;

class procedure TPoly1305Vectors.LoadNaClRows;
var
  LI: Integer;
begin
  FNaClTable := TCsvVectorLoaderBase.LoadTable('Crypto/Poly1305/NaCl.csv');
  SetLength(FNaClRows, Length(FNaClTable.Rows));
  for LI := 0 to High(FNaClTable.Rows) do
    FNaClRows[LI] := NaClRowFromCsv(FNaClTable.Rows[LI]);
end;

class procedure TPoly1305Vectors.LoadRfc7539Rows;
var
  LI: Integer;
begin
  FRfc7539Table := TCsvVectorLoaderBase.LoadTable('Crypto/Poly1305/Rfc7539.csv');
  SetLength(FRfc7539Rows, Length(FRfc7539Table.Rows));
  for LI := 0 to High(FRfc7539Table.Rows) do
    FRfc7539Rows[LI] := Rfc7539RowFromCsv(FRfc7539Table.Rows[LI]);
end;

class function TPoly1305Vectors.GetNaClRows: TCryptoLibGenericArray<TPoly1305NaClRow>;
begin
  Result := FNaClRows;
end;

class function TPoly1305Vectors.GetRfc7539Rows: TCryptoLibGenericArray<TPoly1305Rfc7539Row>;
begin
  Result := FRfc7539Rows;
end;

class constructor TPoly1305Vectors.Create;
begin
  LoadNaClRows;
  LoadRfc7539Rows;
end;

end.
