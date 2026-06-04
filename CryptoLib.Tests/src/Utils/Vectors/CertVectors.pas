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

unit CertVectors;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  SysUtils,
  ClpCryptoLibTypes,
  CryptoLibTestResourceLoader,
  CsvVectorParser,
  CsvVectorLoaderBase,
  PemDerCodec;

type
  TCertAssetRow = record
    CertId, FilePath, EncodingName, Category, SourceName, UsedBy: string;
    CanonicalDer: Boolean;
  end;

  TCertSubjectRow = record
    CertId, ExpectedSubject: string;
  end;

  TCertVectors = class sealed
  strict private
    class var
      FAssets: TCryptoLibGenericArray<TCertAssetRow>;
      FSubjects: TCryptoLibGenericArray<TCertSubjectRow>;
      FAssetTable: TCsvVectorTable;

    class function AssetFromCsv(const ARow: TCsvRow): TCertAssetRow; static;
    class function GetAssetField(const ARow: TCsvRow; const AName: string): string; static;
    class function FindAssetIndex(const ACertId: string): Integer; static;
    class function FindSubjectIndex(const ACertId: string): Integer; static;
    class function ResolveCertId(const ACertId: string): string; static;
    class function LoadManifestFile(const ARelativePath: string): TCsvVectorTable; static;
    class procedure LoadSubjects; static;
    class function LoadBytes(const ACertId: string): TCryptoLibByteArray; static;
  public
    class function LoadDer(const ACertId: string): TCryptoLibByteArray; static;
    class function LoadPemBytes(const ACertId: string): TCryptoLibByteArray; static;
    class function LoadPemString(const ACertId: string): string; static;
    class function LoadPemText(const ACertId: string): string; static;
    class function GetExpectedSubject(const ACertId: string): string; static;
    class constructor Create;
  end;

implementation

{ TCertVectors }

class function TCertVectors.GetAssetField(const ARow: TCsvRow; const AName: string): string;
begin
  Result := Trim(TCsvVectorParser.GetField(ARow, FAssetTable.Header, AName));
end;

class function TCertVectors.AssetFromCsv(const ARow: TCsvRow): TCertAssetRow;
var
  LCanonical: string;
begin
  Result.CertId := GetAssetField(ARow, 'CertId');
  Result.FilePath := GetAssetField(ARow, 'File');
  Result.EncodingName := GetAssetField(ARow, 'Encoding');
  Result.Category := GetAssetField(ARow, 'Category');
  Result.SourceName := GetAssetField(ARow, 'SourceName');
  Result.UsedBy := GetAssetField(ARow, 'UsedBy');
  LCanonical := LowerCase(GetAssetField(ARow, 'CanonicalDer'));
  Result.CanonicalDer := (LCanonical = 'true') or (LCanonical = '1') or (LCanonical = 'yes');
end;

class function TCertVectors.ResolveCertId(const ACertId: string): string;
begin
  if SameText(ACertId, 'LegacyConnect4Server') or SameText(ACertId, 'Certificate2') then
    Exit('Connect4Server');
  if SameText(ACertId, 'LegacyConnect4Ca') then
    Exit('Connect4Ca');
  if SameText(ACertId, 'RsaCrl1') then
    Exit('Crl1');
  if SameText(ACertId, 'Certificate1') then
    Exit('Connect4ServerX509Armor');
  if SameText(ACertId, 'Certificate2NoTrailingNl') then
    Exit('Connect4ServerNoTrailingNl');
  Result := ACertId;
end;

class function TCertVectors.LoadManifestFile(const ARelativePath: string): TCsvVectorTable;
begin
  Result := TCsvVectorLoaderBase.LoadTable(ARelativePath);
end;

class procedure TCertVectors.LoadSubjects;
var
  LTable: TCsvVectorTable;
  LI: Integer;
begin
  if not TCryptoLibTestResourceLoader.Instance.ResourceExists('Cert/Subjects.csv') then
    Exit;
  LTable := TCsvVectorLoaderBase.LoadTable('Cert/Subjects.csv');
  SetLength(FSubjects, Length(LTable.Rows));
  for LI := 0 to High(LTable.Rows) do
  begin
    FSubjects[LI].CertId := Trim(TCsvVectorParser.GetField(LTable.Rows[LI], LTable.Header, 'CertId'));
    FSubjects[LI].ExpectedSubject := Trim(TCsvVectorParser.GetField(LTable.Rows[LI], LTable.Header,
      'ExpectedSubject'));
  end;
end;

class function TCertVectors.FindAssetIndex(const ACertId: string): Integer;
var
  LI: Integer;
  LResolved: string;
begin
  LResolved := ResolveCertId(ACertId);
  for LI := 0 to High(FAssets) do
  begin
    if SameText(FAssets[LI].CertId, LResolved) then
      Exit(LI);
  end;
  raise Exception.CreateFmt('Unknown cert asset: %s', [ACertId]);
end;

class function TCertVectors.FindSubjectIndex(const ACertId: string): Integer;
var
  LI: Integer;
  LResolved: string;
begin
  LResolved := ResolveCertId(ACertId);
  for LI := 0 to High(FSubjects) do
  begin
    if SameText(FSubjects[LI].CertId, LResolved) then
      Exit(LI);
  end;
  raise Exception.CreateFmt('Unknown cert subject: %s', [ACertId]);
end;

class function TCertVectors.LoadBytes(const ACertId: string): TCryptoLibByteArray;
var
  LAsset: TCertAssetRow;
begin
  LAsset := FAssets[FindAssetIndex(ACertId)];
  Result := TCryptoLibTestResourceLoader.Instance.LoadAsBytes(LAsset.FilePath);
end;

class function TCertVectors.LoadDer(const ACertId: string): TCryptoLibByteArray;
var
  LAsset: TCertAssetRow;
  LFileBytes: TCryptoLibByteArray;
begin
  LAsset := FAssets[FindAssetIndex(ACertId)];
  LFileBytes := TCryptoLibTestResourceLoader.Instance.LoadAsBytes(LAsset.FilePath);
  if SameText(LAsset.EncodingName, 'PEM') and LAsset.CanonicalDer then
    Result := TPemDerCodec.ExtractDerFromPem(LFileBytes)
  else
    Result := LFileBytes;
end;

class function TCertVectors.LoadPemBytes(const ACertId: string): TCryptoLibByteArray;
begin
  Result := LoadBytes(ACertId);
end;

class function TCertVectors.LoadPemString(const ACertId: string): string;
begin
  Result := TPemDerCodec.BytesToPemString(LoadPemBytes(ACertId));
end;

class function TCertVectors.LoadPemText(const ACertId: string): string;
begin
  Result := LoadPemString(ACertId);
end;

class function TCertVectors.GetExpectedSubject(const ACertId: string): string;
begin
  Result := FSubjects[FindSubjectIndex(ACertId)].ExpectedSubject;
end;

class constructor TCertVectors.Create;
var
  LTable: TCsvVectorTable;
  LI: Integer;
begin
  LTable := LoadManifestFile('Cert/Manifest.csv');
  FAssetTable := LTable;
  SetLength(FAssets, Length(LTable.Rows));
  for LI := 0 to High(LTable.Rows) do
    FAssets[LI] := AssetFromCsv(LTable.Rows[LI]);
  LoadSubjects;
end;

end.
