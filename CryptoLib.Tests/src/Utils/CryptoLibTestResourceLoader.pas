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

unit CryptoLibTestResourceLoader;

{ USE_EMBEDDED_TEST_DATA: test Data deployed with the app (StartUpCopy / bundle).
  Enabled automatically on Delphi Android, iOS, macOS, and Linux below. Not used by FPC. }

{$IFNDEF FPC}
  {$IF DEFINED(ANDROID) OR DEFINED(IOS) OR DEFINED(MACOS) OR DEFINED(LINUX)}
    {$DEFINE USE_EMBEDDED_TEST_DATA}
  {$ENDIF}
{$ENDIF}

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  Classes,
  SysUtils;

type
  ICryptoLibTestResourceLoader = interface
    ['{A7E3F2B1-4C5D-6E7F-8091-A2B3C4D5E6F7}']
    function LoadAsString(const ARelativePath: string): string; overload;
    function LoadAsString(const ARelativePath: string;
      AEncoding: TEncoding): string; overload;
    function LoadAsBytes(const ARelativePath: string): TBytes;
    function ResourceExists(const ARelativePath: string): Boolean;
  end;

  TFileSystemTestResourceLoader = class(TInterfacedObject,
    ICryptoLibTestResourceLoader)
  private
    function CurrentDataRoot: string;
    function FullPath(const ARelativePath: string): string;
    function ReadFileBytes(const AFullPath: string): TBytes;
    class function DecodeTextFromBytes(const ABytes: TBytes;
      AEncoding: TEncoding): string; static;
  public
    function LoadAsString(const ARelativePath: string): string; overload;
    function LoadAsString(const ARelativePath: string;
      AEncoding: TEncoding): string; overload;
    function LoadAsBytes(const ARelativePath: string): TBytes;
    function ResourceExists(const ARelativePath: string): Boolean;
  end;

  TCryptoLibTestResourceLoader = class sealed
  private
    class var FDataRoot: string;
    class var FInstance: ICryptoLibTestResourceLoader;
    class procedure BootstrapTestDataRoot; static;
  public
    class function DataRoot: string; static;
    class function Instance: ICryptoLibTestResourceLoader; static;
  end;

implementation

{$IF DEFINED(USE_EMBEDDED_TEST_DATA)}
uses
  System.IOUtils;
{$ENDIF}

const
  TestsProjectName = 'CryptoLib.Tests';
  TestsDataFolderName = 'Data';
  TestsDataSuffix = TestsProjectName + PathDelim + TestsDataFolderName;
  TestsDataSentinel = 'Crypto/Dsa/Fips1862Golden.json';
  DataRootNotSet =
    'Test data root not found. Deploy Data for embedded targets or run tests with cwd under the repo.';

function CombineDataPath(const ABase, ARelativePath: string): string;
var
  LRelative: string;
begin
  if ARelativePath = '' then
    Exit(IncludeTrailingPathDelimiter(ExcludeTrailingPathDelimiter(ABase)));
  LRelative := StringReplace(ARelativePath, '\', PathDelim, [rfReplaceAll]);
  LRelative := StringReplace(LRelative, '/', PathDelim, [rfReplaceAll]);
  Result := IncludeTrailingPathDelimiter(ExcludeTrailingPathDelimiter(ABase)) + LRelative;
end;

function IsCryptoLibTestsDataDir(const ADataDir: string): Boolean;
var
  LDataDir, LParentDir: string;
begin
  LDataDir := ExcludeTrailingPathDelimiter(ADataDir);
  if (LDataDir = '') or not DirectoryExists(LDataDir) then
    Exit(False);

  if not SameText(ExtractFileName(LDataDir), TestsDataFolderName) then
    Exit(False);

  LParentDir := ExcludeTrailingPathDelimiter(ExtractFilePath(LDataDir));
  if (LParentDir = '') or not SameText(ExtractFileName(LParentDir), TestsProjectName) then
    Exit(False);

  Result := True;
end;

function DiscoverTestsDataRoot: string;
var
  LDir, LCandidate, LParent: string;
  LI: Integer;
begin
  Result := '';
  LDir := ExcludeTrailingPathDelimiter(GetCurrentDir);
  if LDir = '' then
    Exit;

  for LI := 0 to 12 do
  begin
    if LDir = '' then
      Break;

    LCandidate := IncludeTrailingPathDelimiter(LDir) + TestsDataSuffix;
    if IsCryptoLibTestsDataDir(LCandidate) then
      Exit(ExcludeTrailingPathDelimiter(LCandidate));

    LParent := ExtractFilePath(LDir);
    LParent := ExcludeTrailingPathDelimiter(LParent);
    if (LParent = '') or SameText(LParent, LDir) then
      Break;
    LDir := LParent;
  end;
end;

{$IF DEFINED(USE_EMBEDDED_TEST_DATA)}
function TryGetEmbeddedTestDataRoot: string;

  function EmbeddedDocumentsDataRoot: string;
  begin
    Result := IncludeTrailingPathDelimiter(TPath.GetDocumentsPath) + TestsDataSuffix;
  end;

begin
  Result := '';
  if FileExists(CombineDataPath(EmbeddedDocumentsDataRoot, TestsDataSentinel)) then
    Result := ExcludeTrailingPathDelimiter(EmbeddedDocumentsDataRoot);
end;
{$ENDIF}

{ TFileSystemTestResourceLoader }

function TFileSystemTestResourceLoader.CurrentDataRoot: string;
begin
  Result := TCryptoLibTestResourceLoader.DataRoot;
  if Result = '' then
    raise Exception.Create('Test data root is empty');
end;

function TFileSystemTestResourceLoader.FullPath(const ARelativePath: string): string;
begin
  Result := CombineDataPath(CurrentDataRoot, ARelativePath);
end;

function TFileSystemTestResourceLoader.ReadFileBytes(const AFullPath: string): TBytes;
var
  LStream: TFileStream;
  LSize: Int64;
begin
  if not FileExists(AFullPath) then
    raise Exception.CreateFmt('Test resource not found: %s', [AFullPath]);
  LStream := TFileStream.Create(AFullPath, fmOpenRead or fmShareDenyWrite);
  try
    LSize := LStream.Size;
    SetLength(Result, LSize);
    if LSize > 0 then
      LStream.ReadBuffer(Result[0], LSize);
  finally
    LStream.Free;
  end;
end;

class function TFileSystemTestResourceLoader.DecodeTextFromBytes(
  const ABytes: TBytes; AEncoding: TEncoding): string;
var
  LBOMLength: Integer;
  LEnc: TEncoding;
begin
  if Length(ABytes) = 0 then
    Exit('');
  LEnc := AEncoding;
  if LEnc = nil then
    LEnc := TEncoding.UTF8;
  LBOMLength := TEncoding.GetBufferEncoding(ABytes, LEnc);
  Result := LEnc.GetString(ABytes, LBOMLength, Length(ABytes) - LBOMLength);
end;

function TFileSystemTestResourceLoader.LoadAsBytes(
  const ARelativePath: string): TBytes;
begin
  Result := ReadFileBytes(FullPath(ARelativePath));
end;

function TFileSystemTestResourceLoader.LoadAsString(
  const ARelativePath: string): string;
begin
  Result := LoadAsString(ARelativePath, TEncoding.UTF8);
end;

function TFileSystemTestResourceLoader.LoadAsString(const ARelativePath: string;
  AEncoding: TEncoding): string;
begin
  Result := DecodeTextFromBytes(LoadAsBytes(ARelativePath), AEncoding);
end;

function TFileSystemTestResourceLoader.ResourceExists(
  const ARelativePath: string): Boolean;
begin
  Result := FileExists(FullPath(ARelativePath));
end;

{ TCryptoLibTestResourceLoader }

class function TCryptoLibTestResourceLoader.DataRoot: string;
begin
  Result := FDataRoot;
end;

class procedure TCryptoLibTestResourceLoader.BootstrapTestDataRoot;
var
  LRoot: string;
begin
  FDataRoot := '';
{$IF DEFINED(USE_EMBEDDED_TEST_DATA)}
  FDataRoot := TryGetEmbeddedTestDataRoot;
{$ENDIF}
  if FDataRoot = '' then
  begin
    LRoot := DiscoverTestsDataRoot;
    if LRoot <> '' then
      FDataRoot := LRoot;
  end;
end;

class function TCryptoLibTestResourceLoader.Instance: ICryptoLibTestResourceLoader;
begin
  if FDataRoot = '' then
    raise Exception.Create(DataRootNotSet);
  if FInstance = nil then
    FInstance := TFileSystemTestResourceLoader.Create;
  Result := FInstance;
end;

initialization
  TCryptoLibTestResourceLoader.BootstrapTestDataRoot;

end.
