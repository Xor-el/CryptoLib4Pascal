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

{ USE_EMBEDDED_TEST_DATA: deployed file assets (StartUpCopy / bundle).
  Enabled on Delphi Android, iOS, macOS, and Linux. Not used by FPC. }

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
  SysUtils,
  SyncObjs;

type
  ICryptoLibTestDataPathProvider = interface
    ['{B8C9D0E1-F2A3-4567-8901-BC2D3E4F5A60}']
    function GetDataRoot: string;
    property DataRoot: string read GetDataRoot;
  end;

  ICryptoLibTestResourceLoader = interface
    ['{A7E3F2B1-4C5D-6E7F-8091-A2B3C4D5E6F7}']
    function LoadAsString(const ARelativePath: string): string; overload;
    function LoadAsString(const ARelativePath: string;
      AEncoding: TEncoding): string; overload;
    function LoadAsBytes(const ARelativePath: string): TBytes;
    function ResourceExists(const ARelativePath: string): Boolean;
  end;

  TFileAssetDataRootProvider = class(TInterfacedObject, ICryptoLibTestDataPathProvider)
  private
    FDataRoot: string;
    function GetDataRoot: string;
  public
    constructor Create(const ADataRoot: string);
  end;

  TDiscoveringDataRootProvider = class(TInterfacedObject, ICryptoLibTestDataPathProvider)
  private
    class function IsValidDataDir(const ADataDir: string): Boolean; static;
    class function Discover: string; static;
    function GetDataRoot: string;
  public
  end;

  TBaseCryptoLibTestResourceLoader = class abstract(TInterfacedObject,
    ICryptoLibTestResourceLoader)
  protected
    function DoLoadBytes(const ARelativePath: string): TBytes; virtual; abstract;
    function DoesResourceExist(const ARelativePath: string): Boolean; virtual; abstract;
    function LoadString(const ARelativePath: string;
      AEncoding: TEncoding): string;
  public
    function LoadAsString(const ARelativePath: string): string; overload;
    function LoadAsString(const ARelativePath: string;
      AEncoding: TEncoding): string; overload;
    function LoadAsBytes(const ARelativePath: string): TBytes;
    function ResourceExists(const ARelativePath: string): Boolean;
  end;

  TFileSystemTestResourceLoader = class(TBaseCryptoLibTestResourceLoader)
  private
    FPathProvider: ICryptoLibTestDataPathProvider;
    function TryFullPath(const ARelativePath: string; out AFullPath: string): Boolean;
    function FullPath(const ARelativePath: string): string;
    function ReadFileBytes(const AFullPath: string): TBytes;
  protected
    function DoLoadBytes(const ARelativePath: string): TBytes; override;
    function DoesResourceExist(const ARelativePath: string): Boolean; override;
  public
    constructor Create(const APathProvider: ICryptoLibTestDataPathProvider);
  end;

  TCryptoLibTestResourceLoader = class sealed
  private
    type
      TFacadeState = record
        PathProvider: ICryptoLibTestDataPathProvider;
        Loader: ICryptoLibTestResourceLoader;
        DataRoot: string;
      end;
    class var FLock: TCriticalSection;
    class var FPathProvider: ICryptoLibTestDataPathProvider;
    class var FInstance: ICryptoLibTestResourceLoader;
    class constructor Create;
    class destructor Destroy;
    class procedure ConfigureDefaults; static;
    class function GetFacadeState: TFacadeState; static;
    class procedure ValidateDataRoot(const ADataRoot: string); static;
    class function GetDataRoot: string; static;
    class function GetPathProvider: ICryptoLibTestDataPathProvider; static;
    class function GetInstance: ICryptoLibTestResourceLoader; static;
  public
    const
      CryptoLibTestDataSentinel = 'Crypto/Dsa/Fips1862Golden.json';

    class function ResolveRelativePath(const ARoot, ARelativePath: string): string; static;
    class procedure SetPathProvider(const AProvider: ICryptoLibTestDataPathProvider); static;
    class property DataRoot: string read GetDataRoot;
    class property PathProvider: ICryptoLibTestDataPathProvider read GetPathProvider;
    class property Instance: ICryptoLibTestResourceLoader read GetInstance;
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
  DataRootNotSet =
    'Test data path provider not configured. Call SetPathProvider before using Instance.';
  SentinelMissingFmt =
    'Test data sentinel not found. Expected %s under data root: %s';
  PathProviderNilMsg = 'Test data path provider is nil';
  DataRootEmptyMsg = 'Test data root is empty';

function CombineRelativeToDataRoot(const ARoot, ARelativePath: string): string;
var
  LRelative: string;
begin
  if ARelativePath = '' then
    Exit(IncludeTrailingPathDelimiter(ExcludeTrailingPathDelimiter(ARoot)));
  LRelative := StringReplace(ARelativePath, '\', PathDelim, [rfReplaceAll]);
  LRelative := StringReplace(LRelative, '/', PathDelim, [rfReplaceAll]);
  Result := IncludeTrailingPathDelimiter(ExcludeTrailingPathDelimiter(ARoot)) + LRelative;
end;

procedure RequirePathProvider(const AProvider: ICryptoLibTestDataPathProvider);
begin
  if AProvider = nil then
    raise Exception.Create(PathProviderNilMsg);
end;

{ TFileAssetDataRootProvider }

constructor TFileAssetDataRootProvider.Create(const ADataRoot: string);
begin
  inherited Create;
  FDataRoot := ExcludeTrailingPathDelimiter(ADataRoot);
end;

function TFileAssetDataRootProvider.GetDataRoot: string;
begin
  Result := FDataRoot;
end;

{ TDiscoveringDataRootProvider }

class function TDiscoveringDataRootProvider.IsValidDataDir(const ADataDir: string): Boolean;
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

class function TDiscoveringDataRootProvider.Discover: string;
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
    if IsValidDataDir(LCandidate) then
      Exit(ExcludeTrailingPathDelimiter(LCandidate));

    LParent := ExtractFilePath(LDir);
    LParent := ExcludeTrailingPathDelimiter(LParent);
    if (LParent = '') or SameText(LParent, LDir) then
      Break;
    LDir := LParent;
  end;
end;

function TDiscoveringDataRootProvider.GetDataRoot: string;
begin
  Result := Discover;
end;

{ TBaseCryptoLibTestResourceLoader }

function TBaseCryptoLibTestResourceLoader.LoadString(const ARelativePath: string;
  AEncoding: TEncoding): string;
var
  LBytes: TBytes;
  LBOMLength: Integer;
  LEnc: TEncoding;
begin
  Result := '';
  LBytes := DoLoadBytes(ARelativePath);
  if Length(LBytes) = 0 then
    Exit;
  LEnc := AEncoding;
  if LEnc = nil then
    LEnc := TEncoding.UTF8;
  LBOMLength := TEncoding.GetBufferEncoding(LBytes, LEnc);
  Result := LEnc.GetString(LBytes, LBOMLength, Length(LBytes) - LBOMLength);
end;

function TBaseCryptoLibTestResourceLoader.LoadAsString(
  const ARelativePath: string): string;
begin
  Result := LoadAsString(ARelativePath, TEncoding.UTF8);
end;

function TBaseCryptoLibTestResourceLoader.LoadAsString(const ARelativePath: string;
  AEncoding: TEncoding): string;
begin
  Result := LoadString(ARelativePath, AEncoding);
end;

function TBaseCryptoLibTestResourceLoader.LoadAsBytes(
  const ARelativePath: string): TBytes;
begin
  Result := DoLoadBytes(ARelativePath);
end;

function TBaseCryptoLibTestResourceLoader.ResourceExists(
  const ARelativePath: string): Boolean;
begin
  Result := DoesResourceExist(ARelativePath);
end;

{ TFileSystemTestResourceLoader }

constructor TFileSystemTestResourceLoader.Create(
  const APathProvider: ICryptoLibTestDataPathProvider);
begin
  inherited Create;
  RequirePathProvider(APathProvider);
  FPathProvider := APathProvider;
end;

function TFileSystemTestResourceLoader.TryFullPath(const ARelativePath: string;
  out AFullPath: string): Boolean;
var
  LRoot: string;
begin
  LRoot := FPathProvider.DataRoot;
  if LRoot = '' then
    Exit(False);
  AFullPath := CombineRelativeToDataRoot(LRoot, ARelativePath);
  Result := True;
end;

function TFileSystemTestResourceLoader.FullPath(const ARelativePath: string): string;
begin
  if not TryFullPath(ARelativePath, Result) then
    raise Exception.Create(DataRootEmptyMsg);
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

function TFileSystemTestResourceLoader.DoLoadBytes(
  const ARelativePath: string): TBytes;
begin
  Result := ReadFileBytes(FullPath(ARelativePath));
end;

function TFileSystemTestResourceLoader.DoesResourceExist(
  const ARelativePath: string): Boolean;
var
  LFullPath: string;
begin
  if not TryFullPath(ARelativePath, LFullPath) then
    Exit(False);
  Result := FileExists(LFullPath);
end;

{ TCryptoLibTestResourceLoader }

class constructor TCryptoLibTestResourceLoader.Create;
begin
  FLock := TCriticalSection.Create;
  ConfigureDefaults;
end;

class destructor TCryptoLibTestResourceLoader.Destroy;
begin
  FInstance := nil;
  FPathProvider := nil;
  FreeAndNil(FLock);
end;

class function TCryptoLibTestResourceLoader.ResolveRelativePath(const ARoot,
  ARelativePath: string): string;
begin
  Result := CombineRelativeToDataRoot(ARoot, ARelativePath);
end;

class procedure TCryptoLibTestResourceLoader.ConfigureDefaults;
var
  LPathProvider: ICryptoLibTestDataPathProvider;
begin
{$IF DEFINED(USE_EMBEDDED_TEST_DATA)}
  LPathProvider := TFileAssetDataRootProvider.Create(
    TPath.Combine(TPath.GetDocumentsPath, TestsProjectName, TestsDataFolderName));
{$ELSE}
  LPathProvider := TDiscoveringDataRootProvider.Create;
{$ENDIF}
  SetPathProvider(LPathProvider);
end;

class function TCryptoLibTestResourceLoader.GetFacadeState: TFacadeState;
begin
  FLock.Enter;
  try
    Result.PathProvider := FPathProvider;
    Result.Loader := FInstance;
    if FPathProvider = nil then
      Result.DataRoot := ''
    else
      Result.DataRoot := FPathProvider.DataRoot;
  finally
    FLock.Leave;
  end;
end;

class procedure TCryptoLibTestResourceLoader.ValidateDataRoot(const ADataRoot: string);
var
  LSentinelPath: string;
begin
  if ADataRoot = '' then
    raise Exception.Create(DataRootNotSet);
  LSentinelPath := CombineRelativeToDataRoot(ADataRoot, CryptoLibTestDataSentinel);
  if not FileExists(LSentinelPath) then
    raise Exception.CreateFmt(SentinelMissingFmt,
      [CryptoLibTestDataSentinel, ADataRoot]);
end;

class function TCryptoLibTestResourceLoader.GetDataRoot: string;
begin
  Result := GetFacadeState().DataRoot;
end;

class function TCryptoLibTestResourceLoader.GetPathProvider
  : ICryptoLibTestDataPathProvider;
begin
  Result := GetFacadeState().PathProvider;
end;

class procedure TCryptoLibTestResourceLoader.SetPathProvider(
  const AProvider: ICryptoLibTestDataPathProvider);
begin
  RequirePathProvider(AProvider);
  FLock.Enter;
  try
    FPathProvider := AProvider;
    FInstance := TFileSystemTestResourceLoader.Create(AProvider);
  finally
    FLock.Leave;
  end;
end;

class function TCryptoLibTestResourceLoader.GetInstance
  : ICryptoLibTestResourceLoader;
var
  LRoot: string;
begin
  FLock.Enter;
  try
    if FPathProvider = nil then
      LRoot := ''
    else
      LRoot := FPathProvider.DataRoot;
    ValidateDataRoot(LRoot);
    Result := FInstance;
  finally
    FLock.Leave;
  end;
end;

end.
