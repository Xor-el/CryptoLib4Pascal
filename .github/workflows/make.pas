//castle-engine.io/modern_pascal

program Make;
{$mode objfpc}{$H+}

uses
  Classes,
  SysUtils,
  StrUtils,
  FileUtil,
  LazFileUtils,
  Zipper,
  fphttpclient,
  RegExpr,
  openssl,
  LazUTF8,
  opensslsockets,
  eventlog,
  Process;

function OutLog(const Knd: TEventType; const Msg: string): string; cdecl;
begin
  case Knd of
    etError: Result := #27'[31m%s'#27'[0m';
    etInfo:  Result := #27'[32m%s'#27'[0m';
    etDebug: Result := #27'[33m%s'#27'[0m';
  end;
  if Knd = etError then ExitCode += 1;
  Writeln(stderr, UTF8ToConsole(Result.Format([Msg])));
end;

function SelectString(const Input, Reg: string): string; cdecl;
var Line: string;
begin
  Result := EmptyStr;
  with TRegExpr.Create do begin
    Expression := Reg;
    for Line in Input.Split(LineEnding) do
      if Exec(Line) then Result += Line + LineEnding;
    Free;
  end;
end;

function RunShell(const Command: String): string; cdecl;
begin
  OutLog(etDebug, '-- RunShell:'#9 + Command);
  if not RunCommand(
  {$IFDEF MSWINDOWS}
  'pwsh', [
      '-NoExit',
      '-NonInteractive',
      '-Command',
      '$ErrorActionPreference = "stop"; Set-PSDebug -Strict; ' + Command + '; exit'
    ]
  {$ELSE}
  'bash', ['-c', 'set -euo pipefail; ' + Command]
  {$ENDIF}
  , Result, [poStderrToOutPut, poWaitOnExit]) then
    OutLog(etError, Result);
end;

function AddPackage(const Path: string; const Link: boolean): string;
var Line: string;
begin
  if Link then Line := '--add-package-link'
  else Line := '--build-all'; 
  Result := {$IFDEF MSWINDOWS}
    '(cocoa|x11|_template)' {$ELSE}
    '(cocoa|gdi|_template)' {$ENDIF};
  OutLog(etDebug, 'AddPackage:'#9 + Path);
  if SelectString(Path, Result) = EmptyStr then
    RunShell('lazbuild --recursive %s %s'.Format([Line, Path]));
end;

function AddLibrary(const Path: String): string; cdecl;
begin
  Result := '/usr/lib/';
  OutLog(etDebug, 'AddLibrary:'#9 + Path);
  if not FileExists(Result + ExtractFileName(Path)) then
    RunShell('sudo cp %s %s; ldconfig'.Format([Path, Result]));
end;

function BuildProject(const Path: string): string; cdecl;
var Text: string;
begin
  OutLog(etDebug, 'BuildProject from:'#9 + Path);
  if not RunCommand('lazbuild',
    ['--build-all', '--recursive', '--no-write-project', Path], Result, [poStderrToOutPut, poWaitOnExit])
  then OutLog(etError, SelectString(Result, '(Fatal|Error):'))
  else begin
    Result := SelectString(Result, 'Linking').Split(' ')[2].Replace(LineEnding, EmptyStr);
    OutLog(etInfo, #10#9'to:'#9 + Result);
    Text := ReadFileToString(Path.Replace('.lpi', '.lpr'));
    if Text.Contains('program') and Text.Contains('consoletestrunner') then
      RunShell('%s --all --format=plain'.Format([Result]))
    else if Text.Contains('library') and Text.Contains('exports') then
      AddLibrary(Result);
  end;
end;

function ExtractPackage(const ZipFile: string): string; cdecl;
begin
  Result := GetEnvironmentVariable({$IFDEF MSWINDOWS}'APPDATA'{$ELSE}'HOME'{$ENDIF})
    + '/.lazarus/onlinepackagemanager/packages/'.Replace('/', DirectorySeparator)
    + ZipFile.Split('_')[1];
  OutLog(etDebug, 'ExtPackage from:'#9 + ZipFile + #10#9'to:'#9 + Result);
  if not DirectoryExists(Result) and ForceDirectories(Result) then
  with TUnZipper.Create do begin
    try
      FileName := ZipFile;
      OutputPath := Result;
      Examine;
      UnZipAllFiles;
      DeleteFile(ZipFile);
    finally
      Free;
    end;
  end;
end;

function GetPackage(const Uri, Package: string): string; cdecl;
var FileStream: TStream;
begin
  Result := '%s_%s'.Format([GetTempFileName, Package]);
  OutLog(etDebug, 'GetPackage from'#9 + Uri + #10#9'to:'#9 + Result);
    InitSSLInterface;
    FileStream := TFileStream.Create(Result, fmCreate or fmOpenWrite);
    with TFPHttpClient.Create(nil) do begin
      try
        AddHeader('User-Agent', 'Mozilla/5.0 (compatible; fpweb)');
        AllowRedirect := True;
        Get(Uri + Package + '.zip', FileStream);
      finally
        Free;
        FileStream.Free;
      end;
    end;
end;

function BuildAll(const OutDep: array of string): string;
var
  Item: string;
  DT: TDateTime;
begin
  DT := Time;
  OutLog(etDebug, #10'#----------------------------------[GET OUT DEPENDENS]----------------------------------#'#10);
  for Item in OutDep do
    for Result in FindAllFiles(ExtractPackage(
      GetPackage('https://packages.lazarus-ide.org/', Item)
    ), '*.lpk') do
      AddPackage(Result, true);
  OutLog(etDebug, #10'#----------------------------------[GET IN  DEPENDENS]----------------------------------#'#10);
  for Result in FindAllFiles(GetCurrentDir, '*.lpk') do
    AddPackage(Result, false);
  OutLog(etDebug, #10'#----------------------------------[BUILD     PROECTS]----------------------------------#'#10);
  for Result in FindAllFiles(GetCurrentDir, '*.lpi') do
    if not Result.Contains(DirectorySeparator + 'use' + DirectorySeparator) then
      BuildProject(Result);
  OutLog(etDebug, #10'#----------------------------------[      RESULT      ]----------------------------------#'#10);
  OutLog(etDebug, 'Duration:'#9 + FormatDateTime('hh:nn:ss', Time - DT));
  case ExitCode of
    0: OutLog(etInfo,    #9'Errors:'#9 + ExitCode.ToString);
    else OutLog(etError, #9'Errors:'#9 + ExitCode.ToString);
  end;
end;

begin
  try
    if ParamCount > 0 then
      case ParamStr(1) of
        'build': BuildAll(['HashLib', 'SimpleBaseLib']);
        else OutLog(etError, ParamStr(1));
      end;
  except
    on E: Exception do
      OutLog(etError, E.ClassName + #9 + E.Message);
  end;
end.
