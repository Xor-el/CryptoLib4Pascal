program Make;
{$mode objfpc}{$H+}

uses
  Classes,
  SysUtils,
  StrUtils,
  FileUtil,
  Zipper,
  fphttpclient,
  RegExpr,
  openssl,
  opensslsockets,
  Process;

const
  Target: string = '.';
  Dependencies: array of string = ();

type
  TLog = (audit, info, error);

  Output = record
    Success: boolean;
    Output: string;
  end;

  procedure OutLog(const Knd: TLog; const Msg: string);
  begin
    case Knd of
      error: Writeln(stderr, #27'[31m', Msg, #27'[0m');
      info: Writeln(stderr, #27'[32m', Msg, #27'[0m');
      audit: Writeln(stderr, #27'[33m', Msg, #27'[0m');
    end;
  end;

  function CheckModules: string;
  begin
    if FileExists('.gitmodules') then
      if RunCommand('git', ['submodule', 'update', '--init', '--recursive',
        '--force', '--remote'], Result) then
        OutLog(info, Result);
  end;

  function AddPackage(const Path: string): string;
  begin
    with TRegExpr.Create do
    begin
      Expression :=
        {$IFDEF MSWINDOWS}
        '(cocoa|x11|_template)'
      {$ELSE}
        '(cocoa|gdi|_template)'
      {$ENDIF}
      ;
      if not Exec(Path) and RunCommand('lazbuild', ['--add-package-link', Path],
        Result) then
        OutLog(audit, '    ' + Path);
      Free;
    end;
  end;

  function SelectString(const Input, Reg: string): string;
  var
    Line: string;
  begin
    for Line in SplitString(Input, LineEnding) do
      with TRegExpr.Create do
      begin
        Expression := Reg;
        if Exec(Line) then
          Result += Line + LineEnding;
        Free;
      end;
  end;

  function BuildProject(const Path: string): Output;
  begin
    OutLog(audit, 'Build from ' + Path);
    Result.Success := RunCommand('lazbuild',
      ['--build-all', '--recursive', '--no-write-project', Path], Result.Output);
    Result.Output := SelectString(Result.Output, '(Fatal:|Error:|Linking)');
    if Result.Success then
    begin
      Result.Output := SplitString(Result.Output, ' ')[2];
      OutLog(info, '   to ' + Result.Output);
    end
    else
    begin
      ExitCode += 1;
      OutLog(error, Result.Output);
    end;
  end;

  function RunTest(Path: string): Output;
  begin
    Result := BuildProject(Path);
    if Result.Success then
    begin
      Path := Result.Output;
      OutLog(audit, 'run ' + Path);
      if not RunCommand(Path, ['--all', '--format=plain'], Result.Output) then
      begin
        ExitCode += 1;
        OutLog(error, Result.Output);
      end
      else
        OutLog(info, '    success!');
    end;
  end;

  function DownloadFile(const Uri: string): string;
  var
    OutFile: TStream;
  begin
    InitSSLInterface;
    Result := GetTempFileName;
    OutFile := TFileStream.Create(Result, fmCreate or fmOpenWrite);
    with TFPHttpClient.Create(nil) do
    begin
      try
        AddHeader('User-Agent', 'Mozilla/5.0 (compatible; fpweb)');
        AllowRedirect := True;
        Get(Uri, OutFile);
        OutLog(audit, 'Download from ' + Uri + ' to ' + Result);
      finally
        Free;
        OutFile.Free;
      end;
    end;
  end;

  procedure UnZip(const ZipFile, ZipPath: string);
  begin
    with TUnZipper.Create do
    begin
      try
        FileName := ZipFile;
        OutputPath := ZipPath;
        Examine;
        UnZipAllFiles;
        OutLog(audit, 'Unzip from ' + ZipFile + ' to ' + ZipPath);
        DeleteFile(ZipFile);
      finally
        Free;
      end;
    end;
  end;

  function InstallOPM(const Path: string): string;
  begin
    Result :=
      {$IFDEF MSWINDOWS}
      GetEnvironmentVariable('APPDATA') + '\.lazarus\onlinepackagemanager\packages\'
      {$ELSE}
      GetEnvironmentVariable('HOME') + '/.lazarus/onlinepackagemanager/packages/'
      {$ENDIF}
      + Path;
    if not DirectoryExists(Result) then
    begin
      CreateDir(Result);
      UnZip(DownloadFile('https://packages.lazarus-ide.org/' + Path + '.zip'), Result);
    end;
  end;

  procedure BuildAll;
  var
    Each: string;
    List: TStringList;
  begin
    CheckModules;
    List := FindAllFiles(GetCurrentDir, '*.lpk', True);
    try
      for Each in Dependencies do
        List.AddStrings(FindAllFiles(InstallOPM(Each), '*.lpk', True));
      if List.Count <> 0 then
        OutLog(audit, 'Add packages: ' + IntToStr(List.Count));
      for Each in List do
        AddPackage(Each);
      List := FindAllFiles(Target, '*.lpi', True);
      for Each in List do
        if not ContainsStr(Each, 'zengl') then
          if ContainsStr(ReadFileToString(ReplaceStr(Each, '.lpi', '.lpr')),
            'consoletestrunner') then
            RunTest(Each)
          else
            BuildProject(Each);
    finally
      List.Free;
    end;
    case ExitCode of
      0: OutLog(info, 'Errors: ' + IntToStr(ExitCode));
      else
        OutLog(error, 'Errors: ' + IntToStr(ExitCode));
    end;
  end;

begin
  if ParamCount <> 0 then
    case ParamStr(1) of
      'build': BuildAll;
      else
        OutLog(audit, 'Nothing!');
    end;
end.
