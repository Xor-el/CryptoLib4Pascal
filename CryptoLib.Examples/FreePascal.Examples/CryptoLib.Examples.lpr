program CryptoLib.Examples;

{$IFDEF FPC}
{$MODE DELPHI}
{$HINTS OFF}
{$WARNINGS OFF}
{$ENDIF FPC}

{$APPTYPE CONSOLE}

uses
  SysUtils,
  ClpLogger in '..\src\ClpLogger.pas',
  ClpConsoleLogger in '..\src\ClpConsoleLogger.pas',
  ClpExampleBase in '..\src\ClpExampleBase.pas',
  ClpExampleExplorer in '..\src\ClpExampleExplorer.pas',
  ClpDigestExample in '..\src\Examples\ClpDigestExample.pas',
  ClpRsaExample in '..\src\Examples\ClpRsaExample.pas',
  ClpEcExample in '..\src\Examples\ClpEcExample.pas',
  ClpCertificateExample in '..\src\Examples\ClpCertificateExample.pas',
  ClpCipherExample in '..\src\Examples\ClpCipherExample.pas',
  ClpEdExample in '..\src\Examples\ClpEdExample.pas',
  ClpHybridEncryption in '..\src\Examples\ClpHybridEncryption.pas';

begin
  TClpLogger.SetDefaultLogger(TConsoleLogger.Create('Examples', TLogLevel.Info) as ILogger);
  try
    TExampleExplorer.Execute;
  except
    on E: Exception do
      Writeln(E.ClassName, ': ', E.Message);
  end;
end.

