program CryptoLib.Examples;

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

{$APPTYPE CONSOLE}

uses
  SysUtils,
  ExampleLogger in '..\src\ExampleLogger.pas',
  ConsoleLogger in '..\src\ConsoleLogger.pas',
  ExampleBase in '..\src\ExampleBase.pas',
  ExampleExplorer in '..\src\ExampleExplorer.pas',
  DigestExample in '..\src\Examples\DigestExample.pas',
  RsaExample in '..\src\Examples\RsaExample.pas',
  EcExample in '..\src\Examples\EcExample.pas',
  CertificateExample in '..\src\Examples\CertificateExample.pas',
  CipherExample in '..\src\Examples\CipherExample.pas',
  EdExample in '..\src\Examples\EdExample.pas',
  HybridEncryption in '..\src\Examples\HybridEncryption.pas';

begin
  TExampleLogger.SetDefaultLogger(TConsoleLogger.Create('Examples', TLogLevel.Info) as ILogger);
  try
    TExampleExplorer.Execute;
  except
    on E: Exception do
      Writeln(E.ClassName, ': ', E.Message);
  end;
end.

