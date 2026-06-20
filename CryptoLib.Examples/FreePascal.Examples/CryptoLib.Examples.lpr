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
  ExampleExplorer in '..\src\ExampleExplorer.pas';

begin
  TExampleLogger.SetDefaultLogger(TConsoleLogger.Create('Examples', TLogLevel.Info) as ILogger);
  try
    TExampleExplorer.Execute;
  except
    on E: Exception do
      Writeln(E.ClassName, ': ', E.Message);
  end;
end.

