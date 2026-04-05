{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                           Author - Ugochukwu Mmaduekwe                          * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }

{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }

{ *                              Acknowledgements:                                  * }
{ *                                                                                 * }
{ *      Thanks to Sphere 10 Software (http://www.sphere10.com/) for sponsoring     * }
{ *                           development of this library                           * }

{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit ExampleExplorer;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$HINTS OFF}
{$WARNINGS OFF}
{$ENDIF FPC}

type
  TExampleExplorer = class
  public
    class procedure Execute;
  end;

implementation

uses
  SysUtils,
  ExampleBase,
  RsaExample,
  EcExample,
  EdExample,
  DigestExample,
  CipherExample,
  CertificateExample;

type
  TExampleBaseClass = class of TExampleBase;

const
  KnownExamples: array[0..5] of TExampleBaseClass = (
    TDigestExample,
    TCipherExample,
    TEcExample,
    TEdExample,
    TRsaExample,
    TCertificateExample
  );

class procedure TExampleExplorer.Execute;
var
  Option: string;
  I, Idx, N: Integer;
  LExample: IExample;
begin
  if Length(KnownExamples) = 0 then
  begin
    Writeln('No example classes found.');
    Exit;
  end;

  while True do
  begin
    Writeln('Choose an example to run (type exit/quit to leave):');
    for N := Low(KnownExamples) to High(KnownExamples) do
      Writeln(Format('  %d: %s', [N, KnownExamples[N].ClassName]));

    Readln(Option);
    if SameText(Trim(Option), 'exit') or SameText(Trim(Option), 'quit') then
      Break;

    if not TryStrToInt(Trim(Option), I) or (I < Low(KnownExamples)) or (I > High(KnownExamples)) then
    begin
      Writeln('Invalid option. Enter a number between 0 and ', High(KnownExamples), '.');
      Continue;
    end;

    Idx := I;
    try
      if Supports(KnownExamples[Idx].Create, IExample, LExample) then
      begin
        try
          LExample.Run;
        finally
          LExample := nil;
        end;
      end;
    except
      on E: Exception do
        Writeln(E.ClassName, ': ', E.Message);
    end;
  end;
end;

end.
