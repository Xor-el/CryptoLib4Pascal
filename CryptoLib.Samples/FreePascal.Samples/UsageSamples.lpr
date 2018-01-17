program UsageSamples;

{$mode objfpc}{$H+}

uses {$IFDEF UNIX} {$IFDEF UseCThreads}
  cthreads, {$ENDIF} {$ENDIF}
  SysUtils,
  UsageExamples;

begin
  try
    { TODO -oUser -cConsole Main : Insert code here }
    TUsageExamples.GenerateKeyPairAndSign;
    TUsageExamples.GetPublicKeyFromPrivateKey;
    TUsageExamples.RecreatePublicAndPrivateKeyPairsFromByteArray;
    TUsageExamples.RecreatePublicKeyFromXAndYCoordByteArray;
    Readln;
  except
    on E: Exception do
      Writeln(E.ClassName, ': ', E.Message);
  end;

end.




