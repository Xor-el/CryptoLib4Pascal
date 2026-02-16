unit ClpExampleExplorer;

interface

type
  TExampleExplorer = class
  public
    class procedure Execute;
  end;

implementation

uses
  SysUtils,
  Rtti,
  TypInfo,
  Generics.Collections,
  ClpExampleBase;

class procedure TExampleExplorer.Execute;
var
  Ctx: TRttiContext;
  LType: TRttiType;
  LInst: TRttiInstanceType;
  LCreate: TRttiMethod;
  Examples: TList<TRttiInstanceType>;
  Option: string;
  I, Idx: Integer;
  LExample: IExample;
  N: Integer;
begin
  Examples := TList<TRttiInstanceType>.Create;
  try
    Ctx := TRttiContext.Create;
    for LType in Ctx.GetTypes do
    begin
      if LType is TRttiInstanceType then
      begin
        LInst := TRttiInstanceType(LType);
        if (LInst.MetaclassType <> nil) and LInst.MetaclassType.InheritsFrom(TExampleBase)
          and (LInst.MetaclassType <> TExampleBase) then
        begin
          LCreate := LInst.GetMethod('Create');
          if (LCreate <> nil) and (Length(LCreate.GetParameters) = 0) then
            Examples.Add(LInst);
        end;
      end;
    end;

    if Examples.Count = 0 then
    begin
      Writeln('No example classes found.');
      Exit;
    end;

    while True do
    begin
      Writeln('Choose an example to run (type exit/quit to leave):');
      for N := 0 to Examples.Count - 1 do
        Writeln(Format('  %d: %s', [N, Examples[N].Name]));

      Readln(Option);
      if SameText(Trim(Option), 'exit') or SameText(Trim(Option), 'quit') then
        Break;

      if not TryStrToInt(Trim(Option), I) or (I < 0) or (I >= Examples.Count) then
      begin
        Writeln('Invalid option. Enter a number between 0 and ', Examples.Count - 1, '.');
        Continue;
      end;

      Idx := I;
      try
        LCreate := Examples[Idx].GetMethod('Create');
        if (LCreate <> nil) and Supports(LCreate.Invoke(Examples[Idx].MetaclassType, []).AsObject, IExample, LExample) then
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
  finally
    Examples.Free;
  end;
end;

end.
