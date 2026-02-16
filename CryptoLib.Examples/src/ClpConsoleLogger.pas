unit ClpConsoleLogger;

interface

uses
  SysUtils,
  ClpLogger;

type
  TConsoleLogger = class(TInterfacedObject, ILogger)
  private
    FCategory: string;
    FMinLevel: TLogLevel;
    function LevelToString(ALevel: TLogLevel): string;
  public
    constructor Create(const ACategory: string = ''; AMinLevel: TLogLevel = TLogLevel.Trace);
    procedure Log(ALevel: TLogLevel; const AMsg: string);
    procedure LogTrace(const AMsg: string);
    procedure LogDebug(const AMsg: string);
    procedure LogInformation(const AMsg: string);
    procedure LogWarning(const AMsg: string);
    procedure LogError(const AMsg: string);
    procedure LogCritical(const AMsg: string);
    function IsEnabled(ALevel: TLogLevel): Boolean;
  end;

implementation

const
  LevelNames: array[TLogLevel] of string = ('TRACE', 'DEBUG', 'INFO', 'WARN', 'ERROR', 'FATAL');

{ TConsoleLogger }

constructor TConsoleLogger.Create(const ACategory: string; AMinLevel: TLogLevel);
begin
  inherited Create;
  FCategory := ACategory;
  FMinLevel := AMinLevel;
end;

function TConsoleLogger.LevelToString(ALevel: TLogLevel): string;
begin
  Result := LevelNames[ALevel];
end;

function TConsoleLogger.IsEnabled(ALevel: TLogLevel): Boolean;
begin
  Result := Ord(ALevel) >= Ord(FMinLevel);
end;

procedure TConsoleLogger.Log(ALevel: TLogLevel; const AMsg: string);
var
  Prefix, CategoryPart, Line: string;
begin
  if not IsEnabled(ALevel) then
    Exit;
  Prefix := FormatDateTime('yyyy-mm-dd hh:nn:ss.zzz', Now) + ' [' + LevelToString(ALevel) + '] ';
  if FCategory <> '' then
    CategoryPart := '[' + FCategory + ']: '
  else
    CategoryPart := '';
  Line := Prefix + CategoryPart + AMsg;
  Writeln(Line);
end;

procedure TConsoleLogger.LogTrace(const AMsg: string);
begin
  Log(TLogLevel.Trace, AMsg);
end;

procedure TConsoleLogger.LogDebug(const AMsg: string);
begin
  Log(TLogLevel.Debug, AMsg);
end;

procedure TConsoleLogger.LogInformation(const AMsg: string);
begin
  Log(TLogLevel.Info, AMsg);
end;

procedure TConsoleLogger.LogWarning(const AMsg: string);
begin
  Log(TLogLevel.Warn, AMsg);
end;

procedure TConsoleLogger.LogError(const AMsg: string);
begin
  Log(TLogLevel.Error, AMsg);
end;

procedure TConsoleLogger.LogCritical(const AMsg: string);
begin
  Log(TLogLevel.Fatal, AMsg);
end;

end.
