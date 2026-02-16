unit ClpLogger;

interface

type
  TLogLevel = (Trace, Debug, Info, Warn, Error, Fatal);

  ILogger = interface(IInterface)
    ['{E9BD7306-A6CD-49FA-88C6-8460FBB29E37}']
    procedure Log(ALevel: TLogLevel; const AMsg: string);
    procedure LogTrace(const AMsg: string);
    procedure LogDebug(const AMsg: string);
    procedure LogInformation(const AMsg: string);
    procedure LogWarning(const AMsg: string);
    procedure LogError(const AMsg: string);
    procedure LogCritical(const AMsg: string);
    function IsEnabled(ALevel: TLogLevel): Boolean;
  end;

  TClpLogger = class
  private
    class var FDefaultLogger: ILogger;
  public
    class procedure SetDefaultLogger(const ALogger: ILogger);
    class function GetDefaultLogger: ILogger;
  end;

implementation

{ TClpLogger }

class procedure TClpLogger.SetDefaultLogger(const ALogger: ILogger);
begin
  FDefaultLogger := ALogger;
end;

class function TClpLogger.GetDefaultLogger: ILogger;
begin
  Result := FDefaultLogger;
end;

end.
