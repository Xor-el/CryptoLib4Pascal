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

unit ClpConsoleLogger;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$HINTS OFF}
{$WARNINGS OFF}
{$ENDIF FPC}

uses
  SysUtils,
  ClpLogger;

type
  TConsoleLogger = class(TInterfacedObject, ILogger)
  private
    FCategory: string;
    FMinLevel: TLogLevel;
    FAnsiEnabled: Boolean;

    function LevelToString(ALevel: TLogLevel): string;
    function LevelAnsiColor(ALevel: TLogLevel): string;
    function ResetAnsiColor: string;
    function IsPositionalTemplate(const Template: string): Boolean;
    function FormatMessage(const Template: string; const Args: array of const): string;
    function VarRecToString(const V: TVarRec): string;
    class function BackingObjectFromInterface(const I: IInterface): TObject; static;
    function IsAnsiSupported: Boolean;
  public
    constructor Create(const ACategory: string; AMinLevel: TLogLevel = TLogLevel.Trace);
    class constructor Create;

    procedure Log(ALevel: TLogLevel; const EventId: TEventId; const MessageTemplate: string; const Args: array of const); overload;
    procedure Log(ALevel: TLogLevel; const MessageTemplate: string; const Args: array of const); overload;

    procedure LogException(ALevel: TLogLevel; const EventId: TEventId; const E: Exception; const MessageTemplate: string; const Args: array of const); overload;
    procedure LogException(ALevel: TLogLevel; const E: Exception; const MessageTemplate: string; const Args: array of const); overload;

    procedure LogTrace(const MessageTemplate: string; const Args: array of const); overload;
    procedure LogTrace(const EventId: TEventId; const MessageTemplate: string; const Args: array of const); overload;

    procedure LogDebug(const MessageTemplate: string; const Args: array of const); overload;
    procedure LogDebug(const EventId: TEventId; const MessageTemplate: string; const Args: array of const); overload;

    procedure LogInformation(const MessageTemplate: string; const Args: array of const); overload;
    procedure LogInformation(const EventId: TEventId; const MessageTemplate: string; const Args: array of const); overload;

    procedure LogWarning(const MessageTemplate: string; const Args: array of const); overload;
    procedure LogWarning(const EventId: TEventId; const MessageTemplate: string; const Args: array of const); overload;

    procedure LogError(const MessageTemplate: string; const Args: array of const); overload;
    procedure LogError(const EventId: TEventId; const MessageTemplate: string; const Args: array of const); overload;

    procedure LogCritical(const MessageTemplate: string; const Args: array of const); overload;
    procedure LogCritical(const EventId: TEventId; const MessageTemplate: string; const Args: array of const); overload;

    function IsEnabled(ALevel: TLogLevel): Boolean;
    function Category: string;
  end;

  TConsoleLoggerFactory = class(TInterfacedObject, ILoggerFactory)
  private
    FMinLevel: TLogLevel;
  public
    constructor Create(AMinLevel: TLogLevel = TLogLevel.Trace);
    function CreateLogger(const CategoryName: string): ILogger;
    procedure SetMinimumLevel(ALevel: TLogLevel);
    function GetMinimumLevel: TLogLevel;
  end;

implementation

{$IFDEF MSWINDOWS}
uses
  Windows;

procedure EnableVirtualTerminalProcessing;
var
  hOut: THandle;
  dwMode: DWORD;
begin
  hOut := GetStdHandle(STD_OUTPUT_HANDLE);
  if (hOut = INVALID_HANDLE_VALUE) or not GetConsoleMode(hOut, dwMode) then
    Exit;

  dwMode := dwMode or ENABLE_VIRTUAL_TERMINAL_PROCESSING;
  SetConsoleMode(hOut, dwMode);
end;
{$ENDIF}

{ TConsoleLogger }

class constructor TConsoleLogger.Create;
begin
  {$IFDEF MSWINDOWS}
  EnableVirtualTerminalProcessing;
  {$ENDIF}
end;

constructor TConsoleLogger.Create(const ACategory: string; AMinLevel: TLogLevel);
begin
  inherited Create;
  FCategory := ACategory;
  FMinLevel := AMinLevel;
  FAnsiEnabled := IsAnsiSupported;
end;

function TConsoleLogger.IsAnsiSupported: Boolean;
{$IFDEF MSWINDOWS}
var
  hOut: THandle;
  dwMode: DWORD;
begin
  hOut := GetStdHandle(STD_OUTPUT_HANDLE);
  if (hOut = INVALID_HANDLE_VALUE) or not GetConsoleMode(hOut, dwMode) then
    Exit(False);
  Result := (dwMode and ENABLE_VIRTUAL_TERMINAL_PROCESSING) <> 0;
end;
{$ELSE}
begin
  Result := True;
end;
{$ENDIF}

function TConsoleLogger.Category: string;
begin
  Result := FCategory;
end;

function TConsoleLogger.IsEnabled(ALevel: TLogLevel): Boolean;
begin
  Result := Ord(ALevel) >= Ord(FMinLevel);
end;

function TConsoleLogger.LevelToString(ALevel: TLogLevel): string;
const
  Names: array[TLogLevel] of string = ('TRACE', 'DEBUG', 'INFO', 'WARN', 'ERROR', 'FATAL');
begin
  Result := Names[ALevel];
end;

function TConsoleLogger.LevelAnsiColor(ALevel: TLogLevel): string;
begin
  if not FAnsiEnabled then Exit('');
  case ALevel of
    TLogLevel.Trace: Result := #27'[37m';
    TLogLevel.Debug: Result := #27'[36m';
    TLogLevel.Info:  Result := #27'[32m';
    TLogLevel.Warn:  Result := #27'[33m';
    TLogLevel.Error: Result := #27'[31m';
    TLogLevel.Fatal: Result := #27'[35m';
  else
    Result := #27'[0m';
  end;
end;

function TConsoleLogger.ResetAnsiColor: string;
begin
  if not FAnsiEnabled then Exit('');
  Result := #27'[0m';
end;

function TConsoleLogger.IsPositionalTemplate(const Template: string): Boolean;
var
  i, L: Integer;
begin
  Result := False;
  L := Length(Template);
  if L < 2 then Exit;
  for i := 1 to L - 1 do
    if Template[i] = '{' then
      if CharInSet(Template[i + 1], ['0'..'9']) then
      begin
        Result := True;
        Exit;
      end;
end;

function TConsoleLogger.VarRecToString(const V: TVarRec): string;
var
  Obj: TObject;
  IntfObj: TObject;
begin
  case V.VType of
    vtInteger:       Result := IntToStr(V.VInteger);
    vtInt64:         Result := IntToStr(V.VInt64^);
    vtBoolean:       Result := BoolToStr(V.VBoolean, True);
    vtChar:          Result := string(V.VChar);
    vtWideChar:      Result := V.VWideChar;
    vtExtended:      Result := FloatToStr(V.VExtended^);
    vtString:        Result := string(V.VString^);
    vtPChar:         Result := string(V.VPChar);
    vtPWideChar:     Result := string(V.VPWideChar);
    vtAnsiString:    Result := string(AnsiString(V.VAnsiString));
    vtUnicodeString: Result := string(V.VUnicodeString);
    vtObject:
      begin
        Obj := V.VObject;
        if Assigned(Obj) then
          Result := Format('%s(%p)', [Obj.ClassName, Pointer(Obj)])
        else
          Result := 'nil';
      end;
    vtInterface:
      begin
        IntfObj := BackingObjectFromInterface(IInterface(V.VInterface));
        if Assigned(IntfObj) then
          Result := Format('%s(%p)', [IntfObj.ClassName, Pointer(IntfObj)])
        else
          Result := Format('<interface %p>', [Pointer(V.VInterface)]);
      end;
  else
    Result := '<unknown>';
  end;
end;

class function TConsoleLogger.BackingObjectFromInterface(const I: IInterface): TObject;
var
  Unknown: IInterface;
begin
  Result := nil;
  if I = nil then Exit;
  if I.QueryInterface(IInterface, Unknown) = S_OK then
    if TObject(Unknown) is TObject then
      Result := TObject(Unknown);
end;

function TConsoleLogger.FormatMessage(const Template: string; const Args: array of const): string;
var
  I: Integer;
  S: string;
begin
  S := Template;
  if IsPositionalTemplate(S) then
  begin
    for I := High(Args) downto 0 do
      S := StringReplace(S, '{' + I.ToString + '}', VarRecToString(Args[I]), [rfReplaceAll]);
    Result := S;
    Exit;
  end;

  if Length(Args) > 0 then
    Result := Format(S, Args)
  else
    Result := S;
end;

procedure TConsoleLogger.Log(ALevel: TLogLevel; const MessageTemplate: string; const Args: array of const);
begin
  Log(ALevel, TEventId.Empty, MessageTemplate, Args);
end;

procedure TConsoleLogger.Log(ALevel: TLogLevel; const EventId: TEventId;
  const MessageTemplate: string; const Args: array of const);
const
  DIM_ANSI = #27'[90m';
var
  Msg, LevelStr, DateStr: string;
  Dim, Color, Reset: string;
  Prefix, EventPart, CategoryPart, CategoryWithColon: string;
begin
  if not IsEnabled(ALevel) then Exit;

  Msg      := FormatMessage(MessageTemplate, Args);
  LevelStr := LevelToString(ALevel);
  DateStr  := FormatDateTime('yyyy-mm-dd hh:nn:ss.zzz', Now);

  // Style tokens collapse to empty when ANSI is disabled
  if FAnsiEnabled then
  begin
    Dim   := DIM_ANSI;
    Color := LevelAnsiColor(ALevel);
    Reset := ResetAnsiColor;
  end
  else
  begin
    Dim := '';
    Color := '';
    Reset := '';
  end;

  // Category (optional)
  if FCategory <> '' then
    CategoryPart := Format('%s[%s]%s', [Dim, FCategory, Reset])
  else
    CategoryPart := '';

  // Prefix: date/time and [LEVEL] (brackets dimmed, level colored)
  Prefix := Format('%s%s %s[%s%s%s%s] ', [Dim, DateStr, Dim, Color, LevelStr, Reset, Dim]);

  // Event id (optional)
  if not EventId.IsEmpty then
    EventPart := Format('(%s%d:%s%s) ', [Dim, EventId.Id, EventId.Name, Dim])
  else
    EventPart := '';

  // Category + colon (optional; colon is dimmed if ANSI)
  if CategoryPart <> '' then
    CategoryWithColon := Format('%s%s: ', [CategoryPart, Dim])
  else
    CategoryWithColon := '';

  // Final line (ensure we reset styles before the message)
  Writeln(Format('%s%s%s%s%s', [Prefix, EventPart, CategoryWithColon, Reset, Msg]));
end;

procedure TConsoleLogger.LogException(ALevel: TLogLevel; const E: Exception; const MessageTemplate: string; const Args: array of const);
begin
  LogException(ALevel, TEventId.Empty, E, MessageTemplate, Args);
end;

procedure TConsoleLogger.LogException(ALevel: TLogLevel; const EventId: TEventId; const E: Exception; const MessageTemplate: string; const Args: array of const);
var
  FullMsg: string;
begin
  FullMsg := FormatMessage(MessageTemplate, Args) + sLineBreak + '  Exception: ' + E.ClassName + ' - ' + E.Message;
  Log(ALevel, EventId, FullMsg, []);
end;

procedure TConsoleLogger.LogTrace(const MessageTemplate: string; const Args: array of const);
begin
  Log(TLogLevel.Trace, MessageTemplate, Args);
end;

procedure TConsoleLogger.LogTrace(const EventId: TEventId; const MessageTemplate: string; const Args: array of const);
begin
  Log(TLogLevel.Trace, EventId, MessageTemplate, Args);
end;

procedure TConsoleLogger.LogDebug(const MessageTemplate: string; const Args: array of const);
begin
  Log(TLogLevel.Debug, MessageTemplate, Args);
end;

procedure TConsoleLogger.LogDebug(const EventId: TEventId; const MessageTemplate: string; const Args: array of const);
begin
  Log(TLogLevel.Debug, EventId, MessageTemplate, Args);
end;

procedure TConsoleLogger.LogInformation(const MessageTemplate: string; const Args: array of const);
begin
  Log(TLogLevel.Info, MessageTemplate, Args);
end;

procedure TConsoleLogger.LogInformation(const EventId: TEventId; const MessageTemplate: string; const Args: array of const);
begin
  Log(TLogLevel.Info, EventId, MessageTemplate, Args);
end;

procedure TConsoleLogger.LogWarning(const MessageTemplate: string; const Args: array of const);
begin
  Log(TLogLevel.Warn, MessageTemplate, Args);
end;

procedure TConsoleLogger.LogWarning(const EventId: TEventId; const MessageTemplate: string; const Args: array of const);
begin
  Log(TLogLevel.Warn, EventId, MessageTemplate, Args);
end;

procedure TConsoleLogger.LogError(const MessageTemplate: string; const Args: array of const);
begin
  Log(TLogLevel.Error, MessageTemplate, Args);
end;

procedure TConsoleLogger.LogError(const EventId: TEventId; const MessageTemplate: string; const Args: array of const);
begin
  Log(TLogLevel.Error, EventId, MessageTemplate, Args);
end;

procedure TConsoleLogger.LogCritical(const MessageTemplate: string; const Args: array of const);
begin
  Log(TLogLevel.Fatal, MessageTemplate, Args);
end;

procedure TConsoleLogger.LogCritical(const EventId: TEventId; const MessageTemplate: string; const Args: array of const);
begin
  Log(TLogLevel.Fatal, EventId, MessageTemplate, Args);
end;

{ TConsoleLoggerFactory }

constructor TConsoleLoggerFactory.Create(AMinLevel: TLogLevel);
begin
  inherited Create;
  FMinLevel := AMinLevel;
end;

function TConsoleLoggerFactory.CreateLogger(const CategoryName: string): ILogger;
begin
  Result := TConsoleLogger.Create(CategoryName, FMinLevel);
end;

procedure TConsoleLoggerFactory.SetMinimumLevel(ALevel: TLogLevel);
begin
  FMinLevel := ALevel;
end;

function TConsoleLoggerFactory.GetMinimumLevel: TLogLevel;
begin
  Result := FMinLevel;
end;

end.


