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

unit ClpLogger;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$HINTS OFF}
{$WARNINGS OFF}
{$ENDIF FPC}

uses
  SysUtils;

type
  TLogLevel = (Trace, Debug, Info, Warn, Error, Fatal);

  TEventId = record
  private
    FId: Integer;
    FName: string;

  public
    constructor Create(AId: Integer; const AName: string = '');

    function IsEmpty: Boolean;

    property Id: Integer read FId;
    property Name: string read FName;

    class function Empty: TEventId; static;
  end;

  /// ILogger interface
  ILogger = interface
    ['{A5F8F5E2-25B9-4C5A-9E78-AD52E3A7E8D9}']

    // Core logging
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

  /// ILoggerFactory interface
  ILoggerFactory = interface
    ['{34F7A5B1-9D0C-4DD8-8C6D-6B1E9E8A3A0F}']
    function CreateLogger(const CategoryName: string): ILogger;
    procedure SetMinimumLevel(ALevel: TLogLevel);
    function GetMinimumLevel: TLogLevel;
  end;

implementation

{ TEventId }

constructor TEventId.Create(AId: Integer; const AName: string);
begin
  FId := AId;
  FName := AName;
end;

function TEventId.IsEmpty: Boolean;
begin
  Result := (FId = 0) and (FName = '');
end;

class function TEventId.Empty: TEventId;
begin
  Result := Default(TEventId);
end;

end.


