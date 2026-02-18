{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                Copyright (c) 2018 - 20XX Ugochukwu Mmaduekwe                    * }
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

type
  TLogLevel = (Trace, Debug, Info, Warn, Error, Fatal);

  ILogger = interface(IInterface)
    ['{730BF179-AC3E-4382-B810-315BC32A2F99}']
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
