{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                           Author - Ugochukwu Mmaduekwe                          * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ *                                                                                 * }
{ *                              Acknowledgements:                                  * }
{ *                                                                                 * }
{ *      Thanks to Sphere 10 Software (http://www.sphere10.com/) for sponsoring     * }
{ *                         the development of this library                         * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit ExampleBase;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$HINTS OFF}
{$WARNINGS OFF}
{$ENDIF FPC}

uses
  SysUtils,
  ExampleLogger;

type
  TExampleLogger = class
  private
    class var FDefaultLogger: ILogger;
  public
    class procedure SetDefaultLogger(const ALogger: ILogger);
    class function GetDefaultLogger: ILogger;
  end;

  IExample = interface(IInterface)
    ['{30D86CA2-0F19-4AA6-B106-0A13241BC5AA}']
    procedure Run;
  end;

  TExampleBase = class(TInterfacedObject, IExample)
  protected
    procedure LogWithLineBreak(const AMessage: string);
  public
    function Logger: ILogger;
    procedure Run; virtual; abstract;
  end;

implementation

{ TExampleLogger }

class procedure TExampleLogger.SetDefaultLogger(const ALogger: ILogger);
begin
  FDefaultLogger := ALogger;
end;

class function TExampleLogger.GetDefaultLogger: ILogger;
begin
  Result := FDefaultLogger;
end;

function TExampleBase.Logger: ILogger;
begin
  Result := TExampleLogger.GetDefaultLogger;
end;

procedure TExampleBase.LogWithLineBreak(const AMessage: string);
begin
  Logger.LogInformation('{0}{1}', [AMessage, sLineBreak]);
end;

end.
