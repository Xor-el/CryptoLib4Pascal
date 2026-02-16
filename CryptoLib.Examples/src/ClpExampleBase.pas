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

unit ClpExampleBase;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  ClpLogger;

type
  IExample = interface(IInterface)
    ['{30D86CA2-0F19-4AA6-B106-0A13241BC5AA}']
    procedure Run;
  end;

  TExampleBase = class(TInterfacedObject, IExample)
  public
    function Logger: ILogger;
    procedure Run; virtual; abstract;
  end;

implementation

function TExampleBase.Logger: ILogger;
begin
  Result := TClpLogger.GetDefaultLogger;
end;

end.
