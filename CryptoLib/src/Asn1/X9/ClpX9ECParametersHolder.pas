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

unit ClpX9ECParametersHolder;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SyncObjs,
  ClpIX9ECParameters,
  ClpIX9ECParametersHolder;

type
  TX9ECParametersHolder = class abstract(TInterfacedObject,
    IX9ECParametersHolder)

  strict private
    Fparameters: IX9ECParameters;
    function GetParameters: IX9ECParameters; inline;

    class var

      FLock: TCriticalSection;

    class constructor CreateX9ECParametersHolder();
    class destructor DestroyX9ECParametersHolder();

  strict protected
    function CreateParameters(): IX9ECParameters; virtual; abstract;

  public
    property Parameters: IX9ECParameters read GetParameters;

  end;

implementation

{ TX9ECParametersHolder }

class constructor TX9ECParametersHolder.CreateX9ECParametersHolder;
begin
  FLock := TCriticalSection.Create;
end;

class destructor TX9ECParametersHolder.DestroyX9ECParametersHolder;
begin
  FLock.Free;
end;

function TX9ECParametersHolder.GetParameters: IX9ECParameters;
begin
  FLock.Acquire;
  try
    if (Fparameters = Nil) then
    begin
      Fparameters := CreateParameters();
    end;

  finally
    FLock.Release;
  end;
  Result := Fparameters;
end;

end.
