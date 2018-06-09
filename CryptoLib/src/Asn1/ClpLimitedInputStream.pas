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

unit ClpLimitedInputStream;

{$I ..\Include\CryptoLib.inc}

interface

uses
  Classes,
  ClpBaseInputStream;

type
  TLimitedInputStream = class abstract(TBaseInputStream)

  strict private
  var
    F_limit: Int32;
  strict protected
  var
    F_in: TStream;

    procedure SetParentEofDetect(&on: Boolean);

  public
    constructor Create(inStream: TStream; limit: Int32);
    function GetRemaining(): Int32; virtual;

  end;

implementation

uses
  // included here to avoid circular dependency :)
  ClpIndefiniteLengthInputStream;

{ TLimitedInputStream }

constructor TLimitedInputStream.Create(inStream: TStream; limit: Int32);
begin
  Inherited Create();
  F_in := inStream;
  F_limit := limit;
end;

function TLimitedInputStream.GetRemaining: Int32;
begin
  // TODO: maybe one day this can become more accurate
  Result := F_limit;
end;

procedure TLimitedInputStream.SetParentEofDetect(&on: Boolean);
var
  indefiniteLengthInputStream: TIndefiniteLengthInputStream;
begin

  if F_in is TIndefiniteLengthInputStream then
  begin
    indefiniteLengthInputStream := F_in as TIndefiniteLengthInputStream;
    indefiniteLengthInputStream.SetEofOn00(&on);
  end;

end;

end.
