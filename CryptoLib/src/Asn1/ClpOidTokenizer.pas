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

unit ClpOidTokenizer;

{$I ..\Include\CryptoLib.inc}

interface

uses
  ClpStringUtilities,
  ClpIOidTokenizer;

type

  /// <summary>
  /// class for breaking up an Oid into it's component tokens
  /// </summary>
  TOidTokenizer = class sealed(TInterfacedObject, IOidTokenizer)

  strict private
  var
    FOid: String;
    FIndex: Int32;

    function GetHasMoreTokens: Boolean; inline;

  public
    constructor Create(const AOid: String);

    function NextToken(): String; inline;

    property HasMoreTokens: Boolean read GetHasMoreTokens;

  end;

implementation

{ TOidTokenizer }

constructor TOidTokenizer.Create(const AOid: String);
begin
  FOid := AOid;
  FIndex := 1;
end;

function TOidTokenizer.GetHasMoreTokens: Boolean;
begin
  Result := FIndex <> 0;
end;

function TOidTokenizer.NextToken: String;
var
  LEnd: Int32;
begin
  if (FIndex = 0) then
  begin
    Result := '';
    Exit;
  end;

  LEnd := TStringUtilities.IndexOf(FOid, '.', FIndex);

  if (LEnd = 0) then
  begin
    Result := TStringUtilities.Substring(FOid, FIndex);
    FIndex := 0;
    Exit;
  end;

  Result := TStringUtilities.Substring(FOid, FIndex, LEnd - FIndex);
  FIndex := LEnd + 1;
end;

end.
