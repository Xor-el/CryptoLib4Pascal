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

unit ClpX509NameTokenizer;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpCryptoLibTypes,
  ClpIX509NameTokenizer;

type
  /// <summary>
  /// Class for breaking up an X500 Name into its component tokens, ala java.util.StringTokenizer.
  /// </summary>
  TX509NameTokenizer = class sealed(TInterfacedObject, IX509NameTokenizer)

  strict private
  var
    FValue: String;
    FSeparator: Char;
    FIndex: Int32;

  public
    constructor Create(const AOid: String); overload;
    constructor Create(const AOid: String; ASeparator: Char); overload;

    function HasMoreTokens: Boolean;
    function NextToken: String;

  end;

implementation

{ TX509NameTokenizer }

constructor TX509NameTokenizer.Create(const AOid: String);
begin
  Create(AOid, ',');
end;

constructor TX509NameTokenizer.Create(const AOid: String; ASeparator: Char);
begin
  inherited Create();
  if AOid = '' then
    raise EArgumentNilCryptoLibException.Create('oid');
  if (ASeparator = '"') or (ASeparator = '\') then
    raise EArgumentCryptoLibException.Create('reserved separator character');

  FValue := AOid;
  FSeparator := ASeparator;
  if System.Length(AOid) < 1 then
    FIndex := 0
  else
    FIndex := -1;
end;

function TX509NameTokenizer.HasMoreTokens: Boolean;
begin
  Result := FIndex < System.Length(FValue);
end;

function TX509NameTokenizer.NextToken: String;
var
  LQuoted, LEscaped: Boolean;
  LBeginIndex: Int32;
  LC: Char;
begin
  if FIndex >= System.Length(FValue) then
  begin
    Result := '';
    Exit;
  end;

  LQuoted := False;
  LEscaped := False;
  LBeginIndex := FIndex + 2;

  // increments first, then checks
  // This means: increment m_index, then check if less than Length, then enter loop
  // Equivalent: increment first, then check in while condition
  System.Inc(FIndex); // Increment first
  while FIndex < System.Length(FValue) do
  begin
    LC := FValue[FIndex + 1];

    if LEscaped then
    begin
      LEscaped := False;
    end
    else if LC = '"' then
    begin
      LQuoted := not LQuoted;
    end
    else if LQuoted then
    begin
      // Continue in quoted mode
    end
    else if LC = '\' then
    begin
      LEscaped := True;
    end
    else if LC = FSeparator then
    begin
      Result := System.Copy(FValue, LBeginIndex, FIndex - (LBeginIndex - 1));
      Exit;
    end;

    System.Inc(FIndex); // Increment for next iteration
  end;

  if LEscaped or LQuoted then
    raise EArgumentCryptoLibException.Create('badly formatted directory string');

  Result := System.Copy(FValue, LBeginIndex, FIndex - (LBeginIndex - 1));
end;

end.
