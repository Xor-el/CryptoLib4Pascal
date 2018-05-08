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

unit ClpStringHelper;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  StrUtils,
  ClpBits,
  ClpCryptoLibTypes;

type
  TStringHelper = record helper for
    String public
    function GetHashCode: Int32;
    function SplitString(Delimiter: Char): TCryptoLibStringArray;
    function BeginsWith(const Value: string; IgnoreCase: Boolean): Boolean;

  end;

implementation

{ TStringHelper }

function TStringHelper.GetHashCode: Int32;
var
  temp: string;
  I, Top: UInt32;
  LResult: UInt32;
begin
  temp := Self;
  temp := AnsiUpperCase(temp);

  LResult := 0;
{$IFDEF DELPHIXE3_UP}
  I := System.Low(temp);
  Top := System.High(temp);
{$ELSE}
  I := 1;
  Top := System.Length(temp);
{$ENDIF DELPHIXE3_UP}
  while I <= Top do
  begin
    LResult := TBits.RotateLeft32(LResult, 5);
    LResult := LResult xor UInt32(temp[I]);
    System.Inc(I);
  end;
  Result := Int32(LResult);
end;

function TStringHelper.SplitString(Delimiter: Char): TCryptoLibStringArray;
var
  PosStart, PosDel, SplitPoints, I, Len: Int32;
  S: string;
begin
  Result := Nil;
  S := Self;
  if S <> '' then
  begin
    { Determine the length of the resulting array }
    SplitPoints := 0;
    for I := 1 to System.Length(S) do
    begin
      if (Delimiter = S[I]) then
        System.Inc(SplitPoints);
    end;

    System.SetLength(Result, SplitPoints + 1);

    { Split the string and fill the resulting array }

    I := 0;
    Len := System.Length(Delimiter);
    PosStart := 1;
    PosDel := System.Pos(Delimiter, S);
    while PosDel > 0 do
    begin
      Result[I] := System.Copy(S, PosStart, PosDel - PosStart);
      PosStart := PosDel + Len;
      PosDel := PosEx(Delimiter, S, PosStart);
      System.Inc(I);
    end;
    Result[I] := System.Copy(S, PosStart, System.Length(S));
  end;
end;

function TStringHelper.BeginsWith(const Value: string;
  IgnoreCase: Boolean): Boolean;
var
  L: Integer;
begin
  L := System.Length(Value);
  Result := L > 0;
  if Result then
  begin
    if IgnoreCase then
    begin
      Result := StrLiComp(PChar(Value), PChar(Self), L) = 0
    end
    else
    begin
      Result := StrLComp(PChar(Value), PChar(Self), L) = 0
    end;
  end;
end;

end.
