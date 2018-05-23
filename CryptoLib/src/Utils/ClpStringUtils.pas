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

unit ClpStringUtils;

{$I ..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  StrUtils,
  ClpBits,
  ClpCryptoLibTypes;

type
  TStringUtils = class sealed(TObject)
  public
    class function GetStringHashCode(const Input: string): Int32; static;
    class function SplitString(const Input: string; Delimiter: Char)
      : TCryptoLibStringArray; static;
    class function BeginsWith(const Input, SubString: string;
      IgnoreCase: Boolean; Offset: Int32 = 1): Boolean; static;

  end;

implementation

{ TStringUtils }

class function TStringUtils.GetStringHashCode(const Input: string): Int32;
var
  LowPoint, HighPoint: Int32;
  LResult: UInt32;
begin
  LResult := 0;
{$IFDEF DELPHIXE3_UP}
  LowPoint := System.Low(Input);
  HighPoint := System.High(Input);
{$ELSE}
  LowPoint := 1;
  HighPoint := System.Length(Input);
{$ENDIF DELPHIXE3_UP}
  while LowPoint <= HighPoint do
  begin
    LResult := TBits.RotateLeft32(LResult, 5);
    LResult := LResult xor UInt32(Input[LowPoint]);
    System.Inc(LowPoint);
  end;
  Result := Int32(LResult);
end;

class function TStringUtils.SplitString(const Input: string; Delimiter: Char)
  : TCryptoLibStringArray;
var
  PosStart, PosDel, SplitPoints, I, LowPoint, HighPoint, Len: Int32;
begin
  Result := Nil;
  if Input <> '' then
  begin
    { Determine the length of the resulting array }
{$IFDEF DELPHIXE3_UP}
    LowPoint := System.Low(Input);
    HighPoint := System.High(Input);
{$ELSE}
    LowPoint := 1;
    HighPoint := System.Length(Input);
{$ENDIF DELPHIXE3_UP}
    SplitPoints := 0;
    for I := LowPoint to HighPoint do
    begin
      if (Delimiter = Input[I]) then
        System.Inc(SplitPoints);
    end;

    System.SetLength(Result, SplitPoints + 1);

    { Split the string and fill the resulting array }

    I := 0;
    Len := System.Length(Delimiter);
    PosStart := 1;
    PosDel := System.Pos(Delimiter, Input);
    while PosDel > 0 do
    begin
      Result[I] := System.Copy(Input, PosStart, PosDel - PosStart);
      PosStart := PosDel + Len;
      PosDel := PosEx(Delimiter, Input, PosStart);
      System.Inc(I);
    end;
    Result[I] := System.Copy(Input, PosStart, System.Length(Input));
  end;
end;

class function TStringUtils.BeginsWith(const Input, SubString: string;
  IgnoreCase: Boolean; Offset: Int32): Boolean;
var
  L: Integer;
  PtrInput, PtrSubString: PChar;
begin
  L := System.Length(SubString);
  Result := L > 0;
  PtrInput := PChar(Input);
  System.Inc(PtrInput, Offset - 1);
  PtrSubString := PChar(SubString);
  if Result then
  begin
    if IgnoreCase then
    begin
      Result := StrLiComp(PtrSubString, PtrInput, L) = 0
    end
    else
    begin
      Result := StrLComp(PtrSubString, PtrInput, L) = 0
    end;
  end;
end;

end.
