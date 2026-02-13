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

unit ClpArrayUtilities;

{$I ..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  Math,
  Generics.Defaults,
  ClpCryptoLibTypes;

resourcestring
  SInvalidLength = '%d " > " %d';

type
  TArrayUtilities = class sealed(TObject)

  strict private
    class function GetLength(AFrom, ATo: Int32): Int32; static; inline;

  public

   (* class function AreEqual<T>(const A, B: TCryptoLibGenericArray<T>;
      const AComparer: IEqualityComparer<T> = nil): Boolean; overload; static; *)

    class function AreEqual(const A, B: TCryptoLibByteArray): Boolean; overload; static;
    class function AreEqual(const A, B: TCryptoLibInt32Array): Boolean; overload; static;

    class function Concatenate<T>(const A, B: TCryptoLibGenericArray<T>)
      : TCryptoLibGenericArray<T>; static;

    class function AreAllZeroes(const ABuf: TCryptoLibByteArray; AOff, ALen: Int32)
      : Boolean; static;

    class function GetArrayHashCode(const AData: TCryptoLibByteArray): Int32;
      overload; static;
    class function GetArrayHashCode(const AData: TCryptoLibByteArray;
      AOff, ALen: Int32): Int32; overload; static;

    class function GetArrayHashCode(const AData: TCryptoLibInt32Array): Int32;
      overload; static;

    class function GetArrayHashCode(const AData: TCryptoLibUInt32Array): Int32;
      overload; static;

    class function GetArrayHashCode(const AData: TCryptoLibUInt32Array;
      AOff, ALen: Int32): Int32; overload; static;

    class function GetArrayHashCode(const AData: TCryptoLibUInt64Array;
      AOff, ALen: Int32): Int32; overload; static;

    class function Prepend<T>(const A: TCryptoLibGenericArray<T>; const B: T)
      : TCryptoLibGenericArray<T>; static;

    class function Append<T>(const A: TCryptoLibGenericArray<T>; const B: T)
      : TCryptoLibGenericArray<T>; static;

    class function CopyOf<T>(const AData: TCryptoLibGenericArray<T>; ANewLength: Int32)
      : TCryptoLibGenericArray<T>; static;

    class function CopyOfRange<T>(const AData: TCryptoLibGenericArray<T>;
      AFrom, ATo: Int32): TCryptoLibGenericArray<T>; static;

    class function FixedTimeEquals(const AAr1, AAr2: TCryptoLibByteArray)
      : Boolean; static;

    class procedure Fill<T>(ABuf: TCryptoLibGenericArray<T>; AFrom, ATo: Int32;
      const AFiller: T); static;

    class function Clone<T>(const AData: TCryptoLibGenericArray<T>; const ACloneFunc: TFunc<T, T>): TCryptoLibGenericArray<T>; static;

    class function NoZeroes(const AData: TCryptoLibByteArray): Boolean; static;

   (* class function Contains<T>(const AData: TCryptoLibGenericArray<T>;
      const AValue: T; const AComparer: IEqualityComparer<T> = nil): Boolean; overload; static; *)

    class function Contains(const AData: TCryptoLibInt32Array;
      const AValue: Int32): Boolean; overload; static;

    class function Map<T, TResult>(const AData: TCryptoLibGenericArray<T>;
      const AFunc: TFunc<T, TResult>): TCryptoLibGenericArray<TResult>; static;

    class function ToString<T>(const AData: TCryptoLibGenericArray<T>;
      const AConverter: TFunc<T, String>): String; reintroduce; overload; static;

  end;

implementation

{ TArrayUtilities }

class function TArrayUtilities.GetLength(AFrom, ATo: Int32): Int32;
var
  LNewLength: Int32;
begin
  LNewLength := ATo - AFrom;
  if LNewLength < 0 then
    raise EArgumentCryptoLibException.CreateResFmt(@SInvalidLength, [AFrom, ATo]);
  Result := LNewLength;
end;

class function TArrayUtilities.NoZeroes(const AData: TCryptoLibByteArray): Boolean;
var
  I: Int32;
begin
  Result := True;
  for I := System.Low(AData) to System.High(AData) do
  begin
    if AData[I] = 0 then
    begin
      Result := False;
      Exit;
    end;
  end;
end;

(*
class function TArrayUtilities.AreEqual<T>(const A, B: TCryptoLibGenericArray<T>;
  const AComparer: IEqualityComparer<T>): Boolean;
var
  I: Int32;
  LComparer: IEqualityComparer<T>;
begin
  if System.Length(A) <> System.Length(B) then
    Exit(False);
  if AComparer = nil then
    LComparer := TEqualityComparer<T>.Default
  else
    LComparer := AComparer;
  for I := System.Low(A) to System.High(A) do
    if not LComparer.Equals(A[I], B[I]) then
      Exit(False);
  Result := True;
end; *)

class function TArrayUtilities.AreEqual(const A, B: TCryptoLibByteArray): Boolean;
var
  LLen: Int32;
begin
  LLen := System.Length(A);
  if LLen <> System.Length(B) then
    Exit(False);
  if LLen = 0 then
    Exit(True);
  Result := CompareMem(@A[0], @B[0], LLen * System.SizeOf(Byte));
end;

class function TArrayUtilities.AreEqual(const A, B: TCryptoLibInt32Array): Boolean;
var
  LLen: Int32;
begin
  LLen := System.Length(A);
  if LLen <> System.Length(B) then
    Exit(False);
  if LLen = 0 then
    Exit(True);
  Result := CompareMem(@A[0], @B[0], LLen * System.SizeOf(Int32));
end;

class function TArrayUtilities.Concatenate<T>(const A, B: TCryptoLibGenericArray<T>)
  : TCryptoLibGenericArray<T>;
var
  I, LLenA, LLenB: Int32;
begin
  LLenA := System.Length(A);
  LLenB := System.Length(B);
  System.SetLength(Result, LLenA + LLenB);
  for I := 0 to LLenA - 1 do
    Result[I] := A[I];
  for I := 0 to LLenB - 1 do
    Result[LLenA + I] := B[I];
end;

class function TArrayUtilities.AreAllZeroes(const ABuf: TCryptoLibByteArray;
  AOff, ALen: Int32): Boolean;
var
  LBits: UInt32;
  I: Int32;
begin
  LBits := 0;
  for I := 0 to System.Pred(ALen) do
    LBits := LBits or UInt32(ABuf[AOff + I]);
  Result := LBits = 0;
end;

class function TArrayUtilities.FixedTimeEquals(const AAr1,
  AAr2: TCryptoLibByteArray): Boolean;
var
  I: Int32;
  LDiff: UInt32;
begin
  LDiff := UInt32(System.Length(AAr1)) xor UInt32(System.Length(AAr2));
  I := 0;
  while (I <= System.High(AAr1)) and (I <= System.High(AAr2)) do
  begin
    LDiff := LDiff or (UInt32(AAr1[I] xor AAr2[I]));
    System.Inc(I);
  end;
  Result := LDiff = 0;
end;

class function TArrayUtilities.CopyOf<T>(const AData: TCryptoLibGenericArray<T>;
  ANewLength: Int32): TCryptoLibGenericArray<T>;
var
  I, LCount: Int32;
begin
  if AData = nil then
    Exit(nil);
  System.SetLength(Result, ANewLength);
  LCount := Min(ANewLength, System.Length(AData));
  for I := 0 to LCount - 1 do
    Result[I] := AData[I];
end;

class function TArrayUtilities.CopyOfRange<T>(const AData: TCryptoLibGenericArray<T>;
  AFrom, ATo: Int32): TCryptoLibGenericArray<T>;
var
  I, LNewLength, LCount: Int32;
begin
  if AData = nil then
    Exit(nil);
  LNewLength := GetLength(AFrom, ATo);
  System.SetLength(Result, LNewLength);
  LCount := Min(LNewLength, System.Length(AData) - AFrom);
  for I := 0 to LCount - 1 do
    Result[I] := AData[AFrom + I];
end;

class procedure TArrayUtilities.Fill<T>(ABuf: TCryptoLibGenericArray<T>;
  AFrom, ATo: Int32; const AFiller: T);
var
  I: Int32;
begin
  if ABuf = nil then
    Exit;
  for I := AFrom to ATo - 1 do
    ABuf[I] := AFiller;
end;

class function TArrayUtilities.GetArrayHashCode(const AData: TCryptoLibByteArray): Int32;
var
  I, LHc: Int32;
begin
  if AData = nil then
    Exit(0);
  I := System.Length(AData);
  LHc := I + 1;
  System.Dec(I);
  while I >= 0 do
  begin
    LHc := LHc * 257;
    LHc := LHc xor AData[I];
    System.Dec(I);
  end;
  Result := LHc;
end;

class function TArrayUtilities.GetArrayHashCode(const AData: TCryptoLibByteArray;
  AOff, ALen: Int32): Int32;
var
  I, LHc: Int32;
begin
  if AData = nil then
    Exit(0);
  I := ALen;
  LHc := I + 1;
  System.Dec(I);
  while I >= 0 do
  begin
    LHc := LHc * 257;
    LHc := LHc xor AData[AOff + I];
    System.Dec(I);
  end;
  Result := LHc;
end;

class function TArrayUtilities.GetArrayHashCode(const AData: TCryptoLibInt32Array): Int32;
var
  I, LHc: Int32;
begin
  if AData = nil then
    Exit(0);
  I := System.Length(AData);
  LHc := I + 1;
  System.Dec(I);
  while I >= 0 do
  begin
    LHc := LHc * 257;
    LHc := LHc xor AData[I];
    System.Dec(I);
  end;
  Result := LHc;
end;

class function TArrayUtilities.GetArrayHashCode(const AData: TCryptoLibUInt32Array): Int32;
var
  I, LHc: Int32;
begin
  if AData = nil then
    Exit(0);
  I := System.Length(AData);
  LHc := I + 1;
  System.Dec(I);
  while I >= 0 do
  begin
    LHc := LHc * 257;
    LHc := LHc xor Int32(AData[I]);
    System.Dec(I);
  end;
  Result := LHc;
end;

class function TArrayUtilities.GetArrayHashCode(const AData: TCryptoLibUInt32Array;
  AOff, ALen: Int32): Int32;
var
  I, LHc: Int32;
begin
  if AData = nil then
    Exit(0);
  I := ALen;
  LHc := I + 1;
  System.Dec(I);
  while I >= 0 do
  begin
    LHc := LHc * 257;
    LHc := LHc xor Int32(AData[AOff + I]);
    System.Dec(I);
  end;
  Result := LHc;
end;

class function TArrayUtilities.GetArrayHashCode(const AData: TCryptoLibUInt64Array;
  AOff, ALen: Int32): Int32;
var
  I, LHc: Int32;
  LDi: UInt64;
begin
  if AData = nil then
    Exit(0);
  I := ALen;
  LHc := I + 1;
  System.Dec(I);
  while I >= 0 do
  begin
    LDi := AData[AOff + I];
    LHc := LHc * 257;
    LHc := LHc xor Int32(LDi);
    LHc := LHc * 257;
    LHc := LHc xor Int32(LDi shr 32);
    System.Dec(I);
  end;
  Result := LHc;
end;

class function TArrayUtilities.Prepend<T>(const A: TCryptoLibGenericArray<T>; const B: T)
  : TCryptoLibGenericArray<T>;
var
  I, LLength: Int32;
begin
  if A = nil then
  begin
    System.SetLength(Result, 1);
    Result[0] := B;
    Exit;
  end;
  LLength := System.Length(A);
  System.SetLength(Result, LLength + 1);
  Result[0] := B;
  for I := 0 to LLength - 1 do
    Result[I + 1] := A[I];
end;

class function TArrayUtilities.Append<T>(const A: TCryptoLibGenericArray<T>; const B: T)
  : TCryptoLibGenericArray<T>;
var
  I, LLength: Int32;
begin
  if A = nil then
  begin
    System.SetLength(Result, 1);
    Result[0] := B;
    Exit;
  end;
  LLength := System.Length(A);
  System.SetLength(Result, LLength + 1);
  for I := 0 to LLength - 1 do
    Result[I] := A[I];
  Result[LLength] := B;
end;

class function TArrayUtilities.Clone<T>(const AData: TCryptoLibGenericArray<T>; const ACloneFunc: TFunc<T, T>): TCryptoLibGenericArray<T>;
var
  I: Int32;
begin
  if (AData = nil) or (System.Length(AData) = 0) then
    Exit(nil);
  System.SetLength(Result, System.Length(AData));
  for I := 0 to System.High(AData) do
    Result[I] := ACloneFunc(AData[I]);
end;

(*
class function TArrayUtilities.Contains<T>(const AData: TCryptoLibGenericArray<T>;
  const AValue: T; const AComparer: IEqualityComparer<T>): Boolean;
var
  I: Int32;
  LComparer: IEqualityComparer<T>;
begin
  if (AData = nil) or (System.Length(AData) = 0) then
    Exit(False);
  if AComparer = nil then
    LComparer := TEqualityComparer<T>.Default
  else
    LComparer := AComparer;
  for I := System.Low(AData) to System.High(AData) do
    if LComparer.Equals(AData[I], AValue) then
      Exit(True);
  Result := False;
end; *)

class function TArrayUtilities.Contains(const AData: TCryptoLibInt32Array;
  const AValue: Int32): Boolean;
var
  I: Int32;
begin
  if (AData = nil) or (System.Length(AData) = 0) then
    Exit(False);
  for I := System.Low(AData) to System.High(AData) do
    if AData[I] = AValue then
      Exit(True);
  Result := False;
end;

class function TArrayUtilities.Map<T, TResult>(const AData: TCryptoLibGenericArray<T>;
  const AFunc: TFunc<T, TResult>): TCryptoLibGenericArray<TResult>;
var
  I, LCount: Int32;
begin
  LCount := System.Length(AData);
  System.SetLength(Result, LCount);
  for I := 0 to LCount - 1 do
    Result[I] := AFunc(AData[I]);
end;

class function TArrayUtilities.ToString<T>(const AData: TCryptoLibGenericArray<T>;
  const AConverter: TFunc<T, String>): String;
var
  I, LCount: Int32;
  LSB: TStringBuilder;
begin
  LCount := System.Length(AData);
  if LCount = 0 then
  begin
    Result := '[]';
    Exit;
  end;
  LSB := TStringBuilder.Create;
  try
    LSB.Append('[');
    LSB.Append(AConverter(AData[0]));
    for I := 1 to LCount - 1 do
    begin
      LSB.Append(', ');
      LSB.Append(AConverter(AData[I]));
    end;
    LSB.Append(']');
    Result := LSB.ToString;
  finally
    LSB.Free;
  end;
end;

end.
