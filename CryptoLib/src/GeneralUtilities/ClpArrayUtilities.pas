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
  ClpCryptoLibTypes;

resourcestring
  SInvalidLength = '%d " > " %d';

type
  TArrayUtilities = class sealed(TObject)
  strict private
    class function GetLength(AFrom, ATo: Int32): Int32; static; inline;

    /// <summary>
    /// Core hash computation shared by all GetArrayHashCode overloads.
    /// Processes ACount bytes starting at AData.
    /// </summary>
    class function HashCore(AData: PByte; ACount: Int32): Int32; static;
  public

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

    /// <summary>
    /// Returns a new array of ANewLength, copying min(ANewLength, Length(AData))
    /// elements from AData. Returns nil if AData is nil.
    /// </summary>
    class function CopyOf<T>(const AData: TCryptoLibGenericArray<T>; ANewLength: Int32)
      : TCryptoLibGenericArray<T>; static;

    /// <summary>
    /// Returns a new array containing AData[AFrom..ATo-1].
    /// Returns nil if AData is nil.
    /// </summary>
    class function CopyOfRange<T>(const AData: TCryptoLibGenericArray<T>;
      AFrom, ATo: Int32): TCryptoLibGenericArray<T>; static;

    /// <summary>
    /// Constant-time comparison of two byte arrays.
    /// Both length and content comparisons are constant-time to avoid
    /// leaking information through timing side channels.
    /// </summary>
    class function FixedTimeEquals(const AAr1, AAr2: TCryptoLibByteArray)
      : Boolean; overload; static;

    /// <summary>
    /// Constant-time comparison of ALen bytes from AA[AOff1] and AB[AOff2].
    /// Caller must ensure offsets and length are within bounds.
    /// </summary>
    class function FixedTimeEquals(ALen: Int32; const AA: TCryptoLibByteArray;
      AOff1: Int32; const AB: TCryptoLibByteArray; AOff2: Int32)
      : Boolean; overload; static;

    class procedure Fill<T>(ABuf: TCryptoLibGenericArray<T>; AFrom, ATo: Int32;
      const AFiller: T); static;

    /// <summary>
    /// Deep-clone an array using ACloneFunc. Returns nil if AData is nil.
    /// If ACloneFunc raises mid-way, already-cloned objects are freed to prevent leaks.
    /// </summary>
    class function Clone<T>(const AData: TCryptoLibGenericArray<T>;
      const ACloneFunc: TFunc<T, T>): TCryptoLibGenericArray<T>; static;

    class function NoZeroes(const AData: TCryptoLibByteArray): Boolean; static;

    class function Contains(const AData: TCryptoLibInt32Array;
      const AValue: Int32): Boolean; static;

    class function Map<T, TResult>(const AData: TCryptoLibGenericArray<T>;
      const AFunc: TFunc<T, TResult>): TCryptoLibGenericArray<TResult>; static;

    class function ToString<T>(const AData: TCryptoLibGenericArray<T>;
      const AConverter: TFunc<T, String>): String; reintroduce; overload; static;

    /// <summary>Reverse array elements in place.</summary>
    class procedure ReverseInPlace<T>(var AArray: TCryptoLibGenericArray<T>); overload; static;

    /// <summary>Reverse the range [AFromIndex, AToIndex) in place.</summary>
    class procedure ReverseInPlace<T>(var AArray: TCryptoLibGenericArray<T>;
      AFromIndex, AToIndex: Int32); overload; static;
  end;

implementation

{ TArrayUtilities }

class function TArrayUtilities.GetLength(AFrom, ATo: Int32): Int32;
begin
  Result := ATo - AFrom;
  if Result < 0 then
    raise EArgumentCryptoLibException.CreateResFmt(@SInvalidLength, [AFrom, ATo]);
end;

class function TArrayUtilities.HashCore(AData: PByte; ACount: Int32): Int32;
var
  LI, LHc: Int32;
begin
  LHc := ACount + 1;
  for LI := ACount - 1 downto 0 do
  begin
    LHc := LHc * 257;
    LHc := LHc xor AData[LI];
  end;
  Result := LHc;
end;

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
  LI, LLenA, LLenB: Int32;
begin
  LLenA := System.Length(A);
  LLenB := System.Length(B);
  System.SetLength(Result, LLenA + LLenB);
  for LI := 0 to LLenA - 1 do
    Result[LI] := A[LI];
  for LI := 0 to LLenB - 1 do
    Result[LLenA + LI] := B[LI];
end;

class function TArrayUtilities.AreAllZeroes(const ABuf: TCryptoLibByteArray;
  AOff, ALen: Int32): Boolean;
var
  LBits: UInt32;
  LI: Int32;
begin
  LBits := 0;
  for LI := 0 to System.Pred(ALen) do
    LBits := LBits or UInt32(ABuf[AOff + LI]);
  Result := LBits = 0;
end;

class function TArrayUtilities.FixedTimeEquals(const AAr1,
  AAr2: TCryptoLibByteArray): Boolean;
var
  LLenA, LLenB, LLen, LI: Int32;
  LDiff: UInt32;
begin
  LLenA := System.Length(AAr1);
  LLenB := System.Length(AAr2);
  // Accumulate length mismatch without branching
  LDiff := UInt32(LLenA xor LLenB);
  // Compare up to the shorter length to stay in bounds
  LLen := LLenA;
  if LLenB < LLen then
    LLen := LLenB;
  for LI := 0 to LLen - 1 do
    LDiff := LDiff or UInt32(AAr1[LI] xor AAr2[LI]);
  Result := LDiff = 0;
end;

class function TArrayUtilities.FixedTimeEquals(ALen: Int32;
  const AA: TCryptoLibByteArray; AOff1: Int32;
  const AB: TCryptoLibByteArray; AOff2: Int32): Boolean;
var
  LI: Int32;
  LDiff: UInt32;
begin
  LDiff := 0;
  for LI := 0 to System.Pred(ALen) do
    LDiff := LDiff or UInt32(AA[AOff1 + LI] xor AB[AOff2 + LI]);
  Result := LDiff = 0;
end;

class function TArrayUtilities.CopyOf<T>(const AData: TCryptoLibGenericArray<T>;
  ANewLength: Int32): TCryptoLibGenericArray<T>;
var
  LI, LCount: Int32;
begin
  if AData = nil then
    Exit(nil);
  System.SetLength(Result, ANewLength);
  LCount := Min(ANewLength, System.Length(AData));
  for LI := 0 to LCount - 1 do
    Result[LI] := AData[LI];
end;

class function TArrayUtilities.CopyOfRange<T>(const AData: TCryptoLibGenericArray<T>;
  AFrom, ATo: Int32): TCryptoLibGenericArray<T>;
var
  LI, LNewLength, LCount: Int32;
begin
  if AData = nil then
    Exit(nil);
  LNewLength := GetLength(AFrom, ATo);
  System.SetLength(Result, LNewLength);
  LCount := Min(LNewLength, System.Length(AData) - AFrom);
  for LI := 0 to LCount - 1 do
    Result[LI] := AData[AFrom + LI];
end;

class procedure TArrayUtilities.Fill<T>(ABuf: TCryptoLibGenericArray<T>;
  AFrom, ATo: Int32; const AFiller: T);
var
  LI: Int32;
begin
  if ABuf = nil then
    Exit;
  for LI := AFrom to ATo - 1 do
    ABuf[LI] := AFiller;
end;

class function TArrayUtilities.GetArrayHashCode(const AData: TCryptoLibByteArray): Int32;
begin
  if AData = nil then
    Exit(0);
  Result := HashCore(@AData[0], System.Length(AData));
end;

class function TArrayUtilities.GetArrayHashCode(const AData: TCryptoLibByteArray;
  AOff, ALen: Int32): Int32;
begin
  if AData = nil then
    Exit(0);
  Result := HashCore(@AData[AOff], ALen);
end;

class function TArrayUtilities.GetArrayHashCode(const AData: TCryptoLibInt32Array): Int32;
begin
  if AData = nil then
    Exit(0);
  Result := HashCore(PByte(@AData[0]), System.Length(AData) * System.SizeOf(Int32));
end;

class function TArrayUtilities.GetArrayHashCode(const AData: TCryptoLibUInt32Array): Int32;
begin
  if AData = nil then
    Exit(0);
  Result := HashCore(PByte(@AData[0]), System.Length(AData) * System.SizeOf(UInt32));
end;

class function TArrayUtilities.GetArrayHashCode(const AData: TCryptoLibUInt32Array;
  AOff, ALen: Int32): Int32;
begin
  if AData = nil then
    Exit(0);
  Result := HashCore(PByte(@AData[AOff]), ALen * System.SizeOf(UInt32));
end;

class function TArrayUtilities.GetArrayHashCode(const AData: TCryptoLibUInt64Array;
  AOff, ALen: Int32): Int32;
begin
  if AData = nil then
    Exit(0);
  Result := HashCore(PByte(@AData[AOff]), ALen * System.SizeOf(UInt64));
end;

class function TArrayUtilities.NoZeroes(const AData: TCryptoLibByteArray): Boolean;
var
  LI: Int32;
begin
  for LI := System.Low(AData) to System.High(AData) do
    if AData[LI] = 0 then
      Exit(False);
  Result := True;
end;

class function TArrayUtilities.Prepend<T>(const A: TCryptoLibGenericArray<T>; const B: T)
  : TCryptoLibGenericArray<T>;
var
  LI, LLength: Int32;
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
  for LI := 0 to LLength - 1 do
    Result[LI + 1] := A[LI];
end;

class function TArrayUtilities.Append<T>(const A: TCryptoLibGenericArray<T>; const B: T)
  : TCryptoLibGenericArray<T>;
var
  LI, LLength: Int32;
begin
  if A = nil then
  begin
    System.SetLength(Result, 1);
    Result[0] := B;
    Exit;
  end;
  LLength := System.Length(A);
  System.SetLength(Result, LLength + 1);
  for LI := 0 to LLength - 1 do
    Result[LI] := A[LI];
  Result[LLength] := B;
end;

class function TArrayUtilities.Clone<T>(const AData: TCryptoLibGenericArray<T>;
  const ACloneFunc: TFunc<T, T>): TCryptoLibGenericArray<T>;
var
  LI, LLen, LDone: Int32;
  LObj: TObject;
begin
  if (AData = nil) or (System.Length(AData) = 0) then
    Exit(nil);
  LLen := System.Length(AData);
  System.SetLength(Result, LLen);
  LDone := 0;
  try
    for LI := 0 to LLen - 1 do
    begin
      Result[LI] := ACloneFunc(AData[LI]);
      Inc(LDone);
    end;
  except
    // On failure, free any successfully cloned objects to prevent leaks
    if GetTypeKind(TypeInfo(T)) = tkClass then
      for LI := 0 to LDone - 1 do
      begin
        LObj := TObject(PPointer(@Result[LI])^);
        if Assigned(LObj) then
          LObj.Free;
      end;
    if LDone > 0 then
      Fill<T>(Result, 0, LDone, Default(T));
    raise;
  end;
end;

class function TArrayUtilities.Contains(const AData: TCryptoLibInt32Array;
  const AValue: Int32): Boolean;
var
  LI: Int32;
begin
  for LI := System.Low(AData) to System.High(AData) do
    if AData[LI] = AValue then
      Exit(True);
  Result := False;
end;

class function TArrayUtilities.Map<T, TResult>(const AData: TCryptoLibGenericArray<T>;
  const AFunc: TFunc<T, TResult>): TCryptoLibGenericArray<TResult>;
var
  LI, LCount: Int32;
begin
  LCount := System.Length(AData);
  System.SetLength(Result, LCount);
  for LI := 0 to LCount - 1 do
    Result[LI] := AFunc(AData[LI]);
end;

class function TArrayUtilities.ToString<T>(const AData: TCryptoLibGenericArray<T>;
  const AConverter: TFunc<T, String>): String;
var
  LI, LCount: Int32;
  LSB: TStringBuilder;
begin
  LCount := System.Length(AData);
  if LCount = 0 then
    Exit('[]');
  LSB := TStringBuilder.Create;
  try
    LSB.Append('[');
    LSB.Append(AConverter(AData[0]));
    for LI := 1 to LCount - 1 do
    begin
      LSB.Append(', ');
      LSB.Append(AConverter(AData[LI]));
    end;
    LSB.Append(']');
    Result := LSB.ToString;
  finally
    LSB.Free;
  end;
end;

class procedure TArrayUtilities.ReverseInPlace<T>(var AArray: TCryptoLibGenericArray<T>);
begin
  ReverseInPlace<T>(AArray, 0, System.Length(AArray));
end;

class procedure TArrayUtilities.ReverseInPlace<T>(var AArray: TCryptoLibGenericArray<T>;
  AFromIndex, AToIndex: Int32);
var
  LLeft, LRight: Int32;
  LTemp: T;
begin
  if (AFromIndex < 0) or (AToIndex > System.Length(AArray)) or (AFromIndex > AToIndex) then
    raise EArgumentCryptoLibException.CreateResFmt(@SInvalidLength, [AFromIndex, AToIndex]);
  LLeft := AFromIndex;
  LRight := AToIndex - 1;
  while LLeft < LRight do
  begin
    LTemp := AArray[LLeft];
    AArray[LLeft] := AArray[LRight];
    AArray[LRight] := LTemp;
    System.Inc(LLeft);
    System.Dec(LRight);
  end;
end;

end.
