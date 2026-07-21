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

unit ClpArrayUtilities;

{$I ..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  Math,
  ClpCryptoLibTypes,
  ClpCryptoLibExceptions;

resourcestring
  SInvalidLength = 'length %d exceeds %d';
  SBufferCannotBeNil = 'buffer cannot be nil';
  SInvalidBufferSegment = 'invalid offset or length for buffer';

type
  TArrayUtilities = class sealed(TObject)
  strict private
    class function GetLength(AFrom, ATo: Int32): Int32; static; inline;

    /// <summary>
    /// Core hash computation shared by all GetArrayHashCode overloads.
    /// Processes ACount bytes starting at AData.
    /// </summary>
    class function HashCore(AData: PByte; ACount: Int32): Int32; static;

    // Per-element fill shared by Fill<T> and the typed Fill fallbacks.
    // Callers validate ABuf / range first; the loop assumes AFrom < ATo.
    class procedure FillCore<T>(ABuf: TCryptoLibGenericArray<T>;
      AFrom, ATo: Int32; const AFiller: T); static;
  public

    class function AreEqual(const A, B: TCryptoLibByteArray): Boolean; overload; static;
    /// <summary>
    /// Lexicographic order: the first differing byte decides, otherwise the shorter array sorts
    /// first. Matches the usual array-compare contract.
    /// </summary>
    /// <remarks>
    /// NOT constant time - for ordering only, never for comparing secrets (use FixedTimeEquals).
    /// </remarks>
    class function LexicographicCompare(const A, B: TCryptoLibByteArray): Int32; static;
    class function AreEqual(const A, B: TCryptoLibInt32Array): Boolean; overload; static;

    class function Concatenate<T>(const AArrays: TCryptoLibMatrixGenericArray<T>)
      : TCryptoLibGenericArray<T>; static;

    class function AreAllZeroes(const ABuf: TCryptoLibByteArray; AOff, ALen: Int32)
      : Boolean; static;

    class procedure ValidateBuffer(const ABuf: TCryptoLibByteArray); static;
    class procedure ValidateSegment(const ABuf: TCryptoLibByteArray;
      AOffset, ALength: Int32); static;

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
      const AFiller: T); overload; static;

    class procedure Fill(const ABuf: TCryptoLibByteArray; AFrom, ATo: Int32;
      AFiller: Byte); overload; static; inline;
    class procedure Fill(const ABuf: TCryptoLibUInt32Array; AFrom, ATo: Int32;
      AFiller: UInt32); overload; static; inline;
    class procedure Fill(const ABuf: TCryptoLibUInt64Array; AFrom, ATo: Int32;
      AFiller: UInt64); overload; static; inline;
    class procedure Fill(const ABuf: TCryptoLibInt32Array; AFrom, ATo: Int32;
      AFiller: Int32); overload; static; inline;

    /// <summary>
    /// Grow ABuf's capacity to at least ANeeded by doubling; never shrinks.
    /// </summary>
    class procedure EnsureCapacity(var ABuf: TCryptoLibByteArray;
      ANeeded: Int32); static;

    /// <summary>
    /// Grow ABuf if needed, write at index ALen, and advance ALen by the number
    /// of bytes written.
    /// </summary>
    class procedure AppendTo(var ABuf: TCryptoLibByteArray; var ALen: Int32;
      AValue: Byte); overload; static;
    class procedure AppendTo(var ABuf: TCryptoLibByteArray; var ALen: Int32;
      const ASrc: TCryptoLibByteArray; AOff, ACount: Int32); overload; static;

    /// <summary>
    /// Deep-clone an array using ACloneFunc. Returns nil if AData is nil.
    /// If ACloneFunc raises mid-way, already-cloned objects are freed to prevent leaks.
    /// </summary>
    class function Clone<T>(const AData: TCryptoLibGenericArray<T>;
      const ACloneFunc: TCryptoLibFunc<T, T>): TCryptoLibGenericArray<T>; static;

    class function NoZeroes(const AData: TCryptoLibByteArray): Boolean; static;

    class function Contains(const AData: TCryptoLibInt32Array;
      const AValue: Int32): Boolean; static;

    class function Map<T, TResult>(const AData: TCryptoLibGenericArray<T>;
      const AFunc: TCryptoLibFunc<T, TResult>): TCryptoLibGenericArray<TResult>; static;

    class function ToString<T>(const AData: TCryptoLibGenericArray<T>;
      const AConverter: TCryptoLibFunc<T, String>): String; static;

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

class function TArrayUtilities.LexicographicCompare(const A, B: TCryptoLibByteArray): Int32;
var
  LIdx, LLenA, LLenB, LCommon: Int32;
begin
  LLenA := System.Length(A);
  LLenB := System.Length(B);

  if LLenA < LLenB then
    LCommon := LLenA
  else
    LCommon := LLenB;

  // the first differing byte decides, regardless of the lengths
  for LIdx := 0 to LCommon - 1 do
  begin
    if A[LIdx] <> B[LIdx] then
    begin
      if A[LIdx] < B[LIdx] then
        Result := -1
      else
        Result := 1;
      Exit;
    end;
  end;

  // a common prefix: the shorter array sorts first
  if LLenA < LLenB then
    Result := -1
  else if LLenA > LLenB then
    Result := 1
  else
    Result := 0;
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

class function TArrayUtilities.Concatenate<T>(const AArrays: TCryptoLibMatrixGenericArray<T>)
  : TCryptoLibGenericArray<T>;
var
  LI, LJ, LTotalLen, LOffset: Int32;
begin
  LTotalLen := 0;
  for LI := 0 to System.High(AArrays) do
    Inc(LTotalLen, System.Length(AArrays[LI]));

  System.SetLength(Result, LTotalLen);

  LOffset := 0;
  for LI := 0 to System.High(AArrays) do
  begin
    for LJ := 0 to System.Length(AArrays[LI]) - 1 do
      Result[LOffset + LJ] := AArrays[LI][LJ];
    Inc(LOffset, System.Length(AArrays[LI]));
  end;
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

class procedure TArrayUtilities.ValidateBuffer(const ABuf: TCryptoLibByteArray);
begin
  if ABuf = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SBufferCannotBeNil);
end;

class procedure TArrayUtilities.ValidateSegment(const ABuf: TCryptoLibByteArray;
  AOffset, ALength: Int32);
var
  LLen: Int32;
  LEnd: Int64;
begin
  if (AOffset < 0) or (ALength < 0) then
    raise EArgumentOutOfRangeCryptoLibException.CreateRes(@SInvalidBufferSegment);
  if ABuf = nil then
  begin
    if ALength > 0 then
      raise EArgumentNilCryptoLibException.CreateRes(@SBufferCannotBeNil);
    if AOffset <> 0 then
      raise EArgumentOutOfRangeCryptoLibException.CreateRes(@SInvalidBufferSegment);
    Exit;
  end;
  LLen := System.Length(ABuf);
  LEnd := Int64(AOffset) + Int64(ALength);
  if LEnd > LLen then
    raise EArgumentOutOfRangeCryptoLibException.CreateRes(@SInvalidBufferSegment);
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

class procedure TArrayUtilities.FillCore<T>(ABuf: TCryptoLibGenericArray<T>;
  AFrom, ATo: Int32; const AFiller: T);
begin
  while AFrom < ATo do
  begin
    ABuf[AFrom] := AFiller;
    Inc(AFrom);
  end;
end;

class procedure TArrayUtilities.Fill<T>(ABuf: TCryptoLibGenericArray<T>;
  AFrom, ATo: Int32; const AFiller: T);
begin
  if (ABuf = nil) or (ATo <= AFrom) then
    Exit;
  FillCore<T>(ABuf, AFrom, ATo, AFiller);
end;

class procedure TArrayUtilities.Fill(const ABuf: TCryptoLibByteArray;
  AFrom, ATo: Int32; AFiller: Byte);
begin
  if (ABuf <> nil) and (ATo > AFrom) then
    System.FillChar(ABuf[AFrom], ATo - AFrom, AFiller);
end;

class procedure TArrayUtilities.Fill(const ABuf: TCryptoLibUInt32Array;
  AFrom, ATo: Int32; AFiller: UInt32);
begin
  if (ABuf = nil) or (ATo <= AFrom) then
    Exit;
{$IFDEF FPC}
  System.FillDWord(ABuf[AFrom], ATo - AFrom, AFiller);
{$ELSE}
  FillCore<UInt32>(ABuf, AFrom, ATo, AFiller);
{$ENDIF FPC}
end;

class procedure TArrayUtilities.Fill(const ABuf: TCryptoLibUInt64Array;
  AFrom, ATo: Int32; AFiller: UInt64);
begin
  if (ABuf = nil) or (ATo <= AFrom) then
    Exit;
{$IFDEF FPC}
  System.FillQWord(ABuf[AFrom], ATo - AFrom, AFiller);
{$ELSE}
  FillCore<UInt64>(ABuf, AFrom, ATo, AFiller);
{$ENDIF FPC}
end;

class procedure TArrayUtilities.Fill(const ABuf: TCryptoLibInt32Array;
  AFrom, ATo: Int32; AFiller: Int32);
begin
  if (ABuf = nil) or (ATo <= AFrom) then
    Exit;
{$IFDEF FPC}
  System.FillDWord(ABuf[AFrom], ATo - AFrom, UInt32(AFiller));
{$ELSE}
  FillCore<Int32>(ABuf, AFrom, ATo, AFiller);
{$ENDIF FPC}
end;

class procedure TArrayUtilities.EnsureCapacity(var ABuf: TCryptoLibByteArray;
  ANeeded: Int32);
var
  LCap: Int32;
begin
  LCap := System.Length(ABuf);
  if ANeeded <= LCap then
    Exit;
  if LCap = 0 then
    LCap := 64;
  while (LCap < ANeeded) and (LCap > 0) do
    LCap := LCap * 2;
  if LCap < ANeeded then // Int32 overflow guard for very large packets
    LCap := ANeeded;
  System.SetLength(ABuf, LCap);
end;

class procedure TArrayUtilities.AppendTo(var ABuf: TCryptoLibByteArray;
  var ALen: Int32; AValue: Byte);
begin
  EnsureCapacity(ABuf, ALen + 1);
  ABuf[ALen] := AValue;
  System.Inc(ALen);
end;

class procedure TArrayUtilities.AppendTo(var ABuf: TCryptoLibByteArray;
  var ALen: Int32; const ASrc: TCryptoLibByteArray; AOff, ACount: Int32);
begin
  if ACount <= 0 then
    Exit;
  EnsureCapacity(ABuf, ALen + ACount);
  System.Move(ASrc[AOff], ABuf[ALen], ACount);
  System.Inc(ALen, ACount);
end;

class function TArrayUtilities.GetArrayHashCode(const AData: TCryptoLibByteArray): Int32;
begin
  if AData = nil then
    Exit(0);
  Result := HashCore(PByte(AData), System.Length(AData));
end;

class function TArrayUtilities.GetArrayHashCode(const AData: TCryptoLibByteArray;
  AOff, ALen: Int32): Int32;
begin
  if AData = nil then
    Exit(0);
  Result := HashCore(PByte(AData) + AOff, ALen);
end;

class function TArrayUtilities.GetArrayHashCode(const AData: TCryptoLibInt32Array): Int32;
begin
  if AData = nil then
    Exit(0);
  Result := HashCore(PByte(PInteger(AData)), System.Length(AData) * System.SizeOf(Int32));
end;

class function TArrayUtilities.GetArrayHashCode(const AData: TCryptoLibUInt32Array): Int32;
begin
  if AData = nil then
    Exit(0);
  Result := HashCore(PByte(PCardinal(AData)), System.Length(AData) * System.SizeOf(UInt32));
end;

class function TArrayUtilities.GetArrayHashCode(const AData: TCryptoLibUInt32Array;
  AOff, ALen: Int32): Int32;
begin
  if AData = nil then
    Exit(0);
  Result := HashCore(PByte(PCardinal(AData) + AOff), ALen * System.SizeOf(UInt32));
end;

class function TArrayUtilities.GetArrayHashCode(const AData: TCryptoLibUInt64Array;
  AOff, ALen: Int32): Int32;
begin
  if AData = nil then
    Exit(0);
  Result := HashCore(PByte(PUInt64(AData) + AOff), ALen * System.SizeOf(UInt64));
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
  const ACloneFunc: TCryptoLibFunc<T, T>): TCryptoLibGenericArray<T>;
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
    // TODO: FPC 3.2.x fails when compiling Fill<T>(...), when upgrading minimum FPC to a version
    // that compiles it, remove this loop and use Fill<T>(Result, 0, LDone, Default(T)) instead.
    if LDone > 0 then
      for LI := 0 to LDone - 1 do
        Result[LI] := Default(T);
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
  const AFunc: TCryptoLibFunc<T, TResult>): TCryptoLibGenericArray<TResult>;
var
  LI, LCount: Int32;
begin
  LCount := System.Length(AData);
  System.SetLength(Result, LCount);
  for LI := 0 to LCount - 1 do
    Result[LI] := AFunc(AData[LI]);
end;

class function TArrayUtilities.ToString<T>(const AData: TCryptoLibGenericArray<T>;
  const AConverter: TCryptoLibFunc<T, String>): String;
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
