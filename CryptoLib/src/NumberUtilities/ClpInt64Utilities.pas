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

unit ClpInt64Utilities;

{$I ..\Include\CryptoLib.inc}

interface

uses
  ClpBits,
  ClpBitOperations;

type
  TInt64Utilities = class sealed(TObject)
  public
    const
      NumBits: Int32 = 64;
      NumBytes: Int32 = 8;

    class function Compare(AX, AY: Int64): Int32; overload; static;
    class function Compare(AX, AY: UInt64): Int32; overload; static;
    class function CompareUnsigned(AX, AY: Int64): Int32; static;

    class function HighestOneBit(AValue: Int64): Int64; overload; static;
    class function HighestOneBit(AValue: UInt64): UInt64; overload; static;

    class function LowestOneBit(AValue: Int64): Int64; overload; static;
    class function LowestOneBit(AValue: UInt64): UInt64; overload; static;

    class function NumberOfLeadingZeros(AValue: Int64): Int32; static;
    class function NumberOfTrailingZeros(AValue: Int64): Int32; static;

    class function PopCount(AValue: Int64): Int32; overload; static;
    class function PopCount(AValue: UInt64): Int32; overload; static;

    class function Reverse(AValue: Int64): Int64; overload; static;
    class function Reverse(AValue: UInt64): UInt64; overload; static;

    class function ReverseBytes(AValue: Int64): Int64; overload; static;
    class function ReverseBytes(AValue: UInt64): UInt64; overload; static;

    class function RotateLeft(AValue: Int64; ADistance: Int32): Int64; overload; static;
    class function RotateLeft(AValue: UInt64; ADistance: Int32): UInt64; overload; static;

    class function RotateRight(AValue: Int64; ADistance: Int32): Int64; overload; static;
    class function RotateRight(AValue: UInt64; ADistance: Int32): UInt64; overload; static;
  end;

implementation

{ TInt64Utilities }

class function TInt64Utilities.Compare(AX, AY: Int64): Int32;
begin
  if AX < AY then
    Result := -1
  else if AX > AY then
    Result := 1
  else
    Result := 0;
end;

class function TInt64Utilities.Compare(AX, AY: UInt64): Int32;
begin
  if AX < AY then
    Result := -1
  else if AX > AY then
    Result := 1
  else
    Result := 0;
end;

class function TInt64Utilities.CompareUnsigned(AX, AY: Int64): Int32;
begin
  Result := Compare(UInt64(AX), UInt64(AY));
end;

class function TInt64Utilities.HighestOneBit(AValue: Int64): Int64;
begin
  Result := Int64(HighestOneBit(UInt64(AValue)));
end;

class function TInt64Utilities.HighestOneBit(AValue: UInt64): UInt64;
begin
  AValue := AValue or (AValue shr 1);
  AValue := AValue or (AValue shr 2);
  AValue := AValue or (AValue shr 4);
  AValue := AValue or (AValue shr 8);
  AValue := AValue or (AValue shr 16);
  AValue := AValue or (AValue shr 32);
  Result := AValue - (AValue shr 1);
end;

class function TInt64Utilities.LowestOneBit(AValue: Int64): Int64;
begin
  Result := AValue and (-AValue);
end;

class function TInt64Utilities.LowestOneBit(AValue: UInt64): UInt64;
begin
  Result := UInt64(LowestOneBit(Int64(AValue)));
end;

class function TInt64Utilities.NumberOfLeadingZeros(AValue: Int64): Int32;
begin
  Result := TBitOperations.NumberOfLeadingZeros64(UInt64(AValue));
end;

class function TInt64Utilities.NumberOfTrailingZeros(AValue: Int64): Int32;
begin
  Result := TBitOperations.NumberOfTrailingZeros64(UInt64(AValue));
end;

class function TInt64Utilities.PopCount(AValue: Int64): Int32;
begin
  Result := TBitOperations.PopCount64(UInt64(AValue));
end;

class function TInt64Utilities.PopCount(AValue: UInt64): Int32;
begin
  Result := TBitOperations.PopCount64(AValue);
end;

class function TInt64Utilities.Reverse(AValue: Int64): Int64;
begin
  Result := Int64(Reverse(UInt64(AValue)));
end;

class function TInt64Utilities.Reverse(AValue: UInt64): UInt64;
begin
  AValue := TBits.BitPermuteStepSimple(AValue, UInt64($5555555555555555), 1);
  AValue := TBits.BitPermuteStepSimple(AValue, UInt64($3333333333333333), 2);
  AValue := TBits.BitPermuteStepSimple(AValue, UInt64($0F0F0F0F0F0F0F0F), 4);
  Result := TBitOperations.ReverseBytesUInt64(AValue);
end;

class function TInt64Utilities.ReverseBytes(AValue: Int64): Int64;
begin
  Result := Int64(TBitOperations.ReverseBytesUInt64(UInt64(AValue)));
end;

class function TInt64Utilities.ReverseBytes(AValue: UInt64): UInt64;
begin
  Result := TBitOperations.ReverseBytesUInt64(AValue);
end;

class function TInt64Utilities.RotateLeft(AValue: Int64; ADistance: Int32): Int64;
begin
  Result := Int64(TBitOperations.RotateLeft64(UInt64(AValue), ADistance));
end;

class function TInt64Utilities.RotateLeft(AValue: UInt64; ADistance: Int32): UInt64;
begin
  Result := TBitOperations.RotateLeft64(AValue, ADistance);
end;

class function TInt64Utilities.RotateRight(AValue: Int64; ADistance: Int32): Int64;
begin
  Result := Int64(TBitOperations.RotateRight64(UInt64(AValue), ADistance));
end;

class function TInt64Utilities.RotateRight(AValue: UInt64; ADistance: Int32): UInt64;
begin
  Result := TBitOperations.RotateRight64(AValue, ADistance);
end;

end.
