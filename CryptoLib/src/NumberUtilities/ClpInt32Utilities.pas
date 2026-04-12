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

unit ClpInt32Utilities;

{$I ..\Include\CryptoLib.inc}

interface

uses
  ClpBits,
  ClpBitOperations;

type
  TInt32Utilities = class sealed(TObject)
  public
    const
      NumBits: Int32 = 32;
      NumBytes: Int32 = 4;

    class function Compare(AX, AY: Int32): Int32; overload; static;
    class function Compare(AX, AY: UInt32): Int32; overload; static;
    class function CompareUnsigned(AX, AY: Int32): Int32; static;

    class function HighestOneBit(AValue: Int32): Int32; overload; static;
    class function HighestOneBit(AValue: UInt32): UInt32; overload; static;

    class function LowestOneBit(AValue: Int32): Int32; overload; static;
    class function LowestOneBit(AValue: UInt32): UInt32; overload; static;

    class function NumberOfLeadingZeros(AValue: Int32): Int32; static;
    class function NumberOfTrailingZeros(AValue: Int32): Int32; static;

    class function BitLength(AValue: Int32): Int32; overload; static;
    class function BitLength(AValue: UInt32): Int32; overload; static;

    class function PopCount(AValue: Int32): Int32; overload; static;
    class function PopCount(AValue: UInt32): Int32; overload; static;

    class function Reverse(AValue: Int32): Int32; overload; static;
    class function Reverse(AValue: UInt32): UInt32; overload; static;

    class function ReverseBytes(AValue: Int32): Int32; overload; static;
    class function ReverseBytes(AValue: UInt32): UInt32; overload; static;

    class function RotateLeft(AValue: Int32; ADistance: Int32): Int32; overload; static;
    class function RotateLeft(AValue: UInt32; ADistance: Int32): UInt32; overload; static;

    class function RotateRight(AValue: Int32; ADistance: Int32): Int32; overload; static;
    class function RotateRight(AValue: UInt32; ADistance: Int32): UInt32; overload; static;
  end;

implementation

{ TInt32Utilities }

class function TInt32Utilities.Compare(AX, AY: Int32): Int32;
begin
  if AX < AY then
    Result := -1
  else if AX > AY then
    Result := 1
  else
    Result := 0;
end;

class function TInt32Utilities.Compare(AX, AY: UInt32): Int32;
begin
  if AX < AY then
    Result := -1
  else if AX > AY then
    Result := 1
  else
    Result := 0;
end;

class function TInt32Utilities.CompareUnsigned(AX, AY: Int32): Int32;
begin
  Result := Compare(UInt32(AX), UInt32(AY));
end;

class function TInt32Utilities.HighestOneBit(AValue: Int32): Int32;
begin
  Result := Int32(HighestOneBit(UInt32(AValue)));
end;

class function TInt32Utilities.HighestOneBit(AValue: UInt32): UInt32;
begin
  AValue := AValue or (AValue shr 1);
  AValue := AValue or (AValue shr 2);
  AValue := AValue or (AValue shr 4);
  AValue := AValue or (AValue shr 8);
  AValue := AValue or (AValue shr 16);
  Result := AValue - (AValue shr 1);
end;

class function TInt32Utilities.LowestOneBit(AValue: Int32): Int32;
begin
  Result := AValue and (-AValue);
end;

class function TInt32Utilities.LowestOneBit(AValue: UInt32): UInt32;
begin
  Result := UInt32(LowestOneBit(Int32(AValue)));
end;

class function TInt32Utilities.NumberOfLeadingZeros(AValue: Int32): Int32;
begin
  Result := TBitOperations.NumberOfLeadingZeros32(UInt32(AValue));
end;

class function TInt32Utilities.NumberOfTrailingZeros(AValue: Int32): Int32;
begin
  Result := TBitOperations.NumberOfTrailingZeros32(UInt32(AValue));
end;

class function TInt32Utilities.BitLength(AValue: UInt32): Int32;
begin
  Result := NumBits - TBitOperations.NumberOfLeadingZeros32(AValue);
end;

class function TInt32Utilities.BitLength(AValue: Int32): Int32;
begin
  Result := BitLength(UInt32(AValue));
end;

class function TInt32Utilities.PopCount(AValue: Int32): Int32;
begin
  Result := TBitOperations.PopCount32(UInt32(AValue));
end;

class function TInt32Utilities.PopCount(AValue: UInt32): Int32;
begin
  Result := TBitOperations.PopCount32(AValue);
end;

class function TInt32Utilities.Reverse(AValue: Int32): Int32;
begin
  Result := Int32(Reverse(UInt32(AValue)));
end;

class function TInt32Utilities.Reverse(AValue: UInt32): UInt32;
begin
  AValue := TBits.BitPermuteStepSimple(AValue, UInt32($55555555), 1);
  AValue := TBits.BitPermuteStepSimple(AValue, UInt32($33333333), 2);
  AValue := TBits.BitPermuteStepSimple(AValue, UInt32($0F0F0F0F), 4);
  Result := TBitOperations.ReverseBytesUInt32(AValue);
end;

class function TInt32Utilities.ReverseBytes(AValue: Int32): Int32;
begin
  Result := TBitOperations.ReverseBytesInt32(AValue);
end;

class function TInt32Utilities.ReverseBytes(AValue: UInt32): UInt32;
begin
  Result := TBitOperations.ReverseBytesUInt32(AValue);
end;

class function TInt32Utilities.RotateLeft(AValue: Int32; ADistance: Int32): Int32;
begin
  Result := Int32(TBitOperations.RotateLeft32(UInt32(AValue), ADistance));
end;

class function TInt32Utilities.RotateLeft(AValue: UInt32; ADistance: Int32): UInt32;
begin
  Result := TBitOperations.RotateLeft32(AValue, ADistance);
end;

class function TInt32Utilities.RotateRight(AValue: Int32; ADistance: Int32): Int32;
begin
  Result := Int32(TBitOperations.RotateRight32(UInt32(AValue), ADistance));
end;

class function TInt32Utilities.RotateRight(AValue: UInt32; ADistance: Int32): UInt32;
begin
  Result := TBitOperations.RotateRight32(AValue, ADistance);
end;

end.
