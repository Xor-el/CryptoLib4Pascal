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

unit ClpBigIntegerUtilities;

{$I ..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  Classes,
  Generics.Defaults,
  ClpBigInteger,
  ClpMod,
  ClpNat,
  ClpISecureRandom,
  ClpCryptoLibTypes;

resourcestring
  SStandardLengthExceeded = 'standard length exceeded';
  SMinMayNotBeGreaterThanMax = '''min'' may not be greater than ''max''';
  SMustBeOdd = 'must be odd';
  SModulusNotPositive = 'BigInteger: modulus not positive';
  SBigIntegerNotInvertible = 'BigInteger not invertible';

type
  /// <summary>
  /// Equality comparer for TBigInteger that uses value-based comparison
  /// (Equals) instead of reference equality. Used with TDictionary.
  /// </summary>
  TBigIntegerEqualityComparer = class(TInterfacedObject, IEqualityComparer<TBigInteger>)
  strict private
    function Equals(const ALeft, ARight: TBigInteger): Boolean; reintroduce;
    function GetHashCode(const AValue: TBigInteger): {$IFDEF DELPHI}Int32; {$ELSE}UInt32; {$ENDIF DELPHI} reintroduce;
  end;

  /// <summary>
  /// BigInteger utilities.
  /// </summary>
  TBigIntegerUtilities = class sealed(TObject)
  strict private
    const
      MaxIterations = 1000;

    class var
      FBigIntegerEqualityComparer: IEqualityComparer<TBigInteger>;

    class constructor Create;

  public
    class var
      Zero: TBigInteger;
      One: TBigInteger;

    /// <summary>
    /// Gets the BigInteger equality comparer for use with TDictionary.
    /// </summary>
    class property BigIntegerEqualityComparer: IEqualityComparer<TBigInteger> read FBigIntegerEqualityComparer;

    /// <summary>
    /// Return the passed in value as an unsigned byte array.
    /// </summary>
    /// <param name="AN">the value to be converted.</param>
    /// <returns>a byte array without a leading zero byte if present in the signed encoding.</returns>
    class function AsUnsignedByteArray(const AN: TBigInteger): TCryptoLibByteArray; overload; static;

    /// <summary>
    /// Return the passed in value as an unsigned byte array of the specified length, padded with
    /// leading zeros as necessary.
    /// </summary>
    /// <param name="ALength">the fixed length of the result.</param>
    /// <param name="AN">the value to be converted.</param>
    /// <returns>a byte array padded to a fixed length with leading zeros.</returns>
    class function AsUnsignedByteArray(const ALength: Int32; const AN: TBigInteger): TCryptoLibByteArray; overload; static;

    /// <summary>
    /// Write the passed in value as unsigned bytes to the specified buffer range, padded with
    /// leading zeros as necessary.
    /// </summary>
    /// <param name="AN">the value to be converted.</param>
    /// <param name="ABuf">the buffer to which the value is written.</param>
    /// <param name="AOff">the start offset in array ABuf at which the data is written.</param>
    /// <param name="ALen">the fixed length of data written (possibly padded with leading zeros).</param>
    class procedure AsUnsignedByteArray(const AN: TBigInteger; var ABuf: TCryptoLibByteArray; const AOff, ALen: Int32); overload; static;

    /// <summary>
    /// Creates a Random BigInteger from the secure random of a given bit length.
    /// </summary>
    /// <param name="ABitLength">the bit length.</param>
    /// <param name="ASecureRandom">the source of randomness.</param>
    /// <returns>a random BigInteger value.</returns>
    class function CreateRandomBigInteger(const ABitLength: Int32; const ASecureRandom: ISecureRandom): TBigInteger; static;

    /// <summary>
    /// Return a random BigInteger not less than 'min' and not greater than 'max'
    /// </summary>
    /// <param name="AMin">the least value that may be generated.</param>
    /// <param name="AMax">the greatest value that may be generated.</param>
    /// <param name="ARandom">the source of randomness.</param>
    /// <returns>a random BigInteger value in the range [min,max].</returns>
    class function CreateRandomInRange(const AMin, AMax: TBigInteger; const ARandom: ISecureRandom): TBigInteger; static;

    /// <summary>
    /// Create a BigInteger from an unsigned byte array.
    /// </summary>
    /// <param name="ABuf">the byte array.</param>
    /// <returns>a BigInteger value.</returns>
    class function FromUnsignedByteArray(const ABuf: TCryptoLibByteArray): TBigInteger; overload; static;

    /// <summary>
    /// Create a BigInteger from an unsigned byte array.
    /// </summary>
    /// <param name="ABuf">the byte array.</param>
    /// <param name="AOff">the start offset in array ABuf.</param>
    /// <param name="ALength">the length of data.</param>
    /// <returns>a BigInteger value.</returns>
    class function FromUnsignedByteArray(const ABuf: TCryptoLibByteArray; const AOff, ALength: Int32): TBigInteger; overload; static;

    /// <summary>
    /// Get the byte length of a BigInteger.
    /// </summary>
    /// <param name="AN">the BigInteger.</param>
    /// <returns>the byte length.</returns>
    class function GetByteLength(const AN: TBigInteger): Int32; static;

    /// <summary>
    /// Get the unsigned byte length of a BigInteger.
    /// </summary>
    /// <param name="AN">the BigInteger.</param>
    /// <returns>the unsigned byte length.</returns>
    class function GetUnsignedByteLength(const AN: TBigInteger): Int32; static;

    /// <summary>
    /// Write the passed in value as unsigned bytes to the specified stream.
    /// </summary>
    /// <param name="AOutStr">the stream to which the value is written.</param>
    /// <param name="AN">the value to be converted.</param>
    class procedure WriteUnsignedByteArray(const AOutStr: TStream; const AN: TBigInteger); static;

    /// <summary>
    /// ModOddInverse: modular inverse of X mod M (M must be odd). Throws if not invertible.
    /// </summary>
    /// <param name="AM">the modulus (must be odd).</param>
    /// <param name="AX">the value to invert.</param>
    /// <returns>inverse.</returns>
    class function ModOddInverse(const AM, AX: TBigInteger): TBigInteger; static;

    /// <summary>
    /// ModOddInverseVar: variable-time modular inverse of X mod M (M must be odd). Throws if not invertible.
    /// </summary>
    /// <param name="AM">the modulus (must be odd).</param>
    /// <param name="AX">the value to invert.</param>
    /// <returns>inverse.</returns>
    class function ModOddInverseVar(const AM, AX: TBigInteger): TBigInteger; static;

    /// <summary>
    /// ModOddIsCoprime: whether X is coprime to M (M must be odd).
    /// </summary>
    /// <param name="AM">the modulus (must be odd).</param>
    /// <param name="AX">the value to check.</param>
    /// <returns>whether is coprime or not.</returns>
    class function ModOddIsCoprime(const AM, AX: TBigInteger): Boolean; static;

    /// <summary>
    /// ModOddIsCoprimeVar: variable-time check whether X is coprime to M (M must be odd).
    /// </summary>
    /// <param name="AM">the modulus (must be odd).</param>
    /// <param name="AX">the value to check.</param>
    /// <returns>whether is coprime or not.</returns>
    class function ModOddIsCoprimeVar(const AM, AX: TBigInteger): Boolean; static;
  end;

implementation

{ TBigIntegerEqualityComparer }

function TBigIntegerEqualityComparer.Equals(const ALeft, ARight: TBigInteger): Boolean;
begin
  Result := ALeft.Equals(ARight);
end;

function TBigIntegerEqualityComparer.GetHashCode(const AValue: TBigInteger): {$IFDEF DELPHI}Int32; {$ELSE}UInt32; {$ENDIF DELPHI}
begin
  Result := AValue.GetHashCode();
end;

{ TBigIntegerUtilities }

class constructor TBigIntegerUtilities.Create;
begin
  Zero := TBigInteger.Zero;
  One := TBigInteger.One;
  FBigIntegerEqualityComparer := TBigIntegerEqualityComparer.Create();
end;

class function TBigIntegerUtilities.AsUnsignedByteArray(const AN: TBigInteger): TCryptoLibByteArray;
begin
  Result := AN.ToByteArrayUnsigned();
end;

class function TBigIntegerUtilities.AsUnsignedByteArray(const ALength: Int32; const AN: TBigInteger): TCryptoLibByteArray;
var
  LBytes: TCryptoLibByteArray;
  LBytesLength: Int32;
  I: Int32;
begin
  LBytes := AN.ToByteArrayUnsigned();
  LBytesLength := System.Length(LBytes);

  if LBytesLength > ALength then
    raise EArgumentCryptoLibException.Create(SStandardLengthExceeded);

  if LBytesLength = ALength then
  begin
    Result := LBytes;
    Exit;
  end;

  System.SetLength(Result, ALength);
  // Fill leading bytes with zeros
  for I := 0 to System.Pred(ALength - LBytesLength) do
  begin
    Result[I] := 0;
  end;
  // Copy the actual bytes
  System.Move(LBytes[0], Result[ALength - LBytesLength], LBytesLength * System.SizeOf(Byte));
end;

class procedure TBigIntegerUtilities.AsUnsignedByteArray(const AN: TBigInteger; var ABuf: TCryptoLibByteArray; const AOff, ALen: Int32);
var
  LBytes: TCryptoLibByteArray;
  LBytesLength: Int32;
  LPadLen: Int32;
  I: Int32;
begin
  LBytes := AN.ToByteArrayUnsigned();
  LBytesLength := System.Length(LBytes);

  if LBytesLength > ALen then
    raise EArgumentCryptoLibException.Create(SStandardLengthExceeded);

  LPadLen := ALen - LBytesLength;
  // Fill padding bytes with zeros
  for I := 0 to System.Pred(LPadLen) do
  begin
    ABuf[AOff + I] := 0;
  end;
  // Copy the actual bytes
  System.Move(LBytes[0], ABuf[AOff + LPadLen], LBytesLength * System.SizeOf(Byte));
end;

class function TBigIntegerUtilities.CreateRandomBigInteger(const ABitLength: Int32; const ASecureRandom: ISecureRandom): TBigInteger;
begin
  Result := TBigInteger.Create(ABitLength, ASecureRandom);
end;

class function TBigIntegerUtilities.CreateRandomInRange(const AMin, AMax: TBigInteger; const ARandom: ISecureRandom): TBigInteger;
var
  LCmp: Int32;
  I: Int32;
  LX: TBigInteger;
begin
  LCmp := AMin.CompareTo(AMax);
  if LCmp >= 0 then
  begin
    if LCmp > 0 then
      raise EArgumentCryptoLibException.Create(SMinMayNotBeGreaterThanMax);

    Result := AMin;
    Exit;
  end;

  if AMin.BitLength > (AMax.BitLength div 2) then
  begin
    Result := CreateRandomInRange(TBigInteger.Zero, AMax.Subtract(AMin), ARandom).Add(AMin);
    Exit;
  end;

  for I := 0 to System.Pred(MaxIterations) do
  begin
    LX := TBigInteger.Create(AMax.BitLength, ARandom);
    if (LX.CompareTo(AMin) >= 0) and (LX.CompareTo(AMax) <= 0) then
    begin
      Result := LX;
      Exit;
    end;
  end;

  // fall back to a faster (restricted) method
  Result := TBigInteger.Create(AMax.Subtract(AMin).BitLength - 1, ARandom).Add(AMin);
end;

class function TBigIntegerUtilities.FromUnsignedByteArray(const ABuf: TCryptoLibByteArray): TBigInteger;
begin
  Result := TBigInteger.Create(1, ABuf);
end;

class function TBigIntegerUtilities.FromUnsignedByteArray(const ABuf: TCryptoLibByteArray; const AOff, ALength: Int32): TBigInteger;
begin
  Result := TBigInteger.Create(1, ABuf, AOff, ALength);
end;

class function TBigIntegerUtilities.GetByteLength(const AN: TBigInteger): Int32;
begin
  Result := AN.GetLengthofByteArray();
end;

class function TBigIntegerUtilities.GetUnsignedByteLength(const AN: TBigInteger): Int32;
begin
  Result := AN.GetLengthofByteArrayUnsigned();
end;

class procedure TBigIntegerUtilities.WriteUnsignedByteArray(const AOutStr: TStream; const AN: TBigInteger);
var
  LBuffer: TCryptoLibByteArray;
begin
  LBuffer := AN.ToByteArrayUnsigned();
  AOutStr.Write(LBuffer, 0, System.Length(LBuffer));
end;

class function TBigIntegerUtilities.ModOddInverse(const AM, AX: TBigInteger): TBigInteger;
var
  LBits, LLen: Int32;
  LReducedX: TBigInteger;
  LM, LX, LZ: TCryptoLibUInt32Array;
begin
  if not AM.TestBit(0) then
    raise EArgumentCryptoLibException.Create(SMustBeOdd);

  if AM.SignValue <> 1 then
    raise EArithmeticCryptoLibException.Create(SModulusNotPositive);

  LReducedX := AX;
  if (LReducedX.SignValue < 0) or (LReducedX.BitLength > AM.BitLength) then
    LReducedX := LReducedX.&Mod(AM);

  LBits := AM.BitLength;
  LM := TNat.FromBigInteger(LBits, AM);
  LX := TNat.FromBigInteger(LBits, LReducedX);
  LLen := System.Length(LM);
  LZ := TNat.Create(LLen);

  if TMod.ModOddInverse(LM, LX, LZ) = 0 then
    raise EArithmeticCryptoLibException.Create(SBigIntegerNotInvertible);

  Result := TNat.ToBigInteger(LLen, LZ);
end;

class function TBigIntegerUtilities.ModOddInverseVar(const AM, AX: TBigInteger): TBigInteger;
var
  LBits, LLen: Int32;
  LReducedX: TBigInteger;
  LM, LX, LZ: TCryptoLibUInt32Array;
begin
  if not AM.TestBit(0) then
    raise EArgumentCryptoLibException.Create(SMustBeOdd);

  if AM.SignValue <> 1 then
    raise EArithmeticCryptoLibException.Create(SModulusNotPositive);

  if AM.Equals(One) then
  begin
    Result := Zero;
    Exit;
  end;

  LReducedX := AX;
  if (LReducedX.SignValue < 0) or (LReducedX.BitLength > AM.BitLength) then
    LReducedX := LReducedX.&Mod(AM);

  if LReducedX.Equals(One) then
  begin
    Result := One;
    Exit;
  end;

  LBits := AM.BitLength;
  LM := TNat.FromBigInteger(LBits, AM);
  LX := TNat.FromBigInteger(LBits, LReducedX);
  LLen := System.Length(LM);
  LZ := TNat.Create(LLen);

  if not TMod.ModOddInverseVar(LM, LX, LZ) then
    raise EArithmeticCryptoLibException.Create(SBigIntegerNotInvertible);

  Result := TNat.ToBigInteger(LLen, LZ);
end;

class function TBigIntegerUtilities.ModOddIsCoprime(const AM, AX: TBigInteger): Boolean;
var
  LBits: Int32;
  LReducedX: TBigInteger;
  LM, LX: TCryptoLibUInt32Array;
begin
  if not AM.TestBit(0) then
    raise EArgumentCryptoLibException.Create(SMustBeOdd);

  if AM.SignValue <> 1 then
    raise EArithmeticCryptoLibException.Create(SModulusNotPositive);

  LReducedX := AX;
  if (LReducedX.SignValue < 0) or (LReducedX.BitLength > AM.BitLength) then
    LReducedX := LReducedX.&Mod(AM);

  LBits := AM.BitLength;
  LM := TNat.FromBigInteger(LBits, AM);
  LX := TNat.FromBigInteger(LBits, LReducedX);

  Result := TMod.ModOddIsCoprime(LM, LX) <> 0;
end;

class function TBigIntegerUtilities.ModOddIsCoprimeVar(const AM, AX: TBigInteger): Boolean;
var
  LBits: Int32;
  LReducedX: TBigInteger;
  LM, LX: TCryptoLibUInt32Array;
begin
  if not AM.TestBit(0) then
    raise EArgumentCryptoLibException.Create(SMustBeOdd);

  if AM.SignValue <> 1 then
    raise EArithmeticCryptoLibException.Create(SModulusNotPositive);

  LReducedX := AX;
  if (LReducedX.SignValue < 0) or (LReducedX.BitLength > AM.BitLength) then
    LReducedX := LReducedX.&Mod(AM);

  if LReducedX.Equals(One) then
  begin
    Result := True;
    Exit;
  end;

  LBits := AM.BitLength;
  LM := TNat.FromBigInteger(LBits, AM);
  LX := TNat.FromBigInteger(LBits, LReducedX);

  Result := TMod.ModOddIsCoprimeVar(LM, LX);
end;

end.
