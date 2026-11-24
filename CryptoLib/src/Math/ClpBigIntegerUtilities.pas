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

unit ClpBigIntegerUtilities;

{$I ..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  Classes,
  Generics.Defaults,
  ClpArrayUtilities,
  ClpBigInteger,
  ClpMod,
  ClpNat,
  ClpISecureRandom,
  ClpCryptoLibTypes,
  ClpCryptoLibExceptions;

resourcestring
  SStandardLengthExceeded = 'standard length exceeded';
  SMinMayNotBeGreaterThanMax = 'min may not be greater than max';
  SMustBeOdd = 'must be odd';
  SMustBePositive = 'must be positive';
  SModulusNotPositive = 'BigInteger: modulus not positive';
  SBigIntegerNotInvertible = 'BigInteger not invertible';
  SModOperandsOutOfRange = '''X'' and ''Y'' must be in the range [0, M)';

type
  /// <summary>
  /// Equality comparer for TBigInteger that uses value-based comparison
  /// (Equals) instead of reference equality. Used with TDictionary.
  /// </summary>
  TBigIntegerEqualityComparer = class(TInterfacedObject, IEqualityComparer<TBigInteger>)
  strict private
{$IFDEF CRYPTOLIB_FPC_HAS_CONSTREF_GENERIC_COMPARER}
    function Equals(constref ALeft, ARight: TBigInteger): Boolean; reintroduce;
    function GetHashCode(constref AValue: TBigInteger): UInt32; reintroduce;
{$ELSE}
    function Equals(const ALeft, ARight: TBigInteger): Boolean; reintroduce;
    function GetHashCode(const AValue: TBigInteger): {$IFDEF DELPHI}Int32; {$ELSE}UInt32; {$ENDIF DELPHI} reintroduce;
{$ENDIF}
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
      FSmallPrimesProduct: TBigInteger;

    class constructor Create;
    class function GetZero: TBigInteger; static;
    class function GetOne: TBigInteger; static;

    class procedure CheckModOperands(const AM, AX, AY: TBigInteger); static;
    // z = x * y * R^-1 mod m, for R = 2^(32 * len), x and y in [0, m); z may alias x or y.
    class procedure MontgomeryMultiply(ALen: Int32; const AX, AY, AM: TCryptoLibUInt32Array;
      AMDash: UInt32; const AT, AZ: TCryptoLibUInt32Array); static;
    // modular inverse of X mod M (M odd); returns False (no raise) when X is not invertible.
    class function ImplModOddInverse(const AM, AX: TBigInteger; out AResult: TBigInteger): Boolean; static;

  public
    /// <summary>
    /// Gets the BigInteger equality comparer for use with TDictionary.
    /// </summary>
    class property BigIntegerEqualityComparer: IEqualityComparer<TBigInteger> read FBigIntegerEqualityComparer;
    class property Zero: TBigInteger read GetZero;
    class property One: TBigInteger read GetOne;

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
    /// Creates a random probable prime BigInteger of a given bit length.
    /// </summary>
    class function CreateRandomPrime(ABitLength, ACertainty: Int32;
      const ARandom: ISecureRandom): TBigInteger; static;

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
    /// Returns true if the value has any small prime factors (including if even).
    /// </summary>
    class function HasAnySmallFactors(const AX: TBigInteger): Boolean; static;

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

    /// <summary>
    /// (X + Y) mod M, for X and Y already in [0, M), in time independent of the values. Operands outside
    /// [0, M) are rejected rather than reduced.
    /// </summary>
    class function ModAdd(const AM, AX, AY: TBigInteger): TBigInteger; static;

    /// <summary>
    /// (X - Y) mod M, for X and Y already in [0, M), in time independent of the values. Operands outside
    /// [0, M) are rejected rather than reduced.
    /// </summary>
    class function ModSubtract(const AM, AX, AY: TBigInteger): TBigInteger; static;

    /// <summary>
    /// (X * Y) mod M, for odd M and X, Y already in [0, M), in time independent of the values (Montgomery
    /// multiplication). Operands outside [0, M) are rejected rather than reduced.
    /// </summary>
    class function ModMult(const AM, AX, AY: TBigInteger): TBigInteger; static;

    /// <summary>
    /// X^E mod M for odd prime M and X in [1, M), with the base blinded so a chosen X cannot steer the timing.
    /// For a fresh random v this computes (X * v)^E * (v^-1)^E; neither exponentiation sees a base the caller
    /// knows. The exponent is not randomized. Costs two exponentiations and an inversion.
    /// </summary>
    class function ModPowBaseBlinded(const AM, AX, AE: TBigInteger;
      const ARandom: ISecureRandom): TBigInteger; static;

    /// <summary>
    /// Returns an exponent congruent to AExponent modulo the group order, blinded by a random multiple of
    /// AGroupOrder, so a fixed secret exponent does not drive the timing of a following variable-time ModPow.
    /// </summary>
    class function CreateBlindedExponent(const AExponent, AGroupOrder: TBigInteger;
      const ARandom: ISecureRandom): TBigInteger; static;
  end;

implementation

const
  SmallPrimesProductHex =
    '8138e8a0fcf3a4e84a771d40fd305d7f4aa59306d7251de54d98af8fe95729a1f' +
    '73d893fa424cd2edc8636a6c3285e022b0e3866a565ae8108eed8591cd4fe8d2' +
    'ce86165a978d719ebf647f362d33fca29cd179fb42401cbaf3df0c614056f9c8' +
    'f3cfd51e474afb6bc6974f78db8aba8e9e517fded658591ab7502bd41849462f';

{ TBigIntegerEqualityComparer }

{$IFDEF CRYPTOLIB_FPC_HAS_CONSTREF_GENERIC_COMPARER}
function TBigIntegerEqualityComparer.Equals(constref ALeft, ARight: TBigInteger): Boolean;
{$ELSE}
function TBigIntegerEqualityComparer.Equals(const ALeft, ARight: TBigInteger): Boolean;
{$ENDIF}
begin
  Result := ALeft.Equals(ARight);
end;

{$IFDEF CRYPTOLIB_FPC_HAS_CONSTREF_GENERIC_COMPARER}
function TBigIntegerEqualityComparer.GetHashCode(constref AValue: TBigInteger): UInt32;
{$ELSE}
function TBigIntegerEqualityComparer.GetHashCode(const AValue: TBigInteger): {$IFDEF DELPHI}Int32; {$ELSE}UInt32; {$ENDIF DELPHI}
{$ENDIF}
begin
  Result := AValue.GetHashCode();
end;

{ TBigIntegerUtilities }

class constructor TBigIntegerUtilities.Create;
begin
  FBigIntegerEqualityComparer := TBigIntegerEqualityComparer.Create();
  FSmallPrimesProduct := TBigInteger.Create(SmallPrimesProductHex, 16);
end;

class function TBigIntegerUtilities.GetZero: TBigInteger;
begin
  Result := TBigInteger.Zero;
end;

class function TBigIntegerUtilities.GetOne: TBigInteger;
begin
  Result := TBigInteger.One;
end;

class function TBigIntegerUtilities.AsUnsignedByteArray(const AN: TBigInteger): TCryptoLibByteArray;
begin
  Result := AN.ToByteArrayUnsigned();
end;

class function TBigIntegerUtilities.AsUnsignedByteArray(const ALength: Int32; const AN: TBigInteger): TCryptoLibByteArray;
var
  LBytes: TCryptoLibByteArray;
  LBytesLength: Int32;
  LPadLen: Int32;
begin
  LBytes := AN.ToByteArrayUnsigned();
  LBytesLength := System.Length(LBytes);

  if LBytesLength > ALength then
    raise EArgumentCryptoLibException.CreateRes(@SStandardLengthExceeded);

  if LBytesLength = ALength then
  begin
    Result := LBytes;
    Exit;
  end;

  LPadLen := ALength - LBytesLength;
  System.SetLength(Result, ALength);
  TArrayUtilities.Fill(Result, 0, LPadLen, Byte(0));
  System.Move(LBytes[0], Result[LPadLen], LBytesLength * System.SizeOf(Byte));
end;

class procedure TBigIntegerUtilities.AsUnsignedByteArray(const AN: TBigInteger; var ABuf: TCryptoLibByteArray; const AOff, ALen: Int32);
var
  LBytes: TCryptoLibByteArray;
  LBytesLength: Int32;
  LPadLen: Int32;
begin
  LBytes := AN.ToByteArrayUnsigned();
  LBytesLength := System.Length(LBytes);

  if LBytesLength > ALen then
    raise EArgumentCryptoLibException.CreateRes(@SStandardLengthExceeded);

  LPadLen := ALen - LBytesLength;
  TArrayUtilities.Fill(ABuf, AOff, AOff + LPadLen, Byte(0));
  System.Move(LBytes[0], ABuf[AOff + LPadLen], LBytesLength * System.SizeOf(Byte));
end;

class function TBigIntegerUtilities.CreateRandomBigInteger(const ABitLength: Int32; const ASecureRandom: ISecureRandom): TBigInteger;
begin
  Result := TBigInteger.Create(ABitLength, ASecureRandom);
end;

class function TBigIntegerUtilities.CreateRandomPrime(ABitLength, ACertainty: Int32;
  const ARandom: ISecureRandom): TBigInteger;
begin
  Result := TBigInteger.Create(ABitLength, ACertainty, ARandom);
end;

class function TBigIntegerUtilities.CreateRandomInRange(const AMin, AMax: TBigInteger; const ARandom: ISecureRandom): TBigInteger;
var
  LCmp: Int32;
  LI: Int32;
  LX: TBigInteger;
begin
  LCmp := AMin.CompareTo(AMax);
  if LCmp >= 0 then
  begin
    if LCmp > 0 then
      raise EArgumentCryptoLibException.CreateRes(@SMinMayNotBeGreaterThanMax);

    Result := AMin;
    Exit;
  end;

  if AMin.BitLength > (AMax.BitLength div 2) then
  begin
    Result := CreateRandomInRange(TBigInteger.Zero, AMax.Subtract(AMin), ARandom).Add(AMin);
    Exit;
  end;

  for LI := 0 to System.Pred(MaxIterations) do
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

class function TBigIntegerUtilities.HasAnySmallFactors(const AX: TBigInteger): Boolean;
var
  LM, LX: TBigInteger;
begin
  if not AX.TestBit(0) then
    Exit(True);

  if AX.BitLength < FSmallPrimesProduct.BitLength then
  begin
    LM := FSmallPrimesProduct;
    LX := AX;
  end
  else
  begin
    LM := AX;
    LX := FSmallPrimesProduct;
  end;

  Result := not ModOddIsCoprimeVar(LM, LX);
end;

class procedure TBigIntegerUtilities.WriteUnsignedByteArray(const AOutStr: TStream; const AN: TBigInteger);
var
  LBuffer: TCryptoLibByteArray;
begin
  LBuffer := AN.ToByteArrayUnsigned();
  AOutStr.Write(LBuffer[0], System.Length(LBuffer));
end;

class function TBigIntegerUtilities.ImplModOddInverse(const AM, AX: TBigInteger; out AResult: TBigInteger): Boolean;
var
  LBits, LLen: Int32;
  LReducedX: TBigInteger;
  LM, LX, LZ: TCryptoLibUInt32Array;
begin
  if not AM.TestBit(0) then
    raise EArgumentCryptoLibException.CreateRes(@SMustBeOdd);

  if AM.SignValue <> 1 then
    raise EArithmeticCryptoLibException.CreateRes(@SModulusNotPositive);

  LReducedX := AX;
  if (LReducedX.SignValue < 0) or (LReducedX.BitLength > AM.BitLength) then
    LReducedX := LReducedX.&Mod(AM);

  LBits := AM.BitLength;
  LM := TNat.FromBigInteger(LBits, AM);
  LX := TNat.FromBigInteger(LBits, LReducedX);
  LLen := System.Length(LM);
  LZ := TNat.Create(LLen);

  if TMod.ModOddInverse(LM, LX, LZ) = 0 then
    Exit(False);

  AResult := TNat.ToBigInteger(LLen, LZ);
  Result := True;
end;

class function TBigIntegerUtilities.ModOddInverse(const AM, AX: TBigInteger): TBigInteger;
begin
  if not ImplModOddInverse(AM, AX, Result) then
    raise EArithmeticCryptoLibException.CreateRes(@SBigIntegerNotInvertible);
end;

class function TBigIntegerUtilities.ModOddInverseVar(const AM, AX: TBigInteger): TBigInteger;
var
  LBits, LLen: Int32;
  LReducedX: TBigInteger;
  LM, LX, LZ: TCryptoLibUInt32Array;
begin
  if not AM.TestBit(0) then
    raise EArgumentCryptoLibException.CreateRes(@SMustBeOdd);

  if AM.SignValue <> 1 then
    raise EArithmeticCryptoLibException.CreateRes(@SModulusNotPositive);

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
    raise EArithmeticCryptoLibException.CreateRes(@SBigIntegerNotInvertible);

  Result := TNat.ToBigInteger(LLen, LZ);
end;

class function TBigIntegerUtilities.ModOddIsCoprime(const AM, AX: TBigInteger): Boolean;
var
  LBits: Int32;
  LReducedX: TBigInteger;
  LM, LX: TCryptoLibUInt32Array;
begin
  if not AM.TestBit(0) then
    raise EArgumentCryptoLibException.CreateRes(@SMustBeOdd);

  if AM.SignValue <> 1 then
    raise EArithmeticCryptoLibException.CreateRes(@SModulusNotPositive);

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
    raise EArgumentCryptoLibException.CreateRes(@SMustBeOdd);

  if AM.SignValue <> 1 then
    raise EArithmeticCryptoLibException.CreateRes(@SModulusNotPositive);

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

class procedure TBigIntegerUtilities.CheckModOperands(const AM, AX, AY: TBigInteger);
begin
  if AM.SignValue <> 1 then
    raise EArithmeticCryptoLibException.CreateRes(@SModulusNotPositive);
  if (AX.SignValue < 0) or (AX.CompareTo(AM) >= 0) or (AY.SignValue < 0) or (AY.CompareTo(AM) >= 0) then
    raise EArgumentCryptoLibException.CreateRes(@SModOperandsOutOfRange);
end;

class function TBigIntegerUtilities.ModAdd(const AM, AX, AY: TBigInteger): TBigInteger;
var
  LBits, LLen, LBorrow: Int32;
  LM, LX, LY: TCryptoLibUInt32Array;
begin
  CheckModOperands(AM, AX, AY);

  // the extra bit of width means X + Y, below 2M, cannot carry out of the top word, so one conditional
  // subtraction of M reduces it
  LBits := AM.BitLength + 1;
  LM := TNat.FromBigInteger(LBits, AM);
  LX := TNat.FromBigInteger(LBits, AX);
  LY := TNat.FromBigInteger(LBits, AY);
  LLen := System.Length(LM);

  TNat.Add(LLen, LX, LY, LX);
  LBorrow := TNat.Sub(LLen, LX, LM, LY);     // Y = X - M; borrow is -1 exactly when X < M
  TNat.CMov(LLen, not LBorrow, LY, 0, LX, 0); // keep X - M unless the subtraction went negative
  Result := TNat.ToBigInteger(LLen, LX);
end;

class function TBigIntegerUtilities.ModSubtract(const AM, AX, AY: TBigInteger): TBigInteger;
var
  LBits, LLen, LBorrow: Int32;
  LM, LX, LY: TCryptoLibUInt32Array;
begin
  CheckModOperands(AM, AX, AY);

  // X - Y lies in (-M, M), so one conditional addition of M reduces it; the width is that of ModAdd
  LBits := AM.BitLength + 1;
  LM := TNat.FromBigInteger(LBits, AM);
  LX := TNat.FromBigInteger(LBits, AX);
  LY := TNat.FromBigInteger(LBits, AY);
  LLen := System.Length(LM);

  LBorrow := TNat.Sub(LLen, LX, LY, LX);  // borrow is -1 exactly when X < Y
  TNat.Add(LLen, LX, LM, LY);             // Y = X + M, discarding the carry off the top
  TNat.CMov(LLen, LBorrow, LY, 0, LX, 0); // take X + M only where the difference went negative
  Result := TNat.ToBigInteger(LLen, LX);
end;

class procedure TBigIntegerUtilities.MontgomeryMultiply(ALen: Int32; const AX, AY, AM: TCryptoLibUInt32Array;
  AMDash: UInt32; const AT, AZ: TCryptoLibUInt32Array);
var
  LI, LBorrow, LTopSet: Int32;
  LC: UInt64;
  LTop: UInt32;
begin
  TArrayUtilities.Fill(AT, 0, System.Length(AT), UInt32(0));

  for LI := 0 to ALen - 1 do
  begin
    // the window AT[LI..LI+ALen+1]: its top word has not been written yet, so it is zero
    LC := UInt64(TNat.MulWordAddTo(ALen, AY[LI], AX, 0, AT, LI)) + AT[LI + ALen];
    AT[LI + ALen] := UInt32(LC);
    AT[LI + ALen + 1] := UInt32(LC shr 32);

    LC := UInt64(TNat.MulWordAddTo(ALen, UInt32(AT[LI] * AMDash), AM, 0, AT, LI)) + AT[LI + ALen];
    AT[LI + ALen] := UInt32(LC);
    AT[LI + ALen + 1] := AT[LI + ALen + 1] + UInt32(LC shr 32);
  end;

  // the result, below 2m, is in AT[ALen..2*ALen]: subtract m unless it is already below m, which is when the
  // subtraction goes negative and the top word is clear
  LTop := AT[2 * ALen];
  LBorrow := TNat.Sub(ALen, AT, ALen, AM, 0, AZ, 0);
  LTopSet := Int32((LTop or (UInt32(0) - LTop)) shr 31);
  TNat.CMov(ALen, LBorrow and (LTopSet - 1), AT, ALen, AZ, 0);
end;

class function TBigIntegerUtilities.ModMult(const AM, AX, AY: TBigInteger): TBigInteger;
var
  LBits, LLen: Int32;
  LMDash: UInt32;
  LR2: TBigInteger;
  LM, LX, LY, LR2Words, LT: TCryptoLibUInt32Array;
begin
  if not AM.TestBit(0) then
    raise EArgumentCryptoLibException.CreateRes(@SMustBeOdd);

  CheckModOperands(AM, AX, AY);

  LBits := AM.BitLength;
  LLen := TNat.GetLengthForBits(LBits);

  // R = 2^(32 * len) exceeds the odd M, so they are coprime. R^2 mod M depends only on the public modulus.
  LR2 := One.ShiftLeft(LLen shl 6).&Mod(AM);

  LM := TNat.FromBigInteger(LBits, AM);
  LX := TNat.FromBigInteger(LBits, AX);
  LY := TNat.FromBigInteger(LBits, AY);
  LR2Words := TNat.FromBigInteger(LBits, LR2);
  LT := TNat.Create(2 * LLen + 1);
  LMDash := UInt32(0 - Int64(TMod.Inverse32(LM[0])));

  // the first product leaves X * Y * R^-1, the second multiplies by R^2 * R^-1 to undo it
  MontgomeryMultiply(LLen, LX, LY, LM, LMDash, LT, LX);
  MontgomeryMultiply(LLen, LX, LR2Words, LM, LMDash, LT, LX);
  Result := TNat.ToBigInteger(LLen, LX);
end;

class function TBigIntegerUtilities.ModPowBaseBlinded(const AM, AX, AE: TBigInteger;
  const ARandom: ISecureRandom): TBigInteger;
var
  LMaxV, LV, LVInv, LBlinded, LUnblind: TBigInteger;
begin
  // zero cannot be blinded (the product with v stays zero), and ModMult below rejects X >= M
  if AX.SignValue <= 0 then
    raise EArgumentCryptoLibException.CreateRes(@SMustBePositive);

  // the blinding is only as good as v is secret, so v stays on the fixed-time helpers. For a prime M the
  // first v is always invertible; a v sharing a factor with a composite M is redrawn.
  LMaxV := AM.Subtract(TBigInteger.Two);
  repeat
    LV := CreateRandomInRange(TBigInteger.Two, LMaxV, ARandom);
  until ImplModOddInverse(AM, LV, LVInv);

  LBlinded := ModMult(AM, AX, LV).ModPow(AE, AM);
  LUnblind := LVInv.ModPow(AE, AM);
  Result := ModMult(AM, LBlinded, LUnblind);
end;

class function TBigIntegerUtilities.CreateBlindedExponent(const AExponent, AGroupOrder: TBigInteger;
  const ARandom: ISecureRandom): TBigInteger;
const
  RandomBits = Int32(7);
var
  LBlind: TBigInteger;
begin
  LBlind := CreateRandomBigInteger(RandomBits, ARandom).SetBit(RandomBits);
  Result := AExponent.Add(LBlind.Multiply(AGroupOrder));
end;

end.
