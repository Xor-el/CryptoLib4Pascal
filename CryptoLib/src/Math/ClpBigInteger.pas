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

unit ClpBigInteger;

{$I ..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  Math,
  ClpCryptoLibTypes,
  ClpConverters,
  ClpBitUtilities,
  ClpArrayUtilities,
  ClpISecureRandom,
  ClpIRandom;

resourcestring
  SZeroLengthBigInteger = 'Zero length BigInteger';
  SInvalidSignValue = 'Invalid sign value';
  SInvalidRadix = 'Only bases 2, 8, 10, or 16 allowed';
  SBigIntegerOutOfIntRange = 'BigInteger out of int range';
  SBigIntegerOutOfLongRange = 'BigInteger out of long range';
  SModulusMustBePositive = 'Modulus must be positive';
  SBitAddressLessThanZero = 'Bit address less than zero';
  SSizeInBitsMustBeNonNegative = 'sizeInBits must be non-negative';
  SBitLengthLessThanTwo = 'bitLength < 2';

type
  /// <summary>
  /// Immutable arbitrary-precision integer. All operations return new instances.
  /// </summary>
  TBigInteger = record
  private
    const
    BitsPerByte = Int32(8);
    BitsPerInt = Int32(32);
    BytesPerInt = Int32(4);
    Chunk2 = Int32(1);
    Chunk8 = Int32(1);
    Chunk10 = Int32(19);
    Chunk16 = Int32(16);
    IMASK = Int64($FFFFFFFF);
    UIMASK = UInt64($FFFFFFFF);

    BitLengthTable: array [0 .. 255] of Byte =
    (
      0, 1, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 4, 4, 4, 4,
      5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
      6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6,
      6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6,
      7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
      7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
      7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
      7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
      8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
      8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
      8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
      8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
      8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
      8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
      8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
      8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8
    );

    /// <summary>
    /// These are the threshold bit-lengths (of an exponent) where we increase the window size.
    /// They are calculated according to the expected savings in multiplications.
    /// Some squares will also be saved on average, but we offset these against the extra storage costs.
    /// </summary>
    ExpWindowThresholds: array [0 .. 7] of Int32 =
    (
      7, 25, 81, 241, 673, 1793, 4609, Int32.MaxValue
    );

  var
    // Instance fields (IMMUTABLE - read-only after construction)
    FMagnitude: TCryptoLibUInt32Array; // array of UInt32 with [0] being most significant
    FSign: Int32; // -1 means negative, +1 means positive, 0 means zero
    FNBits: Int32; // cached BitCount() value (-1 if not cached)
    FNBitLength: Int32; // cached BitLength() value (-1 if not cached)
    FIsInitialized: Boolean;

    // Class variables (private, with F prefix) - must come before methods
    class var FZero, FOne, FTwo, FThree, FFour, FFive, FSix, FSeven, FEight, FNine, FTen: TBigInteger;
    class var FPrimeLists: TCryptoLibMatrixInt32Array; // array of prime number arrays
    class var FPrimeProducts: TCryptoLibInt32Array; // array of prime products
    class var FSmallConstants: TCryptoLibGenericArray<TBigInteger>; // precomputed small values
    class var FRadix2, FRadix2E, FRadix8, FRadix8E, FRadix10, FRadix10E, FRadix16, FRadix16E: TBigInteger;

    // Private instance helper methods
    function GetIsInitialized: Boolean;
    function GetInt32Value: Int32;
    function GetInt64Value: Int64;
    function GetSignValue: Int32;
    function GetBitLength: Int32;
    function GetBitCount: Int32;
    function ModInversePow2(const AM: TBigInteger): TBigInteger;
    function ModPowSimple(const AB, AE, AM: TBigInteger): TBigInteger;
    class function ModPowBarrett(const AB, AE, AM: TBigInteger): TBigInteger; static;
    class function ReduceBarrett(const AX, AM, AMr, AYu: TBigInteger): TBigInteger; static;
    class function ModPowMonty(var AYAccum: TCryptoLibUInt32Array; const AB, AE, AM: TBigInteger; const AConvert: Boolean): TBigInteger; static;
    class function ModSquareMonty(var AYAccum: TCryptoLibUInt32Array; const AB, AM: TBigInteger): TBigInteger; static;
    function LastNBits(const AN: Int32): TCryptoLibUInt32Array;
    function QuickPow2Check(): Boolean;
    function Remainder(const AM: Int32): Int32; overload;
    function DivideWords(const AW: Int32): TBigInteger;
    function RemainderWords(const AW: Int32): TBigInteger;
    function GetMQuote(): UInt32;
    function CheckProbablePrime(const ACertainty: Int32; const ARandom: IRandom;
      const ARandomlySelected: Boolean): Boolean;
    function GetLowestSetBitMaskFirst(const AFirstWordMaskX: UInt32): Int32;
    function Square(): TBigInteger; overload;
    function &Inc(): TBigInteger;
    function AddToMagnitude(const AMagToAdd: TCryptoLibUInt32Array): TBigInteger;
    constructor Create(const ASignum: Int32; const AMag: TCryptoLibUInt32Array; const ACheckMag: Boolean); overload;

    // Private class helper functions
    class function PopCount(const AValue: UInt32): Int32; static;
    class function BitLen(const AValue: Byte): Int32; overload; static;
    class function BitLen(const AValue: UInt32): Int32; overload; static;
    class function CreateUValueOf(const AValue: UInt32): TBigInteger; overload; static;
    class function CreateUValueOf(const AValue: UInt64): TBigInteger; overload; static;
    class function GetBytesLength(const ANBits: Int32): Int32; static;
    class function CalcBitLength(const ASign, AIndx: Int32; const AMag: TCryptoLibUInt32Array): Int32; static;
    class function CompareTo(const AXIndx: Int32; const AX: TCryptoLibUInt32Array; const AYIndx: Int32; const AY: TCryptoLibUInt32Array): Int32; overload; static;
    class function CompareNoLeadingZeros(const AXIndx: Int32; const AX: TCryptoLibUInt32Array; const AYIndx: Int32; const AY: TCryptoLibUInt32Array): Int32; static;
    class function IsEqualMagnitude(const AX: TCryptoLibUInt32Array; const AY: TCryptoLibUInt32Array): Boolean; static;
    class function MakeMagnitudeBE(const ABytes: TCryptoLibByteArray; const AOffset, ALength: Int32): TCryptoLibUInt32Array; static;
    class function MakeMagnitudeLE(const ABytes: TCryptoLibByteArray; const AOffset, ALength: Int32): TCryptoLibUInt32Array; static;
    class function InitBE(const ABytes: TCryptoLibByteArray; const AOffset, ALength: Int32; out ASign: Int32): TCryptoLibUInt32Array; static;
    class function InitLE(const ABytes: TCryptoLibByteArray; const AOffset, ALength: Int32; out ASign: Int32): TCryptoLibUInt32Array; static;
    class function AddMagnitudes(const AA: TCryptoLibUInt32Array; const AB: TCryptoLibUInt32Array): TCryptoLibUInt32Array; static;
    class function Subtract(const AXStart: Int32; var AX: TCryptoLibUInt32Array; const AYStart: Int32; const AY: TCryptoLibUInt32Array): TCryptoLibUInt32Array; overload; static;
    class function DoSubBigLil(const ABigMag, ALilMag: TCryptoLibUInt32Array): TCryptoLibUInt32Array; static;
    class function ShiftLeft(const AMag: TCryptoLibUInt32Array; const AN: Int32): TCryptoLibUInt32Array; overload; static;
    class function Multiply(var AX: TCryptoLibUInt32Array; const AY, AZ: TCryptoLibUInt32Array): TCryptoLibUInt32Array; overload; static;
    class function Square(var AW: TCryptoLibUInt32Array; const AX: TCryptoLibUInt32Array): TCryptoLibUInt32Array; overload; static;
    class function Divide(var AX: TCryptoLibUInt32Array; const AY: TCryptoLibUInt32Array): TCryptoLibUInt32Array; overload; static;
    class function Remainder(var AX: TCryptoLibUInt32Array; const AY: TCryptoLibUInt32Array): TCryptoLibUInt32Array; overload; static;
    class procedure ShiftRightOneInPlace(const AStart: Int32; var AMag: TCryptoLibUInt32Array); static;
    class procedure ShiftRightInPlace(const AStart: Int32; var AMag: TCryptoLibUInt32Array; const AN: Int32); static;
    class function ExtEuclid(const AA, AB: TBigInteger; out AU1Out: TBigInteger): TBigInteger; static;
    class function UInt32ToBin(const AValue: UInt32): String; static;
    class function Int32ToOct(const AValue: Int32): String; static;
    class procedure AppendZeroExtendedString(var ASb: String; const &AS: String; const AMinLength: Int32); static;
    class function ParseChunkToUInt64(const AChunk: String; const ARadix: Int32): UInt64; static;
    class function CreateWindowEntry(const AMult, AZeros: UInt32): UInt32; static;
    class function GetWindowList(const AMag: TCryptoLibUInt32Array; const AExtraBits: Int32): TCryptoLibUInt32Array; static;
    class function MultiplyMontyNIsOne(const AX, AY, AM, AMDash: UInt32): UInt32; static;
    class procedure MontgomeryReduce(var AX: TCryptoLibUInt32Array; const AM: TCryptoLibUInt32Array; const AMDash: UInt32); static;
    class procedure MultiplyMonty(var AA: TCryptoLibUInt32Array; var AX: TCryptoLibUInt32Array; const AY, AM: TCryptoLibUInt32Array; const AMDash: UInt32; const ASmallMontyModulus: Boolean); static;
    class procedure SquareMonty(var AA: TCryptoLibUInt32Array; var AX: TCryptoLibUInt32Array; const AM: TCryptoLibUInt32Array; const AMDash: UInt32; const ASmallMontyModulus: Boolean); static;

    // Class constructor for static initialization
    class constructor Create;

  public
    // Instance methods (all return new instances - IMMUTABLE)
    function Add(const AValue: TBigInteger): TBigInteger;
    function Subtract(const AValue: TBigInteger): TBigInteger; overload;
    function Multiply(const AValue: TBigInteger): TBigInteger; overload;
    function Divide(const AValue: TBigInteger): TBigInteger; overload;
    function Remainder(const AValue: TBigInteger): TBigInteger; overload;
    function DivideAndRemainder(const AValue: TBigInteger): TCryptoLibGenericArray<TBigInteger>;
    function &Mod(const AM: TBigInteger): TBigInteger;
    function ModInverse(const AM: TBigInteger): TBigInteger;
    function ModDivide(const AY, AM: TBigInteger): TBigInteger;
    function ModMultiply(const AY, AM: TBigInteger): TBigInteger;
    function ModSquare(const AM: TBigInteger): TBigInteger;
    function ModPow(const AE, AM: TBigInteger): TBigInteger;
    function Pow(const AExponent: Int32): TBigInteger;
    function Gcd(const AValue: TBigInteger): TBigInteger;
    function Abs(): TBigInteger;
    function Negate(): TBigInteger;
    function GetHashCode(): {$IFDEF DELPHI}Int32; {$ELSE}PtrInt; {$ENDIF DELPHI}
    function Int32ValueExact(): Int32;
    function Int64ValueExact(): Int64;

    // Bit operations (all return new instances - IMMUTABLE)
    function ShiftLeft(const AN: Int32): TBigInteger; overload;
    function ShiftRight(const AN: Int32): TBigInteger;
    function &And(const AValue: TBigInteger): TBigInteger;
    function &Or(const AValue: TBigInteger): TBigInteger;
    function &Xor(const AValue: TBigInteger): TBigInteger;
    function &Not(): TBigInteger;
    function AndNot(const AValue: TBigInteger): TBigInteger;
    function TestBit(const AN: Int32): Boolean;
    function SetBit(const AN: Int32): TBigInteger;
    function ClearBit(const AN: Int32): TBigInteger;
    function FlipBit(const AN: Int32): TBigInteger;
    function FlipExistingBit(const AN: Int32): TBigInteger;
    function GetLowestSetBit(): Int32;

    // Comparison operations
    function CompareTo(const AValue: TBigInteger): Int32; overload;
    function Equals(const AValue: TBigInteger): Boolean;
    function Max(const AValue: TBigInteger): TBigInteger;
    function Min(const AValue: TBigInteger): TBigInteger;

    // Conversion methods
    function ToByteArray(): TCryptoLibByteArray;
    function ToByteArrayUnsigned(): TCryptoLibByteArray;
    function ToByteArrayInternal(const AUnsigned: Boolean): TCryptoLibByteArray;
    function GetLengthofByteArray(): Int32;
    function GetLengthofByteArrayUnsigned(): Int32;
    function ToString(): String; overload;
    function ToString(const ARadix: Int32): String; overload;
    procedure ToStringRecursive(var ASb: String; const ARadix: Int32; const AModuli: TCryptoLibGenericArray<TBigInteger>; const AScale: Int32; const APos: TBigInteger);

    // Utility methods
    function IsProbablePrime(const ACertainty: Int32): Boolean; overload;
    function IsProbablePrime(const ACertainty: Int32;
      const ARandomlySelected: Boolean): Boolean; overload;
    function RabinMillerTest(const ACertainty: Int32;
      const ARandom: IRandom): Boolean; overload;
    function RabinMillerTest(const ACertainty: Int32; const ARandom: IRandom;
      const ARandomlySelected: Boolean): Boolean; overload;
    function NextProbablePrime(): TBigInteger;
    function IsEven(): Boolean;

    // Instance Properties
    property IsInitialized: Boolean read GetIsInitialized;
    property Int32Value: Int32 read GetInt32Value;
    property Int64Value: Int64 read GetInt64Value;
    property SignValue: Int32 read GetSignValue;
    property BitLength: Int32 read GetBitLength;
    property BitCount: Int32 read GetBitCount;

    // Constructors (instance constructors)
    constructor Create(const AValue: String); overload;
    constructor Create(const AValue: String; const ARadix: Int32); overload;
    constructor Create(const ABytes: TCryptoLibByteArray); overload;
    constructor Create(const ABytes: TCryptoLibByteArray; const ABigEndian: Boolean); overload;
    constructor Create(const ABytes: TCryptoLibByteArray; const AOffset, ALength: Int32); overload;
    constructor Create(const ABytes: TCryptoLibByteArray; const AOffset, ALength: Int32; const ABigEndian: Boolean); overload;
    constructor Create(const ASign: Int32; const ABytes: TCryptoLibByteArray); overload;
    constructor Create(const ASign: Int32; const ABytes: TCryptoLibByteArray; const ABigEndian: Boolean); overload;
    constructor Create(const ASign: Int32; const ABytes: TCryptoLibByteArray; const AOffset, ALength: Int32); overload;
    constructor Create(const ASign: Int32; const ABytes: TCryptoLibByteArray; const AOffset, ALength: Int32; const ABigEndian: Boolean); overload;
    constructor Create(const ASizeInBits: Int32; const ARandom: IRandom); overload;
    constructor Create(const ABitLength, ACertainty: Int32; const ARandom: IRandom); overload;

    /// <summary>
    /// Returns Default(TBigInteger) - an uninitialized record
    /// </summary>
    class function GetDefault(): TBigInteger; static;

    // Static factory methods
    class function ValueOf(const AValue: Int64): TBigInteger; static;
    class function Arbitrary(const ASizeInBits: Int32): TBigInteger; static;
    class function ProbablePrime(const ABitLength: Int32; const ARandom: IRandom): TBigInteger; static;

    // Class properties (public, exposing class vars)
    class property Zero: TBigInteger read FZero;
    class property One: TBigInteger read FOne;
    class property Two: TBigInteger read FTwo;
    class property Three: TBigInteger read FThree;
    class property Four: TBigInteger read FFour;
    class property Five: TBigInteger read FFive;
    class property Six: TBigInteger read FSix;
    class property Seven: TBigInteger read FSeven;
    class property Eight: TBigInteger read FEight;
    class property Nine: TBigInteger read FNine;
    class property Ten: TBigInteger read FTen;
    class property PrimeLists: TCryptoLibMatrixInt32Array read FPrimeLists;
    class property PrimeProducts: TCryptoLibInt32Array read FPrimeProducts;
    class property SmallConstants: TCryptoLibGenericArray<TBigInteger> read FSmallConstants;
    class property Radix2: TBigInteger read FRadix2;
    class property Radix2E: TBigInteger read FRadix2E;
    class property Radix8: TBigInteger read FRadix8;
    class property Radix8E: TBigInteger read FRadix8E;
    class property Radix10: TBigInteger read FRadix10;
    class property Radix10E: TBigInteger read FRadix10E;
    class property Radix16: TBigInteger read FRadix16;
    class property Radix16E: TBigInteger read FRadix16E;

    /// <summary>
    /// Computes the Jacobi symbol (a/n) for odd positive n.
    /// </summary>
    class function Jacobi(const AA, AN: TBigInteger): Int32; static;
    class procedure Boot; static;
  end;

implementation

uses
  ClpMod,
  ClpSecureRandom;

{ TBigInteger }

class procedure TBigInteger.Boot;
var
  I, J, LProduct: Int32;
  LPrimeList: TCryptoLibInt32Array;
  LSmallConstant: TBigInteger;
  LByteVal: UInt32;
  LBitLen: Byte;
  LZeroMagnitude: TCryptoLibUInt32Array;
begin
  TSecureRandom.Boot;

  System.SetLength(LZeroMagnitude, 0);
  FZero := TBigInteger.Create(0, LZeroMagnitude, False);
  FZero.FNBits := 0;
  FZero.FNBitLength := 0;

  // Initialize SmallConstants array
  System.SetLength(FSmallConstants, 17);
  FSmallConstants[0] := FZero;

  // Initialize small constants 1-16
  for I := 1 to 16 do
  begin
    LSmallConstant := CreateUValueOf(UInt32(I));
    LSmallConstant.FNBits := PopCount(UInt32(I));
    LSmallConstant.FNBitLength := BitLen(UInt32(I));
    FSmallConstants[I] := LSmallConstant;
  end;

  // Set named constants
  FOne := FSmallConstants[1];
  FTwo := FSmallConstants[2];
  FThree := FSmallConstants[3];
  FFour := FSmallConstants[4];
  FFive := FSmallConstants[5];
  FSix := FSmallConstants[6];
  FSeven := FSmallConstants[7];
  FEight := FSmallConstants[8];
  FNine := FSmallConstants[9];
  FTen := FSmallConstants[10];

  // Initialize PrimeLists
  System.SetLength(FPrimeLists, 64);
  FPrimeLists[0] := TCryptoLibInt32Array.Create(3, 5, 7, 11, 13, 17, 19, 23);
  FPrimeLists[1] := TCryptoLibInt32Array.Create(29, 31, 37, 41, 43);
  FPrimeLists[2] := TCryptoLibInt32Array.Create(47, 53, 59, 61, 67);
  FPrimeLists[3] := TCryptoLibInt32Array.Create(71, 73, 79, 83);
  FPrimeLists[4] := TCryptoLibInt32Array.Create(89, 97, 101, 103);
  FPrimeLists[5] := TCryptoLibInt32Array.Create(107, 109, 113, 127);
  FPrimeLists[6] := TCryptoLibInt32Array.Create(131, 137, 139, 149);
  FPrimeLists[7] := TCryptoLibInt32Array.Create(151, 157, 163, 167);
  FPrimeLists[8] := TCryptoLibInt32Array.Create(173, 179, 181, 191);
  FPrimeLists[9] := TCryptoLibInt32Array.Create(193, 197, 199, 211);
  FPrimeLists[10] := TCryptoLibInt32Array.Create(223, 227, 229);
  FPrimeLists[11] := TCryptoLibInt32Array.Create(233, 239, 241);
  FPrimeLists[12] := TCryptoLibInt32Array.Create(251, 257, 263);
  FPrimeLists[13] := TCryptoLibInt32Array.Create(269, 271, 277);
  FPrimeLists[14] := TCryptoLibInt32Array.Create(281, 283, 293);
  FPrimeLists[15] := TCryptoLibInt32Array.Create(307, 311, 313);
  FPrimeLists[16] := TCryptoLibInt32Array.Create(317, 331, 337);
  FPrimeLists[17] := TCryptoLibInt32Array.Create(347, 349, 353);
  FPrimeLists[18] := TCryptoLibInt32Array.Create(359, 367, 373);
  FPrimeLists[19] := TCryptoLibInt32Array.Create(379, 383, 389);
  FPrimeLists[20] := TCryptoLibInt32Array.Create(397, 401, 409);
  FPrimeLists[21] := TCryptoLibInt32Array.Create(419, 421, 431);
  FPrimeLists[22] := TCryptoLibInt32Array.Create(433, 439, 443);
  FPrimeLists[23] := TCryptoLibInt32Array.Create(449, 457, 461);
  FPrimeLists[24] := TCryptoLibInt32Array.Create(463, 467, 479);
  FPrimeLists[25] := TCryptoLibInt32Array.Create(487, 491, 499);
  FPrimeLists[26] := TCryptoLibInt32Array.Create(503, 509, 521);
  FPrimeLists[27] := TCryptoLibInt32Array.Create(523, 541, 547);
  FPrimeLists[28] := TCryptoLibInt32Array.Create(557, 563, 569);
  FPrimeLists[29] := TCryptoLibInt32Array.Create(571, 577, 587);
  FPrimeLists[30] := TCryptoLibInt32Array.Create(593, 599, 601);
  FPrimeLists[31] := TCryptoLibInt32Array.Create(607, 613, 617);
  FPrimeLists[32] := TCryptoLibInt32Array.Create(619, 631, 641);
  FPrimeLists[33] := TCryptoLibInt32Array.Create(643, 647, 653);
  FPrimeLists[34] := TCryptoLibInt32Array.Create(659, 661, 673);
  FPrimeLists[35] := TCryptoLibInt32Array.Create(677, 683, 691);
  FPrimeLists[36] := TCryptoLibInt32Array.Create(701, 709, 719);
  FPrimeLists[37] := TCryptoLibInt32Array.Create(727, 733, 739);
  FPrimeLists[38] := TCryptoLibInt32Array.Create(743, 751, 757);
  FPrimeLists[39] := TCryptoLibInt32Array.Create(761, 769, 773);
  FPrimeLists[40] := TCryptoLibInt32Array.Create(787, 797, 809);
  FPrimeLists[41] := TCryptoLibInt32Array.Create(811, 821, 823);
  FPrimeLists[42] := TCryptoLibInt32Array.Create(827, 829, 839);
  FPrimeLists[43] := TCryptoLibInt32Array.Create(853, 857, 859);
  FPrimeLists[44] := TCryptoLibInt32Array.Create(863, 877, 881);
  FPrimeLists[45] := TCryptoLibInt32Array.Create(883, 887, 907);
  FPrimeLists[46] := TCryptoLibInt32Array.Create(911, 919, 929);
  FPrimeLists[47] := TCryptoLibInt32Array.Create(937, 941, 947);
  FPrimeLists[48] := TCryptoLibInt32Array.Create(953, 967, 971);
  FPrimeLists[49] := TCryptoLibInt32Array.Create(977, 983, 991);
  FPrimeLists[50] := TCryptoLibInt32Array.Create(997, 1009, 1013);
  FPrimeLists[51] := TCryptoLibInt32Array.Create(1019, 1021, 1031);
  FPrimeLists[52] := TCryptoLibInt32Array.Create(1033, 1039, 1049);
  FPrimeLists[53] := TCryptoLibInt32Array.Create(1051, 1061, 1063);
  FPrimeLists[54] := TCryptoLibInt32Array.Create(1069, 1087, 1091);
  FPrimeLists[55] := TCryptoLibInt32Array.Create(1093, 1097, 1103);
  FPrimeLists[56] := TCryptoLibInt32Array.Create(1109, 1117, 1123);
  FPrimeLists[57] := TCryptoLibInt32Array.Create(1129, 1151, 1153);
  FPrimeLists[58] := TCryptoLibInt32Array.Create(1163, 1171, 1181);
  FPrimeLists[59] := TCryptoLibInt32Array.Create(1187, 1193, 1201);
  FPrimeLists[60] := TCryptoLibInt32Array.Create(1213, 1217, 1223);
  FPrimeLists[61] := TCryptoLibInt32Array.Create(1229, 1231, 1237);
  FPrimeLists[62] := TCryptoLibInt32Array.Create(1249, 1259, 1277);
  FPrimeLists[63] := TCryptoLibInt32Array.Create(1279, 1283, 1289);

  // Initialize radix constants
  FRadix2 := FTwo;
  FRadix2E := FRadix2.Pow(Chunk2);
  FRadix8 := FEight;
  FRadix8E := FRadix8.Pow(Chunk8);
  FRadix10 := FTen;
  FRadix10E := FRadix10.Pow(Chunk10);
  FRadix16 := FSmallConstants[16];
  FRadix16E := FRadix16.Pow(Chunk16);

  // Initialize PrimeProducts
  System.SetLength(FPrimeProducts, System.Length(FPrimeLists));
  for I := 0 to System.Pred(System.Length(FPrimeLists)) do
  begin
    LPrimeList := FPrimeLists[I];
    LProduct := LPrimeList[0];
    for J := 1 to System.Pred(System.Length(LPrimeList)) do
    begin
      LProduct := LProduct * LPrimeList[J];
    end;
    FPrimeProducts[I] := LProduct;
  end;
end;

class constructor TBigInteger.Create;
begin
  Boot;
end;

class function TBigInteger.PopCount(const AValue: UInt32): Int32;
begin
  Result := TBitUtilities.PopCount(AValue);
end;

class function TBigInteger.BitLen(const AValue: Byte): Int32;
begin
  //Result := BitLengthTable[AValue];
  Result := 32 - TBitUtilities.NumberOfLeadingZeros(AValue);
end;

class function TBigInteger.BitLen(const AValue: UInt32): Int32;
var
  LT: UInt32;
begin
 (* LT := AValue shr 24;
  if LT <> 0 then
  begin
    Result := 24 + BitLengthTable[LT];
    Exit;
  end;
  LT := AValue shr 16;
  if LT <> 0 then
  begin
    Result := 16 + BitLengthTable[LT];
    Exit;
  end;
  LT := AValue shr 8;
  if LT <> 0 then
  begin
    Result := 8 + BitLengthTable[LT];
    Exit;
  end;
  Result := BitLengthTable[AValue]; *)
  Result := 32 - TBitUtilities.NumberOfLeadingZeros(AValue);
end;

class function TBigInteger.CreateUValueOf(const AValue: UInt32): TBigInteger;
var
  LMagnitude: TCryptoLibUInt32Array;
begin
  if AValue = 0 then
  begin
    Result := FZero;
    Exit;
  end;
  System.SetLength(LMagnitude, 1);
  LMagnitude[0] := AValue;
  Result := TBigInteger.Create(1, LMagnitude, False);
end;

class function TBigInteger.CreateUValueOf(const AValue: UInt64): TBigInteger;
var
  LMagnitude: TCryptoLibUInt32Array;
  LMSW, LLSW: UInt32;
begin
  LMSW := UInt32(AValue shr 32);
  LLSW := UInt32(AValue);
  if LMSW = 0 then
  begin
    Result := CreateUValueOf(LLSW);
    Exit;
  end;
  System.SetLength(LMagnitude, 2);
  LMagnitude[0] := LMSW;
  LMagnitude[1] := LLSW;
  Result := TBigInteger.Create(1, LMagnitude, False);
end;

class function TBigInteger.GetBytesLength(const ANBits: Int32): Int32;
begin
  Result := (ANBits + BitsPerByte - 1) div BitsPerByte;
end;

class function TBigInteger.CalcBitLength(const ASign, AIndx: Int32; const AMag: TCryptoLibUInt32Array): Int32;
var
  LIndx: Int32;
  LFirstMag: UInt32;
begin
  LIndx := AIndx;
  while True do
  begin
    if LIndx >= System.Length(AMag) then
    begin
      Result := 0;
      Exit;
    end;
    if AMag[LIndx] <> 0 then
      Break;
    System.Inc(LIndx);
  end;
  // bit length for everything after the first int
  Result := 32 * ((System.Length(AMag) - LIndx) - 1);
  // and determine bitlength of first int
  LFirstMag := AMag[LIndx];
  Result := Result + BitLen(LFirstMag);
  // Check for negative powers of two
  if (ASign < 0) and ((LFirstMag and (-LFirstMag)) = LFirstMag) then
  begin
    repeat
      System.Inc(LIndx);
      if LIndx >= System.Length(AMag) then
      begin
        System.Dec(Result);
        Break;
      end;
    until AMag[LIndx] <> 0;
  end;
end;

class function TBigInteger.CompareTo(const AXIndx: Int32; const AX: TCryptoLibUInt32Array; const AYIndx: Int32; const AY: TCryptoLibUInt32Array): Int32;
var
  LXIndx, LYIndx: Int32;
begin
  LXIndx := AXIndx;
  while (LXIndx <> System.Length(AX)) and (AX[LXIndx] = 0) do
    System.Inc(LXIndx);

  LYIndx := AYIndx;
  while (LYIndx <> System.Length(AY)) and (AY[LYIndx] = 0) do
    System.Inc(LYIndx);

  Result := CompareNoLeadingZeros(LXIndx, AX, LYIndx, AY);
end;

class function TBigInteger.CompareNoLeadingZeros(const AXIndx: Int32; const AX: TCryptoLibUInt32Array; const AYIndx: Int32; const AY: TCryptoLibUInt32Array): Int32;
var
  LDiff: Int32;
  LXIndx, LYIndx: Int32;
  LV1, LV2: UInt32;
begin
  LDiff := (System.Length(AX) - System.Length(AY)) - (AXIndx - AYIndx);
  if LDiff <> 0 then
  begin
    if LDiff < 0 then
      Result := -1
    else
      Result := 1;
    Exit;
  end;
  // lengths of magnitudes the same, test the magnitude values
  LXIndx := AXIndx;
  LYIndx := AYIndx;
  while LXIndx < System.Length(AX) do
  begin
    LV1 := AX[LXIndx];
    System.Inc(LXIndx);
    LV2 := AY[LYIndx];
    System.Inc(LYIndx);
    if LV1 <> LV2 then
    begin
      if LV1 < LV2 then
        Result := -1
      else
        Result := 1;
      Exit;
    end;
  end;
  Result := 0;
end;

class function TBigInteger.IsEqualMagnitude(const AX: TCryptoLibUInt32Array; const AY: TCryptoLibUInt32Array): Boolean;
var
  I: Int32;
begin
  if System.Length(AX) <> System.Length(AY) then
  begin
    Result := False;
    Exit;
  end;
  for I := 0 to System.Pred(System.Length(AX)) do
  begin
    if AX[I] <> AY[I] then
    begin
      Result := False;
      Exit;
    end;
  end;
  Result := True;
end;

class function TBigInteger.MakeMagnitudeBE(const ABytes: TCryptoLibByteArray; const AOffset, ALength: Int32): TCryptoLibUInt32Array;
var
  LEnd, LStart, LNBytes, LNInts, LFirst, I: Int32;
  LMagnitude: TCryptoLibUInt32Array;
  LPBytes: PByte;
begin
  LEnd := AOffset + ALength;
  // strip leading zeros
  LStart := AOffset;
  while (LStart < LEnd) and (ABytes[LStart] = 0) do
  begin
    System.Inc(LStart);
  end;
  LNBytes := LEnd - LStart;
  if LNBytes <= 0 then
  begin
    System.SetLength(Result, 0);
    Exit;
  end;
  LNInts := (LNBytes + BytesPerInt - 1) div BytesPerInt;
  System.SetLength(LMagnitude, LNInts);
  LFirst := ((LNBytes - 1) mod BytesPerInt) + 1;
  LPBytes := @ABytes[LStart];
  // Read first partial UInt32
  if LFirst = 1 then
    LMagnitude[0] := UInt32(LPBytes^)
  else if LFirst = 2 then
    LMagnitude[0] := (UInt32(LPBytes^) shl 8) or UInt32((LPBytes + 1)^)
  else if LFirst = 3 then
    LMagnitude[0] := (UInt32(LPBytes^) shl 16) or (UInt32((LPBytes + 1)^) shl 8) or UInt32((LPBytes + 2)^)
  else
    LMagnitude[0] := TConverters.ReadBytesAsUInt32BE(LPBytes, 0);
  // Read remaining full UInt32s
  for I := 1 to System.Pred(LNInts) do
  begin
    LMagnitude[I] := TConverters.ReadBytesAsUInt32BE(LPBytes, LFirst + (I - 1) * BytesPerInt);
  end;
  Result := LMagnitude;
end;

class function TBigInteger.MakeMagnitudeLE(const ABytes: TCryptoLibByteArray; const AOffset, ALength: Int32): TCryptoLibUInt32Array;
var
  LLast, LNInts, LPartial, LFirst, LPos, I: Int32;
  LMagnitude: TCryptoLibUInt32Array;
  LPBytes: PByte;
begin
  // strip leading zeros (from the end in little-endian)
  LLast := ALength;
  System.Dec(LLast);
  while (LLast >= 0) and (ABytes[AOffset + LLast] = 0) do
  begin
    System.Dec(LLast);
  end;
  if LLast < 0 then
  begin
    System.SetLength(Result, 0);
    Exit;
  end;
  LNInts := (LLast + BytesPerInt) div BytesPerInt;
  System.SetLength(LMagnitude, LNInts);
  LPartial := LLast mod BytesPerInt;
  LFirst := LPartial + 1;
  LPos := AOffset + LLast - LPartial;
  LPBytes := @ABytes[LPos];
  // Read first partial UInt32
 // LMagnitude[0] := TConverters.ReadBytesAsUInt32LE(LPBytes, LFirst);
  // Read first partial UInt32
  if LFirst = 1 then
    LMagnitude[0] := UInt32(LPBytes^)
  else if LFirst = 2 then
    LMagnitude[0] := UInt32(LPBytes^) or (UInt32((LPBytes + 1)^) shl 8)
  else if LFirst = 3 then
    LMagnitude[0] := UInt32(LPBytes^) or (UInt32((LPBytes + 1)^) shl 8) or (UInt32((LPBytes + 2)^) shl 16)
  else
    LMagnitude[0] := TConverters.ReadBytesAsUInt32LE(LPBytes, 0);
  // Read remaining full UInt32s
  for I := 1 to System.Pred(LNInts) do
  begin
    LPos := LPos - BytesPerInt;
    LMagnitude[I] := TConverters.ReadBytesAsUInt32LE(@ABytes[LPos], 0);
  end;
  Result := LMagnitude;
end;

class function TBigInteger.InitBE(const ABytes: TCryptoLibByteArray; const AOffset, ALength: Int32; out ASign: Int32): TCryptoLibUInt32Array;
var
  LEnd, LIBVal, LNBytes, LIndex: Int32;
  LInverse: TCryptoLibByteArray;
begin
  // TODO Move this processing into MakeMagnitudeBE (provide sign argument)
  if Int8(ABytes[AOffset]) >= 0 then
  begin
    Result := MakeMagnitudeBE(ABytes, AOffset, ALength);
    if System.Length(Result) > 0 then
      ASign := 1
    else
      ASign := 0;
    Exit;
  end;
  ASign := -1;
  LEnd := AOffset + ALength;
  // strip leading sign bytes
  LIBVal := AOffset;
  while (LIBVal < LEnd) and (Int8(ABytes[LIBVal]) = -1) do
  begin
    System.Inc(LIBVal);
  end;
  if LIBVal >= LEnd then
  begin
    Result := FOne.FMagnitude;
    Exit;
  end;
  LNBytes := LEnd - LIBVal;
  System.SetLength(LInverse, LNBytes);
  LIndex := 0;
  while LIndex < LNBytes do
  begin
    LInverse[LIndex] := Byte(not ABytes[LIBVal]);
    System.Inc(LIndex);
    System.Inc(LIBVal);
  end;
  while True do
  begin
    System.Dec(LIndex);
    if (LIndex < 0) or (LInverse[LIndex] <> $FF) then
      Break;
    LInverse[LIndex] := 0;
  end;
  if LIndex >= 0 then
    System.Inc(LInverse[LIndex]);
  Result := MakeMagnitudeBE(LInverse, 0, System.Length(LInverse));
end;

class function TBigInteger.InitLE(const ABytes: TCryptoLibByteArray; const AOffset, ALength: Int32; out ASign: Int32): TCryptoLibUInt32Array;
var
  LEnd, LLast, LNBytes, LIndex: Int32;
  LInverse: TCryptoLibByteArray;
begin
  LEnd := AOffset + ALength;
  // TODO Move this processing into MakeMagnitudeLE (provide sign argument)
  if Int8(ABytes[LEnd - 1]) >= 0 then
  begin
    Result := MakeMagnitudeLE(ABytes, AOffset, ALength);
    if System.Length(Result) > 0 then
      ASign := 1
    else
      ASign := 0;
    Exit;
  end;
  ASign := -1;
  LLast := ALength;
  while True do
  begin
    System.Dec(LLast);
    if (LLast < 0) or (ABytes[AOffset + LLast] <> $FF) then
      Break;
  end;
  if LLast < 0 then
  begin
    Result := FOne.FMagnitude;
    Exit;
  end;

  LNBytes := LLast + 1;
  System.SetLength(LInverse, LNBytes);
  for LIndex := 0 to System.Pred(LNBytes) do
  begin
    LInverse[LIndex] := Byte(not ABytes[AOffset + LIndex]);
  end;

  LIndex := 0;
  while (LInverse[LIndex] = $FF) do
  begin
    LInverse[LIndex] := 0;
    System.Inc(LIndex);
  end;
  if LIndex < LNBytes then
    System.Inc(LInverse[LIndex]);
  Result := MakeMagnitudeLE(LInverse, 0, System.Length(LInverse));
end;

class function TBigInteger.AddMagnitudes(const AA: TCryptoLibUInt32Array; const AB: TCryptoLibUInt32Array): TCryptoLibUInt32Array;
var
  LTI, LVI: Int32;
  LM: UInt64;
  LResult: TCryptoLibUInt32Array;
  I: Int32;
begin
  LResult := AA;
  LTI := System.Length(LResult) - 1;
  LVI := System.Length(AB) - 1;
  LM := 0;
  while LVI >= 0 do
  begin
    LM := LM + UInt64(LResult[LTI]) + UInt64(AB[LVI]);
    System.Dec(LVI);
    LResult[LTI] := UInt32(LM);
    System.Dec(LTI);
    LM := LM shr 32;
  end;
  if LM <> 0 then
  begin
    while (LTI >= 0) do
    begin
      System.Inc(LResult[LTI]);
      if LResult[LTI] <> 0 then
        Break;
      System.Dec(LTI);
    end;
  end;
  Result := LResult;
end;

class function TBigInteger.Subtract(const AXStart: Int32; var AX: TCryptoLibUInt32Array; const AYStart: Int32; const AY: TCryptoLibUInt32Array): TCryptoLibUInt32Array;
var
  LIT, LIV: Int32;
  LM: Int64;
  LBorrow: Int32;
begin
  LIT := System.Length(AX);
  LIV := System.Length(AY);
  LM := 0;
  LBorrow := 0;
  repeat
    System.Dec(LIT);
    System.Dec(LIV);
    LM := Int64(AX[LIT] and UIMASK) - Int64(AY[LIV] and UIMASK) + LBorrow;
    AX[LIT] := UInt32(LM);
    LBorrow := Int32(TBitUtilities.Asr64(LM, 63));
  until LIV <= AYStart;
  if LBorrow <> 0 then
  begin
    while True do
    begin
      System.Dec(LIT);
      if LIT < AXStart then
        Break;
      System.Dec(AX[LIT]);
      if AX[LIT] <> UInt32.MaxValue then
        Break;
    end;
  end;
  Result := AX;
end;

class function TBigInteger.DoSubBigLil(const ABigMag, ALilMag: TCryptoLibUInt32Array): TCryptoLibUInt32Array;
begin
  Result := System.Copy(ABigMag);
  Subtract(0, Result, 0, ALilMag);
end;

class function TBigInteger.ShiftLeft(const AMag: TCryptoLibUInt32Array; const AN: Int32): TCryptoLibUInt32Array;
var
  LNInts, LNBits, LNBits2, LMagLen, I, J: Int32;
  LNewMag: TCryptoLibUInt32Array;
  LM, LNext, LHighBits: UInt32;
begin
  LNInts := UInt32(AN) shr 5;
  LNBits := AN and 31;
  LMagLen := System.Length(AMag);
  if LNBits = 0 then
  begin
    System.SetLength(LNewMag, LMagLen + LNInts);
    for I := 0 to System.Pred(LMagLen) do
    begin
      LNewMag[I] := AMag[I];
    end;
    TArrayUtilities.Fill<UInt32>(LNewMag, LMagLen, System.Length(LNewMag), UInt32(0));
  end
  else
  begin
    I := 0;
    LNBits2 := 32 - LNBits;
    LHighBits := AMag[0] shr LNBits2;
    if LHighBits <> 0 then
    begin
      System.SetLength(LNewMag, LMagLen + LNInts + 1);
      LNewMag[I] := LHighBits;
      System.Inc(I);
    end
    else
    begin
      System.SetLength(LNewMag, LMagLen + LNInts);
    end;
    LM := AMag[0];
    for J := 0 to System.Pred(LMagLen - 1) do
    begin
      LNext := AMag[J + 1];
      LNewMag[I] := (LM shl LNBits) or (LNext shr LNBits2);
      LM := LNext;
      System.Inc(I);
    end;
    LNewMag[I] := AMag[LMagLen - 1] shl LNBits;
  end;
  Result := LNewMag;
end;

class function TBigInteger.Multiply(var AX: TCryptoLibUInt32Array; const AY, AZ: TCryptoLibUInt32Array): TCryptoLibUInt32Array;
var
  I, J, LXBase: Int32;
  LA: Int64;
  LVal: Int64;
begin
  I := System.Length(AZ);
  if I < 1 then
  begin
    Result := AX;
    Exit;
  end;
  LXBase := System.Length(AX) - System.Length(AY);
  repeat
    System.Dec(I);
    LA := Int64(AZ[I]) and IMASK;
    LVal := 0;
    if LA <> 0 then
    begin
      for J := System.Length(AY) - 1 downto 0 do
      begin
        LVal := LVal + LA * Int64(AY[J] and UIMASK) + Int64(AX[LXBase + J] and UIMASK);
        AX[LXBase + J] := UInt32(LVal);
        LVal := Int64(UInt64(LVal) shr 32);
      end;
    end;
    System.Dec(LXBase);
    if LXBase >= 0 then
    begin
      AX[LXBase] := UInt32(LVal);
    end
    else
    begin
{$IFDEF DEBUG}
      System.Assert(LVal = 0);
{$ENDIF DEBUG}
    end;
  until I <= 0;
  Result := AX;
end;

class function TBigInteger.Square(var AW: TCryptoLibUInt32Array; const AX: TCryptoLibUInt32Array): TCryptoLibUInt32Array;
var
  I, J, LWBase: Int32;
  LC: UInt64;
  LV, LProd: UInt64;
begin
  LWBase := System.Length(AW) - 1;
  for I := System.Length(AX) - 1 downto 1 do
  begin
    LV := AX[I];
    LC := LV * LV + AW[LWBase];
    AW[LWBase] := UInt32(LC);
    LC := LC shr 32;
    for J := I - 1 downto 0 do
    begin
      LProd := LV * AX[J];
      System.Dec(LWBase);
      LC := LC + (AW[LWBase] and UIMASK) + (UInt32(LProd) shl 1);
      AW[LWBase] := UInt32(LC);
      LC := (LC shr 32) + (LProd shr 31);
    end;

    System.Dec(LWBase);
    LC := LC + AW[LWBase];
    AW[LWBase] := UInt32(LC);

    System.Dec(LWBase);
    if LWBase >= 0 then
    begin
      AW[LWBase] := UInt32(LC shr 32);
    end
    else
    begin
{$IFDEF DEBUG}
      System.Assert((LC shr 32) = 0);
{$ENDIF DEBUG}
    end;
    LWBase := LWBase + I;
  end;
  LV := AX[0];
  LC := LV * LV + AW[LWBase];
  AW[LWBase] := UInt32(LC);

  System.Dec(LWBase);
  if LWBase >= 0 then
  begin
    AW[LWBase] := AW[LWBase] + UInt32(LC shr 32);
  end
  else
  begin
{$IFDEF DEBUG}
    System.Assert((LC shr 32) = 0);
{$ENDIF DEBUG}
  end;
  Result := AW;
end;

function TBigInteger.QuickPow2Check(): Boolean;
begin
  Result := (FSign > 0) and (FNBits = 1);
end;

class procedure TBigInteger.ShiftRightOneInPlace(const AStart: Int32; var AMag: TCryptoLibUInt32Array);
var
  I: Int32;
  LM, LNext: UInt32;
begin
  I := System.Length(AMag);
  LM := AMag[I - 1];
  System.Dec(I);
  while I > AStart do
  begin
    LNext := AMag[I - 1];
    AMag[I] := (LM shr 1) or (LNext shl 31);
    LM := LNext;
    System.Dec(I);
  end;
  AMag[AStart] := AMag[AStart] shr 1;
end;

class procedure TBigInteger.ShiftRightInPlace(const AStart: Int32; var AMag: TCryptoLibUInt32Array; const AN: Int32);
var
  LNInts, LNBits, LMagEnd, LDelta, I: Int32;
  LNBits2: Int32;
  LM, LNext: UInt32;
begin
  LNInts := (UInt32(AN) shr 5) + AStart;
  LNBits := AN and 31;
  LMagEnd := System.Length(AMag) - 1;
  if LNInts <> AStart then
  begin
    LDelta := LNInts - AStart;
    for I := LMagEnd downto LNInts do
    begin
      AMag[I] := AMag[I - LDelta];
    end;
    TArrayUtilities.Fill<UInt32>(AMag, AStart, LNInts, UInt32(0));
  end;
  if LNBits <> 0 then
  begin
    LNBits2 := 32 - LNBits;
    LM := AMag[LMagEnd];
    for I := LMagEnd downto LNInts + 1 do
    begin
      LNext := AMag[I - 1];
      AMag[I] := (LM shr LNBits) or (LNext shl LNBits2);
      LM := LNext;
    end;
    AMag[LNInts] := AMag[LNInts] shr LNBits;
  end;
end;

class function TBigInteger.Divide(var AX: TCryptoLibUInt32Array; const AY: TCryptoLibUInt32Array): TCryptoLibUInt32Array;
var
  LXStart, LYStart, LXYCmp, LYBitLength, LXBitLength, LShift: Int32;
  LCount, LICount: TCryptoLibUInt32Array;
  LICountStart, LCStart, LCBitLength, I, J: Int32;
  LC: TCryptoLibUInt32Array;
  LFirstC, LFirstX: UInt32;
begin
  LXStart := 0;
  while (LXStart < System.Length(AX)) and (AX[LXStart] = 0) do
  begin
    System.Inc(LXStart);
  end;
  LYStart := 0;
  while (LYStart < System.Length(AY)) and (AY[LYStart] = 0) do
  begin
    System.Inc(LYStart);
  end;
  LXYCmp := CompareNoLeadingZeros(LXStart, AX, LYStart, AY);
  if LXYCmp > 0 then
  begin
    LYBitLength := CalcBitLength(1, LYStart, AY);
    LXBitLength := CalcBitLength(1, LXStart, AX);
    LShift := LXBitLength - LYBitLength;

    LICountStart := 0;
    LCStart := 0;
    LCBitLength := LYBitLength;

    if LShift > 0 then
    begin
      System.SetLength(LICount, (TBitUtilities.Asr32(LShift, 5)) + 1);
      LICount[0] := UInt32(1) shl (LShift mod 32);
      LC := ShiftLeft(AY, LShift);
      LCBitLength := LCBitLength + LShift;
    end
    else
    begin
      System.SetLength(LICount, 1);
      LICount[0] := 1;
      LC := System.Copy(AY, LYStart, System.Length(AY) - LYStart);
    end;

    System.SetLength(LCount, System.Length(LICount));

    while True do
    begin
      if (LCBitLength < LXBitLength) or (CompareNoLeadingZeros(LXStart, AX, LCStart, LC) >= 0) then
      begin
        Subtract(LXStart, AX, LCStart, LC);
        LCount := AddMagnitudes(LCount, LICount);

        while (AX[LXStart] = 0) do
        begin
          System.Inc(LXStart);
          if LXStart = System.Length(AX) then
          begin
            Result := LCount;
            Exit;
          end;
        end;
        LXBitLength := (32 * (System.Length(AX) - LXStart - 1)) + BitLen(AX[LXStart]);
        if LXBitLength <= LYBitLength then
        begin
          if LXBitLength < LYBitLength then
          begin
            Result := LCount;
            Exit;
          end;
          LXYCmp := CompareNoLeadingZeros(LXStart, AX, LYStart, AY);
          if LXYCmp <= 0 then
            Break;
        end;
      end;
      LShift := LCBitLength - LXBitLength;
      if LShift = 1 then
      begin
        LFirstC := LC[LCStart] shr 1;
        LFirstX := AX[LXStart];
        if LFirstC > LFirstX then
        begin
          System.Inc(LShift);
        end;
      end;
      if LShift < 2 then
      begin
        ShiftRightOneInPlace(LCStart, LC);
        System.Dec(LCBitLength);
        ShiftRightOneInPlace(LICountStart, LICount);
      end
      else
      begin
        ShiftRightInPlace(LCStart, LC, LShift);
        LCBitLength := LCBitLength - LShift;
        ShiftRightInPlace(LICountStart, LICount, LShift);
      end;
      while (LC[LCStart] = 0) do
      begin
        System.Inc(LCStart);
      end;

      while (LICount[LICountStart] = 0) do
      begin
        System.Inc(LICountStart);
      end;
    end;
  end
  else
  begin
    System.SetLength(LCount, 1);
    LCount[0] := 0;
  end;
  if LXYCmp = 0 then
  begin
    LCount := AddMagnitudes(LCount, FOne.FMagnitude);
    TArrayUtilities.Fill<UInt32>(AX, LXStart, System.Length(AX), UInt32(0));
  end;
  Result := LCount;
end;

class function TBigInteger.Remainder(var AX: TCryptoLibUInt32Array; const AY: TCryptoLibUInt32Array): TCryptoLibUInt32Array;
var
  LXStart, LYStart, LXYCmp, LYBitLength, LXBitLength, LShift: Int32;
  LCStart, LCBitLength, I: Int32;
  LC: TCryptoLibUInt32Array;
  LFirstC, LFirstX: UInt32;
begin
  LXStart := 0;
  while (LXStart < System.Length(AX)) and (AX[LXStart] = 0) do
  begin
    System.Inc(LXStart);
  end;
  LYStart := 0;
  while (LYStart < System.Length(AY)) and (AY[LYStart] = 0) do
  begin
    System.Inc(LYStart);
  end;
{$IFDEF DEBUG}
  System.Assert(LYStart < System.Length(AY));
{$ENDIF DEBUG}
  LXYCmp := CompareNoLeadingZeros(LXStart, AX, LYStart, AY);
  if LXYCmp > 0 then
  begin
    LYBitLength := CalcBitLength(1, LYStart, AY);
    LXBitLength := CalcBitLength(1, LXStart, AX);
    LShift := LXBitLength - LYBitLength;

    LCStart := 0;
    LCBitLength := LYBitLength;
    if LShift > 0 then
    begin
      LC := ShiftLeft(AY, LShift);
      LCBitLength := LCBitLength + LShift;
{$IFDEF DEBUG}
      System.Assert(LC[0] <> 0);
{$ENDIF DEBUG}
    end
    else
    begin
      LC := System.Copy(AY, LYStart, System.Length(AY) - LYStart);
    end;
    while True do
    begin
      if (LCBitLength < LXBitLength) or (CompareNoLeadingZeros(LXStart, AX, LCStart, LC) >= 0) then
      begin
        Subtract(LXStart, AX, LCStart, LC);

        while (AX[LXStart] = 0) do
        begin

          System.Inc(LXStart);
          if LXStart = System.Length(AX) then
          begin
            Result := AX;
            Exit;
          end;
        end;
        LXBitLength := (32 * (System.Length(AX) - LXStart - 1)) + BitLen(AX[LXStart]);
        if LXBitLength <= LYBitLength then
        begin
          if LXBitLength < LYBitLength then
          begin
            Result := AX;
            Exit;
          end;
          LXYCmp := CompareNoLeadingZeros(LXStart, AX, LYStart, AY);
          if LXYCmp <= 0 then
            Break;
        end;
      end;
      LShift := LCBitLength - LXBitLength;

      if LShift = 1 then
      begin
        LFirstC := LC[LCStart] shr 1;
        LFirstX := AX[LXStart];
        if LFirstC > LFirstX then
        begin
          System.Inc(LShift);
        end;
      end;
      if LShift < 2 then
      begin
        ShiftRightOneInPlace(LCStart, LC);
        System.Dec(LCBitLength);
      end
      else
      begin
        ShiftRightInPlace(LCStart, LC, LShift);
        LCBitLength := LCBitLength - LShift;
      end;

      while (LC[LCStart] = 0) do
      begin
        System.Inc(LCStart);
      end;
    end;
  end;
  if LXYCmp = 0 then
  begin
    TArrayUtilities.Fill<UInt32>(AX, LXStart, System.Length(AX), UInt32(0));
  end;
  Result := AX;
end;

function TBigInteger.LastNBits(const AN: Int32): TCryptoLibUInt32Array;
var
  LNumWords, LExcessBits, I: Int32;
begin
  if AN < 1 then
  begin
    Result := nil;
    Exit;
  end;

  LNumWords := (AN + BitsPerInt - 1) div BitsPerInt;
  LNumWords := Math.Min(LNumWords, System.Length(FMagnitude));
  System.SetLength(Result, LNumWords);

  // Copy last LNumWords from magnitude to result
  for I := 0 to System.Pred(LNumWords) do
  begin
    Result[I] := FMagnitude[System.Length(FMagnitude) - LNumWords + I];
  end;

  // Mask excess bits from result[0]
  LExcessBits := (LNumWords shl 5) - AN;
  if LExcessBits > 0 then
  begin
    Result[0] := Result[0] and (High(UInt32) shr LExcessBits);
  end;
end;

function TBigInteger.GetIsInitialized: Boolean;
begin
  Result := FIsInitialized;
end;

function TBigInteger.GetInt32Value: Int32;
var
  LN: Int32;
  LV: Int32;
begin
  if FSign = 0 then
  begin
    Result := 0;
    Exit;
  end;
  LN := System.Length(FMagnitude);
  LV := Int32(FMagnitude[LN - 1]);
  if FSign < 0 then
    Result := -LV
  else
    Result := LV;
end;

function TBigInteger.GetInt64Value: Int64;
var
  LN: Int32;
  LV: Int64;
begin
  if FSign = 0 then
  begin
    Result := 0;
    Exit;
  end;
  LN := System.Length(FMagnitude);
  LV := Int64(FMagnitude[LN - 1]) and IMASK;
  if LN > 1 then
  begin
    LV := LV or (Int64(FMagnitude[LN - 2]) and IMASK) shl 32;
  end;
  if FSign < 0 then
    Result := -LV
  else
    Result := LV;
end;

function TBigInteger.GetSignValue: Int32;
begin
  Result := FSign;
end;

function TBigInteger.GetBitLength: Int32;
begin
  if FNBitLength = -1 then
  begin
    if FSign = 0 then
      FNBitLength := 0
    else
      FNBitLength := CalcBitLength(FSign, 0, FMagnitude);
  end;
  Result := FNBitLength;
end;

function TBigInteger.GetBitCount: Int32;
var
  I: Int32;
  LSum: Int32;
begin
  if FNBits = -1 then
  begin
    if FSign < 0 then
    begin
      // TODO Optimise this case
      FNBits := &Not().BitCount;
    end
    else
    begin
      LSum := 0;
      for I := 0 to System.Pred(System.Length(FMagnitude)) do
      begin
        LSum := LSum + PopCount(FMagnitude[I]);
      end;
      FNBits := LSum;
    end;
  end;
  Result := FNBits;
end;

constructor TBigInteger.Create(const AValue: String);
begin
  Create(AValue, 10);
end;

constructor TBigInteger.Create(const AValue: String; const ARadix: Int32);
var
  LStr: String;
  LIndex, LChunk, LNext: Int32;
  LS: String;
  LUValue: UInt64;
  LBI: TBigInteger;
  LB: TBigInteger;
  LR, LRE: TBigInteger;
begin
  if System.Length(AValue) = 0 then
    raise EFormatCryptoLibException.Create(SZeroLengthBigInteger);
  if not (ARadix in [2, 8, 10, 16]) then
    raise EFormatCryptoLibException.Create(SInvalidRadix);
  LStr := AValue;
  LIndex := 1; // Pascal strings are 1-indexed
  FSign := 1;
  if (System.Length(LStr) > 0) and (LStr[1] = '-') then
  begin
    if System.Length(LStr) = 1 then
      raise EFormatCryptoLibException.Create(SZeroLengthBigInteger);
    FSign := -1;
    LIndex := 2;
  end;
  // Strip leading zeros
  while (LIndex <= System.Length(LStr)) and (LStr[LIndex] = '0') do
  begin
    System.Inc(LIndex);
  end;
  if LIndex > System.Length(LStr) then
  begin
    Self := FZero;
    Exit;
  end;
  // Determine chunk size and radix constants
  case ARadix of
    2:
    begin
      LChunk := Chunk2;
      LR := FRadix2;
      LRE := FRadix2E;
    end;
    8:
    begin
      LChunk := Chunk8;
      LR := FRadix8;
      LRE := FRadix8E;
    end;
    10:
    begin
      LChunk := Chunk10;
      LR := FRadix10;
      LRE := FRadix10E;
    end;
    16:
    begin
      LChunk := Chunk16;
      LR := FRadix16;
      LRE := FRadix16E;
    end;
  else
    // This should never be reached since we validate radix at the start
    raise EFormatCryptoLibException.Create(SInvalidRadix);
  end;
  LB := FZero;
  LNext := LIndex + LChunk;
  // Process chunks
  if LNext <= System.Length(LStr) then
  begin
    repeat
      LS := System.Copy(LStr, LIndex, LChunk);
      LUValue := ParseChunkToUInt64(LS, ARadix);
      LBI := CreateUValueOf(LUValue);
      // Validate digits for radix 2 and 8
      case ARadix of
        2:
        begin
          if LUValue >= 2 then
            raise EFormatCryptoLibException.Create('Bad character in radix 2 string: ' + LS);
          LB := LB.ShiftLeft(1);
        end;
        8:
        begin
          if LUValue >= 8 then
            raise EFormatCryptoLibException.Create('Bad character in radix 8 string: ' + LS);
          LB := LB.ShiftLeft(3);
        end;
        16:
        begin
          LB := LB.ShiftLeft(64);
        end;
      else
        // radix 10
        LB := LB.Multiply(LRE);
      end;
      LB := LB.Add(LBI);
      LIndex := LNext;
      LNext := LNext + LChunk;
    until LNext > System.Length(LStr);
  end;
  // Handle remaining digits
  if LIndex <= System.Length(LStr) then
  begin
    LS := System.Copy(LStr, LIndex, System.Length(LStr) - LIndex + 1);
    LUValue := ParseChunkToUInt64(LS, ARadix);
    LBI := CreateUValueOf(LUValue);
    if LB.FSign > 0 then
    begin
      case ARadix of
        2:
        begin
          // NB: Can't reach here since chunk2 = 1, parsing one char at a time
          // But handle it anyway for completeness
          LB := LB.ShiftLeft(System.Length(LS));
        end;
        8:
        begin
          // NB: Can't reach here since chunk8 = 1, parsing one char at a time
          // But handle it anyway for completeness
          LB := LB.ShiftLeft(System.Length(LS) * 3);
        end;
        16:
        begin
          LB := LB.ShiftLeft(System.Length(LS) shl 2);
        end;
      else
        // radix 10
        LB := LB.Multiply(LR.Pow(System.Length(LS)));
      end;
      LB := LB.Add(LBI);
    end
    else
    begin
      LB := LBI;
    end;
  end;
  // sign was already set based on '-' prefix
  FMagnitude := LB.FMagnitude;
  FNBits := -1;
  FNBitLength := -1;
  FIsInitialized := True;
end;

constructor TBigInteger.Create(const ABytes: TCryptoLibByteArray);
begin
  Create(ABytes, 0, System.Length(ABytes), True);
end;

constructor TBigInteger.Create(const ABytes: TCryptoLibByteArray; const ABigEndian: Boolean);
begin
  Create(ABytes, 0, System.Length(ABytes), ABigEndian);
end;

constructor TBigInteger.Create(const ABytes: TCryptoLibByteArray; const AOffset, ALength: Int32);
begin
  Create(ABytes, AOffset, ALength, True);
end;

constructor TBigInteger.Create(const ABytes: TCryptoLibByteArray; const AOffset, ALength: Int32; const ABigEndian: Boolean);
var
  LSign: Int32;
begin
  if ALength = 0 then
    raise EFormatCryptoLibException.Create(SZeroLengthBigInteger);
  if ABigEndian then
    FMagnitude := InitBE(ABytes, AOffset, ALength, LSign)
  else
    FMagnitude := InitLE(ABytes, AOffset, ALength, LSign);
  FSign := LSign;
  FNBits := -1;
  FNBitLength := -1;
  FIsInitialized := True;
end;

constructor TBigInteger.Create(const ASign: Int32; const ABytes: TCryptoLibByteArray);
begin
  Create(ASign, ABytes, 0, System.Length(ABytes), True);
end;

constructor TBigInteger.Create(const ASign: Int32; const ABytes: TCryptoLibByteArray; const ABigEndian: Boolean);
begin
  Create(ASign, ABytes, 0, System.Length(ABytes), ABigEndian);
end;

constructor TBigInteger.Create(const ASign: Int32; const ABytes: TCryptoLibByteArray; const AOffset, ALength: Int32);
begin
  Create(ASign, ABytes, AOffset, ALength, True);
end;

constructor TBigInteger.Create(const ASign: Int32; const ABytes: TCryptoLibByteArray; const AOffset, ALength: Int32; const ABigEndian: Boolean);
begin
  if (ASign < -1) or (ASign > 1) then
    raise EFormatCryptoLibException.Create(SInvalidSignValue);
  if ASign = 0 then
  begin
    FSign := 0;
    System.SetLength(FMagnitude, 0);
  end
  else
  begin
    if ABigEndian then
      FMagnitude := MakeMagnitudeBE(ABytes, AOffset, ALength)
    else
      FMagnitude := MakeMagnitudeLE(ABytes, AOffset, ALength);
    if System.Length(FMagnitude) < 1 then
      FSign := 0
    else
      FSign := ASign;
  end;
  FNBits := -1;
  FNBitLength := -1;
  FIsInitialized := True;
end;

constructor TBigInteger.Create(const ASizeInBits: Int32; const ARandom: IRandom);
var
  LNBytes, LXBits, I: Int32;
  LB: TCryptoLibByteArray;
  LByte: Byte;
begin
  if ASizeInBits < 0 then
    raise EArgumentCryptoLibException.Create(SSizeInBitsMustBeNonNegative);
  FNBits := -1;
  FNBitLength := -1;
  if ASizeInBits = 0 then
  begin
    FSign := 0;
    FIsInitialized := True;
    System.SetLength(FMagnitude, 0);
    Exit;
  end;
  LNBytes := GetBytesLength(ASizeInBits);
  System.SetLength(LB, LNBytes);
  ARandom.NextBytes(LB);
  // Strip off any excess bits in the MSB
  LXBits := (BitsPerByte * LNBytes) - ASizeInBits;
  LB[0] := LB[0] and Byte(255 shr LXBits);
  FMagnitude := MakeMagnitudeBE(LB, 0, System.Length(LB));
  if System.Length(FMagnitude) < 1 then
    FSign := 0
  else
    FSign := 1;
  FIsInitialized := True;
end;

constructor TBigInteger.Create(const ABitLength, ACertainty: Int32; const ARandom: IRandom);
var
  LNBytes, LXBits, J: Int32;
  LMask, LLead: Byte;
  LB: TCryptoLibByteArray;
begin
  if ABitLength < 2 then
    raise EArithmeticCryptoLibException.Create(SBitLengthLessThanTwo);
  FSign := 1;
  FNBitLength := ABitLength;
  if ABitLength = 2 then
  begin
    if ARandom.Next(2) = 0 then
      FMagnitude := FTwo.FMagnitude
    else
      FMagnitude := FThree.FMagnitude;
    FNBits := -1;
    FIsInitialized := True;
    Exit;
  end;
  LNBytes := GetBytesLength(ABitLength);
  System.SetLength(LB, LNBytes);
  LXBits := (BitsPerByte * LNBytes) - ABitLength;
  LMask := Byte(255 shr LXBits);
  LLead := Byte(1 shl (7 - LXBits));
  while True do
  begin
    ARandom.NextBytes(LB);

    // strip off any excess bits in the MSB
    LB[0] := LB[0] and LMask;

    // ensure the leading bit is 1 (to meet the strength requirement)
    LB[0] := LB[0] or LLead;

    // ensure the trailing bit is 1 (i.e. must be odd)
    LB[LNBytes - 1] := LB[LNBytes - 1] or 1;

    FMagnitude := MakeMagnitudeBE(LB, 0, System.Length(LB));
    FNBits := -1;
    FIsInitialized := True;

    if ACertainty < 1 then
      Break;

    if CheckProbablePrime(ACertainty, ARandom, True) then
      Break;

    // If failed, try to perturb the internal words
    for J := 1 to System.Pred(System.Length(FMagnitude) - 1) do
    begin
      FMagnitude[J] := FMagnitude[J] xor UInt32(ARandom.Next());
      if CheckProbablePrime(ACertainty, ARandom, True) then
        Exit;
    end;
  end;
end;

constructor TBigInteger.Create(const ASignum: Int32; const AMag: TCryptoLibUInt32Array; const ACheckMag: Boolean);
var
  I: Int32;
  LZeroMagnitude: TCryptoLibUInt32Array;
begin
  if not ACheckMag then
  begin
    FSign := ASignum;
    FMagnitude := AMag;
    FNBits := -1;
    FNBitLength := -1;
    FIsInitialized := True;
    Exit;
  end;
  I := 0;
  while (I < System.Length(AMag)) and (AMag[I] = 0) do
  begin
    System.Inc(I);
  end;
  if I = System.Length(AMag) then
  begin
    FSign := 0;
    System.SetLength(LZeroMagnitude, 0);
    FMagnitude := LZeroMagnitude;
  end
  else
  begin
    FSign := ASignum;
    if I = 0 then
    begin
      FMagnitude := AMag;
    end
    else
    begin
      // strip leading 0 words
      System.SetLength(FMagnitude, System.Length(AMag) - I);
      System.Move(AMag[I], FMagnitude[0], System.Length(FMagnitude) * System.SizeOf(UInt32));
    end;
  end;
  FNBits := -1;
  FNBitLength := -1;
  FIsInitialized := True;
end;

class function TBigInteger.ProbablePrime(const ABitLength: Int32;
  const ARandom: IRandom): TBigInteger;
begin
  Result := TBigInteger.Create(ABitLength, 100, ARandom);
end;

class function TBigInteger.ValueOf(const AValue: Int64): TBigInteger;
var
  LUValue: UInt64;
begin
  if AValue >= 0 then
  begin
    if AValue < System.Length(FSmallConstants) then
    begin
      Result := FSmallConstants[AValue];
      Exit;
    end;
    Result := CreateUValueOf(UInt64(AValue));
  end
  else
  begin
    if AValue = Low(Int64) then
    begin
      LUValue := UInt64(not AValue);
      Result := CreateUValueOf(LUValue).&Not();
    end
    else
    begin
      Result := ValueOf(-AValue).Negate();
    end;
  end;
end;

class function TBigInteger.Arbitrary(const ASizeInBits: Int32): TBigInteger;
begin
  Result := TBigInteger.Create(ASizeInBits, TSecureRandom.MasterRandom as IRandom);
end;

class function TBigInteger.GetDefault(): TBigInteger;
begin
  Result := Default(TBigInteger);
end;

function TBigInteger.AddToMagnitude(const AMagToAdd: TCryptoLibUInt32Array): TBigInteger;
var
  LBig, LSmall: TCryptoLibUInt32Array;
  LLimit: UInt32;
  LPossibleOverflow: Boolean;
  LBigCopy: TCryptoLibUInt32Array;
  I: Int32;
begin
  if System.Length(FMagnitude) < System.Length(AMagToAdd) then
  begin
    LBig := AMagToAdd;
    LSmall := FMagnitude;
  end
  else
  begin
    LBig := FMagnitude;
    LSmall := AMagToAdd;
  end;

  // Conservatively avoid over-allocation when no overflow possible
  LLimit := High(UInt32);
  if System.Length(LBig) = System.Length(LSmall) then
  begin
    LLimit := LLimit - LSmall[0];
  end;

  LPossibleOverflow := LBig[0] >= LLimit;

  if LPossibleOverflow then
  begin
    System.SetLength(LBigCopy, System.Length(LBig) + 1);
    System.Move(LBig[0], LBigCopy[1], System.Length(LBig) * System.SizeOf(UInt32));
  end
  else
  begin
    LBigCopy := System.Copy(LBig);
  end;

  LBigCopy := AddMagnitudes(LBigCopy, LSmall);

  Result := TBigInteger.Create(FSign, LBigCopy, LPossibleOverflow);
end;

function TBigInteger.Add(const AValue: TBigInteger): TBigInteger;
begin
  if FSign = 0 then
  begin
    Result := AValue;
    Exit;
  end;

  if FSign = AValue.FSign then
    Result := AddToMagnitude(AValue.FMagnitude)
  else if AValue.FSign = 0 then
    Result := Self
  else if AValue.FSign < 0 then
    Result := Subtract(AValue.Negate())
  else
    Result := AValue.Subtract(Negate());
end;

function TBigInteger.Subtract(const AValue: TBigInteger): TBigInteger;
var
  LCompare: Int32;
  LBigUn, LLilUn: TBigInteger;
begin
  if AValue.FSign = 0 then
  begin
    Result := Self;
    Exit;
  end;
  if FSign = 0 then
  begin
    Result := AValue.Negate();
    Exit;
  end;
  if FSign <> AValue.FSign then
  begin
    Result := Add(AValue.Negate());
    Exit;
  end;
  LCompare := CompareNoLeadingZeros(0, FMagnitude, 0, AValue.FMagnitude);
  if LCompare = 0 then
  begin
    Result := FZero;
    Exit;
  end;
  if LCompare < 0 then
  begin
    LBigUn := AValue;
    LLilUn := Self;
  end
  else
  begin
    LBigUn := Self;
    LLilUn := AValue;
  end;
  Result := TBigInteger.Create(FSign * LCompare, DoSubBigLil(LBigUn.FMagnitude, LLilUn.FMagnitude), True);
end;

function TBigInteger.Multiply(const AValue: TBigInteger): TBigInteger;
var
  LResLength: Int32;
  LRes: TCryptoLibUInt32Array;
  LResSign: Int32;
  I: Int32;
begin
  if Equals(AValue) then
  begin
    Result := Square();
    Exit;
  end;
  if (FSign and AValue.FSign) = 0 then
  begin
    Result := FZero;
    Exit;
  end;
  if AValue.QuickPow2Check() then
  begin
    // AValue is power of two
    Result := ShiftLeft(AValue.Abs().BitLength - 1);
    if AValue.FSign > 0 then
      // Result is already correct
    else
      Result := Result.Negate();
    Exit;
  end;
  if QuickPow2Check() then
  begin
    // Self is power of two
    Result := AValue.ShiftLeft(Abs().BitLength - 1);
    if FSign > 0 then
      // Result is already correct
    else
      Result := Result.Negate();
    Exit;
  end;
  LResLength := System.Length(FMagnitude) + System.Length(AValue.FMagnitude);
  System.SetLength(LRes, LResLength);
  TArrayUtilities.Fill<UInt32>(LRes, 0, System.Length(LRes), UInt32(0));
  Multiply(LRes, FMagnitude, AValue.FMagnitude);
  LResSign := FSign xor AValue.FSign xor 1;
  Result := TBigInteger.Create(LResSign, LRes, True);
end;

function TBigInteger.Square(): TBigInteger;
var
  LResLength: Int32;
  LRes: TCryptoLibUInt32Array;
begin
  if FSign = 0 then
  begin
    Result := FZero;
    Exit;
  end;
  if QuickPow2Check() then
  begin
    Result := ShiftLeft(Abs().BitLength - 1);
    Exit;
  end;
  LResLength := System.Length(FMagnitude) shl 1;
  if (FMagnitude[0] shr 16) = 0 then
  begin
    System.Dec(LResLength);
  end;
  System.SetLength(LRes, LResLength);
  Square(LRes, FMagnitude);
  Result := TBigInteger.Create(1, LRes, False);
end;

function TBigInteger.Divide(const AValue: TBigInteger): TBigInteger;
var
  LMag: TCryptoLibUInt32Array;
  I: Int32;
begin
  if AValue.FSign = 0 then
    raise EArithmeticCryptoLibException.Create('Division by zero error');
  if FSign = 0 then
  begin
    Result := FZero;
    Exit;
  end;
  if AValue.QuickPow2Check() then
  begin
    // AValue is power of two
    Result := Abs().ShiftRight(AValue.Abs().BitLength - 1);
    if AValue.FSign = FSign then
      // Result is already correct
    else
      Result := Result.Negate();
    Exit;
  end;
  // Clone magnitude
  LMag := System.Copy(FMagnitude);
  Result := TBigInteger.Create(FSign * AValue.FSign, Divide(LMag, AValue.FMagnitude), True);
end;

function TBigInteger.Remainder(const AValue: TBigInteger): TBigInteger;
var
  LResult: TCryptoLibUInt32Array;
  LVal, LRem: Int32;
begin
  if AValue.FSign = 0 then
    raise EArithmeticCryptoLibException.Create('Division by zero error');
  if FSign = 0 then
  begin
    Result := FZero;
    Exit;
  end;
  // For small values, use fast remainder method
  if System.Length(AValue.FMagnitude) = 1 then
  begin
    LVal := Int32(AValue.FMagnitude[0]);
    if LVal > 0 then
    begin
      if LVal = 1 then
      begin
        Result := FZero;
        Exit;
      end;
      LRem := Remainder(LVal);
      if LRem = 0 then
        Result := FZero
      else
        Result := TBigInteger.Create(FSign, [UInt32(LRem)], False);
      Exit;
    end;
  end;

  if CompareNoLeadingZeros(0, FMagnitude, 0, AValue.FMagnitude) < 0 then
  begin
    Result := Self;
    Exit;
  end;

  if AValue.QuickPow2Check() then
  begin
    LResult := LastNBits(AValue.Abs().BitLength - 1);
  end
  else
  begin
    LResult := System.Copy(FMagnitude);
    LResult := Remainder(LResult, AValue.FMagnitude);
  end;
  Result := TBigInteger.Create(FSign, LResult, True);
end;

function TBigInteger.DivideAndRemainder(const AValue: TBigInteger): TCryptoLibGenericArray<TBigInteger>;
var
  LRemainder, LQuotient: TCryptoLibUInt32Array;
  LE: Int32;
begin
  if AValue.FSign = 0 then
    raise EArithmeticCryptoLibException.Create('Division by zero error');
  System.SetLength(Result, 2);
  if FSign = 0 then
  begin
    Result[0] := FZero;
    Result[1] := FZero;
    Exit;
  end
  else if AValue.QuickPow2Check() then
  begin
    // AValue is power of two
    LE := AValue.Abs().BitLength - 1;
    Result[0] := Abs().ShiftRight(LE);
    if AValue.FSign <> FSign then
      Result[0] := Result[0].Negate();
    Result[1] := TBigInteger.Create(FSign, LastNBits(LE), True);
  end
  else
  begin
    LRemainder := System.Copy(FMagnitude);
    LQuotient := Divide(LRemainder, AValue.FMagnitude);
    Result[0] := TBigInteger.Create(FSign * AValue.FSign, LQuotient, True);
    Result[1] := TBigInteger.Create(FSign, LRemainder, True);
  end;
end;

function TBigInteger.&Mod(const AM: TBigInteger): TBigInteger;
var
  LBiggie: TBigInteger;
begin
  if AM.FSign < 1 then
    raise EArithmeticCryptoLibException.Create(SModulusMustBePositive);
  LBiggie := Remainder(AM);
  if LBiggie.FSign >= 0 then
    Result := LBiggie
  else
    Result := LBiggie.Add(AM);
end;

function TBigInteger.ModInverse(const AM: TBigInteger): TBigInteger;
var
  LD, LGcd, LX: TBigInteger;
begin
  if AM.FSign < 1 then
    raise EArithmeticCryptoLibException.Create(SModulusMustBePositive);
  if AM.QuickPow2Check() then
  begin
    Result := ModInversePow2(AM);
    Exit;
  end;
  LD := Remainder(AM);
  LGcd := ExtEuclid(LD, AM, LX);
  if not LGcd.Equals(FOne) then
    raise EArithmeticCryptoLibException.Create('Numbers not relatively prime.');
  if LX.FSign < 0 then
  begin
    LX := LX.Add(AM);
  end;
  Result := LX;
end;

function TBigInteger.ModDivide(const AY, AM: TBigInteger): TBigInteger;
begin
  Result := ModMultiply(AY.ModInverse(AM), AM);
end;

function TBigInteger.ModMultiply(const AY, AM: TBigInteger): TBigInteger;
begin
  Result := Multiply(AY).&Mod(AM);
end;

function TBigInteger.ModSquare(const AM: TBigInteger): TBigInteger;
begin
  Result := Square().&Mod(AM);
end;

function TBigInteger.ModPow(const AE, AM: TBigInteger): TBigInteger;
var
  LNegExp: Boolean;
  LE: TBigInteger;
  LYAccum: TCryptoLibUInt32Array;
begin
  if AM.FSign < 1 then
    raise EArithmeticCryptoLibException.Create(SModulusMustBePositive);
  if AM.Equals(FOne) then
  begin
    Result := FZero;
    Exit;
  end;
  if AE.FSign = 0 then
  begin
    Result := FOne;
    Exit;
  end;
  if FSign = 0 then
  begin
    Result := FZero;
    Exit;
  end;
  LNegExp := AE.FSign < 0;
  if LNegExp then
    LE := AE.Negate()
  else
    LE := AE;
  Result := &Mod(AM);
  if not LE.Equals(FOne) then
  begin
    if (AM.FMagnitude[System.Length(AM.FMagnitude) - 1] and 1) = 0 then
    begin
      // Even modulus - use Barrett reduction
      Result := ModPowBarrett(Result, LE, AM);
    end
    else
    begin
      // Odd modulus - use Montgomery reduction
      System.SetLength(LYAccum, System.Length(AM.FMagnitude) + 1);
      Result := ModPowMonty(LYAccum, Result, LE, AM, True);
    end;
  end;
  if LNegExp then
    Result := Result.ModInverse(AM);
end;

function TBigInteger.Pow(const AExponent: Int32): TBigInteger;
var
  LY, LZ: TBigInteger;
  LExp: Int32;
begin
  if AExponent <= 0 then
  begin
    if AExponent < 0 then
      raise EArithmeticCryptoLibException.Create('Negative exponent');
    Result := FOne;
    Exit;
  end;
  if FSign = 0 then
  begin
    Result := Self;
    Exit;
  end;
  if QuickPow2Check() then
  begin
    // This is a power of two
    // Check for overflow
    if (Int64(AExponent) * Int64(BitLength - 1)) > Int32.MaxValue then
      raise EArithmeticCryptoLibException.Create('Result too large');
    Result := FOne.ShiftLeft((AExponent * (BitLength - 1)));
    Exit;
  end;
  LY := FOne;
  LZ := Self;
  LExp := AExponent;
  while True do
  begin
    if (LExp and 1) = 1 then
    begin
      LY := LY.Multiply(LZ);
    end;
    LExp := TBitUtilities.Asr32(LExp, 1);
    if LExp = 0 then
      Break;
    LZ := LZ.Multiply(LZ);
  end;
  Result := LY;
end;

function TBigInteger.Gcd(const AValue: TBigInteger): TBigInteger;
var
  LR, LU, LV: TBigInteger;
begin
  if AValue.FSign = 0 then
  begin
    Result := Abs();
    Exit;
  end;
  if FSign = 0 then
  begin
    Result := AValue.Abs();
    Exit;
  end;
  LR := Self;
  LU := Self;
  LV := AValue;
  while LV.FSign <> 0 do
  begin
    LR := LU.&Mod(LV);
    LU := LV;
    LV := LR;
  end;
  Result := LU;
end;

function TBigInteger.Abs(): TBigInteger;
begin
  if FSign >= 0 then
    Result := Self
  else
    Result := Negate();
end;

function TBigInteger.Negate(): TBigInteger;
var
  I: Int32;
begin
  if FSign = 0 then
  begin
    Result := Self;
    Exit;
  end;

  Result := TBigInteger.Create(-FSign, FMagnitude, False);
end;

function TBigInteger.GetHashCode(): {$IFDEF DELPHI}Int32; {$ELSE}PtrInt; {$ENDIF DELPHI}
var
  LHC: Int32;
begin
  LHC := System.Length(FMagnitude);
  if System.Length(FMagnitude) > 0 then
  begin
    LHC := LHC xor Int32(FMagnitude[0]);
    if System.Length(FMagnitude) > 1 then
    begin
      LHC := LHC xor Int32(FMagnitude[System.Length(FMagnitude) - 1]);
    end;
  end;
  if FSign < 0 then
    Result := not LHC
  else
    Result := LHC;
end;

function TBigInteger.Int32ValueExact(): Int32;
begin
  // Match C# IntValueExact: if (BitLength > 31) throw; else return IntValue
  if BitLength > 31 then
  begin
    raise EArithmeticCryptoLibException.Create(SBigIntegerOutOfIntRange);
  end;

  Result := Int32Value;
end;

function TBigInteger.Int64ValueExact(): Int64;
begin
  // Match C# LongValueExact: if (BitLength > 63) throw; else return Int64Value
  if BitLength > 63 then
  begin
    raise EArithmeticCryptoLibException.Create(SBigIntegerOutOfLongRange);
  end;

  Result := Int64Value;
end;

function TBigInteger.ShiftLeft(const AN: Int32): TBigInteger;
var
  LNewMag: TCryptoLibUInt32Array;
begin
  if (FSign = 0) or (System.Length(FMagnitude) = 0) then
  begin
    Result := FZero;
    Exit;
  end;
  if AN = 0 then
  begin
    Result := Self;
    Exit;
  end;
  if AN < 0 then
  begin
    Result := ShiftRight(-AN);
    Exit;
  end;
  LNewMag := ShiftLeft(FMagnitude, AN);
  Result := TBigInteger.Create(FSign, LNewMag, True);
  if FNBits <> -1 then
  begin
    if FSign > 0 then
      Result.FNBits := FNBits
    else
      Result.FNBits := FNBits + AN;
  end;
  if FNBitLength <> -1 then
    Result.FNBitLength := FNBitLength + AN;
end;

function TBigInteger.ShiftRight(const AN: Int32): TBigInteger;
var
  LResultLength, LNInts, LNBits, LNBits2, LMagPos, I: Int32;
  LRes: TCryptoLibUInt32Array;
begin
  if AN = 0 then
  begin
    Result := Self;
    Exit;
  end;
  if AN < 0 then
  begin
    Result := ShiftLeft(-AN);
    Exit;
  end;
  if AN >= BitLength then
  begin
    if FSign < 0 then
      Result := FOne.Negate()
    else
      Result := FZero;
    Exit;
  end;
  LResultLength := TBitUtilities.Asr32((BitLength - AN + 31), 5);
  System.SetLength(LRes, LResultLength);
  LNInts := TBitUtilities.Asr32(AN, 5);
  LNBits := AN and 31;
  if LNBits = 0 then
  begin
    System.Move(FMagnitude[0], LRes[0], LResultLength * System.SizeOf(UInt32));
  end
  else
  begin
    LNBits2 := 32 - LNBits;
    LMagPos := System.Length(FMagnitude) - 1 - LNInts;
    for I := LResultLength - 1 downto 0 do
    begin
      LRes[I] := FMagnitude[LMagPos] shr LNBits;
      System.Dec(LMagPos);
      if LMagPos >= 0 then
      begin
        LRes[I] := LRes[I] or (FMagnitude[LMagPos] shl LNBits2);
      end;
    end;
  end;
{$IFDEF DEBUG}
  System.Assert(LRes[0] <> 0);
{$ENDIF DEBUG}
  Result := TBigInteger.Create(FSign, LRes, False);
end;

function TBigInteger.&And(const AValue: TBigInteger): TBigInteger;
var
  LAMag, LBMag: TCryptoLibUInt32Array;
  LResultNeg: Boolean;
  LResultLength, LAStart, LBStart, I: Int32;
  LAWord, LBWord: UInt32;
  LResultMag: TCryptoLibUInt32Array;
begin
  if (FSign = 0) or (AValue.FSign = 0) then
  begin
    Result := FZero;
    Exit;
  end;
  if FSign > 0 then
    LAMag := FMagnitude
  else
    LAMag := Add(FOne).FMagnitude;
  if AValue.FSign > 0 then
    LBMag := AValue.FMagnitude
  else
    LBMag := AValue.Add(FOne).FMagnitude;
  LResultNeg := (FSign < 0) and (AValue.FSign < 0);
  LResultLength := Math.Max(System.Length(LAMag), System.Length(LBMag));
  System.SetLength(LResultMag, LResultLength);
  LAStart := LResultLength - System.Length(LAMag);
  LBStart := LResultLength - System.Length(LBMag);
  for I := 0 to System.Pred(LResultLength) do
  begin
    if I >= LAStart then
      LAWord := LAMag[I - LAStart]
    else
      LAWord := 0;
    if I >= LBStart then
      LBWord := LBMag[I - LBStart]
    else
      LBWord := 0;
    if FSign < 0 then
      LAWord := not LAWord;
    if AValue.FSign < 0 then
      LBWord := not LBWord;
    LResultMag[I] := LAWord and LBWord;
    if LResultNeg then
      LResultMag[I] := not LResultMag[I];
  end;
  Result := TBigInteger.Create(1, LResultMag, True);
  if LResultNeg then
    Result := Result.&Not();
end;

function TBigInteger.&Or(const AValue: TBigInteger): TBigInteger;
var
  LAMag, LBMag: TCryptoLibUInt32Array;
  LResultNeg: Boolean;
  LResultLength, LAStart, LBStart, I: Int32;
  LAWord, LBWord: UInt32;
  LResultMag: TCryptoLibUInt32Array;
begin
  if FSign = 0 then
  begin
    Result := AValue;
    Exit;
  end;
  if AValue.FSign = 0 then
  begin
    Result := Self;
    Exit;
  end;
  if FSign > 0 then
    LAMag := FMagnitude
  else
    LAMag := Add(FOne).FMagnitude;
  if AValue.FSign > 0 then
    LBMag := AValue.FMagnitude
  else
    LBMag := AValue.Add(FOne).FMagnitude;
  LResultNeg := (FSign < 0) or (AValue.FSign < 0);
  LResultLength := Math.Max(System.Length(LAMag), System.Length(LBMag));
  System.SetLength(LResultMag, LResultLength);
  LAStart := LResultLength - System.Length(LAMag);
  LBStart := LResultLength - System.Length(LBMag);
  for I := 0 to System.Pred(LResultLength) do
  begin
    if I >= LAStart then
      LAWord := LAMag[I - LAStart]
    else
      LAWord := 0;
    if I >= LBStart then
      LBWord := LBMag[I - LBStart]
    else
      LBWord := 0;
    if FSign < 0 then
      LAWord := not LAWord;
    if AValue.FSign < 0 then
      LBWord := not LBWord;
    LResultMag[I] := LAWord or LBWord;
    if LResultNeg then
      LResultMag[I] := not LResultMag[I];
  end;
  Result := TBigInteger.Create(1, LResultMag, True);
  if LResultNeg then
    Result := Result.&Not();
end;

function TBigInteger.&Xor(const AValue: TBigInteger): TBigInteger;
var
  LAMag, LBMag: TCryptoLibUInt32Array;
  LResultNeg: Boolean;
  LResultLength, LAStart, LBStart, I: Int32;
  LAWord, LBWord: UInt32;
  LResultMag: TCryptoLibUInt32Array;
begin
  if FSign = 0 then
  begin
    Result := AValue;
    Exit;
  end;
  if AValue.FSign = 0 then
  begin
    Result := Self;
    Exit;
  end;
  if FSign > 0 then
    LAMag := FMagnitude
  else
    LAMag := Add(FOne).FMagnitude;
  if AValue.FSign > 0 then
    LBMag := AValue.FMagnitude
  else
    LBMag := AValue.Add(FOne).FMagnitude;
  LResultNeg := (FSign < 0) <> (AValue.FSign < 0);
  LResultLength := Math.Max(System.Length(LAMag), System.Length(LBMag));
  System.SetLength(LResultMag, LResultLength);
  LAStart := LResultLength - System.Length(LAMag);
  LBStart := LResultLength - System.Length(LBMag);
  for I := 0 to System.Pred(LResultLength) do
  begin
    if I >= LAStart then
      LAWord := LAMag[I - LAStart]
    else
      LAWord := 0;
    if I >= LBStart then
      LBWord := LBMag[I - LBStart]
    else
      LBWord := 0;
    if FSign < 0 then
      LAWord := not LAWord;
    if AValue.FSign < 0 then
      LBWord := not LBWord;
    LResultMag[I] := LAWord xor LBWord;
    if LResultNeg then
      LResultMag[I] := not LResultMag[I];
  end;
  Result := TBigInteger.Create(1, LResultMag, True);
  if LResultNeg then
    Result := Result.&Not();
end;

function TBigInteger.&Not(): TBigInteger;
begin
  Result := &Inc().Negate();
end;

function TBigInteger.AndNot(const AValue: TBigInteger): TBigInteger;
begin
  Result := &And(AValue.&Not());
end;

function TBigInteger.&Inc(): TBigInteger;
begin
  if FSign = 0 then
  begin
    Result := FOne;
    Exit;
  end;

  if FSign < 0 then
  begin
    Result := TBigInteger.Create(-1, DoSubBigLil(FMagnitude, FOne.FMagnitude), True);
    Exit;
  end;

  Result := AddToMagnitude(FOne.FMagnitude);
end;

function TBigInteger.TestBit(const AN: Int32): Boolean;
var
  LWordNum: Int32;
  LWord: UInt32;
begin
  if AN < 0 then
    raise EArithmeticCryptoLibException.Create(SBitAddressLessThanZero);
  if FSign < 0 then
  begin
    Result := not &Not().TestBit(AN);
    Exit;
  end;
  LWordNum := AN div 32;
  if LWordNum >= System.Length(FMagnitude) then
  begin
    Result := False;
    Exit;
  end;
  LWord := FMagnitude[System.Length(FMagnitude) - 1 - LWordNum];
  Result := ((LWord shr (AN mod 32)) and 1) <> 0;
end;

function TBigInteger.SetBit(const AN: Int32): TBigInteger;
begin
  if AN < 0 then
    raise EArithmeticCryptoLibException.Create(SBitAddressLessThanZero);
  if TestBit(AN) then
  begin
    Result := Self;
    Exit;
  end;
  // TODO: Handle negative values and zero
  if (FSign > 0) and (AN < (BitLength - 1)) then
  begin
    Result := FlipExistingBit(AN);
    Exit;
  end;
  Result := &Or(FOne.ShiftLeft(AN));
end;

function TBigInteger.ClearBit(const AN: Int32): TBigInteger;
begin
  if AN < 0 then
    raise EArithmeticCryptoLibException.Create(SBitAddressLessThanZero);
  if not TestBit(AN) then
  begin
    Result := Self;
    Exit;
  end;
  // TODO: Handle negative values
  if (FSign > 0) and (AN < (BitLength - 1)) then
  begin
    Result := FlipExistingBit(AN);
    Exit;
  end;
  Result := AndNot(FOne.ShiftLeft(AN));
end;

function TBigInteger.FlipBit(const AN: Int32): TBigInteger;
begin
  if AN < 0 then
    raise EArithmeticCryptoLibException.Create(SBitAddressLessThanZero);
  // TODO: Handle negative values and zero
  if (FSign > 0) and (AN < (BitLength - 1)) then
  begin
    Result := FlipExistingBit(AN);
    Exit;
  end;
  Result := &Xor(FOne.ShiftLeft(AN));
end;

function TBigInteger.FlipExistingBit(const AN: Int32): TBigInteger;
var
  LMag: TCryptoLibUInt32Array;
  I: Int32;
begin
  // Clone magnitude
  LMag := System.Copy(FMagnitude);
  LMag[System.Length(LMag) - 1 - (TBitUtilities.Asr32(AN, 5))] := LMag[System.Length(LMag) - 1 - (TBitUtilities.Asr32(AN, 5))] xor (UInt32(1) shl (AN and 31));
  Result := TBigInteger.Create(FSign, LMag, False);
end;

function TBigInteger.GetLowestSetBit(): Int32;
begin
  if FSign = 0 then
  begin
    Result := -1;
    Exit;
  end;
  Result := GetLowestSetBitMaskFirst(UInt32.MaxValue);
end;

function TBigInteger.GetLowestSetBitMaskFirst(const AFirstWordMaskX: UInt32): Int32;
var
  LW, LOffset: Int32;
  LWord: UInt32;
begin
  LW := System.Length(FMagnitude);
  LOffset := 0;
{$IFDEF DEBUG}
  System.Assert(FMagnitude[0] <> 0);
{$ENDIF DEBUG}
  System.Dec(LW);
  LWord := FMagnitude[LW] and AFirstWordMaskX;

  while LWord = 0 do
  begin
    System.Dec(LW);
    LWord := FMagnitude[LW];
    LOffset := LOffset + 32;
  end;

  LOffset := LOffset + TBitUtilities.NumberOfTrailingZeros(LWord);
 (*
  while (LWord and $FF) = 0 do
  begin
    LWord := LWord shr 8;
    LOffset := LOffset + 8;
  end;

  while (LWord and 1) = 0 do
  begin
    LWord := LWord shr 1;
    System.Inc(LOffset);
  end;   *)

  Result := LOffset;

end;

class function TBigInteger.Jacobi(const AA, AN: TBigInteger): Int32;
var
  LA, LN: TBigInteger;
  LTmp: TBigInteger;
  LJ: Int32;
  LNMod8: Int32;
begin
  // n must be positive and odd
  if (AN.FSign <= 0) or (not AN.TestBit(0)) then
    raise EArgumentCryptoLibException.Create('n must be positive and odd');

  // a := a mod n (ensure 0 <= a < n)
  LA := AA.Remainder(AN);
  if LA.FSign < 0 then
    LA := LA.Add(AN);

  LN := AN;
  LJ := 1;

  while LA.FSign <> 0 do
  begin
    // Extract factors of 2 from a
    while (LA.FSign <> 0) and (not LA.TestBit(0)) do
    begin
      LA := LA.ShiftRight(1);
      // If n mod 8 in {3,5}, flip sign
      LNMod8 := Int32(LN.FMagnitude[System.Length(LN.FMagnitude) - 1] and 7);
      if (LNMod8 = 3) or (LNMod8 = 5) then
        LJ := -LJ;
    end;

    // Swap a and n
    // quadratic reciprocity
    if (LA.TestBit(1)) and (LN.TestBit(1)) then
      LJ := -LJ;

    // Swap values
    LTmp := LA;
    LA := LN;
    LN := LTmp;

    LA := LA.Remainder(LN);
    if LA.FSign < 0 then
      LA := LA.Add(LN);
  end;

  if LN.Equals(FOne) then
    Result := LJ
  else
    Result := 0;
end;

class function TBigInteger.UInt32ToBin(const AValue: UInt32): String;
var
  LValue: UInt32;
  I: Int32;
begin
  if AValue = 0 then
  begin
    Result := '0';
    Exit;
  end;
  Result := '';
  LValue := AValue;
  while LValue > 0 do
  begin
    if (LValue and 1) = 1 then
      Result := '1' + Result
    else
      Result := '0' + Result;
    LValue := LValue shr 1;
  end;
end;

class function TBigInteger.Int32ToOct(const AValue: Int32): String;
var
  LValue: UInt32;
  LDigit: Int32;
begin
  if AValue = 0 then
  begin
    Result := '0';
    Exit;
  end;
  Result := '';
  LValue := UInt32(AValue);
  while LValue > 0 do
  begin
    LDigit := LValue mod 8;
    Result := IntToStr(LDigit) + Result;
    LValue := LValue div 8;
  end;
end;

class procedure TBigInteger.AppendZeroExtendedString(var ASb: String; const &AS: String; const AMinLength: Int32);
var
  LLen: Int32;
begin
  LLen := System.Length(&AS);
  while LLen < AMinLength do
  begin
    ASb := ASb + '0';
    System.Inc(LLen);
  end;
  ASb := ASb + &AS;
end;

class function TBigInteger.CreateWindowEntry(const AMult, AZeros: UInt32): UInt32;
var
  LMult, LZeros: UInt32;
  LTZ: Int32;
begin
{$IFDEF DEBUG}
  System.Assert(AMult > 0);
{$ENDIF DEBUG}

  LMult := AMult;
  LZeros := AZeros;
 (* while (LMult and 1) = 0 do
  begin
    LMult := LMult shr 1;
    System.Inc(LZeros);
  end; *)
  LTZ := TBitUtilities.NumberOfTrailingZeros(LMult);
  LMult := LMult shr LTZ;
  LZeros := LZeros + UInt32(LTZ);
  // Combine multiplier and zeros: mult | (zeros << 8)
  Result := LMult or (LZeros shl 8);
end;

class function TBigInteger.GetWindowList(const AMag: TCryptoLibUInt32Array; const AExtraBits: Int32): TCryptoLibUInt32Array;
var
  LV: UInt32;
  LLeadingBits, LTotalBits, LResultSize, LResultPos, LBitPos, I: Int32;
  LMult, LMultLimit, LZeros: UInt32;
begin
  LV := AMag[0];
{$IFDEF DEBUG}
  System.Assert(LV <> 0);
{$ENDIF DEBUG}
  LLeadingBits := BitLen(LV);
  LTotalBits := ((System.Length(AMag) - 1) shl 5) + LLeadingBits;
  LResultSize := (LTotalBits + AExtraBits) div (1 + AExtraBits) + 1;
  System.SetLength(Result, LResultSize);
  LResultPos := 0;
  LBitPos := 33 - LLeadingBits;
  LV := LV shl LBitPos;
  LMult := 1;
  LMultLimit := UInt32(1) shl AExtraBits;
  LZeros := 0;
  I := 0;
  while True do
  begin
    while LBitPos < 32 do
    begin
      if LMult < LMultLimit then
      begin
        LMult := (LMult shl 1) or (LV shr 31);
      end
      else if Int32(LV) < 0 then
      begin
        Result[LResultPos] := CreateWindowEntry(LMult, LZeros);
        System.Inc(LResultPos);
        LMult := 1;
        LZeros := 0;
      end
      else
      begin
        System.Inc(LZeros);
      end;
      LV := LV shl 1;
      System.Inc(LBitPos);
    end;
    System.Inc(I);
    if I = System.Length(AMag) then
    begin
      Result[LResultPos] := CreateWindowEntry(LMult, LZeros);
      System.Inc(LResultPos);
      Break;
    end;
    LV := AMag[I];
    LBitPos := 0;
  end;
  Result[LResultPos] := UInt32.MaxValue; // Sentinel value
end;

class function TBigInteger.MultiplyMontyNIsOne(const AX, AY, AM, AMDash: UInt32): UInt32;
var
  LCarry: UInt64;
  LT: UInt32;
  LUM: UInt64;
  LProd2: UInt64;
begin
  LCarry := UInt64(AX) * AY;
  LT := UInt32(LCarry) * AMDash;
  LUM := UInt64(AM);
  LProd2 := LUM * UInt64(LT);
  LCarry := LCarry + UInt32(LProd2);
{$IFDEF DEBUG}
  System.Assert(UInt32(LCarry) = 0);
{$ENDIF DEBUG}
  LCarry := (LCarry shr 32) + (LProd2 shr 32);
  if LCarry > LUM then
  begin
    LCarry := LCarry - LUM;
  end;
{$IFDEF DEBUG}
  System.Assert(LCarry < LUM);
{$ENDIF DEBUG}
  Result := UInt32(LCarry);
end;

class procedure TBigInteger.MontgomeryReduce(var AX: TCryptoLibUInt32Array; const AM: TCryptoLibUInt32Array; const AMDash: UInt32);
var
  LN, I, J: Int32;
  LX0: UInt32;
  LT: UInt64;
  LCarry: UInt64;
begin
  // NOTE: Not a general purpose reduction (which would allow x up to twice the bitlength of m)
{$IFDEF DEBUG}
  System.Assert(System.Length(AX) = System.Length(AM));
{$ENDIF DEBUG}
  LN := System.Length(AM);
  for I := LN - 1 downto 0 do
  begin
    LX0 := AX[LN - 1];
    LT := LX0 * AMDash;
    LCarry := (LT * AM[LN - 1]) + LX0;
{$IFDEF DEBUG}
    System.Assert(UInt32(LCarry) = 0);
{$ENDIF DEBUG}
    LCarry := LCarry shr 32;
    for J := LN - 2 downto 0 do
    begin
      LCarry := LCarry + ((LT * UInt64(AM[J])) + UInt64(AX[J]));
      AX[J + 1] := UInt32(LCarry);
      LCarry := LCarry shr 32;
    end;
    AX[0] := UInt32(LCarry);
{$IFDEF DEBUG}
    System.Assert(LCarry shr 32 = 0);
{$ENDIF DEBUG}
  end;
  if CompareTo(0, AX, 0, AM) >= 0 then
  begin
    Subtract(0, AX, 0, AM);
  end;
end;

class procedure TBigInteger.MultiplyMonty(var AA: TCryptoLibUInt32Array; var AX: TCryptoLibUInt32Array; const AY, AM: TCryptoLibUInt32Array; const AMDash: UInt32; const ASmallMontyModulus: Boolean);
var
  LN, I, J: Int32;
  LY0, LA0, LAMax: UInt32;
  LXI, LCarry, LT, LProd1, LProd2: UInt64;
begin
  // mDash = -m^(-1) mod b
  LN := System.Length(AM);
  if LN = 1 then
  begin
    AX[0] := MultiplyMontyNIsOne(AX[0], AY[0], AM[0], AMDash);
    Exit;
  end;
  LY0 := AY[LN - 1];
  // First iteration
  LXI := UInt64(AX[LN - 1]);
  LCarry := LXI * LY0;
  LT := UInt32(LCarry) * AMDash;
  LProd2 := LT * AM[LN - 1];
  LCarry := LCarry + UInt32(LProd2);
{$IFDEF DEBUG}
  System.Assert(UInt32(LCarry) = 0);
{$ENDIF DEBUG}
  LCarry := (LCarry shr 32) + (LProd2 shr 32);
  for J := LN - 2 downto 0 do
  begin
    LProd1 := LXI * UInt64(AY[J]);
    LProd2 := LT * UInt64(AM[J]);
    LCarry := LCarry + (LProd1 and UIMASK) + UInt32(LProd2);
    AA[J + 2] := UInt32(LCarry);
    LCarry := (LCarry shr 32) + (LProd1 shr 32) + (LProd2 shr 32);
  end;
  AA[1] := UInt32(LCarry);
  LAMax := UInt32(LCarry shr 32);
  // Remaining iterations
  for I := LN - 2 downto 0 do
  begin
    LA0 := AA[LN];
    LXI := UInt64(AX[I]);
    LProd1 := LXI * UInt64(LY0);
    LCarry := (LProd1 and UIMASK) + LA0;
    LT := UInt32(LCarry) * AMDash;
    LProd2 := LT * UInt64(AM[LN - 1]);
    LCarry := LCarry + UInt32(LProd2);
{$IFDEF DEBUG}
    System.Assert(UInt32(LCarry) = 0);
{$ENDIF DEBUG}
    LCarry := (LCarry shr 32) + (LProd1 shr 32) + (LProd2 shr 32);
    for J := LN - 2 downto 0 do
    begin
      LProd1 := LXI * UInt64(AY[J]);
      LProd2 := LT * UInt64(AM[J]);
      LCarry := LCarry + (LProd1 and UIMASK) + UInt32(LProd2) + UInt64(AA[J + 1]);
      AA[J + 2] := UInt32(LCarry);
      LCarry := (LCarry shr 32) + (LProd1 shr 32) + (LProd2 shr 32);
    end;
    LCarry := LCarry + UInt64(LAMax);
    AA[1] := UInt32(LCarry);
    LAMax := UInt32(LCarry shr 32);
  end;
  AA[0] := LAMax;
  if not ASmallMontyModulus and (CompareTo(0, AA, 0, AM) >= 0) then
  begin
    Subtract(0, AA, 0, AM);
  end;
  // Copy result back to x
  System.Move(AA[1], AX[0], LN * System.SizeOf(UInt32));
end;

class procedure TBigInteger.SquareMonty(var AA: TCryptoLibUInt32Array; var AX: TCryptoLibUInt32Array; const AM: TCryptoLibUInt32Array; const AMDash: UInt32; const ASmallMontyModulus: Boolean);
var
  LN, I, J: Int32;
  LX0, LA0, LAMax: UInt32;
  LXI, LCarry, LT, LProd1, LProd2: UInt64;
begin
  // mDash = -m^(-1) mod b
  LN := System.Length(AM);
  if LN = 1 then
  begin
    LX0 := AX[0];
    AX[0] := MultiplyMontyNIsOne(LX0, LX0, AM[0], AMDash);
    Exit;
  end;
  LX0 := AX[LN - 1];
  // First iteration
  LCarry := UInt64(LX0) * LX0;
  LT := UInt32(LCarry) * AMDash;
  LProd2 := LT * AM[LN - 1];
  LCarry := LCarry + UInt32(LProd2);
{$IFDEF DEBUG}
  System.Assert(UInt32(LCarry) = 0);
{$ENDIF DEBUG}
  LCarry := (LCarry shr 32) + (LProd2 shr 32);
  for J := LN - 2 downto 0 do
  begin
    LProd1 := UInt64(LX0) * AX[J];
    LProd2 := LT * AM[J];
    LCarry := LCarry + (LProd2 and UIMASK) + (UInt32(LProd1) shl 1);
    AA[J + 2] := UInt32(LCarry);
    LCarry := (LCarry shr 32) + (LProd1 shr 31) + (LProd2 shr 32);
  end;
  AA[1] := UInt32(LCarry);
  LAMax := UInt32(LCarry shr 32);
  // Remaining iterations
  for I := LN - 2 downto 0 do
  begin
    LA0 := AA[LN];
    LT := LA0 * AMDash;
    LCarry := LT * AM[LN - 1] + LA0;
{$IFDEF DEBUG}
    System.Assert(UInt32(LCarry) = 0);
{$ENDIF DEBUG}
    LCarry := LCarry shr 32;
    for J := LN - 2 downto I + 1 do
    begin
      LCarry := LCarry + LT * UInt64(AM[J]) + UInt64(AA[J + 1]);
      AA[J + 2] := UInt32(LCarry);
      LCarry := LCarry shr 32;
    end;
    LXI := UInt64(AX[I]);
    // Square term
    LProd1 := LXI * LXI;
    LProd2 := LT * UInt64(AM[I]);
    LCarry := LCarry + (LProd1 and UIMASK) + UInt32(LProd2) + UInt64(AA[I + 1]);
    AA[I + 2] := UInt32(LCarry);
    LCarry := (LCarry shr 32) + (LProd1 shr 32) + (LProd2 shr 32);
    // Cross terms
    for J := I - 1 downto 0 do
    begin
      LProd1 := LXI * UInt64(AX[J]);
      LProd2 := LT * UInt64(AM[J]);
      LCarry := LCarry + (LProd2 and UIMASK) + (UInt32(LProd1) shl 1) + UInt64(AA[J + 1]);
      AA[J + 2] := UInt32(LCarry);
      LCarry := (LCarry shr 32) + (LProd1 shr 31) + (LProd2 shr 32);
    end;
    LCarry := LCarry + UInt64(LAMax);
    AA[1] := UInt32(LCarry);
    LAMax := UInt32(LCarry shr 32);
  end;
  AA[0] := LAMax;
  if not ASmallMontyModulus and (CompareTo(0, AA, 0, AM) >= 0) then
  begin
    Subtract(0, AA, 0, AM);
  end;
  // Copy result back to x
  System.Move(AA[1], AX[0], LN * System.SizeOf(UInt32));
end;

class function TBigInteger.ParseChunkToUInt64(const AChunk: String; const ARadix: Int32): UInt64;
var
  I: Int32;
  LChar: Char;
  LDigit: UInt64;
begin
  Result := 0;
  for I := 1 to System.Length(AChunk) do
  begin
    LChar := AChunk[I];
    case ARadix of
      2:
      begin
        if (LChar < '0') or (LChar > '1') then
          raise EFormatCryptoLibException.Create('Bad character in radix 2 string: ' + AChunk);
        LDigit := Ord(LChar) - Ord('0');
      end;
      8:
      begin
        if (LChar < '0') or (LChar > '7') then
          raise EFormatCryptoLibException.Create('Bad character in radix 8 string: ' + AChunk);
        LDigit := Ord(LChar) - Ord('0');
      end;
      10:
      begin
        if (LChar < '0') or (LChar > '9') then
          raise EFormatCryptoLibException.Create('Bad character in radix 10 string: ' + AChunk);
        LDigit := Ord(LChar) - Ord('0');
      end;
      16:
      begin
        if (LChar >= '0') and (LChar <= '9') then
          LDigit := Ord(LChar) - Ord('0')
        else if (LChar >= 'A') and (LChar <= 'F') then
          LDigit := Ord(LChar) - Ord('A') + 10
        else if (LChar >= 'a') and (LChar <= 'f') then
          LDigit := Ord(LChar) - Ord('a') + 10
        else
          raise EFormatCryptoLibException.Create('Bad character in radix 16 string: ' + AChunk);
      end;
    else
      raise EFormatCryptoLibException.Create('Invalid radix');
    end;
    Result := Result * UInt64(ARadix) + LDigit;
  end;
end;

function TBigInteger.CompareTo(const AValue: TBigInteger): Int32;
begin
  if FSign < AValue.FSign then
    Result := -1
  else if FSign > AValue.FSign then
    Result := 1
  else if FSign = 0 then
    Result := 0
  else
    Result := FSign * CompareNoLeadingZeros(0, FMagnitude, 0, AValue.FMagnitude);
end;

function TBigInteger.Equals(const AValue: TBigInteger): Boolean;
begin
  Result := (FIsInitialized = AValue.FIsInitialized) and (FSign = AValue.FSign) and IsEqualMagnitude(FMagnitude, AValue.FMagnitude);
end;

function TBigInteger.Max(const AValue: TBigInteger): TBigInteger;
begin
  if CompareTo(AValue) > 0 then
    Result := Self
  else
    Result := AValue;
end;

function TBigInteger.Min(const AValue: TBigInteger): TBigInteger;
begin
  if CompareTo(AValue) < 0 then
    Result := Self
  else
    Result := AValue;
end;

function TBigInteger.ToByteArray(): TCryptoLibByteArray;
begin
  Result := ToByteArrayInternal(False);
end;

function TBigInteger.ToByteArrayUnsigned(): TCryptoLibByteArray;
begin
  Result := ToByteArrayInternal(True);
end;

function TBigInteger.GetLengthofByteArray(): Int32;
begin
  Result := GetBytesLength(BitLength + 1);
end;

function TBigInteger.GetLengthofByteArrayUnsigned(): Int32;
begin
  if SignValue < 0 then
    Result := GetBytesLength(BitLength + 1)
  else
    Result := GetBytesLength(BitLength);
end;

function TBigInteger.ToByteArrayInternal(const AUnsigned: Boolean): TCryptoLibByteArray;
var
  LNBits, LNBytes, LMagIndex, LBytesIndex, J: Int32;
  LLastMag: UInt32;
  LCarry: Boolean;
  LMag: UInt32;
begin
  Result := nil;
  if FSign = 0 then
  begin
    if AUnsigned then
      System.SetLength(Result, 0)
    else
    begin
      System.SetLength(Result, 1);
      Result[0] := 0;
    end;
    Exit;
  end;
  if AUnsigned and (FSign > 0) then
    LNBits := BitLength
  else
    LNBits := BitLength + 1;
  LNBytes := GetBytesLength(LNBits);
  System.SetLength(Result, LNBytes);
  LMagIndex := System.Length(FMagnitude);
  LBytesIndex := System.Length(Result);
  if FSign > 0 then
  begin
    while LMagIndex > 1 do
    begin
      System.Dec(LMagIndex);
      LMag := FMagnitude[LMagIndex];
      LBytesIndex := LBytesIndex - 4;
      TConverters.ReadUInt32AsBytesBE(LMag, Result, LBytesIndex);
    end;
    LLastMag := FMagnitude[0];
    while LLastMag > Byte.MaxValue do
    begin
      System.Dec(LBytesIndex);
      Result[LBytesIndex] := Byte(LLastMag);
      LLastMag := LLastMag shr 8;
    end;
    System.Dec(LBytesIndex);
    Result[LBytesIndex] := Byte(LLastMag);
  end
  else
  begin
    // sign < 0
    LCarry := True;
    while LMagIndex > 1 do
    begin
      System.Dec(LMagIndex);
      LMag := not FMagnitude[LMagIndex];
      if LCarry then
      begin
        System.Inc(LMag);
        LCarry := (LMag = UInt32.MinValue);
      end;
      LBytesIndex := LBytesIndex - 4;
      TConverters.ReadUInt32AsBytesBE(LMag, Result, LBytesIndex);
    end;
    LLastMag := FMagnitude[0];
    if LCarry then
    begin
      System.Dec(LLastMag);
    end;
    while LLastMag > Byte.MaxValue do
    begin
      System.Dec(LBytesIndex);
      Result[LBytesIndex] := Byte(not LLastMag);
      LLastMag := LLastMag shr 8;
    end;
    System.Dec(LBytesIndex);
    Result[LBytesIndex] := Byte(not LLastMag);
    if LBytesIndex <> 0 then
    begin
      System.Dec(LBytesIndex);
      Result[LBytesIndex] := Byte.MaxValue;
    end;
  end;
end;

function TBigInteger.ToString(): String;
begin
  Result := ToString(10);
end;

function TBigInteger.ToString(const ARadix: Int32): String;
var
  LFirstNonZero, LPos, I: Int32;
  LSb: String;
  LU: TBigInteger;
  LBits: Int32;
  LS: String;
  LQ: TBigInteger;
  LModuli: TCryptoLibGenericArray<TBigInteger>;
  LOctStrings: TCryptoLibStringArray;
  LR: TBigInteger;
  LScale: Int32;
begin
  if not (ARadix in [2, 8, 10, 16]) then
    raise EFormatCryptoLibException.Create(SInvalidRadix);
  if ((not FIsInitialized) and (FMagnitude = nil)) then
  begin
    Result := 'nil';
    Exit;
  end;
  if FSign = 0 then
  begin
    Result := '0';
    Exit;
  end;
  // Find first non-zero
  LFirstNonZero := 0;
  while (LFirstNonZero < System.Length(FMagnitude)) and (FMagnitude[LFirstNonZero] = 0) do
  begin
    System.Inc(LFirstNonZero);
  end;
  if LFirstNonZero >= System.Length(FMagnitude) then
  begin
    Result := '0';
    Exit;
  end;
  LSb := '';
  if FSign = -1 then
    LSb := LSb + '-';
  case ARadix of
    2:
    begin
      LPos := LFirstNonZero;
      LSb := LSb + UInt32ToBin(FMagnitude[LPos]);
      System.Inc(LPos);
      while LPos < System.Length(FMagnitude) do
      begin
        AppendZeroExtendedString(LSb, UInt32ToBin(FMagnitude[LPos]), 32);
        System.Inc(LPos);
      end;
      Result := LSb;
    end;
    8:
    begin
      LU := Abs();
      LBits := LU.BitLength;
      // Process in chunks of 30 bits (10 octal digits per chunk)
      // mask = (1 << 30) - 1 = 0x3FFFFFFF
      LQ := LU;
      System.SetLength(LOctStrings, 0);
      while LBits > 30 do
      begin
        // Extract lower 30 bits and convert to octal
        System.SetLength(LOctStrings, System.Length(LOctStrings) + 1);
        LOctStrings[System.High(LOctStrings)] := Int32ToOct(LQ.Int32Value and $3FFFFFFF);
        LQ := LQ.ShiftRight(30);
        LBits := LBits - 30;
      end;
      // Convert remaining bits
      LSb := LSb + Int32ToOct(LQ.Int32Value);
      // Append stored chunks in reverse order with zero padding
      for I := System.High(LOctStrings) downto 0 do
      begin
        AppendZeroExtendedString(LSb, LOctStrings[I], 10);
      end;
      Result := LSb;
    end;
    16:
    begin
      LPos := LFirstNonZero;
      LSb := LSb + IntToHex(FMagnitude[LPos], 0);
      System.Inc(LPos);
      while LPos < System.Length(FMagnitude) do
      begin
        AppendZeroExtendedString(LSb, IntToHex(FMagnitude[LPos], 0), 8);
        System.Inc(LPos);
      end;
      Result := LSb;
    end;
    10:
    begin
      LQ := Abs();
      if LQ.BitLength < 64 then
      begin
        Result := LSb + IntToStr(LQ.Int64Value);
        Exit;
      end;
      // For large numbers, use recursive division
      System.SetLength(LModuli, 0);
      LR := ValueOf(ARadix);
      while LR.CompareTo(LQ) <= 0 do
      begin
        System.SetLength(LModuli, System.Length(LModuli) + 1);
        LModuli[System.Length(LModuli) - 1] := LR;
        LR := LR.Square();
      end;
      LScale := System.Length(LModuli);
      ToStringRecursive(LSb, ARadix, LModuli, LScale, LQ);
      Result := LSb;
    end;
  else
    Result := '';
  end;
end;

procedure TBigInteger.ToStringRecursive(var ASb: String; const ARadix: Int32; const AModuli: TCryptoLibGenericArray<TBigInteger>; const AScale: Int32; const APos: TBigInteger);
var
  LS: String;
  LQR: TCryptoLibGenericArray<TBigInteger>;
  LNewScale: Int32;
begin
  if APos.BitLength < 64 then
  begin
    LS := IntToStr(APos.Int64Value);
    if (System.Length(ASb) > 1) or ((System.Length(ASb) = 1) and (ASb[1] <> '-')) then
    begin
      AppendZeroExtendedString(ASb, LS, 1 shl AScale);
    end
    else if APos.SignValue <> 0 then
    begin
      ASb := ASb + LS;
    end;
    Exit;
  end;
  LNewScale := AScale - 1;
  LQR := APos.DivideAndRemainder(AModuli[LNewScale]);
  ToStringRecursive(ASb, ARadix, AModuli, LNewScale, LQR[0]);
  ToStringRecursive(ASb, ARadix, AModuli, LNewScale, LQR[1]);
end;

function TBigInteger.IsProbablePrime(const ACertainty: Int32): Boolean;
var
  LN: TBigInteger;
begin
  Result := IsProbablePrime(ACertainty, False);
end;

function TBigInteger.NextProbablePrime(): TBigInteger;
var
  LN: TBigInteger;
begin
  if FSign < 0 then
    raise EArithmeticCryptoLibException.Create('Cannot be called on value < 0');
  if CompareTo(FTwo) < 0 then
  begin
    Result := FTwo;
    Exit;
  end;
  LN := &Inc().SetBit(0);
  while not LN.CheckProbablePrime(100, TSecureRandom.MasterRandom as IRandom, False) do
  begin
    LN := LN.Add(FTwo);
  end;
  Result := LN;
end;

function TBigInteger.IsEven(): Boolean;
begin
  if FSign = 0 then
    Result := True
  else if System.Length(FMagnitude) = 0 then
    Result := True
  else
    Result := (FMagnitude[System.Length(FMagnitude) - 1] and 1) = 0;
end;

class function TBigInteger.ExtEuclid(const AA, AB: TBigInteger; out AU1Out: TBigInteger): TBigInteger;
var
  LU1, LV1, LU3, LV3, LOldU1, LV1New: TBigInteger;
  LQ: TCryptoLibGenericArray<TBigInteger>;
begin
  LU1 := FOne;
  LV1 := FZero;
  LU3 := AA;
  LV3 := AB;
  if LV3.FSign > 0 then
  begin
    while True do
    begin
      LQ := LU3.DivideAndRemainder(LV3);
      LU3 := LV3;
      LV3 := LQ[1];
      LOldU1 := LU1;
      LU1 := LV1;
      if LV3.FSign <= 0 then
        Break;
      LV1New := LOldU1.Subtract(LV1.Multiply(LQ[0]));
      LV1 := LV1New;
    end;
  end;
  AU1Out := LU1;
  Result := LU3;
end;

function TBigInteger.ModInversePow2(const AM: TBigInteger): TBigInteger;
var
  LPow, LBitsCorrect: Int32;
  LInv64: Int64;
  LX, LD, LT: TBigInteger;
begin
{$IFDEF DEBUG}
  System.Assert(AM.FSign > 0);
  System.Assert(AM.BitCount = 1);
{$ENDIF DEBUG}
  if not TestBit(0) then
    raise EArithmeticCryptoLibException.Create('Numbers not relatively prime.');
  LPow := AM.BitLength - 1;
  LInv64 := Int64(TMod.Inverse64(UInt64(Int64Value)));
  if LPow < 64 then
  begin
    LInv64 := LInv64 and ((Int64(1) shl LPow) - 1);
  end;
  LX := ValueOf(LInv64);
  if LPow > 64 then
  begin
    LD := Remainder(AM);
    LBitsCorrect := 64;
    repeat
      LT := LX.Multiply(LD).Remainder(AM);
      LX := LX.Multiply(FTwo.Subtract(LT)).Remainder(AM);
      LBitsCorrect := LBitsCorrect shl 1;
    until LBitsCorrect >= LPow;
  end;
  if LX.FSign < 0 then
    LX := LX.Add(AM);
  Result := LX;
end;

function TBigInteger.ModPowSimple(const AB, AE, AM: TBigInteger): TBigInteger;
var
  LY, LZ: TBigInteger;
  LExp: TBigInteger;
begin
  LY := FOne;
  LZ := AB;
  LExp := AE;
  while LExp.FSign > 0 do
  begin
    if LExp.TestBit(0) then
    begin
      LY := LY.Multiply(LZ).&Mod(AM);
    end;
    LExp := LExp.ShiftRight(1);
    if LExp.FSign > 0 then
    begin
      LZ := LZ.Multiply(LZ).&Mod(AM);
    end;
  end;
  Result := LY;
end;

class function TBigInteger.ReduceBarrett(const AX, AM, AMr, AYu: TBigInteger): TBigInteger;
var
  LXLen, LMLen, LK: Int32;
  LQ1, LQ2, LQ3, LR1, LR2, LR3: TBigInteger;
begin
  LXLen := AX.BitLength;
  LMLen := AM.BitLength;
  if LXLen < LMLen then
  begin
    Result := AX;
    Exit;
  end;
  if LXLen - LMLen > 1 then
  begin
    LK := System.Length(AM.FMagnitude);
    LQ1 := AX.DivideWords(LK - 1);
    LQ2 := LQ1.Multiply(AYu); // TODO Only need partial multiplication here
    LQ3 := LQ2.DivideWords(LK + 1);
    LR1 := AX.RemainderWords(LK + 1);
    LR2 := LQ3.Multiply(AM); // TODO Only need partial multiplication here
    LR3 := LR2.RemainderWords(LK + 1);
    Result := LR1.Subtract(LR3);
    if Result.FSign < 0 then
    begin
      Result := Result.Add(AMr);
    end;
  end
  else
  begin
    Result := AX;
  end;
  while Result.CompareTo(AM) >= 0 do
  begin
    Result := Result.Subtract(AM);
  end;
end;

class function TBigInteger.ModPowBarrett(const AB, AE, AM: TBigInteger): TBigInteger;
var
  LK, LExtraBits, LExpLength, LNumPowers, I, J, LWindowPos, LBits: Int32;
  LMr, LYu: TBigInteger;
  LOddPowers: TCryptoLibGenericArray<TBigInteger>;
  LB2, LY: TBigInteger;
  LWindowList: TCryptoLibUInt32Array;
  LWindow, LMult, LLastZeros: UInt32;
begin
  LK := System.Length(AM.FMagnitude);
  LMr := FOne.ShiftLeft((LK + 1) shl 5);
  LYu := FOne.ShiftLeft(LK shl 6).Divide(AM);
  // Sliding window from MSW to LSW
  LExtraBits := 0;
  LExpLength := AE.BitLength;
  while LExpLength > ExpWindowThresholds[LExtraBits] do
  begin
    System.Inc(LExtraBits);
  end;
  LNumPowers := 1 shl LExtraBits;
  System.SetLength(LOddPowers, LNumPowers);
  LOddPowers[0] := AB;
  LB2 := ReduceBarrett(AB.Square(), AM, LMr, LYu);
  for I := 1 to System.Pred(LNumPowers) do
  begin
    LOddPowers[I] := ReduceBarrett(LOddPowers[I - 1].Multiply(LB2), AM, LMr, LYu);
  end;
  LWindowList := GetWindowList(AE.FMagnitude, LExtraBits);
{$IFDEF DEBUG}
  System.Assert(System.Length(LWindowList) > 0);
{$ENDIF DEBUG}
  LWindow := LWindowList[0];
  LMult := LWindow and $FF;
  LLastZeros := LWindow shr 8;
  if LMult = 1 then
  begin
    LY := LB2;
    System.Dec(LLastZeros);
  end
  else
  begin
    LY := LOddPowers[LMult shr 1];
  end;
  LWindowPos := 1;
  LWindow := LWindowList[LWindowPos];
  System.Inc(LWindowPos);
  while LWindow <> High(UInt32) do
  begin
    LMult := LWindow and $FF;
    LBits := Int32(LLastZeros) + BitLen(Byte(LMult));
    for J := 0 to System.Pred(LBits) do
    begin
      LY := ReduceBarrett(LY.Square(), AM, LMr, LYu);
    end;
    LY := ReduceBarrett(LY.Multiply(LOddPowers[LMult shr 1]), AM, LMr, LYu);
    LLastZeros := LWindow shr 8;
    LWindow := LWindowList[LWindowPos];
    System.Inc(LWindowPos);
  end;
  for I := 0 to System.Pred(Int32(LLastZeros)) do
  begin
    LY := ReduceBarrett(LY.Square(), AM, LMr, LYu);
  end;
  Result := LY;
end;

class function TBigInteger.ModPowMonty(var AYAccum: TCryptoLibUInt32Array; const AB, AE, AM: TBigInteger; const AConvert: Boolean): TBigInteger;
var
  LN, LPowR, LExtraBits, LExpLength, LNumPowers, I, J, LWindowPos, LBits: Int32;
  LSmallMontyModulus: Boolean;
  LMDash: UInt32;
  LB: TBigInteger;
  LZVal, LZSquared: TCryptoLibUInt32Array;
  LOddPowers: TCryptoLibMatrixUInt32Array;
  LWindowList: TCryptoLibUInt32Array;
  LWindow, LMult, LLastZeros: UInt32;
  LYVal, LTmp: TCryptoLibUInt32Array;
begin
  LN := System.Length(AM.FMagnitude);
  LPowR := 32 * LN;
  LSmallMontyModulus := AM.BitLength + 2 <= LPowR;
  LMDash := AM.GetMQuote();
  // tmp = this * R mod m
  LB := AB;
  if AConvert then
  begin
    LB := LB.ShiftLeft(LPowR).Remainder(AM);
  end;
{$IFDEF DEBUG}
  System.Assert(System.Length(AYAccum) = LN + 1);
{$ENDIF DEBUG}
  LZVal := LB.FMagnitude;
  if System.Length(LZVal) < LN then
  begin
    System.SetLength(LTmp, LN);
    System.Move(LZVal[0], LTmp[LN - System.Length(LZVal)], System.Length(LZVal) * System.SizeOf(UInt32));
    LZVal := LTmp;
  end;

{$IFDEF DEBUG}
  System.Assert(System.Length(LZVal) = LN);
{$ENDIF DEBUG}
  // Sliding window from MSW to LSW
  LExtraBits := 0;
  // Filter the common case of small RSA exponents with few bits set
  if (System.Length(AE.FMagnitude) > 1) or (AE.BitCount > 2) then
  begin
    LExpLength := AE.BitLength;
    while LExpLength > ExpWindowThresholds[LExtraBits] do
    begin
      System.Inc(LExtraBits);
    end;
  end;
  LNumPowers := 1 shl LExtraBits;
  System.SetLength(LOddPowers, LNumPowers);
  LOddPowers[0] := LZVal;

  LZSquared := System.Copy(LZVal);
  SquareMonty(AYAccum, LZSquared, AM.FMagnitude, LMDash, LSmallMontyModulus);

  for I := 1 to System.Pred(LNumPowers) do
  begin
    LOddPowers[I] := System.Copy(LOddPowers[I - 1]);

    MultiplyMonty(AYAccum, LOddPowers[I], LZSquared, AM.FMagnitude, LMDash, LSmallMontyModulus);
  end;

  LWindowList := GetWindowList(AE.FMagnitude, LExtraBits);
{$IFDEF DEBUG}
  System.Assert(System.Length(LWindowList) > 1);
{$ENDIF DEBUG}
  LWindow := LWindowList[0];
  LMult := LWindow and $FF;
  LLastZeros := LWindow shr 8;
  if LMult = 1 then
  begin
    LYVal := LZSquared;
    System.Dec(LLastZeros);
  end
  else
  begin
    LYVal := System.Copy(LOddPowers[LMult shr 1]);
  end;

  LWindowPos := 1;
  LWindow := LWindowList[LWindowPos];
  System.Inc(LWindowPos);
  while LWindow <> UInt32.MaxValue do
  begin
    LMult := LWindow and $FF;
    LBits := Int32(LLastZeros) + BitLen(Byte(LMult));
    for J := 0 to System.Pred(LBits) do
    begin
      SquareMonty(AYAccum, LYVal, AM.FMagnitude, LMDash, LSmallMontyModulus);
    end;
    MultiplyMonty(AYAccum, LYVal, LOddPowers[LMult shr 1], AM.FMagnitude, LMDash, LSmallMontyModulus);
    LLastZeros := LWindow shr 8;
    // Get next window value
    LWindow := LWindowList[LWindowPos];
    System.Inc(LWindowPos);
  end;
  for I := 0 to System.Pred(Int32(LLastZeros)) do
  begin
    SquareMonty(AYAccum, LYVal, AM.FMagnitude, LMDash, LSmallMontyModulus);
  end;
  if AConvert then
  begin
    // Return y * R^(-1) mod m
    MontgomeryReduce(LYVal, AM.FMagnitude, LMDash);
  end
  else if LSmallMontyModulus and (CompareTo(0, LYVal, 0, AM.FMagnitude) >= 0) then
  begin
    Subtract(0, LYVal, 0, AM.FMagnitude);
  end;
  Result := TBigInteger.Create(1, LYVal, True);
end;

class function TBigInteger.ModSquareMonty(var AYAccum: TCryptoLibUInt32Array; const AB, AM: TBigInteger): TBigInteger;
var
  LN, LPowR: Int32;
  LSmallMontyModulus: Boolean;
  LMDash: UInt32;
  LZVal, LYVal: TCryptoLibUInt32Array;
begin
  LN := System.Length(AM.FMagnitude);
  LPowR := 32 * LN;
  LSmallMontyModulus := AM.BitLength + 2 <= LPowR;
  LMDash := AM.GetMQuote();
{$IFDEF DEBUG}
  System.Assert(System.Length(AYAccum) = LN + 1);
{$ENDIF DEBUG}
  LZVal := AB.FMagnitude;
{$IFDEF DEBUG}
  System.Assert(System.Length(LZVal) <= LN);
{$ENDIF DEBUG}

  System.SetLength(LYVal, LN);
  System.Move(LZVal[0], LYVal[LN - System.Length(LZVal)], System.Length(LZVal) * System.SizeOf(UInt32));

  SquareMonty(AYAccum, LYVal, AM.FMagnitude, LMDash, LSmallMontyModulus);
  if LSmallMontyModulus and (CompareTo(0, LYVal, 0, AM.FMagnitude) >= 0) then
  begin
    Subtract(0, LYVal, 0, AM.FMagnitude);
  end;
  Result := TBigInteger.Create(1, LYVal, True);
end;

function TBigInteger.Remainder(const AM: Int32): Int32;
var
  LAcc: Int64;
  LPos: Int32;
  LPosVal: Int64;
begin
{$IFDEF DEBUG}
  System.Assert(AM > 0);
{$ENDIF DEBUG}
  if AM <= 0 then
    raise EArgumentCryptoLibException.Create('m must be > 0');

  LAcc := 0;
  for LPos := 0 to System.Pred(System.Length(FMagnitude)) do
  begin
    LPosVal := FMagnitude[LPos];
    LAcc := (LAcc shl 32 or LPosVal) mod AM;
  end;

  Result := Int32(LAcc);
end;

function TBigInteger.DivideWords(const AW: Int32): TBigInteger;
var
  LN: Int32;
  LMag: TCryptoLibUInt32Array;
begin
{$IFDEF DEBUG}
  System.Assert(AW >= 0);
{$ENDIF DEBUG}
  LN := System.Length(FMagnitude);
  if AW >= LN then
  begin
    Result := FZero;
    Exit;
  end;
  System.SetLength(LMag, LN - AW);
  System.Move(FMagnitude[0], LMag[0], (LN - AW) * System.SizeOf(UInt32));
  Result := TBigInteger.Create(FSign, LMag, False);
end;

function TBigInteger.RemainderWords(const AW: Int32): TBigInteger;
var
  LN: Int32;
  LMag: TCryptoLibUInt32Array;
begin
{$IFDEF DEBUG}
  System.Assert(AW >= 0);
{$ENDIF DEBUG}
  LN := System.Length(FMagnitude);
  if AW >= LN then
  begin
    Result := Self;
    Exit;
  end;
  System.SetLength(LMag, AW);
  System.Move(FMagnitude[LN - AW], LMag[0], AW * System.SizeOf(UInt32));
  Result := TBigInteger.Create(FSign, LMag, False);
end;

function TBigInteger.GetMQuote(): UInt32;
var
  LD: UInt32;
begin
{$IFDEF DEBUG}
  System.Assert(FSign > 0);
{$ENDIF DEBUG}
  LD := 0 - FMagnitude[System.Length(FMagnitude) - 1];
{$IFDEF DEBUG}
  System.Assert((LD and 1) <> 0);
{$ENDIF DEBUG}
  Result := TMod.Inverse32(LD);
end;

function TBigInteger.CheckProbablePrime(const ACertainty: Int32;
  const ARandom: IRandom; const ARandomlySelected: Boolean): Boolean;
var
  LNumLists, I, J, LTest, LPrime, LQRem: Int32;
  LPrimeList: TCryptoLibInt32Array;
begin
{$IFDEF DEBUG}
  System.Assert(ACertainty > 0);
  System.Assert(CompareTo(FTwo) > 0);
  System.Assert(TestBit(0));
{$ENDIF DEBUG}

  // Try to reduce the penalty for really small numbers
  LNumLists := Math.Min(BitLength - 1, System.Length(FPrimeLists));

  for I := 0 to System.Pred(LNumLists) do
  begin
    LTest := Remainder(FPrimeProducts[I]);
    LPrimeList := FPrimeLists[I];

    for J := 0 to System.Pred(System.Length(LPrimeList)) do
    begin
      LPrime := LPrimeList[J];
      LQRem := LTest mod LPrime;
      if LQRem = 0 then
      begin
        // We may find small numbers in the list
        Result := (BitLength < 16) and (Int32Value = LPrime);
        Exit;
      end;
    end;
  end;

  Result := RabinMillerTest(ACertainty, ARandom, ARandomlySelected);
end;

function TBigInteger.IsProbablePrime(const ACertainty: Int32;
  const ARandomlySelected: Boolean): Boolean;
var
  LN: TBigInteger;
begin
  if ACertainty <= 0 then
  begin
    Result := True;
    Exit;
  end;

  LN := Abs();

  if not LN.TestBit(0) then
  begin
    Result := LN.Equals(FTwo);
    Exit;
  end;

  if LN.Equals(FOne) then
  begin
    Result := False;
    Exit;
  end;

  Result := LN.CheckProbablePrime(ACertainty, TSecureRandom.MasterRandom as IRandom,
    ARandomlySelected);
end;

function TBigInteger.RabinMillerTest(const ACertainty: Int32;
  const ARandom: IRandom): Boolean;
begin
  Result := RabinMillerTest(ACertainty, ARandom, False);
end;

function TBigInteger.RabinMillerTest(const ACertainty: Int32; const ARandom: IRandom;
  const ARandomlySelected: Boolean): Boolean;
var
  LBits, LIterations, LItersFor100Cert: Int32;
  LN, LR, LY, LA: TBigInteger;
  LMontRadix, LMinusMontRadix: TBigInteger;
  LS, LJ: Int32;
  LYAccum: TCryptoLibUInt32Array;
begin
  LBits := BitLength;

{$IFDEF DEBUG}
  System.Assert(ACertainty > 0);
  System.Assert(LBits > 2);
  System.Assert(TestBit(0));
{$ENDIF DEBUG}

  LIterations := ((ACertainty - 1) div 2) + 1;
  if ARandomlySelected then
  begin
    if LBits >= 1024 then
      LItersFor100Cert := 4
    else if LBits >= 512 then
      LItersFor100Cert := 8
    else if LBits >= 256 then
      LItersFor100Cert := 16
    else
      LItersFor100Cert := 50;

    if ACertainty < 100 then
      LIterations := Math.Min(LItersFor100Cert, LIterations)
    else
    begin
      LIterations := LIterations - 50;
      LIterations := LIterations + LItersFor100Cert;
    end;
  end;

  // let n = 1 + d . 2^s
  LN := Self;
  LS := LN.GetLowestSetBitMaskFirst(UInt32.MaxValue shl 1);
{$IFDEF DEBUG}
  System.Assert(LS >= 1);
{$ENDIF DEBUG}
  LR := LN.ShiftRight(LS);

  // NOTE: Avoid conversion to/from Montgomery form and check for R/-R as result instead
  LMontRadix := FOne.ShiftLeft(32 * System.Length(LN.FMagnitude)).Remainder(LN);
  LMinusMontRadix := LN.Subtract(LMontRadix);

  System.SetLength(LYAccum, System.Length(LN.FMagnitude) + 1);

  repeat
    repeat
      LA := TBigInteger.Create(LN.BitLength, ARandom);
    until (LA.FSign <> 0) and (LA.CompareTo(LN) < 0)
      and (not IsEqualMagnitude(LA.FMagnitude, LMontRadix.FMagnitude))
      and (not IsEqualMagnitude(LA.FMagnitude, LMinusMontRadix.FMagnitude));

    LY := ModPowMonty(LYAccum, LA, LR, LN, False);

    if not LY.Equals(LMontRadix) then
    begin
      LJ := 0;
      while not LY.Equals(LMinusMontRadix) do
      begin
        System.Inc(LJ);
        if LJ = LS then
        begin
          Result := False;
          Exit;
        end;

        LY := ModSquareMonty(LYAccum, LY, LN);

        if LY.Equals(LMontRadix) then
        begin
          Result := False;
          Exit;
        end;
      end;
    end;

    System.Dec(LIterations);
  until LIterations <= 0;

  Result := True;
end;

end.
