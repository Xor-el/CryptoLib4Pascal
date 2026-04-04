{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                           Author - Ugochukwu Mmaduekwe                          * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }

{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }

{ *                              Acknowledgements:                                  * }
{ *                                                                                 * }
{ *      Thanks to Sphere 10 Software (http://www.sphere10.com/) for sponsoring     * }
{ *                           development of this library                           * }

{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit ClpRijndaelEngine;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpCheck,
  ClpIBlockCipher,
  ClpIRijndaelEngine,
  ClpIKeyParameter,
  ClpICipherParameters,
  ClpArrayUtilities,
  ClpPlatformUtilities,
  ClpCryptoLibTypes;

resourcestring
  SInputBuffertooShort = 'Input Buffer too Short';
  SOutputBuffertooShort = 'Output Buffer too Short';
  SUnsupportedBlock = 'Unknown Blocksize to Rijndael';
  SInvalidKeyLength = 'Key Length not 128/160/192/224/256 bits.';
  SRijndaelEngineNotInitialised = 'Rijndael Engine not Initialised';
  SInvalidParameterRijndaelInit =
    'Invalid Parameter Passed to Rijndael Init - "%s"';

type

  /// <summary>
  /// <para>
  /// an implementation of Rijndael, based on the documentation and
  /// reference implementation by Paulo Barreto, Vincent Rijmen, for v2.0
  /// August '99.
  /// </para>
  /// <para>
  /// Note: this implementation is based on information prior to readonly
  /// NIST publication.
  /// </para>
  /// </summary>
  TRijndaelEngine = class(TInterfacedObject, IRijndaelEngine, IBlockCipher)

  strict private
  const
    MAXROUNDS = Int32(14);
    MAXKC = Int32(256 div 4);

    LogTable: array [0 .. 255] of Byte = (0, 0, 25, 1, 50, 2, 26, 198, 75, 199,
      27, 104, 51, 238, 223, 3, 100, 4, 224, 14, 52, 141, 129, 239, 76, 113, 8,
      200, 248, 105, 28, 193, 125, 194, 29, 181, 249, 185, 39, 106, 77, 228,
      166, 114, 154, 201, 9, 120, 101, 47, 138, 5, 33, 15, 225, 36, 18, 240,
      130, 69, 53, 147, 218, 142, 150, 143, 219, 189, 54, 208, 206, 148, 19, 92,
      210, 241, 64, 70, 131, 56, 102, 221, 253, 48, 191, 6, 139, 98, 179, 37,
      226, 152, 34, 136, 145, 16, 126, 110, 72, 195, 163, 182, 30, 66, 58, 107,
      40, 84, 250, 133, 61, 186, 43, 121, 10, 21, 155, 159, 94, 202, 78, 212,
      172, 229, 243, 115, 167, 87, 175, 88, 168, 80, 244, 234, 214, 116, 79,
      174, 233, 213, 231, 230, 173, 232, 44, 215, 117, 122, 235, 22, 11, 245,
      89, 203, 95, 176, 156, 169, 81, 160, 127, 12, 246, 111, 23, 196, 73, 236,
      216, 67, 31, 45, 164, 118, 123, 183, 204, 187, 62, 90, 251, 96, 177, 134,
      59, 82, 161, 108, 170, 85, 41, 157, 151, 178, 135, 144, 97, 190, 220, 252,
      188, 149, 207, 205, 55, 63, 91, 209, 83, 57, 132, 60, 65, 162, 109, 71,
      20, 42, 158, 93, 86, 242, 211, 171, 68, 17, 146, 217, 35, 32, 46, 137,
      180, 124, 184, 38, 119, 153, 227, 165, 103, 74, 237, 222, 197, 49, 254,
      24, 13, 99, 140, 128, 192, 247, 112, 7);

    ALogTable: array [0 .. 510] of Byte = (0, 3, 5, 15, 17, 51, 85, 255, 26, 46,
      114, 150, 161, 248, 19, 53, 95, 225, 56, 72, 216, 115, 149, 164, 247, 2,
      6, 10, 30, 34, 102, 170, 229, 52, 92, 228, 55, 89, 235, 38, 106, 190, 217,
      112, 144, 171, 230, 49, 83, 245, 4, 12, 20, 60, 68, 204, 79, 209, 104,
      184, 211, 110, 178, 205, 76, 212, 103, 169, 224, 59, 77, 215, 98, 166,
      241, 8, 24, 40, 120, 136, 131, 158, 185, 208, 107, 189, 220, 127, 129,
      152, 179, 206, 73, 219, 118, 154, 181, 196, 87, 249, 16, 48, 80, 240, 11,
      29, 39, 105, 187, 214, 97, 163, 254, 25, 43, 125, 135, 146, 173, 236, 47,
      113, 147, 174, 233, 32, 96, 160, 251, 22, 58, 78, 210, 109, 183, 194, 93,
      231, 50, 86, 250, 21, 63, 65, 195, 94, 226, 61, 71, 201, 64, 192, 91, 237,
      44, 116, 156, 191, 218, 117, 159, 186, 213, 100, 172, 239, 42, 126, 130,
      157, 188, 223, 122, 142, 137, 128, 155, 182, 193, 88, 232, 35, 101, 175,
      234, 37, 111, 177, 200, 67, 197, 84, 252, 31, 33, 99, 165, 244, 7, 9, 27,
      45, 119, 153, 176, 203, 70, 202, 69, 207, 74, 222, 121, 139, 134, 145,
      168, 227, 62, 66, 198, 81, 243, 14, 18, 54, 90, 238, 41, 123, 141, 140,
      143, 138, 133, 148, 167, 242, 13, 23, 57, 75, 221, 124, 132, 151, 162,
      253, 28, 36, 108, 180, 199, 82, 246, 1, 3, 5, 15, 17, 51, 85, 255, 26, 46,
      114, 150, 161, 248, 19, 53, 95, 225, 56, 72, 216, 115, 149, 164, 247, 2,
      6, 10, 30, 34, 102, 170, 229, 52, 92, 228, 55, 89, 235, 38, 106, 190, 217,
      112, 144, 171, 230, 49, 83, 245, 4, 12, 20, 60, 68, 204, 79, 209, 104,
      184, 211, 110, 178, 205, 76, 212, 103, 169, 224, 59, 77, 215, 98, 166,
      241, 8, 24, 40, 120, 136, 131, 158, 185, 208, 107, 189, 220, 127, 129,
      152, 179, 206, 73, 219, 118, 154, 181, 196, 87, 249, 16, 48, 80, 240, 11,
      29, 39, 105, 187, 214, 97, 163, 254, 25, 43, 125, 135, 146, 173, 236, 47,
      113, 147, 174, 233, 32, 96, 160, 251, 22, 58, 78, 210, 109, 183, 194, 93,
      231, 50, 86, 250, 21, 63, 65, 195, 94, 226, 61, 71, 201, 64, 192, 91, 237,
      44, 116, 156, 191, 218, 117, 159, 186, 213, 100, 172, 239, 42, 126, 130,
      157, 188, 223, 122, 142, 137, 128, 155, 182, 193, 88, 232, 35, 101, 175,
      234, 37, 111, 177, 200, 67, 197, 84, 252, 31, 33, 99, 165, 244, 7, 9, 27,
      45, 119, 153, 176, 203, 70, 202, 69, 207, 74, 222, 121, 139, 134, 145,
      168, 227, 62, 66, 198, 81, 243, 14, 18, 54, 90, 238, 41, 123, 141, 140,
      143, 138, 133, 148, 167, 242, 13, 23, 57, 75, 221, 124, 132, 151, 162,
      253, 28, 36, 108, 180, 199, 82, 246, 1);

    S: array [0 .. 255] of Byte = (99, 124, 119, 123, 242, 107, 111, 197, 48, 1,
      103, 43, 254, 215, 171, 118, 202, 130, 201, 125, 250, 89, 71, 240, 173,
      212, 162, 175, 156, 164, 114, 192, 183, 253, 147, 38, 54, 63, 247, 204,
      52, 165, 229, 241, 113, 216, 49, 21, 4, 199, 35, 195, 24, 150, 5, 154, 7,
      18, 128, 226, 235, 39, 178, 117, 9, 131, 44, 26, 27, 110, 90, 160, 82, 59,
      214, 179, 41, 227, 47, 132, 83, 209, 0, 237, 32, 252, 177, 91, 106, 203,
      190, 57, 74, 76, 88, 207, 208, 239, 170, 251, 67, 77, 51, 133, 69, 249, 2,
      127, 80, 60, 159, 168, 81, 163, 64, 143, 146, 157, 56, 245, 188, 182, 218,
      33, 16, 255, 243, 210, 205, 12, 19, 236, 95, 151, 68, 23, 196, 167, 126,
      61, 100, 93, 25, 115, 96, 129, 79, 220, 34, 42, 144, 136, 70, 238, 184,
      20, 222, 94, 11, 219, 224, 50, 58, 10, 73, 6, 36, 92, 194, 211, 172, 98,
      145, 149, 228, 121, 231, 200, 55, 109, 141, 213, 78, 169, 108, 86, 244,
      234, 101, 122, 174, 8, 186, 120, 37, 46, 28, 166, 180, 198, 232, 221, 116,
      31, 75, 189, 139, 138, 112, 62, 181, 102, 72, 3, 246, 14, 97, 53, 87, 185,
      134, 193, 29, 158, 225, 248, 152, 17, 105, 217, 142, 148, 155, 30, 135,
      233, 206, 85, 40, 223, 140, 161, 137, 13, 191, 230, 66, 104, 65, 153, 45,
      15, 176, 84, 187, 22);

    Si: array [0 .. 255] of Byte = (82, 9, 106, 213, 48, 54, 165, 56, 191, 64,
      163, 158, 129, 243, 215, 251, 124, 227, 57, 130, 155, 47, 255, 135, 52,
      142, 67, 68, 196, 222, 233, 203, 84, 123, 148, 50, 166, 194, 35, 61, 238,
      76, 149, 11, 66, 250, 195, 78, 8, 46, 161, 102, 40, 217, 36, 178, 118, 91,
      162, 73, 109, 139, 209, 37, 114, 248, 246, 100, 134, 104, 152, 22, 212,
      164, 92, 204, 93, 101, 182, 146, 108, 112, 72, 80, 253, 237, 185, 218, 94,
      21, 70, 87, 167, 141, 157, 132, 144, 216, 171, 0, 140, 188, 211, 10, 247,
      228, 88, 5, 184, 179, 69, 6, 208, 44, 30, 143, 202, 63, 15, 2, 193, 175,
      189, 3, 1, 19, 138, 107, 58, 145, 17, 65, 79, 103, 220, 234, 151, 242,
      207, 206, 240, 180, 230, 115, 150, 172, 116, 34, 231, 173, 53, 133, 226,
      249, 55, 232, 28, 117, 223, 110, 71, 241, 26, 113, 29, 41, 197, 137, 111,
      183, 98, 14, 170, 24, 190, 27, 252, 86, 62, 75, 198, 210, 121, 32, 154,
      219, 192, 254, 120, 205, 90, 244, 31, 221, 168, 51, 136, 7, 199, 49, 177,
      18, 16, 89, 39, 128, 236, 95, 96, 81, 127, 169, 25, 181, 74, 13, 45, 229,
      122, 159, 147, 201, 156, 239, 160, 224, 59, 77, 174, 42, 245, 176, 200,
      235, 187, 60, 131, 83, 153, 97, 23, 43, 4, 126, 186, 119, 214, 38, 225,
      105, 20, 99, 85, 33, 12, 125);

    RCon: array [0 .. 29] of Byte = ($01, $02, $04, $08, $10, $20, $40, $80,
      $1B, $36, $6C, $D8, $AB, $4D, $9A, $2F, $5E, $BC, $63, $C6, $97, $35, $6A,
      $D4, $B3, $7D, $FA, $EF, $C5, $91);

    Shifts0: array [0 .. 4, 0 .. 3] of Byte = ((0, 8, 16, 24), (0, 8, 16, 24),
      (0, 8, 16, 24), (0, 8, 16, 32), (0, 8, 24, 32));

    Shifts1: array [0 .. 4, 0 .. 3] of Byte = ((0, 24, 16, 8), (0, 32, 24, 16),
      (0, 40, 32, 24), (0, 48, 40, 24), (0, 56, 40, 32));

  var
    FForEncryption: Boolean;
    FBC, FROUNDS, FBlockBits: Int32;
    FBC_MASK, FA0, FA1, FA2, FA3: UInt64;
    FShifts0SC, FShifts1SC: TCryptoLibByteArray;
    FWorkingKey: TCryptoLibMatrixUInt64Array;

    /// <summary>
    /// multiply two elements of GF(2^m) needed for MixColumn and
    /// InvMixColumn
    /// </summary>
    function Mul0x2(AB: Int32): Byte; inline;

    function Mul0x3(AB: Int32): Byte; inline;

    function Mul0x9(AB: Int32): Byte; inline;

    function Mul0xb(AB: Int32): Byte; inline;

    function Mul0xd(AB: Int32): Byte; inline;

    function Mul0xe(AB: Int32): Byte; inline;

    /// <summary>
    /// xor corresponding text input and round key input bytes
    /// </summary>
    procedure KeyAddition(const ARk: TCryptoLibUInt64Array); inline;

    /// <summary>
    /// rotate right custom
    /// </summary>
    function Shift(AR: UInt64; AShift: Int32): UInt64; inline;

    /// <summary>
    /// Row 0 remains unchanged <br />The other three rows are shifted a
    /// variable amount
    /// </summary>
    procedure ShiftRow(const AShiftsSC: TCryptoLibByteArray); inline;

    function ApplyS(AR: UInt64; ABox: PByte): UInt64; inline;

    /// <summary>
    /// Replace every byte of the input by the byte at that place <br />in
    /// the nonlinear S-box
    /// </summary>
    procedure Substitution(ABox: PByte); inline;

    /// <summary>
    /// Mix the bytes of every column in a linear way
    /// </summary>
    procedure MixColumn();

    /// <summary>
    /// Mix the bytes of every column in a linear way <br />This is the
    /// opposite operation of Mixcolumn
    /// </summary>
    procedure InvMixColumn();

    /// <summary>
    /// Calculate the necessary round keys <br />The number of calculations
    /// depends on keyBits and blockBits
    /// </summary>
    function GenerateWorkingKey(const AKey: TCryptoLibByteArray)
      : TCryptoLibMatrixUInt64Array;

    procedure UnPackBlock(const ABytes: TCryptoLibByteArray; AOff: Int32); inline;
    procedure PackBlock(const ABytes: TCryptoLibByteArray; AOff: Int32); inline;

    procedure EncryptBlock(const ARk: TCryptoLibMatrixUInt64Array);

    procedure DecryptBlock(const ARk: TCryptoLibMatrixUInt64Array);

  strict protected
    function GetAlgorithmName: String; virtual;

  public

    /// <summary>
    /// default constructor - 128 bit block size.
    /// </summary>
    constructor Create(); overload;

    /// <summary>
    /// basic constructor - set the cipher up for a given blocksize
    /// </summary>
    /// <param name="ABlockBits">
    /// the blocksize in bits, must be 128, 192, or 256.
    /// </param>
    constructor Create(ABlockBits: Int32); overload;

    /// <summary>
    /// initialise a Rijndael cipher.
    /// </summary>
    /// <param name="AForEncryption">
    /// whether or not we are for encryption.
    /// </param>
    /// <param name="AParameters">
    /// the parameters required to set up the cipher.
    /// </param>
    /// <exception cref="ClpCryptoLibTypes|EArgumentCryptoLibException">
    /// if the parameters argument is inappropriate.
    /// </exception>
    procedure Init(AForEncryption: Boolean;
      const AParameters: ICipherParameters); virtual;

    function ProcessBlock(const AInput: TCryptoLibByteArray; AInOff: Int32;
      const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32; virtual;

    function GetBlockSize(): Int32; virtual;

    property AlgorithmName: String read GetAlgorithmName;

  end;

implementation

{ TRijndaelEngine }

function TRijndaelEngine.Mul0x2(AB: Int32): Byte;
begin
  if (AB <> 0) then
  begin
    Result := ALogTable[25 + (LogTable[AB] and $FF)];
  end
  else
  begin
    Result := 0;
  end;
end;

function TRijndaelEngine.Mul0x3(AB: Int32): Byte;
begin
  if (AB <> 0) then
  begin
    Result := ALogTable[1 + (LogTable[AB] and $FF)];
  end
  else
  begin
    Result := 0;
  end;
end;

function TRijndaelEngine.Mul0x9(AB: Int32): Byte;
begin
  if (AB >= 0) then
  begin
    Result := ALogTable[199 + AB];
  end
  else
  begin
    Result := 0;
  end;
end;

function TRijndaelEngine.Mul0xb(AB: Int32): Byte;
begin
  if (AB >= 0) then
  begin
    Result := ALogTable[104 + AB];
  end
  else
  begin
    Result := 0;
  end;
end;

function TRijndaelEngine.Mul0xd(AB: Int32): Byte;
begin
  if (AB >= 0) then
  begin
    Result := ALogTable[238 + AB];
  end
  else
  begin
    Result := 0;
  end;
end;

function TRijndaelEngine.Mul0xe(AB: Int32): Byte;
begin
  if (AB >= 0) then
  begin
    Result := ALogTable[223 + AB];
  end
  else
  begin
    Result := 0;
  end;
end;

procedure TRijndaelEngine.KeyAddition(const ARk: TCryptoLibUInt64Array);
begin
  FA0 := FA0 xor ARk[0];
  FA1 := FA1 xor ARk[1];
  FA2 := FA2 xor ARk[2];
  FA3 := FA3 xor ARk[3];
end;

function TRijndaelEngine.Shift(AR: UInt64; AShift: Int32): UInt64;
begin
  Result := (((AR shr AShift) or (AR shl (FBC - AShift)))) and FBC_MASK;
end;

procedure TRijndaelEngine.ShiftRow(const AShiftsSC: TCryptoLibByteArray);
begin
  FA1 := Shift(FA1, AShiftsSC[1]);
  FA2 := Shift(FA2, AShiftsSC[2]);
  FA3 := Shift(FA3, AShiftsSC[3]);
end;

function TRijndaelEngine.ApplyS(AR: UInt64; ABox: PByte): UInt64;
var
  LJ: Int32;
begin
  Result := 0;
  LJ := 0;
  while LJ < FBC do
  begin
    Result := Result or (UInt64(ABox[((AR shr LJ) and $FF)] and $FF) shl LJ);
    System.Inc(LJ, 8);
  end;
end;

procedure TRijndaelEngine.Substitution(ABox: PByte);
begin
  FA0 := ApplyS(FA0, ABox);
  FA1 := ApplyS(FA1, ABox);
  FA2 := ApplyS(FA2, ABox);
  FA3 := ApplyS(FA3, ABox);
end;

procedure TRijndaelEngine.MixColumn;
var
  LR0, LR1, LR2, LR3: UInt64;
  LA0, LA1, LA2, LA3, LJ: Int32;
begin
  LR0 := 0;
  LR1 := 0;
  LR2 := 0;
  LR3 := 0;
  LJ := 0;
  while LJ < FBC do
  begin

    LA0 := Int32((FA0 shr LJ) and $FF);
    LA1 := Int32((FA1 shr LJ) and $FF);
    LA2 := Int32((FA2 shr LJ) and $FF);
    LA3 := Int32((FA3 shr LJ) and $FF);

    LR0 := LR0 or (UInt64(((Mul0x2(LA0) xor Mul0x3(LA1) xor LA2 xor LA3) and
      $FF)) shl LJ);

    LR1 := LR1 or (UInt64(((Mul0x2(LA1) xor Mul0x3(LA2) xor LA3 xor LA0) and
      $FF)) shl LJ);

    LR2 := LR2 or (UInt64(((Mul0x2(LA2) xor Mul0x3(LA3) xor LA0 xor LA1) and
      $FF)) shl LJ);

    LR3 := LR3 or (UInt64(((Mul0x2(LA3) xor Mul0x3(LA0) xor LA1 xor LA2) and
      $FF)) shl LJ);

    System.Inc(LJ, 8);
  end;

  FA0 := LR0;
  FA1 := LR1;
  FA2 := LR2;
  FA3 := LR3;
end;

procedure TRijndaelEngine.InvMixColumn;
var
  LR0, LR1, LR2, LR3: UInt64;
  LA0, LA1, LA2, LA3, LJ: Int32;
begin
  LR0 := 0;
  LR1 := 0;
  LR2 := 0;
  LR3 := 0;
  LJ := 0;
  while LJ < FBC do
  begin

    LA0 := Int32((FA0 shr LJ) and $FF);
    LA1 := Int32((FA1 shr LJ) and $FF);
    LA2 := Int32((FA2 shr LJ) and $FF);
    LA3 := Int32((FA3 shr LJ) and $FF);

    //
    // pre-lookup the log table
    //
    if (LA0 <> 0) then
    begin
      LA0 := (LogTable[LA0 and $FF] and $FF);
    end
    else
    begin
      LA0 := -1;
    end;

    if (LA1 <> 0) then
    begin
      LA1 := (LogTable[LA1 and $FF] and $FF);
    end
    else
    begin
      LA1 := -1;
    end;

    if (LA2 <> 0) then
    begin
      LA2 := (LogTable[LA2 and $FF] and $FF);
    end
    else
    begin
      LA2 := -1;
    end;

    if (LA3 <> 0) then
    begin
      LA3 := (LogTable[LA3 and $FF] and $FF);
    end
    else
    begin
      LA3 := -1;
    end;

    LR0 := LR0 or
      (UInt64(((Mul0xe(LA0) xor Mul0xb(LA1) xor Mul0xd(LA2) xor Mul0x9(LA3)) and
      $FF)) shl LJ);

    LR1 := LR1 or
      (UInt64(((Mul0xe(LA1) xor Mul0xb(LA2) xor Mul0xd(LA3) xor Mul0x9(LA0)) and
      $FF)) shl LJ);

    LR2 := LR2 or
      (UInt64(((Mul0xe(LA2) xor Mul0xb(LA3) xor Mul0xd(LA0) xor Mul0x9(LA1)) and
      $FF)) shl LJ);

    LR3 := LR3 or
      (UInt64(((Mul0xe(LA3) xor Mul0xb(LA0) xor Mul0xd(LA1) xor Mul0x9(LA2)) and
      $FF)) shl LJ);

    System.Inc(LJ, 8);
  end;

  FA0 := LR0;
  FA1 := LR1;
  FA2 := LR2;
  FA3 := LR3;
end;

function TRijndaelEngine.GenerateWorkingKey(const AKey: TCryptoLibByteArray)
  : TCryptoLibMatrixUInt64Array;
var
  LKc, LT, LRConPointer, LKeyBits, LI, LIndex, LJ: Int32;
  LTk: TCryptoLibMatrixByteArray;
  LW: TCryptoLibMatrixUInt64Array;
begin
  LRConPointer := 0;
  LKeyBits := System.Length(AKey) * 8;
  System.SetLength(LTk, 4);
  for LI := System.Low(LTk) to System.High(LTk) do
  begin
    System.SetLength(LTk[LI], MAXKC);
  end;

  System.SetLength(LW, MAXROUNDS + 1);
  for LI := System.Low(LW) to System.High(LW) do
  begin
    System.SetLength(LW[LI], 4);
  end;

  case LKeyBits of
    128:
      LKc := 4;
    160:
      LKc := 5;
    192:
      LKc := 6;
    224:
      LKc := 7;
    256:
      LKc := 8
  else
    begin
      TArrayUtilities.Fill<Byte>(AKey, 0, System.Length(AKey), Byte(0));
      raise EArgumentCryptoLibException.CreateRes(@SInvalidKeyLength);
    end;
  end;

  if (LKeyBits >= FBlockBits) then
  begin
    FROUNDS := LKc + 6;
  end
  else
  begin
    FROUNDS := (FBC div 8) + 6;
  end;

  //
  // copy the key into the processing area
  //
  LIndex := 0;

  for LI := 0 to System.Pred(System.Length(AKey)) do
  begin
    LTk[LI mod 4][LI div 4] := AKey[LIndex];
    System.Inc(LIndex);
  end;

  LT := 0;
  //
  // copy values into round key array
  //
  LJ := 0;

  while ((LJ < LKc) and (LT < ((FROUNDS + 1) * (FBC div 8)))) do
  begin
    for LI := 0 to System.Pred(4) do
    begin
      LW[LT div (FBC div 8)][LI] := LW[LT div (FBC div 8)][LI] or
        (UInt64(LTk[LI][LJ] and $FF) shl ((LT * 8) mod FBC));
    end;
    System.Inc(LJ);
    System.Inc(LT);
  end;

  //
  // while not enough round key material calculated
  // calculate new values
  //
  while (LT < ((FROUNDS + 1) * (FBC div 8))) do
  begin

    for LI := 0 to System.Pred(4) do
    begin
      LTk[LI][0] := LTk[LI][0] xor (S[LTk[(LI + 1) mod 4][LKc - 1] and $FF]);
    end;

    LTk[0][0] := LTk[0][0] xor Byte(RCon[LRConPointer]);
    System.Inc(LRConPointer);

    if (LKc <= 6) then
    begin
      for LJ := 1 to System.Pred(LKc) do
      begin
        for LI := 0 to System.Pred(4) do
        begin
          LTk[LI][LJ] := LTk[LI][LJ] xor LTk[LI][LJ - 1];
        end;
      end;
    end
    else
    begin

      for LJ := 1 to System.Pred(4) do
      begin
        for LI := 0 to System.Pred(4) do
        begin
          LTk[LI][LJ] := LTk[LI][LJ] xor LTk[LI][LJ - 1];
        end;
      end;

      for LI := 0 to System.Pred(4) do
      begin
        LTk[LI][4] := LTk[LI][4] xor (S[LTk[LI][3] and $FF]);
      end;

      for LJ := 5 to System.Pred(LKc) do
      begin
        for LI := 0 to System.Pred(4) do
        begin
          LTk[LI][LJ] := LTk[LI][LJ] xor LTk[LI][LJ - 1];
        end;
      end;
    end;

    //
    // copy values into round key array
    //
    LJ := 0;

    while ((LJ < LKc) and (LT < ((FROUNDS + 1) * (FBC div 8)))) do
    begin
      for LI := 0 to System.Pred(4) do
      begin
        LW[LT div (FBC div 8)][LI] := LW[LT div (FBC div 8)][LI] or
          (UInt64(LTk[LI][LJ] and $FF) shl ((LT * 8) mod FBC));
      end;
      System.Inc(LJ);
      System.Inc(LT);
    end;
  end;
  Result := LW;

  TArrayUtilities.Fill<Byte>(AKey, 0, System.Length(AKey), Byte(0));
end;

procedure TRijndaelEngine.PackBlock(const ABytes: TCryptoLibByteArray;
  AOff: Int32);
var
  LIndex, LJ: Int32;
begin
  LIndex := AOff;
  LJ := 0;

  while LJ <> FBC do
  begin
    ABytes[LIndex] := Byte(FA0 shr LJ);
    System.Inc(LIndex);
    ABytes[LIndex] := Byte(FA1 shr LJ);
    System.Inc(LIndex);
    ABytes[LIndex] := Byte(FA2 shr LJ);
    System.Inc(LIndex);
    ABytes[LIndex] := Byte(FA3 shr LJ);
    System.Inc(LIndex);
    System.Inc(LJ, 8);
  end;
end;

procedure TRijndaelEngine.UnPackBlock(const ABytes: TCryptoLibByteArray;
  AOff: Int32);
var
  LIndex, LJ: Int32;
begin
  LIndex := AOff;

  FA0 := UInt64(ABytes[LIndex] and $FF);
  System.Inc(LIndex);
  FA1 := UInt64(ABytes[LIndex] and $FF);
  System.Inc(LIndex);
  FA2 := UInt64(ABytes[LIndex] and $FF);
  System.Inc(LIndex);
  FA3 := UInt64(ABytes[LIndex] and $FF);
  System.Inc(LIndex);

  LJ := 8;

  while LJ <> FBC do
  begin
    FA0 := FA0 or (UInt64(ABytes[LIndex] and $FF) shl LJ);
    System.Inc(LIndex);
    FA1 := FA1 or (UInt64(ABytes[LIndex] and $FF) shl LJ);
    System.Inc(LIndex);
    FA2 := FA2 or (UInt64(ABytes[LIndex] and $FF) shl LJ);
    System.Inc(LIndex);
    FA3 := FA3 or (UInt64(ABytes[LIndex] and $FF) shl LJ);
    System.Inc(LIndex);
    System.Inc(LJ, 8);
  end;
end;

procedure TRijndaelEngine.EncryptBlock(const ARk: TCryptoLibMatrixUInt64Array);
var
  LR: Int32;
begin
  //
  // begin with a key addition
  //
  KeyAddition(ARk[0]);

  //
  // ROUNDS-1 ordinary rounds
  //
  for LR := 1 to System.Pred(FROUNDS) do
  begin
    Substitution(@(S[0]));
    ShiftRow(FShifts0SC);
    MixColumn();
    KeyAddition(ARk[LR]);
  end;

  //
  // Last round is special: there is no MixColumn
  //
  Substitution(@(S[0]));
  ShiftRow(FShifts0SC);
  KeyAddition(ARk[FROUNDS]);
end;

procedure TRijndaelEngine.DecryptBlock(const ARk: TCryptoLibMatrixUInt64Array);
var
  LR: Int32;
begin
  // To decrypt: apply the inverse operations of the encrypt routine,
  // in opposite order
  //
  // (KeyAddition is an involution: it 's equal to its inverse)
  // (the inverse of Substitution with table S is Substitution with the inverse table of S)
  // (the inverse of Shiftrow is Shiftrow over a suitable distance)
  //

  // First the special round:
  // without InvMixColumn
  // with extra KeyAddition
  //
  KeyAddition(ARk[FROUNDS]);
  Substitution(@(Si[0]));
  ShiftRow(FShifts1SC);

  //
  // ROUNDS-1 ordinary rounds
  //
  for LR := System.Pred(FROUNDS) downto 1 do
  begin
    KeyAddition(ARk[LR]);
    InvMixColumn();
    Substitution(@(Si[0]));
    ShiftRow(FShifts1SC);
  end;

  //
  // End with the extra key addition
  //
  KeyAddition(ARk[0]);
end;

constructor TRijndaelEngine.Create();
begin
  Create(128);
end;

constructor TRijndaelEngine.Create(ABlockBits: Int32);
begin
  Inherited Create();
  case ABlockBits of

    128:
      begin
        FBC := 32;
        FBC_MASK := $FFFFFFFF;
        System.SetLength(FShifts0SC, System.SizeOf(Shifts0[0]));
        System.Move(Shifts0[0], FShifts0SC[0], System.SizeOf(Shifts0[0]));
        System.SetLength(FShifts1SC, System.SizeOf(Shifts1[0]));
        System.Move(Shifts1[0], FShifts1SC[0], System.SizeOf(Shifts1[0]));
      end;

    160:
      begin
        FBC := 40;
        FBC_MASK := $FFFFFFFFFF;
        System.SetLength(FShifts0SC, System.SizeOf(Shifts0[1]));
        System.Move(Shifts0[1], FShifts0SC[0], System.SizeOf(Shifts0[1]));
        System.SetLength(FShifts1SC, System.SizeOf(Shifts1[1]));
        System.Move(Shifts1[1], FShifts1SC[0], System.SizeOf(Shifts1[1]));
      end;

    192:
      begin
        FBC := 48;
        FBC_MASK := $FFFFFFFFFFFF;
        System.SetLength(FShifts0SC, System.SizeOf(Shifts0[2]));
        System.Move(Shifts0[2], FShifts0SC[0], System.SizeOf(Shifts0[2]));
        System.SetLength(FShifts1SC, System.SizeOf(Shifts1[2]));
        System.Move(Shifts1[2], FShifts1SC[0], System.SizeOf(Shifts1[2]));
      end;

    224:
      begin
        FBC := 56;
        FBC_MASK := $FFFFFFFFFFFFFF;
        System.SetLength(FShifts0SC, System.SizeOf(Shifts0[3]));
        System.Move(Shifts0[3], FShifts0SC[0], System.SizeOf(Shifts0[3]));
        System.SetLength(FShifts1SC, System.SizeOf(Shifts1[3]));
        System.Move(Shifts1[3], FShifts1SC[0], System.SizeOf(Shifts1[3]));
      end;

    256:
      begin
        FBC := 64;
        FBC_MASK := UInt64($FFFFFFFFFFFFFFFF);
        System.SetLength(FShifts0SC, System.SizeOf(Shifts0[4]));
        System.Move(Shifts0[4], FShifts0SC[0], System.SizeOf(Shifts0[4]));
        System.SetLength(FShifts1SC, System.SizeOf(Shifts1[4]));
        System.Move(Shifts1[4], FShifts1SC[0], System.SizeOf(Shifts1[4]));
      end
  else
    begin
      raise EArgumentOutOfRangeCryptoLibException.CreateRes(@SUnsupportedBlock);
    end;

  end;

  FBlockBits := ABlockBits;
end;

function TRijndaelEngine.GetAlgorithmName: String;
begin
  Result := 'Rijndael';
end;

function TRijndaelEngine.GetBlockSize: Int32;
begin
  Result := FBC div 2;
end;

procedure TRijndaelEngine.Init(AForEncryption: Boolean;
  const AParameters: ICipherParameters);
var
  LKeyParameter: IKeyParameter;
begin
  if not Supports(AParameters, IKeyParameter, LKeyParameter) then
  begin
    raise EArgumentCryptoLibException.CreateResFmt(@SInvalidParameterRijndaelInit,
      [TPlatformUtilities.GetTypeName(AParameters as TObject)]);
  end;

  FWorkingKey := GenerateWorkingKey(LKeyParameter.GetKey());

  FForEncryption := AForEncryption;
end;

function TRijndaelEngine.ProcessBlock(const AInput: TCryptoLibByteArray;
  AInOff: Int32; const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32;
begin
  if (FWorkingKey = nil) then
  begin
    raise EInvalidOperationCryptoLibException.CreateRes
      (@SRijndaelEngineNotInitialised);
  end;

  TCheck.DataLength(AInput, AInOff, (FBC div 2), SInputBuffertooShort);
  TCheck.OutputLength(AOutput, AOutOff, (FBC div 2), SOutputBuffertooShort);

  UnPackBlock(AInput, AInOff);

  if (FForEncryption) then
  begin
    EncryptBlock(FWorkingKey);
  end
  else
  begin
    DecryptBlock(FWorkingKey);
  end;

  PackBlock(AOutput, AOutOff);

  Result := FBC div 2;
end;

end.
