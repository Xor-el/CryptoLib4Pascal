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

unit ClpAesLightEngine;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpIAesLightEngine,
  ClpIBlockCipher,
  ClpICipherParameters,
  ClpIKeyParameter,
  ClpCheck,
  ClpBitOperations,
  ClpPack,
  ClpArrayUtilities,
  ClpPlatformUtilities,
  ClpCryptoLibTypes;

resourcestring
  SAESEngineNotInitialised = 'AES Engine not Initialised';
  SInputBuffertooShort = 'Input Buffer too Short';
  SOutputBuffertooShort = 'Output Buffer too Short';
  SInvalidParameterAESInit = 'Invalid Parameter Passed to AES Init - "%s"';
  SInvalidKeyLength = 'Key Length not 128/192/256 bits.';
  SInvalidOperation = 'Should Never Get Here';

type

  /// <summary>
  /// <para>
  /// an implementation of the AES (Rijndael), from FIPS-197.
  /// </para>
  /// <para>
  /// For further details see: <see href="http://csrc.nist.gov/encryption/aes/" />
  /// </para>
  /// <para>
  /// This implementation is based on optimizations from Dr. Brian
  /// Gladman's paper and C code at <see href="http://fp.gladman.plus.com/cryptography_technology/rijndael/" />
  /// </para>
  /// <para>
  /// This version uses no static tables at all and computes the values
  /// in each round.
  /// </para>
  /// <para>
  /// This file contains the slowest performance version with no static
  /// tables for round precomputation, but it has the smallest foot
  /// print.
  /// </para>
  /// </summary>
  TAesLightEngine = class sealed(TInterfacedObject, IAesLightEngine,
    IBlockCipher)

  strict private

  const
    // multiply four bytes in GF(2^8) by 'x' {02} in parallel //

    M1 = UInt32($80808080);
    M2 = UInt32($7F7F7F7F);
    M3 = UInt32($0000001B);
    M4 = UInt32($C0C0C0C0);
    M5 = UInt32($3F3F3F3F);
    BLOCK_SIZE = Int32(16);

    // The S box
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

    // The inverse S-box
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

    // vector used in calculating key schedule (powers of x in GF(256))
    RCon: array [0 .. 29] of Byte = ($01, $02, $04, $08, $10, $20, $40, $80,
      $1B, $36, $6C, $D8, $AB, $4D, $9A, $2F, $5E, $BC, $63, $C6, $97, $35, $6A,
      $D4, $B3, $7D, $FA, $EF, $C5, $91);

  var
    FRounds: Int32;
    FWorkingKey: TCryptoLibMatrixUInt32Array;
    FC0, FC1, FC2, FC3: UInt32;
    FForEncryption: Boolean;

    /// <summary>
    /// <para>
    /// Calculate the necessary round keys
    /// </para>
    /// <para>
    /// The number of calculations depends on key size and block size
    /// </para>
    /// <para>
    /// AES specified a fixed block size of 128 bits and key sizes
    /// 128/192/256 bits
    /// </para>
    /// <para>
    /// This code is written assuming those are the only possible values
    /// </para>
    /// </summary>
    function GenerateWorkingKey(AForEncryption: Boolean;
      const AKey: TCryptoLibByteArray): TCryptoLibMatrixUInt32Array;

    procedure UnPackBlock(const ABytes: TCryptoLibByteArray; AOff: Int32); inline;
    procedure PackBlock(const ABytes: TCryptoLibByteArray; AOff: Int32); inline;

    procedure EncryptBlock(const AKw: TCryptoLibMatrixUInt32Array);

    procedure DecryptBlock(const AKw: TCryptoLibMatrixUInt32Array);

    class function Shift(AR: UInt32; AShift: Int32): UInt32; static; inline;
    class function FFmulX(AX: UInt32): UInt32; static; inline;
    class function FFmulX2(AX: UInt32): UInt32; static; inline;

    class function Mcol(AX: UInt32): UInt32; static; inline;
    class function Inv_Mcol(AX: UInt32): UInt32; static; inline;
    class function SubWord(AX: UInt32): UInt32; static; inline;

  strict protected
    function GetAlgorithmName: String; virtual;

  public
    /// <summary>
    /// initialise an AES cipher.
    /// </summary>
    /// <param name="AForEncryption">
    /// whether or not we are for encryption.
    /// </param>
    /// <param name="AParameters">
    /// the parameters required to set up the cipher.
    /// </param>
    /// <exception cref="EArgumentCryptoLibException">
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

{ TAesLightEngine }

class function TAesLightEngine.Shift(AR: UInt32; AShift: Int32): UInt32;
begin
  Result := TBitOperations.RotateRight32(AR, AShift);
end;

class function TAesLightEngine.SubWord(AX: UInt32): UInt32;
begin
  Result := UInt32(S[AX and 255]) or (UInt32(S[(AX shr 8) and 255]) shl 8) or
    (UInt32(S[(AX shr 16) and 255]) shl 16) or
    (UInt32(S[(AX shr 24) and 255]) shl 24);
end;

class function TAesLightEngine.FFmulX(AX: UInt32): UInt32;
begin
  Result := ((AX and M2) shl 1) xor (((AX and M1) shr 7) * M3);
end;

class function TAesLightEngine.FFmulX2(AX: UInt32): UInt32;
var
  LT0, LT1: UInt32;
begin
  LT0 := (AX and M5) shl 2;
  LT1 := (AX and M4);
  LT1 := LT1 xor (LT1 shr 1);
  Result := LT0 xor (LT1 shr 2) xor (LT1 shr 5);
end;

class function TAesLightEngine.Mcol(AX: UInt32): UInt32;
var
  LT0, LT1: UInt32;
begin
  LT0 := Shift(AX, 8);
  LT1 := AX xor LT0;
  Result := Shift(LT1, 16) xor LT0 xor FFmulX(LT1);
end;

class function TAesLightEngine.Inv_Mcol(AX: UInt32): UInt32;
var
  LT0, LT1: UInt32;
begin
  LT0 := AX;
  LT1 := LT0 xor Shift(LT0, 8);
  LT0 := LT0 xor FFmulX(LT1);
  LT1 := LT1 xor FFmulX2(LT0);
  LT0 := LT0 xor (LT1 xor Shift(LT1, 16));
  Result := LT0;
end;

procedure TAesLightEngine.EncryptBlock(const AKw: TCryptoLibMatrixUInt32Array);
var
  LKw: TCryptoLibUInt32Array;
  LT0, LT1, LT2, LR0, LR1, LR2, LR3: UInt32;
  LR: Int32;
begin
  LKw := AKw[0];
  LT0 := FC0 xor LKw[0];
  LT1 := FC1 xor LKw[1];
  LT2 := FC2 xor LKw[2];

  LR3 := FC3 xor LKw[3];
  LR := 1;

  while (LR < FRounds - 1) do
  begin
    LKw := AKw[LR];
    System.Inc(LR);
    LR0 := Mcol(UInt32(S[LT0 and 255]) xor ((UInt32(S[(LT1 shr 8) and 255]))
      shl 8) xor ((UInt32(S[(LT2 shr 16) and 255])) shl 16)
      xor ((UInt32(S[(LR3 shr 24) and 255])) shl 24)) xor LKw[0];
    LR1 := Mcol(UInt32(S[LT1 and 255]) xor ((UInt32(S[(LT2 shr 8) and 255]))
      shl 8) xor ((UInt32(S[(LR3 shr 16) and 255])) shl 16)
      xor ((UInt32(S[(LT0 shr 24) and 255])) shl 24)) xor LKw[1];
    LR2 := Mcol(UInt32(S[LT2 and 255]) xor ((UInt32(S[(LR3 shr 8) and 255]))
      shl 8) xor ((UInt32(S[(LT0 shr 16) and 255])) shl 16)
      xor ((UInt32(S[(LT1 shr 24) and 255])) shl 24)) xor LKw[2];
    LR3 := Mcol(UInt32(S[LR3 and 255]) xor ((UInt32(S[(LT0 shr 8) and 255]))
      shl 8) xor ((UInt32(S[(LT1 shr 16) and 255])) shl 16)
      xor ((UInt32(S[(LT2 shr 24) and 255])) shl 24)) xor LKw[3];
    LKw := AKw[LR];
    System.Inc(LR);
    LT0 := Mcol(UInt32(S[LR0 and 255]) xor ((UInt32(S[(LR1 shr 8) and 255]))
      shl 8) xor ((UInt32(S[(LR2 shr 16) and 255])) shl 16)
      xor ((UInt32(S[(LR3 shr 24) and 255])) shl 24)) xor LKw[0];
    LT1 := Mcol(UInt32(S[LR1 and 255]) xor ((UInt32(S[(LR2 shr 8) and 255]))
      shl 8) xor ((UInt32(S[(LR3 shr 16) and 255])) shl 16)
      xor ((UInt32(S[(LR0 shr 24) and 255])) shl 24)) xor LKw[1];
    LT2 := Mcol(UInt32(S[LR2 and 255]) xor ((UInt32(S[(LR3 shr 8) and 255]))
      shl 8) xor ((UInt32(S[(LR0 shr 16) and 255])) shl 16)
      xor ((UInt32(S[(LR1 shr 24) and 255])) shl 24)) xor LKw[2];
    LR3 := Mcol(UInt32(S[LR3 and 255]) xor ((UInt32(S[(LR0 shr 8) and 255]))
      shl 8) xor ((UInt32(S[(LR1 shr 16) and 255])) shl 16)
      xor ((UInt32(S[(LR2 shr 24) and 255])) shl 24)) xor LKw[3];
  end;

  LKw := AKw[LR];
  System.Inc(LR);
  LR0 := Mcol(UInt32(S[LT0 and 255]) xor ((UInt32(S[(LT1 shr 8) and 255]))
    shl 8) xor ((UInt32(S[(LT2 shr 16) and 255])) shl 16)
    xor ((UInt32(S[(LR3 shr 24) and 255])) shl 24)) xor LKw[0];
  LR1 := Mcol(UInt32(S[LT1 and 255]) xor ((UInt32(S[(LT2 shr 8) and 255]))
    shl 8) xor ((UInt32(S[(LR3 shr 16) and 255])) shl 16)
    xor ((UInt32(S[(LT0 shr 24) and 255])) shl 24)) xor LKw[1];
  LR2 := Mcol(UInt32(S[LT2 and 255]) xor ((UInt32(S[(LR3 shr 8) and 255]))
    shl 8) xor ((UInt32(S[(LT0 shr 16) and 255])) shl 16)
    xor ((UInt32(S[(LT1 shr 24) and 255])) shl 24)) xor LKw[2];
  LR3 := Mcol(UInt32(S[LR3 and 255]) xor ((UInt32(S[(LT0 shr 8) and 255]))
    shl 8) xor ((UInt32(S[(LT1 shr 16) and 255])) shl 16)
    xor ((UInt32(S[(LT2 shr 24) and 255])) shl 24)) xor LKw[3];

  // the final round is a simple function of S

  LKw := AKw[LR];
  FC0 := UInt32(S[LR0 and 255]) xor ((UInt32(S[(LR1 shr 8) and 255])) shl 8)
    xor ((UInt32(S[(LR2 shr 16) and 255])) shl 16)
    xor ((UInt32(S[(LR3 shr 24) and 255])) shl 24) xor LKw[0];
  FC1 := UInt32(S[LR1 and 255]) xor ((UInt32(S[(LR2 shr 8) and 255])) shl 8)
    xor ((UInt32(S[(LR3 shr 16) and 255])) shl 16)
    xor ((UInt32(S[(LR0 shr 24) and 255])) shl 24) xor LKw[1];
  FC2 := UInt32(S[LR2 and 255]) xor ((UInt32(S[(LR3 shr 8) and 255])) shl 8)
    xor ((UInt32(S[(LR0 shr 16) and 255])) shl 16)
    xor ((UInt32(S[(LR1 shr 24) and 255])) shl 24) xor LKw[2];
  FC3 := UInt32(S[LR3 and 255]) xor ((UInt32(S[(LR0 shr 8) and 255])) shl 8)
    xor ((UInt32(S[(LR1 shr 16) and 255])) shl 16)
    xor ((UInt32(S[(LR2 shr 24) and 255])) shl 24) xor LKw[3];
end;

procedure TAesLightEngine.DecryptBlock(const AKw: TCryptoLibMatrixUInt32Array);
var
  LKw: TCryptoLibUInt32Array;
  LT0, LT1, LT2, LR0, LR1, LR2, LR3: UInt32;
  LR: Int32;
begin
  LKw := AKw[FRounds];
  LT0 := FC0 xor LKw[0];
  LT1 := FC1 xor LKw[1];
  LT2 := FC2 xor LKw[2];

  LR3 := FC3 xor LKw[3];
  LR := FRounds - 1;

  while (LR > 1) do
  begin
    LKw := AKw[LR];
    System.Dec(LR);
    LR0 := Inv_Mcol(UInt32(Si[LT0 and 255])
      xor ((UInt32(Si[(LR3 shr 8) and 255])) shl 8)
      xor ((UInt32(Si[(LT2 shr 16) and 255])) shl 16)
      xor (UInt32(Si[(LT1 shr 24) and 255]) shl 24)) xor LKw[0];
    LR1 := Inv_Mcol(UInt32(Si[LT1 and 255])
      xor ((UInt32(Si[(LT0 shr 8) and 255])) shl 8)
      xor ((UInt32(Si[(LR3 shr 16) and 255])) shl 16)
      xor (UInt32(Si[(LT2 shr 24) and 255]) shl 24)) xor LKw[1];
    LR2 := Inv_Mcol(UInt32(Si[LT2 and 255])
      xor ((UInt32(Si[(LT1 shr 8) and 255])) shl 8)
      xor ((UInt32(Si[(LT0 shr 16) and 255])) shl 16)
      xor (UInt32(Si[(LR3 shr 24) and 255]) shl 24)) xor LKw[2];
    LR3 := Inv_Mcol(UInt32(Si[LR3 and 255])
      xor ((UInt32(Si[(LT2 shr 8) and 255])) shl 8)
      xor ((UInt32(Si[(LT1 shr 16) and 255])) shl 16)
      xor (UInt32(Si[(LT0 shr 24) and 255]) shl 24)) xor LKw[3];
    LKw := AKw[LR];
    System.Dec(LR);
    LT0 := Inv_Mcol(UInt32(Si[LR0 and 255])
      xor ((UInt32(Si[(LR3 shr 8) and 255])) shl 8)
      xor ((UInt32(Si[(LR2 shr 16) and 255])) shl 16)
      xor (UInt32(Si[(LR1 shr 24) and 255]) shl 24)) xor LKw[0];
    LT1 := Inv_Mcol(UInt32(Si[LR1 and 255])
      xor ((UInt32(Si[(LR0 shr 8) and 255])) shl 8)
      xor ((UInt32(Si[(LR3 shr 16) and 255])) shl 16)
      xor (UInt32(Si[(LR2 shr 24) and 255]) shl 24)) xor LKw[1];
    LT2 := Inv_Mcol(UInt32(Si[LR2 and 255])
      xor ((UInt32(Si[(LR1 shr 8) and 255])) shl 8)
      xor ((UInt32(Si[(LR0 shr 16) and 255])) shl 16)
      xor (UInt32(Si[(LR3 shr 24) and 255]) shl 24)) xor LKw[2];
    LR3 := Inv_Mcol(UInt32(Si[LR3 and 255])
      xor ((UInt32(Si[(LR2 shr 8) and 255])) shl 8)
      xor ((UInt32(Si[(LR1 shr 16) and 255])) shl 16)
      xor (UInt32(Si[(LR0 shr 24) and 255]) shl 24)) xor LKw[3];
  end;

  LKw := AKw[1];
  LR0 := Inv_Mcol(UInt32(Si[LT0 and 255]) xor ((UInt32(Si[(LR3 shr 8) and 255]))
    shl 8) xor ((UInt32(Si[(LT2 shr 16) and 255])) shl 16)
    xor (UInt32(Si[(LT1 shr 24) and 255]) shl 24)) xor LKw[0];
  LR1 := Inv_Mcol(UInt32(Si[LT1 and 255]) xor ((UInt32(Si[(LT0 shr 8) and 255]))
    shl 8) xor ((UInt32(Si[(LR3 shr 16) and 255])) shl 16)
    xor (UInt32(Si[(LT2 shr 24) and 255]) shl 24)) xor LKw[1];
  LR2 := Inv_Mcol(UInt32(Si[LT2 and 255]) xor ((UInt32(Si[(LT1 shr 8) and 255]))
    shl 8) xor ((UInt32(Si[(LT0 shr 16) and 255])) shl 16)
    xor (UInt32(Si[(LR3 shr 24) and 255]) shl 24)) xor LKw[2];
  LR3 := Inv_Mcol(UInt32(Si[LR3 and 255]) xor ((UInt32(Si[(LT2 shr 8) and 255]))
    shl 8) xor ((UInt32(Si[(LT1 shr 16) and 255])) shl 16)
    xor (UInt32(Si[(LT0 shr 24) and 255]) shl 24)) xor LKw[3];

  // the final round's table is a simple function of Si

  LKw := AKw[0];
  FC0 := UInt32(Si[LR0 and 255]) xor ((UInt32(Si[(LR3 shr 8) and 255])) shl 8)
    xor ((UInt32(Si[(LR2 shr 16) and 255])) shl 16)
    xor ((UInt32(Si[(LR1 shr 24) and 255])) shl 24) xor LKw[0];
  FC1 := UInt32(Si[LR1 and 255]) xor ((UInt32(Si[(LR0 shr 8) and 255])) shl 8)
    xor ((UInt32(Si[(LR3 shr 16) and 255])) shl 16)
    xor ((UInt32(Si[(LR2 shr 24) and 255])) shl 24) xor LKw[1];
  FC2 := UInt32(Si[LR2 and 255]) xor ((UInt32(Si[(LR1 shr 8) and 255])) shl 8)
    xor ((UInt32(Si[(LR0 shr 16) and 255])) shl 16)
    xor ((UInt32(Si[(LR3 shr 24) and 255])) shl 24) xor LKw[2];
  FC3 := UInt32(Si[LR3 and 255]) xor ((UInt32(Si[(LR2 shr 8) and 255])) shl 8)
    xor ((UInt32(Si[(LR1 shr 16) and 255])) shl 16)
    xor ((UInt32(Si[(LR0 shr 24) and 255])) shl 24) xor LKw[3];
end;

function TAesLightEngine.GenerateWorkingKey(AForEncryption: Boolean;
  const AKey: TCryptoLibByteArray): TCryptoLibMatrixUInt32Array;
var
  LKeyLen, LKc, LI, LJ: Int32;
  LSmallW: TCryptoLibUInt32Array;
  LBigW: TCryptoLibMatrixUInt32Array;
  LU, LRCon, LT0, LT1, LT2, LT3, LT4, LT5, LT6, LT7: UInt32;

begin
  LKeyLen := System.Length(AKey);
  if ((LKeyLen < 16) or (LKeyLen > 32) or ((LKeyLen and 7) <> 0)) then
  begin
    TArrayUtilities.Fill<Byte>(AKey, 0, System.Length(AKey), Byte(0));
    raise EArgumentCryptoLibException.CreateRes(@SInvalidKeyLength);
  end;

  LKc := LKeyLen shr 2;
  FRounds := LKc + 6;
  // This is not always true for the generalized Rijndael that allows larger block sizes
  System.SetLength(LBigW, FRounds + 1); // 4 words in a block

  for LI := 0 to FRounds do
  begin
    System.SetLength(LBigW[LI], 4);
  end;

  case LKc of
    4:
      begin
        LT0 := TPack.LE_To_UInt32(AKey, 0);
        LBigW[0][0] := LT0;
        LT1 := TPack.LE_To_UInt32(AKey, 4);
        LBigW[0][1] := LT1;
        LT2 := TPack.LE_To_UInt32(AKey, 8);
        LBigW[0][2] := LT2;
        LT3 := TPack.LE_To_UInt32(AKey, 12);
        LBigW[0][3] := LT3;

        for LI := 1 to 10 do
        begin
          LU := SubWord(Shift(LT3, 8)) xor RCon[LI - 1];
          LT0 := LT0 xor LU;
          LBigW[LI][0] := LT0;
          LT1 := LT1 xor LT0;
          LBigW[LI][1] := LT1;
          LT2 := LT2 xor LT1;
          LBigW[LI][2] := LT2;
          LT3 := LT3 xor LT2;
          LBigW[LI][3] := LT3;
        end;
      end;

    6:
      begin
        LT0 := TPack.LE_To_UInt32(AKey, 0);
        LBigW[0][0] := LT0;
        LT1 := TPack.LE_To_UInt32(AKey, 4);
        LBigW[0][1] := LT1;
        LT2 := TPack.LE_To_UInt32(AKey, 8);
        LBigW[0][2] := LT2;
        LT3 := TPack.LE_To_UInt32(AKey, 12);
        LBigW[0][3] := LT3;
        LT4 := TPack.LE_To_UInt32(AKey, 16);
        LBigW[1][0] := LT4;
        LT5 := TPack.LE_To_UInt32(AKey, 20);
        LBigW[1][1] := LT5;

        LRCon := 1;
        LU := SubWord(Shift(LT5, 8)) xor LRCon;
        LRCon := LRCon shl 1;
        LT0 := LT0 xor LU;
        LBigW[1][2] := LT0;
        LT1 := LT1 xor LT0;
        LBigW[1][3] := LT1;
        LT2 := LT2 xor LT1;
        LBigW[2][0] := LT2;
        LT3 := LT3 xor LT2;
        LBigW[2][1] := LT3;
        LT4 := LT4 xor LT3;
        LBigW[2][2] := LT4;
        LT5 := LT5 xor LT4;
        LBigW[2][3] := LT5;

        LI := 3;

        while LI < 12 do

        begin
          LU := SubWord(Shift(LT5, 8)) xor LRCon;
          LRCon := LRCon shl 1;
          LT0 := LT0 xor LU;
          LBigW[LI][0] := LT0;
          LT1 := LT1 xor LT0;
          LBigW[LI][1] := LT1;
          LT2 := LT2 xor LT1;
          LBigW[LI][2] := LT2;
          LT3 := LT3 xor LT2;
          LBigW[LI][3] := LT3;
          LT4 := LT4 xor LT3;
          LBigW[LI + 1][0] := LT4;
          LT5 := LT5 xor LT4;
          LBigW[LI + 1][1] := LT5;
          LU := SubWord(Shift(LT5, 8)) xor LRCon;
          LRCon := LRCon shl 1;
          LT0 := LT0 xor LU;
          LBigW[LI + 1][2] := LT0;
          LT1 := LT1 xor LT0;
          LBigW[LI + 1][3] := LT1;
          LT2 := LT2 xor LT1;
          LBigW[LI + 2][0] := LT2;
          LT3 := LT3 xor LT2;
          LBigW[LI + 2][1] := LT3;
          LT4 := LT4 xor LT3;
          LBigW[LI + 2][2] := LT4;
          LT5 := LT5 xor LT4;
          LBigW[LI + 2][3] := LT5;
          System.Inc(LI, 3);
        end;

        LU := SubWord(Shift(LT5, 8)) xor LRCon;
        LT0 := LT0 xor LU;
        LBigW[12][0] := LT0;
        LT1 := LT1 xor LT0;
        LBigW[12][1] := LT1;
        LT2 := LT2 xor LT1;
        LBigW[12][2] := LT2;
        LT3 := LT3 xor LT2;
        LBigW[12][3] := LT3;
      end;

    8:
      begin
        LT0 := TPack.LE_To_UInt32(AKey, 0);
        LBigW[0][0] := LT0;
        LT1 := TPack.LE_To_UInt32(AKey, 4);
        LBigW[0][1] := LT1;
        LT2 := TPack.LE_To_UInt32(AKey, 8);
        LBigW[0][2] := LT2;
        LT3 := TPack.LE_To_UInt32(AKey, 12);
        LBigW[0][3] := LT3;
        LT4 := TPack.LE_To_UInt32(AKey, 16);
        LBigW[1][0] := LT4;
        LT5 := TPack.LE_To_UInt32(AKey, 20);
        LBigW[1][1] := LT5;
        LT6 := TPack.LE_To_UInt32(AKey, 24);
        LBigW[1][2] := LT6;
        LT7 := TPack.LE_To_UInt32(AKey, 28);
        LBigW[1][3] := LT7;

        LRCon := 1;

        LI := 2;

        while LI < 14 do

        begin
          LU := SubWord(Shift(LT7, 8)) xor LRCon;
          LRCon := LRCon shl 1;
          LT0 := LT0 xor LU;
          LBigW[LI][0] := LT0;
          LT1 := LT1 xor LT0;
          LBigW[LI][1] := LT1;
          LT2 := LT2 xor LT1;
          LBigW[LI][2] := LT2;
          LT3 := LT3 xor LT2;;
          LBigW[LI][3] := LT3;
          LU := SubWord(LT3);
          LT4 := LT4 xor LU;
          LBigW[LI + 1][0] := LT4;
          LT5 := LT5 xor LT4;
          LBigW[LI + 1][1] := LT5;
          LT6 := LT6 xor LT5;
          LBigW[LI + 1][2] := LT6;
          LT7 := LT7 xor LT6;
          LBigW[LI + 1][3] := LT7;
          System.Inc(LI, 2);
        end;

        LU := SubWord(Shift(LT7, 8)) xor LRCon;
        LT0 := LT0 xor LU;
        LBigW[14][0] := LT0;
        LT1 := LT1 xor LT0;
        LBigW[14][1] := LT1;
        LT2 := LT2 xor LT1;
        LBigW[14][2] := LT2;
        LT3 := LT3 xor LT2;;
        LBigW[14][3] := LT3;
      end
  else
    begin
      TArrayUtilities.Fill<Byte>(AKey, 0, System.Length(AKey), Byte(0));
      raise EInvalidOperationCryptoLibException.CreateRes(@SInvalidOperation);
    end;
  end;

  if (not AForEncryption) then
  begin
    for LJ := 1 to System.Pred(FRounds) do

    begin
      LSmallW := LBigW[LJ];
      for LI := 0 to System.Pred(4) do

      begin
        LSmallW[LI] := Inv_Mcol(LSmallW[LI]);
      end;
    end;
  end;

  Result := LBigW;

  TArrayUtilities.Fill<Byte>(AKey, 0, System.Length(AKey), Byte(0));
end;

function TAesLightEngine.GetAlgorithmName: String;
begin
  Result := 'AES';
end;

function TAesLightEngine.GetBlockSize: Int32;
begin
  Result := BLOCK_SIZE;
end;

procedure TAesLightEngine.Init(AForEncryption: Boolean;
  const AParameters: ICipherParameters);
var
  LKeyParameter: IKeyParameter;
begin

  if not Supports(AParameters, IKeyParameter, LKeyParameter) then
  begin
    raise EArgumentCryptoLibException.CreateResFmt(@SInvalidParameterAESInit,
      [TPlatformUtilities.GetTypeName(AParameters as TObject)]);
  end;

  FWorkingKey := GenerateWorkingKey(AForEncryption, LKeyParameter.GetKey());

  FForEncryption := AForEncryption;
end;

procedure TAesLightEngine.PackBlock(const ABytes: TCryptoLibByteArray;
  AOff: Int32);
begin
  TPack.UInt32_To_LE(FC0, ABytes, AOff);
  TPack.UInt32_To_LE(FC1, ABytes, AOff + 4);
  TPack.UInt32_To_LE(FC2, ABytes, AOff + 8);
  TPack.UInt32_To_LE(FC3, ABytes, AOff + 12);
end;

procedure TAesLightEngine.UnPackBlock(const ABytes: TCryptoLibByteArray;
  AOff: Int32);
begin
  FC0 := TPack.LE_To_UInt32(ABytes, AOff);
  FC1 := TPack.LE_To_UInt32(ABytes, AOff + 4);
  FC2 := TPack.LE_To_UInt32(ABytes, AOff + 8);
  FC3 := TPack.LE_To_UInt32(ABytes, AOff + 12);
end;

function TAesLightEngine.ProcessBlock(const AInput: TCryptoLibByteArray;
  AInOff: Int32; const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32;
begin
  if (FWorkingKey = nil) then
  begin
    raise EInvalidOperationCryptoLibException.CreateRes
      (@SAESEngineNotInitialised);
  end;

  TCheck.DataLength(AInput, AInOff, 16, SInputBuffertooShort);
  TCheck.OutputLength(AOutput, AOutOff, 16, SOutputBuffertooShort);

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

  Result := BLOCK_SIZE;
end;

end.
