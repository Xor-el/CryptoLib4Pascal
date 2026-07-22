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

unit ClpAesBitSlicedEngine;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpIAesEngine,
  ClpIBlockCipher,
  ClpICipherParameters,
  ClpIKeyParameter,
  ClpCheck,
  ClpPack,
  ClpBitOperations,
  ClpArrayUtilities,
  ClpPlatformUtilities,
  ClpCryptoLibTypes,
  ClpCryptoLibExceptions;

resourcestring
  SAesEngineNotInitialized = 'AES engine not initialized';
  SInputBufferTooShort = 'input buffer too short';
  SOutputBufferTooShort = 'output buffer too short';
  SInvalidParameterAESInit = 'invalid parameter passed to AES init: %s';
  SInvalidKeyLength = 'key length not 128/192/256 bits';

type

  /// <summary>
  /// Constant-time, table-free AES (Rijndael) per FIPS-197.
  /// </summary>
  /// <remarks>
  /// <para>
  /// A software AES engine that performs no data- or key-dependent memory
  /// lookups and takes no secret-dependent branch: the S-box is realised as a
  /// Boolean circuit (Boyar&#8211;Peralta) over a bit-sliced state held in eight
  /// <c>UInt64</c> words, and the linear layers are word rotations/XORs. It is
  /// therefore immune to cache-timing side channels that affect the table-based
  /// <c>TAesEngine</c>.
  /// </para>
  /// <para>
  /// It is a full <see cref="IBlockCipher"/>/<see cref="IAesEngine"/> peer to
  /// <c>TAesEngine</c> (both encrypt and decrypt, 128/192/256-bit keys) and is
  /// bit-exact with it. It is materially slower per byte than the table engine.
  /// </para>
  /// <para>
  /// Intended use is constant-time software AES on hosts without hardware AES.
  /// </para>
  /// </remarks>
  TAesBitSlicedEngine = class sealed(TInterfacedObject, IAesEngine, IBlockCipher)

  strict private
  const
    BLOCK_SIZE = Int32(16);

  type
    // Bit-sliced AES state / round key: eight bit-planes, one per UInt64 word.
    TBitSliceState = array [0 .. 7] of UInt64;

  const
    // Round constants (powers of x in GF(2^8)); ten entries cover AES-128/192/256.
    RCon: array [0 .. 9] of Byte = ($01, $02, $04, $08, $10, $20, $40, $80,
      $1B, $36);

  var
    FRounds: Int32;
    // Expanded (uncompressed) round keys in bit-sliced form: (FRounds + 1) * 8 words.
    FSkey: TCryptoLibUInt64Array;
    FForEncryption: Boolean;

    class procedure Swapn(ACl, ACh: UInt64; AShift: Int32;
      var AX, AY: UInt64); static; inline;
    class procedure Ortho(var AQ: TBitSliceState); static;
    class procedure InterleaveIn(const AW0, AW1, AW2, AW3: UInt32;
      out AQ0, AQ1: UInt64); static;
    class procedure InterleaveOut(out AW0, AW1, AW2, AW3: UInt32;
      AQ0, AQ1: UInt64); static;
    class procedure BitsliceSbox(var AQ: TBitSliceState); static;
    class procedure BitsliceInvSbox(var AQ: TBitSliceState); static;
    class procedure ShiftRows(var AQ: TBitSliceState); static;
    class procedure InvShiftRows(var AQ: TBitSliceState); static;
    class procedure MixColumns(var AQ: TBitSliceState); static;
    class procedure InvMixColumns(var AQ: TBitSliceState); static;
    class function Rotr32(AX: UInt64): UInt64; static; inline;
    class function SubWord(AX: UInt32): UInt32; static;
    class procedure AddRoundKey(var AQ: TBitSliceState;
      const ASkey: TCryptoLibUInt64Array; ASkOff: Int32); static; inline;

    procedure KeySchedule(const AKey: TCryptoLibByteArray);
    procedure BitsliceEncrypt(var AQ: TBitSliceState);
    procedure BitsliceDecrypt(var AQ: TBitSliceState);

  strict protected
    function GetAlgorithmName: String; virtual;

  public

    /// <summary>Initialise the bit-sliced AES cipher.</summary>
    /// <param name="AForEncryption">Whether to initialise for encryption.</param>
    /// <param name="AParameters">The key parameters required to set up the cipher.</param>
    /// <exception cref="EArgumentCryptoLibException">If the parameters argument is inappropriate.</exception>
    procedure Init(AForEncryption: Boolean;
      const AParameters: ICipherParameters); virtual;

    /// <summary>Process one 16-byte block.</summary>
    /// <returns>Always 16 (AES block size in bytes).</returns>
    /// <exception cref="EInvalidOperationCryptoLibException">If <c>Init</c> has not been called.</exception>
    /// <exception cref="EDataLengthCryptoLibException">If the input or output buffer range is too short.</exception>
    function ProcessBlock(const AInput: TCryptoLibByteArray; AInOff: Int32;
      const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32; virtual;

    /// <summary>Return the AES block size.</summary>
    /// <returns>16 (fixed AES block size in bytes).</returns>
    function GetBlockSize(): Int32; virtual;

    /// <summary>Reset the cipher back to its post-Init state.</summary>
    procedure Reset(); virtual;

    /// <summary>Zeroize the expanded round-key schedule on teardown.</summary>
    destructor Destroy; override;

    /// <summary>The cipher name (<c>AES[BitSliced]</c>).</summary>
    property AlgorithmName: String read GetAlgorithmName;
  end;

implementation

{ TAesBitSlicedEngine }

class procedure TAesBitSlicedEngine.Swapn(ACl, ACh: UInt64; AShift: Int32;
  var AX, AY: UInt64);
var
  LA, LB: UInt64;
begin
  LA := AX;
  LB := AY;
  AX := (LA and ACl) or ((LB and ACl) shl AShift);
  AY := ((LA and ACh) shr AShift) or (LB and ACh);
end;

class procedure TAesBitSlicedEngine.Ortho(var AQ: TBitSliceState);
const
  CL2 = UInt64($5555555555555555);
  CH2 = UInt64($AAAAAAAAAAAAAAAA);
  CL4 = UInt64($3333333333333333);
  CH4 = UInt64($CCCCCCCCCCCCCCCC);
  CL8 = UInt64($0F0F0F0F0F0F0F0F);
  CH8 = UInt64($F0F0F0F0F0F0F0F0);
begin
  Swapn(CL2, CH2, 1, AQ[0], AQ[1]);
  Swapn(CL2, CH2, 1, AQ[2], AQ[3]);
  Swapn(CL2, CH2, 1, AQ[4], AQ[5]);
  Swapn(CL2, CH2, 1, AQ[6], AQ[7]);

  Swapn(CL4, CH4, 2, AQ[0], AQ[2]);
  Swapn(CL4, CH4, 2, AQ[1], AQ[3]);
  Swapn(CL4, CH4, 2, AQ[4], AQ[6]);
  Swapn(CL4, CH4, 2, AQ[5], AQ[7]);

  Swapn(CL8, CH8, 4, AQ[0], AQ[4]);
  Swapn(CL8, CH8, 4, AQ[1], AQ[5]);
  Swapn(CL8, CH8, 4, AQ[2], AQ[6]);
  Swapn(CL8, CH8, 4, AQ[3], AQ[7]);
end;

class procedure TAesBitSlicedEngine.InterleaveIn(const AW0, AW1, AW2,
  AW3: UInt32; out AQ0, AQ1: UInt64);
const
  M16 = UInt64($0000FFFF0000FFFF);
  M8 = UInt64($00FF00FF00FF00FF);
var
  LX0, LX1, LX2, LX3: UInt64;
begin
  LX0 := AW0;
  LX1 := AW1;
  LX2 := AW2;
  LX3 := AW3;
  LX0 := LX0 or (LX0 shl 16);
  LX1 := LX1 or (LX1 shl 16);
  LX2 := LX2 or (LX2 shl 16);
  LX3 := LX3 or (LX3 shl 16);
  LX0 := LX0 and M16;
  LX1 := LX1 and M16;
  LX2 := LX2 and M16;
  LX3 := LX3 and M16;
  LX0 := LX0 or (LX0 shl 8);
  LX1 := LX1 or (LX1 shl 8);
  LX2 := LX2 or (LX2 shl 8);
  LX3 := LX3 or (LX3 shl 8);
  LX0 := LX0 and M8;
  LX1 := LX1 and M8;
  LX2 := LX2 and M8;
  LX3 := LX3 and M8;
  AQ0 := LX0 or (LX2 shl 8);
  AQ1 := LX1 or (LX3 shl 8);
end;

class procedure TAesBitSlicedEngine.InterleaveOut(out AW0, AW1, AW2,
  AW3: UInt32; AQ0, AQ1: UInt64);
const
  M16 = UInt64($0000FFFF0000FFFF);
  M8 = UInt64($00FF00FF00FF00FF);
var
  LX0, LX1, LX2, LX3: UInt64;
begin
  LX0 := AQ0 and M8;
  LX1 := AQ1 and M8;
  LX2 := (AQ0 shr 8) and M8;
  LX3 := (AQ1 shr 8) and M8;
  LX0 := LX0 or (LX0 shr 8);
  LX1 := LX1 or (LX1 shr 8);
  LX2 := LX2 or (LX2 shr 8);
  LX3 := LX3 or (LX3 shr 8);
  LX0 := LX0 and M16;
  LX1 := LX1 and M16;
  LX2 := LX2 and M16;
  LX3 := LX3 and M16;
  AW0 := UInt32(LX0) or UInt32(LX0 shr 16);
  AW1 := UInt32(LX1) or UInt32(LX1 shr 16);
  AW2 := UInt32(LX2) or UInt32(LX2 shr 16);
  AW3 := UInt32(LX3) or UInt32(LX3 shr 16);
end;

class procedure TAesBitSlicedEngine.BitsliceSbox(var AQ: TBitSliceState);
var
  x0, x1, x2, x3, x4, x5, x6, x7: UInt64;
  y1, y2, y3, y4, y5, y6, y7, y8, y9: UInt64;
  y10, y11, y12, y13, y14, y15, y16, y17, y18, y19: UInt64;
  y20, y21: UInt64;
  z0, z1, z2, z3, z4, z5, z6, z7, z8, z9: UInt64;
  z10, z11, z12, z13, z14, z15, z16, z17: UInt64;
  t0, t1, t2, t3, t4, t5, t6, t7, t8, t9: UInt64;
  t10, t11, t12, t13, t14, t15, t16, t17, t18, t19: UInt64;
  t20, t21, t22, t23, t24, t25, t26, t27, t28, t29: UInt64;
  t30, t31, t32, t33, t34, t35, t36, t37, t38, t39: UInt64;
  t40, t41, t42, t43, t44, t45, t46, t47, t48, t49: UInt64;
  t50, t51, t52, t53, t54, t55, t56, t57, t58, t59: UInt64;
  t60, t61, t62, t63, t64, t65, t66, t67: UInt64;
  s0, s1, s2, s3, s4, s5, s6, s7: UInt64;
begin
  x0 := AQ[7];
  x1 := AQ[6];
  x2 := AQ[5];
  x3 := AQ[4];
  x4 := AQ[3];
  x5 := AQ[2];
  x6 := AQ[1];
  x7 := AQ[0];

  // Top linear transformation.
  y14 := x3 xor x5;
  y13 := x0 xor x6;
  y9 := x0 xor x3;
  y8 := x0 xor x5;
  t0 := x1 xor x2;
  y1 := t0 xor x7;
  y4 := y1 xor x3;
  y12 := y13 xor y14;
  y2 := y1 xor x0;
  y5 := y1 xor x6;
  y3 := y5 xor y8;
  t1 := x4 xor y12;
  y15 := t1 xor x5;
  y20 := t1 xor x1;
  y6 := y15 xor x7;
  y10 := y15 xor t0;
  y11 := y20 xor y9;
  y7 := x7 xor y11;
  y17 := y10 xor y11;
  y19 := y10 xor y8;
  y16 := t0 xor y11;
  y21 := y13 xor y16;
  y18 := x0 xor y16;

  // Non-linear section.
  t2 := y12 and y15;
  t3 := y3 and y6;
  t4 := t3 xor t2;
  t5 := y4 and x7;
  t6 := t5 xor t2;
  t7 := y13 and y16;
  t8 := y5 and y1;
  t9 := t8 xor t7;
  t10 := y2 and y7;
  t11 := t10 xor t7;
  t12 := y9 and y11;
  t13 := y14 and y17;
  t14 := t13 xor t12;
  t15 := y8 and y10;
  t16 := t15 xor t12;
  t17 := t4 xor t14;
  t18 := t6 xor t16;
  t19 := t9 xor t14;
  t20 := t11 xor t16;
  t21 := t17 xor y20;
  t22 := t18 xor y19;
  t23 := t19 xor y21;
  t24 := t20 xor y18;

  t25 := t21 xor t22;
  t26 := t21 and t23;
  t27 := t24 xor t26;
  t28 := t25 and t27;
  t29 := t28 xor t22;
  t30 := t23 xor t24;
  t31 := t22 xor t26;
  t32 := t31 and t30;
  t33 := t32 xor t24;
  t34 := t23 xor t33;
  t35 := t27 xor t33;
  t36 := t24 and t35;
  t37 := t36 xor t34;
  t38 := t27 xor t36;
  t39 := t29 and t38;
  t40 := t25 xor t39;

  t41 := t40 xor t37;
  t42 := t29 xor t33;
  t43 := t29 xor t40;
  t44 := t33 xor t37;
  t45 := t42 xor t41;
  z0 := t44 and y15;
  z1 := t37 and y6;
  z2 := t33 and x7;
  z3 := t43 and y16;
  z4 := t40 and y1;
  z5 := t29 and y7;
  z6 := t42 and y11;
  z7 := t45 and y17;
  z8 := t41 and y10;
  z9 := t44 and y12;
  z10 := t37 and y3;
  z11 := t33 and y4;
  z12 := t43 and y13;
  z13 := t40 and y5;
  z14 := t29 and y2;
  z15 := t42 and y9;
  z16 := t45 and y14;
  z17 := t41 and y8;

  // Bottom linear transformation.
  t46 := z15 xor z16;
  t47 := z10 xor z11;
  t48 := z5 xor z13;
  t49 := z9 xor z10;
  t50 := z2 xor z12;
  t51 := z2 xor z5;
  t52 := z7 xor z8;
  t53 := z0 xor z3;
  t54 := z6 xor z7;
  t55 := z16 xor z17;
  t56 := z12 xor t48;
  t57 := t50 xor t53;
  t58 := z4 xor t46;
  t59 := z3 xor t54;
  t60 := t46 xor t57;
  t61 := z14 xor t57;
  t62 := t52 xor t58;
  t63 := t49 xor t58;
  t64 := z4 xor t59;
  t65 := t61 xor t62;
  t66 := z1 xor t63;
  s0 := t59 xor t63;
  s6 := t56 xor (not t62);
  s7 := t48 xor (not t60);
  t67 := t64 xor t65;
  s3 := t53 xor t66;
  s4 := t51 xor t66;
  s5 := t47 xor t65;
  s1 := t64 xor (not s3);
  s2 := t55 xor (not t67);

  AQ[7] := s0;
  AQ[6] := s1;
  AQ[5] := s2;
  AQ[4] := s3;
  AQ[3] := s4;
  AQ[2] := s5;
  AQ[1] := s6;
  AQ[0] := s7;
end;

class procedure TAesBitSlicedEngine.BitsliceInvSbox(var AQ: TBitSliceState);
var
  q0, q1, q2, q3, q4, q5, q6, q7: UInt64;
begin
  q0 := not AQ[0];
  q1 := not AQ[1];
  q2 := AQ[2];
  q3 := AQ[3];
  q4 := AQ[4];
  q5 := not AQ[5];
  q6 := not AQ[6];
  q7 := AQ[7];
  AQ[7] := q1 xor q4 xor q6;
  AQ[6] := q0 xor q3 xor q5;
  AQ[5] := q7 xor q2 xor q4;
  AQ[4] := q6 xor q1 xor q3;
  AQ[3] := q5 xor q0 xor q2;
  AQ[2] := q4 xor q7 xor q1;
  AQ[1] := q3 xor q6 xor q0;
  AQ[0] := q2 xor q5 xor q7;

  BitsliceSbox(AQ);

  q0 := not AQ[0];
  q1 := not AQ[1];
  q2 := AQ[2];
  q3 := AQ[3];
  q4 := AQ[4];
  q5 := not AQ[5];
  q6 := not AQ[6];
  q7 := AQ[7];
  AQ[7] := q1 xor q4 xor q6;
  AQ[6] := q0 xor q3 xor q5;
  AQ[5] := q7 xor q2 xor q4;
  AQ[4] := q6 xor q1 xor q3;
  AQ[3] := q5 xor q0 xor q2;
  AQ[2] := q4 xor q7 xor q1;
  AQ[1] := q3 xor q6 xor q0;
  AQ[0] := q2 xor q5 xor q7;
end;

class procedure TAesBitSlicedEngine.ShiftRows(var AQ: TBitSliceState);
var
  LI: Int32;
  x: UInt64;
begin
  for LI := 0 to 7 do
  begin
    x := AQ[LI];
    AQ[LI] := (x and UInt64($000000000000FFFF))
      or ((x and UInt64($00000000FFF00000)) shr 4)
      or ((x and UInt64($00000000000F0000)) shl 12)
      or ((x and UInt64($0000FF0000000000)) shr 8)
      or ((x and UInt64($000000FF00000000)) shl 8)
      or ((x and UInt64($F000000000000000)) shr 12)
      or ((x and UInt64($0FFF000000000000)) shl 4);
  end;
end;

class procedure TAesBitSlicedEngine.InvShiftRows(var AQ: TBitSliceState);
var
  LI: Int32;
  x: UInt64;
begin
  for LI := 0 to 7 do
  begin
    x := AQ[LI];
    AQ[LI] := (x and UInt64($000000000000FFFF))
      or ((x and UInt64($000000000FFF0000)) shl 4)
      or ((x and UInt64($00000000F0000000)) shr 12)
      or ((x and UInt64($000000FF00000000)) shl 8)
      or ((x and UInt64($0000FF0000000000)) shr 8)
      or ((x and UInt64($000F000000000000)) shl 12)
      or ((x and UInt64($FFF0000000000000)) shr 4);
  end;
end;

class function TAesBitSlicedEngine.Rotr32(AX: UInt64): UInt64;
begin
  Result := TBitOperations.RotateRight64(AX, 32);
end;

class procedure TAesBitSlicedEngine.MixColumns(var AQ: TBitSliceState);
var
  q0, q1, q2, q3, q4, q5, q6, q7: UInt64;
  r0, r1, r2, r3, r4, r5, r6, r7: UInt64;
begin
  q0 := AQ[0];
  q1 := AQ[1];
  q2 := AQ[2];
  q3 := AQ[3];
  q4 := AQ[4];
  q5 := AQ[5];
  q6 := AQ[6];
  q7 := AQ[7];
  r0 := TBitOperations.RotateRight64(q0, 16);
  r1 := TBitOperations.RotateRight64(q1, 16);
  r2 := TBitOperations.RotateRight64(q2, 16);
  r3 := TBitOperations.RotateRight64(q3, 16);
  r4 := TBitOperations.RotateRight64(q4, 16);
  r5 := TBitOperations.RotateRight64(q5, 16);
  r6 := TBitOperations.RotateRight64(q6, 16);
  r7 := TBitOperations.RotateRight64(q7, 16);

  AQ[0] := q7 xor r7 xor r0 xor Rotr32(q0 xor r0);
  AQ[1] := q0 xor r0 xor q7 xor r7 xor r1 xor Rotr32(q1 xor r1);
  AQ[2] := q1 xor r1 xor r2 xor Rotr32(q2 xor r2);
  AQ[3] := q2 xor r2 xor q7 xor r7 xor r3 xor Rotr32(q3 xor r3);
  AQ[4] := q3 xor r3 xor q7 xor r7 xor r4 xor Rotr32(q4 xor r4);
  AQ[5] := q4 xor r4 xor r5 xor Rotr32(q5 xor r5);
  AQ[6] := q5 xor r5 xor r6 xor Rotr32(q6 xor r6);
  AQ[7] := q6 xor r6 xor r7 xor Rotr32(q7 xor r7);
end;

class procedure TAesBitSlicedEngine.InvMixColumns(var AQ: TBitSliceState);
var
  q0, q1, q2, q3, q4, q5, q6, q7: UInt64;
  r0, r1, r2, r3, r4, r5, r6, r7: UInt64;
begin
  q0 := AQ[0];
  q1 := AQ[1];
  q2 := AQ[2];
  q3 := AQ[3];
  q4 := AQ[4];
  q5 := AQ[5];
  q6 := AQ[6];
  q7 := AQ[7];
  r0 := TBitOperations.RotateRight64(q0, 16);
  r1 := TBitOperations.RotateRight64(q1, 16);
  r2 := TBitOperations.RotateRight64(q2, 16);
  r3 := TBitOperations.RotateRight64(q3, 16);
  r4 := TBitOperations.RotateRight64(q4, 16);
  r5 := TBitOperations.RotateRight64(q5, 16);
  r6 := TBitOperations.RotateRight64(q6, 16);
  r7 := TBitOperations.RotateRight64(q7, 16);

  AQ[0] := q5 xor q6 xor q7 xor r0 xor r5 xor r7
    xor Rotr32(q0 xor q5 xor q6 xor r0 xor r5);
  AQ[1] := q0 xor q5 xor r0 xor r1 xor r5 xor r6 xor r7
    xor Rotr32(q1 xor q5 xor q7 xor r1 xor r5 xor r6);
  AQ[2] := q0 xor q1 xor q6 xor r1 xor r2 xor r6 xor r7
    xor Rotr32(q0 xor q2 xor q6 xor r2 xor r6 xor r7);
  AQ[3] := q0 xor q1 xor q2 xor q5 xor q6 xor r0 xor r2 xor r3 xor r5
    xor Rotr32(q0 xor q1 xor q3 xor q5 xor q6 xor q7 xor r0 xor r3 xor r5 xor r7);
  AQ[4] := q1 xor q2 xor q3 xor q5 xor r1 xor r3 xor r4 xor r5 xor r6 xor r7
    xor Rotr32(q1 xor q2 xor q4 xor q5 xor q7 xor r1 xor r4 xor r5 xor r6);
  AQ[5] := q2 xor q3 xor q4 xor q6 xor r2 xor r4 xor r5 xor r6 xor r7
    xor Rotr32(q2 xor q3 xor q5 xor q6 xor r2 xor r5 xor r6 xor r7);
  AQ[6] := q3 xor q4 xor q5 xor q7 xor r3 xor r5 xor r6 xor r7
    xor Rotr32(q3 xor q4 xor q6 xor q7 xor r3 xor r6 xor r7);
  AQ[7] := q4 xor q5 xor q6 xor r4 xor r6 xor r7
    xor Rotr32(q4 xor q5 xor q7 xor r4 xor r7);
end;

class procedure TAesBitSlicedEngine.AddRoundKey(var AQ: TBitSliceState;
  const ASkey: TCryptoLibUInt64Array; ASkOff: Int32);
begin
  AQ[0] := AQ[0] xor ASkey[ASkOff + 0];
  AQ[1] := AQ[1] xor ASkey[ASkOff + 1];
  AQ[2] := AQ[2] xor ASkey[ASkOff + 2];
  AQ[3] := AQ[3] xor ASkey[ASkOff + 3];
  AQ[4] := AQ[4] xor ASkey[ASkOff + 4];
  AQ[5] := AQ[5] xor ASkey[ASkOff + 5];
  AQ[6] := AQ[6] xor ASkey[ASkOff + 6];
  AQ[7] := AQ[7] xor ASkey[ASkOff + 7];
end;

class function TAesBitSlicedEngine.SubWord(AX: UInt32): UInt32;
var
  LQ: TBitSliceState;
begin
  System.FillChar(LQ, System.SizeOf(LQ), 0);
  LQ[0] := AX;
  Ortho(LQ);
  BitsliceSbox(LQ);
  Ortho(LQ);
  Result := UInt32(LQ[0]);
end;

procedure TAesBitSlicedEngine.KeySchedule(const AKey: TCryptoLibByteArray);
const
  M1 = UInt64($1111111111111111);
  M2 = UInt64($2222222222222222);
  M4 = UInt64($4444444444444444);
  M8 = UInt64($8888888888888888);
var
  LKeyLen, LNk, LNkf, LI, LJ, LK, LV, LN: Int32;
  LTmp: UInt32;
  LSkey32: array [0 .. 59] of UInt32;
  LCompSkey: TCryptoLibUInt64Array;
  LQ: TBitSliceState;
  LX0, LX1, LX2, LX3: UInt64;
begin
  LKeyLen := System.Length(AKey);
  case LKeyLen of
    16:
      FRounds := 10;
    24:
      FRounds := 12;
    32:
      FRounds := 14;
  else
    begin
      TArrayUtilities.Fill(AKey, 0, System.Length(AKey), Byte(0));
      raise EArgumentCryptoLibException.CreateRes(@SInvalidKeyLength);
    end;
  end;

  try
    LNk := LKeyLen shr 2;
    LNkf := (FRounds + 1) shl 2;

    LTmp := 0;
    for LI := 0 to LNk - 1 do
    begin
      LTmp := TPack.LE_To_UInt32(AKey, LI shl 2);
      LSkey32[LI] := LTmp;
    end;

    LJ := 0;
    LK := 0;
    for LI := LNk to LNkf - 1 do
    begin
      if LJ = 0 then
      begin
        LTmp := TBitOperations.RotateLeft32(LTmp, 24);
        LTmp := SubWord(LTmp) xor RCon[LK];
      end
      else if (LNk > 6) and (LJ = 4) then
      begin
        LTmp := SubWord(LTmp);
      end;
      LTmp := LTmp xor LSkey32[LI - LNk];
      LSkey32[LI] := LTmp;
      System.Inc(LJ);
      if LJ = LNk then
      begin
        LJ := 0;
        System.Inc(LK);
      end;
    end;

    // Compress round keys into two words per round key (one bit per nibble).
    System.SetLength(LCompSkey, (FRounds + 1) * 2);
    LI := 0;
    LJ := 0;
    while LI < LNkf do
    begin
      InterleaveIn(LSkey32[LI], LSkey32[LI + 1], LSkey32[LI + 2],
        LSkey32[LI + 3], LQ[0], LQ[4]);
      LQ[1] := LQ[0];
      LQ[2] := LQ[0];
      LQ[3] := LQ[0];
      LQ[5] := LQ[4];
      LQ[6] := LQ[4];
      LQ[7] := LQ[4];
      Ortho(LQ);
      LCompSkey[LJ + 0] := (LQ[0] and M1) or (LQ[1] and M2) or (LQ[2] and M4)
        or (LQ[3] and M8);
      LCompSkey[LJ + 1] := (LQ[4] and M1) or (LQ[5] and M2) or (LQ[6] and M4)
        or (LQ[7] and M8);
      System.Inc(LI, 4);
      System.Inc(LJ, 2);
    end;

    // Expand the compressed round keys to the full bit-sliced form.
    TArrayUtilities.Fill(FSkey, 0, System.Length(FSkey), UInt64(0));
    System.SetLength(FSkey, (FRounds + 1) * 8);
    LN := (FRounds + 1) * 2;
    LV := 0;
    for LI := 0 to LN - 1 do
    begin
      LX0 := LCompSkey[LI];
      LX1 := LX0;
      LX2 := LX0;
      LX3 := LX0;
      LX0 := LX0 and M1;
      LX1 := LX1 and M2;
      LX2 := LX2 and M4;
      LX3 := LX3 and M8;
      LX1 := LX1 shr 1;
      LX2 := LX2 shr 2;
      LX3 := LX3 shr 3;
      FSkey[LV + 0] := (LX0 shl 4) - LX0;
      FSkey[LV + 1] := (LX1 shl 4) - LX1;
      FSkey[LV + 2] := (LX2 shl 4) - LX2;
      FSkey[LV + 3] := (LX3 shl 4) - LX3;
      System.Inc(LV, 4);
    end;
  finally
    TArrayUtilities.Fill(LCompSkey, 0, System.Length(LCompSkey), UInt64(0));
    System.FillChar(LSkey32, System.SizeOf(LSkey32), 0);
    System.FillChar(LQ, System.SizeOf(LQ), 0);
  end;
end;

procedure TAesBitSlicedEngine.BitsliceEncrypt(var AQ: TBitSliceState);
var
  LU: Int32;
begin
  AddRoundKey(AQ, FSkey, 0);
  for LU := 1 to FRounds - 1 do
  begin
    BitsliceSbox(AQ);
    ShiftRows(AQ);
    MixColumns(AQ);
    AddRoundKey(AQ, FSkey, LU shl 3);
  end;
  BitsliceSbox(AQ);
  ShiftRows(AQ);
  AddRoundKey(AQ, FSkey, FRounds shl 3);
end;

procedure TAesBitSlicedEngine.BitsliceDecrypt(var AQ: TBitSliceState);
var
  LU: Int32;
begin
  AddRoundKey(AQ, FSkey, FRounds shl 3);
  for LU := FRounds - 1 downto 1 do
  begin
    InvShiftRows(AQ);
    BitsliceInvSbox(AQ);
    AddRoundKey(AQ, FSkey, LU shl 3);
    InvMixColumns(AQ);
  end;
  InvShiftRows(AQ);
  BitsliceInvSbox(AQ);
  AddRoundKey(AQ, FSkey, 0);
end;

function TAesBitSlicedEngine.GetAlgorithmName: String;
begin
  Result := 'AES';
end;

function TAesBitSlicedEngine.GetBlockSize: Int32;
begin
  Result := BLOCK_SIZE;
end;

procedure TAesBitSlicedEngine.Init(AForEncryption: Boolean;
  const AParameters: ICipherParameters);
var
  LKeyParameter: IKeyParameter;
begin
  if not Supports(AParameters, IKeyParameter, LKeyParameter) then
  begin
    raise EArgumentCryptoLibException.CreateResFmt(@SInvalidParameterAESInit,
      [TPlatformUtilities.GetTypeName(AParameters as TObject)]);
  end;

  FForEncryption := AForEncryption;
  KeySchedule(LKeyParameter.GetKey());
end;

procedure TAesBitSlicedEngine.Reset;
begin
  // The bit-sliced engine keeps no per-block chaining state; nothing to reset.
end;

destructor TAesBitSlicedEngine.Destroy;
begin
  TArrayUtilities.Fill(FSkey, 0, System.Length(FSkey), UInt64(0));
  inherited Destroy;
end;

function TAesBitSlicedEngine.ProcessBlock(const AInput: TCryptoLibByteArray;
  AInOff: Int32; const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32;
var
  LQ: TBitSliceState;
  LW0, LW1, LW2, LW3: UInt32;
begin
  if FSkey = nil then
  begin
    raise EInvalidOperationCryptoLibException.CreateRes
      (@SAesEngineNotInitialized);
  end;

  TCheck.DataLength(AInput, AInOff, 16, SInputBufferTooShort);
  TCheck.OutputLength(AOutput, AOutOff, 16, SOutputBufferTooShort);

  // Load the single 16-byte block into lane 0 (q[0], q[4]); other lanes unused.
  LW0 := TPack.LE_To_UInt32(AInput, AInOff);
  LW1 := TPack.LE_To_UInt32(AInput, AInOff + 4);
  LW2 := TPack.LE_To_UInt32(AInput, AInOff + 8);
  LW3 := TPack.LE_To_UInt32(AInput, AInOff + 12);

  InterleaveIn(LW0, LW1, LW2, LW3, LQ[0], LQ[4]);
  LQ[1] := 0;
  LQ[2] := 0;
  LQ[3] := 0;
  LQ[5] := 0;
  LQ[6] := 0;
  LQ[7] := 0;

  Ortho(LQ);
  if FForEncryption then
  begin
    BitsliceEncrypt(LQ);
  end
  else
  begin
    BitsliceDecrypt(LQ);
  end;
  Ortho(LQ);

  InterleaveOut(LW0, LW1, LW2, LW3, LQ[0], LQ[4]);

  TPack.UInt32_To_LE(LW0, AOutput, AOutOff);
  TPack.UInt32_To_LE(LW1, AOutput, AOutOff + 4);
  TPack.UInt32_To_LE(LW2, AOutput, AOutOff + 8);
  TPack.UInt32_To_LE(LW3, AOutput, AOutOff + 12);

  Result := BLOCK_SIZE;
end;

end.
