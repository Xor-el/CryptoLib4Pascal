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

unit ClpMlKemCore;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpPack,
  ClpIXof,
  ClpIMlKemCore,
  ClpIMlKemEngine,
  ClpDigestUtilities,
  ClpIDigest,
  ClpBitOperations,
  ClpCryptoLibTypes,
  ClpWeakRef;

const
  MlKemN = 256;
  MlKemQ = 3329;
  MlKemQInv = 62209;
  MlKemSymBytes = 32;
  MlKemPolyBytes = 384;

type
  TMlKemReduce = class sealed(TObject)
  public
    class function MontgomeryReduce(A: Int32): SmallInt; static; inline;
    class function BarrettReduce(A: SmallInt): SmallInt; static; inline;
    class function CondSubQ(A: SmallInt): SmallInt; static; inline;
    class function CheckModulus(A: SmallInt): Int32; static; inline;
  end;

  TMlKemNtt = class sealed(TObject)
  strict private
  const
    MlKemNttZetaCount = MlKemN div 2;
  class var
    FZetas: TCryptoLibSmallIntArray;
    FZetasInv: TCryptoLibSmallIntArray;
    class constructor Create;
    class function MulMont(A, B: SmallInt): SmallInt; static; inline;
  public
    class function GetZeta(AIndex: Int32): SmallInt; static; inline;
    class procedure NTT(var ACoeffs: TCryptoLibSmallIntArray); static;
    class procedure InvNTT(var ACoeffs: TCryptoLibSmallIntArray); static;
    class procedure BaseMult(var ACoeffs: TCryptoLibSmallIntArray; AOff: Int32;
      A0, A1, B0, B1, AZeta: SmallInt); static;
  end;

  TMlKemCbd = class sealed(TObject)
  public
    class procedure Eta2(var ACoeffs: TCryptoLibSmallIntArray;
      const ABytes: TCryptoLibByteArray); static;
    class procedure Eta3(var ACoeffs: TCryptoLibSmallIntArray;
      const ABytes: TCryptoLibByteArray); static;
  end;

  TMlKemPoly = class(TInterfacedObject, IMlKemPoly)
  strict private
    FCoeffs: TCryptoLibSmallIntArray;
    class procedure Prf(const AXof: IXof; const ASeed: TCryptoLibByteArray;
      ASeedOff: Int32; ANonce: Byte; const AOutput: TCryptoLibByteArray); static;
  public
    constructor Create;
    function GetCoeffs: TCryptoLibSmallIntArray;
    procedure SetCoeffs(const ACoeffs: TCryptoLibSmallIntArray);

    procedure GetNoiseEta2(const AXof: IXof; const ASeed: TCryptoLibByteArray;
      ASeedOff: Int32; ANonce: Byte);
    procedure GetNoiseEta3(const AXof: IXof; const ASeed: TCryptoLibByteArray;
      ASeedOff: Int32; ANonce: Byte);
    procedure PolyNtt;
    procedure PolyInverseNttToMont;
    class procedure BaseMultMontgomery(AR, AA, AB: IMlKemPoly); static;
    procedure ToMont;
    procedure Add(const AA: IMlKemPoly);
    procedure Subtract(const AA: IMlKemPoly);
    procedure PolyReduce;
    procedure CompressPoly128(const ABuf: TCryptoLibByteArray; AOff: Int32);
    procedure CompressPoly160(const ABuf: TCryptoLibByteArray; AOff: Int32);
    procedure DecompressPoly128(const ABuf: TCryptoLibByteArray; AOff: Int32);
    procedure DecompressPoly160(const ABuf: TCryptoLibByteArray; AOff: Int32);
    procedure FromBytes(const ABuf: TCryptoLibByteArray; AOff: Int32);
    procedure ToBytes(const ABuf: TCryptoLibByteArray; AOff: Int32);
    procedure ToMsg(const AMsg: TCryptoLibByteArray);
    procedure FromMsg(const AMsg: TCryptoLibByteArray; AMsgOff: Int32);
    procedure CondSubQ;
    class function CheckModulus(const ABuf: TCryptoLibByteArray; AOff: Int32): Int32; static;
  end;

  TMlKemPolyVec = class(TInterfacedObject, IMlKemPolyVec)
  strict private
    FVec: TCryptoLibGenericArray<IMlKemPoly>;
    FK: Int32;
  public
    constructor Create(AK: Int32);
    function GetK: Int32;
    function GetPoly(AIndex: Int32): IMlKemPoly;

    procedure Ntt;
    procedure InverseNttToMont;
    class procedure PointwiseAccountMontgomery(AR: IMlKemPoly; AA, AB: IMlKemPolyVec); static;
    procedure Add(const AA: IMlKemPolyVec);
    procedure Reduce;
    procedure CompressPolyVec(const ABuf: TCryptoLibByteArray; AOff: Int32);
    procedure DecompressPolyVec(const ABuf: TCryptoLibByteArray; AOff: Int32);
    procedure FromBytes(const ABuf: TCryptoLibByteArray; AOff: Int32);
    procedure ToBytes(const ABuf: TCryptoLibByteArray; AOff: Int32);
    class function CheckModulus(AK: Int32; const ABuf: TCryptoLibByteArray): Int32; static;
  end;

  TMlKemIndCpa = class(TInterfacedObject, IMlKemIndCpa)
  strict private
  const
    Shake128Rate = 168;
  var
    FEngine: TWeakRef<IMlKemEngine>;
    class var
      FNumMatrixBlocks: Int32;
    class constructor Create;
    procedure GenerateMatrixA(var AMatrix: TCryptoLibGenericArray<IMlKemPolyVec>;
      const ASeed: TCryptoLibByteArray; ATranspose: Boolean);
    class function RejectionSampling(APoly: IMlKemPoly; AOff, ALen: Int32;
      const ABuf: TCryptoLibByteArray; ABufLen: Int32): Int32; static;
    procedure PackCipherText(AB: IMlKemPolyVec; AV: IMlKemPoly;
      const ABuf: TCryptoLibByteArray; AOff: Int32);
    procedure PackPublicKey(APkpv: IMlKemPolyVec; const ASeed: TCryptoLibByteArray;
      const APk: TCryptoLibByteArray; APkOff: Int32);
    procedure PackSecretKey(ASkpv: IMlKemPolyVec; const ASk: TCryptoLibByteArray; ASkOff: Int32);
    procedure UnpackCipherText(const ABuf: TCryptoLibByteArray; AOff: Int32;
      AB: IMlKemPolyVec; AV: IMlKemPoly);
    procedure UnpackPublicKey(const APk: TCryptoLibByteArray; APkOff: Int32;
      APkpv: IMlKemPolyVec; const ASeed: TCryptoLibByteArray);
    procedure UnpackSecretKey(const ASk: TCryptoLibByteArray; ASkOff: Int32; ASkpv: IMlKemPolyVec);
  public
    constructor Create(const AEngine: IMlKemEngine);
    procedure GenerateKeyPair(const AD, AKp: TCryptoLibByteArray);
    procedure Decrypt(const AEncapsulation, ASk: TCryptoLibByteArray; AEncOff, ASkOff: Int32;
      const AMsg: TCryptoLibByteArray);
    procedure Encrypt(const APk, AMsg, ACoins: TCryptoLibByteArray;
      APkOff, AMsgOff, ACoinsOff: Int32; const AEncapsulation: TCryptoLibByteArray; AEncOff: Int32);
  end;

implementation

{ TMlKemReduce }

class function TMlKemReduce.MontgomeryReduce(A: Int32): SmallInt;
var
  LU: SmallInt;
  LT: Int32;
begin
  LU := SmallInt(Int32(A) * MlKemQInv);
  LT := Int32(LU) * MlKemQ;
  LT := A - LT;
  LT := TBitOperations.Asr32(LT, 16);
  Result := SmallInt(LT);
end;

class function TMlKemReduce.BarrettReduce(A: SmallInt): SmallInt;
var
  LV, LT: SmallInt;
begin
  LV := SmallInt(((UInt32(1) shl 26) + (MlKemQ div 2)) div MlKemQ);
  LT := SmallInt(TBitOperations.Asr32(Int32(LV) * Int32(A), 26));
  LT := SmallInt(Int32(LT) * MlKemQ);
  Result := SmallInt(Int32(A) - Int32(LT));
end;

class function TMlKemReduce.CondSubQ(A: SmallInt): SmallInt;
var
  LT: Int32;
begin
  LT := Int32(A) - MlKemQ;
  LT := LT + (TBitOperations.Asr32(LT, 15) and MlKemQ);
  Result := SmallInt(LT);
end;

class function TMlKemReduce.CheckModulus(A: SmallInt): Int32;
begin
  Result := A - MlKemQ;
end;

{ TMlKemNtt }

class constructor TMlKemNtt.Create;
begin
  FZetas := TCryptoLibSmallIntArray.Create(
    2285, 2571, 2970, 1812, 1493, 1422, 287, 202, 3158, 622, 1577, 182, 962, 2127, 1855, 1468,
    573, 2004, 264, 383, 2500, 1458, 1727, 3199, 2648, 1017, 732, 608, 1787, 411, 3124, 1758,
    1223, 652, 2777, 1015, 2036, 1491, 3047, 1785, 516, 3321, 3009, 2663, 1711, 2167, 126, 1469,
    2476, 3239, 3058, 830, 107, 1908, 3082, 2378, 2931, 961, 1821, 2604, 448, 2264, 677, 2054,
    2226, 430, 555, 843, 2078, 871, 1550, 105, 422, 587, 177, 3094, 3038, 2869, 1574, 1653,
    3083, 778, 1159, 3182, 2552, 1483, 2727, 1119, 1739, 644, 2457, 349, 418, 329, 3173, 3254,
    817, 1097, 603, 610, 1322, 2044, 1864, 384, 2114, 3193, 1218, 1994, 2455, 220, 2142, 1670,
    2144, 1799, 2051, 794, 1819, 2475, 2459, 478, 3221, 3021, 996, 991, 958, 1869, 1522, 1628);

  FZetasInv := TCryptoLibSmallIntArray.Create(
    1701, 1807, 1460, 2371, 2338, 2333, 308, 108, 2851, 870, 854, 1510, 2535, 1278, 1530, 1185,
    1659, 1187, 3109, 874, 1335, 2111, 136, 1215, 2945, 1465, 1285, 2007, 2719, 2726, 2232, 2512,
    75, 156, 3000, 2911, 2980, 872, 2685, 1590, 2210, 602, 1846, 777, 147, 2170, 2551, 246,
    1676, 1755, 460, 291, 235, 3152, 2742, 2907, 3224, 1779, 2458, 1251, 2486, 2774, 2899, 1103,
    1275, 2652, 1065, 2881, 725, 1508, 2368, 398, 951, 247, 1421, 3222, 2499, 271, 90, 853,
    1860, 3203, 1162, 1618, 666, 320, 8, 2813, 1544, 282, 1838, 1293, 2314, 552, 2677, 2106,
    1571, 205, 2918, 1542, 2721, 2597, 2312, 681, 130, 1602, 1871, 829, 2946, 3065, 1325, 2756,
    1861, 1474, 1202, 2367, 3147, 1752, 2707, 171, 3127, 3042, 1907, 1836, 1517, 359, 758, 1441);
end;

class function TMlKemNtt.MulMont(A, B: SmallInt): SmallInt;
begin
  Result := TMlKemReduce.MontgomeryReduce(Int32(A) * Int32(B));
end;

class function TMlKemNtt.GetZeta(AIndex: Int32): SmallInt;
begin
  Result := FZetas[AIndex];
end;

class procedure TMlKemNtt.NTT(var ACoeffs: TCryptoLibSmallIntArray);
var
  LJ, LK, LStart, LLen: Int32;
  LT, LU, LZeta: SmallInt;
begin
  LK := 1;
  LLen := 128;
  while LLen >= 2 do
  begin
    LStart := 0;
    while LStart < MlKemN do
    begin
      LZeta := FZetas[LK];
      System.Inc(LK);
      LJ := LStart;
      while LJ < LStart + LLen do
      begin
        LT := ACoeffs[LJ];
        LU := MulMont(LZeta, ACoeffs[LJ + LLen]);
        ACoeffs[LJ + LLen] := SmallInt(Int32(LT) - Int32(LU));
        ACoeffs[LJ] := SmallInt(Int32(LT) + Int32(LU));
        System.Inc(LJ);
      end;
      LStart := LJ + LLen;
    end;
    LLen := LLen shr 1;
  end;
end;

class procedure TMlKemNtt.InvNTT(var ACoeffs: TCryptoLibSmallIntArray);
var
  LJ, LK, LStart, LLen, LI: Int32;
  LT, LU: SmallInt;
  LZeta: SmallInt;
begin
  LK := 0;
  LLen := 2;
  while LLen <= 128 do
  begin
    LStart := 0;
    while LStart < MlKemN do
    begin
      LZeta := FZetasInv[LK];
      System.Inc(LK);
      LJ := LStart;
      while LJ < LStart + LLen do
      begin
        LT := ACoeffs[LJ];
        LU := ACoeffs[LJ + LLen];
        ACoeffs[LJ] := TMlKemReduce.BarrettReduce(SmallInt(Int32(LT) + Int32(LU)));
        ACoeffs[LJ + LLen] := MulMont(LZeta, SmallInt(Int32(LT) - Int32(LU)));
        System.Inc(LJ);
      end;
      LStart := LJ + LLen;
    end;
    LLen := LLen shl 1;
  end;
  for LI := 0 to MlKemN - 1 do
    ACoeffs[LI] := MulMont(ACoeffs[LI], FZetasInv[127]);
end;

class procedure TMlKemNtt.BaseMult(var ACoeffs: TCryptoLibSmallIntArray; AOff: Int32;
  A0, A1, B0, B1, AZeta: SmallInt);
var
  LOut0, LOut1: SmallInt;
begin
  LOut0 := MulMont(A1, B1);
  LOut0 := MulMont(LOut0, AZeta);
  LOut0 := SmallInt(Int32(LOut0) + MulMont(A0, B0));
  ACoeffs[AOff] := LOut0;
  LOut1 := MulMont(A0, B1);
  LOut1 := SmallInt(Int32(LOut1) + MulMont(A1, B0));
  ACoeffs[AOff + 1] := LOut1;
end;

{ TMlKemCbd }

class procedure TMlKemCbd.Eta2(var ACoeffs: TCryptoLibSmallIntArray;
  const ABytes: TCryptoLibByteArray);
var
  LI, LJ: Int32;
  LT, LD: UInt32;
  LA, LB: SmallInt;
begin
  for LI := 0 to (MlKemN div 8) - 1 do
  begin
    LT := TPack.LE_To_UInt32(ABytes, 4 * LI);
    LD := LT and $55555555;
    LD := LD + ((LT shr 1) and $55555555);
    for LJ := 0 to 7 do
    begin
      LA := SmallInt((LD shr (4 * LJ + 0)) and 3);
      LB := SmallInt((LD shr (4 * LJ + 2)) and 3);
      ACoeffs[8 * LI + LJ] := SmallInt(LA - LB);
    end;
  end;
end;

class procedure TMlKemCbd.Eta3(var ACoeffs: TCryptoLibSmallIntArray;
  const ABytes: TCryptoLibByteArray);
var
  LI, LJ: Int32;
  LT, LD: UInt32;
  LA, LB: SmallInt;
begin
  for LI := 0 to (MlKemN div 4) - 1 do
  begin
    LT := TPack.LE_To_UInt24(ABytes, 3 * LI);
    LD := LT and $00249249;
    LD := LD + ((LT shr 1) and $00249249);
    LD := LD + ((LT shr 2) and $00249249);
    for LJ := 0 to 3 do
    begin
      LA := SmallInt((LD shr (6 * LJ + 0)) and 7);
      LB := SmallInt((LD shr (6 * LJ + 3)) and 7);
      ACoeffs[4 * LI + LJ] := SmallInt(LA - LB);
    end;
  end;
end;

{ TMlKemPoly }

constructor TMlKemPoly.Create;
begin
  inherited Create;
  System.SetLength(FCoeffs, MlKemN);
end;

function TMlKemPoly.GetCoeffs: TCryptoLibSmallIntArray;
begin
  Result := FCoeffs;
end;

procedure TMlKemPoly.SetCoeffs(const ACoeffs: TCryptoLibSmallIntArray);
begin
  FCoeffs := ACoeffs;
end;

class procedure TMlKemPoly.Prf(const AXof: IXof; const ASeed: TCryptoLibByteArray;
  ASeedOff: Int32; ANonce: Byte; const AOutput: TCryptoLibByteArray);
begin
  AXof.BlockUpdate(ASeed, ASeedOff, MlKemSymBytes);
  AXof.Update(ANonce);
  AXof.OutputFinal(AOutput, 0, System.Length(AOutput));
end;

procedure TMlKemPoly.GetNoiseEta2(const AXof: IXof; const ASeed: TCryptoLibByteArray;
  ASeedOff: Int32; ANonce: Byte);
var
  LBuf: TCryptoLibByteArray;
begin
  System.SetLength(LBuf, 2 * MlKemN div 4);
  Prf(AXof, ASeed, ASeedOff, ANonce, LBuf);
  TMlKemCbd.Eta2(FCoeffs, LBuf);
end;

procedure TMlKemPoly.GetNoiseEta3(const AXof: IXof; const ASeed: TCryptoLibByteArray;
  ASeedOff: Int32; ANonce: Byte);
var
  LBuf: TCryptoLibByteArray;
begin
  System.SetLength(LBuf, 3 * MlKemN div 4);
  Prf(AXof, ASeed, ASeedOff, ANonce, LBuf);
  TMlKemCbd.Eta3(FCoeffs, LBuf);
end;

procedure TMlKemPoly.PolyNtt;
begin
  TMlKemNtt.NTT(FCoeffs);
  PolyReduce;
end;

procedure TMlKemPoly.PolyInverseNttToMont;
begin
  TMlKemNtt.InvNTT(FCoeffs);
end;

class procedure TMlKemPoly.BaseMultMontgomery(AR, AA, AB: IMlKemPoly);
var
  LI: Int32;
  LZeta: SmallInt;
  LRCoeffs, LACoeffs, LBCoeffs: TCryptoLibSmallIntArray;
begin
  LRCoeffs := AR.Coeffs;
  LACoeffs := AA.Coeffs;
  LBCoeffs := AB.Coeffs;
  for LI := 0 to (MlKemN div 4) - 1 do
  begin
    LZeta := TMlKemNtt.GetZeta(64 + LI);
    TMlKemNtt.BaseMult(LRCoeffs, 4 * LI,
      LACoeffs[4 * LI], LACoeffs[4 * LI + 1],
      LBCoeffs[4 * LI], LBCoeffs[4 * LI + 1], LZeta);
    TMlKemNtt.BaseMult(LRCoeffs, 4 * LI + 2,
      LACoeffs[4 * LI + 2], LACoeffs[4 * LI + 3],
      LBCoeffs[4 * LI + 2], LBCoeffs[4 * LI + 3],
      SmallInt(-1 * LZeta));
  end;
  AR.Coeffs := LRCoeffs;
end;

procedure TMlKemPoly.ToMont;
const
  LF = SmallInt((Int64(1) shl 32) mod MlKemQ);
var
  LI: Int32;
begin
  for LI := 0 to MlKemN - 1 do
    FCoeffs[LI] := TMlKemReduce.MontgomeryReduce(Int32(FCoeffs[LI]) * Int32(LF));
end;

procedure TMlKemPoly.Add(const AA: IMlKemPoly);
var
  LI: Int32;
  LACoeffs: TCryptoLibSmallIntArray;
begin
  LACoeffs := AA.Coeffs;
  for LI := 0 to MlKemN - 1 do
    FCoeffs[LI] := SmallInt(Int32(FCoeffs[LI]) + Int32(LACoeffs[LI]));
end;

procedure TMlKemPoly.Subtract(const AA: IMlKemPoly);
var
  LI: Int32;
  LACoeffs: TCryptoLibSmallIntArray;
begin
  LACoeffs := AA.Coeffs;
  for LI := 0 to MlKemN - 1 do
    FCoeffs[LI] := SmallInt(Int32(LACoeffs[LI]) - Int32(FCoeffs[LI]));
end;

procedure TMlKemPoly.PolyReduce;
var
  LI: Int32;
begin
  for LI := 0 to MlKemN - 1 do
    FCoeffs[LI] := TMlKemReduce.BarrettReduce(FCoeffs[LI]);
end;

procedure TMlKemPoly.CompressPoly128(const ABuf: TCryptoLibByteArray; AOff: Int32);
var
  LPos, LI, LJ, LC: Int32;
  LT: array[0..7] of Byte;
begin
  LPos := AOff;
  CondSubQ;
  for LI := 0 to (MlKemN div 8) - 1 do
  begin
    for LJ := 0 to 7 do
    begin
      LC := FCoeffs[8 * LI + LJ];
      LT[LJ] := Byte((((LC + (MlKemQ shr 5)) * 315) shr 16) and 15);
    end;
    ABuf[LPos + 0] := Byte(LT[0] or (LT[1] shl 4));
    ABuf[LPos + 1] := Byte(LT[2] or (LT[3] shl 4));
    ABuf[LPos + 2] := Byte(LT[4] or (LT[5] shl 4));
    ABuf[LPos + 3] := Byte(LT[6] or (LT[7] shl 4));
    System.Inc(LPos, 4);
  end;
end;

procedure TMlKemPoly.CompressPoly160(const ABuf: TCryptoLibByteArray; AOff: Int32);
var
  LPos, LI, LJ, LC: Int32;
  LT: array[0..7] of Byte;
begin
  LPos := AOff;
  CondSubQ;
  for LI := 0 to (MlKemN div 8) - 1 do
  begin
    for LJ := 0 to 7 do
    begin
      LC := FCoeffs[8 * LI + LJ];
      LT[LJ] := Byte((((LC + (MlKemQ shr 6)) * 630) shr 16) and 31);
    end;
    ABuf[LPos + 0] := Byte((LT[0] shr 0) or (LT[1] shl 5));
    ABuf[LPos + 1] := Byte((LT[1] shr 3) or (LT[2] shl 2) or (LT[3] shl 7));
    ABuf[LPos + 2] := Byte((LT[3] shr 1) or (LT[4] shl 4));
    ABuf[LPos + 3] := Byte((LT[4] shr 4) or (LT[5] shl 1) or (LT[6] shl 6));
    ABuf[LPos + 4] := Byte((LT[6] shr 2) or (LT[7] shl 3));
    System.Inc(LPos, 5);
  end;
end;

procedure TMlKemPoly.DecompressPoly128(const ABuf: TCryptoLibByteArray; AOff: Int32);
var
  LPos, LI: Int32;
begin
  LPos := AOff;
  for LI := 0 to (MlKemN div 2) - 1 do
  begin
    FCoeffs[2 * LI + 0] := SmallInt((((SmallInt(ABuf[LPos] and 15) * MlKemQ) + 8) shr 4));
    FCoeffs[2 * LI + 1] := SmallInt((((SmallInt(ABuf[LPos] shr 4) * MlKemQ) + 8) shr 4));
    System.Inc(LPos);
  end;
end;

procedure TMlKemPoly.DecompressPoly160(const ABuf: TCryptoLibByteArray; AOff: Int32);
var
  LPos, LI, LJ: Int32;
  LT: array[0..7] of Byte;
begin
  LPos := AOff;
  for LI := 0 to (MlKemN div 8) - 1 do
  begin
    LT[0] := Byte(ABuf[LPos + 0] shr 0);
    LT[1] := Byte((ABuf[LPos + 0] shr 5) or (ABuf[LPos + 1] shl 3));
    LT[2] := Byte(ABuf[LPos + 1] shr 2);
    LT[3] := Byte((ABuf[LPos + 1] shr 7) or (ABuf[LPos + 2] shl 1));
    LT[4] := Byte((ABuf[LPos + 2] shr 4) or (ABuf[LPos + 3] shl 4));
    LT[5] := Byte(ABuf[LPos + 3] shr 1);
    LT[6] := Byte((ABuf[LPos + 3] shr 6) or (ABuf[LPos + 4] shl 2));
    LT[7] := Byte(ABuf[LPos + 4] shr 3);
    System.Inc(LPos, 5);
    for LJ := 0 to 7 do
      FCoeffs[8 * LI + LJ] := SmallInt(((LT[LJ] and 31) * MlKemQ + 16) shr 5);
  end;
end;

procedure TMlKemPoly.FromBytes(const ABuf: TCryptoLibByteArray; AOff: Int32);
var
  LI: Int32;
  LA0, LA1, LA2: UInt16;
begin
  for LI := 0 to (MlKemN div 2) - 1 do
  begin
    LA0 := ABuf[AOff + 3 * LI + 0];
    LA1 := ABuf[AOff + 3 * LI + 1];
    LA2 := ABuf[AOff + 3 * LI + 2];
    FCoeffs[2 * LI + 0] := SmallInt(((LA0 shr 0) or (LA1 shl 8)) and $FFF);
    FCoeffs[2 * LI + 1] := SmallInt(((LA1 shr 4) or (LA2 shl 4)) and $FFF);
  end;
end;

procedure TMlKemPoly.ToBytes(const ABuf: TCryptoLibByteArray; AOff: Int32);
var
  LI: Int32;
  LT0, LT1: UInt16;
begin
  CondSubQ;
  for LI := 0 to (MlKemN div 2) - 1 do
  begin
    LT0 := UInt16(FCoeffs[2 * LI + 0]);
    LT1 := UInt16(FCoeffs[2 * LI + 1]);
    ABuf[AOff + 3 * LI + 0] := Byte(LT0);
    ABuf[AOff + 3 * LI + 1] := Byte((LT0 shr 8) or (LT1 shl 4));
    ABuf[AOff + 3 * LI + 2] := Byte(LT1 shr 4);
  end;
end;

procedure TMlKemPoly.ToMsg(const AMsg: TCryptoLibByteArray);
const
  LLower = MlKemQ shr 2;
  LUpper = MlKemQ - LLower;
var
  LI, LJ, LC: Int32;
  LM: UInt32;
  LT: UInt32;
begin
  CondSubQ;
  for LI := 0 to (MlKemN div 8) - 1 do
  begin
    LM := 0;
    for LJ := 0 to 7 do
    begin
      LC := FCoeffs[8 * LI + LJ];
      LT := UInt32((LLower - LC) and (LC - LUpper)) shr 31;
      LM := LM or (LT shl LJ);
    end;
    AMsg[LI] := Byte(LM);
  end;
end;

procedure TMlKemPoly.FromMsg(const AMsg: TCryptoLibByteArray; AMsgOff: Int32);
var
  LI, LJ, LMsgI: Int32;
  LMask: SmallInt;
begin
  for LI := 0 to (MlKemN div 8) - 1 do
  begin
    LMsgI := AMsg[AMsgOff + LI];
    for LJ := 0 to 7 do
    begin
      LMask := SmallInt(-((LMsgI shr LJ) and 1));
      FCoeffs[8 * LI + LJ] := SmallInt(LMask and ((MlKemQ + 1) div 2));
    end;
  end;
end;

procedure TMlKemPoly.CondSubQ;
var
  LI: Int32;
begin
  for LI := 0 to MlKemN - 1 do
    FCoeffs[LI] := TMlKemReduce.CondSubQ(FCoeffs[LI]);
end;

class function TMlKemPoly.CheckModulus(const ABuf: TCryptoLibByteArray;
  AOff: Int32): Int32;
var
  LI: Int32;
  LA0, LA1, LA2: UInt16;
  LC0, LC1: SmallInt;
begin
  Result := -1;
  for LI := 0 to (MlKemN div 2) - 1 do
  begin
    LA0 := ABuf[AOff + 3 * LI + 0];
    LA1 := ABuf[AOff + 3 * LI + 1];
    LA2 := ABuf[AOff + 3 * LI + 2];
    LC0 := SmallInt(((LA0 shr 0) or (LA1 shl 8)) and $FFF);
    LC1 := SmallInt(((LA1 shr 4) or (LA2 shl 4)) and $FFF);
    Result := Result and TMlKemReduce.CheckModulus(LC0);
    Result := Result and TMlKemReduce.CheckModulus(LC1);
  end;
end;

{ TMlKemPolyVec }

constructor TMlKemPolyVec.Create(AK: Int32);
var
  LI: Int32;
begin
  inherited Create;
  FK := AK;
  System.SetLength(FVec, AK);
  for LI := 0 to AK - 1 do
    FVec[LI] := TMlKemPoly.Create;
end;

function TMlKemPolyVec.GetK: Int32;
begin
  Result := FK;
end;

function TMlKemPolyVec.GetPoly(AIndex: Int32): IMlKemPoly;
begin
  Result := FVec[AIndex];
end;

procedure TMlKemPolyVec.Ntt;
var
  LI: Int32;
begin
  for LI := 0 to FK - 1 do
    FVec[LI].PolyNtt;
end;

procedure TMlKemPolyVec.InverseNttToMont;
var
  LI: Int32;
begin
  for LI := 0 to FK - 1 do
    FVec[LI].PolyInverseNttToMont;
end;

class procedure TMlKemPolyVec.PointwiseAccountMontgomery(AR: IMlKemPoly;
  AA, AB: IMlKemPolyVec);
var
  LT: IMlKemPoly;
  LI: Int32;
begin
  LT := TMlKemPoly.Create;
  TMlKemPoly.BaseMultMontgomery(AR, AA.GetPoly(0), AB.GetPoly(0));
  for LI := 1 to AA.K - 1 do
  begin
    TMlKemPoly.BaseMultMontgomery(LT, AA.GetPoly(LI), AB.GetPoly(LI));
    AR.Add(LT);
  end;
  AR.PolyReduce;
end;

procedure TMlKemPolyVec.Add(const AA: IMlKemPolyVec);
var
  LI: Int32;
begin
  for LI := 0 to FK - 1 do
    FVec[LI].Add(AA.GetPoly(LI));
end;

procedure TMlKemPolyVec.Reduce;
var
  LI: Int32;
begin
  for LI := 0 to FK - 1 do
    FVec[LI].PolyReduce;
end;

procedure TMlKemPolyVec.CompressPolyVec(const ABuf: TCryptoLibByteArray; AOff: Int32);
var
  LPos, LI, LJ, LK, LC: Int32;
  LT4: array[0..3] of SmallInt;
  LT8: array[0..7] of SmallInt;
begin
  LPos := AOff;
  for LI := 0 to FK - 1 do
    FVec[LI].CondSubQ;

  if FK = 4 then
  begin
    for LI := 0 to FK - 1 do
    begin
      for LJ := 0 to (MlKemN div 8) - 1 do
      begin
        for LK := 0 to 7 do
        begin
          LC := FVec[LI].Coeffs[8 * LJ + LK];
          LT8[LK] := SmallInt((((Int64((LC shl 4) + (MlKemQ shr 8)) * 165141429) shr 32) and $7FF));
        end;
        ABuf[LPos + 0] := Byte(LT8[0] shr 0);
        ABuf[LPos + 1] := Byte((LT8[0] shr 8) or (LT8[1] shl 3));
        ABuf[LPos + 2] := Byte((LT8[1] shr 5) or (LT8[2] shl 6));
        ABuf[LPos + 3] := Byte(LT8[2] shr 2);
        ABuf[LPos + 4] := Byte((LT8[2] shr 10) or (LT8[3] shl 1));
        ABuf[LPos + 5] := Byte((LT8[3] shr 7) or (LT8[4] shl 4));
        ABuf[LPos + 6] := Byte((LT8[4] shr 4) or (LT8[5] shl 7));
        ABuf[LPos + 7] := Byte(LT8[5] shr 1);
        ABuf[LPos + 8] := Byte((LT8[5] shr 9) or (LT8[6] shl 2));
        ABuf[LPos + 9] := Byte((LT8[6] shr 6) or (LT8[7] shl 5));
        ABuf[LPos + 10] := Byte(LT8[7] shr 3);
        System.Inc(LPos, 11);
      end;
    end;
  end
  else
  begin
    for LI := 0 to FK - 1 do
    begin
      for LJ := 0 to (MlKemN div 4) - 1 do
      begin
        for LK := 0 to 3 do
        begin
          LC := FVec[LI].Coeffs[4 * LJ + LK];
          LT4[LK] := SmallInt((((Int64((LC shl 3) + (MlKemQ shr 8)) * 165141429) shr 32) and $3FF));
        end;
        ABuf[LPos + 0] := Byte(LT4[0] shr 0);
        ABuf[LPos + 1] := Byte((LT4[0] shr 8) or (LT4[1] shl 2));
        ABuf[LPos + 2] := Byte((LT4[1] shr 6) or (LT4[2] shl 4));
        ABuf[LPos + 3] := Byte((LT4[2] shr 4) or (LT4[3] shl 6));
        ABuf[LPos + 4] := Byte(LT4[3] shr 2);
        System.Inc(LPos, 5);
      end;
    end;
  end;
end;

procedure TMlKemPolyVec.DecompressPolyVec(const ABuf: TCryptoLibByteArray; AOff: Int32);
var
  LPos, LI, LJ: Int32;
  LC0, LC1, LC2, LC3, LC4, LC5, LC6, LC7, LC8, LC9, LC10: Int32;
  LT0, LT1, LT2, LT3, LT4, LT5, LT6, LT7: SmallInt;
begin
  LPos := AOff;
  if FK = 4 then
  begin
    for LI := 0 to FK - 1 do
    begin
      LJ := 0;
      while LJ < MlKemN do
      begin
        LC0 := ABuf[LPos + 0];
        LC1 := ABuf[LPos + 1];
        LC2 := ABuf[LPos + 2];
        LC3 := ABuf[LPos + 3];
        LC4 := ABuf[LPos + 4];
        LC5 := ABuf[LPos + 5];
        LC6 := ABuf[LPos + 6];
        LC7 := ABuf[LPos + 7];
        LC8 := ABuf[LPos + 8];
        LC9 := ABuf[LPos + 9];
        LC10 := ABuf[LPos + 10];
        System.Inc(LPos, 11);
        LT0 := SmallInt((LC0 shr 0) or (UInt16(LC1) shl 8));
        LT1 := SmallInt((LC1 shr 3) or (UInt16(LC2) shl 5));
        LT2 := SmallInt((LC2 shr 6) or (UInt16(LC3) shl 2) or (UInt16(LC4 shl 10)));
        LT3 := SmallInt((LC4 shr 1) or (UInt16(LC5) shl 7));
        LT4 := SmallInt((LC5 shr 4) or (UInt16(LC6) shl 4));
        LT5 := SmallInt((LC6 shr 7) or (UInt16(LC7) shl 1) or (UInt16(LC8 shl 9)));
        LT6 := SmallInt((LC8 shr 2) or (UInt16(LC9) shl 6));
        LT7 := SmallInt((LC9 shr 5) or (UInt16(LC10) shl 3));
        FVec[LI].Coeffs[LJ + 0] := SmallInt(((LT0 and $7FF) * MlKemQ + 1024) shr 11);
        FVec[LI].Coeffs[LJ + 1] := SmallInt(((LT1 and $7FF) * MlKemQ + 1024) shr 11);
        FVec[LI].Coeffs[LJ + 2] := SmallInt(((LT2 and $7FF) * MlKemQ + 1024) shr 11);
        FVec[LI].Coeffs[LJ + 3] := SmallInt(((LT3 and $7FF) * MlKemQ + 1024) shr 11);
        FVec[LI].Coeffs[LJ + 4] := SmallInt(((LT4 and $7FF) * MlKemQ + 1024) shr 11);
        FVec[LI].Coeffs[LJ + 5] := SmallInt(((LT5 and $7FF) * MlKemQ + 1024) shr 11);
        FVec[LI].Coeffs[LJ + 6] := SmallInt(((LT6 and $7FF) * MlKemQ + 1024) shr 11);
        FVec[LI].Coeffs[LJ + 7] := SmallInt(((LT7 and $7FF) * MlKemQ + 1024) shr 11);
        System.Inc(LJ, 8);
      end;
    end;
  end
  else
  begin
    for LI := 0 to FK - 1 do
    begin
      LJ := 0;
      while LJ < MlKemN do
      begin
        LC0 := ABuf[LPos + 0];
        LC1 := ABuf[LPos + 1];
        LC2 := ABuf[LPos + 2];
        LC3 := ABuf[LPos + 3];
        LC4 := ABuf[LPos + 4];
        System.Inc(LPos, 5);
        LT0 := SmallInt((LC0 shr 0) or (UInt16(LC1) shl 8));
        LT1 := SmallInt((LC1 shr 2) or (UInt16(LC2) shl 6));
        LT2 := SmallInt((LC2 shr 4) or (UInt16(LC3) shl 4));
        LT3 := SmallInt((LC3 shr 6) or (UInt16(LC4) shl 2));
        FVec[LI].Coeffs[LJ + 0] := SmallInt(((LT0 and $3FF) * MlKemQ + 512) shr 10);
        FVec[LI].Coeffs[LJ + 1] := SmallInt(((LT1 and $3FF) * MlKemQ + 512) shr 10);
        FVec[LI].Coeffs[LJ + 2] := SmallInt(((LT2 and $3FF) * MlKemQ + 512) shr 10);
        FVec[LI].Coeffs[LJ + 3] := SmallInt(((LT3 and $3FF) * MlKemQ + 512) shr 10);
        System.Inc(LJ, 4);
      end;
    end;
  end;
end;

procedure TMlKemPolyVec.FromBytes(const ABuf: TCryptoLibByteArray; AOff: Int32);
var
  LI: Int32;
begin
  for LI := 0 to FK - 1 do
    FVec[LI].FromBytes(ABuf, AOff + LI * MlKemPolyBytes);
end;

procedure TMlKemPolyVec.ToBytes(const ABuf: TCryptoLibByteArray; AOff: Int32);
var
  LI: Int32;
begin
  for LI := 0 to FK - 1 do
    FVec[LI].ToBytes(ABuf, AOff + LI * MlKemPolyBytes);
end;

class function TMlKemPolyVec.CheckModulus(AK: Int32;
  const ABuf: TCryptoLibByteArray): Int32;
var
  LI: Int32;
begin
  Result := -1;
  for LI := 0 to AK - 1 do
    Result := Result and TMlKemPoly.CheckModulus(ABuf, LI * MlKemPolyBytes);
end;

{ TMlKemIndCpa }

class constructor TMlKemIndCpa.Create;
begin
  FNumMatrixBlocks := (((12 * MlKemN div 8) shl 12) div MlKemQ + Shake128Rate) div Shake128Rate;
end;

constructor TMlKemIndCpa.Create(const AEngine: IMlKemEngine);
begin
  inherited Create;
  FEngine := AEngine;
end;

class function TMlKemIndCpa.RejectionSampling(APoly: IMlKemPoly; AOff, ALen: Int32;
  const ABuf: TCryptoLibByteArray; ABufLen: Int32): Int32;
var
  LCtr, LPos: Int32;
  LT: UInt32;
  LD1, LD2: UInt16;
  LCoeffs: TCryptoLibSmallIntArray;
begin
  LCoeffs := APoly.Coeffs;
  LCtr := 0;
  LPos := 0;
  while (LCtr < ALen) and (LPos + 3 <= ABufLen) do
  begin
    LT := TPack.LE_To_UInt24(ABuf, LPos);
    LD1 := UInt16(LT and $FFF);
    LD2 := UInt16(LT shr 12);
    System.Inc(LPos, 3);
    if LD1 < MlKemQ then
    begin
      LCoeffs[AOff + LCtr] := SmallInt(LD1);
      System.Inc(LCtr);
    end;
    if (LCtr < ALen) and (LD2 < MlKemQ) then
    begin
      LCoeffs[AOff + LCtr] := SmallInt(LD2);
      System.Inc(LCtr);
    end;
  end;
  APoly.Coeffs := LCoeffs;
  Result := LCtr;
end;

procedure TMlKemIndCpa.GenerateMatrixA(var AMatrix: TCryptoLibGenericArray<IMlKemPolyVec>;
  const ASeed: TCryptoLibByteArray; ATranspose: Boolean);
var
  LEngine: IMlKemEngine;
  LK, LI, LJ, LBufLen, LCtr, LOff, LKIdx: Int32;
  LDigest: IDigest;
  LXof: IXof;
  LBuf, LSeedPlus: TCryptoLibByteArray;
begin
  LEngine := FEngine;
  LK := LEngine.K;
  LDigest := TDigestUtilities.GetDigest('SHAKE128-256');
  LXof := LDigest as IXof;
  System.SetLength(LBuf, FNumMatrixBlocks * Shake128Rate + 2);
  System.SetLength(LSeedPlus, MlKemSymBytes + 2);
  System.Move(ASeed[0], LSeedPlus[0], MlKemSymBytes);
  for LI := 0 to LK - 1 do
  begin
    for LJ := 0 to LK - 1 do
    begin
      LDigest.Reset;
      if ATranspose then
      begin
        LSeedPlus[MlKemSymBytes + 0] := Byte(LI);
        LSeedPlus[MlKemSymBytes + 1] := Byte(LJ);
      end
      else
      begin
        LSeedPlus[MlKemSymBytes + 0] := Byte(LJ);
        LSeedPlus[MlKemSymBytes + 1] := Byte(LI);
      end;
      LDigest.BlockUpdate(LSeedPlus, 0, System.Length(LSeedPlus));
      LBufLen := FNumMatrixBlocks * Shake128Rate;
      LXof.Output(LBuf, 0, LBufLen);
      LCtr := RejectionSampling(AMatrix[LI].GetPoly(LJ), 0, MlKemN, LBuf, LBufLen);
      while LCtr < MlKemN do
      begin
        LOff := LBufLen mod 3;
        for LKIdx := 0 to LOff - 1 do
          LBuf[LKIdx] := LBuf[LBufLen - LOff + LKIdx];
        LXof.Output(LBuf, LOff, Shake128Rate * 2);
        LBufLen := LOff + Shake128Rate;
        LCtr := LCtr + RejectionSampling(AMatrix[LI].GetPoly(LJ), LCtr,
          MlKemN - LCtr, LBuf, LBufLen);
      end;
    end;
  end;
end;

procedure TMlKemIndCpa.GenerateKeyPair(const AD, AKp: TCryptoLibByteArray);
var
  LEngine: IMlKemEngine;
  LK, LI: Int32;
  LBuf: TCryptoLibByteArray;
  LE, LSkpv, LPkpv: IMlKemPolyVec;
  LMatrix: TCryptoLibGenericArray<IMlKemPolyVec>;
  LG: IDigest;
  LXof: IXof;
  LNonce: Byte;
begin
  LEngine := FEngine;
  LK := LEngine.K;
  System.SetLength(LBuf, 2 * MlKemSymBytes);
  LE := TMlKemPolyVec.Create(LK);
  LSkpv := TMlKemPolyVec.Create(LK);
  LG := TDigestUtilities.GetDigest('SHA3-512');
  LG.BlockUpdate(AD, 0, MlKemSymBytes);
  LG.Update(Byte(LK));
  LG.DoFinal(LBuf, 0);
  System.SetLength(LMatrix, LK);
  for LI := 0 to LK - 1 do
    LMatrix[LI] := TMlKemPolyVec.Create(LK);
  GenerateMatrixA(LMatrix, LBuf, False);
  LXof := TDigestUtilities.GetDigest('SHAKE256-512') as IXof;
  LNonce := 0;
  if LEngine.Eta1 = 2 then
  begin
    for LI := 0 to LK - 1 do
    begin
      LSkpv.GetPoly(LI).GetNoiseEta2(LXof, LBuf, MlKemSymBytes, LNonce);
      System.Inc(LNonce);
    end;
    for LI := 0 to LK - 1 do
    begin
      LE.GetPoly(LI).GetNoiseEta2(LXof, LBuf, MlKemSymBytes, LNonce);
      System.Inc(LNonce);
    end;
  end
  else
  begin
    for LI := 0 to LK - 1 do
    begin
      LSkpv.GetPoly(LI).GetNoiseEta3(LXof, LBuf, MlKemSymBytes, LNonce);
      System.Inc(LNonce);
    end;
    for LI := 0 to LK - 1 do
    begin
      LE.GetPoly(LI).GetNoiseEta3(LXof, LBuf, MlKemSymBytes, LNonce);
      System.Inc(LNonce);
    end;
  end;
  LSkpv.Ntt;
  LE.Ntt;
  LPkpv := TMlKemPolyVec.Create(LK);
  for LI := 0 to LK - 1 do
  begin
    TMlKemPolyVec.PointwiseAccountMontgomery(LPkpv.GetPoly(LI), LMatrix[LI], LSkpv);
    LPkpv.GetPoly(LI).ToMont;
  end;
  LPkpv.Add(LE);
  LPkpv.Reduce;
  PackSecretKey(LSkpv, AKp, 0);
  PackPublicKey(LPkpv, LBuf, AKp, LEngine.IndCpaSecretKeyBytes);
end;

procedure TMlKemIndCpa.Decrypt(const AEncapsulation, ASk: TCryptoLibByteArray;
  AEncOff, ASkOff: Int32; const AMsg: TCryptoLibByteArray);
var
  LEngine: IMlKemEngine;
  LK: Int32;
  LBp, LSkpv: IMlKemPolyVec;
  LV, LMp: IMlKemPoly;
begin
  LEngine := FEngine;
  LK := LEngine.K;
  LBp := TMlKemPolyVec.Create(LK);
  LSkpv := TMlKemPolyVec.Create(LK);
  LV := TMlKemPoly.Create;
  LMp := TMlKemPoly.Create;
  UnpackCipherText(AEncapsulation, AEncOff, LBp, LV);
  UnpackSecretKey(ASk, ASkOff, LSkpv);
  LBp.Ntt;
  TMlKemPolyVec.PointwiseAccountMontgomery(LMp, LSkpv, LBp);
  LMp.PolyInverseNttToMont;
  LMp.Subtract(LV);
  LMp.PolyReduce;
  LMp.ToMsg(AMsg);
end;

procedure TMlKemIndCpa.Encrypt(const APk, AMsg, ACoins: TCryptoLibByteArray;
  APkOff, AMsgOff, ACoinsOff: Int32; const AEncapsulation: TCryptoLibByteArray; AEncOff: Int32);
var
  LEngine: IMlKemEngine;
  LK, LI: Int32;
  LSeed: TCryptoLibByteArray;
  LSp, LPkpv, LEp, LBp: IMlKemPolyVec;
  LV, LKPoly, LEpp: IMlKemPoly;
  LMatrix: TCryptoLibGenericArray<IMlKemPolyVec>;
  LXof: IXof;
  LNonce: Byte;
begin
  LEngine := FEngine;
  LK := LEngine.K;
  System.SetLength(LSeed, MlKemSymBytes);
  LSp := TMlKemPolyVec.Create(LK);
  LPkpv := TMlKemPolyVec.Create(LK);
  LEp := TMlKemPolyVec.Create(LK);
  LBp := TMlKemPolyVec.Create(LK);
  LV := TMlKemPoly.Create;
  LKPoly := TMlKemPoly.Create;
  LEpp := TMlKemPoly.Create;
  UnpackPublicKey(APk, APkOff, LPkpv, LSeed);
  LKPoly.FromMsg(AMsg, AMsgOff);
  System.SetLength(LMatrix, LK);
  for LI := 0 to LK - 1 do
    LMatrix[LI] := TMlKemPolyVec.Create(LK);
  GenerateMatrixA(LMatrix, LSeed, True);
  LXof := TDigestUtilities.GetDigest('SHAKE256-512') as IXof;
  LNonce := 0;
  if LEngine.Eta1 = 2 then
  begin
    for LI := 0 to LK - 1 do
    begin
      LSp.GetPoly(LI).GetNoiseEta2(LXof, ACoins, ACoinsOff, LNonce);
      System.Inc(LNonce);
    end;
  end
  else
  begin
    for LI := 0 to LK - 1 do
    begin
      LSp.GetPoly(LI).GetNoiseEta3(LXof, ACoins, ACoinsOff, LNonce);
      System.Inc(LNonce);
    end;
  end;
  for LI := 0 to LK - 1 do
  begin
    LEp.GetPoly(LI).GetNoiseEta2(LXof, ACoins, ACoinsOff, LNonce);
    System.Inc(LNonce);
  end;
  LEpp.GetNoiseEta2(LXof, ACoins, ACoinsOff, LNonce);
  LSp.Ntt;
  for LI := 0 to LK - 1 do
    TMlKemPolyVec.PointwiseAccountMontgomery(LBp.GetPoly(LI), LMatrix[LI], LSp);
  TMlKemPolyVec.PointwiseAccountMontgomery(LV, LPkpv, LSp);
  LBp.InverseNttToMont;
  LV.PolyInverseNttToMont;
  LBp.Add(LEp);
  LV.Add(LEpp);
  LV.Add(LKPoly);
  LBp.Reduce;
  LV.PolyReduce;
  PackCipherText(LBp, LV, AEncapsulation, AEncOff);
end;

procedure TMlKemIndCpa.PackCipherText(AB: IMlKemPolyVec; AV: IMlKemPoly;
  const ABuf: TCryptoLibByteArray; AOff: Int32);
var
  LEngine: IMlKemEngine;
  LCOff: Int32;
begin
  LEngine := FEngine;
  AB.CompressPolyVec(ABuf, AOff);
  LCOff := AOff + LEngine.PolyVecCompressedBytes;
  if LEngine.K = 4 then
    AV.CompressPoly160(ABuf, LCOff)
  else
    AV.CompressPoly128(ABuf, LCOff);
end;

procedure TMlKemIndCpa.PackPublicKey(APkpv: IMlKemPolyVec; const ASeed: TCryptoLibByteArray;
  const APk: TCryptoLibByteArray; APkOff: Int32);
var
  LEngine: IMlKemEngine;
begin
  LEngine := FEngine;
  APkpv.ToBytes(APk, APkOff);
  System.Move(ASeed[0], APk[APkOff + LEngine.PolyVecBytes], MlKemSymBytes);
end;

procedure TMlKemIndCpa.PackSecretKey(ASkpv: IMlKemPolyVec; const ASk: TCryptoLibByteArray; ASkOff: Int32);
begin
  ASkpv.ToBytes(ASk, ASkOff);
end;

procedure TMlKemIndCpa.UnpackCipherText(const ABuf: TCryptoLibByteArray; AOff: Int32;
  AB: IMlKemPolyVec; AV: IMlKemPoly);
var
  LEngine: IMlKemEngine;
  LCOff: Int32;
begin
  LEngine := FEngine;
  AB.DecompressPolyVec(ABuf, AOff);
  LCOff := AOff + LEngine.PolyVecCompressedBytes;
  if LEngine.K = 4 then
    AV.DecompressPoly160(ABuf, LCOff)
  else
    AV.DecompressPoly128(ABuf, LCOff);
end;

procedure TMlKemIndCpa.UnpackPublicKey(const APk: TCryptoLibByteArray; APkOff: Int32;
  APkpv: IMlKemPolyVec; const ASeed: TCryptoLibByteArray);
var
  LEngine: IMlKemEngine;
begin
  LEngine := FEngine;
  APkpv.FromBytes(APk, APkOff);
  System.Move(APk[APkOff + LEngine.PolyVecBytes], ASeed[0], MlKemSymBytes);
end;

procedure TMlKemIndCpa.UnpackSecretKey(const ASk: TCryptoLibByteArray; ASkOff: Int32;
  ASkpv: IMlKemPolyVec);
begin
  ASkpv.FromBytes(ASk, ASkOff);
end;

end.
