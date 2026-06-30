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

unit ClpMlDsaCore;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpPack,
  ClpIXof,
  ClpIMlDsaCore,
  ClpIMlDsaEngine,
  ClpDigestUtilities,
  ClpIDigest,
  ClpBitOperations,
  ClpCryptoLibTypes;

resourcestring
  SWrongMlDsaEta = 'wrong ML-DSA eta';
  SWrongMlDsaGamma1 = 'wrong ML-DSA Gamma1';
  SWrongMlDsaGamma2 = 'wrong ML-DSA Gamma2';

const
  MlDsaN = 256;
  MlDsaQ = 8380417;
  MlDsaQInv = 58728449;
  MlDsaD = 13;
  MlDsaRootOfUnity = 1753;
  MlDsaSeedBytes = 32;
  MlDsaCrhBytes = 64;
  MlDsaRndBytes = 32;
  MlDsaTrBytes = 64;
  MlDsaPolyT1PackedBytes = 320;
  MlDsaPolyT0PackedBytes = 416;

type
  TMlDsaReduce = class sealed(TObject)
  public
    class function MontgomeryReduce(A: Int64): Int32; static; inline;
    class function Reduce32(A: Int32): Int32; static; inline;
    class function ConditionalAddQ(A: Int32): Int32; static; inline;
  end;

  TMlDsaNtt = class sealed(TObject)
  strict private
  class var
    FZetas: TCryptoLibInt32Array;
    class constructor Create;
  public
    class procedure NTT(var ACoeffs: TCryptoLibInt32Array); static;
    class procedure InverseNttToMont(var ACoeffs: TCryptoLibInt32Array); static;
  end;

  TMlDsaRounding = class sealed(TObject)
  public
    class procedure Power2RoundAll(var AC0, AC1: TCryptoLibInt32Array); static;
    class procedure DecomposeAll(var AC0, AC1: TCryptoLibInt32Array; AGamma2: Int32); static;
    class function MakeHint(AA0, AA1: Int32; const AEngine: IMlDsaEngine): Int32; static; inline;
    class function UseHint(AA, AHint, AGamma2: Int32): Int32; static;
  end;

  TMlDsaShakeSymmetric = class(TInterfacedObject, IMlDsaSymmetric)
  strict private
  const
    Stream128BlockBytes = 168;
    Stream256BlockBytes = 136;
  var
    FDigest128: IXof;
    FDigest256: IXof;
    class procedure StreamInit(const ADigest: IXof; const ASeed: TCryptoLibByteArray; ANonce: UInt16); static;
  public
    constructor Create;
    function GetStream128BlockBytes: Int32;
    function GetStream256BlockBytes: Int32;
    procedure Stream128Init(const ASeed: TCryptoLibByteArray; ANonce: UInt16);
    procedure Stream256Init(const ASeed: TCryptoLibByteArray; ANonce: UInt16);
    procedure Stream128SqueezeBlocks(const AOutput: TCryptoLibByteArray; AOffset, ASize: Int32);
    procedure Stream256SqueezeBlocks(const AOutput: TCryptoLibByteArray; AOffset, ASize: Int32);
  end;

  TMlDsaPoly = class(TInterfacedObject, IMlDsaPoly)
  strict private
    FEngine: IMlDsaEngine;
    FCoeffs: TCryptoLibInt32Array;
    FPolyUniformNBlocks: Int32;
    class function RejectUniform(var ACoeffs: TCryptoLibInt32Array; AOff, ALen: Int32;
      const ABuf: TCryptoLibByteArray; ABufLen: Int32): Int32; static;
    class function RejectEta(var ACoeffs: TCryptoLibInt32Array; AOff, ALen: Int32;
      const ABuf: TCryptoLibByteArray; ABufLen, AEta: Int32): Int32; static;
  public
    constructor Create(const AEngine: IMlDsaEngine);
    function GetCoeffs: TCryptoLibInt32Array;
    procedure SetCoeffs(const ACoeffs: TCryptoLibInt32Array);

    procedure CopyTo(const ATarget: IMlDsaPoly);
    procedure UniformBlocks(const ASeed: TCryptoLibByteArray; ANonce: UInt16);
    procedure UniformEta(const ASeed: TCryptoLibByteArray; ANonce: UInt16);
    procedure UniformGamma1(const ASeed: TCryptoLibByteArray; ANonce: UInt16);
    procedure PointwiseMontgomery(const AV, AW: IMlDsaPoly);
    procedure PointwiseAccountMontgomery(const AU, AV: IMlDsaPolyVec);
    procedure Add(const AA: IMlDsaPoly);
    procedure Subtract(const AB: IMlDsaPoly);
    procedure ReducePoly;
    procedure PolyNtt;
    procedure InverseNttToMont;
    procedure ConditionalAddQ;
    procedure Power2Round(const AA: IMlDsaPoly);
    procedure PolyT0Pack(const ABuf: TCryptoLibByteArray; AOff: Int32);
    procedure PolyT0Unpack(const ABuf: TCryptoLibByteArray; AOff: Int32);
    procedure PolyT1Pack(const ABuf: TCryptoLibByteArray; ABufOff: Int32);
    procedure PolyT1Unpack(const ABuf: TCryptoLibByteArray; ABufOff: Int32);
    procedure PolyEtaPack(const ABuf: TCryptoLibByteArray; AOff: Int32);
    procedure PolyEtaUnpack(const ABuf: TCryptoLibByteArray; AOff: Int32);
    procedure PackZ(const ABuf: TCryptoLibByteArray; AOffset: Int32);
    procedure UnpackZ(const ABuf: TCryptoLibByteArray; ABufOff: Int32);
    procedure Decompose(const AA: IMlDsaPoly);
    procedure PackW1(const ABuf: TCryptoLibByteArray; AOff: Int32);
    procedure Challenge(const ASeed: TCryptoLibByteArray; ASeedOff, ASeedLen: Int32);
    function CheckNorm(ABound: Int32): Boolean;
    function PolyMakeHint(const AA0, AA1: IMlDsaPoly): Int32;
    procedure PolyUseHint(const AA, AH: IMlDsaPoly);
    procedure ShiftLeft;
  end;

  TMlDsaPolyVec = class(TInterfacedObject, IMlDsaPolyVec)
  strict private
    FEngine: IMlDsaEngine;
    FVec: TCryptoLibGenericArray<IMlDsaPoly>;
  public
    constructor Create(const AEngine: IMlDsaEngine; ALength: Int32);
    function GetLength: Int32;
    function GetPoly(AIndex: Int32): IMlDsaPoly;

    procedure Add(const AV: IMlDsaPolyVec);
    function CheckNorm(ABound: Int32): Boolean;
    procedure CopyTo(const AZ: IMlDsaPolyVec);
    procedure ConditionalAddQ;
    procedure Decompose(const AV: IMlDsaPolyVec);
    procedure InverseNttToMont;
    function MakeHint(const AV0, AV1: IMlDsaPolyVec): Int32;
    procedure Ntt;
    procedure PackW1(const ABuf: TCryptoLibByteArray; ABufOff: Int32);
    procedure PointwisePolyMontgomery(const AA: IMlDsaPoly; const AV: IMlDsaPolyVec);
    procedure Power2Round(const AV: IMlDsaPolyVec);
    procedure Reduce;
    procedure ShiftLeft;
    procedure Subtract(const AV: IMlDsaPolyVec);
    procedure UniformBlocks(const ARho: TCryptoLibByteArray; AT: Int32);
    procedure UniformEta(const ASeed: TCryptoLibByteArray; ANonce: UInt16);
    procedure UniformGamma1(const ASeed: TCryptoLibByteArray; ANonce: UInt16);
    procedure UseHint(const AA, AH: IMlDsaPolyVec);
  end;

  TMlDsaPolyVecMatrix = class(TInterfacedObject, IMlDsaPolyVecMatrix)
  strict private
    FMatrix: TCryptoLibGenericArray<IMlDsaPolyVec>;
  public
    constructor Create(const AEngine: IMlDsaEngine);
    procedure ExpandMatrix(const ARho: TCryptoLibByteArray);
    procedure PointwiseMontgomery(const AT, AV: IMlDsaPolyVec);
  end;

  TMlDsaPacking = class sealed(TObject)
  public
    class function PackPublicKey(const AT1: IMlDsaPolyVec; const AEngine: IMlDsaEngine): TCryptoLibByteArray; static;
    class procedure UnpackPublicKey(const AT1: IMlDsaPolyVec; const APk: TCryptoLibByteArray;
      const AEngine: IMlDsaEngine); static;
    class procedure PackSecretKey(const AT0, AS1, AS2: IMlDsaPolyVec;
      var AT0Enc, AS1Enc, AS2Enc: TCryptoLibByteArray; const AEngine: IMlDsaEngine); static;
    class procedure UnpackSecretKey(const AT0, AS1, AS2: IMlDsaPolyVec;
      const AT0Enc, AS1Enc, AS2Enc: TCryptoLibByteArray; const AEngine: IMlDsaEngine); static;
    class procedure PackSignature(var ASig: TCryptoLibByteArray; const AZ, AH: IMlDsaPolyVec;
      const AEngine: IMlDsaEngine); static;
    class function UnpackSignature(const AZ, AH: IMlDsaPolyVec; const ASig: TCryptoLibByteArray;
      const AEngine: IMlDsaEngine): Boolean; static;
  end;

implementation

{ TMlDsaReduce }

class function TMlDsaReduce.MontgomeryReduce(A: Int64): Int32;
var
  LT: Int32;
  LResult: Int64;
begin
  LT := Int32(A * Int64(MlDsaQInv));
  LResult := A - Int64(LT) * MlDsaQ;
  Result := TBitOperations.Asr64(LResult, 32);
end;

class function TMlDsaReduce.Reduce32(A: Int32): Int32;
var
  LT: Int32;
begin
  LT := TBitOperations.Asr32(A + (1 shl 22), 23);
  Result := A - LT * MlDsaQ;
end;

class function TMlDsaReduce.ConditionalAddQ(A: Int32): Int32;
begin
  Result := A + (TBitOperations.Asr32(A, 31) and MlDsaQ);
end;

{ TMlDsaNtt }

class constructor TMlDsaNtt.Create;
begin
  FZetas := TCryptoLibInt32Array.Create(
    0, 25847, -2608894, -518909, 237124, -777960, -876248, 466468,
    1826347, 2353451, -359251, -2091905, 3119733, -2884855, 3111497, 2680103,
    2725464, 1024112, -1079900, 3585928, -549488, -1119584, 2619752, -2108549,
    -2118186, -3859737, -1399561, -3277672, 1757237, -19422, 4010497, 280005,
    2706023, 95776, 3077325, 3530437, -1661693, -3592148, -2537516, 3915439,
    -3861115, -3043716, 3574422, -2867647, 3539968, -300467, 2348700, -539299,
    -1699267, -1643818, 3505694, -3821735, 3507263, -2140649, -1600420, 3699596,
    811944, 531354, 954230, 3881043, 3900724, -2556880, 2071892, -2797779,
    -3930395, -1528703, -3677745, -3041255, -1452451, 3475950, 2176455, -1585221,
    -1257611, 1939314, -4083598, -1000202, -3190144, -3157330, -3632928, 126922,
    3412210, -983419, 2147896, 2715295, -2967645, -3693493, -411027, -2477047,
    -671102, -1228525, -22981, -1308169, -381987, 1349076, 1852771, -1430430,
    -3343383, 264944, 508951, 3097992, 44288, -1100098, 904516, 3958618,
    -3724342, -8578, 1653064, -3249728, 2389356, -210977, 759969, -1316856,
    189548, -3553272, 3159746, -1851402, -2409325, -177440, 1315589, 1341330,
    1285669, -1584928, -812732, -1439742, -3019102, -3881060, -3628969, 3839961,
    2091667, 3407706, 2316500, 3817976, -3342478, 2244091, -2446433, -3562462,
    266997, 2434439, -1235728, 3513181, -3520352, -3759364, -1197226, -3193378,
    900702, 1859098, 909542, 819034, 495491, -1613174, -43260, -522500,
    -655327, -3122442, 2031748, 3207046, -3556995, -525098, -768622, -3595838,
    342297, 286988, -2437823, 4108315, 3437287, -3342277, 1735879, 203044,
    2842341, 2691481, -2590150, 1265009, 4055324, 1247620, 2486353, 1595974,
    -3767016, 1250494, 2635921, -3548272, -2994039, 1869119, 1903435, -1050970,
    -1333058, 1237275, -3318210, -1430225, -451100, 1312455, 3306115, -1962642,
    -1279661, 1917081, -2546312, -1374803, 1500165, 777191, 2235880, 3406031,
    -542412, -2831860, -1671176, -1846953, -2584293, -3724270, 594136, -3776993,
    -2013608, 2432395, 2454455, -164721, 1957272, 3369112, 185531, -1207385,
    -3183426, 162844, 1616392, 3014001, 810149, 1652634, -3694233, -1799107,
    -3038916, 3523897, 3866901, 269760, 2213111, -975884, 1717735, 472078,
    -426683, 1723600, -1803090, 1910376, -1667432, -1104333, -260646, -3833893,
    -2939036, -2235985, -420899, -2286327, 183443, -976891, 1612842, -3545687,
    -554416, 3919660, -48306, -1362209, 3937738, 1400424, -846154, 1976782);
end;

class procedure TMlDsaNtt.NTT(var ACoeffs: TCryptoLibInt32Array);
var
  LJ, LK, LStart, LLen, LZeta, LR0, LT: Int32;
begin
  LK := 0;
  LLen := 128;
  while LLen > 0 do
  begin
    LStart := 0;
    while LStart < MlDsaN do
    begin
      System.Inc(LK);
      LZeta := FZetas[LK];
      LJ := LStart;
      while LJ < LStart + LLen do
      begin
        LR0 := ACoeffs[LJ];
        LT := TMlDsaReduce.MontgomeryReduce(Int64(LZeta) * Int64(ACoeffs[LJ + LLen]));
        ACoeffs[LJ] := LR0 + LT;
        ACoeffs[LJ + LLen] := LR0 - LT;
        System.Inc(LJ);
      end;
      LStart := LJ + LLen;
    end;
    LLen := LLen shr 1;
  end;
end;

class procedure TMlDsaNtt.InverseNttToMont(var ACoeffs: TCryptoLibInt32Array);
const
  LF = 41978;
var
  LJ, LK, LStart, LLen, LZeta, LA0, LA1, LI: Int32;
begin
  LK := 256;
  LLen := 1;
  while LLen < MlDsaN do
  begin
    LStart := 0;
    while LStart < MlDsaN do
    begin
      System.Dec(LK);
      LZeta := -FZetas[LK];
      LJ := LStart;
      while LJ < LStart + LLen do
      begin
        LA0 := ACoeffs[LJ];
        LA1 := ACoeffs[LJ + LLen];
        ACoeffs[LJ] := LA0 + LA1;
        ACoeffs[LJ + LLen] := TMlDsaReduce.MontgomeryReduce(Int64(LZeta) * (Int64(LA0) - Int64(LA1)));
        System.Inc(LJ);
      end;
      LStart := LJ + LLen;
    end;
    LLen := LLen shl 1;
  end;
  for LI := 0 to MlDsaN - 1 do
    ACoeffs[LI] := TMlDsaReduce.MontgomeryReduce(Int64(LF) * Int64(ACoeffs[LI]));
end;

{ TMlDsaRounding }

class procedure TMlDsaRounding.Power2RoundAll(var AC0, AC1: TCryptoLibInt32Array);
const
  LU = (1 shl (MlDsaD - 1)) - 1;
  LV = -1 shl MlDsaD;
var
  LI, LA, LT, LR1: Int32;
begin
  for LI := 0 to MlDsaN - 1 do
  begin
    LA := AC0[LI];
    LT := LA + LU;
    LR1 := LA - (LT and LV);
    AC0[LI] := TBitOperations.Asr32(LT, MlDsaD);
    AC1[LI] := LR1;
  end;
end;

class procedure TMlDsaRounding.DecomposeAll(var AC0, AC1: TCryptoLibInt32Array; AGamma2: Int32);
var
  LI, LA, LA1, LA0: Int32;
begin
  if AGamma2 = (MlDsaQ - 1) div 32 then
  begin
    for LI := 0 to MlDsaN - 1 do
    begin
      LA := AC1[LI];
      LA1 := TBitOperations.Asr32(LA + 127, 7);
      LA1 := TBitOperations.Asr32(LA1 * 1025 + (1 shl 21), 22);
      LA1 := LA1 and 15;
      LA0 := LA - LA1 * 2 * AGamma2;
      LA0 := LA0 - (TBitOperations.Asr32((MlDsaQ - 1) div 2 - LA0, 31) and MlDsaQ);
      AC0[LI] := LA0;
      AC1[LI] := LA1;
    end;
  end
  else if AGamma2 = (MlDsaQ - 1) div 88 then
  begin
    for LI := 0 to MlDsaN - 1 do
    begin
      LA := AC1[LI];
      LA1 := TBitOperations.Asr32(LA + 127, 7);
      LA1 := TBitOperations.Asr32(LA1 * 11275 + (1 shl 23), 24);
      LA1 := LA1 xor (TBitOperations.Asr32(43 - LA1, 31) and LA1);
      LA0 := LA - LA1 * 2 * AGamma2;
      LA0 := LA0 - (TBitOperations.Asr32((MlDsaQ - 1) div 2 - LA0, 31) and MlDsaQ);
      AC0[LI] := LA0;
      AC1[LI] := LA1;
    end;
  end
  else
    raise EArgumentCryptoLibException.CreateRes(@SWrongMlDsaGamma2);
end;

class function TMlDsaRounding.MakeHint(AA0, AA1: Int32; const AEngine: IMlDsaEngine): Int32;
var
  LG2, LT, LU: Int32;
begin
  LG2 := AEngine.Gamma2;
  LT := MlDsaQ - LG2 - AA0;
  LU := LT or AA1;
  Result := (TBitOperations.Asr32((LG2 - AA0) and (LT xor -1) and (LU or -LU), 31) and 1);
end;

class function TMlDsaRounding.UseHint(AA, AHint, AGamma2: Int32): Int32;
var
  LA1, LA0: Int32;
begin
  if AGamma2 = (MlDsaQ - 1) div 32 then
  begin
    LA1 := TBitOperations.Asr32(AA + 127, 7);
    LA1 := TBitOperations.Asr32(LA1 * 1025 + (1 shl 21), 22);
    LA1 := LA1 and 15;
    if AHint = 0 then
      Exit(LA1);
    LA0 := AA - LA1 * 2 * AGamma2;
    LA0 := LA0 - (TBitOperations.Asr32((MlDsaQ - 1) div 2 - LA0, 31) and MlDsaQ);
    if LA0 > 0 then
      Result := (LA1 + 1) and 15
    else
      Result := (LA1 - 1) and 15;
  end
  else if AGamma2 = (MlDsaQ - 1) div 88 then
  begin
    LA1 := TBitOperations.Asr32(AA + 127, 7);
    LA1 := TBitOperations.Asr32(LA1 * 11275 + (1 shl 23), 24);
    LA1 := LA1 xor (TBitOperations.Asr32(43 - LA1, 31) and LA1);
    if AHint = 0 then
      Exit(LA1);
    LA0 := AA - LA1 * 2 * AGamma2;
    LA0 := LA0 - (TBitOperations.Asr32((MlDsaQ - 1) div 2 - LA0, 31) and MlDsaQ);
    if LA0 > 0 then
    begin
      if LA1 = 43 then
        Result := 0
      else
        Result := LA1 + 1;
    end
    else
    begin
      if LA1 = 0 then
        Result := 43
      else
        Result := LA1 - 1;
    end;
  end
  else
    raise EArgumentCryptoLibException.CreateRes(@SWrongMlDsaGamma2);
end;

{ TMlDsaShakeSymmetric }

constructor TMlDsaShakeSymmetric.Create;
begin
  inherited Create;
  FDigest128 := TDigestUtilities.GetDigest('SHAKE128-256') as IXof;
  FDigest256 := TDigestUtilities.GetDigest('SHAKE256-512') as IXof;
end;

function TMlDsaShakeSymmetric.GetStream128BlockBytes: Int32;
begin
  Result := Stream128BlockBytes;
end;

function TMlDsaShakeSymmetric.GetStream256BlockBytes: Int32;
begin
  Result := Stream256BlockBytes;
end;

class procedure TMlDsaShakeSymmetric.StreamInit(const ADigest: IXof;
  const ASeed: TCryptoLibByteArray; ANonce: UInt16);
var
  LTemp: TCryptoLibByteArray;
begin
  LTemp := TCryptoLibByteArray.Create(Byte(ANonce), Byte(ANonce shr 8));
  ADigest.Reset;
  ADigest.BlockUpdate(ASeed, 0, System.Length(ASeed));
  ADigest.BlockUpdate(LTemp, 0, System.Length(LTemp));
end;

procedure TMlDsaShakeSymmetric.Stream128Init(const ASeed: TCryptoLibByteArray; ANonce: UInt16);
begin
  StreamInit(FDigest128, ASeed, ANonce);
end;

procedure TMlDsaShakeSymmetric.Stream256Init(const ASeed: TCryptoLibByteArray; ANonce: UInt16);
begin
  StreamInit(FDigest256, ASeed, ANonce);
end;

procedure TMlDsaShakeSymmetric.Stream128SqueezeBlocks(const AOutput: TCryptoLibByteArray;
  AOffset, ASize: Int32);
begin
  FDigest128.Output(AOutput, AOffset, ASize);
end;

procedure TMlDsaShakeSymmetric.Stream256SqueezeBlocks(const AOutput: TCryptoLibByteArray;
  AOffset, ASize: Int32);
begin
  FDigest256.Output(AOutput, AOffset, ASize);
end;

{ TMlDsaPoly }

constructor TMlDsaPoly.Create(const AEngine: IMlDsaEngine);
var
  LSymm: IMlDsaSymmetric;
begin
  inherited Create;
  FEngine := AEngine;
  System.SetLength(FCoeffs, MlDsaN);
  LSymm := FEngine.Symmetric;
  FPolyUniformNBlocks := (768 + LSymm.Stream128BlockBytes - 1) div LSymm.Stream128BlockBytes;
end;

function TMlDsaPoly.GetCoeffs: TCryptoLibInt32Array;
begin
  Result := FCoeffs;
end;

procedure TMlDsaPoly.SetCoeffs(const ACoeffs: TCryptoLibInt32Array);
begin
  FCoeffs := ACoeffs;
end;

procedure TMlDsaPoly.CopyTo(const ATarget: IMlDsaPoly);
begin
  System.Move(FCoeffs[0], ATarget.Coeffs[0], MlDsaN * SizeOf(Int32));
end;

class function TMlDsaPoly.RejectUniform(var ACoeffs: TCryptoLibInt32Array; AOff, ALen: Int32;
  const ABuf: TCryptoLibByteArray; ABufLen: Int32): Int32;
var
  LCtr, LPos: Int32;
  LT: UInt32;
begin
  LCtr := 0;
  LPos := 0;
  while (LCtr < ALen) and (LPos + 3 <= ABufLen) do
  begin
    LT := ABuf[LPos];
    System.Inc(LPos);
    LT := LT or (UInt32(ABuf[LPos]) shl 8);
    System.Inc(LPos);
    LT := LT or (UInt32(ABuf[LPos]) shl 16);
    System.Inc(LPos);
    LT := LT and $7FFFFF;
    if LT < UInt32(MlDsaQ) then
    begin
      ACoeffs[AOff + LCtr] := Int32(LT);
      System.Inc(LCtr);
    end;
  end;
  Result := LCtr;
end;

procedure TMlDsaPoly.UniformBlocks(const ASeed: TCryptoLibByteArray; ANonce: UInt16);
var
  LSymm: IMlDsaSymmetric;
  LBufLen, LCtr, LOff, LI: Int32;
  LBuf: TCryptoLibByteArray;
begin
  LSymm := FEngine.Symmetric;
  LBufLen := FPolyUniformNBlocks * LSymm.Stream128BlockBytes;
  System.SetLength(LBuf, LBufLen + 2);
  LSymm.Stream128Init(ASeed, ANonce);
  LSymm.Stream128SqueezeBlocks(LBuf, 0, LBufLen);
  LCtr := RejectUniform(FCoeffs, 0, MlDsaN, LBuf, LBufLen);
  while LCtr < MlDsaN do
  begin
    LOff := LBufLen mod 3;
    for LI := 0 to LOff - 1 do
      LBuf[LI] := LBuf[LBufLen - LOff + LI];
    LSymm.Stream128SqueezeBlocks(LBuf, LOff, LSymm.Stream128BlockBytes);
    LBufLen := LSymm.Stream128BlockBytes + LOff;
    LCtr := LCtr + RejectUniform(FCoeffs, LCtr, MlDsaN - LCtr, LBuf, LBufLen);
  end;
end;

class function TMlDsaPoly.RejectEta(var ACoeffs: TCryptoLibInt32Array; AOff, ALen: Int32;
  const ABuf: TCryptoLibByteArray; ABufLen, AEta: Int32): Int32;
var
  LCtr, LPos: Int32;
  LB: Byte;
  LT0, LT1: UInt32;
begin
  LCtr := 0;
  LPos := 0;
  while (LCtr < ALen) and (LPos < ABufLen) do
  begin
    LB := ABuf[LPos];
    System.Inc(LPos);
    LT0 := LB and $0F;
    LT1 := UInt32(LB shr 4);
    if AEta = 2 then
    begin
      if LT0 < 15 then
      begin
        LT0 := LT0 - (205 * LT0 shr 10) * 5;
        ACoeffs[AOff + LCtr] := 2 - Int32(LT0);
        System.Inc(LCtr);
      end;
      if (LT1 < 15) and (LCtr < ALen) then
      begin
        LT1 := LT1 - (205 * LT1 shr 10) * 5;
        ACoeffs[AOff + LCtr] := 2 - Int32(LT1);
        System.Inc(LCtr);
      end;
    end
    else if AEta = 4 then
    begin
      if LT0 < 9 then
      begin
        ACoeffs[AOff + LCtr] := 4 - Int32(LT0);
        System.Inc(LCtr);
      end;
      if (LT1 < 9) and (LCtr < ALen) then
      begin
        ACoeffs[AOff + LCtr] := 4 - Int32(LT1);
        System.Inc(LCtr);
      end;
    end;
  end;
  Result := LCtr;
end;

procedure TMlDsaPoly.UniformEta(const ASeed: TCryptoLibByteArray; ANonce: UInt16);
var
  LSymm: IMlDsaSymmetric;
  LEta, LPolyUniformEtaNBlocks, LBufLen, LCtr: Int32;
  LBuf: TCryptoLibByteArray;
begin
  LSymm := FEngine.Symmetric;
  LEta := FEngine.Eta;
  if LEta = 2 then
    LPolyUniformEtaNBlocks := (136 + LSymm.Stream256BlockBytes - 1) div LSymm.Stream256BlockBytes
  else if LEta = 4 then
    LPolyUniformEtaNBlocks := (227 + LSymm.Stream256BlockBytes - 1) div LSymm.Stream256BlockBytes
  else
    raise EArgumentCryptoLibException.CreateRes(@SWrongMlDsaEta);
  LBufLen := LPolyUniformEtaNBlocks * LSymm.Stream256BlockBytes;
  System.SetLength(LBuf, LBufLen);
  LSymm.Stream256Init(ASeed, ANonce);
  LSymm.Stream256SqueezeBlocks(LBuf, 0, LBufLen);
  LCtr := RejectEta(FCoeffs, 0, MlDsaN, LBuf, LBufLen, LEta);
  while LCtr < MlDsaN do
  begin
    LSymm.Stream256SqueezeBlocks(LBuf, 0, LSymm.Stream256BlockBytes);
    LCtr := LCtr + RejectEta(FCoeffs, LCtr, MlDsaN - LCtr, LBuf, LSymm.Stream256BlockBytes, LEta);
  end;
end;

procedure TMlDsaPoly.PointwiseMontgomery(const AV, AW: IMlDsaPoly);
var
  LI: Int32;
  LVCoeffs, LWCoeffs: TCryptoLibInt32Array;
begin
  LVCoeffs := AV.Coeffs;
  LWCoeffs := AW.Coeffs;
  for LI := 0 to MlDsaN - 1 do
    FCoeffs[LI] := TMlDsaReduce.MontgomeryReduce(Int64(LVCoeffs[LI]) * Int64(LWCoeffs[LI]));
end;

procedure TMlDsaPoly.PointwiseAccountMontgomery(const AU, AV: IMlDsaPolyVec);
var
  LI: Int32;
  LT: IMlDsaPoly;
begin
  PointwiseMontgomery(AU.GetPoly(0), AV.GetPoly(0));
  for LI := 1 to FEngine.L - 1 do
  begin
    LT := TMlDsaPoly.Create(FEngine);
    try
      LT.PointwiseMontgomery(AU.GetPoly(LI), AV.GetPoly(LI));
      Add(LT);
    finally
      LT := nil;
    end;
  end;
end;

procedure TMlDsaPoly.Add(const AA: IMlDsaPoly);
var
  LI: Int32;
  LACoeffs: TCryptoLibInt32Array;
begin
  LACoeffs := AA.Coeffs;
  for LI := 0 to MlDsaN - 1 do
    FCoeffs[LI] := FCoeffs[LI] + LACoeffs[LI];
end;

procedure TMlDsaPoly.Subtract(const AB: IMlDsaPoly);
var
  LI: Int32;
  LBCoeffs: TCryptoLibInt32Array;
begin
  LBCoeffs := AB.Coeffs;
  for LI := 0 to MlDsaN - 1 do
    FCoeffs[LI] := FCoeffs[LI] - LBCoeffs[LI];
end;

procedure TMlDsaPoly.ReducePoly;
var
  LI: Int32;
begin
  for LI := 0 to MlDsaN - 1 do
    FCoeffs[LI] := TMlDsaReduce.Reduce32(FCoeffs[LI]);
end;

procedure TMlDsaPoly.PolyNtt;
begin
  TMlDsaNtt.NTT(FCoeffs);
end;

procedure TMlDsaPoly.InverseNttToMont;
begin
  TMlDsaNtt.InverseNttToMont(FCoeffs);
end;

procedure TMlDsaPoly.ConditionalAddQ;
var
  LI: Int32;
begin
  for LI := 0 to MlDsaN - 1 do
    FCoeffs[LI] := TMlDsaReduce.ConditionalAddQ(FCoeffs[LI]);
end;

procedure TMlDsaPoly.Power2Round(const AA: IMlDsaPoly);
var
  LACoeffs: TCryptoLibInt32Array;
begin
  LACoeffs := AA.Coeffs;
  TMlDsaRounding.Power2RoundAll(FCoeffs, LACoeffs);
  AA.Coeffs := LACoeffs;
end;

procedure TMlDsaPoly.PolyT0Pack(const ABuf: TCryptoLibByteArray; AOff: Int32);
const
  LM = 1 shl (MlDsaD - 1);
var
  LI, LT0, LT1, LT2, LT3, LT4, LT5, LT6, LT7: Int32;
begin
  for LI := 0 to (MlDsaN div 8) - 1 do
  begin
    LT0 := LM - FCoeffs[8 * LI + 0];
    LT1 := LM - FCoeffs[8 * LI + 1];
    LT2 := LM - FCoeffs[8 * LI + 2];
    LT3 := LM - FCoeffs[8 * LI + 3];
    LT4 := LM - FCoeffs[8 * LI + 4];
    LT5 := LM - FCoeffs[8 * LI + 5];
    LT6 := LM - FCoeffs[8 * LI + 6];
    LT7 := LM - FCoeffs[8 * LI + 7];
    TPack.UInt32_To_LE(UInt32(LT0 or (LT1 shl 13) or (LT2 shl 26)), ABuf, AOff + 13 * LI + 0);
    TPack.UInt32_To_LE(UInt32((LT2 shr 6) or (LT3 shl 7) or (LT4 shl 20)), ABuf, AOff + 13 * LI + 4);
    TPack.UInt32_To_LE(UInt32((LT4 shr 12) or (LT5 shl 1) or (LT6 shl 14) or (LT7 shl 27)),
      ABuf, AOff + 13 * LI + 8);
    ABuf[AOff + 13 * LI + 12] := Byte(LT7 shr 5);
  end;
end;

procedure TMlDsaPoly.PolyT0Unpack(const ABuf: TCryptoLibByteArray; AOff: Int32);
const
  LM = 1 shl (MlDsaD - 1);
var
  LI: Int32;
  LT0, LT1, LT2, LT3: UInt32;
begin
  for LI := 0 to (MlDsaN div 8) - 1 do
  begin
    LT0 := TPack.LE_To_UInt32(ABuf, AOff + 13 * LI + 0);
    LT1 := TPack.LE_To_UInt32(ABuf, AOff + 13 * LI + 4);
    LT2 := TPack.LE_To_UInt32(ABuf, AOff + 13 * LI + 8);
    LT3 := ABuf[AOff + 13 * LI + 12];
    FCoeffs[8 * LI + 0] := LM - Int32(LT0 and $1FFF);
    FCoeffs[8 * LI + 1] := LM - Int32((LT0 shr 13) and $1FFF);
    FCoeffs[8 * LI + 2] := LM - Int32((LT0 shr 26) or (LT1 shl 6)) and $1FFF;
    FCoeffs[8 * LI + 3] := LM - Int32((LT1 shr 7) and $1FFF);
    FCoeffs[8 * LI + 4] := LM - Int32((LT1 shr 20) or (LT2 shl 12)) and $1FFF;
    FCoeffs[8 * LI + 5] := LM - Int32((LT2 shr 1) and $1FFF);
    FCoeffs[8 * LI + 6] := LM - Int32((LT2 shr 14) and $1FFF);
    FCoeffs[8 * LI + 7] := LM - Int32((LT2 shr 27) or (LT3 shl 5)) and $1FFF;
  end;
end;

procedure TMlDsaPoly.PolyT1Pack(const ABuf: TCryptoLibByteArray; ABufOff: Int32);
var
  LI, LT0, LT1, LT2, LT3: Int32;
begin
  for LI := 0 to (MlDsaN div 4) - 1 do
  begin
    LT0 := FCoeffs[4 * LI + 0];
    LT1 := FCoeffs[4 * LI + 1];
    LT2 := FCoeffs[4 * LI + 2];
    LT3 := FCoeffs[4 * LI + 3];
    TPack.UInt32_To_LE(UInt32(LT0 or (LT1 shl 10) or (LT2 shl 20) or (LT3 shl 30)), ABuf, ABufOff + 5 * LI);
    ABuf[ABufOff + 5 * LI + 4] := Byte(LT3 shr 2);
  end;
end;

procedure TMlDsaPoly.PolyT1Unpack(const ABuf: TCryptoLibByteArray; ABufOff: Int32);
var
  LI: Int32;
  LT0, LT1: UInt32;
begin
  for LI := 0 to (MlDsaN div 4) - 1 do
  begin
    LT0 := TPack.LE_To_UInt32(ABuf, ABufOff + 5 * LI);
    LT1 := ABuf[ABufOff + 5 * LI + 4];
    FCoeffs[4 * LI + 0] := Int32(LT0 and $3FF);
    FCoeffs[4 * LI + 1] := Int32((LT0 shr 10) and $3FF);
    FCoeffs[4 * LI + 2] := Int32((LT0 shr 20) and $3FF);
    FCoeffs[4 * LI + 3] := Int32((LT0 shr 30) or (LT1 shl 2)) and $3FF;
  end;
end;

procedure TMlDsaPoly.PolyEtaPack(const ABuf: TCryptoLibByteArray; AOff: Int32);
var
  LEta, LI: Int32;
  LT0, LT1, LT2, LT3, LT4, LT5, LT6, LT7: Byte;
begin
  LEta := FEngine.Eta;
  if LEta = 2 then
  begin
    for LI := 0 to (MlDsaN div 8) - 1 do
    begin
      LT0 := Byte(LEta - FCoeffs[8 * LI + 0]);
      LT1 := Byte(LEta - FCoeffs[8 * LI + 1]);
      LT2 := Byte(LEta - FCoeffs[8 * LI + 2]);
      LT3 := Byte(LEta - FCoeffs[8 * LI + 3]);
      LT4 := Byte(LEta - FCoeffs[8 * LI + 4]);
      LT5 := Byte(LEta - FCoeffs[8 * LI + 5]);
      LT6 := Byte(LEta - FCoeffs[8 * LI + 6]);
      LT7 := Byte(LEta - FCoeffs[8 * LI + 7]);
      ABuf[AOff + 3 * LI + 0] := Byte((LT0 shr 0) or (LT1 shl 3) or (LT2 shl 6));
      ABuf[AOff + 3 * LI + 1] := Byte((LT2 shr 2) or (LT3 shl 1) or (LT4 shl 4) or (LT5 shl 7));
      ABuf[AOff + 3 * LI + 2] := Byte((LT5 shr 1) or (LT6 shl 2) or (LT7 shl 5));
    end;
  end
  else if LEta = 4 then
  begin
    for LI := 0 to (MlDsaN div 2) - 1 do
    begin
      LT0 := Byte(LEta - FCoeffs[2 * LI + 0]);
      LT1 := Byte(LEta - FCoeffs[2 * LI + 1]);
      ABuf[AOff + LI] := Byte(LT0 or (LT1 shl 4));
    end;
  end
  else
    raise EArgumentCryptoLibException.CreateRes(@SWrongMlDsaEta);
end;

procedure TMlDsaPoly.PolyEtaUnpack(const ABuf: TCryptoLibByteArray; AOff: Int32);
var
  LEta, LI: Int32;
begin
  LEta := FEngine.Eta;
  if LEta = 2 then
  begin
    for LI := 0 to (MlDsaN div 8) - 1 do
    begin
      FCoeffs[8 * LI + 0] := LEta - (ABuf[AOff + 3 * LI + 0] and 7);
      FCoeffs[8 * LI + 1] := LEta - ((ABuf[AOff + 3 * LI + 0] shr 3) and 7);
      FCoeffs[8 * LI + 2] := LEta - ((ABuf[AOff + 3 * LI + 0] shr 6) or (ABuf[AOff + 3 * LI + 1] shl 2)) and 7;
      FCoeffs[8 * LI + 3] := LEta - ((ABuf[AOff + 3 * LI + 1] shr 1) and 7);
      FCoeffs[8 * LI + 4] := LEta - ((ABuf[AOff + 3 * LI + 1] shr 4) and 7);
      FCoeffs[8 * LI + 5] := LEta - ((ABuf[AOff + 3 * LI + 1] shr 7) or (ABuf[AOff + 3 * LI + 2] shl 1)) and 7;
      FCoeffs[8 * LI + 6] := LEta - ((ABuf[AOff + 3 * LI + 2] shr 2) and 7);
      FCoeffs[8 * LI + 7] := LEta - ((ABuf[AOff + 3 * LI + 2] shr 5) and 7);
    end;
  end
  else if LEta = 4 then
  begin
    for LI := 0 to (MlDsaN div 2) - 1 do
    begin
      FCoeffs[2 * LI + 0] := LEta - (ABuf[AOff + LI] and $0F);
      FCoeffs[2 * LI + 1] := LEta - (ABuf[AOff + LI] shr 4);
    end;
  end;
end;

procedure TMlDsaPoly.UniformGamma1(const ASeed: TCryptoLibByteArray; ANonce: UInt16);
var
  LSymm: IMlDsaSymmetric;
  LBuf: TCryptoLibByteArray;
begin
  LSymm := FEngine.Symmetric;
  System.SetLength(LBuf, FEngine.PolyUniformGamma1NBytes * LSymm.Stream256BlockBytes);
  LSymm.Stream256Init(ASeed, ANonce);
  LSymm.Stream256SqueezeBlocks(LBuf, 0, System.Length(LBuf));
  UnpackZ(LBuf, 0);
end;

procedure TMlDsaPoly.PackZ(const ABuf: TCryptoLibByteArray; AOffset: Int32);
var
  LGamma1, LI: Int32;
  LT0, LT1, LT2, LT3: UInt32;
begin
  LGamma1 := FEngine.Gamma1;
  if LGamma1 = (1 shl 17) then
  begin
    for LI := 0 to (MlDsaN div 4) - 1 do
    begin
      LT0 := UInt32(LGamma1 - FCoeffs[4 * LI + 0]);
      LT1 := UInt32(LGamma1 - FCoeffs[4 * LI + 1]);
      LT2 := UInt32(LGamma1 - FCoeffs[4 * LI + 2]);
      LT3 := UInt32(LGamma1 - FCoeffs[4 * LI + 3]);
      TPack.UInt32_To_LE(LT0 or (LT1 shl 18), ABuf, AOffset + 9 * LI + 0);
      TPack.UInt32_To_LE((LT1 shr 14) or (LT2 shl 4) or (LT3 shl 22), ABuf, AOffset + 9 * LI + 4);
      ABuf[AOffset + 9 * LI + 8] := Byte(LT3 shr 10);
    end;
  end
  else if LGamma1 = (1 shl 19) then
  begin
    for LI := 0 to (MlDsaN div 2) - 1 do
    begin
      LT0 := UInt32(LGamma1 - FCoeffs[2 * LI + 0]);
      LT1 := UInt32(LGamma1 - FCoeffs[2 * LI + 1]);
      TPack.UInt32_To_LE(LT0 or (LT1 shl 20), ABuf, AOffset + 5 * LI + 0);
      ABuf[AOffset + 5 * LI + 4] := Byte(LT1 shr 12);
    end;
  end
  else
    raise EArgumentCryptoLibException.CreateRes(@SWrongMlDsaGamma1);
end;

procedure TMlDsaPoly.UnpackZ(const ABuf: TCryptoLibByteArray; ABufOff: Int32);
var
  LGamma1, LI: Int32;
  LT0, LT1, LT2: UInt32;
begin
  LGamma1 := FEngine.Gamma1;
  if LGamma1 = (1 shl 17) then
  begin
    for LI := 0 to (MlDsaN div 4) - 1 do
    begin
      LT0 := TPack.LE_To_UInt32(ABuf, ABufOff + 9 * LI + 0);
      LT1 := TPack.LE_To_UInt32(ABuf, ABufOff + 9 * LI + 4);
      LT2 := ABuf[ABufOff + 9 * LI + 8];
      FCoeffs[4 * LI + 0] := LGamma1 - Int32(LT0 and $3FFFF);
      FCoeffs[4 * LI + 1] := LGamma1 - Int32((LT0 shr 18) or (LT1 shl 14)) and $3FFFF;
      FCoeffs[4 * LI + 2] := LGamma1 - Int32((LT1 shr 4) and $3FFFF);
      FCoeffs[4 * LI + 3] := LGamma1 - Int32((LT1 shr 22) or (LT2 shl 10)) and $3FFFF;
    end;
  end
  else if LGamma1 = (1 shl 19) then
  begin
    for LI := 0 to (MlDsaN div 2) - 1 do
    begin
      LT0 := TPack.LE_To_UInt32(ABuf, ABufOff + 5 * LI + 0);
      LT1 := ABuf[ABufOff + 5 * LI + 4];
      FCoeffs[2 * LI + 0] := LGamma1 - Int32(LT0 and $FFFFF);
      FCoeffs[2 * LI + 1] := LGamma1 - Int32((LT0 shr 20) or (LT1 shl 12)) and $FFFFF;
    end;
  end
  else
    raise EArgumentCryptoLibException.CreateRes(@SWrongMlDsaGamma1);
end;

procedure TMlDsaPoly.Decompose(const AA: IMlDsaPoly);
var
  LACoeffs: TCryptoLibInt32Array;
begin
  LACoeffs := AA.Coeffs;
  TMlDsaRounding.DecomposeAll(LACoeffs, FCoeffs, FEngine.Gamma2);
  AA.Coeffs := LACoeffs;
end;

procedure TMlDsaPoly.PackW1(const ABuf: TCryptoLibByteArray; AOff: Int32);
var
  LGamma2, LI: Int32;
begin
  LGamma2 := FEngine.Gamma2;
  if LGamma2 = (MlDsaQ - 1) div 88 then
  begin
    for LI := 0 to (MlDsaN div 4) - 1 do
    begin
      ABuf[AOff + 3 * LI + 0] := Byte(FCoeffs[4 * LI + 0] or (FCoeffs[4 * LI + 1] shl 6));
      ABuf[AOff + 3 * LI + 1] := Byte((FCoeffs[4 * LI + 1] shr 2) or (FCoeffs[4 * LI + 2] shl 4));
      ABuf[AOff + 3 * LI + 2] := Byte((FCoeffs[4 * LI + 2] shr 4) or (FCoeffs[4 * LI + 3] shl 2));
    end;
  end
  else if LGamma2 = (MlDsaQ - 1) div 32 then
  begin
    for LI := 0 to (MlDsaN div 2) - 1 do
      ABuf[AOff + LI] := Byte(FCoeffs[2 * LI + 0] or (FCoeffs[2 * LI + 1] shl 4));
  end;
end;

procedure TMlDsaPoly.Challenge(const ASeed: TCryptoLibByteArray; ASeedOff, ASeedLen: Int32);
var
  LSymm: IMlDsaSymmetric;
  LBuf: TCryptoLibByteArray;
  LShake256: IXof;
  LSigns: UInt64;
  LBufPos, LI, LB, LTau: Int32;
begin
  LSymm := FEngine.Symmetric;
  LTau := FEngine.Tau;
  System.SetLength(LBuf, LSymm.Stream256BlockBytes);
  LShake256 := TDigestUtilities.GetDigest('SHAKE256-512') as IXof;
  LShake256.BlockUpdate(ASeed, ASeedOff, ASeedLen);
  LShake256.Output(LBuf, 0, LSymm.Stream256BlockBytes);
  LSigns := TPack.LE_To_UInt64(LBuf, 0);
  LBufPos := 8;
  for LI := 0 to MlDsaN - 1 do
    FCoeffs[LI] := 0;
  for LI := MlDsaN - LTau to MlDsaN - 1 do
  begin
    repeat
      if LBufPos >= LSymm.Stream256BlockBytes then
      begin
        LShake256.Output(LBuf, 0, LSymm.Stream256BlockBytes);
        LBufPos := 0;
      end;
      LB := LBuf[LBufPos];
      System.Inc(LBufPos);
    until LB <= LI;
    FCoeffs[LI] := FCoeffs[LB];
    FCoeffs[LB] := 1 - 2 * Int32(LSigns and 1);
    LSigns := LSigns shr 1;
  end;
end;

function TMlDsaPoly.CheckNorm(ABound: Int32): Boolean;
var
  LI, LT: Int32;
begin
  if ABound > (MlDsaQ - 1) div 8 then
    Exit(True);
  for LI := 0 to MlDsaN - 1 do
  begin
    LT := TBitOperations.Asr32(FCoeffs[LI], 31);
    LT := FCoeffs[LI] - (LT and (2 * FCoeffs[LI]));
    if LT >= ABound then
      Exit(True);
  end;
  Result := False;
end;

function TMlDsaPoly.PolyMakeHint(const AA0, AA1: IMlDsaPoly): Int32;
var
  LI, LS: Int32;
  LA0Coeffs, LA1Coeffs: TCryptoLibInt32Array;
begin
  LA0Coeffs := AA0.Coeffs;
  LA1Coeffs := AA1.Coeffs;
  LS := 0;
  for LI := 0 to MlDsaN - 1 do
  begin
    FCoeffs[LI] := TMlDsaRounding.MakeHint(LA0Coeffs[LI], LA1Coeffs[LI], FEngine);
    LS := LS + FCoeffs[LI];
  end;
  Result := LS;
end;

procedure TMlDsaPoly.PolyUseHint(const AA, AH: IMlDsaPoly);
var
  LI: Int32;
  LGamma2: Int32;
  LACoeffs, LHCoeffs: TCryptoLibInt32Array;
begin
  LGamma2 := FEngine.Gamma2;
  LACoeffs := AA.Coeffs;
  LHCoeffs := AH.Coeffs;
  for LI := 0 to MlDsaN - 1 do
    FCoeffs[LI] := TMlDsaRounding.UseHint(LACoeffs[LI], LHCoeffs[LI], LGamma2);
end;

procedure TMlDsaPoly.ShiftLeft;
var
  LI: Int32;
begin
  for LI := 0 to MlDsaN - 1 do
    FCoeffs[LI] := FCoeffs[LI] shl MlDsaD;
end;

{ TMlDsaPolyVec }

constructor TMlDsaPolyVec.Create(const AEngine: IMlDsaEngine; ALength: Int32);
var
  LI: Int32;
begin
  inherited Create;
  FEngine := AEngine;
  System.SetLength(FVec, ALength);
  for LI := 0 to ALength - 1 do
    FVec[LI] := TMlDsaPoly.Create(AEngine);
end;

function TMlDsaPolyVec.GetLength: Int32;
begin
  Result := System.Length(FVec);
end;

function TMlDsaPolyVec.GetPoly(AIndex: Int32): IMlDsaPoly;
begin
  Result := FVec[AIndex];
end;

procedure TMlDsaPolyVec.Add(const AV: IMlDsaPolyVec);
var
  LI: Int32;
begin
  for LI := 0 to System.Length(FVec) - 1 do
    FVec[LI].Add(AV.GetPoly(LI));
end;

function TMlDsaPolyVec.CheckNorm(ABound: Int32): Boolean;
var
  LI: Int32;
begin
  for LI := 0 to System.Length(FVec) - 1 do
    if FVec[LI].CheckNorm(ABound) then
      Exit(True);
  Result := False;
end;

procedure TMlDsaPolyVec.CopyTo(const AZ: IMlDsaPolyVec);
var
  LI: Int32;
begin
  for LI := 0 to System.Length(FVec) - 1 do
    FVec[LI].CopyTo(AZ.GetPoly(LI));
end;

procedure TMlDsaPolyVec.ConditionalAddQ;
var
  LI: Int32;
begin
  for LI := 0 to System.Length(FVec) - 1 do
    FVec[LI].ConditionalAddQ;
end;

procedure TMlDsaPolyVec.Decompose(const AV: IMlDsaPolyVec);
var
  LI: Int32;
begin
  for LI := 0 to System.Length(FVec) - 1 do
    FVec[LI].Decompose(AV.GetPoly(LI));
end;

procedure TMlDsaPolyVec.InverseNttToMont;
var
  LI: Int32;
begin
  for LI := 0 to System.Length(FVec) - 1 do
    FVec[LI].InverseNttToMont;
end;

function TMlDsaPolyVec.MakeHint(const AV0, AV1: IMlDsaPolyVec): Int32;
var
  LI, LS: Int32;
begin
  LS := 0;
  for LI := 0 to System.Length(FVec) - 1 do
    LS := LS + FVec[LI].PolyMakeHint(AV0.GetPoly(LI), AV1.GetPoly(LI));
  Result := LS;
end;

procedure TMlDsaPolyVec.Ntt;
var
  LI: Int32;
begin
  for LI := 0 to System.Length(FVec) - 1 do
    FVec[LI].PolyNtt;
end;

procedure TMlDsaPolyVec.PackW1(const ABuf: TCryptoLibByteArray; ABufOff: Int32);
var
  LI: Int32;
begin
  for LI := 0 to System.Length(FVec) - 1 do
    FVec[LI].PackW1(ABuf, ABufOff + LI * FEngine.PolyW1PackedBytes);
end;

procedure TMlDsaPolyVec.PointwisePolyMontgomery(const AA: IMlDsaPoly; const AV: IMlDsaPolyVec);
var
  LI: Int32;
begin
  for LI := 0 to System.Length(FVec) - 1 do
    FVec[LI].PointwiseMontgomery(AA, AV.GetPoly(LI));
end;

procedure TMlDsaPolyVec.Power2Round(const AV: IMlDsaPolyVec);
var
  LI: Int32;
begin
  for LI := 0 to System.Length(FVec) - 1 do
    FVec[LI].Power2Round(AV.GetPoly(LI));
end;

procedure TMlDsaPolyVec.Reduce;
var
  LI: Int32;
begin
  for LI := 0 to System.Length(FVec) - 1 do
    FVec[LI].ReducePoly;
end;

procedure TMlDsaPolyVec.ShiftLeft;
var
  LI: Int32;
begin
  for LI := 0 to System.Length(FVec) - 1 do
    FVec[LI].ShiftLeft;
end;

procedure TMlDsaPolyVec.Subtract(const AV: IMlDsaPolyVec);
var
  LI: Int32;
begin
  for LI := 0 to System.Length(FVec) - 1 do
    FVec[LI].Subtract(AV.GetPoly(LI));
end;

procedure TMlDsaPolyVec.UniformBlocks(const ARho: TCryptoLibByteArray; AT: Int32);
var
  LI: Int32;
begin
  for LI := 0 to System.Length(FVec) - 1 do
    FVec[LI].UniformBlocks(ARho, UInt16(AT + LI));
end;

procedure TMlDsaPolyVec.UniformEta(const ASeed: TCryptoLibByteArray; ANonce: UInt16);
var
  LI: Int32;
  LNonce: UInt16;
begin
  LNonce := ANonce;
  for LI := 0 to System.Length(FVec) - 1 do
  begin
    FVec[LI].UniformEta(ASeed, LNonce);
    System.Inc(LNonce);
  end;
end;

procedure TMlDsaPolyVec.UniformGamma1(const ASeed: TCryptoLibByteArray; ANonce: UInt16);
var
  LI: Int32;
begin
  for LI := 0 to System.Length(FVec) - 1 do
    FVec[LI].UniformGamma1(ASeed, UInt16(System.Length(FVec) * ANonce + LI));
end;

procedure TMlDsaPolyVec.UseHint(const AA, AH: IMlDsaPolyVec);
var
  LI: Int32;
begin
  for LI := 0 to System.Length(FVec) - 1 do
    FVec[LI].PolyUseHint(AA.GetPoly(LI), AH.GetPoly(LI));
end;

{ TMlDsaPolyVecMatrix }

constructor TMlDsaPolyVecMatrix.Create(const AEngine: IMlDsaEngine);
var
  LI: Int32;
begin
  inherited Create;
  System.SetLength(FMatrix, AEngine.K);
  for LI := 0 to AEngine.K - 1 do
    FMatrix[LI] := TMlDsaPolyVec.Create(AEngine, AEngine.L);
end;

procedure TMlDsaPolyVecMatrix.ExpandMatrix(const ARho: TCryptoLibByteArray);
var
  LI: Int32;
begin
  for LI := 0 to System.Length(FMatrix) - 1 do
    FMatrix[LI].UniformBlocks(ARho, LI shl 8);
end;

procedure TMlDsaPolyVecMatrix.PointwiseMontgomery(const AT, AV: IMlDsaPolyVec);
var
  LI: Int32;
begin
  for LI := 0 to System.Length(FMatrix) - 1 do
    AT.GetPoly(LI).PointwiseAccountMontgomery(FMatrix[LI], AV);
end;

{ TMlDsaPacking }

class function TMlDsaPacking.PackPublicKey(const AT1: IMlDsaPolyVec;
  const AEngine: IMlDsaEngine): TCryptoLibByteArray;
var
  LI: Int32;
begin
  System.SetLength(Result, AEngine.CryptoPublicKeyBytes - MlDsaSeedBytes);
  for LI := 0 to AEngine.K - 1 do
    AT1.GetPoly(LI).PolyT1Pack(Result, LI * MlDsaPolyT1PackedBytes);
end;

class procedure TMlDsaPacking.UnpackPublicKey(const AT1: IMlDsaPolyVec;
  const APk: TCryptoLibByteArray; const AEngine: IMlDsaEngine);
var
  LI: Int32;
begin
  for LI := 0 to AEngine.K - 1 do
    AT1.GetPoly(LI).PolyT1Unpack(APk, LI * MlDsaPolyT1PackedBytes);
end;

class procedure TMlDsaPacking.PackSecretKey(const AT0, AS1, AS2: IMlDsaPolyVec;
  var AT0Enc, AS1Enc, AS2Enc: TCryptoLibByteArray; const AEngine: IMlDsaEngine);
var
  LI: Int32;
begin
  System.SetLength(AS1Enc, AEngine.L * AEngine.PolyEtaPackedBytes);
  System.SetLength(AS2Enc, AEngine.K * AEngine.PolyEtaPackedBytes);
  System.SetLength(AT0Enc, AEngine.K * MlDsaPolyT0PackedBytes);
  for LI := 0 to AEngine.L - 1 do
    AS1.GetPoly(LI).PolyEtaPack(AS1Enc, LI * AEngine.PolyEtaPackedBytes);
  for LI := 0 to AEngine.K - 1 do
    AS2.GetPoly(LI).PolyEtaPack(AS2Enc, LI * AEngine.PolyEtaPackedBytes);
  for LI := 0 to AEngine.K - 1 do
    AT0.GetPoly(LI).PolyT0Pack(AT0Enc, LI * MlDsaPolyT0PackedBytes);
end;

class procedure TMlDsaPacking.UnpackSecretKey(const AT0, AS1, AS2: IMlDsaPolyVec;
  const AT0Enc, AS1Enc, AS2Enc: TCryptoLibByteArray; const AEngine: IMlDsaEngine);
var
  LI: Int32;
begin
  for LI := 0 to AEngine.L - 1 do
    AS1.GetPoly(LI).PolyEtaUnpack(AS1Enc, LI * AEngine.PolyEtaPackedBytes);
  for LI := 0 to AEngine.K - 1 do
    AS2.GetPoly(LI).PolyEtaUnpack(AS2Enc, LI * AEngine.PolyEtaPackedBytes);
  for LI := 0 to AEngine.K - 1 do
    AT0.GetPoly(LI).PolyT0Unpack(AT0Enc, LI * MlDsaPolyT0PackedBytes);
end;

class procedure TMlDsaPacking.PackSignature(var ASig: TCryptoLibByteArray; const AZ, AH: IMlDsaPolyVec;
  const AEngine: IMlDsaEngine);
var
  LI, LJ, LEnd, LK: Int32;
  LHCoeffs: TCryptoLibInt32Array;
begin
  LEnd := AEngine.CTilde;
  for LI := 0 to AEngine.L - 1 do
  begin
    AZ.GetPoly(LI).PackZ(ASig, LEnd);
    System.Inc(LEnd, AEngine.PolyZPackedBytes);
  end;
  for LI := 0 to AEngine.Omega + AEngine.K - 1 do
    ASig[LEnd + LI] := 0;
  LK := 0;
  for LI := 0 to AEngine.K - 1 do
  begin
    LHCoeffs := AH.GetPoly(LI).Coeffs;
    for LJ := 0 to MlDsaN - 1 do
      if LHCoeffs[LJ] <> 0 then
      begin
        ASig[LEnd + LK] := Byte(LJ);
        System.Inc(LK);
      end;
    ASig[LEnd + AEngine.Omega + LI] := Byte(LK);
  end;
end;

class function TMlDsaPacking.UnpackSignature(const AZ, AH: IMlDsaPolyVec;
  const ASig: TCryptoLibByteArray; const AEngine: IMlDsaEngine): Boolean;
var
  LI, LJ, LEnd, LK, LSigEndOmegaI: Int32;
  LHCoeffs: TCryptoLibInt32Array;
begin
  LEnd := AEngine.CTilde;
  for LI := 0 to AEngine.L - 1 do
  begin
    AZ.GetPoly(LI).UnpackZ(ASig, LEnd);
    System.Inc(LEnd, AEngine.PolyZPackedBytes);
  end;
  LK := 0;
  for LI := 0 to AEngine.K - 1 do
  begin
    LHCoeffs := AH.GetPoly(LI).Coeffs;
    for LJ := 0 to MlDsaN - 1 do
      LHCoeffs[LJ] := 0;
    LSigEndOmegaI := ASig[LEnd + AEngine.Omega + LI];
    if (LSigEndOmegaI < LK) or (LSigEndOmegaI > AEngine.Omega) then
      Exit(False);
    for LJ := LK to LSigEndOmegaI - 1 do
    begin
      if (LJ > LK) and (ASig[LEnd + LJ] <= ASig[LEnd + LJ - 1]) then
        Exit(False);
      LHCoeffs[ASig[LEnd + LJ]] := 1;
    end;
    LK := LSigEndOmegaI;
  end;
  for LJ := LK to AEngine.Omega - 1 do
    if ASig[LEnd + LJ] <> 0 then
      Exit(False);
  Result := True;
end;

end.
