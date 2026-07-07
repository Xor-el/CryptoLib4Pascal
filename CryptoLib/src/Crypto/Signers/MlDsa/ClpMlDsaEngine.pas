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

unit ClpMlDsaEngine;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  Math,
  ClpMlDsaCore,
  ClpIMlDsaCore,
  ClpIMlDsaEngine,
  ClpDigestUtilities,
  ClpIDigest,
  ClpIXof,
  ClpISecureRandom,
  ClpSecureRandom,
  ClpBitOperations,
  ClpArrayUtilities,
  ClpCryptoLibTypes;

resourcestring
  SUnsupportedMlDsaMode = 'mode %d is not supported for ML-DSA';
  SWrongMlDsaGamma1Engine = 'wrong ML-DSA Gamma1';
  SMlDsaSignFailed = 'ML-DSA signing failed';

type
  TMlDsaEngine = class(TInterfacedObject, IMlDsaEngine)
  public
    const
      N = MlDsaN;
      Q = MlDsaQ;
      QInv = MlDsaQInv;
      D = MlDsaD;
      RootOfUnity = MlDsaRootOfUnity;
      SeedBytes = MlDsaSeedBytes;
      CrhBytes = MlDsaCrhBytes;
      RndBytes = MlDsaRndBytes;
      TrBytes = MlDsaTrBytes;
      PolyT1PackedBytes = MlDsaPolyT1PackedBytes;
      PolyT0PackedBytes = MlDsaPolyT0PackedBytes;
  strict private
  var
    FRandom: ISecureRandom;
    FK, FL, FEta, FTau, FBeta, FGamma1, FGamma2, FOmega, FCTilde: Int32;
    FPolyVecHPackedBytes, FPolyZPackedBytes, FPolyW1PackedBytes, FPolyEtaPackedBytes: Int32;
    FCryptoPublicKeyBytes, FCryptoBytes, FPolyUniformGamma1NBytes: Int32;
    FSymmetric: IMlDsaSymmetric;
    class function FixedTimeEquals(ALen: Int32; const AA: TCryptoLibByteArray; AAOff: Int32;
      const AB: TCryptoLibByteArray; ABOff: Int32): Boolean; static;
    procedure MsgRepEndSignCore(const ADigest: IXof; var ASig: TCryptoLibByteArray; ASigLen: Int32;
      const ARho, AK, AT0Enc, AS1Enc, AS2Enc, ARnd: TCryptoLibByteArray);
    function MsgRepEndVerifyCore(const ADigest: IXof; const ASig: TCryptoLibByteArray; ASigLen: Int32;
      const ARho, AEncT1: TCryptoLibByteArray): Boolean;
  public
    constructor Create(AMode: Int32; const ARandom: ISecureRandom);

    class function CalculatePublicKeyHash(const ARho, AEncT1: TCryptoLibByteArray): TCryptoLibByteArray; static;

    function GetK: Int32;
    function GetL: Int32;
    function GetEta: Int32;
    function GetTau: Int32;
    function GetBeta: Int32;
    function GetGamma1: Int32;
    function GetGamma2: Int32;
    function GetOmega: Int32;
    function GetCTilde: Int32;
    function GetPolyVecHPackedBytes: Int32;
    function GetPolyZPackedBytes: Int32;
    function GetPolyW1PackedBytes: Int32;
    function GetPolyEtaPackedBytes: Int32;
    function GetCryptoPublicKeyBytes: Int32;
    function GetCryptoBytes: Int32;
    function GetPolyUniformGamma1NBytes: Int32;
    function GetSymmetric: IMlDsaSymmetric;

    procedure GenerateKeyPair(const ARandom: ISecureRandom; out ASeed: TCryptoLibByteArray;
      out ARho, AK, ATr, AS1, AS2, AT0, AEncT1: TCryptoLibByteArray);
    procedure GenerateKeyPairFromSeed(const ASeed: TCryptoLibByteArray;
      out ARho, AK, ATr, AS1, AS2, AT0, AEncT1: TCryptoLibByteArray);
    function DeriveT1(const ARho, AS1Enc, AS2Enc, AT0Enc: TCryptoLibByteArray): TCryptoLibByteArray;

    procedure MsgRepBegin(const ADigest: IXof; const ATr: TCryptoLibByteArray);
    function CreateMsgRepDigest: IXof;
    procedure MsgRepEndSign(const ADigest: IXof; var ASig: TCryptoLibByteArray; ASigLen: Int32;
      const ARho, AK, AT0Enc, AS1Enc, AS2Enc: TCryptoLibByteArray);
    function MsgRepEndVerify(const ADigest: IXof; const ASig: TCryptoLibByteArray; ASigLen: Int32;
      const ARho, AEncT1: TCryptoLibByteArray): Boolean;
    function MsgRepPreHash(const ATr, AMsg: TCryptoLibByteArray; AMsgOff, AMsgLen: Int32): IXof;

    procedure Sign(var ASig: TCryptoLibByteArray; ASigLen: Int32; const AMsg: TCryptoLibByteArray;
      AMsgOff, AMsgLen: Int32; const ARho, AK, ATr, AT0Enc, AS1Enc, AS2Enc: TCryptoLibByteArray);
    procedure SignRaw(var ASig: TCryptoLibByteArray; ASigLen: Int32; const AMsg: TCryptoLibByteArray;
      AMsgOff, AMsgLen: Int32; const ARho, AK, ATr, AT0Enc, AS1Enc, AS2Enc, ARnd: TCryptoLibByteArray);
    function VerifyRaw(const ASig: TCryptoLibByteArray; ASigLen: Int32; const AMsg: TCryptoLibByteArray;
      AMsgOff, AMsgLen: Int32; const ARho, AEncT1, ATr: TCryptoLibByteArray): Boolean;
  end;

implementation

{ TMlDsaEngine }

constructor TMlDsaEngine.Create(AMode: Int32; const ARandom: ISecureRandom);
var
  LSymm: IMlDsaSymmetric;
begin
  inherited Create;
  FRandom := ARandom;
  case AMode of
    2:
      begin
        FK := 4;
        FL := 4;
        FEta := 2;
        FTau := 39;
        FBeta := 78;
        FGamma1 := 1 shl 17;
        FGamma2 := (Q - 1) div 88;
        FOmega := 80;
        FPolyZPackedBytes := 576;
        FPolyW1PackedBytes := 192;
        FPolyEtaPackedBytes := 96;
        FCTilde := 32;
      end;
    3:
      begin
        FK := 6;
        FL := 5;
        FEta := 4;
        FTau := 49;
        FBeta := 196;
        FGamma1 := 1 shl 19;
        FGamma2 := (Q - 1) div 32;
        FOmega := 55;
        FPolyZPackedBytes := 640;
        FPolyW1PackedBytes := 128;
        FPolyEtaPackedBytes := 128;
        FCTilde := 48;
      end;
    5:
      begin
        FK := 8;
        FL := 7;
        FEta := 2;
        FTau := 60;
        FBeta := 120;
        FGamma1 := 1 shl 19;
        FGamma2 := (Q - 1) div 32;
        FOmega := 75;
        FPolyZPackedBytes := 640;
        FPolyW1PackedBytes := 128;
        FPolyEtaPackedBytes := 96;
        FCTilde := 64;
      end;
  else
    raise EArgumentCryptoLibException.CreateResFmt(@SUnsupportedMlDsaMode, [AMode]);
  end;
  FSymmetric := TMlDsaShakeSymmetric.Create;
  LSymm := FSymmetric;
  FPolyVecHPackedBytes := FOmega + FK;
  FCryptoPublicKeyBytes := SeedBytes + FK * PolyT1PackedBytes;
  FCryptoBytes := FCTilde + FL * FPolyZPackedBytes + FPolyVecHPackedBytes;
  if FGamma1 = (1 shl 17) then
    FPolyUniformGamma1NBytes := (576 + LSymm.Stream256BlockBytes - 1) div LSymm.Stream256BlockBytes
  else if FGamma1 = (1 shl 19) then
    FPolyUniformGamma1NBytes := (640 + LSymm.Stream256BlockBytes - 1) div LSymm.Stream256BlockBytes
  else
    raise EArgumentCryptoLibException.CreateRes(@SWrongMlDsaGamma1Engine);
end;

class function TMlDsaEngine.CalculatePublicKeyHash(const ARho, AEncT1: TCryptoLibByteArray): TCryptoLibByteArray;
var
  LDigest: IXof;
begin
  System.SetLength(Result, TrBytes);
  LDigest := TDigestUtilities.GetDigest('SHAKE256-512') as IXof;
  LDigest.BlockUpdate(ARho, 0, System.Length(ARho));
  LDigest.BlockUpdate(AEncT1, 0, System.Length(AEncT1));
  LDigest.OutputFinal(Result, 0, TrBytes);
end;

function TMlDsaEngine.GetK: Int32;
begin
  Result := FK;
end;

function TMlDsaEngine.GetL: Int32;
begin
  Result := FL;
end;

function TMlDsaEngine.GetEta: Int32;
begin
  Result := FEta;
end;

function TMlDsaEngine.GetTau: Int32;
begin
  Result := FTau;
end;

function TMlDsaEngine.GetBeta: Int32;
begin
  Result := FBeta;
end;

function TMlDsaEngine.GetGamma1: Int32;
begin
  Result := FGamma1;
end;

function TMlDsaEngine.GetGamma2: Int32;
begin
  Result := FGamma2;
end;

function TMlDsaEngine.GetOmega: Int32;
begin
  Result := FOmega;
end;

function TMlDsaEngine.GetCTilde: Int32;
begin
  Result := FCTilde;
end;

function TMlDsaEngine.GetPolyVecHPackedBytes: Int32;
begin
  Result := FPolyVecHPackedBytes;
end;

function TMlDsaEngine.GetPolyZPackedBytes: Int32;
begin
  Result := FPolyZPackedBytes;
end;

function TMlDsaEngine.GetPolyW1PackedBytes: Int32;
begin
  Result := FPolyW1PackedBytes;
end;

function TMlDsaEngine.GetPolyEtaPackedBytes: Int32;
begin
  Result := FPolyEtaPackedBytes;
end;

function TMlDsaEngine.GetCryptoPublicKeyBytes: Int32;
begin
  Result := FCryptoPublicKeyBytes;
end;

function TMlDsaEngine.GetCryptoBytes: Int32;
begin
  Result := FCryptoBytes;
end;

function TMlDsaEngine.GetPolyUniformGamma1NBytes: Int32;
begin
  Result := FPolyUniformGamma1NBytes;
end;

function TMlDsaEngine.GetSymmetric: IMlDsaSymmetric;
begin
  Result := FSymmetric;
end;

class function TMlDsaEngine.FixedTimeEquals(ALen: Int32; const AA: TCryptoLibByteArray;
  AAOff: Int32; const AB: TCryptoLibByteArray; ABOff: Int32): Boolean;
var
  LI, LD: Int32;
begin
  LD := 0;
  for LI := 0 to ALen - 1 do
    LD := LD or (AA[AAOff + LI] xor AB[ABOff + LI]);
  LD := LD or (LD shr 16);
  LD := LD and $FFFF;
  Result := TBitOperations.Asr32(LD - 1, 31) <> 0;
end;

procedure TMlDsaEngine.GenerateKeyPair(const ARandom: ISecureRandom; out ASeed: TCryptoLibByteArray;
  out ARho, AK, ATr, AS1, AS2, AT0, AEncT1: TCryptoLibByteArray);
begin
  ASeed := TSecureRandom.GetNextBytes(ARandom, SeedBytes);
  GenerateKeyPairFromSeed(ASeed, ARho, AK, ATr, AS1, AS2, AT0, AEncT1);
end;

procedure TMlDsaEngine.GenerateKeyPairFromSeed(const ASeed: TCryptoLibByteArray;
  out ARho, AK, ATr, AS1, AS2, AT0, AEncT1: TCryptoLibByteArray);
var
  LBuf, LRhoPrime: TCryptoLibByteArray;
  LMatrix: IMlDsaPolyVecMatrix;
  LS1, LS2, LT1, LT0, LS1Hat: IMlDsaPolyVec;
  LShake256: IXof;
begin
  System.SetLength(LBuf, 2 * SeedBytes + CrhBytes);
  LBuf[0] := Byte(FK);
  LBuf[1] := Byte(FL);
  LShake256 := TDigestUtilities.GetDigest('SHAKE256-512') as IXof;
  LShake256.BlockUpdate(ASeed, 0, SeedBytes);
  LShake256.BlockUpdate(LBuf, 0, 2);
  LShake256.OutputFinal(LBuf, 0, 2 * SeedBytes + CrhBytes);
  System.SetLength(LRhoPrime, CrhBytes);
  System.SetLength(ARho, SeedBytes);
  System.SetLength(AK, SeedBytes);
  System.SetLength(ATr, TrBytes);
  System.SetLength(AS1, FL * FPolyEtaPackedBytes);
  System.SetLength(AS2, FK * FPolyEtaPackedBytes);
  System.SetLength(AT0, FK * PolyT0PackedBytes);
  System.Move(LBuf[0], ARho[0], SeedBytes);
  System.Move(LBuf[SeedBytes], LRhoPrime[0], CrhBytes);
  System.Move(LBuf[SeedBytes + CrhBytes], AK[0], SeedBytes);
  LMatrix := TMlDsaPolyVecMatrix.Create(Self as IMlDsaEngine);
  LS1 := TMlDsaPolyVec.Create(Self as IMlDsaEngine, FL);
  LS2 := TMlDsaPolyVec.Create(Self as IMlDsaEngine, FK);
  LT1 := TMlDsaPolyVec.Create(Self as IMlDsaEngine, FK);
  LT0 := TMlDsaPolyVec.Create(Self as IMlDsaEngine, FK);
  LMatrix.ExpandMatrix(ARho);
  LS1.UniformEta(LRhoPrime, 0);
  LS2.UniformEta(LRhoPrime, UInt16(FL));
  LS1Hat := TMlDsaPolyVec.Create(Self as IMlDsaEngine, FL);
  try
    LS1.CopyTo(LS1Hat);
    LS1Hat.Ntt;
    LMatrix.PointwiseMontgomery(LT1, LS1Hat);
  finally
    LS1Hat := nil;
  end;
  LT1.Reduce;
  LT1.InverseNttToMont;
  LT1.Add(LS2);
  LT1.ConditionalAddQ;
  LT1.Power2Round(LT0);
  AEncT1 := TMlDsaPacking.PackPublicKey(LT1, Self as IMlDsaEngine);
  LShake256.Reset;
  LShake256.BlockUpdate(ARho, 0, System.Length(ARho));
  LShake256.BlockUpdate(AEncT1, 0, System.Length(AEncT1));
  LShake256.OutputFinal(ATr, 0, TrBytes);
  TMlDsaPacking.PackSecretKey(LT0, LS1, LS2, AT0, AS1, AS2, Self as IMlDsaEngine);
end;

function TMlDsaEngine.DeriveT1(const ARho, AS1Enc, AS2Enc, AT0Enc: TCryptoLibByteArray): TCryptoLibByteArray;
var
  LMatrix: IMlDsaPolyVecMatrix;
  LS1, LS2, LT1, LT0, LS1Hat: IMlDsaPolyVec;
begin
  LMatrix := TMlDsaPolyVecMatrix.Create(Self as IMlDsaEngine);
  LS1 := TMlDsaPolyVec.Create(Self as IMlDsaEngine, FL);
  LS2 := TMlDsaPolyVec.Create(Self as IMlDsaEngine, FK);
  LT1 := TMlDsaPolyVec.Create(Self as IMlDsaEngine, FK);
  LT0 := TMlDsaPolyVec.Create(Self as IMlDsaEngine, FK);
  TMlDsaPacking.UnpackSecretKey(LT0, LS1, LS2, AT0Enc, AS1Enc, AS2Enc, Self as IMlDsaEngine);
  LMatrix.ExpandMatrix(ARho);
  LS1Hat := TMlDsaPolyVec.Create(Self as IMlDsaEngine, FL);
  try
    LS1.CopyTo(LS1Hat);
    LS1Hat.Ntt;
    LMatrix.PointwiseMontgomery(LT1, LS1Hat);
  finally
    LS1Hat := nil;
  end;
  LT1.Reduce;
  LT1.InverseNttToMont;
  LT1.Add(LS2);
  LT1.ConditionalAddQ;
  LT1.Power2Round(LT0);
  Result := TMlDsaPacking.PackPublicKey(LT1, Self as IMlDsaEngine);
end;

procedure TMlDsaEngine.MsgRepBegin(const ADigest: IXof; const ATr: TCryptoLibByteArray);
begin
  ADigest.BlockUpdate(ATr, 0, TrBytes);
end;

function TMlDsaEngine.CreateMsgRepDigest: IXof;
begin
  Result := TDigestUtilities.GetDigest('SHAKE256-512') as IXof;
end;

procedure TMlDsaEngine.MsgRepEndSign(const ADigest: IXof; var ASig: TCryptoLibByteArray; ASigLen: Int32;
  const ARho, AK, AT0Enc, AS1Enc, AS2Enc: TCryptoLibByteArray);
var
  LRnd: TCryptoLibByteArray;
begin
  System.SetLength(LRnd, RndBytes);
  if FRandom <> nil then
    LRnd := TSecureRandom.GetNextBytes(FRandom, RndBytes)
  else
    TArrayUtilities.Fill(LRnd, 0, RndBytes, Byte(0));
  MsgRepEndSignCore(ADigest, ASig, ASigLen, ARho, AK, AT0Enc, AS1Enc, AS2Enc, LRnd);
end;

function TMlDsaEngine.MsgRepEndVerify(const ADigest: IXof; const ASig: TCryptoLibByteArray;
  ASigLen: Int32; const ARho, AEncT1: TCryptoLibByteArray): Boolean;
begin
  Result := MsgRepEndVerifyCore(ADigest, ASig, ASigLen, ARho, AEncT1);
end;

procedure TMlDsaEngine.MsgRepEndSignCore(const ADigest: IXof; var ASig: TCryptoLibByteArray; ASigLen: Int32;
  const ARho, AK, AT0Enc, AS1Enc, AS2Enc, ARnd: TCryptoLibByteArray);
var
  LMu, LRhoPrime: TCryptoLibByteArray;
  LMatrix: IMlDsaPolyVecMatrix;
  LS1, LY, LZ, LT0, LS2, LW1, LW0, LH: IMlDsaPolyVec;
  LCp: IMlDsaPoly;
  LNonce: UInt16;
  LCount, LN: Int32;
begin
  System.SetLength(LMu, CrhBytes);
  ADigest.OutputFinal(LMu, 0, CrhBytes);
  System.SetLength(LRhoPrime, CrhBytes);
  LMatrix := TMlDsaPolyVecMatrix.Create(Self as IMlDsaEngine);
  LS1 := TMlDsaPolyVec.Create(Self as IMlDsaEngine, FL);
  LY := TMlDsaPolyVec.Create(Self as IMlDsaEngine, FL);
  LZ := TMlDsaPolyVec.Create(Self as IMlDsaEngine, FL);
  LT0 := TMlDsaPolyVec.Create(Self as IMlDsaEngine, FK);
  LS2 := TMlDsaPolyVec.Create(Self as IMlDsaEngine, FK);
  LW1 := TMlDsaPolyVec.Create(Self as IMlDsaEngine, FK);
  LW0 := TMlDsaPolyVec.Create(Self as IMlDsaEngine, FK);
  LH := TMlDsaPolyVec.Create(Self as IMlDsaEngine, FK);
  LCp := TMlDsaPoly.Create(Self as IMlDsaEngine);
  TMlDsaPacking.UnpackSecretKey(LT0, LS1, LS2, AT0Enc, AS1Enc, AS2Enc, Self as IMlDsaEngine);
  ADigest.Reset;
  ADigest.BlockUpdate(AK, 0, SeedBytes);
  ADigest.BlockUpdate(ARnd, 0, RndBytes);
  ADigest.BlockUpdate(LMu, 0, CrhBytes);
  ADigest.OutputFinal(LRhoPrime, 0, CrhBytes);
  LMatrix.ExpandMatrix(ARho);
  LS1.Ntt;
  LS2.Ntt;
  LT0.Ntt;
  LNonce := 0;
  LCount := 0;
  System.SetLength(ASig, FCryptoBytes);
  while True do
  begin
    System.Inc(LCount);
    if LCount > 1000 then
      raise EInvalidOperationCryptoLibException.CreateRes(@SMlDsaSignFailed);
    LY.UniformGamma1(LRhoPrime, LNonce);
    System.Inc(LNonce);
    LY.CopyTo(LZ);
    LZ.Ntt;
    LMatrix.PointwiseMontgomery(LW1, LZ);
    LW1.Reduce;
    LW1.InverseNttToMont;
    LW1.ConditionalAddQ;
    LW1.Decompose(LW0);
    LW1.PackW1(ASig, 0);
    ADigest.Reset;
    ADigest.BlockUpdate(LMu, 0, CrhBytes);
    ADigest.BlockUpdate(ASig, 0, FK * FPolyW1PackedBytes);
    ADigest.OutputFinal(ASig, 0, FCTilde);
    LCp.Challenge(ASig, 0, FCTilde);
    LCp.PolyNtt;
    LZ.PointwisePolyMontgomery(LCp, LS1);
    LZ.InverseNttToMont;
    LZ.Add(LY);
    LZ.Reduce;
    if LZ.CheckNorm(FGamma1 - FBeta) then
      Continue;
    LH.PointwisePolyMontgomery(LCp, LS2);
    LH.InverseNttToMont;
    LW0.Subtract(LH);
    LW0.Reduce;
    if LW0.CheckNorm(FGamma2 - FBeta) then
      Continue;
    LH.PointwisePolyMontgomery(LCp, LT0);
    LH.InverseNttToMont;
    LH.Reduce;
    if LH.CheckNorm(FGamma2) then
      Continue;
    LW0.Add(LH);
    LW0.ConditionalAddQ;
    LN := LH.MakeHint(LW0, LW1);
    if LN > FOmega then
      Continue;
    TMlDsaPacking.PackSignature(ASig, LZ, LH, Self as IMlDsaEngine);
    Exit;
  end;
end;

function TMlDsaEngine.MsgRepEndVerifyCore(const ADigest: IXof; const ASig: TCryptoLibByteArray;
  ASigLen: Int32; const ARho, AEncT1: TCryptoLibByteArray): Boolean;
var
  LBuf: TCryptoLibByteArray;
  LH, LZ: IMlDsaPolyVec;
  LCp: IMlDsaPoly;
  LMatrix: IMlDsaPolyVecMatrix;
  LT1, LW1: IMlDsaPolyVec;
begin
  if ASigLen <> FCryptoBytes then
    Exit(False);
  LH := TMlDsaPolyVec.Create(Self as IMlDsaEngine, FK);
  LZ := TMlDsaPolyVec.Create(Self as IMlDsaEngine, FL);
  if not TMlDsaPacking.UnpackSignature(LZ, LH, ASig, Self as IMlDsaEngine) then
    Exit(False);
  if LZ.CheckNorm(FGamma1 - FBeta) then
    Exit(False);
  System.SetLength(LBuf, Math.Max(CrhBytes + FK * FPolyW1PackedBytes, FCTilde));
  ADigest.OutputFinal(LBuf, 0, CrhBytes);
  LCp := TMlDsaPoly.Create(Self as IMlDsaEngine);
  LMatrix := TMlDsaPolyVecMatrix.Create(Self as IMlDsaEngine);
  LT1 := TMlDsaPolyVec.Create(Self as IMlDsaEngine, FK);
  LW1 := TMlDsaPolyVec.Create(Self as IMlDsaEngine, FK);
  TMlDsaPacking.UnpackPublicKey(LT1, AEncT1, Self as IMlDsaEngine);
  LCp.Challenge(ASig, 0, FCTilde);
  LMatrix.ExpandMatrix(ARho);
  LZ.Ntt;
  LMatrix.PointwiseMontgomery(LW1, LZ);
  LCp.PolyNtt;
  LT1.ShiftLeft;
  LT1.Ntt;
  LT1.PointwisePolyMontgomery(LCp, LT1);
  LW1.Subtract(LT1);
  LW1.Reduce;
  LW1.InverseNttToMont;
  LW1.ConditionalAddQ;
  LW1.UseHint(LW1, LH);
  LW1.PackW1(LBuf, CrhBytes);
  ADigest.Reset;
  ADigest.BlockUpdate(LBuf, 0, CrhBytes + FK * FPolyW1PackedBytes);
  ADigest.OutputFinal(LBuf, 0, FCTilde);
  Result := FixedTimeEquals(FCTilde, ASig, 0, LBuf, 0);
end;

function TMlDsaEngine.MsgRepPreHash(const ATr, AMsg: TCryptoLibByteArray; AMsgOff, AMsgLen: Int32): IXof;
begin
  Result := CreateMsgRepDigest;
  MsgRepBegin(Result, ATr);
  Result.BlockUpdate(AMsg, AMsgOff, AMsgLen);
end;

procedure TMlDsaEngine.Sign(var ASig: TCryptoLibByteArray; ASigLen: Int32; const AMsg: TCryptoLibByteArray;
  AMsgOff, AMsgLen: Int32; const ARho, AK, ATr, AT0Enc, AS1Enc, AS2Enc: TCryptoLibByteArray);
var
  LDigest: IXof;
begin
  LDigest := MsgRepPreHash(ATr, AMsg, AMsgOff, AMsgLen);
  MsgRepEndSign(LDigest, ASig, ASigLen, ARho, AK, AT0Enc, AS1Enc, AS2Enc);
end;

procedure TMlDsaEngine.SignRaw(var ASig: TCryptoLibByteArray; ASigLen: Int32; const AMsg: TCryptoLibByteArray;
  AMsgOff, AMsgLen: Int32; const ARho, AK, ATr, AT0Enc, AS1Enc, AS2Enc, ARnd: TCryptoLibByteArray);
var
  LDigest: IXof;
begin
  LDigest := MsgRepPreHash(ATr, AMsg, AMsgOff, AMsgLen);
  MsgRepEndSignCore(LDigest, ASig, ASigLen, ARho, AK, AT0Enc, AS1Enc, AS2Enc, ARnd);
end;

function TMlDsaEngine.VerifyRaw(const ASig: TCryptoLibByteArray; ASigLen: Int32;
  const AMsg: TCryptoLibByteArray; AMsgOff, AMsgLen: Int32; const ARho, AEncT1,
  ATr: TCryptoLibByteArray): Boolean;
var
  LDigest: IXof;
begin
  LDigest := MsgRepPreHash(ATr, AMsg, AMsgOff, AMsgLen);
  Result := MsgRepEndVerifyCore(LDigest, ASig, ASigLen, ARho, AEncT1);
end;

end.
