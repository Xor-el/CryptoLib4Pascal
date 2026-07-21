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

unit ClpSlhDsaCore;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  Generics.Collections,
  ClpPack,
  ClpArrayUtilities,
  ClpISlhDsaCore,
  ClpISlhDsaEngine,
  ClpCryptoLibTypes,
  ClpCryptoLibExceptions;

resourcestring
  SSlhDsaInvalidTreeHashIndex = 'invalid tree hash index';
  SSlhDsaInvalidChain = 'invalid WOTS+ chain';

const
  SlhDsaAdrsWotsHash = UInt32(0);
  SlhDsaAdrsWotsPK = UInt32(1);
  SlhDsaAdrsTree = UInt32(2);
  SlhDsaAdrsForsTree = UInt32(3);
  SlhDsaAdrsForsPK = UInt32(4);
  SlhDsaAdrsWotsPrf = UInt32(5);
  SlhDsaAdrsForsPrf = UInt32(6);

  SlhDsaAdrsOffsetLayer = 0;
  SlhDsaAdrsOffsetTree = 4;
  SlhDsaAdrsOffsetTreeHgt = 24;
  SlhDsaAdrsOffsetTreeIndex = 28;
  SlhDsaAdrsOffsetType = 16;
  SlhDsaAdrsOffsetKPAddr = 20;
  SlhDsaAdrsOffsetChainAddr = 24;
  SlhDsaAdrsOffsetHashAddr = 28;

type
  TSlhDsaSK = record
    Seed: TCryptoLibByteArray;
    Prf: TCryptoLibByteArray;
  end;

  TSlhDsaPK = record
    Seed: TCryptoLibByteArray;
    Root: TCryptoLibByteArray;
  end;

  TSlhDsaNodeEntry = record
    NodeValue: TCryptoLibByteArray;
    NodeHeight: UInt32;
  end;

  TSlhDsaIndexedDigest = class sealed(TInterfacedObject, ISlhDsaIndexedDigest)
  strict private
  var
    FIdxTree: UInt64;
    FIdxLeaf: UInt32;
    FDigest: TCryptoLibByteArray;
  public
    constructor Create(AIdxTree: UInt64; AIdxLeaf: UInt32; const ADigest: TCryptoLibByteArray);
    function GetIdxTree: UInt64;
    function GetIdxLeaf: UInt32;
    function GetDigest: TCryptoLibByteArray;
  end;

  TSlhDsaAdrs = class sealed(TInterfacedObject, ISlhDsaAdrs)
  strict private
  var
    FValue: TCryptoLibByteArray;
  public
    constructor Create; overload;
    constructor Create(AAdrsType: UInt32); overload;
    constructor Create(const AAdrs: ISlhDsaAdrs); overload;
    constructor Create(const AAdrs: ISlhDsaAdrs; AAdrsType: UInt32); overload;
    procedure SetLayerAddress(ALayer: UInt32);
    procedure SetTreeAddress(ATree: UInt64);
    procedure SetTreeHeight(AHeight: UInt32);
    procedure SetTreeIndex(AIndex: UInt32);
    function GetTreeIndex: UInt32;
    procedure SetType(AAdrsType: UInt32);
    procedure SetTypeAndClear(AAdrsType: UInt32);
    procedure SetKeyPairAddress(AKeyPairAddr: UInt32);
    function GetKeyPairAddress: UInt32;
    procedure SetHashAddress(AHashAddr: UInt32);
    procedure SetChainAddress(AChainAddr: UInt32);
    function GetValue: TCryptoLibByteArray;
  end;

  TSlhDsaIndexGenerator = record
  strict private
  var
    FBitsPerIndex: Int32;
    FIndexMask: UInt32;
    FAvailableBits: Int32;
    FMessagePos: Int32;
    FIndexValue: UInt32;
  public
    procedure Init(ABitsPerIndex: Int32);
    function NextIndex(const AMessage: TCryptoLibByteArray): UInt32;
  end;

  TSlhDsaFors = class sealed(TObject)
  public
    class procedure TreeHash(const AEngine: ISlhDsaEngine; const ASkSeed: TCryptoLibByteArray;
      S: UInt32; Z: Int32; const AAdrsParam: ISlhDsaAdrs; var AOutput: TCryptoLibByteArray;
      AOutputOff: Int32); static;
    class procedure Sign(const AEngine: ISlhDsaEngine; const AMd, ASkSeed: TCryptoLibByteArray;
      const AParamAdrs: ISlhDsaAdrs; var ASignature: TCryptoLibByteArray); static;
    class procedure PKFromSig(const AEngine: ISlhDsaEngine; const ASignature, AMessage: TCryptoLibByteArray;
      const AAdrs: ISlhDsaAdrs; var AOutput: TCryptoLibByteArray; AOutputOff: Int32); static;
  end;

  TSlhDsaWotsPlus = class
  strict private
  var
    FEngine: ISlhDsaEngine;
    procedure Chain(AI, ASteps: UInt32; const APkSeed: TCryptoLibByteArray; const AAdrs: ISlhDsaAdrs;
      var AX: TCryptoLibByteArray; AXOff: Int32);
    procedure BaseW(const AX: TCryptoLibByteArray; AXOff: Int32; AW: UInt32; var AOutput: TCryptoLibUInt32Array;
      AOutOff, AOutLen: Int32);
  public
    constructor Create(const AEngine: ISlhDsaEngine);
    destructor Destroy; override;
    procedure PKGen(const ASkSeed, APkSeed: TCryptoLibByteArray; const AParamAdrs: ISlhDsaAdrs;
      var AOutput: TCryptoLibByteArray; AOutputOff: Int32);
    procedure Sign(const AM, ASkSeed, APkSeed: TCryptoLibByteArray; const AParamAdrs: ISlhDsaAdrs;
      var AOutput: TCryptoLibByteArray; AOutputOff: Int32);
    procedure PKFromSig(const ASig: TCryptoLibByteArray; ASigOff: Int32; const AM, APkSeed: TCryptoLibByteArray;
      const AAdrs: ISlhDsaAdrs; var AOutput: TCryptoLibByteArray; AOutputOff: Int32);
  end;

  TSlhDsaHT = class
  strict private
  var
    FSkSeed: TCryptoLibByteArray;
    FPkSeed: TCryptoLibByteArray;
    FEngine: ISlhDsaEngine;
    FWots: TSlhDsaWotsPlus;
    FHTPubKey: TCryptoLibByteArray;
    class function GetXmssOffset(const AEngine: ISlhDsaEngine): Int32; static;
    function XmssPkFromSig(AIdx: UInt32; const ASigXmss: TCryptoLibByteArray; ASigXmssOff: Int32;
      const AM, APkSeed: TCryptoLibByteArray; const AParamAdrs: ISlhDsaAdrs): TCryptoLibByteArray;
    procedure XmssSign(const AM, ASkSeed, APkSeed: TCryptoLibByteArray; AIdx: UInt32;
      const AParamAdrs: ISlhDsaAdrs; var ASigXmss: TCryptoLibByteArray; var ASigXmssPos: Int32);
    procedure TreeHash(const ASkSeed: TCryptoLibByteArray; S: UInt32; Z: Int32; const APkSeed: TCryptoLibByteArray;
      const AAdrsParam: ISlhDsaAdrs; var AOutput: TCryptoLibByteArray; AOutputOff: Int32);
  public
    constructor Create(const AEngine: ISlhDsaEngine; const ASkSeed, APkSeed: TCryptoLibByteArray);
    destructor Destroy; override;
    function GetHTPubKey: TCryptoLibByteArray;
    procedure Sign(const AM: TCryptoLibByteArray; AIdxTree: UInt64; AIdxLeaf: UInt32;
      var ASignature: TCryptoLibByteArray);
    function Verify(const AM, ASignature, APkSeed: TCryptoLibByteArray; AIdxTree: UInt64; AIdxLeaf: UInt32;
      const APK_HT: TCryptoLibByteArray): Boolean;
  end;

implementation

{ TSlhDsaIndexedDigest }

constructor TSlhDsaIndexedDigest.Create(AIdxTree: UInt64; AIdxLeaf: UInt32;
  const ADigest: TCryptoLibByteArray);
begin
  inherited Create;
  FIdxTree := AIdxTree;
  FIdxLeaf := AIdxLeaf;
  FDigest := ADigest;
end;

function TSlhDsaIndexedDigest.GetDigest: TCryptoLibByteArray;
begin
  Result := FDigest;
end;

function TSlhDsaIndexedDigest.GetIdxLeaf: UInt32;
begin
  Result := FIdxLeaf;
end;

function TSlhDsaIndexedDigest.GetIdxTree: UInt64;
begin
  Result := FIdxTree;
end;

{ TSlhDsaAdrs }

constructor TSlhDsaAdrs.Create;
begin
  inherited Create;
  System.SetLength(FValue, 32);
end;

constructor TSlhDsaAdrs.Create(AAdrsType: UInt32);
begin
  Create;
  SetType(AAdrsType);
end;

constructor TSlhDsaAdrs.Create(const AAdrs: ISlhDsaAdrs);
begin
  Create;
  System.Move(AAdrs.GetValue[0], FValue[0], 32);
end;

constructor TSlhDsaAdrs.Create(const AAdrs: ISlhDsaAdrs; AAdrsType: UInt32);
begin
  Create;
  System.Move(AAdrs.GetValue[0], FValue[0], SlhDsaAdrsOffsetType);
  SetType(AAdrsType);
end;

function TSlhDsaAdrs.GetKeyPairAddress: UInt32;
begin
  Result := TPack.BE_To_UInt32(FValue, SlhDsaAdrsOffsetKPAddr);
end;

function TSlhDsaAdrs.GetTreeIndex: UInt32;
begin
  Result := TPack.BE_To_UInt32(FValue, SlhDsaAdrsOffsetTreeIndex);
end;

function TSlhDsaAdrs.GetValue: TCryptoLibByteArray;
begin
  Result := FValue;
end;

procedure TSlhDsaAdrs.SetChainAddress(AChainAddr: UInt32);
begin
  TPack.UInt32_To_BE(AChainAddr, FValue, SlhDsaAdrsOffsetChainAddr);
end;

procedure TSlhDsaAdrs.SetHashAddress(AHashAddr: UInt32);
begin
  TPack.UInt32_To_BE(AHashAddr, FValue, SlhDsaAdrsOffsetHashAddr);
end;

procedure TSlhDsaAdrs.SetKeyPairAddress(AKeyPairAddr: UInt32);
begin
  TPack.UInt32_To_BE(AKeyPairAddr, FValue, SlhDsaAdrsOffsetKPAddr);
end;

procedure TSlhDsaAdrs.SetLayerAddress(ALayer: UInt32);
begin
  TPack.UInt32_To_BE(ALayer, FValue, SlhDsaAdrsOffsetLayer);
end;

procedure TSlhDsaAdrs.SetTreeAddress(ATree: UInt64);
begin
  TPack.UInt64_To_BE(ATree, FValue, SlhDsaAdrsOffsetTree + 4);
end;

procedure TSlhDsaAdrs.SetTreeHeight(AHeight: UInt32);
begin
  TPack.UInt32_To_BE(AHeight, FValue, SlhDsaAdrsOffsetTreeHgt);
end;

procedure TSlhDsaAdrs.SetTreeIndex(AIndex: UInt32);
begin
  TPack.UInt32_To_BE(AIndex, FValue, SlhDsaAdrsOffsetTreeIndex);
end;

procedure TSlhDsaAdrs.SetType(AAdrsType: UInt32);
begin
  TPack.UInt32_To_BE(AAdrsType, FValue, SlhDsaAdrsOffsetType);
end;

procedure TSlhDsaAdrs.SetTypeAndClear(AAdrsType: UInt32);
begin
  SetType(AAdrsType);
  TArrayUtilities.Fill(FValue, SlhDsaAdrsOffsetType + 4, 32, Byte(0));
end;

{ TSlhDsaIndexGenerator }

procedure TSlhDsaIndexGenerator.Init(ABitsPerIndex: Int32);
begin
  FBitsPerIndex := ABitsPerIndex;
  FIndexMask := (UInt32(1) shl ABitsPerIndex) - UInt32(1);
  FAvailableBits := 0;
  FMessagePos := 0;
  FIndexValue := 0;
end;

function TSlhDsaIndexGenerator.NextIndex(const AMessage: TCryptoLibByteArray): UInt32;
begin
  while FAvailableBits < FBitsPerIndex do
  begin
    FAvailableBits := FAvailableBits + 8;
    FIndexValue := FIndexValue shl 8;
    FIndexValue := FIndexValue or UInt32(AMessage[FMessagePos]);
    System.Inc(FMessagePos);
  end;
  FAvailableBits := FAvailableBits - FBitsPerIndex;
  Result := (FIndexValue shr FAvailableBits) and FIndexMask;
end;

{ TSlhDsaFors }

class procedure TSlhDsaFors.TreeHash(const AEngine: ISlhDsaEngine; const ASkSeed: TCryptoLibByteArray;
  S: UInt32; Z: Int32; const AAdrsParam: ISlhDsaAdrs; var AOutput: TCryptoLibByteArray; AOutputOff: Int32);
var
  LStack: TStack<TSlhDsaNodeEntry>;
  LAdrs: ISlhDsaAdrs;
  LIdx: UInt32;
  LNode: TCryptoLibByteArray;
  LAdrsTreeHeight, LAdrsTreeIndex: UInt32;
  LCurrent, LEntry: TSlhDsaNodeEntry;
begin
  if ((S shr Z) shl Z) <> S then
    raise EInvalidOperationCryptoLibException.CreateRes(@SSlhDsaInvalidTreeHashIndex);

  LStack := TStack<TSlhDsaNodeEntry>.Create;
  try
    LAdrs := TSlhDsaAdrs.Create(AAdrsParam);
    for LIdx := 0 to (UInt32(1) shl Z) - 1 do
    begin
      LAdrs.SetTypeAndClear(SlhDsaAdrsForsPrf);
      LAdrs.SetKeyPairAddress(AAdrsParam.GetKeyPairAddress);
      LAdrs.SetTreeHeight(0);
      LAdrs.SetTreeIndex(S + LIdx);

      System.SetLength(LNode, AEngine.N);
      AEngine.Prf(LAdrs, ASkSeed, LNode, 0);

      LAdrs.SetType(SlhDsaAdrsForsTree);
      AEngine.F(LAdrs, LNode, 0);
      LAdrs.SetTreeHeight(1);

      LAdrsTreeHeight := 1;
      LAdrsTreeIndex := S + LIdx;

      while (LStack.Count > 0) and (LStack.Peek.NodeHeight = LAdrsTreeHeight) do
      begin
        LAdrsTreeIndex := (LAdrsTreeIndex - 1) div 2;
        LAdrs.SetTreeIndex(LAdrsTreeIndex);
        LCurrent := LStack.Pop;
        AEngine.H2(LAdrs, LCurrent.NodeValue, 0, LNode, 0);
        System.Inc(LAdrsTreeHeight);
        LAdrs.SetTreeHeight(LAdrsTreeHeight);
      end;

      LEntry.NodeValue := LNode;
      LEntry.NodeHeight := LAdrsTreeHeight;
      LStack.Push(LEntry);
    end;
    System.Move(LStack.Peek.NodeValue[0], AOutput[AOutputOff], AEngine.N);
  finally
    LStack.Free;
  end;
end;

class procedure TSlhDsaFors.Sign(const AEngine: ISlhDsaEngine; const AMd, ASkSeed: TCryptoLibByteArray;
  const AParamAdrs: ISlhDsaAdrs; var ASignature: TCryptoLibByteArray);
var
  LAdrs: ISlhDsaAdrs;
  LIndexGenerator: TSlhDsaIndexGenerator;
  LForsPos, LI, LJ: Int32;
  LIndex: UInt32;
  LS: UInt32;
begin
  LAdrs := TSlhDsaAdrs.Create(AParamAdrs);
  LIndexGenerator.Init(AEngine.A);
  LForsPos := AEngine.N;

  for LI := 0 to AEngine.K - 1 do
  begin
    LIndex := LIndexGenerator.NextIndex(AMd);

    LAdrs.SetTypeAndClear(SlhDsaAdrsForsPrf);
    LAdrs.SetKeyPairAddress(AParamAdrs.GetKeyPairAddress);
    LAdrs.SetTreeHeight(0);
    LAdrs.SetTreeIndex((UInt32(LI) shl AEngine.A) + LIndex);

    AEngine.Prf(LAdrs, ASkSeed, ASignature, LForsPos);
    LForsPos := LForsPos + AEngine.N;

    LAdrs.SetType(SlhDsaAdrsForsTree);

    for LJ := 0 to AEngine.A - 1 do
    begin
      LS := (LIndex shr LJ) xor 1;
      TreeHash(AEngine, ASkSeed, (UInt32(LI) shl AEngine.A) + (LS shl LJ), LJ, LAdrs, ASignature, LForsPos);
      LForsPos := LForsPos + AEngine.N;
    end;
  end;
end;

class procedure TSlhDsaFors.PKFromSig(const AEngine: ISlhDsaEngine; const ASignature, AMessage: TCryptoLibByteArray;
  const AAdrs: ISlhDsaAdrs; var AOutput: TCryptoLibByteArray; AOutputOff: Int32);
var
  LA, LK, LN, LI, LJ, LRootsPos, LForsPos: Int32;
  LRoots: TCryptoLibByteArray;
  LIndexGenerator: TSlhDsaIndexGenerator;
  LIdx, LAdrsTreeIndex: UInt32;
  LForsPkAdrs: ISlhDsaAdrs;
begin
  LA := AEngine.A;
  LK := AEngine.K;
  LN := AEngine.N;

  System.SetLength(LRoots, LK * LN);
  LIndexGenerator.Init(LA);
  LForsPos := LN;

  for LI := 0 to LK - 1 do
  begin
    LIdx := LIndexGenerator.NextIndex(AMessage);
    LAdrsTreeIndex := (UInt32(LI) shl LA) + LIdx;

    AAdrs.SetTreeHeight(0);
    AAdrs.SetTreeIndex(LAdrsTreeIndex);

    LRootsPos := LI * LN;
    System.Move(ASignature[LForsPos], LRoots[LRootsPos], LN);
    LForsPos := LForsPos + LN;
    AEngine.F(AAdrs, LRoots, LRootsPos);

    for LJ := 0 to LA - 1 do
    begin
      AAdrs.SetTreeHeight(UInt32(LJ + 1));

      if (LIdx and (UInt32(1) shl LJ)) = 0 then
      begin
        LAdrsTreeIndex := LAdrsTreeIndex div 2;
        AAdrs.SetTreeIndex(LAdrsTreeIndex);
        AEngine.H1(AAdrs, LRoots, LRootsPos, ASignature, LForsPos);
      end
      else
      begin
        LAdrsTreeIndex := (LAdrsTreeIndex - 1) div 2;
        AAdrs.SetTreeIndex(LAdrsTreeIndex);
        AEngine.H2(AAdrs, ASignature, LForsPos, LRoots, LRootsPos);
      end;
      LForsPos := LForsPos + LN;
    end;
  end;

  LForsPkAdrs := TSlhDsaAdrs.Create(AAdrs, SlhDsaAdrsForsPK);
  LForsPkAdrs.SetKeyPairAddress(AAdrs.GetKeyPairAddress);
  AEngine.T_l(LForsPkAdrs, LRoots, AOutput, AOutputOff);
end;

{ TSlhDsaWotsPlus }

constructor TSlhDsaWotsPlus.Create(const AEngine: ISlhDsaEngine);
begin
  inherited Create;
  FEngine := AEngine;
end;

destructor TSlhDsaWotsPlus.Destroy;
begin
  FEngine := nil;
  inherited Destroy;
end;

procedure TSlhDsaWotsPlus.BaseW(const AX: TCryptoLibByteArray; AXOff: Int32; AW: UInt32;
  var AOutput: TCryptoLibUInt32Array; AOutOff, AOutLen: Int32);
var
  LWotsLogW, LTotal, LBits, LXOff, LOutOff, LConsumed: Int32;
begin
  LWotsLogW := FEngine.WotsLogW;
  LTotal := 0;
  LBits := 0;
  LXOff := AXOff;
  LOutOff := AOutOff;

  for LConsumed := 0 to AOutLen - 1 do
  begin
    if LBits = 0 then
    begin
      LTotal := AX[LXOff];
      System.Inc(LXOff);
      LBits := LBits + 8;
    end;
    LBits := LBits - LWotsLogW;
    AOutput[LOutOff] := UInt32((LTotal shr LBits) and (AW - 1));
    System.Inc(LOutOff);
  end;
end;

procedure TSlhDsaWotsPlus.Chain(AI, ASteps: UInt32; const APkSeed: TCryptoLibByteArray; const AAdrs: ISlhDsaAdrs;
  var AX: TCryptoLibByteArray; AXOff: Int32);
var
  LJ: UInt32;
begin
  if (AI + ASteps) > UInt32(FEngine.WotsW - 1) then
    raise EInvalidOperationCryptoLibException.CreateRes(@SSlhDsaInvalidChain);

  LJ := 0;
  while LJ < ASteps do
  begin
    AAdrs.SetHashAddress(AI + LJ);
    FEngine.F(AAdrs, AX, AXOff);
    System.Inc(LJ);
  end;
end;

procedure TSlhDsaWotsPlus.PKGen(const ASkSeed, APkSeed: TCryptoLibByteArray; const AParamAdrs: ISlhDsaAdrs;
  var AOutput: TCryptoLibByteArray; AOutputOff: Int32);
var
  LN, LWotsLen, LI: Int32;
  LW: UInt32;
  LWotsPkAdrs, LAdrs: ISlhDsaAdrs;
  LTmpConcat: TCryptoLibByteArray;
begin
  LN := FEngine.N;
  LWotsLen := FEngine.WotsLen;
  LW := UInt32(FEngine.WotsW);

  LWotsPkAdrs := TSlhDsaAdrs.Create(AParamAdrs);
  System.SetLength(LTmpConcat, LWotsLen * LN);

  for LI := 0 to LWotsLen - 1 do
  begin
    LAdrs := TSlhDsaAdrs.Create(AParamAdrs);
    LAdrs.SetTypeAndClear(SlhDsaAdrsWotsPrf);
    LAdrs.SetKeyPairAddress(AParamAdrs.GetKeyPairAddress);
    LAdrs.SetChainAddress(UInt32(LI));
    LAdrs.SetHashAddress(0);

    FEngine.Prf(LAdrs, ASkSeed, LTmpConcat, LN * LI);

    LAdrs.SetTypeAndClear(SlhDsaAdrsWotsHash);
    LAdrs.SetKeyPairAddress(AParamAdrs.GetKeyPairAddress);
    LAdrs.SetChainAddress(UInt32(LI));
    LAdrs.SetHashAddress(0);

    Chain(0, LW - 1, APkSeed, LAdrs, LTmpConcat, LN * LI);
  end;

  LWotsPkAdrs.SetTypeAndClear(SlhDsaAdrsWotsPK);
  LWotsPkAdrs.SetKeyPairAddress(AParamAdrs.GetKeyPairAddress);
  FEngine.T_l(LWotsPkAdrs, LTmpConcat, AOutput, AOutputOff);
end;

procedure TSlhDsaWotsPlus.Sign(const AM, ASkSeed, APkSeed: TCryptoLibByteArray; const AParamAdrs: ISlhDsaAdrs;
  var AOutput: TCryptoLibByteArray; AOutputOff: Int32);
var
  LN, LWotsLen, LWotsLen1, LWotsLen2, LWotsLogW, LI, LLen2Bytes: Int32;
  LW: UInt32;
  LAdrs: ISlhDsaAdrs;
  LMsg: TCryptoLibUInt32Array;
  LCsum: UInt32;
  LCsumBytes: TCryptoLibByteArray;
begin
  LN := FEngine.N;
  LWotsLen := FEngine.WotsLen;
  LWotsLen1 := FEngine.WotsLen1;
  LWotsLen2 := FEngine.WotsLen2;
  LWotsLogW := FEngine.WotsLogW;
  LW := UInt32(FEngine.WotsW);

  LAdrs := TSlhDsaAdrs.Create(AParamAdrs);
  System.SetLength(LMsg, LWotsLen);

  BaseW(AM, 0, LW, LMsg, 0, LWotsLen1);

  LCsum := 0;
  for LI := 0 to LWotsLen1 - 1 do
    LCsum := LCsum + (LW - 1 - LMsg[LI]);

  if (LWotsLogW mod 8) <> 0 then
    LCsum := LCsum shl (8 - ((LWotsLen2 * LWotsLogW) mod 8));

  LLen2Bytes := (LWotsLen2 * LWotsLogW + 7) div 8;
  LCsumBytes := TPack.UInt32_To_BE(LCsum);
  BaseW(LCsumBytes, 4 - LLen2Bytes, LW, LMsg, LWotsLen1, LWotsLen2);

  for LI := 0 to LWotsLen - 1 do
  begin
    LAdrs.SetTypeAndClear(SlhDsaAdrsWotsPrf);
    LAdrs.SetKeyPairAddress(AParamAdrs.GetKeyPairAddress);
    LAdrs.SetChainAddress(UInt32(LI));
    LAdrs.SetHashAddress(0);

    FEngine.Prf(LAdrs, ASkSeed, AOutput, AOutputOff + LN * LI);

    LAdrs.SetTypeAndClear(SlhDsaAdrsWotsHash);
    LAdrs.SetKeyPairAddress(AParamAdrs.GetKeyPairAddress);
    LAdrs.SetChainAddress(UInt32(LI));
    LAdrs.SetHashAddress(0);

    Chain(0, LMsg[LI], APkSeed, LAdrs, AOutput, AOutputOff + LN * LI);
  end;
end;

procedure TSlhDsaWotsPlus.PKFromSig(const ASig: TCryptoLibByteArray; ASigOff: Int32; const AM, APkSeed: TCryptoLibByteArray;
  const AAdrs: ISlhDsaAdrs; var AOutput: TCryptoLibByteArray; AOutputOff: Int32);
var
  LN, LWotsLen, LWotsLen1, LWotsLen2, LWotsLogW, LI, LLen2Bytes, LSigPos: Int32;
  LW: UInt32;
  LWotsPkAdrs: ISlhDsaAdrs;
  LMsg: TCryptoLibUInt32Array;
  LCsum: UInt32;
  LCsumBytes: TCryptoLibByteArray;
  LTmpConcat: TCryptoLibByteArray;
begin
  LN := FEngine.N;
  LWotsLen := FEngine.WotsLen;
  LWotsLen1 := FEngine.WotsLen1;
  LWotsLen2 := FEngine.WotsLen2;
  LWotsLogW := FEngine.WotsLogW;
  LW := UInt32(FEngine.WotsW);

  LWotsPkAdrs := TSlhDsaAdrs.Create(AAdrs);
  System.SetLength(LMsg, LWotsLen);

  BaseW(AM, 0, LW, LMsg, 0, LWotsLen1);

  LCsum := 0;
  for LI := 0 to LWotsLen1 - 1 do
    LCsum := LCsum + (LW - 1 - LMsg[LI]);

  LCsum := LCsum shl (8 - ((LWotsLen2 * LWotsLogW) mod 8));
  LLen2Bytes := (LWotsLen2 * LWotsLogW + 7) div 8;
  LCsumBytes := TPack.UInt32_To_BE(LCsum);
  BaseW(LCsumBytes, 4 - LLen2Bytes, LW, LMsg, LWotsLen1, LWotsLen2);

  System.SetLength(LTmpConcat, LWotsLen * LN);

  for LI := 0 to LWotsLen - 1 do
  begin
    AAdrs.SetChainAddress(UInt32(LI));
    LSigPos := LN * LI;
    System.Move(ASig[ASigOff + LSigPos], LTmpConcat[LSigPos], LN);
    Chain(LMsg[LI], LW - 1 - LMsg[LI], APkSeed, AAdrs, LTmpConcat, LSigPos);
  end;

  LWotsPkAdrs.SetTypeAndClear(SlhDsaAdrsWotsPK);
  LWotsPkAdrs.SetKeyPairAddress(AAdrs.GetKeyPairAddress);
  FEngine.T_l(LWotsPkAdrs, LTmpConcat, AOutput, AOutputOff);
end;

{ TSlhDsaHT }

constructor TSlhDsaHT.Create(const AEngine: ISlhDsaEngine; const ASkSeed, APkSeed: TCryptoLibByteArray);
var
  LAdrs: ISlhDsaAdrs;
begin
  inherited Create;
  FSkSeed := ASkSeed;
  FPkSeed := APkSeed;
  FEngine := AEngine;
  FWots := TSlhDsaWotsPlus.Create(AEngine);

  LAdrs := TSlhDsaAdrs.Create;
  LAdrs.SetLayerAddress(UInt32(FEngine.D - 1));
  LAdrs.SetTreeAddress(0);

  if ASkSeed <> nil then
  begin
    System.SetLength(FHTPubKey, FEngine.N);
    TreeHash(ASkSeed, 0, FEngine.HPrime, APkSeed, LAdrs, FHTPubKey, 0);
  end
  else
    FHTPubKey := nil;
end;

destructor TSlhDsaHT.Destroy;
begin
  FWots.Free;
  FEngine := nil;
  inherited Destroy;
end;

function TSlhDsaHT.GetHTPubKey: TCryptoLibByteArray;
begin
  Result := FHTPubKey;
end;

class function TSlhDsaHT.GetXmssOffset(const AEngine: ISlhDsaEngine): Int32;
begin
  Result := (((AEngine.A + 1) * AEngine.K) + 1) * AEngine.N;
end;

function TSlhDsaHT.XmssPkFromSig(AIdx: UInt32; const ASigXmss: TCryptoLibByteArray; ASigXmssOff: Int32;
  const AM, APkSeed: TCryptoLibByteArray; const AParamAdrs: ISlhDsaAdrs): TCryptoLibByteArray;
var
  LN, LK: Int32;
  LAdrs: ISlhDsaAdrs;
  LNode: TCryptoLibByteArray;
begin
  LN := FEngine.N;
  LAdrs := TSlhDsaAdrs.Create(AParamAdrs, SlhDsaAdrsWotsHash);
  LAdrs.SetKeyPairAddress(AIdx);

  System.SetLength(LNode, LN);
  FWots.PKFromSig(ASigXmss, ASigXmssOff, AM, APkSeed, LAdrs, LNode, 0);
  ASigXmssOff := ASigXmssOff + FEngine.WotsLen * LN;

  LAdrs.SetTypeAndClear(SlhDsaAdrsTree);
  LAdrs.SetTreeIndex(AIdx);

  for LK := 0 to FEngine.HPrime - 1 do
  begin
    LAdrs.SetTreeHeight(UInt32(LK + 1));
    if (AIdx and (UInt32(1) shl LK)) = 0 then
    begin
      LAdrs.SetTreeIndex(LAdrs.GetTreeIndex div 2);
      FEngine.H1(LAdrs, LNode, 0, ASigXmss, ASigXmssOff);
    end
    else
    begin
      LAdrs.SetTreeIndex((LAdrs.GetTreeIndex - 1) div 2);
      FEngine.H2(LAdrs, ASigXmss, ASigXmssOff, LNode, 0);
    end;
    ASigXmssOff := ASigXmssOff + LN;
  end;

  Result := LNode;
end;

procedure TSlhDsaHT.XmssSign(const AM, ASkSeed, APkSeed: TCryptoLibByteArray; AIdx: UInt32;
  const AParamAdrs: ISlhDsaAdrs; var ASigXmss: TCryptoLibByteArray; var ASigXmssPos: Int32);
var
  LAdrs: ISlhDsaAdrs;
  LJ: Int32;
  LK: UInt32;
begin
  LAdrs := TSlhDsaAdrs.Create(AParamAdrs, SlhDsaAdrsWotsHash);
  LAdrs.SetKeyPairAddress(AIdx);

  FWots.Sign(AM, ASkSeed, APkSeed, LAdrs, ASigXmss, ASigXmssPos);
  ASigXmssPos := ASigXmssPos + FEngine.WotsLen * FEngine.N;

  LAdrs := TSlhDsaAdrs.Create(AParamAdrs, SlhDsaAdrsTree);

  for LJ := 0 to FEngine.HPrime - 1 do
  begin
    LK := (AIdx shr LJ) xor 1;
    TreeHash(ASkSeed, LK shl LJ, LJ, APkSeed, LAdrs, ASigXmss, ASigXmssPos);
    ASigXmssPos := ASigXmssPos + FEngine.N;
  end;
end;

procedure TSlhDsaHT.TreeHash(const ASkSeed: TCryptoLibByteArray; S: UInt32; Z: Int32;
  const APkSeed: TCryptoLibByteArray; const AAdrsParam: ISlhDsaAdrs; var AOutput: TCryptoLibByteArray;
  AOutputOff: Int32);
var
  LN: Int32;
  LStack: TStack<TSlhDsaNodeEntry>;
  LAdrs: ISlhDsaAdrs;
  LIdx: UInt32;
  LNode: TCryptoLibByteArray;
  LAdrsTreeHeight, LAdrsTreeIndex: UInt32;
  LCurrent, LEntry: TSlhDsaNodeEntry;
begin
  if ((S shr Z) shl Z) <> S then
    raise EInvalidOperationCryptoLibException.CreateRes(@SSlhDsaInvalidTreeHashIndex);

  LN := FEngine.N;
  LStack := TStack<TSlhDsaNodeEntry>.Create;
  try
    LAdrs := TSlhDsaAdrs.Create(AAdrsParam);
    for LIdx := 0 to (UInt32(1) shl Z) - 1 do
    begin
      LAdrs.SetTypeAndClear(SlhDsaAdrsWotsHash);
      LAdrs.SetKeyPairAddress(S + LIdx);

      System.SetLength(LNode, LN);
      FWots.PKGen(ASkSeed, APkSeed, LAdrs, LNode, 0);

      LAdrs.SetTypeAndClear(SlhDsaAdrsTree);
      LAdrs.SetTreeHeight(1);
      LAdrs.SetTreeIndex(S + LIdx);

      LAdrsTreeHeight := 1;
      LAdrsTreeIndex := S + LIdx;

      while (LStack.Count > 0) and (LStack.Peek.NodeHeight = LAdrsTreeHeight) do
      begin
        LAdrsTreeIndex := (LAdrsTreeIndex - 1) div 2;
        LAdrs.SetTreeIndex(LAdrsTreeIndex);
        LCurrent := LStack.Pop;
        FEngine.H2(LAdrs, LCurrent.NodeValue, 0, LNode, 0);
        System.Inc(LAdrsTreeHeight);
        LAdrs.SetTreeHeight(LAdrsTreeHeight);
      end;

      LEntry.NodeValue := LNode;
      LEntry.NodeHeight := LAdrsTreeHeight;
      LStack.Push(LEntry);
    end;
    System.Move(LStack.Peek.NodeValue[0], AOutput[AOutputOff], LN);
  finally
    LStack.Free;
  end;
end;

procedure TSlhDsaHT.Sign(const AM: TCryptoLibByteArray; AIdxTree: UInt64; AIdxLeaf: UInt32;
  var ASignature: TCryptoLibByteArray);
var
  LAdrs: ISlhDsaAdrs;
  LSigXmssPos, LPos0, LPosJ, LJ: Int32;
  LRoot: TCryptoLibByteArray;
  LIdxTree: UInt64;
  LIdxLeaf: UInt32;
begin
  LAdrs := TSlhDsaAdrs.Create;
  LAdrs.SetLayerAddress(0);
  LAdrs.SetTreeAddress(AIdxTree);

  LSigXmssPos := GetXmssOffset(FEngine);
  LPos0 := LSigXmssPos;
  XmssSign(AM, FSkSeed, FPkSeed, AIdxLeaf, LAdrs, ASignature, LSigXmssPos);

  LAdrs.SetLayerAddress(0);
  LAdrs.SetTreeAddress(AIdxTree);
  LRoot := XmssPkFromSig(AIdxLeaf, ASignature, LPos0, AM, FPkSeed, LAdrs);

  LIdxTree := AIdxTree;
  LIdxLeaf := AIdxLeaf;
  for LJ := 1 to FEngine.D - 1 do
  begin
    LIdxLeaf := UInt32(LIdxTree and UInt64((1 shl FEngine.HPrime) - 1));
    LIdxTree := LIdxTree shr FEngine.HPrime;
    LAdrs.SetLayerAddress(UInt32(LJ));
    LAdrs.SetTreeAddress(LIdxTree);

    LPosJ := LSigXmssPos;
    XmssSign(LRoot, FSkSeed, FPkSeed, LIdxLeaf, LAdrs, ASignature, LSigXmssPos);

    if LJ < FEngine.D - 1 then
      LRoot := XmssPkFromSig(LIdxLeaf, ASignature, LPosJ, LRoot, FPkSeed, LAdrs);
  end;
end;

function TSlhDsaHT.Verify(const AM, ASignature, APkSeed: TCryptoLibByteArray; AIdxTree: UInt64; AIdxLeaf: UInt32;
  const APK_HT: TCryptoLibByteArray): Boolean;
var
  LAdrs: ISlhDsaAdrs;
  LXmssPos, LJ: Int32;
  LNode: TCryptoLibByteArray;
  LIdxTree: UInt64;
  LIdxLeaf: UInt32;
begin
  LXmssPos := GetXmssOffset(FEngine);

  LAdrs := TSlhDsaAdrs.Create;
  LAdrs.SetLayerAddress(0);
  LAdrs.SetTreeAddress(AIdxTree);

  LNode := XmssPkFromSig(AIdxLeaf, ASignature, LXmssPos, AM, APkSeed, LAdrs);

  LIdxTree := AIdxTree;
  LIdxLeaf := AIdxLeaf;
  for LJ := 1 to FEngine.D - 1 do
  begin
    LIdxLeaf := UInt32(LIdxTree and UInt64((1 shl FEngine.HPrime) - 1));
    LIdxTree := LIdxTree shr FEngine.HPrime;

    LAdrs.SetLayerAddress(UInt32(LJ));
    LAdrs.SetTreeAddress(LIdxTree);

    LXmssPos := LXmssPos + (FEngine.HPrime + FEngine.WotsLen) * FEngine.N;
    LNode := XmssPkFromSig(LIdxLeaf, ASignature, LXmssPos, LNode, APkSeed, LAdrs);
  end;

  Result := TArrayUtilities.AreEqual(APK_HT, LNode);
end;

end.
