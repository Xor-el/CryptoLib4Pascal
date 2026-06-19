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

unit ClpSlhDsaEngine;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpSlhDsaCore,
  ClpISlhDsaCore,
  ClpISlhDsaEngine,
  ClpDigestUtilities,
  ClpIDigest,
  ClpIXof,
  ClpIHMac,
  ClpHMac,
  ClpIKeyParameter,
  ClpKeyParameter,
  ClpPack,
  ClpArrayUtilities,
  ClpCryptoLibTypes;

resourcestring
  SSlhDsaInvalidWotsW = 'wots_w assumed 16 or 256';
  SSlhDsaInvalidWotsLen2 = 'cannot precompute SPX_WOTS_LEN2 for n outside {2, .., 256}';

type
  TSlhDsaEngine = class abstract(TInterfacedObject, ISlhDsaEngine)
  strict protected
  var
    FN, FWotsW, FWotsLogW, FWotsLen, FWotsLen1, FWotsLen2: Int32;
    FD, FA, FK, FFH, FHPrime, FSignatureLength: Int32;
    constructor Create(AN, AW, AD, AA, AK, AH: Int32);
  public
    function GetN: Int32;
    function GetWotsW: Int32;
    function GetWotsLogW: Int32;
    function GetWotsLen: Int32;
    function GetWotsLen1: Int32;
    function GetWotsLen2: Int32;
    function GetD: Int32;
    function GetA: Int32;
    function GetK: Int32;
    function GetFH: Int32;
    function GetHPrime: Int32;
    function GetSignatureLength: Int32;
    procedure Init(const APkSeed: TCryptoLibByteArray); virtual; abstract;
    procedure F(const AAdrs: ISlhDsaAdrs; var AM1: TCryptoLibByteArray; AM1Off: Int32); virtual; abstract;
    procedure H1(const AAdrs: ISlhDsaAdrs; var AM1: TCryptoLibByteArray; AM1Off: Int32;
      const AM2: TCryptoLibByteArray; AM2Off: Int32); virtual; abstract;
    procedure H2(const AAdrs: ISlhDsaAdrs; const AM1: TCryptoLibByteArray; AM1Off: Int32;
      var AM2: TCryptoLibByteArray; AM2Off: Int32); virtual; abstract;
    function HMsg(const APrf: TCryptoLibByteArray; APrfOff: Int32; const APkSeed, APkRoot: TCryptoLibByteArray;
      const AMsg: TCryptoLibByteArray; AMsgOff, AMsgLen: Int32): ISlhDsaIndexedDigest; virtual; abstract;
    procedure T_l(const AAdrs: ISlhDsaAdrs; const AM: TCryptoLibByteArray; var AOutput: TCryptoLibByteArray;
      AOutputOff: Int32); virtual; abstract;
    procedure Prf(const AAdrs: ISlhDsaAdrs; const ASkSeed: TCryptoLibByteArray; var APrf: TCryptoLibByteArray;
      APrfOff: Int32); virtual; abstract;
    procedure PrfMsg(const APrf, ARandomiser, AMsg: TCryptoLibByteArray; AMsgOff, AMsgLen: Int32;
      var AR: TCryptoLibByteArray; AROff: Int32); virtual; abstract;
  end;

  TSlhDsaSha2Engine = class sealed(TSlhDsaEngine)
  strict private
  var
    FZeroPad128: TCryptoLibByteArray;
    FTreeHMac: IHMac;
    FMsgDigest, FSha256: IDigest;
    FMsgMemo, FSha256Memo: IDigest;
    FHmacBuf, FMsgDigestBuf, FSha256Buf: TCryptoLibByteArray;
    class procedure UpdateCompressedAdrs(const ADigest: IDigest; const AAdrs: ISlhDsaAdrs); static;
    class procedure Mgf1Generate(const ADigest: IDigest; const ASeed: TCryptoLibByteArray; var AOutput: TCryptoLibByteArray;
      AOutOff, ALength: Int32); static;
  public
    constructor Create(AN, AW, AD, AA, AK, AH: Int32);
    procedure Init(const APkSeed: TCryptoLibByteArray); override;
    procedure F(const AAdrs: ISlhDsaAdrs; var AM1: TCryptoLibByteArray; AM1Off: Int32); override;
    procedure H1(const AAdrs: ISlhDsaAdrs; var AM1: TCryptoLibByteArray; AM1Off: Int32;
      const AM2: TCryptoLibByteArray; AM2Off: Int32); override;
    procedure H2(const AAdrs: ISlhDsaAdrs; const AM1: TCryptoLibByteArray; AM1Off: Int32;
      var AM2: TCryptoLibByteArray; AM2Off: Int32); override;
    function HMsg(const APrf: TCryptoLibByteArray; APrfOff: Int32; const APkSeed, APkRoot: TCryptoLibByteArray;
      const AMsg: TCryptoLibByteArray; AMsgOff, AMsgLen: Int32): ISlhDsaIndexedDigest; override;
    procedure T_l(const AAdrs: ISlhDsaAdrs; const AM: TCryptoLibByteArray; var AOutput: TCryptoLibByteArray;
      AOutputOff: Int32); override;
    procedure Prf(const AAdrs: ISlhDsaAdrs; const ASkSeed: TCryptoLibByteArray; var APrf: TCryptoLibByteArray;
      APrfOff: Int32); override;
    procedure PrfMsg(const APrf, ARandomiser, AMsg: TCryptoLibByteArray; AMsgOff, AMsgLen: Int32;
      var AR: TCryptoLibByteArray; AROff: Int32); override;
  end;

  TSlhDsaShake256Engine = class sealed(TSlhDsaEngine)
  strict private
  var
    FTreeDigest: IXof;
    FPkSeed: TCryptoLibByteArray;
  public
    constructor Create(AN, AW, AD, AA, AK, AH: Int32);
    procedure Init(const APkSeed: TCryptoLibByteArray); override;
    procedure F(const AAdrs: ISlhDsaAdrs; var AM1: TCryptoLibByteArray; AM1Off: Int32); override;
    procedure H1(const AAdrs: ISlhDsaAdrs; var AM1: TCryptoLibByteArray; AM1Off: Int32;
      const AM2: TCryptoLibByteArray; AM2Off: Int32); override;
    procedure H2(const AAdrs: ISlhDsaAdrs; const AM1: TCryptoLibByteArray; AM1Off: Int32;
      var AM2: TCryptoLibByteArray; AM2Off: Int32); override;
    function HMsg(const APrf: TCryptoLibByteArray; APrfOff: Int32; const APkSeed, APkRoot: TCryptoLibByteArray;
      const AMsg: TCryptoLibByteArray; AMsgOff, AMsgLen: Int32): ISlhDsaIndexedDigest; override;
    procedure T_l(const AAdrs: ISlhDsaAdrs; const AM: TCryptoLibByteArray; var AOutput: TCryptoLibByteArray;
      AOutputOff: Int32); override;
    procedure Prf(const AAdrs: ISlhDsaAdrs; const ASkSeed: TCryptoLibByteArray; var APrf: TCryptoLibByteArray;
      APrfOff: Int32); override;
    procedure PrfMsg(const APrf, ARandomiser, AMsg: TCryptoLibByteArray; AMsgOff, AMsgLen: Int32;
      var AR: TCryptoLibByteArray; AROff: Int32); override;
  end;

implementation

{ TSlhDsaEngine }

constructor TSlhDsaEngine.Create(AN, AW, AD, AA, AK, AH: Int32);
begin
  inherited Create;
  FN := AN;

  if AW = 16 then
  begin
    FWotsLogW := 4;
    FWotsLen1 := (8 * AN) div FWotsLogW;
    if AN <= 8 then
      FWotsLen2 := 2
    else if AN <= 136 then
      FWotsLen2 := 3
    else if AN <= 256 then
      FWotsLen2 := 4
    else
      raise EArgumentCryptoLibException.CreateRes(@SSlhDsaInvalidWotsLen2);
  end
  else if AW = 256 then
  begin
    FWotsLogW := 8;
    FWotsLen1 := (8 * AN) div FWotsLogW;
    if AN <= 1 then
      FWotsLen2 := 1
    else if AN <= 256 then
      FWotsLen2 := 2
    else
      raise EArgumentCryptoLibException.CreateRes(@SSlhDsaInvalidWotsLen2);
  end
  else
    raise EArgumentCryptoLibException.CreateRes(@SSlhDsaInvalidWotsW);

  FWotsW := AW;
  FWotsLen := FWotsLen1 + FWotsLen2;
  FD := AD;
  FA := AA;
  FK := AK;
  FFH := AH;
  FHPrime := AH div AD;
  FSignatureLength := (1 + FK * (1 + FA) + FFH + FD * FWotsLen) * FN;
end;

function TSlhDsaEngine.GetA: Int32;
begin
  Result := FA;
end;

function TSlhDsaEngine.GetD: Int32;
begin
  Result := FD;
end;

function TSlhDsaEngine.GetFH: Int32;
begin
  Result := FFH;
end;

function TSlhDsaEngine.GetHPrime: Int32;
begin
  Result := FHPrime;
end;

function TSlhDsaEngine.GetK: Int32;
begin
  Result := FK;
end;

function TSlhDsaEngine.GetN: Int32;
begin
  Result := FN;
end;

function TSlhDsaEngine.GetSignatureLength: Int32;
begin
  Result := FSignatureLength;
end;

function TSlhDsaEngine.GetWotsLen: Int32;
begin
  Result := FWotsLen;
end;

function TSlhDsaEngine.GetWotsLen1: Int32;
begin
  Result := FWotsLen1;
end;

function TSlhDsaEngine.GetWotsLen2: Int32;
begin
  Result := FWotsLen2;
end;

function TSlhDsaEngine.GetWotsLogW: Int32;
begin
  Result := FWotsLogW;
end;

function TSlhDsaEngine.GetWotsW: Int32;
begin
  Result := FWotsW;
end;

{ TSlhDsaSha2Engine }

constructor TSlhDsaSha2Engine.Create(AN, AW, AD, AA, AK, AH: Int32);
begin
  inherited Create(AN, AW, AD, AA, AK, AH);
  FSha256 := TDigestUtilities.GetDigest('SHA-256');
  System.SetLength(FSha256Buf, FSha256.GetDigestSize);

  if AN = 16 then
  begin
    FMsgDigest := TDigestUtilities.GetDigest('SHA-256');
    FTreeHMac := THMac.Create(TDigestUtilities.GetDigest('SHA-256'));
  end
  else
  begin
    FMsgDigest := TDigestUtilities.GetDigest('SHA-512');
    FTreeHMac := THMac.Create(TDigestUtilities.GetDigest('SHA-512'));
  end;

  System.SetLength(FHmacBuf, FTreeHMac.GetMacSize);
  System.SetLength(FMsgDigestBuf, FMsgDigest.GetDigestSize);
  FZeroPad128 := nil;
  System.SetLength(FZeroPad128, 128);
end;

class procedure TSlhDsaSha2Engine.UpdateCompressedAdrs(const ADigest: IDigest; const AAdrs: ISlhDsaAdrs);
var
  LValue: TCryptoLibByteArray;
begin
  LValue := AAdrs.GetValue;
  ADigest.Update(LValue[SlhDsaAdrsOffsetLayer + 3]);
  ADigest.BlockUpdate(LValue, SlhDsaAdrsOffsetTree + 4, 8);
  ADigest.Update(LValue[SlhDsaAdrsOffsetType + 3]);
  ADigest.BlockUpdate(LValue, 20, 12);
end;

class procedure TSlhDsaSha2Engine.Mgf1Generate(const ADigest: IDigest; const ASeed: TCryptoLibByteArray;
  var AOutput: TCryptoLibByteArray; AOutOff, ALength: Int32);
var
  LHLen, LHashPos, LCounterPos, LEnd, LLimit: Int32;
  LCounter: UInt32;
  LBuffer: TCryptoLibByteArray;
begin
  LHLen := ADigest.GetDigestSize;
  System.SetLength(LBuffer, System.Length(ASeed) + 4 + LHLen);
  System.Move(ASeed[0], LBuffer[0], System.Length(ASeed));
  LHashPos := System.Length(LBuffer) - LHLen;
  LCounterPos := LHashPos - 4;
  LCounter := 0;

  LEnd := AOutOff + ALength;
  LLimit := LEnd - LHLen;

  while AOutOff <= LLimit do
  begin
    TPack.UInt32_To_BE(LCounter, LBuffer, LCounterPos);
    System.Inc(LCounter);
    ADigest.Reset;
    ADigest.BlockUpdate(LBuffer, 0, LHashPos);
    ADigest.DoFinal(AOutput, AOutOff);
    AOutOff := AOutOff + LHLen;
  end;

  if AOutOff < LEnd then
  begin
    TPack.UInt32_To_BE(LCounter, LBuffer, LCounterPos);
    ADigest.Reset;
    ADigest.BlockUpdate(LBuffer, 0, LHashPos);
    ADigest.DoFinal(LBuffer, LHashPos);
    System.Move(LBuffer[LHashPos], AOutput[AOutOff], LEnd - AOutOff);
  end;
end;

procedure TSlhDsaSha2Engine.Init(const APkSeed: TCryptoLibByteArray);
var
  LN, LBl: Int32;
begin
  LN := FN;
  if LN = 16 then
    LBl := 64
  else
    LBl := 128;

  FMsgDigest.BlockUpdate(APkSeed, 0, LN);
  FMsgDigest.BlockUpdate(FZeroPad128, 0, LBl - LN);
  FMsgMemo := FMsgDigest.Clone;
  FMsgDigest.Reset;

  FSha256.BlockUpdate(APkSeed, 0, LN);
  FSha256.BlockUpdate(FZeroPad128, 0, 64 - LN);
  FSha256Memo := FSha256.Clone;
  FSha256.Reset;
end;

procedure TSlhDsaSha2Engine.F(const AAdrs: ISlhDsaAdrs; var AM1: TCryptoLibByteArray; AM1Off: Int32);
begin
  FSha256 := FSha256Memo.Clone;
  UpdateCompressedAdrs(FSha256, AAdrs);
  FSha256.BlockUpdate(AM1, AM1Off, FN);
  FSha256.DoFinal(FSha256Buf, 0);
  System.Move(FSha256Buf[0], AM1[AM1Off], FN);
end;

procedure TSlhDsaSha2Engine.H1(const AAdrs: ISlhDsaAdrs; var AM1: TCryptoLibByteArray; AM1Off: Int32;
  const AM2: TCryptoLibByteArray; AM2Off: Int32);
begin
  FMsgDigest := FMsgMemo.Clone;
  UpdateCompressedAdrs(FMsgDigest, AAdrs);
  FMsgDigest.BlockUpdate(AM1, AM1Off, FN);
  FMsgDigest.BlockUpdate(AM2, AM2Off, FN);
  FMsgDigest.DoFinal(FMsgDigestBuf, 0);
  System.Move(FMsgDigestBuf[0], AM1[AM1Off], FN);
end;

procedure TSlhDsaSha2Engine.H2(const AAdrs: ISlhDsaAdrs; const AM1: TCryptoLibByteArray; AM1Off: Int32;
  var AM2: TCryptoLibByteArray; AM2Off: Int32);
begin
  FMsgDigest := FMsgMemo.Clone;
  UpdateCompressedAdrs(FMsgDigest, AAdrs);
  FMsgDigest.BlockUpdate(AM1, AM1Off, FN);
  FMsgDigest.BlockUpdate(AM2, AM2Off, FN);
  FMsgDigest.DoFinal(FMsgDigestBuf, 0);
  System.Move(FMsgDigestBuf[0], AM2[AM2Off], FN);
end;

function TSlhDsaSha2Engine.HMsg(const APrf: TCryptoLibByteArray; APrfOff: Int32; const APkSeed, APkRoot: TCryptoLibByteArray;
  const AMsg: TCryptoLibByteArray; AMsgOff, AMsgLen: Int32): ISlhDsaIndexedDigest;
var
  LForsMsgBytes, LLeafBits, LTreeBits, LLeafBytes, LTreeBytes, LM: Int32;
  LOutput, LDig, LKey: TCryptoLibByteArray;
  LTreeIndex: UInt64;
  LLeafIndex: UInt32;
begin
  LForsMsgBytes := ((FA * FK) + 7) div 8;
  LLeafBits := FFH div FD;
  LTreeBits := FFH - LLeafBits;
  LLeafBytes := (LLeafBits + 7) div 8;
  LTreeBytes := (LTreeBits + 7) div 8;
  LM := LForsMsgBytes + LTreeBytes + LLeafBytes;
  System.SetLength(LOutput, LM);

  System.SetLength(LDig, FMsgDigest.GetDigestSize);
  FMsgDigest.Reset;
  FMsgDigest.BlockUpdate(APrf, APrfOff, FN);
  FMsgDigest.BlockUpdate(APkSeed, 0, System.Length(APkSeed));
  FMsgDigest.BlockUpdate(APkRoot, 0, System.Length(APkRoot));
  FMsgDigest.BlockUpdate(AMsg, AMsgOff, AMsgLen);
  FMsgDigest.DoFinal(LDig, 0);

  System.SetLength(LKey, FN + System.Length(APkSeed) + System.Length(LDig));
  System.Move(APrf[APrfOff], LKey[0], FN);
  System.Move(APkSeed[0], LKey[FN], System.Length(APkSeed));
  System.Move(LDig[0], LKey[FN + System.Length(APkSeed)], System.Length(LDig));

  if FN = 16 then
    Mgf1Generate(TDigestUtilities.GetDigest('SHA-256'), LKey, LOutput, 0, LM)
  else
    Mgf1Generate(TDigestUtilities.GetDigest('SHA-512'), LKey, LOutput, 0, LM);

  LTreeIndex := TPack.BE_To_UInt64_Low(LOutput, LForsMsgBytes, LTreeBytes)
    and (High(UInt64) shr (64 - LTreeBits));
  LLeafIndex := TPack.BE_To_UInt32_Low(LOutput, LForsMsgBytes + LTreeBytes, LLeafBytes)
    and (High(UInt32) shr (32 - LLeafBits));

  Result := TSlhDsaIndexedDigest.Create(LTreeIndex, LLeafIndex,
    TArrayUtilities.CopyOfRange<Byte>(LOutput, 0, LForsMsgBytes));
end;

procedure TSlhDsaSha2Engine.T_l(const AAdrs: ISlhDsaAdrs; const AM: TCryptoLibByteArray; var AOutput: TCryptoLibByteArray;
  AOutputOff: Int32);
begin
  FMsgDigest := FMsgMemo.Clone;
  UpdateCompressedAdrs(FMsgDigest, AAdrs);
  FMsgDigest.BlockUpdate(AM, 0, System.Length(AM));
  FMsgDigest.DoFinal(FMsgDigestBuf, 0);
  System.Move(FMsgDigestBuf[0], AOutput[AOutputOff], FN);
end;

procedure TSlhDsaSha2Engine.Prf(const AAdrs: ISlhDsaAdrs; const ASkSeed: TCryptoLibByteArray; var APrf: TCryptoLibByteArray;
  APrfOff: Int32);
begin
  FSha256 := FSha256Memo.Clone;
  UpdateCompressedAdrs(FSha256, AAdrs);
  FSha256.BlockUpdate(ASkSeed, 0, FN);
  FSha256.DoFinal(FSha256Buf, 0);
  System.Move(FSha256Buf[0], APrf[APrfOff], FN);
end;

procedure TSlhDsaSha2Engine.PrfMsg(const APrf, ARandomiser, AMsg: TCryptoLibByteArray; AMsgOff, AMsgLen: Int32;
  var AR: TCryptoLibByteArray; AROff: Int32);
var
  LKey: IKeyParameter;
begin
  LKey := TKeyParameter.Create(APrf);
  FTreeHMac.Init(LKey);
  FTreeHMac.BlockUpdate(ARandomiser, 0, System.Length(ARandomiser));
  FTreeHMac.BlockUpdate(AMsg, AMsgOff, AMsgLen);
  FTreeHMac.DoFinal(FHmacBuf, 0);
  System.Move(FHmacBuf[0], AR[AROff], FN);
end;

{ TSlhDsaShake256Engine }

constructor TSlhDsaShake256Engine.Create(AN, AW, AD, AA, AK, AH: Int32);
begin
  inherited Create(AN, AW, AD, AA, AK, AH);
  FTreeDigest := TDigestUtilities.GetDigest('SHAKE256-512') as IXof;
  System.SetLength(FPkSeed, AN);
end;

procedure TSlhDsaShake256Engine.Init(const APkSeed: TCryptoLibByteArray);
begin
  FTreeDigest.Reset;
  System.Move(APkSeed[0], FPkSeed[0], FN);
end;

procedure TSlhDsaShake256Engine.F(const AAdrs: ISlhDsaAdrs; var AM1: TCryptoLibByteArray; AM1Off: Int32);
var
  LValue: TCryptoLibByteArray;
begin
  LValue := AAdrs.GetValue;
  FTreeDigest.BlockUpdate(FPkSeed, 0, FN);
  FTreeDigest.BlockUpdate(LValue, 0, System.Length(LValue));
  FTreeDigest.BlockUpdate(AM1, AM1Off, FN);
  FTreeDigest.OutputFinal(AM1, AM1Off, FN);
end;

procedure TSlhDsaShake256Engine.H1(const AAdrs: ISlhDsaAdrs; var AM1: TCryptoLibByteArray; AM1Off: Int32;
  const AM2: TCryptoLibByteArray; AM2Off: Int32);
var
  LValue: TCryptoLibByteArray;
begin
  LValue := AAdrs.GetValue;
  FTreeDigest.BlockUpdate(FPkSeed, 0, FN);
  FTreeDigest.BlockUpdate(LValue, 0, System.Length(LValue));
  FTreeDigest.BlockUpdate(AM1, AM1Off, FN);
  FTreeDigest.BlockUpdate(AM2, AM2Off, FN);
  FTreeDigest.OutputFinal(AM1, AM1Off, FN);
end;

procedure TSlhDsaShake256Engine.H2(const AAdrs: ISlhDsaAdrs; const AM1: TCryptoLibByteArray; AM1Off: Int32;
  var AM2: TCryptoLibByteArray; AM2Off: Int32);
var
  LValue: TCryptoLibByteArray;
begin
  LValue := AAdrs.GetValue;
  FTreeDigest.BlockUpdate(FPkSeed, 0, FN);
  FTreeDigest.BlockUpdate(LValue, 0, System.Length(LValue));
  FTreeDigest.BlockUpdate(AM1, AM1Off, FN);
  FTreeDigest.BlockUpdate(AM2, AM2Off, FN);
  FTreeDigest.OutputFinal(AM2, AM2Off, FN);
end;

function TSlhDsaShake256Engine.HMsg(const APrf: TCryptoLibByteArray; APrfOff: Int32; const APkSeed, APkRoot: TCryptoLibByteArray;
  const AMsg: TCryptoLibByteArray; AMsgOff, AMsgLen: Int32): ISlhDsaIndexedDigest;
var
  LForsMsgBytes, LLeafBits, LTreeBits, LLeafBytes, LTreeBytes, LM: Int32;
  LOutput: TCryptoLibByteArray;
  LTreeIndex: UInt64;
  LLeafIndex: UInt32;
begin
  LForsMsgBytes := ((FA * FK) + 7) div 8;
  LLeafBits := FFH div FD;
  LTreeBits := FFH - LLeafBits;
  LLeafBytes := (LLeafBits + 7) div 8;
  LTreeBytes := (LTreeBits + 7) div 8;
  LM := LForsMsgBytes + LTreeBytes + LLeafBytes;
  System.SetLength(LOutput, LM);

  FTreeDigest.BlockUpdate(APrf, APrfOff, FN);
  FTreeDigest.BlockUpdate(APkSeed, 0, System.Length(APkSeed));
  FTreeDigest.BlockUpdate(APkRoot, 0, System.Length(APkRoot));
  FTreeDigest.BlockUpdate(AMsg, AMsgOff, AMsgLen);
  FTreeDigest.OutputFinal(LOutput, 0, System.Length(LOutput));

  LTreeIndex := TPack.BE_To_UInt64_Low(LOutput, LForsMsgBytes, LTreeBytes)
    and (High(UInt64) shr (64 - LTreeBits));
  LLeafIndex := TPack.BE_To_UInt32_Low(LOutput, LForsMsgBytes + LTreeBytes, LLeafBytes)
    and (High(UInt32) shr (32 - LLeafBits));

  Result := TSlhDsaIndexedDigest.Create(LTreeIndex, LLeafIndex,
    TArrayUtilities.CopyOfRange<Byte>(LOutput, 0, LForsMsgBytes));
end;

procedure TSlhDsaShake256Engine.T_l(const AAdrs: ISlhDsaAdrs; const AM: TCryptoLibByteArray; var AOutput: TCryptoLibByteArray;
  AOutputOff: Int32);
var
  LValue: TCryptoLibByteArray;
begin
  LValue := AAdrs.GetValue;
  FTreeDigest.BlockUpdate(FPkSeed, 0, FN);
  FTreeDigest.BlockUpdate(LValue, 0, System.Length(LValue));
  FTreeDigest.BlockUpdate(AM, 0, System.Length(AM));
  FTreeDigest.OutputFinal(AOutput, AOutputOff, FN);
end;

procedure TSlhDsaShake256Engine.Prf(const AAdrs: ISlhDsaAdrs; const ASkSeed: TCryptoLibByteArray; var APrf: TCryptoLibByteArray;
  APrfOff: Int32);
var
  LValue: TCryptoLibByteArray;
begin
  LValue := AAdrs.GetValue;
  FTreeDigest.BlockUpdate(FPkSeed, 0, FN);
  FTreeDigest.BlockUpdate(LValue, 0, System.Length(LValue));
  FTreeDigest.BlockUpdate(ASkSeed, 0, System.Length(ASkSeed));
  FTreeDigest.OutputFinal(APrf, APrfOff, FN);
end;

procedure TSlhDsaShake256Engine.PrfMsg(const APrf, ARandomiser, AMsg: TCryptoLibByteArray; AMsgOff, AMsgLen: Int32;
  var AR: TCryptoLibByteArray; AROff: Int32);
begin
  FTreeDigest.BlockUpdate(APrf, 0, System.Length(APrf));
  FTreeDigest.BlockUpdate(ARandomiser, 0, System.Length(ARandomiser));
  FTreeDigest.BlockUpdate(AMsg, AMsgOff, AMsgLen);
  FTreeDigest.OutputFinal(AR, AROff, FN);
end;

end.
