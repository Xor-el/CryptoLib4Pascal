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

unit ClpBip327MuSig2KeyAggregation;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpBigInteger,
  ClpIECCommon,
  ClpIECParameters,
  ClpIX9ECAsn1Objects,
  ClpBip327MuSig2Utilities,
  ClpBip340SchnorrUtilities,
  ClpECUtilities,
  ClpECAlgorithms,
  ClpConverters,
  ClpArrayUtilities,
  ClpCryptoLibTypes;

type
  IBip327KeyAggContext = interface(IInterface)
    ['{8B3C4D5E-6F70-41A2-B3C4-D5E6F7081920}']
    function GetQ: IECPoint;
    function GetGAcc: TBigInteger;
    function GetTAcc: TBigInteger;
    function GetDomain: IECDomainParameters;
    function GetXOnlyPubKey(): TCryptoLibByteArray;
    function GetPlainPubKey(const ADomain: IECDomainParameters): TCryptoLibByteArray;
  end;

  TBip327KeyAggContext = class sealed(TInterfacedObject, IBip327KeyAggContext)
  strict private
    var
      FQ: IECPoint;
      FGAcc: TBigInteger;
      FTAcc: TBigInteger;
      FDomain: IECDomainParameters;
  strict protected
    function GetQ: IECPoint;
    function GetGAcc: TBigInteger;
    function GetTAcc: TBigInteger;
    function GetDomain: IECDomainParameters;
    function GetXOnlyPubKey(): TCryptoLibByteArray;
    function GetPlainPubKey(const ADomain: IECDomainParameters): TCryptoLibByteArray;
  public
    constructor Create(const AQ: IECPoint; const AGAcc, ATAcc: TBigInteger;
      const ADomain: IECDomainParameters);
  end;

  TBip327MuSig2KeyAggregation = class sealed(TObject)
  public
    /// <summary>Sort pubkeys lexicographically (33 bytes each). Returns new sorted array.</summary>
    class function KeySort(const APubKeys: TCryptoLibGenericArray<TCryptoLibByteArray>):
      TCryptoLibGenericArray<TCryptoLibByteArray>; static;
    /// <summary>KeyAgg with MuSig2* (second distinct key gets coefficient 1).</summary>
    class function KeyAgg(const ADomain: IECDomainParameters;
      const APubKeys: TCryptoLibGenericArray<TCryptoLibByteArray>): IBip327KeyAggContext; static;
    /// <summary>Apply tweak. is_xonly_t: true for BIP341 Taproot, false for BIP32 plain.</summary>
    class function ApplyTweak(const AKeyAggCtx: IBip327KeyAggContext;
      const ATweak: TCryptoLibByteArray; AIsXOnlyT: Boolean): IBip327KeyAggContext; static;
    /// <summary>Key aggregation coefficient for a given pk in the pubkey list (for session/signing).</summary>
    class function KeyAggCoeff(const APubKeys: TCryptoLibGenericArray<TCryptoLibByteArray>;
      const APk: TCryptoLibByteArray): TBigInteger; static;
  private
    class function HashKeys(const APubKeys: TCryptoLibGenericArray<TCryptoLibByteArray>): TCryptoLibByteArray; static;
    class function GetSecondKey(const APubKeys: TCryptoLibGenericArray<TCryptoLibByteArray>): TCryptoLibByteArray; static;
    class function KeyAggCoeffInternal(const APubKeys: TCryptoLibGenericArray<TCryptoLibByteArray>;
      const APk, APk2: TCryptoLibByteArray; const AN: TBigInteger): TBigInteger; static;
  end;

implementation

{ TBip327KeyAggContext }

constructor TBip327KeyAggContext.Create(const AQ: IECPoint; const AGAcc, ATAcc: TBigInteger;
  const ADomain: IECDomainParameters);
begin
  Inherited Create();
  FQ := AQ;
  FGAcc := AGAcc;
  FTAcc := ATAcc;
  FDomain := ADomain;
end;

function TBip327KeyAggContext.GetQ: IECPoint;
begin
  Result := FQ;
end;

function TBip327KeyAggContext.GetGAcc: TBigInteger;
begin
  Result := FGAcc;
end;

function TBip327KeyAggContext.GetTAcc: TBigInteger;
begin
  Result := FTAcc;
end;

function TBip327KeyAggContext.GetDomain: IECDomainParameters;
begin
  Result := FDomain;
end;

function TBip327KeyAggContext.GetXOnlyPubKey(): TCryptoLibByteArray;
begin
  Result := TBip340SchnorrUtilities.BytesFromPoint(FQ);
end;

function TBip327KeyAggContext.GetPlainPubKey(const ADomain: IECDomainParameters): TCryptoLibByteArray;
begin
  Result := TBip327MuSig2Utilities.CBytes(ADomain, FQ);
end;

{ TBip327MuSig2KeyAggregation }

function LexCompareBytes(const A, B: TCryptoLibByteArray): Int32;
var
  LLen, LI: Int32;
begin
  LLen := System.Length(A);
  if LLen > System.Length(B) then
    LLen := System.Length(B);
  for LI := 0 to LLen - 1 do
  begin
    if A[LI] < B[LI] then
      Exit(-1);
    if A[LI] > B[LI] then
      Exit(1);
  end;
  if System.Length(A) < System.Length(B) then
    Exit(-1);
  if System.Length(A) > System.Length(B) then
    Exit(1);
  Result := 0;
end;

class function TBip327MuSig2KeyAggregation.KeySort(
  const APubKeys: TCryptoLibGenericArray<TCryptoLibByteArray>):
  TCryptoLibGenericArray<TCryptoLibByteArray>;
var
  LResult: TCryptoLibGenericArray<TCryptoLibByteArray>;
  LLen, LI, LJ: Int32;
  LKey: TCryptoLibByteArray;
  LMin: Int32;
begin
  if System.Length(APubKeys) = 0 then
  begin
    Result := nil;
    Exit;
  end;
  LLen := System.Length(APubKeys);
  System.SetLength(LResult, LLen);
  for LI := 0 to LLen - 1 do
  begin
    if (APubKeys[LI] = nil) or (System.Length(APubKeys[LI]) <> TBip327MuSig2Utilities.BIP327_PLAIN_PUBKEY_SIZE) then
      raise EArgumentCryptoLibException.Create('KeySort: each key must be 33 bytes');
    System.SetLength(LResult[LI], System.Length(APubKeys[LI]));
    System.Move(APubKeys[LI][0], LResult[LI][0], System.Length(APubKeys[LI]) * System.SizeOf(Byte));
  end;
  for LI := 0 to LLen - 2 do
  begin
    LMin := LI;
    for LJ := LI + 1 to LLen - 1 do
      if LexCompareBytes(LResult[LJ], LResult[LMin]) < 0 then
        LMin := LJ;
    if LMin <> LI then
    begin
      LKey := LResult[LI];
      LResult[LI] := LResult[LMin];
      LResult[LMin] := LKey;
    end;
  end;
  Result := LResult;
end;

class function TBip327MuSig2KeyAggregation.KeyAgg(const ADomain: IECDomainParameters;
  const APubKeys: TCryptoLibGenericArray<TCryptoLibByteArray>): IBip327KeyAggContext;
var
  LCurve: IECCurve;
  LN: TBigInteger;
  LPk2: TCryptoLibByteArray;
  LU, LI: Int32;
  LP: IECPoint;
  LA: TBigInteger;
  LSum: IECPoint;
begin
  if System.Length(APubKeys) = 0 then
    raise EArgumentCryptoLibException.Create('KeyAgg: at least one pubkey required');
  LCurve := ADomain.Curve;
  LN := ADomain.N;
  LU := System.Length(APubKeys);
  LPk2 := GetSecondKey(APubKeys);
  LSum := LCurve.Infinity;
  for LI := 0 to LU - 1 do
  begin
    LP := TBip327MuSig2Utilities.CPoint(ADomain, APubKeys[LI], LI);
    LA := KeyAggCoeffInternal(APubKeys, APubKeys[LI], LPk2, LN);
    if LSum.IsInfinity then
      LSum := TECAlgorithms.ReferenceMultiply(LP, LA)
    else
      LSum := LSum.Add(TECAlgorithms.ReferenceMultiply(LP, LA));
  end;
  if (LSum = nil) or (LSum.IsInfinity) then
    raise EArgumentCryptoLibException.Create('KeyAgg: Q is infinity');
  Result := TBip327KeyAggContext.Create(LSum, TBigInteger.One, TBigInteger.Zero, ADomain);
end;

class function TBip327MuSig2KeyAggregation.ApplyTweak(const AKeyAggCtx: IBip327KeyAggContext;
  const ATweak: TCryptoLibByteArray; AIsXOnlyT: Boolean): IBip327KeyAggContext;
var
  LQ: IECPoint;
  LGAcc, LTAcc, LN: TBigInteger;
  LG, LT: TBigInteger;
  LQPrime: IECPoint;
  LDomain: IECDomainParameters;
begin
  if (AKeyAggCtx = nil) then
    raise EArgumentCryptoLibException.Create('ApplyTweak: invalid context');
  if (ATweak = nil) or (System.Length(ATweak) <> 32) then
    raise EArgumentCryptoLibException.Create('ApplyTweak: tweak must be 32 bytes');
  LDomain := AKeyAggCtx.GetDomain();
  LN := LDomain.N;
  LQ := AKeyAggCtx.GetQ();
  LGAcc := AKeyAggCtx.GetGAcc();
  LTAcc := AKeyAggCtx.GetTAcc();
  LT := TBigInteger.Create(1, ATweak);
  if LT.CompareTo(LN) >= 0 then
    raise EArgumentCryptoLibException.Create('ApplyTweak: tweak >= n');
  if AIsXOnlyT and (not TBip340SchnorrUtilities.HasEvenY(LQ)) then
    LG := LN.Subtract(TBigInteger.One)
  else
    LG := TBigInteger.One;
  LQPrime := LQ.Multiply(LG).Add(TECAlgorithms.ReferenceMultiply(LDomain.G, LT));
  if (LQPrime = nil) or (LQPrime.IsInfinity) then
    raise EArgumentCryptoLibException.Create('ApplyTweak: result is infinity');
  LGAcc := LG.Multiply(LGAcc).&Mod(LN);
  LTAcc := LT.Add(LG.Multiply(LTAcc)).&Mod(LN);
  Result := TBip327KeyAggContext.Create(LQPrime, LGAcc, LTAcc, LDomain);
end;

class function TBip327MuSig2KeyAggregation.KeyAggCoeff(
  const APubKeys: TCryptoLibGenericArray<TCryptoLibByteArray>;
  const APk: TCryptoLibByteArray): TBigInteger;
var
  LX9: IX9ECParameters;
  LPk2: TCryptoLibByteArray;
  LN: TBigInteger;
begin
  if System.Length(APubKeys) = 0 then
    raise EArgumentCryptoLibException.Create('KeyAggCoeff: pubkeys required');
  LX9 := TECUtilities.FindECCurveByName('secp256k1');
  if LX9 = nil then
    raise EInvalidOperationCryptoLibException.Create('secp256k1 curve not found');
  LN := LX9.N;
  LPk2 := GetSecondKey(APubKeys);
  Result := KeyAggCoeffInternal(APubKeys, APk, LPk2, LN);
end;

class function TBip327MuSig2KeyAggregation.HashKeys(const APubKeys: TCryptoLibGenericArray<TCryptoLibByteArray>): TCryptoLibByteArray;
var
  LTotalLen, LOff, LI: Int32;
  LTagBytes: TCryptoLibByteArray;
begin
  LTotalLen := 0;
  for LI := 0 to System.Length(APubKeys) - 1 do
    LTotalLen := LTotalLen + System.Length(APubKeys[LI]);
  System.SetLength(Result, LTotalLen);
  LOff := 0;
  for LI := 0 to System.Length(APubKeys) - 1 do
  begin
    System.Move(APubKeys[LI][0], Result[LOff], System.Length(APubKeys[LI]) * System.SizeOf(Byte));
    LOff := LOff + System.Length(APubKeys[LI]);
  end;
  LTagBytes := TConverters.ConvertStringToBytes(
    TBip327MuSig2Utilities.KEYAGG_LIST_TAG_STR, TEncoding.UTF8);
  Result := TBip340SchnorrUtilities.TaggedHash(LTagBytes, Result);
end;

class function TBip327MuSig2KeyAggregation.GetSecondKey(const APubKeys: TCryptoLibGenericArray<TCryptoLibByteArray>): TCryptoLibByteArray;
var
  LJ, LU: Int32;
begin
  LU := System.Length(APubKeys);
  for LJ := 1 to LU - 1 do
    if not TArrayUtilities.FixedTimeEquals(APubKeys[LJ], APubKeys[0]) then
    begin
      Result := System.Copy(APubKeys[LJ]);
      Exit;
    end;
  System.SetLength(Result, TBip327MuSig2Utilities.BIP327_PLAIN_PUBKEY_SIZE);
  TArrayUtilities.Fill<Byte>(Result, 0, System.Length(Result), Byte(0));
end;

class function TBip327MuSig2KeyAggregation.KeyAggCoeffInternal(const APubKeys: TCryptoLibGenericArray<TCryptoLibByteArray>;
  const APk, APk2: TCryptoLibByteArray; const AN: TBigInteger): TBigInteger;
var
  LL: TCryptoLibByteArray;
  LTagBytes: TCryptoLibByteArray;
  LHashInput: TCryptoLibByteArray;
begin
  if TArrayUtilities.FixedTimeEquals(APk, APk2) then
  begin
    Result := TBigInteger.One;
    Exit;
  end;
  LL := HashKeys(APubKeys);
  LTagBytes := TConverters.ConvertStringToBytes(
    TBip327MuSig2Utilities.KEYAGG_COEFFICIENT_TAG_STR, TEncoding.UTF8);
  System.SetLength(LHashInput, System.Length(LL) + System.Length(APk));
  System.Move(LL[0], LHashInput[0], System.Length(LL) * System.SizeOf(Byte));
  System.Move(APk[0], LHashInput[System.Length(LL)], System.Length(APk) * System.SizeOf(Byte));
  Result := TBigInteger.Create(1, TBip340SchnorrUtilities.TaggedHash(LTagBytes, LHashInput)).&Mod(AN);
end;

end.
