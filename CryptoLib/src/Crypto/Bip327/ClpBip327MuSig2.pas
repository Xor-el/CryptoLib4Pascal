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

unit ClpBip327MuSig2;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpBigInteger,
  ClpIECCommon,
  ClpIECParameters,
  ClpISecureRandom,
  ClpBip327MuSig2Utilities,
  ClpBip327MuSig2KeyAggregation,
  ClpBip340SchnorrUtilities,
  ClpPack,
  ClpECAlgorithms,
  ClpECParameters,
  ClpConverters,
  ClpArrayUtilities,
  ClpByteUtilities,
  ClpBigIntegerUtilities,
  ClpCryptoLibTypes;

type
  TBip327SessionContext = record
    AggNonce: TCryptoLibByteArray;   // 66 bytes
    PubKeys: TCryptoLibGenericArray<TCryptoLibByteArray>;
    Tweaks: TCryptoLibGenericArray<TCryptoLibByteArray>;
    IsXOnlyT: TCryptoLibBooleanArray;
    Msg: TCryptoLibByteArray;
  end;

  TBip327SessionValues = record
    Q: IECPoint;
    GAcc: TBigInteger;
    TAcc: TBigInteger;
    B: TBigInteger;
    R: IECPoint;
    E: TBigInteger;
  end;

  TBip327MuSig2 = class sealed(TObject)
  private
    class function KeyAggAndTweak(const ADomain: IECDomainParameters;
      const APubKeys: TCryptoLibGenericArray<TCryptoLibByteArray>;
      const ATweaks: TCryptoLibGenericArray<TCryptoLibByteArray>;
      const AIsXOnlyT: TCryptoLibBooleanArray): IBip327KeyAggContext; static;
    class function GetSessionValues(const ADomain: IECDomainParameters;
      const ASessionCtx: TBip327SessionContext; out AValues: TBip327SessionValues): Boolean; static;
    class function NonceHash(const ARand: TCryptoLibByteArray; const APk: TCryptoLibByteArray;
      const AAggPk: TCryptoLibByteArray; const AMsgPrefixed: TCryptoLibByteArray;
      const AExtraIn: TCryptoLibByteArray; const ATagBytes: TCryptoLibByteArray;
      const AN: TBigInteger; AIndex: Int32): TBigInteger; static;
    class function DetNonceHash(const ADomain: IECDomainParameters;
      const ASkPrime, AAggOtherNonce, AAggPk, AMsg: TCryptoLibByteArray;
      AIndex: Int32): TBigInteger; static;
    class function PartialSigVerifyInternal(const ADomain: IECDomainParameters;
      const APsig: TCryptoLibByteArray; const APubnonce: TCryptoLibByteArray;
      const APubKey: TCryptoLibByteArray; const ASessionCtx: TBip327SessionContext;
      const AValues: TBip327SessionValues): Boolean; static;
  public
    class function NonceGen(const ADomain: IECDomainParameters;
      const ASk: TCryptoLibByteArray; const APk: TCryptoLibByteArray;
      const AAggPk: TCryptoLibByteArray; const AMsg: TCryptoLibByteArray;
      AMsgProvided: Boolean; const AExtraIn: TCryptoLibByteArray; const ARandom: ISecureRandom;
      out ASecNonce: TCryptoLibByteArray; out APubNonce: TCryptoLibByteArray): Boolean; static;
    class function NonceAgg(const ADomain: IECDomainParameters;
      const APubNonces: TCryptoLibGenericArray<TCryptoLibByteArray>): TCryptoLibByteArray; static;
    class function GetSessionKeyAggCoeff(const ASessionCtx: TBip327SessionContext;
      const ADomain: IECDomainParameters; const AP: IECPoint): TBigInteger; static;
    class function Sign(const ADomain: IECDomainParameters;
      var ASecNonce: TCryptoLibByteArray; const ASk: TCryptoLibByteArray;
      const ASessionCtx: TBip327SessionContext; out APSig: TCryptoLibByteArray): Boolean; static;
    class function PartialSigVerify(const ADomain: IECDomainParameters;
      const APSig: TCryptoLibByteArray;
      const APubNonces: TCryptoLibGenericArray<TCryptoLibByteArray>;
      const APubKeys: TCryptoLibGenericArray<TCryptoLibByteArray>;
      const ATweaks: TCryptoLibGenericArray<TCryptoLibByteArray>;
      const AIsXOnlyT: TCryptoLibBooleanArray; const AMsg: TCryptoLibByteArray;
      ASignerIndex: Int32): Boolean; static;
    class function PartialSigAgg(const ADomain: IECDomainParameters;
      const APsigs: TCryptoLibGenericArray<TCryptoLibByteArray>;
      const ASessionCtx: TBip327SessionContext): TCryptoLibByteArray; static;
    class function DeterministicSign(const ADomain: IECDomainParameters;
      const ASk: TCryptoLibByteArray; const AAggOtherNonce: TCryptoLibByteArray;
      const APubKeys: TCryptoLibGenericArray<TCryptoLibByteArray>;
      const ATweaks: TCryptoLibGenericArray<TCryptoLibByteArray>;
      const AIsXOnlyT: TCryptoLibBooleanArray; const AMsg: TCryptoLibByteArray;
      const ARand: TCryptoLibByteArray; out APubNonce: TCryptoLibByteArray;
      out APSig: TCryptoLibByteArray): Boolean; static;
  end;

implementation

{ TBip327MuSig2 }

class function TBip327MuSig2.NonceGen(const ADomain: IECDomainParameters;
  const ASk: TCryptoLibByteArray; const APk: TCryptoLibByteArray;
  const AAggPk: TCryptoLibByteArray; const AMsg: TCryptoLibByteArray;
  AMsgProvided: Boolean; const AExtraIn: TCryptoLibByteArray; const ARandom: ISecureRandom;
  out ASecNonce: TCryptoLibByteArray; out APubNonce: TCryptoLibByteArray): Boolean;
var
  LN: TBigInteger;
  LRandPrime, LRand, LAuxHash: TCryptoLibByteArray;
  LMsgPrefixed: TCryptoLibByteArray;
  LTagBytes: TCryptoLibByteArray;
  LK1, LK2: TBigInteger;
  LR1, LR2: IECPoint;
  LLenMsg: Int32;
begin
  Result := False;
  if (APk = nil) or (System.Length(APk) <> TBip327MuSig2Utilities.BIP327_PLAIN_PUBKEY_SIZE) then
    Exit;
  if (ASk <> nil) and (System.Length(ASk) <> 32) then
    Exit;
  if (AAggPk <> nil) and (System.Length(AAggPk) <> 32) then
    Exit;

  LN := ADomain.N;

  if ARandom = nil then
    raise EArgumentCryptoLibException.Create('NonceGen requires a secure random generator (BIP-327)');

  System.SetLength(LRandPrime, 32);
  ARandom.NextBytes(LRandPrime);
  if (ASk <> nil) and (System.Length(ASk) = 32) then
  begin
    LTagBytes := TConverters.ConvertStringToBytes(
      TBip327MuSig2Utilities.MUSIG_AUX_TAG_STR, TEncoding.UTF8);
    LAuxHash := TBip340SchnorrUtilities.TaggedHash(LTagBytes, LRandPrime);
    System.SetLength(LRand, 32);
    TByteUtilities.&Xor(32, ASk, 0, LAuxHash, 0, LRand, 0);
  end
  else
    LRand := LRandPrime;
  if not AMsgProvided then
    LMsgPrefixed := TCryptoLibByteArray.Create(0)
  else
  begin
    LLenMsg := System.Length(AMsg);
    System.SetLength(LMsgPrefixed, 1 + 8 + LLenMsg);
    LMsgPrefixed[0] := 1;
    TPack.UInt64_To_BE(UInt64(LLenMsg), LMsgPrefixed, 1);
    if LLenMsg > 0 then
      System.Move(AMsg[0], LMsgPrefixed[9], LLenMsg);
  end;
  LTagBytes := TConverters.ConvertStringToBytes(
    TBip327MuSig2Utilities.MUSIG_NONCE_TAG_STR, TEncoding.UTF8);

  LK1 := NonceHash(LRand, APk, AAggPk, LMsgPrefixed, AExtraIn, LTagBytes, LN, 0);
  LK2 := NonceHash(LRand, APk, AAggPk, LMsgPrefixed, AExtraIn, LTagBytes, LN, 1);

  if (LK1.SignValue = 0) or (LK2.SignValue = 0) then
    Exit;
  LR1 := TECAlgorithms.ReferenceMultiply(ADomain.G, LK1).Normalize();
  LR2 := TECAlgorithms.ReferenceMultiply(ADomain.G, LK2).Normalize();
  APubNonce := TBip327MuSig2Utilities.CBytes(ADomain, LR1);
  System.SetLength(APubNonce, TBip327MuSig2Utilities.BIP327_PUBNONCE_SIZE);
  System.Move(TBip327MuSig2Utilities.CBytes(ADomain, LR2)[0], APubNonce[33], 33);
  System.SetLength(ASecNonce, TBip327MuSig2Utilities.BIP327_SECNONCE_SIZE);
  TBigIntegerUtilities.AsUnsignedByteArray(LK1, ASecNonce, 0, 32);
  TBigIntegerUtilities.AsUnsignedByteArray(LK2, ASecNonce, 32, 32);
  System.Move(APk[0], ASecNonce[64], System.Length(APk));
  Result := True;
end;

class function TBip327MuSig2.NonceHash(const ARand: TCryptoLibByteArray; const APk: TCryptoLibByteArray;
  const AAggPk: TCryptoLibByteArray; const AMsgPrefixed: TCryptoLibByteArray;
  const AExtraIn: TCryptoLibByteArray; const ATagBytes: TCryptoLibByteArray;
  const AN: TBigInteger; AIndex: Int32): TBigInteger;
var
  LHashInput: TCryptoLibByteArray;
  LOff: Int32;
  LAggPkLen, LExtraInLen: Int32;
begin
  LAggPkLen := System.Length(AAggPk);
  LExtraInLen := System.Length(AExtraIn);
  LOff := 0;
  System.SetLength(LHashInput,
    32 + 1 + System.Length(APk) + 1 + LAggPkLen +
    System.Length(AMsgPrefixed) + 4 + LExtraInLen + 1);
  System.Move(ARand[0], LHashInput[LOff], 32); Inc(LOff, 32);
  LHashInput[LOff] := Byte(System.Length(APk)); Inc(LOff, 1);
  System.Move(APk[0], LHashInput[LOff], System.Length(APk)); Inc(LOff, System.Length(APk));
  if System.Length(AAggPk) = 0 then
  begin
    LHashInput[LOff] := 0;
    Inc(LOff, 1);
  end
  else
  begin
    LHashInput[LOff] := 32; Inc(LOff, 1);
    System.Move(AAggPk[0], LHashInput[LOff], 32); Inc(LOff, 32);
  end;
  if LOff + 1 + System.Length(AMsgPrefixed) + 4 + LExtraInLen + 1 > System.Length(LHashInput) then
    System.SetLength(LHashInput, LOff + 1 + System.Length(AMsgPrefixed) + 4 + LExtraInLen + 1);
  System.Move(AMsgPrefixed[0], LHashInput[LOff], System.Length(AMsgPrefixed)); Inc(LOff, System.Length(AMsgPrefixed));
  TPack.UInt32_To_BE(UInt32(System.Length(AExtraIn)), LHashInput, LOff); Inc(LOff, 4);
  if (AExtraIn <> nil) and (System.Length(AExtraIn) > 0) then
  begin
    System.Move(AExtraIn[0], LHashInput[LOff], System.Length(AExtraIn)); Inc(LOff, System.Length(AExtraIn));
  end;
  LHashInput[LOff] := Byte(AIndex);
  System.SetLength(LHashInput, LOff + 1);
  Result := TBigInteger.Create(1, TBip340SchnorrUtilities.TaggedHash(ATagBytes, LHashInput)).&Mod(AN);
end;

class function TBip327MuSig2.NonceAgg(const ADomain: IECDomainParameters;
  const APubNonces: TCryptoLibGenericArray<TCryptoLibByteArray>): TCryptoLibByteArray;
var
  LU, LI, LJ: Int32;
  LR1, LR2, LRJ: IECPoint;
  LCurve: IECCurve;
  LPt: IECPoint;
begin
  if (APubNonces = nil) or (System.Length(APubNonces) = 0) then
    raise EArgumentCryptoLibException.Create('NonceAgg: at least one pubnonce required');
  LU := System.Length(APubNonces);
  LCurve := ADomain.Curve;
  for LJ := 0 to 1 do
  begin
    LRJ := LCurve.Infinity;
    for LI := 0 to LU - 1 do
    begin
      if (APubNonces[LI] = nil) or (System.Length(APubNonces[LI]) <> TBip327MuSig2Utilities.BIP327_PUBNONCE_SIZE) then
        raise EBip327InvalidContributionException.Create('Invalid pubnonce length', LI, 'pubnonce');
      try
        if LJ = 0 then
          LPt := TBip327MuSig2Utilities.CPoint(ADomain, System.Copy(APubNonces[LI], 0, 33), LI)
        else
          LPt := TBip327MuSig2Utilities.CPoint(ADomain, System.Copy(APubNonces[LI], 33, 33), LI);
      except
        on E: EBip327InvalidContributionException do
          raise EBip327InvalidContributionException.Create(E.Message, E.SignerIndex, 'pubnonce');
      end;
      LRJ := LRJ.Add(LPt);
    end;
    if LJ = 0 then
      LR1 := LRJ
    else
      LR2 := LRJ;
  end;
  Result := TBip327MuSig2Utilities.CBytesExt(ADomain, LR1);
  System.SetLength(Result, TBip327MuSig2Utilities.BIP327_PUBNONCE_SIZE);
  System.Move(TBip327MuSig2Utilities.CBytesExt(ADomain, LR2)[0], Result[33], 33);
end;

class function TBip327MuSig2.GetSessionValues(const ADomain: IECDomainParameters;
  const ASessionCtx: TBip327SessionContext; out AValues: TBip327SessionValues): Boolean;
var
  LCtx: IBip327KeyAggContext;
  LN: TBigInteger;
  LTagBytes: TCryptoLibByteArray;
  LHashInput: TCryptoLibByteArray;
  LB: TBigInteger;
  LR1, LR2, LRPrime, LR: IECPoint;
  LCurve: IECCurve;
  LE: TBigInteger;
  LOff: Int32;
begin
  Result := False;
  if (ASessionCtx.AggNonce = nil) or (System.Length(ASessionCtx.AggNonce) <> 66) then
    Exit;
  try
    LCtx := KeyAggAndTweak(ADomain, ASessionCtx.PubKeys, ASessionCtx.Tweaks, ASessionCtx.IsXOnlyT);
  except
    on E: EArgumentCryptoLibException do
      raise;
    on E: EBip327InvalidContributionException do
      raise;
    else
      Exit;
  end;
  LN := ADomain.N;
  LCurve := ADomain.Curve;
  System.SetLength(LHashInput, 66 + 32 + System.Length(ASessionCtx.Msg));
  System.Move(ASessionCtx.AggNonce[0], LHashInput[0], 66);
  System.Move(LCtx.GetXOnlyPubKey()[0], LHashInput[66], 32);
  if (ASessionCtx.Msg <> nil) and (System.Length(ASessionCtx.Msg) > 0) then
    System.Move(ASessionCtx.Msg[0], LHashInput[98], System.Length(ASessionCtx.Msg));
  LOff := 66 + 32;
  System.SetLength(LHashInput, LOff + System.Length(ASessionCtx.Msg));
  LTagBytes := TConverters.ConvertStringToBytes(
    TBip327MuSig2Utilities.MUSIG_NONCECOEFF_TAG_STR, TEncoding.UTF8);
  LB := TBigInteger.Create(1, TBip340SchnorrUtilities.TaggedHash(LTagBytes, LHashInput)).&Mod(LN);
  LR1 := TBip327MuSig2Utilities.CPointExt(ADomain, System.Copy(ASessionCtx.AggNonce, 0, 33));
  LR2 := TBip327MuSig2Utilities.CPointExt(ADomain, System.Copy(ASessionCtx.AggNonce, 33, 33));
  LRPrime := LR1.Add(LR2.Multiply(LB));
  if (LRPrime = nil) or (LRPrime.IsInfinity) then
    LR := TECAlgorithms.ReferenceMultiply(ADomain.G, TBigInteger.One)
  else
    LR := LRPrime;
  System.SetLength(LHashInput, 32 + 32 + System.Length(ASessionCtx.Msg));
  System.Move(TBip340SchnorrUtilities.BytesFromPoint(LR)[0], LHashInput[0], 32);
  System.Move(LCtx.GetXOnlyPubKey()[0], LHashInput[32], 32);
  if (ASessionCtx.Msg <> nil) and (System.Length(ASessionCtx.Msg) > 0) then
    System.Move(ASessionCtx.Msg[0], LHashInput[64], System.Length(ASessionCtx.Msg));
  LTagBytes := TConverters.ConvertStringToBytes(
    TBip340SchnorrUtilities.BIP0340_CHALLENGE_TAG_STR, TEncoding.UTF8);
  LE := TBigInteger.Create(1, TBip340SchnorrUtilities.TaggedHash(LTagBytes, LHashInput)).&Mod(LN);
  AValues.Q := LCtx.GetQ();
  AValues.GAcc := LCtx.GetGAcc();
  AValues.TAcc := LCtx.GetTAcc();
  AValues.B := LB;
  AValues.R := LR;
  AValues.E := LE;
  Result := True;
end;

class function TBip327MuSig2.GetSessionKeyAggCoeff(const ASessionCtx: TBip327SessionContext;
  const ADomain: IECDomainParameters; const AP: IECPoint): TBigInteger;
var
  LPk: TCryptoLibByteArray;
  LI: Int32;
begin
  LPk := TBip327MuSig2Utilities.CBytes(ADomain, AP);
  for LI := 0 to System.Length(ASessionCtx.PubKeys) - 1 do
    if TArrayUtilities.FixedTimeEquals(ASessionCtx.PubKeys[LI], LPk) then
    begin
      Result := TBip327MuSig2KeyAggregation.KeyAggCoeff(ASessionCtx.PubKeys, LPk);
      Exit;
    end;
  raise EArgumentCryptoLibException.Create('GetSessionKeyAggCoeff: P not in pubkeys');
end;

class function TBip327MuSig2.PartialSigVerifyInternal(const ADomain: IECDomainParameters;
  const APsig: TCryptoLibByteArray; const APubnonce: TCryptoLibByteArray;
  const APubKey: TCryptoLibByteArray; const ASessionCtx: TBip327SessionContext;
  const AValues: TBip327SessionValues): Boolean;
var
  LN: TBigInteger;
  LS: TBigInteger;
  LP: IECPoint;
  LReS1, LReS2, LRePrime, LRe, LRight: IECPoint;
  LA, LGP: TBigInteger;
begin
  Result := False;
  if (APsig = nil) or (System.Length(APsig) <> TBip327MuSig2Utilities.BIP327_PSIG_SIZE) then
    Exit;
  if (APubnonce = nil) or (System.Length(APubnonce) <> TBip327MuSig2Utilities.BIP327_PUBNONCE_SIZE) then
    Exit;
  if (APubKey = nil) or (System.Length(APubKey) <> TBip327MuSig2Utilities.BIP327_PLAIN_PUBKEY_SIZE) then
    Exit;
  LN := ADomain.N;
  LS := TBigInteger.Create(1, APsig);
  if LS.CompareTo(LN) >= 0 then
    Exit;
  LP := TBip327MuSig2Utilities.CPoint(ADomain, APubKey);
  LReS1 := TBip327MuSig2Utilities.CPoint(ADomain, System.Copy(APubnonce, 0, 33));
  LReS2 := TBip327MuSig2Utilities.CPoint(ADomain, System.Copy(APubnonce, 33, 33));
  LRePrime := LReS1.Add(LReS2.Multiply(AValues.B));
  if TBip340SchnorrUtilities.HasEvenY(AValues.R) then
    LRe := LRePrime
  else
    LRe := LRePrime.Negate();
  LA := GetSessionKeyAggCoeff(ASessionCtx, ADomain, LP);
  if TBip340SchnorrUtilities.HasEvenY(AValues.Q) then
    LGP := AValues.GAcc
  else
    LGP := LN.Subtract(TBigInteger.One).Multiply(AValues.GAcc).&Mod(LN);
  LRight := LRe.Add(LP.Multiply(AValues.E.Multiply(LA).Multiply(LGP).&Mod(LN)));
  Result := TECAlgorithms.ReferenceMultiply(ADomain.G, LS).Equals(LRight);
end;

class function TBip327MuSig2.Sign(const ADomain: IECDomainParameters;
  var ASecNonce: TCryptoLibByteArray; const ASk: TCryptoLibByteArray;
  const ASessionCtx: TBip327SessionContext; out APSig: TCryptoLibByteArray): Boolean;
var
  LValues: TBip327SessionValues;
  LK1Orig, LK2Orig, LK1, LK2, LD, LA, LG, LEffectiveD, LS: TBigInteger;
  LP: IECPoint;
  LPk: TCryptoLibByteArray;
  LN: TBigInteger;
  LPubnonce: TCryptoLibByteArray;
  LR1, LR2: IECPoint;
begin
  Result := False;
  if (ASecNonce = nil) or (System.Length(ASecNonce) <> TBip327MuSig2Utilities.BIP327_SECNONCE_SIZE) then
    Exit;
  if (ASk = nil) or (System.Length(ASk) <> 32) then
    Exit;
  if not GetSessionValues(ADomain, ASessionCtx, LValues) then
    Exit;
  LN := ADomain.N;
  LK1Orig := TBigInteger.Create(1, System.Copy(ASecNonce, 0, 32));
  LK2Orig := TBigInteger.Create(1, System.Copy(ASecNonce, 32, 32));
  LK1 := LK1Orig;
  LK2 := LK2Orig;
  TArrayUtilities.Fill<Byte>(ASecNonce, 0, 64, Byte(0));
  if (LK1.SignValue <= 0) or (LK1.CompareTo(LN) >= 0) then
    Exit;
  if (LK2.SignValue <= 0) or (LK2.CompareTo(LN) >= 0) then
    Exit;
  if not TBip340SchnorrUtilities.HasEvenY(LValues.R) then
  begin
    LK1 := LN.Subtract(LK1);
    LK2 := LN.Subtract(LK2);
  end;
  LD := TBigInteger.Create(1, ASk);
  if (LD.SignValue <= 0) or (LD.CompareTo(LN) >= 0) then
    Exit;
  LP := TECAlgorithms.ReferenceMultiply(ADomain.G, LD).Normalize();
  LPk := TBip327MuSig2Utilities.CBytes(ADomain, LP);
  if not TArrayUtilities.FixedTimeEquals(System.Copy(ASecNonce, 64, 33), LPk) then
    Exit;
  LA := GetSessionKeyAggCoeff(ASessionCtx, ADomain, LP);
  if TBip340SchnorrUtilities.HasEvenY(LValues.Q) then
    LG := TBigInteger.One
  else
    LG := LN.Subtract(TBigInteger.One);
  LEffectiveD := LG.Multiply(LValues.GAcc).Multiply(LD).&Mod(LN);
  LS := LK1.Add(LValues.B.Multiply(LK2)).Add(LValues.E.Multiply(LA).Multiply(LEffectiveD)).&Mod(LN);
  System.SetLength(APSig, TBip327MuSig2Utilities.BIP327_PSIG_SIZE);
  TBigIntegerUtilities.AsUnsignedByteArray(LS, APSig, 0, 32);
  // Optional correctness check (BIP-327): internal partial sig verify before returning.
  LR1 := TECAlgorithms.ReferenceMultiply(ADomain.G, LK1Orig).Normalize();
  LR2 := TECAlgorithms.ReferenceMultiply(ADomain.G, LK2Orig).Normalize();
  System.SetLength(LPubnonce, TBip327MuSig2Utilities.BIP327_PUBNONCE_SIZE);
  System.Move(TBip327MuSig2Utilities.CBytes(ADomain, LR1)[0], LPubnonce[0], 33);
  System.Move(TBip327MuSig2Utilities.CBytes(ADomain, LR2)[0], LPubnonce[33], 33);
  if not PartialSigVerifyInternal(ADomain, APSig, LPubnonce, LPk, ASessionCtx, LValues) then
    Exit;
  Result := True;
end;

class function TBip327MuSig2.PartialSigVerify(const ADomain: IECDomainParameters;
  const APSig: TCryptoLibByteArray;
  const APubNonces: TCryptoLibGenericArray<TCryptoLibByteArray>;
  const APubKeys: TCryptoLibGenericArray<TCryptoLibByteArray>;
  const ATweaks: TCryptoLibGenericArray<TCryptoLibByteArray>;
  const AIsXOnlyT: TCryptoLibBooleanArray; const AMsg: TCryptoLibByteArray;
  ASignerIndex: Int32): Boolean;
var
  LAggNonce: TCryptoLibByteArray;
  LSessionCtx: TBip327SessionContext;
  LValues: TBip327SessionValues;
  LS: TBigInteger;
  LReS1, LReS2, LRePrime, LRe: IECPoint;
  LP: IECPoint;
  LA, LGP: TBigInteger;
  LN: TBigInteger;
  LRight: IECPoint;
begin
  Result := False;
  if (ASignerIndex < 0) or (ASignerIndex >= System.Length(APubNonces)) then
    Exit;
  LAggNonce := NonceAgg(ADomain, APubNonces);
  LSessionCtx.AggNonce := LAggNonce;
  LSessionCtx.PubKeys := APubKeys;
  LSessionCtx.Tweaks := ATweaks;
  LSessionCtx.IsXOnlyT := AIsXOnlyT;
  LSessionCtx.Msg := AMsg;
  if not GetSessionValues(ADomain, LSessionCtx, LValues) then
    Exit;
  LN := ADomain.N;
  LS := TBigInteger.Create(1, APSig);
  if LS.CompareTo(LN) >= 0 then
    Exit;
  LReS1 := TBip327MuSig2Utilities.CPoint(ADomain, System.Copy(APubNonces[ASignerIndex], 0, 33));
  LReS2 := TBip327MuSig2Utilities.CPoint(ADomain, System.Copy(APubNonces[ASignerIndex], 33, 33));
  LRePrime := LReS1.Add(LReS2.Multiply(LValues.B));
  if TBip340SchnorrUtilities.HasEvenY(LValues.R) then
    LRe := LRePrime
  else
    LRe := LRePrime.Negate();
  LP := TBip327MuSig2Utilities.CPoint(ADomain, APubKeys[ASignerIndex]);
  LA := GetSessionKeyAggCoeff(LSessionCtx, ADomain, LP);
  if TBip340SchnorrUtilities.HasEvenY(LValues.Q) then
    LGP := LValues.GAcc
  else
    LGP := LN.Subtract(TBigInteger.One).Multiply(LValues.GAcc).&Mod(LN);
  LRight := LRe.Add(LP.Multiply(LValues.E.Multiply(LA).Multiply(LGP).&Mod(LN)));
  Result := TECAlgorithms.ReferenceMultiply(ADomain.G, LS).Equals(LRight);
end;

class function TBip327MuSig2.PartialSigAgg(const ADomain: IECDomainParameters;
  const APsigs: TCryptoLibGenericArray<TCryptoLibByteArray>;
  const ASessionCtx: TBip327SessionContext): TCryptoLibByteArray;
var
  LValues: TBip327SessionValues;
  LS: TBigInteger;
  LI: Int32;
  LSi: TBigInteger;
  LN: TBigInteger;
  LG: TBigInteger;
begin
  if not GetSessionValues(ADomain, ASessionCtx, LValues) then
    raise EArgumentCryptoLibException.Create('PartialSigAgg: invalid session');
  LN := ADomain.N;
  LS := TBigInteger.Zero;
  for LI := 0 to System.Length(APsigs) - 1 do
  begin
    LSi := TBigInteger.Create(1, APsigs[LI]);
    if LSi.CompareTo(LN) >= 0 then
      raise EBip327InvalidContributionException.Create('Invalid psig', LI, 'psig');
    LS := LS.Add(LSi).&Mod(LN);
  end;
  if TBip340SchnorrUtilities.HasEvenY(LValues.Q) then
    LG := TBigInteger.One
  else
    LG := LN.Subtract(TBigInteger.One);
  LS := LS.Add(LValues.E.Multiply(LG).Multiply(LValues.TAcc).&Mod(LN)).&Mod(LN);
  Result := TBip340SchnorrUtilities.BytesFromPoint(LValues.R);
  System.SetLength(Result, TBip340SchnorrUtilities.BIP340_SIG_SIZE);
  TBigIntegerUtilities.AsUnsignedByteArray(LS, Result, 32, 32);
end;

class function TBip327MuSig2.DetNonceHash(const ADomain: IECDomainParameters;
  const ASkPrime, AAggOtherNonce, AAggPk, AMsg: TCryptoLibByteArray;
  AIndex: Int32): TBigInteger;
var
  LTagBytes, LHashInput: TCryptoLibByteArray;
  LN: TBigInteger;
  LOff, LLenMsg: Int32;
begin
  LN := ADomain.N;
  LTagBytes := TConverters.ConvertStringToBytes(
    TBip327MuSig2Utilities.MUSIG_DETERMINISTIC_NONCE_TAG_STR, TEncoding.UTF8);
  LLenMsg := System.Length(AMsg);
  System.SetLength(LHashInput, 32 + 66 + 32 + 8 + LLenMsg + 1);
  LOff := 0;
  System.Move(ASkPrime[0], LHashInput[LOff], 32); Inc(LOff, 32);
  System.Move(AAggOtherNonce[0], LHashInput[LOff], 66); Inc(LOff, 66);
  System.Move(AAggPk[0], LHashInput[LOff], 32); Inc(LOff, 32);
  TPack.UInt64_To_BE(UInt64(LLenMsg), LHashInput, LOff); Inc(LOff, 8);
  if (AMsg <> nil) and (LLenMsg > 0) then
    System.Move(AMsg[0], LHashInput[LOff], LLenMsg);
  Inc(LOff, LLenMsg);
  LHashInput[LOff] := Byte(AIndex);
  Result := TBigInteger.Create(1, TBip340SchnorrUtilities.TaggedHash(LTagBytes, LHashInput)).&Mod(LN);
end;

class function TBip327MuSig2.KeyAggAndTweak(const ADomain: IECDomainParameters;
  const APubKeys: TCryptoLibGenericArray<TCryptoLibByteArray>;
  const ATweaks: TCryptoLibGenericArray<TCryptoLibByteArray>;
  const AIsXOnlyT: TCryptoLibBooleanArray): IBip327KeyAggContext;
var
  LCtx: IBip327KeyAggContext;
  LI: Int32;
begin
  if System.Length(ATweaks) <> System.Length(AIsXOnlyT) then
    raise EArgumentCryptoLibException.Create('tweaks and is_xonly_t length mismatch');
  LCtx := TBip327MuSig2KeyAggregation.KeyAgg(ADomain, APubKeys);
  for LI := 0 to System.Length(ATweaks) - 1 do
    LCtx := TBip327MuSig2KeyAggregation.ApplyTweak(LCtx, ATweaks[LI], AIsXOnlyT[LI]);
  Result := LCtx;
end;

class function TBip327MuSig2.DeterministicSign(const ADomain: IECDomainParameters;
  const ASk: TCryptoLibByteArray; const AAggOtherNonce: TCryptoLibByteArray;
  const APubKeys: TCryptoLibGenericArray<TCryptoLibByteArray>;
  const ATweaks: TCryptoLibGenericArray<TCryptoLibByteArray>;
  const AIsXOnlyT: TCryptoLibBooleanArray; const AMsg: TCryptoLibByteArray;
  const ARand: TCryptoLibByteArray; out APubNonce: TCryptoLibByteArray;
  out APSig: TCryptoLibByteArray): Boolean;
var
  LSkPrime: TCryptoLibByteArray;
  LAggpk: TCryptoLibByteArray;
  LCtx: IBip327KeyAggContext;
  LTagBytes: TCryptoLibByteArray;
  LK1, LK2: TBigInteger;
  LN: TBigInteger;
  LR1, LR2: IECPoint;
  LAggnonce: TCryptoLibByteArray;
  LSessionCtx: TBip327SessionContext;
  LSecnonce: TCryptoLibByteArray;
begin
  Result := False;
  if (ARand <> nil) and (System.Length(ARand) = 32) then
  begin
    LTagBytes := TConverters.ConvertStringToBytes(
      TBip327MuSig2Utilities.MUSIG_AUX_TAG_STR, TEncoding.UTF8);
    System.SetLength(LSkPrime, 32);
    TByteUtilities.&Xor(32, ASk, 0, TBip340SchnorrUtilities.TaggedHash(LTagBytes, ARand), 0, LSkPrime, 0);
  end
  else
    LSkPrime := ASk;
  LCtx := KeyAggAndTweak(ADomain, APubKeys, ATweaks, AIsXOnlyT);
  LAggpk := LCtx.GetXOnlyPubKey();
  LN := ADomain.N;
  LK1 := DetNonceHash(ADomain, LSkPrime, AAggOtherNonce, LAggpk, AMsg, 0);
  LK2 := DetNonceHash(ADomain, LSkPrime, AAggOtherNonce, LAggpk, AMsg, 1);
  if (LK1.SignValue = 0) or (LK2.SignValue = 0) then
    Exit;
  LR1 := TECAlgorithms.ReferenceMultiply(ADomain.G, LK1).Normalize();
  LR2 := TECAlgorithms.ReferenceMultiply(ADomain.G, LK2).Normalize();
  System.SetLength(APubNonce, TBip327MuSig2Utilities.BIP327_PUBNONCE_SIZE);
  System.Move(TBip327MuSig2Utilities.CBytes(ADomain, LR1)[0], APubNonce[0], 33);
  System.Move(TBip327MuSig2Utilities.CBytes(ADomain, LR2)[0], APubNonce[33], 33);
  LAggnonce := NonceAgg(ADomain, TCryptoLibGenericArray<TCryptoLibByteArray>.Create(AAggOtherNonce, APubNonce));
  LSessionCtx.AggNonce := LAggnonce;
  LSessionCtx.PubKeys := APubKeys;
  LSessionCtx.Tweaks := ATweaks;
  LSessionCtx.IsXOnlyT := AIsXOnlyT;
  LSessionCtx.Msg := AMsg;
  System.SetLength(LSecnonce, TBip327MuSig2Utilities.BIP327_SECNONCE_SIZE);
  TBigIntegerUtilities.AsUnsignedByteArray(LK1, LSecnonce, 0, 32);
  TBigIntegerUtilities.AsUnsignedByteArray(LK2, LSecnonce, 32, 32);
  System.Move(TBip327MuSig2Utilities.IndividualPubKey(ADomain, ASk)[0], LSecnonce[64], 33);
  Result := Sign(ADomain, LSecnonce, ASk, LSessionCtx, APSig);
end;

end.
