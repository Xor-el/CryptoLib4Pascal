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

unit ClpBip340SchnorrBatchVerifier;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpBigInteger,
  ClpIECCommon,
  ClpIECParameters,
  ClpIX9ECAsn1Objects,
  ClpIDigest,
  ClpBip340SchnorrUtilities,
  ClpECUtilities,
  ClpECParameters,
  ClpECAlgorithms,
  ClpConverters,
  ClpIBufferedCipher,
  ClpCipherUtilities,
  ClpIKeyParameter,
  ClpKeyParameter,
  ClpIParametersWithIV,
  ClpParametersWithIV,
  ClpDigestUtilities,
  ClpBigIntegerUtilities,
  ClpArrayUtilities,
  ClpCryptoLibTypes;

type
  /// <summary>Single entry for BIP-340 batch verification: 32-byte public key, arbitrary message, 64-byte signature.</summary>
  TBip340SchnorrVerificationEntry = record
    PublicKey: TCryptoLibByteArray;   // 32 bytes
    &Message: TCryptoLibByteArray;
    Signature: TCryptoLibByteArray;   // 64 bytes
  end;

  TBip340SchnorrBatchVerifier = class sealed
  private
    /// <summary>BIP-340 batch seed: SHA256(pk_1..pk_u || m_1..m_u || sig_1..sig_u). Arrays must have same length (at least 1).</summary>
    class function BuildBatchSeed(const APublicKeys, AMessages,
      ASignatures: TCryptoLibGenericArray<TCryptoLibByteArray>): TCryptoLibByteArray; static;
  public
    /// <summary>Batch-verify BIP-340 Schnorr signatures. AItems must be non-nil with at least one entry; each entry must have PublicKey length 32 and Signature length 64. Returns False on any verification failure.</summary>
    class function BatchVerify(const AItems: TCryptoLibGenericArray<TBip340SchnorrVerificationEntry>): Boolean; static;
  end;

implementation

{ TBip340SchnorrBatchVerifier }

class function TBip340SchnorrBatchVerifier.BuildBatchSeed(const APublicKeys,
  AMessages, ASignatures: TCryptoLibGenericArray<TCryptoLibByteArray>): TCryptoLibByteArray;
var
  LDigest: IDigest;
  LConcat: TCryptoLibByteArray;
  LU, LI, LOffset: Int32;
begin
  if (APublicKeys = nil) or (AMessages = nil) or (ASignatures = nil) then
    raise EArgumentCryptoLibException.Create('BuildBatchSeed: arrays cannot be nil');

  LU := System.Length(APublicKeys);
  if (LU < 1) or (System.Length(AMessages) <> LU) or (System.Length(ASignatures) <> LU) then
    raise EArgumentCryptoLibException.Create('BuildBatchSeed: arrays must have same length (at least 1)');

  LOffset := 0;
  for LI := 0 to System.Pred(LU) do
    LOffset := LOffset + System.Length(APublicKeys[LI]) + System.Length(AMessages[LI]) +
      System.Length(ASignatures[LI]);

  System.SetLength(LConcat, LOffset);
  LOffset := 0;

  for LI := 0 to System.Pred(LU) do
  begin
    if System.Length(APublicKeys[LI]) > 0 then
    begin
      System.Move(APublicKeys[LI][0], LConcat[LOffset], System.Length(APublicKeys[LI]));
      LOffset := LOffset + System.Length(APublicKeys[LI]);
    end;
  end;

  for LI := 0 to System.Pred(LU) do
  begin
    if System.Length(AMessages[LI]) > 0 then
    begin
      System.Move(AMessages[LI][0], LConcat[LOffset], System.Length(AMessages[LI]));
      LOffset := LOffset + System.Length(AMessages[LI]);
    end;
  end;

  for LI := 0 to System.Pred(LU) do
  begin
    if System.Length(ASignatures[LI]) > 0 then
    begin
      System.Move(ASignatures[LI][0], LConcat[LOffset], System.Length(ASignatures[LI]));
      LOffset := LOffset + System.Length(ASignatures[LI]);
    end;
  end;

  LDigest := TDigestUtilities.GetDigest('SHA-256');
  LDigest.BlockUpdate(LConcat, 0, System.Length(LConcat));
  System.SetLength(Result, LDigest.GetDigestSize());
  LDigest.DoFinal(Result, 0);
end;

class function TBip340SchnorrBatchVerifier.BatchVerify(const AItems
  : TCryptoLibGenericArray<TBip340SchnorrVerificationEntry>): Boolean;
var
  LX9: IX9ECParameters;
  LDomain: IECDomainParameters;
  LCurve: IECCurve;
  LN, LSumS: TBigInteger;
  LU, LI, LJ: Int32;
  LSeed, LChallengeTagBytes, LChallenge, LBlock, LRBytes, LSBytes: TCryptoLibByteArray;
  LPubs, LMsgs, LSigs: TCryptoLibGenericArray<TCryptoLibByteArray>;
  LCipher: IBufferedCipher;
  LZeroIV, LZeros: TCryptoLibByteArray;
  LParams: IParametersWithIV;
  LKeyParam: IKeyParameter;
  LCoefs: TCryptoLibGenericArray<TBigInteger>;
  LPs, LRs: TCryptoLibGenericArray<IECPoint>;
  LEs: TCryptoLibGenericArray<TBigInteger>;
  LPoints: TCryptoLibGenericArray<IECPoint>;
  LScalars: TCryptoLibGenericArray<TBigInteger>;
  LP: IECPoint;
  LR, LS, LE, LVal: TBigInteger;
  LLhs, LRhs, LNhs, LRhsNorm: IECPoint;
begin
  if (AItems = nil) or (System.Length(AItems) < 1) then
    raise EArgumentCryptoLibException.Create('BatchVerify requires at least one item');

  LU := System.Length(AItems);

  for LI := 0 to System.Pred(LU) do
  begin
    if (System.Length(AItems[LI].PublicKey) <> TBip340SchnorrUtilities.BIP340_PUBKEY_SIZE) then
      raise EArgumentCryptoLibException.Create('PublicKey must be 32 bytes');

    if (System.Length(AItems[LI].Signature) <> TBip340SchnorrUtilities.BIP340_SIG_SIZE) then
      raise EArgumentCryptoLibException.Create('Signature must be 64 bytes');
  end;

  LX9 := TECUtilities.FindECCurveByName('secp256k1');
  if (LX9 = nil) then
  begin
    Result := False;
    Exit;
  end;
  LDomain := TECDomainParameters.FromX9ECParameters(LX9);
  LCurve := LDomain.Curve;
  LN := LDomain.N;

  System.SetLength(LPubs, LU);
  System.SetLength(LMsgs, LU);
  System.SetLength(LSigs, LU);

  for LI := 0 to System.Pred(LU) do
  begin
    LPubs[LI] := AItems[LI].PublicKey;
    LMsgs[LI] := AItems[LI].Message;
    LSigs[LI] := AItems[LI].Signature;
  end;

  // Seed = SHA256(pk_1..pk_u || m_1..m_u || sig_1..sig_u)
  LSeed := BuildBatchSeed(LPubs, LMsgs, LSigs);

  // Coefficients a_1=1, a_2..a_u from ChaCha20 CSPRNG (u-1 values)
  System.SetLength(LCoefs, LU);
  LCoefs[0] := TBigInteger.One;
  if (LU > 1) then
  begin
    System.SetLength(LZeroIV, 12);
    TArrayUtilities.Fill<Byte>(LZeroIV, 0, 12, Byte(0));
    LKeyParam := TKeyParameter.Create(LSeed);
    LParams := TParametersWithIV.Create(LKeyParam, LZeroIV);
    LCipher := TCipherUtilities.GetCipher('CHACHA7539');
    LCipher.Init(True, LParams);
    System.SetLength(LZeros, 32);
    TArrayUtilities.Fill<Byte>(LZeros, 0, 32, Byte(0));
    System.SetLength(LBlock, 32);
    LJ := 0;
    while LJ < (LU - 1) do
    begin
      LCipher.ProcessBytes(LZeros, 0, 32, LBlock, 0);
      LVal := TBigInteger.Create(1, LBlock);
      if (LVal.CompareTo(TBigInteger.One) >= 0) and (LVal.CompareTo(LN) < 0) then
      begin
        LCoefs[LJ + 1] := LVal;
        Inc(LJ);
      end;
    end;
  end;

  // Per-signature: P[i], R[i], e[i]; fail on LiftX or r/s bounds
  System.SetLength(LPs, LU);
  System.SetLength(LRs, LU);
  System.SetLength(LEs, LU);
  LChallengeTagBytes := TConverters.ConvertStringToBytes
    (TBip340SchnorrUtilities.BIP0340_CHALLENGE_TAG_STR, TEncoding.UTF8);

  for LI := 0 to System.Pred(LU) do
  begin
    try
      LP := TBip340SchnorrUtilities.LiftX(LDomain, AItems[LI].PublicKey);
    except
      Result := False;
      Exit;
    end;

    LPs[LI] := LP;

    System.SetLength(LRBytes, 32);
    System.SetLength(LSBytes, 32);
    System.Move(AItems[LI].Signature[0], LRBytes[0], 32);
    System.Move(AItems[LI].Signature[32], LSBytes[0], 32);
    LR := TBigInteger.Create(1, LRBytes);
    LS := TBigInteger.Create(1, LSBytes);

    if (LR.CompareTo(LCurve.Field.Characteristic) >= 0) or (LS.CompareTo(LN) >= 0) then
    begin
      Result := False;
      Exit;
    end;

    System.SetLength(LChallenge, 32 + 32 + System.Length(AItems[LI].Message));
    System.Move(LRBytes[0], LChallenge[0], 32);
    System.Move(TBip340SchnorrUtilities.BytesFromPoint(LP)[0], LChallenge[32], 32);

    if System.Length(AItems[LI].Message) > 0 then
      System.Move(AItems[LI].Message[0], LChallenge[64], System.Length(AItems[LI].Message));

    LE := TBigInteger.Create(1, TBip340SchnorrUtilities.TaggedHash(LChallengeTagBytes, LChallenge))
      .&Mod(LN);
    LEs[LI] := LE;

    try
      LRs[LI] := TBip340SchnorrUtilities.LiftX(LDomain, LRBytes);
    except
      Result := False;
      Exit;
    end;
  end;

  // sumS = s_1 + a_2*s_2 + ... + a_u*s_u (mod n)
  LSumS := TBigInteger.Create(1, System.Copy(AItems[0].Signature, 32, 32)).&Mod(LN);
  for LI := 1 to System.Pred(LU) do
  begin
    LS := TBigInteger.Create(1, System.Copy(AItems[LI].Signature, 32, 32));
    LSumS := LSumS.Add(LCoefs[LI].Multiply(LS)).&Mod(LN);
  end;

  // LHS = G * sumS
  LLhs := TECAlgorithms.ReferenceMultiply(LDomain.G, LSumS);

  // RHS = R_1 + a_2*R_2 + ... + a_u*R_u + e_1*P_1 + (a_2*e_2)*P_2 + ... + (a_u*e_u)*P_u
  System.SetLength(LPoints, LU * 2);
  System.SetLength(LScalars, LU * 2);

  for LI := 0 to System.Pred(LU) do
  begin
    LPoints[LI] := LRs[LI];
    LScalars[LI] := LCoefs[LI];
  end;

  for LI := 0 to System.Pred(LU) do
  begin
    LPoints[LU + LI] := LPs[LI];
    LScalars[LU + LI] := LCoefs[LI].Multiply(LEs[LI]).&Mod(LN);
  end;

  LRhs := TECAlgorithms.SumOfMultiplies(LPoints, LScalars);

  LNhs := LLhs.Normalize();
  LRhsNorm := LRhs.Normalize();
  if LNhs.IsInfinity and LRhsNorm.IsInfinity then
    Result := True
  else if LNhs.IsInfinity or LRhsNorm.IsInfinity then
    Result := False
  else
    Result := LNhs.AffineXCoord.ToBigInteger().Equals(LRhsNorm.AffineXCoord.ToBigInteger()) and
      LNhs.AffineYCoord.ToBigInteger().Equals(LRhsNorm.AffineYCoord.ToBigInteger());
end;

end.
