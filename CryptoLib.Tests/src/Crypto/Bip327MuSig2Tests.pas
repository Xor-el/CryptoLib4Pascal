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

(* BIP-327 MuSig2 tests; vectors from https://github.com/bitcoin/bips/tree/master/bip-0327 *)

unit Bip327MuSig2Tests;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  SysUtils,
{$IFDEF FPC}
  fpcunit,
  testregistry,
{$ELSE}
  TestFramework,
{$ENDIF FPC}
  ClpBip327MuSig2Utilities,
  ClpBip327MuSig2KeyAggregation,
  ClpBip327MuSig2,
  ClpBip340SchnorrBatchVerifier,
  ClpBip340SchnorrParameters,
  ClpBip340SchnorrUtilities,
  ClpSignerUtilities,
  ClpISigner,
  ClpICipherParameters,
  ClpECUtilities,
  ClpECParameters,
  ClpIECParameters,
  ClpIX9ECAsn1Objects,
  FixedSecureRandom,
  ClpISecureRandom,
  ClpGeneratorUtilities,
  ClpKeyGenerationParameters,
  ClpIKeyGenerationParameters,
  ClpIAsymmetricCipherKeyPair,
  ClpIAsymmetricCipherKeyPairGenerator,
  ClpIBip340SchnorrParameters,
  ClpSecureRandom,
  ClpConverters,
  ClpCryptoLibTypes,
  Bip327Vectors,
  CryptoLibTestBase;

type
  TTestBip327MuSig2 = class(TCryptoLibAlgorithmTestCase)
  strict private
    function Secp256k1Domain: IECDomainParameters;
    procedure VerifyAggSigBip340(const AMsg, AAggPk, AAggsig: TCryptoLibByteArray;
      const ACheckMessage: string);
    procedure ExpectInvalidContribution(const E: EBip327InvalidContributionException;
      ASigner: Int32; const AContrib: string);
  published
    procedure TestKeyAggSingleKey;
    procedure TestKeyAggTwoKeys;
    procedure TestIndividualPubkey;
    procedure TestKeySortVectors;
    procedure TestKeyAggVectors;
    procedure TestNonceGenVectors;
    procedure TestNonceAggVectors;
    procedure TestTweakVectors;
    procedure TestSignVerifyVectors;
    procedure TestSigAggVectors;
    procedure TestDetSignVectors;
    procedure TestSignAndVerifyRandom;
    procedure TestServerClientMuSig2;
  end;

implementation

{ TTestBip327MuSig2 }

procedure TTestBip327MuSig2.VerifyAggSigBip340(const AMsg, AAggPk, AAggsig: TCryptoLibByteArray;
  const ACheckMessage: string);
var
  LSigner: ISigner;
  LVerifyEntry: TBip340SchnorrVerificationEntry;
  LVerifyItems: TCryptoLibGenericArray<TBip340SchnorrVerificationEntry>;
begin
  // Simple verification: ISigner (BIP-340 single sig verify)
  LSigner := TSignerUtilities.GetSigner('BIP340Schnorr');
  LSigner.Init(False, TBip340SchnorrPublicKeyParameters.Create(AAggPk) as ICipherParameters);
  if System.Length(AMsg) > 0 then
    LSigner.BlockUpdate(AMsg, 0, System.Length(AMsg));
  Check(LSigner.VerifySignature(AAggsig), ACheckMessage + ': BIP-340 verify (ISigner)');
  // Batch verification: single-entry batch (same result, different API)
  LVerifyEntry.PublicKey := AAggPk;
  LVerifyEntry.Message := AMsg;
  LVerifyEntry.Signature := AAggsig;
  LVerifyItems := TCryptoLibGenericArray<TBip340SchnorrVerificationEntry>.Create(LVerifyEntry);
  Check(TBip340SchnorrBatchVerifier.BatchVerify(LVerifyItems), ACheckMessage + ': BIP-340 verify (batch)');
end;

function TTestBip327MuSig2.Secp256k1Domain: IECDomainParameters;
var
  LX9: IX9ECParameters;
begin
  LX9 := TECUtilities.FindECCurveByName('secp256k1');
  if LX9 = nil then
    raise EInvalidOperationCryptoLibException.Create('secp256k1 not found');
  Result := TECDomainParameters.FromX9ECParameters(LX9);
end;

procedure TTestBip327MuSig2.ExpectInvalidContribution(
  const E: EBip327InvalidContributionException; ASigner: Int32; const AContrib: string);
begin
  Check(E.SignerIndex = ASigner, 'signer index');
  Check(E.Contribution = AContrib, 'contrib');
end;

procedure TTestBip327MuSig2.TestKeyAggSingleKey;
var
  LDomain: IECDomainParameters;
  LPk: TCryptoLibByteArray;
  LCtx: IBip327KeyAggContext;
  LXonly: TCryptoLibByteArray;
begin
  LDomain := Secp256k1Domain();
  LPk := DecodeHex('02' + '79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798');
  LCtx := TBip327MuSig2KeyAggregation.KeyAgg(LDomain, TCryptoLibGenericArray<TCryptoLibByteArray>.Create(LPk));
  LXonly := LCtx.GetXOnlyPubKey();
  Check(Length(LXonly) = TBip340SchnorrUtilities.BIP340_PUBKEY_SIZE, 'xonly length');
end;

procedure TTestBip327MuSig2.TestKeyAggTwoKeys;
var
  LDomain: IECDomainParameters;
  LPks: TCryptoLibGenericArray<TCryptoLibByteArray>;
  LPk1, LPk2: TCryptoLibByteArray;
  LCtx: IBip327KeyAggContext;
  LXonly: TCryptoLibByteArray;
begin
  LDomain := Secp256k1Domain();
  LPk1 := DecodeHex('02' + '79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798');
  LPk2 := DecodeHex('02' + 'C6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5');
  LPks := TCryptoLibGenericArray<TCryptoLibByteArray>.Create(LPk1, LPk2);
  LCtx := TBip327MuSig2KeyAggregation.KeyAgg(LDomain, LPks);
  LXonly := LCtx.GetXOnlyPubKey();
  Check(Length(LXonly) = TBip340SchnorrUtilities.BIP340_PUBKEY_SIZE, 'xonly length');
end;

procedure TTestBip327MuSig2.TestIndividualPubkey;
var
  LDomain: IECDomainParameters;
  LSk, LPk: TCryptoLibByteArray;
begin
  LDomain := Secp256k1Domain();
  LSk := DecodeHex('0000000000000000000000000000000000000000000000000000000000000003');
  LPk := TBip327MuSig2Utilities.IndividualPubKey(LDomain, LSk);
  Check(Length(LPk) = TBip327MuSig2Utilities.BIP327_PLAIN_PUBKEY_SIZE, 'plain pubkey length');
end;

procedure TTestBip327MuSig2.TestKeySortVectors;
var
  LSorted: TCryptoLibGenericArray<TCryptoLibByteArray>;
  LI: Int32;
begin
  LSorted := TBip327MuSig2KeyAggregation.KeySort(TBip327Vectors.GetKeySort.Pubkeys);
  for LI := 0 to System.High(TBip327Vectors.GetKeySort.ExpectedSorted) do
    Check(AreEqual(LSorted[LI], TBip327Vectors.GetKeySort.ExpectedSorted[LI]),
      Format('KeySort vector index %d', [LI]));
end;

procedure TTestBip327MuSig2.TestKeyAggVectors;
var
  LDomain: IECDomainParameters;
  LCase: TBip327KeyAggValidCase;
  LErrorCase: TBip327KeyAggErrorCase;
  LCtx: IBip327KeyAggContext;
  LI: Int32;
begin
  LDomain := Secp256k1Domain();
  for LI := 0 to System.High(TBip327Vectors.GetKeyAggValid) do
  begin
    LCase := TBip327Vectors.GetKeyAggValid[LI];
    LCtx := TBip327MuSig2KeyAggregation.KeyAgg(LDomain, LCase.Keys);
    Check(AreEqual(LCtx.GetXOnlyPubKey(), LCase.Expected), Format('KeyAgg valid case %d', [LI]));
  end;
  for LI := 0 to System.High(TBip327Vectors.GetKeyAggErrors) do
  begin
    LErrorCase := TBip327Vectors.GetKeyAggErrors[LI];
    if LErrorCase.Kind = TBip327KeyAggErrorCaseKind.InvalidContribution then
    begin
      try
        TBip327MuSig2KeyAggregation.KeyAgg(LDomain, LErrorCase.Keys);
        Fail(Format('KeyAgg error case %d should raise', [LI]));
      except
        on E: EBip327InvalidContributionException do
          ExpectInvalidContribution(E, LErrorCase.ExpectedSigner, LErrorCase.ExpectedContrib);
        else
          raise;
      end;
    end
    else
    begin
      LCtx := TBip327MuSig2KeyAggregation.KeyAgg(LDomain, LErrorCase.Keys);
      try
        TBip327MuSig2KeyAggregation.ApplyTweak(LCtx, LErrorCase.Tweaks[0], LErrorCase.IsXonly[0]);
        Fail(Format('KeyAgg tweak error case %d should raise', [LI]));
      except
        on E: EArgumentCryptoLibException do
        begin
          if Pos('tweak', LowerCase(E.Message)) > 0 then
            Check(True, 'tweak error message')
          else if Pos('infinity', LowerCase(E.Message)) > 0 then
            Check(True, 'infinity error message')
          else
            raise;
        end;
        else
          raise;
      end;
    end;
  end;
end;

procedure TTestBip327MuSig2.TestNonceGenVectors;
var
  LDomain: IECDomainParameters;
  LCase: TBip327NonceGenCase;
  LFixedRand: ISecureRandom;
  LSecnonce, LPubnonce: TCryptoLibByteArray;
  LOk: Boolean;
  LI: Int32;
begin
  LDomain := Secp256k1Domain();
  for LI := 0 to System.High(TBip327Vectors.GetNonceGenCases) do
  begin
    LCase := TBip327Vectors.GetNonceGenCases[LI];
    LFixedRand := TFixedSecureRandom.From(TCryptoLibMatrixByteArray.Create(LCase.RandBytes));
    LOk := TBip327MuSig2.NonceGen(LDomain, LCase.Sk, LCase.Pk, LCase.AggPk, LCase.Msg,
      LCase.MsgProvided, LCase.ExtraIn, LFixedRand, LSecnonce, LPubnonce);
    Check(LOk, Format('NonceGen vector %d', [LI]));
    Check(AreEqual(LSecnonce, LCase.ExpectedSecnonce), Format('NonceGen vector %d secnonce', [LI]));
    Check(AreEqual(LPubnonce, LCase.ExpectedPubnonce), Format('NonceGen vector %d pubnonce', [LI]));
  end;
end;

procedure TTestBip327MuSig2.TestNonceAggVectors;
var
  LDomain: IECDomainParameters;
  LCase: TBip327NonceAggValidCase;
  LErrorCase: TBip327NonceAggErrorCase;
  LResult: TCryptoLibByteArray;
  LI: Int32;
begin
  LDomain := Secp256k1Domain();
  for LI := 0 to System.High(TBip327Vectors.GetNonceAggValid) do
  begin
    LCase := TBip327Vectors.GetNonceAggValid[LI];
    LResult := TBip327MuSig2.NonceAgg(LDomain, LCase.Pnonces);
    Check(AreEqual(LResult, LCase.Expected), Format('NonceAgg valid case %d', [LI]));
  end;
  for LI := 0 to System.High(TBip327Vectors.GetNonceAggErrors) do
  begin
    LErrorCase := TBip327Vectors.GetNonceAggErrors[LI];
    try
      TBip327MuSig2.NonceAgg(LDomain, LErrorCase.Pnonces);
      Fail(Format('NonceAgg error case %d should raise', [LI]));
    except
      on E: EBip327InvalidContributionException do
        ExpectInvalidContribution(E, LErrorCase.ExpectedSigner, LErrorCase.ExpectedContrib);
      else
        raise;
    end;
  end;
end;

procedure TTestBip327MuSig2.TestTweakVectors;
var
  LDomain: IECDomainParameters;
  LCase: TBip327TweakValidCase;
  LErrorCase: TBip327TweakErrorCase;
  LSecnonce, LPsig, LComputedAggNonce: TCryptoLibByteArray;
  LSessionCtx: TBip327SessionContext;
  LI: Int32;
begin
  LDomain := Secp256k1Domain();
  LComputedAggNonce := TBip327MuSig2.NonceAgg(LDomain, TBip327Vectors.GetTweak.Pnonces);
  Check(AreEqual(TBip327Vectors.GetTweak.AggNonce, LComputedAggNonce), 'Computed Agg Nonce does not match that from vector');
  for LI := 0 to System.High(TBip327Vectors.GetTweakValid) do
  begin
    LCase := TBip327Vectors.GetTweakValid[LI];
    LSessionCtx.AggNonce := TBip327Vectors.GetTweak.AggNonce;
    LSessionCtx.PubKeys := LCase.Keys;
    if LCase.HasTweaks then
    begin
      LSessionCtx.Tweaks := LCase.TweakBytes;
      LSessionCtx.IsXOnlyT := LCase.IsXonly;
    end
    else
    begin
      LSessionCtx.Tweaks := nil;
      LSessionCtx.IsXOnlyT := nil;
    end;
    LSessionCtx.Msg := TBip327Vectors.GetTweak.Msg;
    LSecnonce := Copy(TBip327Vectors.GetTweak.Secnonce);
    Check(TBip327MuSig2.Sign(LDomain, LSecnonce, TBip327Vectors.GetTweak.Sk, LSessionCtx, LPsig),
      Format('Tweak vector sign case %d', [LI]));
    Check(AreEqual(LPsig, LCase.Expected), Format('Tweak vector expected case %d', [LI]));
  end;
  for LI := 0 to System.High(TBip327Vectors.GetTweakErrors) do
  begin
    LErrorCase := TBip327Vectors.GetTweakErrors[LI];
    LSessionCtx.AggNonce := TBip327Vectors.GetTweak.AggNonce;
    LSessionCtx.PubKeys := LErrorCase.Keys;
    LSessionCtx.Tweaks := LErrorCase.TweakBytes;
    LSessionCtx.IsXOnlyT := LErrorCase.IsXonly;
    LSessionCtx.Msg := TBip327Vectors.GetTweak.Msg;
    LSecnonce := Copy(TBip327Vectors.GetTweak.Secnonce);
    try
      TBip327MuSig2.Sign(LDomain, LSecnonce, TBip327Vectors.GetTweak.Sk, LSessionCtx, LPsig);
      Fail(Format('Tweak error case %d should raise', [LI]));
    except
      on E: EArgumentCryptoLibException do
        Check(Pos('tweak', LowerCase(E.Message)) > 0, 'tweak error');
      else
        raise;
    end;
  end;
end;

procedure TTestBip327MuSig2.TestSignVerifyVectors;
var
  LDomain: IECDomainParameters;
  LCase: TBip327SignVerifyValidCase;
  LErrorCase: TBip327SignVerifySignErrorCase;
  LFailCase: TBip327SignVerifyVerifyFailCase;
  LVerifyErrorCase: TBip327SignVerifyVerifyErrorCase;
  LSessionCtx: TBip327SessionContext;
  LPsig, LSecnonce: TCryptoLibByteArray;
  LI: Int32;
begin
  LDomain := Secp256k1Domain();
  for LI := 0 to System.High(TBip327Vectors.GetSignVerifyValid) do
  begin
    LCase := TBip327Vectors.GetSignVerifyValid[LI];
    LSessionCtx.AggNonce := LCase.AggNonce;
    LSessionCtx.PubKeys := LCase.Keys;
    LSessionCtx.Tweaks := nil;
    LSessionCtx.IsXOnlyT := nil;
    LSessionCtx.Msg := LCase.Msg;
    LSecnonce := Copy(LCase.Secnonce);
    Check(TBip327MuSig2.Sign(LDomain, LSecnonce, TBip327Vectors.GetSignVerify.Sk, LSessionCtx, LPsig),
      Format('SignVerify sign case %d', [LI]));
    Check(AreEqual(LPsig, LCase.Expected), Format('SignVerify expected case %d', [LI]));
    if LCase.CheckPartialVerifySigner0 then
      Check(TBip327MuSig2.PartialSigVerify(LDomain, LPsig, LCase.NoncesForSession, LCase.Keys,
        nil, nil, LCase.Msg, 0), 'PartialSigVerify signer 0');
  end;
  LFailCase := TBip327Vectors.GetSignVerifyWrongSigner;
  Check(not TBip327MuSig2.PartialSigVerify(LDomain, LFailCase.Sig, LFailCase.NoncesForSession,
    LFailCase.Keys, nil, nil, LFailCase.Msg, LFailCase.SignerIndex), 'Verify fail wrong signer');
  for LI := 0 to System.High(TBip327Vectors.GetSignVerifySignErrors) do
  begin
    LErrorCase := TBip327Vectors.GetSignVerifySignErrors[LI];
    LSessionCtx.AggNonce := LErrorCase.AggNonce;
    LSessionCtx.PubKeys := LErrorCase.Keys;
    LSessionCtx.Tweaks := nil;
    LSessionCtx.IsXOnlyT := nil;
    LSessionCtx.Msg := LErrorCase.Msg;
    LSecnonce := Copy(LErrorCase.Secnonce);
    if LErrorCase.Kind = TBip327SignVerifySignErrorCaseKind.InvalidContribution then
    begin
      try
        TBip327MuSig2.Sign(LDomain, LSecnonce, TBip327Vectors.GetSignVerify.Sk, LSessionCtx, LPsig);
        Fail(Format('Sign error case %d should raise', [LI]));
      except
        on E: EBip327InvalidContributionException do
        begin
          if LErrorCase.MapAggnonceContribToPubkey then
            ExpectInvalidContribution(E, -1, 'pubkey')
          else
            ExpectInvalidContribution(E, LErrorCase.ExpectedSigner, LErrorCase.ExpectedContrib);
        end;
        else
          raise;
      end;
    end
    else if LErrorCase.Kind = TBip327SignVerifySignErrorCaseKind.ValueSecnonce then
      Check(not TBip327MuSig2.Sign(LDomain, LSecnonce, TBip327Vectors.GetSignVerify.Sk, LSessionCtx, LPsig),
        Format('Sign invalid secnonce case %d', [LI]))
    else
    begin
      try
        if TBip327MuSig2.Sign(LDomain, LSecnonce, TBip327Vectors.GetSignVerify.Sk, LSessionCtx, LPsig) then
          Fail(Format('Sign error case %d should fail', [LI]));
      except
        on E: EArgumentCryptoLibException do
          Check(Pos('pubkey', LowerCase(E.Message)) > 0, 'sign_error pubkey message');
        else
          raise;
      end;
    end;
  end;
  for LI := 0 to System.High(TBip327Vectors.GetSignVerifyVerifyFails) do
  begin
    LFailCase := TBip327Vectors.GetSignVerifyVerifyFails[LI];
    Check(not TBip327MuSig2.PartialSigVerify(LDomain, LFailCase.Sig, LFailCase.NoncesForSession,
      LFailCase.Keys, nil, nil, LFailCase.Msg, LFailCase.SignerIndex),
      Format('Verify fail case %d', [LI]));
  end;
  for LI := 0 to System.High(TBip327Vectors.GetSignVerifyVerifyErrors) do
  begin
    LVerifyErrorCase := TBip327Vectors.GetSignVerifyVerifyErrors[LI];
    try
      TBip327MuSig2.PartialSigVerify(LDomain, LVerifyErrorCase.Sig, LVerifyErrorCase.NoncesForSession,
        LVerifyErrorCase.Keys, nil, nil, LVerifyErrorCase.Msg, LVerifyErrorCase.SignerIndex);
      Fail(Format('Verify error case %d should raise', [LI]));
    except
      on E: EBip327InvalidContributionException do
        ExpectInvalidContribution(E, LVerifyErrorCase.ExpectedSigner, LVerifyErrorCase.ExpectedContrib);
      else
        raise;
    end;
  end;
end;

procedure TTestBip327MuSig2.TestSigAggVectors;
var
  LDomain: IECDomainParameters;
  LCase: TBip327SigAggValidCase;
  LErrorCase: TBip327SigAggErrorCase;
  LSessionCtx: TBip327SessionContext;
  LCtx: IBip327KeyAggContext;
  LAggsig, LAggPk: TCryptoLibByteArray;
  LI, LT: Int32;
begin
  LDomain := Secp256k1Domain();
  for LI := 0 to System.High(TBip327Vectors.GetSigAggValid) do
  begin
    LCase := TBip327Vectors.GetSigAggValid[LI];
    LSessionCtx.AggNonce := LCase.AggNonce;
    LSessionCtx.PubKeys := LCase.Keys;
    if LCase.HasTweaks then
    begin
      LSessionCtx.Tweaks := LCase.TweakBytes;
      LSessionCtx.IsXOnlyT := LCase.IsXonly;
    end
    else
    begin
      LSessionCtx.Tweaks := nil;
      LSessionCtx.IsXOnlyT := nil;
    end;
    LSessionCtx.Msg := TBip327Vectors.GetSigAgg.Msg;
    LAggsig := TBip327MuSig2.PartialSigAgg(LDomain, LCase.Psigs, LSessionCtx);
    Check(AreEqual(LAggsig, LCase.Expected), Format('SigAgg valid case %d', [LI]));
    LCtx := TBip327MuSig2KeyAggregation.KeyAgg(LDomain, LSessionCtx.PubKeys);
    if LSessionCtx.Tweaks <> nil then
      for LT := 0 to System.Length(LSessionCtx.Tweaks) - 1 do
        LCtx := TBip327MuSig2KeyAggregation.ApplyTweak(LCtx, LSessionCtx.Tweaks[LT],
          LSessionCtx.IsXOnlyT[LT]);
    LAggPk := LCtx.GetXOnlyPubKey();
    VerifyAggSigBip340(LSessionCtx.Msg, LAggPk, LAggsig, Format('SigAgg valid case %d', [LI]));
  end;
  for LI := 0 to System.High(TBip327Vectors.GetSigAggErrors) do
  begin
    LErrorCase := TBip327Vectors.GetSigAggErrors[LI];
    LSessionCtx.AggNonce := LErrorCase.AggNonce;
    LSessionCtx.PubKeys := LErrorCase.Keys;
    LSessionCtx.Tweaks := LErrorCase.TweakBytes;
    LSessionCtx.IsXOnlyT := LErrorCase.IsXonly;
    LSessionCtx.Msg := TBip327Vectors.GetSigAgg.Msg;
    try
      TBip327MuSig2.PartialSigAgg(LDomain, LErrorCase.Psigs, LSessionCtx);
      Fail(Format('SigAgg error case %d should raise', [LI]));
    except
      on E: EBip327InvalidContributionException do
        ExpectInvalidContribution(E, LErrorCase.ExpectedSigner, LErrorCase.ExpectedContrib);
      else
        raise;
    end;
  end;
end;

procedure TTestBip327MuSig2.TestDetSignVectors;
var
  LDomain: IECDomainParameters;
  LCase: TBip327DetSignValidCase;
  LErrorCase: TBip327DetSignErrorCase;
  LPubnonce, LPsig: TCryptoLibByteArray;
  LI: Int32;
begin
  LDomain := Secp256k1Domain();
  for LI := 0 to System.High(TBip327Vectors.GetDetSignValid) do
  begin
    LCase := TBip327Vectors.GetDetSignValid[LI];
    Check(TBip327MuSig2.DeterministicSign(LDomain, TBip327Vectors.GetDetSign.Sk, LCase.AggOtherNonce,
      LCase.Keys, LCase.Tweaks, LCase.IsXonly, LCase.Msg, LCase.RandBytes, LPubnonce, LPsig),
      Format('DetSign valid case %d', [LI]));
    Check(AreEqual(LPubnonce, LCase.ExpectedPubnonce), Format('DetSign pubnonce case %d', [LI]));
    Check(AreEqual(LPsig, LCase.ExpectedPsig), Format('DetSign psig case %d', [LI]));
  end;
  for LI := 0 to System.High(TBip327Vectors.GetDetSignErrors) do
  begin
    LErrorCase := TBip327Vectors.GetDetSignErrors[LI];
    try
      TBip327MuSig2.DeterministicSign(LDomain, TBip327Vectors.GetDetSign.Sk, LErrorCase.AggOtherNonce,
        LErrorCase.Keys, LErrorCase.Tweaks, LErrorCase.IsXonly, LErrorCase.Msg,
        LErrorCase.RandBytes, LPubnonce, LPsig);
      Fail(Format('DetSign error case %d should raise', [LI]));
    except
      on E: EBip327InvalidContributionException do
      begin
        if LErrorCase.ExpectAggOtherNonceMapping then
        begin
          Check((E.SignerIndex = -1) or (E.SignerIndex = 0), 'aggothernonce error signer index');
          Check(E.Contribution = 'pubnonce', 'aggothernonce error contrib');
        end
        else
          ExpectInvalidContribution(E, LErrorCase.ExpectedSigner, LErrorCase.ExpectedContrib);
      end;
      on E: EArgumentCryptoLibException do
      begin
        if LErrorCase.Kind = TBip327DetSignErrorCaseKind.TweakValue then
          Check(True, 'DetSign tweak error')
        else if LErrorCase.Kind = TBip327DetSignErrorCaseKind.PubkeyValue then
          Check(True, 'DetSign pubkey error')
        else
          raise;
      end;
      else
        raise;
    end;
  end;
end;
procedure TTestBip327MuSig2.TestSignAndVerifyRandom;
var
  LDomain: IECDomainParameters;
  LRandom: ISecureRandom;
  LKpg: IAsymmetricCipherKeyPairGenerator;
  LKeyPair: IAsymmetricCipherKeyPair;
  LPubkeys: TCryptoLibGenericArray<TCryptoLibByteArray>;
  LSk1, LSk2, LSk3: TCryptoLibByteArray;
  LPk1, LPk2, LPk3: TCryptoLibByteArray;
  LSecnonces: TCryptoLibGenericArray<TCryptoLibByteArray>;
  LPubnonces: TCryptoLibGenericArray<TCryptoLibByteArray>;
  LPsigs: TCryptoLibGenericArray<TCryptoLibByteArray>;
  LCtx: IBip327KeyAggContext;
  AggPk: TCryptoLibByteArray;
  LSessionCtx: TBip327SessionContext;
  LMsg: TCryptoLibByteArray;
  AggSig: TCryptoLibByteArray;
  LI, LIterations: Int32;
  LAggOtherNonce: TCryptoLibByteArray;
  LMsgProvided: Boolean;
begin
  // Multi-iteration random MuSig2 sign and verify (mirrors ref test_sign_and_verify_random).
  LDomain := Secp256k1Domain();
  LRandom := TSecureRandom.Create();
  LKpg := TGeneratorUtilities.GetKeyPairGenerator('BIP340Schnorr');
  LKpg.Init(TKeyGenerationParameters.Create(LRandom, 256) as IKeyGenerationParameters);
  LIterations := 6;

  for LI := 0 to LIterations - 1 do
  begin
    // Generate 3 signers
    LKeyPair := LKpg.GenerateKeyPair();
    LSk1 := (LKeyPair.Private as IBip340SchnorrPrivateKeyParameters).GetEncoded();
    LPk1 := TBip327MuSig2Utilities.IndividualPubKey(LDomain, LSk1);
    LKeyPair := LKpg.GenerateKeyPair();
    LSk2 := (LKeyPair.Private as IBip340SchnorrPrivateKeyParameters).GetEncoded();
    LPk2 := TBip327MuSig2Utilities.IndividualPubKey(LDomain, LSk2);
    LKeyPair := LKpg.GenerateKeyPair();
    LSk3 := (LKeyPair.Private as IBip340SchnorrPrivateKeyParameters).GetEncoded();
    LPk3 := TBip327MuSig2Utilities.IndividualPubKey(LDomain, LSk3);

    LPubkeys := TCryptoLibGenericArray<TCryptoLibByteArray>.Create(LPk1, LPk2, LPk3);
    LCtx := TBip327MuSig2KeyAggregation.KeyAgg(LDomain, LPubkeys);
    AggPk := LCtx.GetXOnlyPubKey();

    // Random message (variable length)
    LMsg := nil;
    System.SetLength(LMsg, 20 + (LI mod 40));
    LRandom.NextBytes(LMsg);
    LMsgProvided := True;

    // NonceGen for all three
    LSecnonces := nil;
    LPubnonces := nil;
    System.SetLength(LSecnonces, 3);
    System.SetLength(LPubnonces, 3);
    Check(TBip327MuSig2.NonceGen(LDomain, LSk1, LPk1, AggPk, LMsg, LMsgProvided, nil, LRandom, LSecnonces[0], LPubnonces[0]), 'NonceGen 1');
    Check(TBip327MuSig2.NonceGen(LDomain, LSk2, LPk2, AggPk, LMsg, LMsgProvided, nil, LRandom, LSecnonces[1], LPubnonces[1]), 'NonceGen 2');
    Check(TBip327MuSig2.NonceGen(LDomain, LSk3, LPk3, AggPk, LMsg, LMsgProvided, nil, LRandom, LSecnonces[2], LPubnonces[2]), 'NonceGen 3');

    LSessionCtx.AggNonce := TBip327MuSig2.NonceAgg(LDomain, LPubnonces);
    LSessionCtx.PubKeys := LPubkeys;
    LSessionCtx.Tweaks := nil;
    LSessionCtx.IsXOnlyT := nil;
    LSessionCtx.Msg := LMsg;

    // Partial sign
    LPsigs := nil;
    System.SetLength(LPsigs, 3);
    Check(TBip327MuSig2.Sign(LDomain, LSecnonces[0], LSk1, LSessionCtx, LPsigs[0]), 'Sign 1');
    Check(TBip327MuSig2.Sign(LDomain, LSecnonces[1], LSk2, LSessionCtx, LPsigs[1]), 'Sign 2');
    Check(TBip327MuSig2.Sign(LDomain, LSecnonces[2], LSk3, LSessionCtx, LPsigs[2]), 'Sign 3');

    AggSig := TBip327MuSig2.PartialSigAgg(LDomain, LPsigs, LSessionCtx);
    Check(System.Length(AggSig) = 64, 'agg sig length');
    VerifyAggSigBip340(LMsg, AggPk, AggSig, 'TestSignAndVerifyRandom iteration ' + IntToStr(LI));
  end;

  // One iteration with DeterministicSign for last signer
  LKeyPair := LKpg.GenerateKeyPair();
  LSk1 := (LKeyPair.Private as IBip340SchnorrPrivateKeyParameters).GetEncoded();
  LPk1 := TBip327MuSig2Utilities.IndividualPubKey(LDomain, LSk1);
  LKeyPair := LKpg.GenerateKeyPair();
  LSk2 := (LKeyPair.Private as IBip340SchnorrPrivateKeyParameters).GetEncoded();
  LPk2 := TBip327MuSig2Utilities.IndividualPubKey(LDomain, LSk2);
  LKeyPair := LKpg.GenerateKeyPair();
  LSk3 := (LKeyPair.Private as IBip340SchnorrPrivateKeyParameters).GetEncoded();
  LPk3 := TBip327MuSig2Utilities.IndividualPubKey(LDomain, LSk3);
  LPubkeys := TCryptoLibGenericArray<TCryptoLibByteArray>.Create(LPk1, LPk2, LPk3);
  LCtx := TBip327MuSig2KeyAggregation.KeyAgg(LDomain, LPubkeys);
  AggPk := LCtx.GetXOnlyPubKey();
  LMsg := nil;
  System.SetLength(LMsg, 32);
  LRandom.NextBytes(LMsg);
  LSecnonces := nil;
  LPubnonces := nil;
  System.SetLength(LSecnonces, 2);
  System.SetLength(LPubnonces, 3);
  Check(TBip327MuSig2.NonceGen(LDomain, LSk1, LPk1, AggPk, LMsg, True, nil, LRandom, LSecnonces[0], LPubnonces[0]), 'DetSign NonceGen 1');
  Check(TBip327MuSig2.NonceGen(LDomain, LSk2, LPk2, AggPk, LMsg, True, nil, LRandom, LSecnonces[1], LPubnonces[1]), 'DetSign NonceGen 2');
  LAggOtherNonce := TBip327MuSig2.NonceAgg(LDomain, TCryptoLibGenericArray<TCryptoLibByteArray>.Create(LPubnonces[0], LPubnonces[1]));
  LPsigs := nil;
  System.SetLength(LPsigs, 3);
  Check(TBip327MuSig2.DeterministicSign(LDomain, LSk3, LAggOtherNonce, LPubkeys, nil, nil, LMsg, nil, LPubnonces[2], LPsigs[2]), 'DeterministicSign last');
  LSessionCtx.AggNonce := TBip327MuSig2.NonceAgg(LDomain, LPubnonces);
  LSessionCtx.PubKeys := LPubkeys;
  LSessionCtx.Tweaks := nil;
  LSessionCtx.IsXOnlyT := nil;
  LSessionCtx.Msg := LMsg;
  Check(TBip327MuSig2.Sign(LDomain, LSecnonces[0], LSk1, LSessionCtx, LPsigs[0]), 'DetSign Sign 1');
  Check(TBip327MuSig2.Sign(LDomain, LSecnonces[1], LSk2, LSessionCtx, LPsigs[1]), 'DetSign Sign 2');
  AggSig := TBip327MuSig2.PartialSigAgg(LDomain, LPsigs, LSessionCtx);
  VerifyAggSigBip340(LMsg, AggPk, AggSig, 'TestSignAndVerifyRandom DeterministicSign');

  // Secnonce reuse: second Sign with same (zeroed) secnonce buffer must return False
  LKeyPair := LKpg.GenerateKeyPair();
  LSk1 := (LKeyPair.Private as IBip340SchnorrPrivateKeyParameters).GetEncoded();
  LPk1 := TBip327MuSig2Utilities.IndividualPubKey(LDomain, LSk1);
  LKeyPair := LKpg.GenerateKeyPair();
  LSk2 := (LKeyPair.Private as IBip340SchnorrPrivateKeyParameters).GetEncoded();
  LPk2 := TBip327MuSig2Utilities.IndividualPubKey(LDomain, LSk2);
  LPubkeys := TCryptoLibGenericArray<TCryptoLibByteArray>.Create(LPk1, LPk2);
  LCtx := TBip327MuSig2KeyAggregation.KeyAgg(LDomain, LPubkeys);
  AggPk := LCtx.GetXOnlyPubKey();
  LMsg := nil;
  System.SetLength(LMsg, 32);
  LRandom.NextBytes(LMsg);
  LSecnonces := nil;
  LPubnonces := nil;
  System.SetLength(LSecnonces, 2);
  System.SetLength(LPubnonces, 2);
  Check(TBip327MuSig2.NonceGen(LDomain, LSk1, LPk1, AggPk, LMsg, True, nil, LRandom, LSecnonces[0], LPubnonces[0]), 'Reuse NonceGen 1');
  Check(TBip327MuSig2.NonceGen(LDomain, LSk2, LPk2, AggPk, LMsg, True, nil, LRandom, LSecnonces[1], LPubnonces[1]), 'Reuse NonceGen 2');
  LSessionCtx.AggNonce := TBip327MuSig2.NonceAgg(LDomain, LPubnonces);
  LSessionCtx.PubKeys := LPubkeys;
  LSessionCtx.Tweaks := nil;
  LSessionCtx.IsXOnlyT := nil;
  LSessionCtx.Msg := LMsg;
  LPsigs := nil;
  System.SetLength(LPsigs, 2);
  Check(TBip327MuSig2.Sign(LDomain, LSecnonces[0], LSk1, LSessionCtx, LPsigs[0]), 'Reuse first Sign');
  Check(not TBip327MuSig2.Sign(LDomain, LSecnonces[0], LSk1, LSessionCtx, LPsigs[1]), 'Secnonce reuse must return False');

  // Wrong message: aggregate sig for LMsg, verify with different message must fail
  LKeyPair := LKpg.GenerateKeyPair();
  LSk1 := (LKeyPair.Private as IBip340SchnorrPrivateKeyParameters).GetEncoded();
  LPk1 := TBip327MuSig2Utilities.IndividualPubKey(LDomain, LSk1);
  LKeyPair := LKpg.GenerateKeyPair();
  LSk2 := (LKeyPair.Private as IBip340SchnorrPrivateKeyParameters).GetEncoded();
  LPk2 := TBip327MuSig2Utilities.IndividualPubKey(LDomain, LSk2);
  LPubkeys := TCryptoLibGenericArray<TCryptoLibByteArray>.Create(LPk1, LPk2);
  LCtx := TBip327MuSig2KeyAggregation.KeyAgg(LDomain, LPubkeys);
  AggPk := LCtx.GetXOnlyPubKey();
  LMsg := TConverters.ConvertStringToBytes('correct message', TEncoding.UTF8);
  LSecnonces := nil;
  LPubnonces := nil;
  System.SetLength(LSecnonces, 2);
  System.SetLength(LPubnonces, 2);
  Check(TBip327MuSig2.NonceGen(LDomain, LSk1, LPk1, AggPk, LMsg, True, nil, LRandom, LSecnonces[0], LPubnonces[0]), 'WrongMsg NonceGen 1');
  Check(TBip327MuSig2.NonceGen(LDomain, LSk2, LPk2, AggPk, LMsg, True, nil, LRandom, LSecnonces[1], LPubnonces[1]), 'WrongMsg NonceGen 2');
  LSessionCtx.AggNonce := TBip327MuSig2.NonceAgg(LDomain, LPubnonces);
  LSessionCtx.PubKeys := LPubkeys;
  LSessionCtx.Tweaks := nil;
  LSessionCtx.IsXOnlyT := nil;
  LSessionCtx.Msg := LMsg;
  LPsigs := nil;
  System.SetLength(LPsigs, 2);
  Check(TBip327MuSig2.Sign(LDomain, LSecnonces[0], LSk1, LSessionCtx, LPsigs[0]), 'WrongMsg Sign 1');
  Check(TBip327MuSig2.Sign(LDomain, LSecnonces[1], LSk2, LSessionCtx, LPsigs[1]), 'WrongMsg Sign 2');
  AggSig := TBip327MuSig2.PartialSigAgg(LDomain, LPsigs, LSessionCtx);
  VerifyAggSigBip340(LMsg, AggPk, AggSig, 'WrongMsg correct');
  Check(not TBip327MuSig2.PartialSigVerify(LDomain, LPsigs[0], LPubnonces, LPubkeys, nil, nil, TConverters.ConvertStringToBytes('wrong message', TEncoding.UTF8), 0), 'Wrong message verify must fail');
end;

procedure TTestBip327MuSig2.TestServerClientMuSig2;
var
  LDomain: IECDomainParameters;
  LRandom: ISecureRandom;
  LKpg: IAsymmetricCipherKeyPairGenerator;
  LKeyPair: IAsymmetricCipherKeyPair;
  // --- Client (Alice): keys and nonces; secret material stays on device
  AliceSk, BobSk, CharlieSk: TCryptoLibByteArray;
  AlicePlainPubkey, BobPlainPubkey, CharliePlainPubkey: TCryptoLibByteArray;
  AliceSecnonce, BobSecnonce, CharlieSecnonce: TCryptoLibByteArray;
  AlicePubnonce, BobPubnonce, CharliePubnonce: TCryptoLibByteArray;
  AlicePsig, BobPsig, CharliePsig: TCryptoLibByteArray;
  // --- Sent to server (or exchanged): plain pubkeys, pubnonces, then session, then partial sigs
  LPubkeys: TCryptoLibGenericArray<TCryptoLibByteArray>;
  LPubnonces: TCryptoLibGenericArray<TCryptoLibByteArray>;
  LPsigs: TCryptoLibGenericArray<TCryptoLibByteArray>;
  // --- Server: aggregated values and session
  LCtx: IBip327KeyAggContext;
  AggPk: TCryptoLibByteArray;
  LSessionCtx: TBip327SessionContext;
  LMsg: TCryptoLibByteArray;
  AggSig: TCryptoLibByteArray;
begin
  // Real-world MuSig2 in a server/client model: clients hold secrets and send only
  // public data; server coordinates key agg, nonce agg, session broadcast, partial sig agg, verify.
  LDomain := Secp256k1Domain();
  LRandom := TSecureRandom.Create();
  LKpg := TGeneratorUtilities.GetKeyPairGenerator('BIP340Schnorr');
  LKpg.Init(TKeyGenerationParameters.Create(LRandom, 256) as IKeyGenerationParameters);

  // ---------- Client (Alice): key pair ----------
  // Stays on device: AliceSk. Sent to server: AlicePlainPubkey (33-byte for key agg).
  LKeyPair := LKpg.GenerateKeyPair();
  AliceSk := (LKeyPair.Private as IBip340SchnorrPrivateKeyParameters).GetEncoded();
  AlicePlainPubkey := TBip327MuSig2Utilities.IndividualPubKey(LDomain, AliceSk);

  // ---------- Client (Bob): key pair ----------
  LKeyPair := LKpg.GenerateKeyPair();
  BobSk := (LKeyPair.Private as IBip340SchnorrPrivateKeyParameters).GetEncoded();
  BobPlainPubkey := TBip327MuSig2Utilities.IndividualPubKey(LDomain, BobSk);

  // ---------- Client (Charlie): key pair ----------
  LKeyPair := LKpg.GenerateKeyPair();
  CharlieSk := (LKeyPair.Private as IBip340SchnorrPrivateKeyParameters).GetEncoded();
  CharliePlainPubkey := TBip327MuSig2Utilities.IndividualPubKey(LDomain, CharlieSk);

  // ---------- Server: key aggregation ----------
  // Receives from clients: AlicePlainPubkey, BobPlainPubkey, CharliePlainPubkey (sent across).
  LPubkeys := TCryptoLibGenericArray<TCryptoLibByteArray>.Create(AlicePlainPubkey, BobPlainPubkey, CharliePlainPubkey);
  LCtx := TBip327MuSig2KeyAggregation.KeyAgg(LDomain, LPubkeys);
  AggPk := LCtx.GetXOnlyPubKey();
  Check(System.Length(AggPk) = TBip340SchnorrUtilities.BIP340_PUBKEY_SIZE, 'aggregate pubkey must be 32 bytes');
  // Server sends AggPk (or session later) to clients so they can generate nonces and sign.

  LMsg := TConverters.ConvertStringToBytes('Real-world MuSig2 test message', TEncoding.UTF8);

  // ---------- Client (Alice): nonce generation ----------
  // Stays on device: AliceSecnonce. Sent to server: AlicePubnonce.
  Check(TBip327MuSig2.NonceGen(LDomain, AliceSk, AlicePlainPubkey, AggPk, LMsg, True, nil, LRandom,
    AliceSecnonce, AlicePubnonce), 'Alice NonceGen');

  // ---------- Client (Bob): nonce generation ----------
  Check(TBip327MuSig2.NonceGen(LDomain, BobSk, BobPlainPubkey, AggPk, LMsg, True, nil, LRandom,
    BobSecnonce, BobPubnonce), 'Bob NonceGen');

  // ---------- Client (Charlie): nonce generation ----------
  Check(TBip327MuSig2.NonceGen(LDomain, CharlieSk, CharliePlainPubkey, AggPk, LMsg, True, nil, LRandom,
    CharlieSecnonce, CharliePubnonce), 'Charlie NonceGen');

  // ---------- Server: nonce aggregation and session ----------
  // Receives from clients: AlicePubnonce, BobPubnonce, CharliePubnonce (sent across).
  LPubnonces := TCryptoLibGenericArray<TCryptoLibByteArray>.Create(AlicePubnonce, BobPubnonce, CharliePubnonce);
  LSessionCtx.AggNonce := TBip327MuSig2.NonceAgg(LDomain, LPubnonces);
  LSessionCtx.PubKeys := LPubkeys;
  LSessionCtx.Tweaks := nil;
  LSessionCtx.IsXOnlyT := nil;
  LSessionCtx.Msg := LMsg;
  // Server sends session (agg_nonce, pubkeys, msg, tweaks) to clients so they can produce partial sigs.

  // ---------- Client (Alice): partial sign ----------
  // Stays on device: AliceSk, AliceSecnonce (consumed). Sent to server: AlicePsig.
  Check(TBip327MuSig2.Sign(LDomain, AliceSecnonce, AliceSk, LSessionCtx, AlicePsig), 'Alice Sign');

  // ---------- Client (Bob): partial sign ----------
  Check(TBip327MuSig2.Sign(LDomain, BobSecnonce, BobSk, LSessionCtx, BobPsig), 'Bob Sign');

  // ---------- Client (Charlie): partial sign ----------
  Check(TBip327MuSig2.Sign(LDomain, CharlieSecnonce, CharlieSk, LSessionCtx, CharliePsig), 'Charlie Sign');

  // ---------- Server: partial sig aggregation and verify ----------
  // Receives from clients: AlicePsig, BobPsig, CharliePsig (sent across).
  LPsigs := TCryptoLibGenericArray<TCryptoLibByteArray>.Create(AlicePsig, BobPsig, CharliePsig);
  AggSig := TBip327MuSig2.PartialSigAgg(LDomain, LPsigs, LSessionCtx);
  Check(System.Length(AggSig) = 64, 'aggregate signature must be 64 bytes');
  VerifyAggSigBip340(LMsg, AggPk, AggSig, 'Real-world MuSig2');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestBip327MuSig2);
{$ELSE}
  RegisterTest(TTestBip327MuSig2.Suite);
{$ENDIF FPC}

end.
