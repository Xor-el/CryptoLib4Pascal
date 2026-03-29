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

(* BIP-327 MuSig2 tests with embedded vectors from https://github.com/bitcoin/bips/tree/master/bip-0327 *)

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
  ClpFixedSecureRandom,
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
  CryptoLibTestBase;

type
  TTestBip327MuSig2 = class(TCryptoLibAlgorithmTestCase)
  private
    function Secp256k1Domain: IECDomainParameters;
    procedure VerifyAggSigBip340(const AMsg, AAggPk, AAggsig: TCryptoLibByteArray;
      const ACheckMessage: string);
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
  LPubkeys, LSorted: TCryptoLibGenericArray<TCryptoLibByteArray>;
  I: Int32;
  LHexPubkeys: array[0..5] of String;
  LHexSorted: array[0..5] of String;
begin
  LHexPubkeys[0] := '02DD308AFEC5777E13121FA72B9CC1B7CC0139715309B086C960E18FD969774EB8';
  LHexPubkeys[1] := '02F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9';
  LHexPubkeys[2] := '03DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659';
  LHexPubkeys[3] := '023590A94E768F8E1815C2F24B4D80A8E3149316C3518CE7B7AD338368D038CA66';
  LHexPubkeys[4] := '02DD308AFEC5777E13121FA72B9CC1B7CC0139715309B086C960E18FD969774EFF';
  LHexPubkeys[5] := '02DD308AFEC5777E13121FA72B9CC1B7CC0139715309B086C960E18FD969774EB8';
  LHexSorted[0] := '023590A94E768F8E1815C2F24B4D80A8E3149316C3518CE7B7AD338368D038CA66';
  LHexSorted[1] := '02DD308AFEC5777E13121FA72B9CC1B7CC0139715309B086C960E18FD969774EB8';
  LHexSorted[2] := '02DD308AFEC5777E13121FA72B9CC1B7CC0139715309B086C960E18FD969774EB8';
  LHexSorted[3] := '02DD308AFEC5777E13121FA72B9CC1B7CC0139715309B086C960E18FD969774EFF';
  LHexSorted[4] := '02F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9';
  LHexSorted[5] := '03DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659';
  LPubkeys := TCryptoLibGenericArray<TCryptoLibByteArray>.Create(
    DecodeHex(LHexPubkeys[0]), DecodeHex(LHexPubkeys[1]), DecodeHex(LHexPubkeys[2]),
    DecodeHex(LHexPubkeys[3]), DecodeHex(LHexPubkeys[4]), DecodeHex(LHexPubkeys[5]));
  LSorted := TBip327MuSig2KeyAggregation.KeySort(LPubkeys);
  for I := 0 to 5 do
    Check(AreEqual(LSorted[I], DecodeHex(LHexSorted[I])), Format('KeySort vector index %d', [I]));
end;

procedure TTestBip327MuSig2.TestKeyAggVectors;
var
  LDomain: IECDomainParameters;
  LPubkeys: TCryptoLibGenericArray<TCryptoLibByteArray>;
  LTweaks: TCryptoLibGenericArray<TCryptoLibByteArray>;
  LHexPubkeys: array[0..6] of String;
  LHexTweaks: array[0..1] of String;
  LExpected: String;
  LPks: TCryptoLibGenericArray<TCryptoLibByteArray>;
  LCtx: IBip327KeyAggContext;
begin
  LDomain := Secp256k1Domain();
  LHexPubkeys[0] := '02F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9';
  LHexPubkeys[1] := '03DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659';
  LHexPubkeys[2] := '023590A94E768F8E1815C2F24B4D80A8E3149316C3518CE7B7AD338368D038CA66';
  LHexPubkeys[3] := '020000000000000000000000000000000000000000000000000000000000000005';
  LHexPubkeys[4] := '02FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC30';
  LHexPubkeys[5] := '04F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9';
  LHexPubkeys[6] := '03935F972DA013F80AE011890FA89B67A27B7BE6CCB24D3274D18B2D4067F261A9';
  LHexTweaks[0] := 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141';
  LHexTweaks[1] := '252E4BD67410A76CDF933D30EAA1608214037F1B105A013ECCD3C5C184A6110B';
  LPubkeys := TCryptoLibGenericArray<TCryptoLibByteArray>.Create(
    DecodeHex(LHexPubkeys[0]), DecodeHex(LHexPubkeys[1]), DecodeHex(LHexPubkeys[2]),
    DecodeHex(LHexPubkeys[3]), DecodeHex(LHexPubkeys[4]), DecodeHex(LHexPubkeys[5]),
    DecodeHex(LHexPubkeys[6]));
  LTweaks := TCryptoLibGenericArray<TCryptoLibByteArray>.Create(
    DecodeHex(LHexTweaks[0]), DecodeHex(LHexTweaks[1]));
  // valid: key_indices [0,1,2] -> expected
  LPks := TCryptoLibGenericArray<TCryptoLibByteArray>.Create(LPubkeys[0], LPubkeys[1], LPubkeys[2]);
  LCtx := TBip327MuSig2KeyAggregation.KeyAgg(LDomain, LPks);
  LExpected := '90539EEDE565F5D054F32CC0C220126889ED1E5D193BAF15AEF344FE59D4610C';
  Check(AreEqual(LCtx.GetXOnlyPubKey(), DecodeHex(LExpected)), 'KeyAgg valid [0,1,2]');
  // valid: [2,1,0]
  LPks := TCryptoLibGenericArray<TCryptoLibByteArray>.Create(LPubkeys[2], LPubkeys[1], LPubkeys[0]);
  LCtx := TBip327MuSig2KeyAggregation.KeyAgg(LDomain, LPks);
  LExpected := '6204DE8B083426DC6EAF9502D27024D53FC826BF7D2012148A0575435DF54B2B';
  Check(AreEqual(LCtx.GetXOnlyPubKey(), DecodeHex(LExpected)), 'KeyAgg valid [2,1,0]');
  // valid: [0,0,0]
  LPks := TCryptoLibGenericArray<TCryptoLibByteArray>.Create(LPubkeys[0], LPubkeys[0], LPubkeys[0]);
  LCtx := TBip327MuSig2KeyAggregation.KeyAgg(LDomain, LPks);
  LExpected := 'B436E3BAD62B8CD409969A224731C193D051162D8C5AE8B109306127DA3AA935';
  Check(AreEqual(LCtx.GetXOnlyPubKey(), DecodeHex(LExpected)), 'KeyAgg valid [0,0,0]');
  // valid: [0,0,1,1]
  LPks := TCryptoLibGenericArray<TCryptoLibByteArray>.Create(LPubkeys[0], LPubkeys[0], LPubkeys[1], LPubkeys[1]);
  LCtx := TBip327MuSig2KeyAggregation.KeyAgg(LDomain, LPks);
  LExpected := '69BC22BFA5D106306E48A20679DE1D7389386124D07571D0D872686028C26A3E';
  Check(AreEqual(LCtx.GetXOnlyPubKey(), DecodeHex(LExpected)), 'KeyAgg valid [0,0,1,1]');
  // error: [0,3] invalid pubkey -> invalid_contribution signer 1 pubkey
  try
    LPks := TCryptoLibGenericArray<TCryptoLibByteArray>.Create(LPubkeys[0], LPubkeys[3]);
    TBip327MuSig2KeyAggregation.KeyAgg(LDomain, LPks);
    Fail('KeyAgg [0,3] should raise');
  except
    on E: EBip327InvalidContributionException do
    begin
      Check(E.SignerIndex = 1, 'KeyAgg error signer index');
      Check(E.Contribution = 'pubkey', 'KeyAgg error contrib');
    end;
    else
      raise;
  end;
  // error: [0,4] pubkey exceeds field
  try
    LPks := TCryptoLibGenericArray<TCryptoLibByteArray>.Create(LPubkeys[0], LPubkeys[4]);
    TBip327MuSig2KeyAggregation.KeyAgg(LDomain, LPks);
    Fail('KeyAgg [0,4] should raise');
  except
    on E: EBip327InvalidContributionException do
      Check(E.SignerIndex = 1, 'KeyAgg error [0,4]');
    else
      raise;
  end;
  // error: [5,0] first byte not 2 or 3
  try
    LPks := TCryptoLibGenericArray<TCryptoLibByteArray>.Create(LPubkeys[5], LPubkeys[0]);
    TBip327MuSig2KeyAggregation.KeyAgg(LDomain, LPks);
    Fail('KeyAgg [5,0] should raise');
  except
    on E: EBip327InvalidContributionException do
      Check(E.SignerIndex = 0, 'KeyAgg error [5,0]');
    else
      raise;
  end;
  // error: [0,1] + tweak 0 (is_xonly true) -> tweak >= n
  try
    LPks := TCryptoLibGenericArray<TCryptoLibByteArray>.Create(LPubkeys[0], LPubkeys[1]);
    LCtx := TBip327MuSig2KeyAggregation.KeyAgg(LDomain, LPks);
    TBip327MuSig2KeyAggregation.ApplyTweak(LCtx, LTweaks[0], True);
    Fail('ApplyTweak tweak>=n should raise');
  except
    on E: EArgumentCryptoLibException do
      Check(Pos('tweak', LowerCase(E.Message)) > 0, 'tweak error message');
    else
      raise;
  end;
  // error: [6] + tweak 1 -> infinity
  try
    LPks := TCryptoLibGenericArray<TCryptoLibByteArray>.Create(LPubkeys[6]);
    LCtx := TBip327MuSig2KeyAggregation.KeyAgg(LDomain, LPks);
    TBip327MuSig2KeyAggregation.ApplyTweak(LCtx, LTweaks[1], False);
    Fail('ApplyTweak infinity should raise');
  except
    on E: EArgumentCryptoLibException do
      Check(Pos('infinity', LowerCase(E.Message)) > 0, 'infinity error message');
    else
      raise;
  end;
end;

procedure TTestBip327MuSig2.TestNonceGenVectors;
var
  LDomain: IECDomainParameters;
  LSk, LPk, LAggpk, LMsg, LExtraIn, LRandBytes: TCryptoLibByteArray;
  LSecnonce, LPubnonce: TCryptoLibByteArray;
  LExpectedSec, LExpectedPub: String;
  LFixedRand: ISecureRandom;
  LOk: Boolean;
begin
  LDomain := Secp256k1Domain();
  // Vector 1: with sk, aggpk, msg, extra_in, fixed rand_
  LSk := DecodeHex('0202020202020202020202020202020202020202020202020202020202020202');
  LPk := DecodeHex('024D4B6CD1361032CA9BD2AEB9D900AA4D45D9EAD80AC9423374C451A7254D0766');
  LAggpk := DecodeHex('0707070707070707070707070707070707070707070707070707070707070707');
  LMsg := DecodeHex('0101010101010101010101010101010101010101010101010101010101010101');
  LExtraIn := DecodeHex('0808080808080808080808080808080808080808080808080808080808080808');
  LRandBytes := DecodeHex('0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F');
  LFixedRand := TFixedSecureRandom.From(TCryptoLibMatrixByteArray.Create(LRandBytes));
  LOk := TBip327MuSig2.NonceGen(LDomain, LSk, LPk, LAggpk, LMsg, True, LExtraIn, LFixedRand, LSecnonce, LPubnonce);
  Check(LOk, 'NonceGen vector 1');
  LExpectedSec := 'B114E502BEAA4E301DD08A50264172C84E41650E6CB726B410C0694D59EFFB6495B5CAF28D045B973D63E3C99A44B807BDE375FD6CB39E46DC4A511708D0E9D2024D4B6CD1361032CA9BD2AEB9D900AA4D45D9EAD80AC9423374C451A7254D0766';
  LExpectedPub := '02F7BE7089E8376EB355272368766B17E88E7DB72047D05E56AA881EA52B3B35DF02C29C8046FDD0DED4C7E55869137200FBDBFE2EB654267B6D7013602CAED3115A';
  Check(AreEqual(LSecnonce, DecodeHex(LExpectedSec)), 'NonceGen vector 1 secnonce');
  Check(AreEqual(LPubnonce, DecodeHex(LExpectedPub)), 'NonceGen vector 1 pubnonce');
  // Vector 2: msg present but empty (BIP-327 distinguishes from "not present"; in Pascal nil = empty array so we pass AMsgProvided = True)
  LMsg := nil;
  LFixedRand := TFixedSecureRandom.From(TCryptoLibMatrixByteArray.Create(LRandBytes));
  LOk := TBip327MuSig2.NonceGen(LDomain, LSk, LPk, LAggpk, LMsg, True, LExtraIn, LFixedRand, LSecnonce, LPubnonce);
  Check(LOk, 'NonceGen vector 2');
  LExpectedSec := 'E862B068500320088138468D47E0E6F147E01B6024244AE45EAC40ACE5929B9F0789E051170B9E705D0B9EB49049A323BBBBB206D8E05C19F46C6228742AA7A9024D4B6CD1361032CA9BD2AEB9D900AA4D45D9EAD80AC9423374C451A7254D0766';
  LExpectedPub := '023034FA5E2679F01EE66E12225882A7A48CC66719B1B9D3B6C4DBD743EFEDA2C503F3FD6F01EB3A8E9CB315D73F1F3D287CAFBB44AB321153C6287F407600205109';
  Check(AreEqual(LSecnonce, DecodeHex(LExpectedSec)), 'NonceGen vector 2 secnonce');
  Check(AreEqual(LPubnonce, DecodeHex(LExpectedPub)), 'NonceGen vector 2 pubnonce');
  // Vector 3: 38-byte message (ref nonce_gen_vectors test_cases[2])
  LSk := DecodeHex('0202020202020202020202020202020202020202020202020202020202020202');
  LPk := DecodeHex('024D4B6CD1361032CA9BD2AEB9D900AA4D45D9EAD80AC9423374C451A7254D0766');
  LAggpk := DecodeHex('0707070707070707070707070707070707070707070707070707070707070707');
  LMsg := DecodeHex('2626262626262626262626262626262626262626262626262626262626262626262626262626');
  LExtraIn := DecodeHex('0808080808080808080808080808080808080808080808080808080808080808');
  LFixedRand := TFixedSecureRandom.From(TCryptoLibMatrixByteArray.Create(LRandBytes));
  LOk := TBip327MuSig2.NonceGen(LDomain, LSk, LPk, LAggpk, LMsg, True, LExtraIn, LFixedRand, LSecnonce, LPubnonce);
  Check(LOk, 'NonceGen vector 3 (38-byte msg)');
  LExpectedSec := '3221975ACBDEA6820EABF02A02B7F27D3A8EF68EE42787B88CBEFD9AA06AF3632EE85B1A61D8EF31126D4663A00DD96E9D1D4959E72D70FE5EBB6E7696EBA66F024D4B6CD1361032CA9BD2AEB9D900AA4D45D9EAD80AC9423374C451A7254D0766';
  LExpectedPub := '02E5BBC21C69270F59BD634FCBFA281BE9D76601295345112C58954625BF23793A021307511C79F95D38ACACFF1B4DA98228B77E65AA216AD075E9673286EFB4EAF3';
  Check(AreEqual(LSecnonce, DecodeHex(LExpectedSec)), 'NonceGen vector 3 secnonce');
  Check(AreEqual(LPubnonce, DecodeHex(LExpectedPub)), 'NonceGen vector 3 pubnonce');
  // Vector 4: sk null, aggpk null, msg null, extra_in null
  LSk := nil;
  LAggpk := nil;
  LMsg := nil;
  LExtraIn := nil;
  LPk := DecodeHex('02F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9');
  LRandBytes := DecodeHex('0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F');
  LFixedRand := TFixedSecureRandom.From(TCryptoLibMatrixByteArray.Create(LRandBytes));
  LOk := TBip327MuSig2.NonceGen(LDomain, LSk, LPk, LAggpk, LMsg, False, LExtraIn, LFixedRand, LSecnonce, LPubnonce);
  Check(LOk, 'NonceGen vector 4');
  LExpectedSec := '89BDD787D0284E5E4D5FC572E49E316BAB7E21E3B1830DE37DFE80156FA41A6D0B17AE8D024C53679699A6FD7944D9C4A366B514BAF43088E0708B1023DD289702F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9';
  LExpectedPub := '02C96E7CB1E8AA5DAC64D872947914198F607D90ECDE5200DE52978AD5DED63C000299EC5117C2D29EDEE8A2092587C3909BE694D5CFF0667D6C02EA4059F7CD9786';
  Check(AreEqual(LSecnonce, DecodeHex(LExpectedSec)), 'NonceGen vector 4 secnonce');
  Check(AreEqual(LPubnonce, DecodeHex(LExpectedPub)), 'NonceGen vector 4 pubnonce');
end;

procedure TTestBip327MuSig2.TestNonceAggVectors;
var
  LDomain: IECDomainParameters;
  LPnonces: TCryptoLibGenericArray<TCryptoLibByteArray>;
  LHexPnonces: array[0..6] of String;
  LExpected: String;
  LResult: TCryptoLibByteArray;
begin
  LDomain := Secp256k1Domain();
  LHexPnonces[0] := '020151C80F435648DF67A22B749CD798CE54E0321D034B92B709B567D60A42E66603BA47FBC1834437B3212E89A84D8425E7BF12E0245D98262268EBDCB385D50641';
  LHexPnonces[1] := '03FF406FFD8ADB9CD29877E4985014F66A59F6CD01C0E88CAA8E5F3166B1F676A60248C264CDD57D3C24D79990B0F865674EB62A0F9018277A95011B41BFC193B833';
  LHexPnonces[2] := '020151C80F435648DF67A22B749CD798CE54E0321D034B92B709B567D60A42E6660279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798';
  LHexPnonces[3] := '03FF406FFD8ADB9CD29877E4985014F66A59F6CD01C0E88CAA8E5F3166B1F676A60379BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798';
  LHexPnonces[4] := '04FF406FFD8ADB9CD29877E4985014F66A59F6CD01C0E88CAA8E5F3166B1F676A60248C264CDD57D3C24D79990B0F865674EB62A0F9018277A95011B41BFC193B833';
  LHexPnonces[5] := '03FF406FFD8ADB9CD29877E4985014F66A59F6CD01C0E88CAA8E5F3166B1F676A60248C264CDD57D3C24D79990B0F865674EB62A0F9018277A95011B41BFC193B831';
  LHexPnonces[6] := '03FF406FFD8ADB9CD29877E4985014F66A59F6CD01C0E88CAA8E5F3166B1F676A602FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC30';
  LPnonces := TCryptoLibGenericArray<TCryptoLibByteArray>.Create(
    DecodeHex(LHexPnonces[0]), DecodeHex(LHexPnonces[1]), DecodeHex(LHexPnonces[2]),
    DecodeHex(LHexPnonces[3]), DecodeHex(LHexPnonces[4]), DecodeHex(LHexPnonces[5]),
    DecodeHex(LHexPnonces[6]));
  // valid [0,1]
  LResult := TBip327MuSig2.NonceAgg(LDomain, TCryptoLibGenericArray<TCryptoLibByteArray>.Create(LPnonces[0], LPnonces[1]));
  LExpected := '035FE1873B4F2967F52FEA4A06AD5A8ECCBE9D0FD73068012C894E2E87CCB5804B024725377345BDE0E9C33AF3C43C0A29A9249F2F2956FA8CFEB55C8573D0262DC8';
  Check(AreEqual(LResult, DecodeHex(LExpected)), 'NonceAgg valid [0,1]');
  // valid [2,3] (R2 sum = infinity)
  LResult := TBip327MuSig2.NonceAgg(LDomain, TCryptoLibGenericArray<TCryptoLibByteArray>.Create(LPnonces[2], LPnonces[3]));
  LExpected := '035FE1873B4F2967F52FEA4A06AD5A8ECCBE9D0FD73068012C894E2E87CCB5804B000000000000000000000000000000000000000000000000000000000000000000';
  Check(AreEqual(LResult, DecodeHex(LExpected)), 'NonceAgg valid [2,3]');
  // error [0,4] invalid pubnonce signer 1
  try
    TBip327MuSig2.NonceAgg(LDomain, TCryptoLibGenericArray<TCryptoLibByteArray>.Create(LPnonces[0], LPnonces[4]));
    Fail('NonceAgg [0,4] should raise');
  except
    on E: EBip327InvalidContributionException do
    begin
      Check(E.SignerIndex = 1, 'NonceAgg error signer');
      Check(E.Contribution = 'pubnonce', 'NonceAgg error contrib');
    end;
    else
      raise;
  end;
  // error [5,1] invalid pubnonce signer 0
  try
    TBip327MuSig2.NonceAgg(LDomain, TCryptoLibGenericArray<TCryptoLibByteArray>.Create(LPnonces[5], LPnonces[1]));
    Fail('NonceAgg [5,1] should raise');
  except
    on E: EBip327InvalidContributionException do
      Check(E.SignerIndex = 0, 'NonceAgg error [5,1]');
    else
      raise;
  end;
  // error [6,1]
  try
    TBip327MuSig2.NonceAgg(LDomain, TCryptoLibGenericArray<TCryptoLibByteArray>.Create(LPnonces[6], LPnonces[1]));
    Fail('NonceAgg [6,1] should raise');
  except
    on E: EBip327InvalidContributionException do
      Check(E.SignerIndex = 0, 'NonceAgg error [6,1]');
    else
      raise;
  end;
end;

procedure TTestBip327MuSig2.TestTweakVectors;
var
  LDomain: IECDomainParameters;
  LSk, LSecnonce: TCryptoLibByteArray;
  LPubkeys, LPnonces, LTweaks: TCryptoLibGenericArray<TCryptoLibByteArray>;
  LMsg: TCryptoLibByteArray;
  LExpected: String;
  LSessionCtx: TBip327SessionContext;
  LPsig, LComputedAggNonce, LAggNonceFromVector: TCryptoLibByteArray;
begin
  LDomain := Secp256k1Domain();
  LSk := DecodeHex('7FB9E0E687ADA1EEBF7ECFE2F21E73EBDB51A7D450948DFE8D76D7F2D1007671');
  LSecnonce := DecodeHex('508B81A611F100A6B2B6B29656590898AF488BCF2E1F55CF22E5CFB84421FE61FA27FD49B1D50085B481285E1CA205D55C82CC1B31FF5CD54A489829355901F703935F972DA013F80AE011890FA89B67A27B7BE6CCB24D3274D18B2D4067F261A9');
  LPubkeys := TCryptoLibGenericArray<TCryptoLibByteArray>.Create(
    DecodeHex('03935F972DA013F80AE011890FA89B67A27B7BE6CCB24D3274D18B2D4067F261A9'),
    DecodeHex('02F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9'),
    DecodeHex('02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659'));
  LPnonces := TCryptoLibGenericArray<TCryptoLibByteArray>.Create(
    DecodeHex('0337C87821AFD50A8644D820A8F3E02E499C931865C2360FB43D0A0D20DAFE07EA0287BF891D2A6DEAEBADC909352AA9405D1428C15F4B75F04DAE642A95C2548480'),
    DecodeHex('0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F817980279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798'),
    DecodeHex('032DE2662628C90B03F5E720284EB52FF7D71F4284F627B68A853D78C78E1FFE9303E4C5524E83FFE1493B9077CF1CA6BEB2090C93D930321071AD40B2F44E599046'));
  LTweaks := TCryptoLibGenericArray<TCryptoLibByteArray>.Create(
    DecodeHex('E8F791FF9225A2AF0102AFFF4A9A723D9612A682A25EBE79802B263CDFCD83BB'),
    DecodeHex('AE2EA797CC0FE72AC5B97B97F3C6957D7E4199A167A58EB08BCAFFDA70AC0455'),
    DecodeHex('F52ECBC565B3D8BEA2DFD5B75A4F457E54369809322E4120831626F290FA87E0'),
    DecodeHex('1969AD73CC177FA0B4FCED6DF1F7BF9907E665FDE9BA196A74FED0A3CF5AEF9D'),
    DecodeHex('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141'));
  LMsg := DecodeHex('F95466D086770E689964664219266FE5ED215C92AE20BAB5C9D79ADDDDF3C0CF');

  LAggNonceFromVector := DecodeHex('028465FCF0BBDBCF443AABCCE533D42B4B5A10966AC09A49655E8C42DAAB8FCD61037496A3CC86926D452CAFCFD55D25972CA1675D549310DE296BFF42F72EEEA8C9');
  LComputedAggNonce := TBip327MuSig2.NonceAgg(LDomain, LPnonces);
  Check(AreEqual(LAggNonceFromVector, LComputedAggNonce), 'Computed Agg Nonce does not match that from vector');
  // valid: key_indices [1,2,0], nonce [1,2,0], tweak [0], is_xonly [true], signer 2 -> expected
  LSessionCtx.AggNonce := LAggNonceFromVector;
  LSessionCtx.PubKeys := TCryptoLibGenericArray<TCryptoLibByteArray>.Create(LPubkeys[1], LPubkeys[2], LPubkeys[0]);
  LSessionCtx.Tweaks := TCryptoLibGenericArray<TCryptoLibByteArray>.Create(LTweaks[0]);
  LSessionCtx.IsXOnlyT := TCryptoLibBooleanArray.Create(True);
  LSessionCtx.Msg := LMsg;
  LSecnonce := DecodeHex('508B81A611F100A6B2B6B29656590898AF488BCF2E1F55CF22E5CFB84421FE61FA27FD49B1D50085B481285E1CA205D55C82CC1B31FF5CD54A489829355901F703935F972DA013F80AE011890FA89B67A27B7BE6CCB24D3274D18B2D4067F261A9');
  Check(TBip327MuSig2.Sign(LDomain, LSecnonce, LSk, LSessionCtx, LPsig), 'Tweak vector sign');
  LExpected := 'E28A5C66E61E178C2BA19DB77B6CF9F7E2F0F56C17918CD13135E60CC848FE91';
  Check(AreEqual(LPsig, DecodeHex(LExpected)), 'Tweak vector 1 xonly psig');
  // valid: is_xonly [false] -> different expected
  LSessionCtx.IsXOnlyT := TCryptoLibBooleanArray.Create(False);
  LSecnonce := DecodeHex('508B81A611F100A6B2B6B29656590898AF488BCF2E1F55CF22E5CFB84421FE61FA27FD49B1D50085B481285E1CA205D55C82CC1B31FF5CD54A489829355901F703935F972DA013F80AE011890FA89B67A27B7BE6CCB24D3274D18B2D4067F261A9');
  Check(TBip327MuSig2.Sign(LDomain, LSecnonce, LSk, LSessionCtx, LPsig), 'Tweak vector plain');
  LExpected := '38B0767798252F21BF5702C48028B095428320F73A4B14DB1E25DE58543D2D2D';
  Check(AreEqual(LPsig, DecodeHex(LExpected)), 'Tweak vector 2 plain psig');
  // error: tweak index 4 (>= n)
  try
    LSessionCtx.Tweaks := TCryptoLibGenericArray<TCryptoLibByteArray>.Create(LTweaks[4]);
    LSessionCtx.IsXOnlyT := TCryptoLibBooleanArray.Create(False);
    LSecnonce := DecodeHex('508B81A611F100A6B2B6B29656590898AF488BCF2E1F55CF22E5CFB84421FE61FA27FD49B1D50085B481285E1CA205D55C82CC1B31FF5CD54A489829355901F703935F972DA013F80AE011890FA89B67A27B7BE6CCB24D3274D18B2D4067F261A9');
    TBip327MuSig2.Sign(LDomain, LSecnonce, LSk, LSessionCtx, LPsig);
    Fail('Tweak >= n should raise');
  except
    on E: EArgumentCryptoLibException do
      Check(Pos('tweak', LowerCase(E.Message)) > 0, 'tweak error');
    else
      raise;
  end;
end;

procedure TTestBip327MuSig2.TestSignVerifyVectors;
var
  LDomain: IECDomainParameters;
  LSk: TCryptoLibByteArray;
  LPubkeys, LSecnonces, LPnonces, LMsgs: TCryptoLibGenericArray<TCryptoLibByteArray>;
  LAggnonces: TCryptoLibGenericArray<TCryptoLibByteArray>;
  LExpected: String;
  LSessionCtx: TBip327SessionContext;
  LPsig: TCryptoLibByteArray;
  LPks: TCryptoLibGenericArray<TCryptoLibByteArray>;
  LPnoncesForSession: TCryptoLibGenericArray<TCryptoLibByteArray>;
  LI: Int32;
begin
  LDomain := Secp256k1Domain();
  LSk := DecodeHex('7FB9E0E687ADA1EEBF7ECFE2F21E73EBDB51A7D450948DFE8D76D7F2D1007671');
  LPubkeys := TCryptoLibGenericArray<TCryptoLibByteArray>.Create(
    DecodeHex('03935F972DA013F80AE011890FA89B67A27B7BE6CCB24D3274D18B2D4067F261A9'),
    DecodeHex('02F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9'),
    DecodeHex('02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA661'),
    DecodeHex('020000000000000000000000000000000000000000000000000000000000000007'));
  LSecnonces := TCryptoLibGenericArray<TCryptoLibByteArray>.Create(
    DecodeHex('508B81A611F100A6B2B6B29656590898AF488BCF2E1F55CF22E5CFB84421FE61FA27FD49B1D50085B481285E1CA205D55C82CC1B31FF5CD54A489829355901F703935F972DA013F80AE011890FA89B67A27B7BE6CCB24D3274D18B2D4067F261A9'),
    DecodeHex('0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003935F972DA013F80AE011890FA89B67A27B7BE6CCB24D3274D18B2D4067F261A9'));
  LPnonces := TCryptoLibGenericArray<TCryptoLibByteArray>.Create(
    DecodeHex('0337C87821AFD50A8644D820A8F3E02E499C931865C2360FB43D0A0D20DAFE07EA0287BF891D2A6DEAEBADC909352AA9405D1428C15F4B75F04DAE642A95C2548480'),
    DecodeHex('0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F817980279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798'),
    DecodeHex('032DE2662628C90B03F5E720284EB52FF7D71F4284F627B68A853D78C78E1FFE9303E4C5524E83FFE1493B9077CF1CA6BEB2090C93D930321071AD40B2F44E599046'),
    DecodeHex('0237C87821AFD50A8644D820A8F3E02E499C931865C2360FB43D0A0D20DAFE07EA0387BF891D2A6DEAEBADC909352AA9405D1428C15F4B75F04DAE642A95C2548480'),
    DecodeHex('0200000000000000000000000000000000000000000000000000000000000000090287BF891D2A6DEAEBADC909352AA9405D1428C15F4B75F04DAE642A95C2548480'));
  LAggnonces := TCryptoLibGenericArray<TCryptoLibByteArray>.Create(
    DecodeHex('028465FCF0BBDBCF443AABCCE533D42B4B5A10966AC09A49655E8C42DAAB8FCD61037496A3CC86926D452CAFCFD55D25972CA1675D549310DE296BFF42F72EEEA8C9'),
    DecodeHex('000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'),
    DecodeHex('048465FCF0BBDBCF443AABCCE533D42B4B5A10966AC09A49655E8C42DAAB8FCD61037496A3CC86926D452CAFCFD55D25972CA1675D549310DE296BFF42F72EEEA8C9'),
    DecodeHex('028465FCF0BBDBCF443AABCCE533D42B4B5A10966AC09A49655E8C42DAAB8FCD61020000000000000000000000000000000000000000000000000000000000000009'),
    DecodeHex('028465FCF0BBDBCF443AABCCE533D42B4B5A10966AC09A49655E8C42DAAB8FCD6102FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC30'));
  LMsgs := TCryptoLibGenericArray<TCryptoLibByteArray>.Create(
    DecodeHex('F95466D086770E689964664219266FE5ED215C92AE20BAB5C9D79ADDDDF3C0CF'),
    nil,
    DecodeHex('2626262626262626262626262626262626262626262626262626262626262626262626262626'));
  // valid [0,1,2] nonce [0,1,2] aggnonce 0 msg 0 signer 0
  System.SetLength(LPks, 3);
  LPks[0] := LPubkeys[0]; LPks[1] := LPubkeys[1]; LPks[2] := LPubkeys[2];
  LSessionCtx.AggNonce := LAggnonces[0];
  LSessionCtx.PubKeys := LPks;
  LSessionCtx.Tweaks := nil;
  System.SetLength(LSessionCtx.IsXOnlyT, 0);
  LSessionCtx.Msg := LMsgs[0];
  LSecnonces[0] := DecodeHex('508B81A611F100A6B2B6B29656590898AF488BCF2E1F55CF22E5CFB84421FE61FA27FD49B1D50085B481285E1CA205D55C82CC1B31FF5CD54A489829355901F703935F972DA013F80AE011890FA89B67A27B7BE6CCB24D3274D18B2D4067F261A9');
  Check(TBip327MuSig2.Sign(LDomain, LSecnonces[0], LSk, LSessionCtx, LPsig), 'SignVerify sign 0');
  LExpected := '012ABBCB52B3016AC03AD82395A1A415C48B93DEF78718E62A7A90052FE224FB';
  Check(AreEqual(LPsig, DecodeHex(LExpected)), 'SignVerify expected 0');
  // valid signer 1 and 2 (use same aggnonce/session, different secnonce from vectors - we only test signer 0 output; other signers would need their secnonces)
  // Verify partial: signer 0 psig vs pubnonces [0,1,2], pubkeys [0,1,2], no tweaks, msg 0
  System.SetLength(LPnoncesForSession, 3);
  LPnoncesForSession[0] := LPnonces[0]; LPnoncesForSession[1] := LPnonces[1]; LPnoncesForSession[2] := LPnonces[2];
  Check(TBip327MuSig2.PartialSigVerify(LDomain, LPsig, LPnoncesForSession, LPks, nil, nil, LMsgs[0], 0), 'PartialSigVerify signer 0');
  // verify_fail: wrong signer (expected psig for signer 0 but verify as signer 1 should fail)
  Check(not TBip327MuSig2.PartialSigVerify(LDomain, DecodeHex('012ABBCB52B3016AC03AD82395A1A415C48B93DEF78718E62A7A90052FE224FB'), LPnoncesForSession, LPks, nil, nil, LMsgs[0], 1), 'Verify fail wrong signer');
  // Empty message vector: key [0,1,2] nonce [0,1,2] msg 1 (empty) signer 0
  LSessionCtx.Msg := LMsgs[1];
  if System.Length(LSessionCtx.Msg) = 0 then
    LSessionCtx.Msg := nil;
  LSecnonces[0] := DecodeHex('508B81A611F100A6B2B6B29656590898AF488BCF2E1F55CF22E5CFB84421FE61FA27FD49B1D50085B481285E1CA205D55C82CC1B31FF5CD54A489829355901F703935F972DA013F80AE011890FA89B67A27B7BE6CCB24D3274D18B2D4067F261A9');
  Check(TBip327MuSig2.Sign(LDomain, LSecnonces[0], LSk, LSessionCtx, LPsig), 'Sign empty msg');
  LExpected := 'D7D63FFD644CCDA4E62BC2BC0B1D02DD32A1DC3030E155195810231D1037D82D';
  Check(AreEqual(LPsig, DecodeHex(LExpected)), 'Sign empty msg expected');

  // ref valid_test_cases: signer 1 (key [1,0,2], nonce [1,0,2], aggnonce 0, msg 0)
  LPks := TCryptoLibGenericArray<TCryptoLibByteArray>.Create(LPubkeys[1], LPubkeys[0], LPubkeys[2]);
  System.SetLength(LPnoncesForSession, 3);
  LPnoncesForSession[0] := LPnonces[1];
  LPnoncesForSession[1] := LPnonces[0];
  LPnoncesForSession[2] := LPnonces[2];
  LSessionCtx.AggNonce := LAggnonces[0];
  LSessionCtx.PubKeys := LPks;
  LSessionCtx.Tweaks := nil;
  LSessionCtx.IsXOnlyT := nil;
  LSessionCtx.Msg := LMsgs[0];
  LSecnonces[0] := DecodeHex('508B81A611F100A6B2B6B29656590898AF488BCF2E1F55CF22E5CFB84421FE61FA27FD49B1D50085B481285E1CA205D55C82CC1B31FF5CD54A489829355901F703935F972DA013F80AE011890FA89B67A27B7BE6CCB24D3274D18B2D4067F261A9');
  Check(TBip327MuSig2.Sign(LDomain, LSecnonces[0], LSk, LSessionCtx, LPsig), 'SignVerify signer 1');
  LExpected := '9FF2F7AAA856150CC8819254218D3ADEEB0535269051897724F9DB3789513A52';
  Check(AreEqual(LPsig, DecodeHex(LExpected)), 'SignVerify expected signer 1');

  // ref valid_test_cases: signer 2 (key [1,2,0], nonce [1,2,0], aggnonce 0, msg 0)
  LPks := TCryptoLibGenericArray<TCryptoLibByteArray>.Create(LPubkeys[1], LPubkeys[2], LPubkeys[0]);
  LPnoncesForSession[0] := LPnonces[1];
  LPnoncesForSession[1] := LPnonces[2];
  LPnoncesForSession[2] := LPnonces[0];
  LSessionCtx.AggNonce := LAggnonces[0];
  LSessionCtx.PubKeys := LPks;
  LSessionCtx.Msg := LMsgs[0];
  LSecnonces[0] := DecodeHex('508B81A611F100A6B2B6B29656590898AF488BCF2E1F55CF22E5CFB84421FE61FA27FD49B1D50085B481285E1CA205D55C82CC1B31FF5CD54A489829355901F703935F972DA013F80AE011890FA89B67A27B7BE6CCB24D3274D18B2D4067F261A9');
  Check(TBip327MuSig2.Sign(LDomain, LSecnonces[0], LSk, LSessionCtx, LPsig), 'SignVerify signer 2');
  LExpected := 'FA23C359F6FAC4E7796BB93BC9F0532A95468C539BA20FF86D7C76ED92227900';
  Check(AreEqual(LPsig, DecodeHex(LExpected)), 'SignVerify expected signer 2');

  // ref valid_test_cases: infinity aggnonce (key [0,1], nonce [0,3], aggnonce_index 1, msg 0)
  LPks := TCryptoLibGenericArray<TCryptoLibByteArray>.Create(LPubkeys[0], LPubkeys[1]);
  System.SetLength(LPnoncesForSession, 2);
  LPnoncesForSession[0] := LPnonces[0];
  LPnoncesForSession[1] := LPnonces[3];
  LSessionCtx.AggNonce := LAggnonces[1];
  LSessionCtx.PubKeys := LPks;
  LSessionCtx.Msg := LMsgs[0];
  LSecnonces[0] := DecodeHex('508B81A611F100A6B2B6B29656590898AF488BCF2E1F55CF22E5CFB84421FE61FA27FD49B1D50085B481285E1CA205D55C82CC1B31FF5CD54A489829355901F703935F972DA013F80AE011890FA89B67A27B7BE6CCB24D3274D18B2D4067F261A9');
  Check(TBip327MuSig2.Sign(LDomain, LSecnonces[0], LSk, LSessionCtx, LPsig), 'SignVerify infinity aggnonce');
  LExpected := 'AE386064B26105404798F75DE2EB9AF5EDA5387B064B83D049CB7C5E08879531';
  Check(AreEqual(LPsig, DecodeHex(LExpected)), 'SignVerify expected infinity aggnonce');

  // ref valid_test_cases: 38-byte message (key [0,1,2], nonce [0,1,2], aggnonce 0, msg_index 2)
  LPks := TCryptoLibGenericArray<TCryptoLibByteArray>.Create(LPubkeys[0], LPubkeys[1], LPubkeys[2]);
  System.SetLength(LPnoncesForSession, 3);
  LPnoncesForSession[0] := LPnonces[0];
  LPnoncesForSession[1] := LPnonces[1];
  LPnoncesForSession[2] := LPnonces[2];
  LSessionCtx.AggNonce := LAggnonces[0];
  LSessionCtx.PubKeys := LPks;
  LSessionCtx.Msg := LMsgs[2];
  LSecnonces[0] := DecodeHex('508B81A611F100A6B2B6B29656590898AF488BCF2E1F55CF22E5CFB84421FE61FA27FD49B1D50085B481285E1CA205D55C82CC1B31FF5CD54A489829355901F703935F972DA013F80AE011890FA89B67A27B7BE6CCB24D3274D18B2D4067F261A9');
  Check(TBip327MuSig2.Sign(LDomain, LSecnonces[0], LSk, LSessionCtx, LPsig), 'SignVerify 38-byte msg');
  LExpected := 'E184351828DA5094A97C79CABDAAA0BFB87608C32E8829A4DF5340A6F243B78C';
  Check(AreEqual(LPsig, DecodeHex(LExpected)), 'SignVerify expected 38-byte msg');

  // sign_error_test_cases: Sign must raise or return False as per ref vectors
  // Case 1: signer's pubkey not in list (key_indices [1,2], sk corresponds to pubkeys[0])
  LPks := TCryptoLibGenericArray<TCryptoLibByteArray>.Create(LPubkeys[1], LPubkeys[2]);
  LSessionCtx.AggNonce := LAggnonces[0];
  LSessionCtx.PubKeys := LPks;
  LSessionCtx.Tweaks := nil;
  LSessionCtx.IsXOnlyT := nil;
  LSessionCtx.Msg := LMsgs[0];
  LSecnonces[0] := DecodeHex('508B81A611F100A6B2B6B29656590898AF488BCF2E1F55CF22E5CFB84421FE61FA27FD49B1D50085B481285E1CA205D55C82CC1B31FF5CD54A489829355901F703935F972DA013F80AE011890FA89B67A27B7BE6CCB24D3274D18B2D4067F261A9');
  try
    if TBip327MuSig2.Sign(LDomain, LSecnonces[0], LSk, LSessionCtx, LPsig) then
      Fail('Sign with signer pubkey not in list should fail');
  except
    on E: EArgumentCryptoLibException do
      Check(Pos('pubkey', LowerCase(E.Message)) > 0, 'sign_error case 1: pubkey message');
    else
      raise;
  end;

  // Case 2: ref sign_verify_vectors sign_error key_indices [1, 0, 3] — key at index 3 is invalid (point not on curve; ref: "Signer 2 provided an invalid public key")
  LPks := TCryptoLibGenericArray<TCryptoLibByteArray>.Create(LPubkeys[1], LPubkeys[0], LPubkeys[3]);
  LSessionCtx.PubKeys := LPks;
  LSecnonces[0] := DecodeHex('508B81A611F100A6B2B6B29656590898AF488BCF2E1F55CF22E5CFB84421FE61FA27FD49B1D50085B481285E1CA205D55C82CC1B31FF5CD54A489829355901F703935F972DA013F80AE011890FA89B67A27B7BE6CCB24D3274D18B2D4067F261A9');
  try
    TBip327MuSig2.Sign(LDomain, LSecnonces[0], LSk, LSessionCtx, LPsig);
    Fail('Sign with invalid pubkey should raise');
  except
    on E: EBip327InvalidContributionException do
    begin
      Check(E.SignerIndex = 2, 'sign_error case 2: signer index');
      Check(E.Contribution = 'pubkey', 'sign_error case 2: contrib');
    end;
    else
      raise;
  end;

  // Cases 3,4,5: invalid aggnonce (wrong tag or invalid encoding); GetSessionValues fails via CPointExt/CPoint -> contrib pubkey, SignerIndex -1
  for LI := 2 to 4 do
  begin
    LPks := TCryptoLibGenericArray<TCryptoLibByteArray>.Create(LPubkeys[1], LPubkeys[2], LPubkeys[0]);
    LSessionCtx.AggNonce := LAggnonces[LI];
    LSessionCtx.PubKeys := LPks;
    LSessionCtx.Msg := LMsgs[0];
    LSecnonces[0] := DecodeHex('508B81A611F100A6B2B6B29656590898AF488BCF2E1F55CF22E5CFB84421FE61FA27FD49B1D50085B481285E1CA205D55C82CC1B31FF5CD54A489829355901F703935F972DA013F80AE011890FA89B67A27B7BE6CCB24D3274D18B2D4067F261A9');
    try
      TBip327MuSig2.Sign(LDomain, LSecnonces[0], LSk, LSessionCtx, LPsig);
      Fail('Sign with invalid aggnonce should raise');
    except
      on E: EBip327InvalidContributionException do
      begin
        Check(E.SignerIndex = -1, 'sign_error aggnonce: signer index');
        Check(E.Contribution = 'pubkey', 'sign_error aggnonce: contrib');
      end;
      else
        raise;
    end;
  end;

  // Case 6: invalid secnonce (secnonce_index 1 has k1=k2=0); Sign returns False
  LPks := TCryptoLibGenericArray<TCryptoLibByteArray>.Create(LPubkeys[0], LPubkeys[1], LPubkeys[2]);
  LSessionCtx.AggNonce := LAggnonces[0];
  LSessionCtx.PubKeys := LPks;
  LSessionCtx.Msg := LMsgs[0];
  LSecnonces[1] := DecodeHex('0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003935F972DA013F80AE011890FA89B67A27B7BE6CCB24D3274D18B2D4067F261A9');
  Check(not TBip327MuSig2.Sign(LDomain, LSecnonces[1], LSk, LSessionCtx, LPsig), 'Sign with invalid secnonce should return False');

  // verify_fail: use valid session [0,1,2]
  LPks := TCryptoLibGenericArray<TCryptoLibByteArray>.Create(LPubkeys[0], LPubkeys[1], LPubkeys[2]);
  System.SetLength(LPnoncesForSession, 3);
  LPnoncesForSession[0] := LPnonces[0];
  LPnoncesForSession[1] := LPnonces[1];
  LPnoncesForSession[2] := LPnonces[2];
  // verify_fail: wrong sig (negation of valid)
  Check(not TBip327MuSig2.PartialSigVerify(LDomain, DecodeHex('FED54434AD4CFE953FC527DC6A5E5BE8F6234907B7C187559557CE87A0541C46'), LPnoncesForSession, LPks, nil, nil, LMsgs[0], 0), 'Verify fail wrong sig');
  // verify_fail: sig >= n
  Check(not TBip327MuSig2.PartialSigVerify(LDomain, DecodeHex('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141'), LPnoncesForSession, LPks, nil, nil, LMsgs[0], 0), 'Verify fail sig >= n');

  // verify_error: invalid pubnonce (nonce_indices [4,1,2], pnonces[4] invalid)
  System.SetLength(LPnoncesForSession, 3);
  LPnoncesForSession[0] := LPnonces[4];
  LPnoncesForSession[1] := LPnonces[1];
  LPnoncesForSession[2] := LPnonces[2];
  try
    TBip327MuSig2.PartialSigVerify(LDomain, DecodeHex('012ABBCB52B3016AC03AD82395A1A415C48B93DEF78718E62A7A90052FE224FB'), LPnoncesForSession, LPks, nil, nil, LMsgs[0], 0);
    Fail('PartialSigVerify with invalid pubnonce should raise');
  except
    on E: EBip327InvalidContributionException do
    begin
      Check(E.SignerIndex = 0, 'verify_error pubnonce: signer index');
      Check(E.Contribution = 'pubnonce', 'verify_error pubnonce: contrib');
    end;
    else
      raise;
  end;

  // verify_error: invalid pubkey (ref key_indices [3,1,2]; key 3 not on curve, signer index 0)
  LPks := TCryptoLibGenericArray<TCryptoLibByteArray>.Create(LPubkeys[3], LPubkeys[1], LPubkeys[2]);
  System.SetLength(LPnoncesForSession, 3);
  LPnoncesForSession[0] := LPnonces[0];
  LPnoncesForSession[1] := LPnonces[1];
  LPnoncesForSession[2] := LPnonces[2];
  try
    TBip327MuSig2.PartialSigVerify(LDomain, DecodeHex('012ABBCB52B3016AC03AD82395A1A415C48B93DEF78718E62A7A90052FE224FB'), LPnoncesForSession, LPks, nil, nil, LMsgs[0], 0);
    Fail('PartialSigVerify with invalid pubkey should raise');
  except
    on E: EBip327InvalidContributionException do
    begin
      Check(E.SignerIndex = 0, 'verify_error pubkey: signer index');
      Check(E.Contribution = 'pubkey', 'verify_error pubkey: contrib');
    end;
    else
      raise;
  end;
end;

procedure TTestBip327MuSig2.TestSigAggVectors;
var
  LDomain: IECDomainParameters;
  LPubkeys, LPsigs, LTweaks: TCryptoLibGenericArray<TCryptoLibByteArray>;
  LMsg: TCryptoLibByteArray;
  LSessionCtx: TBip327SessionContext;
  LAggsig: TCryptoLibByteArray;
  LExpected: String;
  LPks: TCryptoLibGenericArray<TCryptoLibByteArray>;
  LPsigsSub: TCryptoLibGenericArray<TCryptoLibByteArray>;
  I: Int32;
  LCtx: IBip327KeyAggContext;
  LAggPk: TCryptoLibByteArray;
begin
  LDomain := Secp256k1Domain();
  LPubkeys := TCryptoLibGenericArray<TCryptoLibByteArray>.Create(
    DecodeHex('03935F972DA013F80AE011890FA89B67A27B7BE6CCB24D3274D18B2D4067F261A9'),
    DecodeHex('02D2DC6F5DF7C56ACF38C7FA0AE7A759AE30E19B37359DFDE015872324C7EF6E05'),
    DecodeHex('03C7FB101D97FF930ACD0C6760852EF64E69083DE0B06AC6335724754BB4B0522C'),
    DecodeHex('02352433B21E7E05D3B452B81CAE566E06D2E003ECE16D1074AABA4289E0E3D581'));
  LPsigs := TCryptoLibGenericArray<TCryptoLibByteArray>.Create(
    DecodeHex('B15D2CD3C3D22B04DAE438CE653F6B4ECF042F42CFDED7C41B64AAF9B4AF53FB'),
    DecodeHex('6193D6AC61B354E9105BBDC8937A3454A6D705B6D57322A5A472A02CE99FCB64'),
    DecodeHex('9A87D3B79EC67228CB97878B76049B15DBD05B8158D17B5B9114D3C226887505'),
    DecodeHex('66F82EA90923689B855D36C6B7E032FB9970301481B99E01CDB4D6AC7C347A15'),
    DecodeHex('4F5AEE41510848A6447DCD1BBC78457EF69024944C87F40250D3EF2C25D33EFE'),
    DecodeHex('DDEF427BBB847CC027BEFF4EDB01038148917832253EBC355FC33F4A8E2FCCE4'),
    DecodeHex('97B890A26C981DA8102D3BC294159D171D72810FDF7C6A691DEF02F0F7AF3FDC'),
    DecodeHex('53FA9E08BA5243CBCB0D797C5EE83BC6728E539EB76C2D0BF0F971EE4E909971'),
    DecodeHex('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141'));
  LMsg := DecodeHex('599C67EA410D005B9DA90817CF03ED3B1C868E4DA4EDF00A5880B0082C237869');
  LTweaks := TCryptoLibGenericArray<TCryptoLibByteArray>.Create(
    DecodeHex('B511DA492182A91B0FFB9A98020D55F260AE86D7ECBD0399C7383D59A5F2AF7C'),
    DecodeHex('A815FE049EE3C5AAB66310477FBC8BCCCAC2F3395F59F921C364ACD78A2F48DC'),
    DecodeHex('75448A87274B056468B977BE06EB1E9F657577B7320B0A3376EA51FD420D18A8'));
  // valid: aggnonce, key [0,1], psig [0,1], no tweaks
  LSessionCtx.AggNonce := DecodeHex('0341432722C5CD0268D829C702CF0D1CBCE57033EED201FD335191385227C3210C03D377F2D258B64AADC0E16F26462323D701D286046A2EA93365656AFD9875982B');
  LPks := TCryptoLibGenericArray<TCryptoLibByteArray>.Create(LPubkeys[0], LPubkeys[1]);
  LSessionCtx.PubKeys := LPks;
  LSessionCtx.Tweaks := nil;
  LSessionCtx.IsXOnlyT := nil;
  LSessionCtx.Msg := LMsg;
  LPsigsSub := TCryptoLibGenericArray<TCryptoLibByteArray>.Create(LPsigs[0], LPsigs[1]);
  LAggsig := TBip327MuSig2.PartialSigAgg(LDomain, LPsigsSub, LSessionCtx);
  LExpected := '041DA22223CE65C92C9A0D6C2CAC828AAF1EEE56304FEC371DDF91EBB2B9EF0912F1038025857FEDEB3FF696F8B99FA4BB2C5812F6095A2E0004EC99CE18DE1E';
  Check(AreEqual(LAggsig, DecodeHex(LExpected)), 'SigAgg valid 1');
  LCtx := TBip327MuSig2KeyAggregation.KeyAgg(LDomain, LSessionCtx.PubKeys);
  LAggPk := LCtx.GetXOnlyPubKey();
  VerifyAggSigBip340(LSessionCtx.Msg, LAggPk, LAggsig, 'SigAgg valid 1');
  // valid: key [0,2] tweak [0] is_xonly false, psig [4,5]
  LSessionCtx.AggNonce := DecodeHex('0208C5C438C710F4F96A61E9FF3C37758814B8C3AE12BFEA0ED2C87FF6954FF186020B1816EA104B4FCA2D304D733E0E19CEAD51303FF6420BFD222335CAA402916D');
  LPks := TCryptoLibGenericArray<TCryptoLibByteArray>.Create(LPubkeys[0], LPubkeys[2]);
  LSessionCtx.PubKeys := LPks;
  LSessionCtx.Tweaks := TCryptoLibGenericArray<TCryptoLibByteArray>.Create(LTweaks[0]);
  LSessionCtx.IsXOnlyT := TCryptoLibBooleanArray.Create(False);
  LPsigsSub := TCryptoLibGenericArray<TCryptoLibByteArray>.Create(LPsigs[4], LPsigs[5]);
  LAggsig := TBip327MuSig2.PartialSigAgg(LDomain, LPsigsSub, LSessionCtx);
  LExpected := '5C558E1DCADE86DA0B2F02626A512E30A22CF5255CAEA7EE32C38E9A71A0E9148BA6C0E6EC7683B64220F0298696F1B878CD47B107B81F7188812D593971E0CC';
  Check(AreEqual(LAggsig, DecodeHex(LExpected)), 'SigAgg valid with tweak');
  LCtx := TBip327MuSig2KeyAggregation.KeyAgg(LDomain, LSessionCtx.PubKeys);
  for I := 0 to System.Length(LSessionCtx.Tweaks) - 1 do
    LCtx := TBip327MuSig2KeyAggregation.ApplyTweak(LCtx, LSessionCtx.Tweaks[I], LSessionCtx.IsXOnlyT[I]);
  LAggPk := LCtx.GetXOnlyPubKey();
  VerifyAggSigBip340(LSessionCtx.Msg, LAggPk, LAggsig, 'SigAgg valid with tweak');
  // error: psig [7,8] -> psig 8 invalid (>= n)
  try
    LSessionCtx.AggNonce := DecodeHex('02B5AD07AFCD99B6D92CB433FBD2A28FDEB98EAE2EB09B6014EF0F8197CD58403302E8616910F9293CF692C49F351DB86B25E352901F0E237BAFDA11F1C1CEF29FFD');
    LPks := TCryptoLibGenericArray<TCryptoLibByteArray>.Create(LPubkeys[0], LPubkeys[3]);
    LSessionCtx.PubKeys := LPks;
    LSessionCtx.Tweaks := TCryptoLibGenericArray<TCryptoLibByteArray>.Create(LTweaks[0], LTweaks[1], LTweaks[2]);
    LSessionCtx.IsXOnlyT := TCryptoLibBooleanArray.Create(True, False, True);
    LPsigsSub := TCryptoLibGenericArray<TCryptoLibByteArray>.Create(LPsigs[7], LPsigs[8]);
    TBip327MuSig2.PartialSigAgg(LDomain, LPsigsSub, LSessionCtx);
    Fail('SigAgg invalid psig should raise');
  except
    on E: EBip327InvalidContributionException do
    begin
      Check(E.SignerIndex = 1, 'SigAgg error signer');
      Check(E.Contribution = 'psig', 'SigAgg error contrib');
    end;
    else
      raise;
  end;
end;

procedure TTestBip327MuSig2.TestDetSignVectors;
var
  LDomain: IECDomainParameters;
  LSk: TCryptoLibByteArray;
  LPubkeys, LMsgs: TCryptoLibGenericArray<TCryptoLibByteArray>;
  LTweaks: TCryptoLibGenericArray<TCryptoLibByteArray>;
  LIsXonly: TCryptoLibBooleanArray;
  LExpectedPubnonce, LExpectedPsig: String;
  LPubnonce, LPsig: TCryptoLibByteArray;
  LPks: TCryptoLibGenericArray<TCryptoLibByteArray>;
  LRandBytes: TCryptoLibByteArray;
begin
  LDomain := Secp256k1Domain();
  LSk := DecodeHex('7FB9E0E687ADA1EEBF7ECFE2F21E73EBDB51A7D450948DFE8D76D7F2D1007671');
  LPubkeys := TCryptoLibGenericArray<TCryptoLibByteArray>.Create(
    DecodeHex('03935F972DA013F80AE011890FA89B67A27B7BE6CCB24D3274D18B2D4067F261A9'),
    DecodeHex('02F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9'),
    DecodeHex('02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659'),
    DecodeHex('020000000000000000000000000000000000000000000000000000000000000007'));
  LMsgs := TCryptoLibGenericArray<TCryptoLibByteArray>.Create(
    DecodeHex('F95466D086770E689964664219266FE5ED215C92AE20BAB5C9D79ADDDDF3C0CF'),
    DecodeHex('2626262626262626262626262626262626262626262626262626262626262626262626262626'));
  // valid: rand 0..0, aggothernonce, key [0,1,2], no tweaks, msg 0, signer 0
  LPks := TCryptoLibGenericArray<TCryptoLibByteArray>.Create(LPubkeys[0], LPubkeys[1], LPubkeys[2]);
  LRandBytes := DecodeHex('0000000000000000000000000000000000000000000000000000000000000000');
  Check(TBip327MuSig2.DeterministicSign(LDomain, LSk,
    DecodeHex('0337C87821AFD50A8644D820A8F3E02E499C931865C2360FB43D0A0D20DAFE07EA0287BF891D2A6DEAEBADC909352AA9405D1428C15F4B75F04DAE642A95C2548480'),
    LPks, nil, nil, LMsgs[0], LRandBytes, LPubnonce, LPsig), 'DetSign valid 1');
  LExpectedPubnonce := '03D96275257C2FCCBB6EEB77BDDF51D3C88C26EE1626C6CDA8999B9D34F4BA13A60309BE2BF883C6ABE907FA822D9CA166D51A3DCC28910C57528F6983FC378B7843';
  LExpectedPsig := '41EA65093F71D084785B20DC26A887CD941C9597860A21660CBDB9CC2113CAD3';
  Check(AreEqual(LPubnonce, DecodeHex(LExpectedPubnonce)), 'DetSign valid 1 pubnonce');
  Check(AreEqual(LPsig, DecodeHex(LExpectedPsig)), 'DetSign valid 1 psig');
  // valid: rand null (no aux), key [1,0,2], signer 1
  LPks := TCryptoLibGenericArray<TCryptoLibByteArray>.Create(LPubkeys[1], LPubkeys[0], LPubkeys[2]);
  Check(TBip327MuSig2.DeterministicSign(LDomain, LSk,
    DecodeHex('0337C87821AFD50A8644D820A8F3E02E499C931865C2360FB43D0A0D20DAFE07EA0287BF891D2A6DEAEBADC909352AA9405D1428C15F4B75F04DAE642A95C2548480'),
    LPks, nil, nil, LMsgs[0], nil, LPubnonce, LPsig), 'DetSign valid 2');
  LExpectedPubnonce := '028FBCCF5BB73A7B61B270BAD15C0F9475D577DD85C2157C9D38BEF1EC922B48770253BE3638C87369BC287E446B7F2C8CA5BEB9FFBD1EA082C62913982A65FC214D';
  LExpectedPsig := 'AEAA31262637BFA88D5606679018A0FEEEC341F3107D1199857F6C81DE61B8DD';
  Check(AreEqual(LPubnonce, DecodeHex(LExpectedPubnonce)), 'DetSign valid 2 pubnonce');
  Check(AreEqual(LPsig, DecodeHex(LExpectedPsig)), 'DetSign valid 2 psig');
  // valid: tweak vector
  LPks := TCryptoLibGenericArray<TCryptoLibByteArray>.Create(LPubkeys[0], LPubkeys[1], LPubkeys[2]);
  LTweaks := TCryptoLibGenericArray<TCryptoLibByteArray>.Create(DecodeHex('E8F791FF9225A2AF0102AFFF4A9A723D9612A682A25EBE79802B263CDFCD83BB'));
  LIsXonly := TCryptoLibBooleanArray.Create(True);
  Check(TBip327MuSig2.DeterministicSign(LDomain, LSk,
    DecodeHex('032DE2662628C90B03F5E720284EB52FF7D71F4284F627B68A853D78C78E1FFE9303E4C5524E83FFE1493B9077CF1CA6BEB2090C93D930321071AD40B2F44E599046'),
    LPks, LTweaks, LIsXonly, LMsgs[0], LRandBytes, LPubnonce, LPsig), 'DetSign with tweak');
  LExpectedPubnonce := '031E07C0D11A0134E55DB1FC16095ADCBD564236194374AA882BFB3C78273BF673039D0336E8CA6288C00BFC1F8B594563529C98661172B9BC1BE85C23A4CE1F616B';
  LExpectedPsig := '7B1246C5889E59CB0375FA395CC86AC42D5D7D59FD8EAB4FDF1DCAB2B2F006EA';
  Check(AreEqual(LPubnonce, DecodeHex(LExpectedPubnonce)), 'DetSign tweak pubnonce');
  Check(AreEqual(LPsig, DecodeHex(LExpectedPsig)), 'DetSign tweak psig');
  // error: key [1,0,3] invalid pubkey signer 2
  try
    LPks := TCryptoLibGenericArray<TCryptoLibByteArray>.Create(LPubkeys[1], LPubkeys[0], LPubkeys[3]);
    TBip327MuSig2.DeterministicSign(LDomain, LSk,
      DecodeHex('0337C87821AFD50A8644D820A8F3E02E499C931865C2360FB43D0A0D20DAFE07EA0287BF891D2A6DEAEBADC909352AA9405D1428C15F4B75F04DAE642A95C2548480'),
      LPks, nil, nil, LMsgs[0], LRandBytes, LPubnonce, LPsig);
    Fail('DetSign invalid pubkey should raise');
  except
    on E: EBip327InvalidContributionException do
      Check(E.SignerIndex = 2, 'DetSign error signer');
    else
      raise;
  end;
  // error: tweak >= n
  try
    LPks := TCryptoLibGenericArray<TCryptoLibByteArray>.Create(LPubkeys[1], LPubkeys[2], LPubkeys[0]);
    LTweaks := TCryptoLibGenericArray<TCryptoLibByteArray>.Create(DecodeHex('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141'));
    LIsXonly := TCryptoLibBooleanArray.Create(False);
    TBip327MuSig2.DeterministicSign(LDomain, LSk,
      DecodeHex('0337C87821AFD50A8644D820A8F3E02E499C931865C2360FB43D0A0D20DAFE07EA0287BF891D2A6DEAEBADC909352AA9405D1428C15F4B75F04DAE642A95C2548480'),
      LPks, LTweaks, LIsXonly, LMsgs[0], LRandBytes, LPubnonce, LPsig);
    Fail('DetSign tweak >= n should raise');
  except
    on E: EArgumentCryptoLibException do
      Check(Pos('tweak', LowerCase(E.Message)) > 0, 'DetSign tweak error');
    else
      raise;
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
    System.SetLength(LMsg, 20 + (LI mod 40));
    LRandom.NextBytes(LMsg);
    LMsgProvided := True;

    // NonceGen for all three
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
  System.SetLength(LMsg, 32);
  LRandom.NextBytes(LMsg);
  System.SetLength(LSecnonces, 2);
  System.SetLength(LPubnonces, 3);
  Check(TBip327MuSig2.NonceGen(LDomain, LSk1, LPk1, AggPk, LMsg, True, nil, LRandom, LSecnonces[0], LPubnonces[0]), 'DetSign NonceGen 1');
  Check(TBip327MuSig2.NonceGen(LDomain, LSk2, LPk2, AggPk, LMsg, True, nil, LRandom, LSecnonces[1], LPubnonces[1]), 'DetSign NonceGen 2');
  LAggOtherNonce := TBip327MuSig2.NonceAgg(LDomain, TCryptoLibGenericArray<TCryptoLibByteArray>.Create(LPubnonces[0], LPubnonces[1]));
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
  System.SetLength(LMsg, 32);
  LRandom.NextBytes(LMsg);
  System.SetLength(LSecnonces, 2);
  System.SetLength(LPubnonces, 2);
  Check(TBip327MuSig2.NonceGen(LDomain, LSk1, LPk1, AggPk, LMsg, True, nil, LRandom, LSecnonces[0], LPubnonces[0]), 'Reuse NonceGen 1');
  Check(TBip327MuSig2.NonceGen(LDomain, LSk2, LPk2, AggPk, LMsg, True, nil, LRandom, LSecnonces[1], LPubnonces[1]), 'Reuse NonceGen 2');
  LSessionCtx.AggNonce := TBip327MuSig2.NonceAgg(LDomain, LPubnonces);
  LSessionCtx.PubKeys := LPubkeys;
  LSessionCtx.Tweaks := nil;
  LSessionCtx.IsXOnlyT := nil;
  LSessionCtx.Msg := LMsg;
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
  System.SetLength(LSecnonces, 2);
  System.SetLength(LPubnonces, 2);
  Check(TBip327MuSig2.NonceGen(LDomain, LSk1, LPk1, AggPk, LMsg, True, nil, LRandom, LSecnonces[0], LPubnonces[0]), 'WrongMsg NonceGen 1');
  Check(TBip327MuSig2.NonceGen(LDomain, LSk2, LPk2, AggPk, LMsg, True, nil, LRandom, LSecnonces[1], LPubnonces[1]), 'WrongMsg NonceGen 2');
  LSessionCtx.AggNonce := TBip327MuSig2.NonceAgg(LDomain, LPubnonces);
  LSessionCtx.PubKeys := LPubkeys;
  LSessionCtx.Tweaks := nil;
  LSessionCtx.IsXOnlyT := nil;
  LSessionCtx.Msg := LMsg;
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
