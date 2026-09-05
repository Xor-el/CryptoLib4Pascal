unit HpkeTests;

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
  CryptoLibTestBase,
  HpkeVectors,
  ClpHpkeTypes,
  ClpHpke,
  ClpIHpke,
  ClpDhKem,
  ClpIHpkeKem,
  ClpHpkeAead,
  ClpIHpkeAead,
  ClpHpkeContext,
  ClpIHpkeContext,
  ClpIAsymmetricKeyParameter,
  ClpIAsymmetricCipherKeyPair,
  ClpX25519,
  ClpX448,
  ClpCryptoLibTypes;

type
  TTestHpke = class(TCryptoLibAlgorithmTestCase)
  private
    function ClampedFor(AKemId: THpkeKemId; const ASk: TBytes): TBytes;
    procedure RunVector(const ARecord: THpkeVectorRecord);
  published
    procedure TestVectors;
    procedure TestBasePairwise;
    procedure TestAuthPairwise;
    procedure TestExportOnlyPairwise;
    procedure TestOpenFailureDoesNotAdvanceSequence;
    procedure TestOffsetOverloadsAndAeadId;
    procedure TestAeadOwnsItsKeyMaterial;
  end;

implementation

{ TTestHpke }

function TTestHpke.ClampedFor(AKemId: THpkeKemId; const ASk: TBytes): TBytes;
begin
  Result := System.Copy(ASk);
  case AKemId of
    THpkeKemId.X25519_SHA256:
      TX25519.ClampPrivateKey(Result);
    THpkeKemId.X448_SHA512:
      TX448.ClampPrivateKey(Result);
  end;
end;

procedure TTestHpke.RunVector(const ARecord: THpkeVectorRecord);
var
  LMode: THpkeMode;
  LKemId: THpkeKemId;
  LKdfId: THpkeKdfId;
  LAeadId: THpkeAeadId;
  LHpke: IHpke;
  LKem: IHpkeKem;
  LAead: IHpkeAead;
  LKp, LDerivedR, LDerivedS, LDerivedE: IAsymmetricCipherKeyPair;
  LSenderPub, LPkR: IAsymmetricKeyParameter;
  LCtx: IHpkeContext;
  LGotCt, LMessage, LSharedSecret, LEncOut: TBytes;
  I: Int32;
  LEnc: THpkeEncryptionVector;
  LExp: THpkeExportVector;
begin
  LMode := THpkeMode(ARecord.Mode);
  LKemId := THpkeKemId(ARecord.KemId);
  LKdfId := THpkeKdfId(ARecord.KdfId);
  LAeadId := THpkeAeadId(ARecord.AeadId);

  LSenderPub := nil;

  LHpke := THpke.Create(LMode, LKemId, LKdfId, LAeadId);

  // AEAD direct test: seal each plaintext with the vector's key/base_nonce and
  // verify the sequence-folded nonce reproduces the expected ciphertext.
  LAead := THpkeAead.Create(LAeadId, ARecord.Key, ARecord.BaseNonce);
  for I := 0 to System.Length(ARecord.Encryptions) - 1 do
  begin
    LEnc := ARecord.Encryptions[I];
    LGotCt := LAead.Seal(LEnc.Aad, LEnc.Pt);
    CheckTrue(AreEqual(LGotCt, LEnc.Ct), 'AEAD seal mismatch');
  end;

  LDerivedR := LHpke.DeriveKeyPair(ARecord.IkmR);
  LKp := LHpke.DeserializePrivateKey(ARecord.SkRm, ARecord.PkRm);

  // serialize round-trips (private key comparison uses the clamped form)
  CheckTrue(AreEqual(ARecord.PkRm, LHpke.SerializePublicKey(LKp.&Public)),
    'serialize public key');
  CheckTrue(AreEqual(ClampedFor(LKemId, ARecord.SkRm),
    LHpke.SerializePrivateKey(LKp.&Private)), 'serialize private key');

  CheckTrue(AreEqual(ARecord.PkRm, LHpke.SerializePublicKey(LDerivedR.&Public)),
    'receiver derived public key');
  CheckTrue(AreEqual(ClampedFor(LKemId, ARecord.SkRm),
    LHpke.SerializePrivateKey(LDerivedR.&Private)),
    'receiver derived private key');

  if (LMode = THpkeMode.Auth) or (LMode = THpkeMode.AuthPsk) then
  begin
    LDerivedS := LHpke.DeriveKeyPair(ARecord.IkmS);
    CheckTrue(AreEqual(ARecord.PkSm, LHpke.SerializePublicKey(LDerivedS.&Public)),
      'sender derived public key');
    CheckTrue(AreEqual(ClampedFor(LKemId, ARecord.SkSm),
      LHpke.SerializePrivateKey(LDerivedS.&Private)),
      'sender derived private key');
  end;

  LDerivedE := LHpke.DeriveKeyPair(ARecord.IkmE);
  CheckTrue(AreEqual(ARecord.PkEm, LHpke.SerializePublicKey(LDerivedE.&Public)),
    'ephemeral derived public key');
  CheckTrue(AreEqual(ClampedFor(LKemId, ARecord.SkEm),
    LHpke.SerializePrivateKey(LDerivedE.&Private)),
    'ephemeral derived private key');

  // setup receiver context (enc == pkEm in the vectors)
  case LMode of
    THpkeMode.Base:
      LCtx := LHpke.SetupBaseR(ARecord.PkEm, LKp, ARecord.Info);
    THpkeMode.Psk:
      LCtx := LHpke.SetupPskR(ARecord.PkEm, LKp, ARecord.Info, ARecord.Psk,
        ARecord.PskId);
    THpkeMode.Auth:
      begin
        LSenderPub := LHpke.DeserializePublicKey(ARecord.PkSm);
        LCtx := LHpke.SetupAuthR(ARecord.PkEm, LKp, ARecord.Info, LSenderPub);
      end;
    THpkeMode.AuthPsk:
      begin
        LSenderPub := LHpke.DeserializePublicKey(ARecord.PkSm);
        LCtx := LHpke.SetupAuthPskR(ARecord.PkEm, LKp, ARecord.Info, ARecord.Psk,
          ARecord.PskId, LSenderPub);
      end;
  end;

  // KEM shared_secret KAT: base/psk reproduce sender Encap (ephemeral from
  // ikmE) and receiver Decap; auth modes check receiver AuthDecap only.
  LKem := TDhKem.Create(LKemId) as IHpkeKem;
  case LMode of
    THpkeMode.Base, THpkeMode.Psk:
      begin
        LPkR := LKem.DeserializePublicKey(ARecord.PkRm);
        LKem.Encap(LPkR, LDerivedE, LSharedSecret, LEncOut);
        CheckTrue(AreEqual(LEncOut, ARecord.PkEm), 'kem encap enc');
        CheckTrue(AreEqual(LSharedSecret, ARecord.SharedSecret),
          'kem encap shared secret (sender)');
        CheckTrue(AreEqual(LKem.Decap(ARecord.PkEm, LKp), ARecord.SharedSecret),
          'kem decap shared secret (receiver)');
      end;
    THpkeMode.Auth, THpkeMode.AuthPsk:
      CheckTrue(AreEqual(LKem.AuthDecap(ARecord.PkEm, LKp, LSenderPub),
        ARecord.SharedSecret), 'kem authdecap shared secret (receiver)');
  end;

  for I := 0 to System.Length(ARecord.Encryptions) - 1 do
  begin
    LEnc := ARecord.Encryptions[I];
    if I = 0 then
    begin
      // one-shot open (first message only)
      LMessage := LHpke.Open(ARecord.PkEm, LKp, ARecord.Info, LEnc.Aad, LEnc.Ct,
        ARecord.Psk, ARecord.PskId, LSenderPub);
      CheckTrue(AreEqual(LMessage, LEnc.Pt), 'one-shot open');
    end;
    CheckTrue(AreEqual(LCtx.Open(LEnc.Aad, LEnc.Ct), LEnc.Pt), 'context open');
  end;

  for I := 0 to System.Length(ARecord.ExportVectors) - 1 do
  begin
    LExp := ARecord.ExportVectors[I];
    CheckTrue(AreEqual(LCtx.Export(LExp.ExporterContext, LExp.L),
      LExp.ExportedValue), 'export value');
  end;
end;

procedure TTestHpke.TestVectors;
var
  LRecords: TCryptoLibGenericArray<THpkeVectorRecord>;
  I: Int32;
begin
  LRecords := THpkeVectors.GetRecords();
  CheckTrue(System.Length(LRecords) > 0, 'no HPKE vectors loaded');
  for I := 0 to System.Length(LRecords) - 1 do
  begin
    RunVector(LRecords[I]);
  end;
end;

procedure TTestHpke.TestBasePairwise;
var
  LHpke: IHpke;
  LReceiver: IAsymmetricCipherKeyPair;
  LCtxS: IHpkeContextWithEncapsulation;
  LCtxR: IHpkeContext;
  LAad, LMsg, LCt: TBytes;
begin
  LHpke := THpke.Create(THpkeMode.Base, THpkeKemId.P256_SHA256,
    THpkeKdfId.HkdfSha256, THpkeAeadId.AesGcm128);
  LReceiver := LHpke.GeneratePrivateKey();

  LCtxS := LHpke.SetupBaseS(LReceiver.&Public, TEncoding.UTF8.GetBytes('info'));
  LCtxR := LHpke.SetupBaseR(LCtxS.GetEncapsulation(), LReceiver,
    TEncoding.UTF8.GetBytes('info'));

  CheckTrue(AreEqual(LCtxS.Export(TEncoding.UTF8.GetBytes('ctx'), 64),
    LCtxR.Export(TEncoding.UTF8.GetBytes('ctx'), 64)), 'export mismatch');

  LAad := TEncoding.UTF8.GetBytes('aad');
  LMsg := TEncoding.UTF8.GetBytes('a slightly longer message body');
  LCt := LCtxS.Seal(LAad, LMsg);
  CheckTrue(AreEqual(LMsg, LCtxR.Open(LAad, LCt)), 'base round trip');
end;

procedure TTestHpke.TestAuthPairwise;
var
  LHpke: IHpke;
  LReceiver, LSender: IAsymmetricCipherKeyPair;
  LCtxS: IHpkeContextWithEncapsulation;
  LCtxR: IHpkeContext;
  LAad, LMsg, LCt: TBytes;
begin
  LHpke := THpke.Create(THpkeMode.Auth, THpkeKemId.X25519_SHA256,
    THpkeKdfId.HkdfSha256, THpkeAeadId.ChaCha20Poly1305);
  LReceiver := LHpke.GeneratePrivateKey();
  LSender := LHpke.GeneratePrivateKey();

  LCtxS := LHpke.SetupAuthS(LReceiver.&Public, TEncoding.UTF8.GetBytes('info'),
    LSender);
  LCtxR := LHpke.SetupAuthR(LCtxS.GetEncapsulation(), LReceiver,
    TEncoding.UTF8.GetBytes('info'), LSender.&Public);

  LAad := TEncoding.UTF8.GetBytes('aad');
  LMsg := TEncoding.UTF8.GetBytes('authenticated message');
  LCt := LCtxS.Seal(LAad, LMsg);
  CheckTrue(AreEqual(LMsg, LCtxR.Open(LAad, LCt)), 'auth round trip');

  // wrong sender public key must fail the tag check
  try
    LCtxR := LHpke.SetupAuthR(LCtxS.GetEncapsulation(), LReceiver,
      TEncoding.UTF8.GetBytes('info'), LReceiver.&Public);
    LCtxR.Open(LAad, LCt);
    Fail('expected open failure with wrong sender key');
  except
    on E: Exception do
      // expected
  end;
end;

procedure TTestHpke.TestExportOnlyPairwise;
var
  LHpke: IHpke;
  LReceiver: IAsymmetricCipherKeyPair;
  LEnc, LExported, LReceived: TBytes;
begin
  LHpke := THpke.Create(THpkeMode.Base, THpkeKemId.P256_SHA256,
    THpkeKdfId.HkdfSha256, THpkeAeadId.ExportOnly);
  LReceiver := LHpke.GeneratePrivateKey();

  LHpke.SendExport(LReceiver.&Public, TEncoding.UTF8.GetBytes('info'),
    TEncoding.UTF8.GetBytes('exporter context'), 32, nil, nil, nil, LEnc,
    LExported);

  LReceived := LHpke.ReceiveExport(LEnc, LReceiver,
    TEncoding.UTF8.GetBytes('info'), TEncoding.UTF8.GetBytes('exporter context'),
    32, nil, nil, nil);

  CheckTrue(AreEqual(LExported, LReceived), 'export-only secrets differ');
end;

procedure TTestHpke.TestOpenFailureDoesNotAdvanceSequence;
var
  LHpke: IHpke;
  LReceiver: IAsymmetricCipherKeyPair;
  LCtxS: IHpkeContextWithEncapsulation;
  LCtxR: IHpkeContext;
  LAad, LFirst, LSecond, LCt1, LCt2, LForged: TBytes;
begin
  LHpke := THpke.Create(THpkeMode.Base, THpkeKemId.P256_SHA256,
    THpkeKdfId.HkdfSha256, THpkeAeadId.AesGcm128);
  LReceiver := LHpke.GeneratePrivateKey();

  LCtxS := LHpke.SetupBaseS(LReceiver.&Public, TEncoding.UTF8.GetBytes('info'));
  LCtxR := LHpke.SetupBaseR(LCtxS.GetEncapsulation(), LReceiver,
    TEncoding.UTF8.GetBytes('info'));

  LAad := DecodeHex('0011223344556677');
  LFirst := TEncoding.UTF8.GetBytes('first message');
  LSecond := TEncoding.UTF8.GetBytes('second message');

  LCt1 := LCtxS.Seal(LAad, LFirst);
  LCt2 := LCtxS.Seal(LAad, LSecond);

  CheckTrue(AreEqual(LFirst, LCtxR.Open(LAad, LCt1)), 'first opens');

  LForged := System.Copy(LCt2);
  LForged[System.Length(LForged) - 1] := LForged[System.Length(LForged) - 1]
    xor $01;
  try
    LCtxR.Open(LAad, LForged);
    Fail('forged ciphertext accepted');
  except
    on E: Exception do
      // expected
  end;

  // the genuine message for the same sequence number must still open
  CheckTrue(AreEqual(LSecond, LCtxR.Open(LAad, LCt2)),
    'receiver desynchronised by a rejected ciphertext');
end;

procedure TTestHpke.TestOffsetOverloadsAndAeadId;
var
  LHpke: IHpke;
  LReceiver: IAsymmetricCipherKeyPair;
  LCtxS: IHpkeContextWithEncapsulation;
  LCtxR: IHpkeContext;
  LAad, LPt, LPadded, LCt, LPaddedCt: TBytes;
begin
  LHpke := THpke.Create(THpkeMode.Base, THpkeKemId.P256_SHA256,
    THpkeKdfId.HkdfSha256, THpkeAeadId.AesGcm128);

  CheckTrue(LHpke.GetAeadId = THpkeAeadId.AesGcm128, 'aead id');

  LReceiver := LHpke.GeneratePrivateKey();
  LCtxS := LHpke.SetupBaseS(LReceiver.&Public, TEncoding.UTF8.GetBytes('info'));
  LCtxR := LHpke.SetupBaseR(LCtxS.GetEncapsulation(), LReceiver,
    TEncoding.UTF8.GetBytes('info'));

  LAad := TEncoding.UTF8.GetBytes('aad');
  // 'slice me' = 736c696365206d65, padded by aaaa (2) before and bbbbbb (3) after
  LPt := DecodeHex('736c696365206d65');
  LPadded := DecodeHex('aaaa736c696365206d65bbbbbb');

  // seal the plaintext embedded in a larger buffer via the offset overload
  LCt := LCtxS.Seal(LAad, LPadded, 2, System.Length(LPt));

  // open the ciphertext embedded in a larger buffer via the offset overload
  System.SetLength(LPaddedCt, System.Length(LCt) + 2);
  LPaddedCt[0] := $CC;
  System.Move(LCt[0], LPaddedCt[1], System.Length(LCt));
  LPaddedCt[System.Length(LPaddedCt) - 1] := $DD;

  CheckTrue(AreEqual(LPt, LCtxR.Open(LAad, LPaddedCt, 1, System.Length(LCt))),
    'offset seal/open round trip');
end;

procedure TTestHpke.TestAeadOwnsItsKeyMaterial;
var
  LKey, LNonce, LKeyBefore, LNonceBefore: TBytes;
  LAead: IHpkeAead;
begin
  LKey := DecodeHex('000102030405060708090a0b0c0d0e0f');
  LNonce := DecodeHex('101112131415161718191a1b');
  LKeyBefore := System.Copy(LKey);
  LNonceBefore := System.Copy(LNonce);

  LAead := THpkeAead.Create(THpkeAeadId.AesGcm128, LKey, LNonce);
  LAead.Seal(nil, DecodeHex('00'));
  // releasing the AEAD triggers its wiping destructor
  LAead := nil;

  // the caller's (here, a cached vector's) key material must be untouched
  CheckTrue(AreEqual(LKey, LKeyBefore), 'AEAD wiped caller-owned key');
  CheckTrue(AreEqual(LNonce, LNonceBefore), 'AEAD wiped caller-owned nonce');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestHpke);
{$ELSE}
  RegisterTest(TTestHpke.Suite);
{$ENDIF FPC}

end.
