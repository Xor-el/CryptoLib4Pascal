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

unit Ed25519HigherLevelTests;

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
  ClpEd25519,
  ClpEd25519Signer,
  ClpEd25519CtxSigner,
  ClpEd25519PhSigner,
  ClpEd25519Parameters,
  ClpIEd25519Parameters,
  ClpEd25519Generators,
  ClpIEd25519Generators,
  ClpIAsymmetricCipherKeyPair,
  ClpISigner,
  ClpSecureRandom,
  ClpISecureRandom,
  ClpICipherParameters,
  ClpStringUtilities,
  ClpCryptoLibTypes,
  CryptoLibTestBase,
  AsymmetricTestVectors;

type

  TTestEd25519HigherLevel = class(TCryptoLibAlgorithmTestCase)
  private
  var
    FRandom: ISecureRandom;

    function CreateSigner(AAlgorithm: TEd25519.TAlgorithm;
      const AContext: TBytes): ISigner;
    procedure DoTestConsistency(AAlgorithm: TEd25519.TAlgorithm;
      const AContext: TBytes);
    function RandomContext(ALength: Int32): TBytes;
    procedure TestRegressionInfiniteLoopImpl();
  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestBasicSig();
    procedure TestConsistencyEd25519();
    procedure TestConsistencyEd25519ctx();
    procedure TestConsistencyEd25519ph();
    procedure TestRegressionInfiniteLoop();
  end;

implementation

{ TTestEd25519HigherLevel }

function TTestEd25519HigherLevel.CreateSigner(AAlgorithm: TEd25519.TAlgorithm;
  const AContext: TBytes): ISigner;
begin
  case AAlgorithm of
    TEd25519.TAlgorithm.Ed25519:
      Result := TEd25519Signer.Create();
    TEd25519.TAlgorithm.Ed25519ctx:
      Result := TEd25519CtxSigner.Create(AContext);
    TEd25519.TAlgorithm.Ed25519ph:
      Result := TEd25519PhSigner.Create(AContext);
  else
    raise EArgumentException.Create('algorithm');
  end;
end;

procedure TTestEd25519HigherLevel.DoTestConsistency(AAlgorithm: TEd25519.TAlgorithm;
  const AContext: TBytes);
var
  LKpg: IEd25519KeyPairGenerator;
  LKp: IAsymmetricCipherKeyPair;
  LPriv: IEd25519PrivateKeyParameters;
  LPub: IEd25519PublicKeyParameters;
  LMsg, LSignature, LWrongLengthSignature, LBadSignature: TBytes;
  LMsgLen, LIdx, LBit: Int32;
  LSigner, LVerifier: ISigner;
  LShouldVerify, LShouldNotVerify: Boolean;
begin
  LKpg := TEd25519KeyPairGenerator.Create() as IEd25519KeyPairGenerator;
  LKpg.Init(TEd25519KeyGenerationParameters.Create(FRandom)
    as IEd25519KeyGenerationParameters);

  LKp := LKpg.GenerateKeyPair();
  LPriv := LKp.Private as IEd25519PrivateKeyParameters;
  LPub := LKp.Public as IEd25519PublicKeyParameters;

  LMsgLen := FRandom.NextInt32() and 255;
  System.SetLength(LMsg, LMsgLen);
  FRandom.NextBytes(LMsg);

  LSigner := CreateSigner(AAlgorithm, AContext);
  LSigner.Init(True, LPriv as ICipherParameters);
  LSigner.BlockUpdate(LMsg, 0, System.Length(LMsg));
  LSignature := LSigner.GenerateSignature();

  LVerifier := CreateSigner(AAlgorithm, AContext);
  LVerifier.Init(False, LPub as ICipherParameters);
  LVerifier.BlockUpdate(LMsg, 0, System.Length(LMsg));
  LShouldVerify := LVerifier.VerifySignature(LSignature);
  if not LShouldVerify then
    Fail(Format('Ed25519(%s) signature failed to verify', [IntToStr(Ord(AAlgorithm))]));

  System.SetLength(LWrongLengthSignature, System.Length(LSignature) + 1);
  System.Move(LSignature[0], LWrongLengthSignature[0],
    System.Length(LSignature) * System.SizeOf(Byte));
  LWrongLengthSignature[System.Length(LSignature)] := 0;
  LVerifier.Init(False, LPub as ICipherParameters);
  LVerifier.BlockUpdate(LMsg, 0, System.Length(LMsg));
  LShouldNotVerify := LVerifier.VerifySignature(LWrongLengthSignature);
  if LShouldNotVerify then
    Fail(Format('Ed25519(%s) wrong length signature incorrectly verified',
      [IntToStr(Ord(AAlgorithm))]));

  if LMsgLen > 0 then
  begin
    LShouldNotVerify := LVerifier.VerifySignature(LSignature);
    if LShouldNotVerify then
      Fail(Format('Ed25519(%s) wrong length failure did not reset verifier',
        [IntToStr(Ord(AAlgorithm))]));
  end;

  LBadSignature := System.Copy(LSignature);
  LIdx := (FRandom.Next()) mod System.Length(LBadSignature);
  LBit := FRandom.NextInt32() and 7;
  LBadSignature[LIdx] := Byte(LBadSignature[LIdx] xor (1 shl LBit));
  LVerifier.Init(False, LPub as ICipherParameters);
  LVerifier.BlockUpdate(LMsg, 0, System.Length(LMsg));
  LShouldNotVerify := LVerifier.VerifySignature(LBadSignature);
  if LShouldNotVerify then
    Fail(Format('Ed25519(%s) bad signature incorrectly verified',
      [IntToStr(Ord(AAlgorithm))]));
end;

function TTestEd25519HigherLevel.RandomContext(ALength: Int32): TBytes;
begin
  System.SetLength(Result, ALength);
  FRandom.NextBytes(Result);
end;

procedure TTestEd25519HigherLevel.SetUp;
begin
  inherited;
  FRandom := TSecureRandom.Create();
end;

procedure TTestEd25519HigherLevel.TearDown;
begin
  inherited;
end;

procedure TTestEd25519HigherLevel.TestBasicSig;
var
  LPrivKey: IEd25519PrivateKeyParameters;
  LPubKey: IEd25519PublicKeyParameters;
  LSig, LSigGen: TBytes;
  LSigner: ISigner;
begin
  LPrivKey := TEd25519PrivateKeyParameters.Create(DecodeHex(
    '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60'));
  LPubKey := TEd25519PublicKeyParameters.Create(DecodeHex(
    'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a'));

  LSig := DecodeHex(
    'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b');

  LSigner := TEd25519Signer.Create();
  LSigner.Init(True, LPrivKey as ICipherParameters);
  LSigGen := LSigner.GenerateSignature();

  CheckTrue(AreEqual(LSig, LSigGen),
    'Ed25519 basic signature mismatch');

  LSigner.Init(False, LPubKey as ICipherParameters);
  CheckTrue(LSigner.VerifySignature(LSig), 'Ed25519 basic verify');
end;

procedure TTestEd25519HigherLevel.TestConsistencyEd25519;
var
  I: Int32;
begin
  I := 0;
  while I < 10 do
  begin
    DoTestConsistency(TEd25519.TAlgorithm.Ed25519, nil);
    System.Inc(I);
  end;
end;

procedure TTestEd25519HigherLevel.TestConsistencyEd25519ctx;
var
  I: Int32;
  LCtx: TBytes;
begin
  I := 0;
  while I < 10 do
  begin
    LCtx := RandomContext(FRandom.NextInt32() and 255);
    DoTestConsistency(TEd25519.TAlgorithm.Ed25519ctx, LCtx);
    System.Inc(I);
  end;
end;

procedure TTestEd25519HigherLevel.TestConsistencyEd25519ph;
var
  I: Int32;
  LCtx: TBytes;
begin
  I := 0;
  while I < 10 do
  begin
    LCtx := RandomContext(FRandom.NextInt32() and 255);
    DoTestConsistency(TEd25519.TAlgorithm.Ed25519ph, LCtx);
    System.Inc(I);
  end;
end;

procedure TTestEd25519HigherLevel.TestRegressionInfiniteLoopImpl;
var
  LRows: TCryptoLibGenericArray<TEdwardsRegressionRow>;
  I: Int32;
  LRow: TEdwardsRegressionRow;
  LX509PubBytes, LX509PrivBytes, LMsg, LSig, LPubBytes, LPrivBytes: TBytes;
  LPub: IEd25519PublicKeyParameters;
  LPriv: IEd25519PrivateKeyParameters;
  LPubDerived: IEd25519PublicKeyParameters;
  LSigner: ISigner;
  LSigDerived: TBytes;
  LError: String;
begin
  LRows := TEd25519RegressionVectors.GetRows;
  for I := 0 to High(LRows) do
  begin
    LRow := LRows[I];
    LX509PubBytes := DecodeBase64(LRow.PubB64);
    LX509PrivBytes := DecodeBase64(LRow.PrivB64);
    LMsg := DecodeBase64(LRow.MsgB64);
    LSig := DecodeBase64(LRow.SigB64);
    LError := LRow.Comment;

    if System.Length(LX509PubBytes) < 12 then
      Fail('x509PubBytes too short');
    if System.Length(LX509PrivBytes) < 16 then
      Fail('x509PrivBytes too short');
    LPubBytes := CopyOfRange(LX509PubBytes, 12,
      System.Length(LX509PubBytes));
    LPrivBytes := CopyOfRange(LX509PrivBytes, 16,
      System.Length(LX509PrivBytes));

    LPub := TEd25519PublicKeyParameters.Create(LPubBytes);
    LPriv := TEd25519PrivateKeyParameters.Create(LPrivBytes);
    LPubDerived := LPriv.GeneratePublicKey();

    if not AreEqual(LPubDerived.GetEncoded(), LPub.GetEncoded()) then
      Fail('different derived public keys; expected=' + EncodeHex(LPub.GetEncoded()) +
        ' derived=' + EncodeHex(LPubDerived.GetEncoded()));

    LSigner := TEd25519Signer.Create();
    LSigner.Init(True, LPriv as ICipherParameters);
    LSigner.BlockUpdate(LMsg, 0, System.Length(LMsg));
    LSigDerived := LSigner.GenerateSignature();

    if not AreEqual(LSigDerived, LSig) then
      Fail('different signatures of message; expected=' + EncodeHex(LSig) +
        ' actual=' + EncodeHex(LSigDerived));

    LSigner.Init(False, LPub as ICipherParameters);
    LSigner.BlockUpdate(LMsg, 0, System.Length(LMsg));
    CheckTrue(LSigner.VerifySignature(LSig),
      'signature verification failed for test vector: ' + LError);
  end;
end;

procedure TTestEd25519HigherLevel.TestRegressionInfiniteLoop;
begin
  TestRegressionInfiniteLoopImpl();
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestEd25519HigherLevel);
{$ELSE}
  RegisterTest(TTestEd25519HigherLevel.Suite);
{$ENDIF FPC}

end.
