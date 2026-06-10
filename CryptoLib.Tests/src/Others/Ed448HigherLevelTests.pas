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

unit Ed448HigherLevelTests;

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
  ClpEd448,
  ClpEd448Signer,
  ClpEd448PhSigner,
  ClpEd448Parameters,
  ClpIEd448Parameters,
  ClpEd448Generators,
  ClpIEd448Generators,
  ClpIAsymmetricCipherKeyPair,
  ClpISigner,
  ClpSecureRandom,
  ClpISecureRandom,
  ClpICipherParameters,
  ClpCryptoLibTypes,
  CryptoLibTestBase,
  AsymmetricTestVectors;

type

  TTestEd448HigherLevel = class(TCryptoLibAlgorithmTestCase)
  private
  var
    FRandom: ISecureRandom;

    function CreateSigner(AAlgorithm: TEd448.TAlgorithm;
      const AContext: TBytes): ISigner;
    procedure DoTestConsistency(AAlgorithm: TEd448.TAlgorithm;
      const AContext: TBytes);
    function RandomContext(ALength: Int32): TBytes;
    procedure TestRegressionInfiniteLoopImpl();
  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestBasicSig();
    procedure TestConsistencyEd448();
    procedure TestConsistencyEd448ph();
    procedure TestRegressionInfiniteLoop();
  end;

implementation

{ TTestEd448HigherLevel }

function TTestEd448HigherLevel.CreateSigner(AAlgorithm: TEd448.TAlgorithm;
  const AContext: TBytes): ISigner;
begin
  case AAlgorithm of
    TEd448.TAlgorithm.Ed448:
      Result := TEd448Signer.Create(AContext);
    TEd448.TAlgorithm.Ed448ph:
      Result := TEd448PhSigner.Create(AContext);
  else
    raise EArgumentException.Create('algorithm');
  end;
end;

procedure TTestEd448HigherLevel.DoTestConsistency(AAlgorithm: TEd448.TAlgorithm;
  const AContext: TBytes);
var
  LKpg: IEd448KeyPairGenerator;
  LKp: IAsymmetricCipherKeyPair;
  LPriv: IEd448PrivateKeyParameters;
  LPub: IEd448PublicKeyParameters;
  LMsg, LSignature, LWrongLengthSignature, LBadSignature: TBytes;
  LMsgLen, LIdx, LBit: Int32;
  LSigner, LVerifier: ISigner;
  LShouldVerify, LShouldNotVerify: Boolean;
begin
  LKpg := TEd448KeyPairGenerator.Create() as IEd448KeyPairGenerator;
  LKpg.Init(TEd448KeyGenerationParameters.Create(FRandom)
    as IEd448KeyGenerationParameters);

  LKp := LKpg.GenerateKeyPair();
  LPriv := LKp.Private as IEd448PrivateKeyParameters;
  LPub := LKp.Public as IEd448PublicKeyParameters;

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
    Fail(Format('Ed448(%s) signature failed to verify', [IntToStr(Ord(AAlgorithm))]));

  System.SetLength(LWrongLengthSignature, System.Length(LSignature) + 1);
  System.Move(LSignature[0], LWrongLengthSignature[0],
    System.Length(LSignature) * System.SizeOf(Byte));
  LWrongLengthSignature[System.Length(LSignature)] := 0;
  LVerifier.Init(False, LPub as ICipherParameters);
  LVerifier.BlockUpdate(LMsg, 0, System.Length(LMsg));
  LShouldNotVerify := LVerifier.VerifySignature(LWrongLengthSignature);
  if LShouldNotVerify then
    Fail(Format('Ed448(%s) wrong length signature incorrectly verified',
      [IntToStr(Ord(AAlgorithm))]));

  if LMsgLen > 0 then
  begin
    LShouldNotVerify := LVerifier.VerifySignature(LSignature);
    if LShouldNotVerify then
      Fail(Format('Ed448(%s) wrong length failure did not reset verifier',
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
    Fail(Format('Ed448(%s) bad signature incorrectly verified',
      [IntToStr(Ord(AAlgorithm))]));
end;

function TTestEd448HigherLevel.RandomContext(ALength: Int32): TBytes;
begin
  System.SetLength(Result, ALength);
  FRandom.NextBytes(Result);
end;

procedure TTestEd448HigherLevel.SetUp;
begin
  inherited;
  FRandom := TSecureRandom.Create();
end;

procedure TTestEd448HigherLevel.TearDown;
begin
  inherited;
end;

procedure TTestEd448HigherLevel.TestBasicSig;
var
  LPrivKey: IEd448PrivateKeyParameters;
  LPubKey: IEd448PublicKeyParameters;
  LSig, LSigGen: TBytes;
  LSigner: ISigner;
begin
  LPrivKey := TEd448PrivateKeyParameters.Create(DecodeHex(
    '6c82a562cb808d10d632be89c8513ebf' +
    '6c929f34ddfa8c9f63c9960ef6e348a3' +
    '528c8a3fcc2f044e39a3fc5b94492f8f' +
    '032e7549a20098f95b'));
  LPubKey := TEd448PublicKeyParameters.Create(DecodeHex(
    '5fd7449b59b461fd2ce787ec616ad46a' +
    '1da1342485a70e1f8a0ea75d80e96778' +
    'edf124769b46c7061bd6783df1e50f6c' +
    'd1fa1abeafe8256180'));

  LSig := DecodeHex(
    '533a37f6bbe457251f023c0d88f976ae' +
    '2dfb504a843e34d2074fd823d41a591f' +
    '2b233f034f628281f2fd7a22ddd47d78' +
    '28c59bd0a21bfd3980ff0d2028d4b18a' +
    '9df63e006c5d1c2d345b925d8dc00b41' +
    '04852db99ac5c7cdda8530a113a0f4db' +
    'b61149f05a7363268c71d95808ff2e65' +
    '2600');

  LSigner := TEd448Signer.Create(nil);
  LSigner.Init(True, LPrivKey as ICipherParameters);
  LSigGen := LSigner.GenerateSignature();

  CheckTrue(AreEqual(LSig, LSigGen),
    'Ed448 basic signature mismatch');

  LSigner.Init(False, LPubKey as ICipherParameters);
  CheckTrue(LSigner.VerifySignature(LSig), 'Ed448 basic verify');
end;

procedure TTestEd448HigherLevel.TestConsistencyEd448;
var
  I: Int32;
begin
  for I := 0 to 9 do
    DoTestConsistency(TEd448.TAlgorithm.Ed448,
      RandomContext(FRandom.NextInt32() and 255));
end;

procedure TTestEd448HigherLevel.TestConsistencyEd448ph;
var
  I: Int32;
begin
  for I := 0 to 9 do
    DoTestConsistency(TEd448.TAlgorithm.Ed448ph,
      RandomContext(FRandom.NextInt32() and 255));
end;

procedure TTestEd448HigherLevel.TestRegressionInfiniteLoopImpl;
var
  LRows: TCryptoLibGenericArray<TEdwardsRegressionRow>;
  I: Int32;
  LRow: TEdwardsRegressionRow;
  LX509PubBytes, LX509PrivBytes, LMsg, LSig, LPubBytes, LPrivBytes: TBytes;
  LPub: IEd448PublicKeyParameters;
  LPriv: IEd448PrivateKeyParameters;
  LPubDerived: IEd448PublicKeyParameters;
  LSigner: ISigner;
  LSigDerived: TBytes;
  LError: String;
begin
  LRows := TEd448RegressionVectors.GetRows;
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

    LPub := TEd448PublicKeyParameters.Create(LPubBytes);
    LPriv := TEd448PrivateKeyParameters.Create(LPrivBytes);
    LPubDerived := LPriv.GeneratePublicKey();

    if not AreEqual(LPubDerived.GetEncoded(), LPub.GetEncoded()) then
      Fail('different derived public keys; expected=' + EncodeHex(LPub.GetEncoded()) +
        ' derived=' + EncodeHex(LPubDerived.GetEncoded()));

    LSigner := TEd448Signer.Create(Nil);
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

procedure TTestEd448HigherLevel.TestRegressionInfiniteLoop;
begin
  TestRegressionInfiniteLoopImpl();
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestEd448HigherLevel);
{$ELSE}
  RegisterTest(TTestEd448HigherLevel.Suite);
{$ENDIF FPC}

end.
