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

unit Bip340SchnorrTests;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  StrUtils,
  SysUtils,
{$IFDEF FPC}
  fpcunit,
  testregistry,
{$ELSE}
  TestFramework,
{$ENDIF FPC}
  ClpBip340SchnorrBatchVerifier,
  ClpBip340SchnorrParameters,
  ClpIBip340SchnorrParameters,
  ClpParametersWithRandom,
  ClpISecureRandom,
  FixedSecureRandom,
  ClpGeneratorUtilities,
  ClpSignerUtilities,
  ClpKeyGenerationParameters,
  ClpConverters,
  ClpSecureRandom,
  ClpIKeyGenerationParameters,
  ClpISigner,
  ClpICipherParameters,
  ClpIAsymmetricCipherKeyPair,
  ClpIAsymmetricCipherKeyPairGenerator,
  ClpCryptoLibTypes,
  ClpCryptoLibExceptions,
  CryptoLibTestBase,
  Bip340Vectors;

type
  TTestBip340Schnorr = class(TCryptoLibAlgorithmTestCase)
  published
    procedure TestBip340Vectors;
    procedure TestGenerateKeyPairSignAndVerify;
    procedure TestBip340BatchVerifySingleEntry;
    procedure TestBip340BatchVerifyMultipleValid;
    procedure TestBip340BatchVerifyOneInvalidSignature;
    procedure TestBip340BatchVerifyEmptyRaises;
  end;

implementation

{ TTestBip340Schnorr }

procedure TTestBip340Schnorr.TestBip340Vectors;
var
  I: Int32;
  LSigner: ISigner;
  LPrivKey: IBip340SchnorrPrivateKeyParameters;
  LPubKey: IBip340SchnorrPublicKeyParameters;
  LParams: ICipherParameters;
  LSecBytes, LPubBytes, LAuxBytes, LMsgBytes, LSigBytes: TBytes;
  LSig: TBytes;
  LVerify: Boolean;
  LRows: TCryptoLibGenericArray<TBip340VectorRow>;
begin
  LRows := TBip340Vectors.GetRows;
  LSigner := TSignerUtilities.GetSigner('BIP340Schnorr');

  for I := 0 to High(LRows) do
  begin
    LPubBytes := DecodeHex(LRows[I].PublicKey);
    LMsgBytes := DecodeHex(LRows[I].Message);
    LSigBytes := DecodeHex(LRows[I].Signature);

    if LRows[I].SecretKey <> '' then
    begin
      LSecBytes := DecodeHex(LRows[I].SecretKey);
      LPrivKey := TBip340SchnorrPrivateKeyParameters.Create(LSecBytes);
      if LRows[I].AuxRand <> '' then
      begin
        LAuxBytes := DecodeHex(LRows[I].AuxRand);
        LParams := TParametersWithRandom.Create(LPrivKey as ICipherParameters,
          TFixedSecureRandom.From(TCryptoLibMatrixByteArray.Create(LAuxBytes)));
      end
      else
        LParams := LPrivKey as ICipherParameters;

      LSigner.Init(True, LParams);
      if System.Length(LMsgBytes) > 0 then
        LSigner.BlockUpdate(LMsgBytes, 0, System.Length(LMsgBytes));
      LSig := LSigner.GenerateSignature();
      if LRows[I].VerifyResult then
        Check(AreEqual(LSig, LSigBytes), Format('Vector %d: signature mismatch; expected %s actual %s%s', [I, EncodeHex(LSigBytes), EncodeHex(LSig), IfThen(LRows[I].Comment <> '', ' (' + LRows[I].Comment + ')', '')]));
    end;

    try
      LPubKey := TBip340SchnorrPublicKeyParameters.Create(LPubBytes);
    except
      on E: Exception do
      begin
        Check(not LRows[I].VerifyResult, Format('Vector %d: invalid public key but expected verification TRUE%s', [I, IfThen(LRows[I].Comment <> '', ' (' + LRows[I].Comment + ')', '')]));
        continue;
      end;
    end;

    LSigner.Init(False, LPubKey as ICipherParameters);
    if System.Length(LMsgBytes) > 0 then
      LSigner.BlockUpdate(LMsgBytes, 0, System.Length(LMsgBytes));
    LVerify := LSigner.VerifySignature(LSigBytes);
    Check(LVerify = LRows[I].VerifyResult, Format('Vector %d: verification result mismatch (got %s)%s', [I, SysUtils.BoolToStr(LVerify, True), IfThen(LRows[I].Comment <> '', ' (' + LRows[I].Comment + ')', '')]));
  end;
end;

procedure TTestBip340Schnorr.TestGenerateKeyPairSignAndVerify;
var
  LKpg: IAsymmetricCipherKeyPairGenerator;
  LKeyPair: IAsymmetricCipherKeyPair;
  LSigner: ISigner;
  LMessage: TBytes;
  LSignature: TBytes;
begin
  LKpg := TGeneratorUtilities.GetKeyPairGenerator('BIP340Schnorr');
  LKpg.Init(TKeyGenerationParameters.Create(TSecureRandom.Create() as ISecureRandom, 256) as IKeyGenerationParameters);
  LKeyPair := LKpg.GenerateKeyPair();

  LSigner := TSignerUtilities.GetSigner('BIP340Schnorr');
  LMessage := TConverters.ConvertStringToBytes('BIP340 Schnorr test message', TEncoding.UTF8);

  LSigner.Init(True, LKeyPair.Private);
  LSigner.BlockUpdate(LMessage, 0, System.Length(LMessage));
  LSignature := LSigner.GenerateSignature();

  Check(System.Length(LSignature) = 64, 'BIP340 signature must be 64 bytes');

  LSigner.Init(False, LKeyPair.Public);
  LSigner.BlockUpdate(LMessage, 0, System.Length(LMessage));
  Check(LSigner.VerifySignature(LSignature), 'Signature verification must succeed');
end;

procedure TTestBip340Schnorr.TestBip340BatchVerifySingleEntry;
var
  LItems: TCryptoLibGenericArray<TBip340SchnorrVerificationEntry>;
  LEntry: TBip340SchnorrVerificationEntry;
  LRows: TCryptoLibGenericArray<TBip340VectorRow>;
begin
  LRows := TBip340Vectors.GetRows;
  LEntry.PublicKey := DecodeHex(LRows[0].PublicKey);
  LEntry.Message := DecodeHex(LRows[0].Message);
  LEntry.Signature := DecodeHex(LRows[0].Signature);
  LItems := TCryptoLibGenericArray<TBip340SchnorrVerificationEntry>.Create(LEntry);
  Check(TBip340SchnorrBatchVerifier.BatchVerify(LItems), 'Single-entry batch verify (vector 0) must succeed');
end;

procedure TTestBip340Schnorr.TestBip340BatchVerifyMultipleValid;
var
  LItems: TCryptoLibGenericArray<TBip340SchnorrVerificationEntry>;
  LEntry: TBip340SchnorrVerificationEntry;
  LRows: TCryptoLibGenericArray<TBip340VectorRow>;
  I: Int32;
begin
  LRows := TBip340Vectors.GetRows;
  System.SetLength(LItems, 3);
  for I := 0 to 2 do
  begin
    LEntry.PublicKey := DecodeHex(LRows[I].PublicKey);
    LEntry.Message := DecodeHex(LRows[I].Message);
    LEntry.Signature := DecodeHex(LRows[I].Signature);
    LItems[I] := LEntry;
  end;
  Check(TBip340SchnorrBatchVerifier.BatchVerify(LItems), 'Multi-entry batch verify (vectors 0,1,2) must succeed');
end;

procedure TTestBip340Schnorr.TestBip340BatchVerifyOneInvalidSignature;
var
  LItems: TCryptoLibGenericArray<TBip340SchnorrVerificationEntry>;
  LEntry: TBip340SchnorrVerificationEntry;
  LRows: TCryptoLibGenericArray<TBip340VectorRow>;
  I: Int32;
  LSig: TCryptoLibByteArray;
begin
  LRows := TBip340Vectors.GetRows;
  System.SetLength(LItems, 3);
  for I := 0 to 2 do
  begin
    LEntry.PublicKey := DecodeHex(LRows[I].PublicKey);
    LEntry.Message := DecodeHex(LRows[I].Message);
    LEntry.Signature := DecodeHex(LRows[I].Signature);
    LItems[I] := LEntry;
  end;
  LSig := System.Copy(LItems[1].Signature, 0, System.Length(LItems[1].Signature));
  if LSig[0] = 0 then
    LSig[0] := 1
  else
    LSig[0] := 0;
  LItems[1].Signature := LSig;
  Check(not TBip340SchnorrBatchVerifier.BatchVerify(LItems), 'Batch with one invalid signature must fail');
end;

procedure TTestBip340Schnorr.TestBip340BatchVerifyEmptyRaises;
var
  LItems: TCryptoLibGenericArray<TBip340SchnorrVerificationEntry>;
begin
  LItems := nil;
  try
    TBip340SchnorrBatchVerifier.BatchVerify(LItems);
    Fail('BatchVerify with empty array must raise');
  except
    on E: EArgumentCryptoLibException do
      ; // expected
  end;
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestBip340Schnorr);
{$ELSE}
  RegisterTest(TTestBip340Schnorr.Suite);
{$ENDIF FPC}

end.
