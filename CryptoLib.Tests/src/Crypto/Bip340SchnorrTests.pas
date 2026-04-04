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
  ClpFixedSecureRandom,
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
  CryptoLibTestBase;

type
  TBip340VectorRec = record
    SecretKey, PublicKey, AuxRand, Message, Signature: String;
    VerifyResult: Boolean;
    Comment: String;  // from CSV; documents intent of vector (display/failure message only)
  end;

  TTestBip340Schnorr = class(TCryptoLibAlgorithmTestCase)
  strict private
    FVectors: array [0 .. 18] of TBip340VectorRec;
  protected
    procedure SetUp; override;
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

procedure TTestBip340Schnorr.SetUp;
begin
  inherited SetUp;
  // BIP-340 test vectors from https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv
  FVectors[0].SecretKey := '0000000000000000000000000000000000000000000000000000000000000003';
  FVectors[0].PublicKey := 'F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9';
  FVectors[0].AuxRand := '0000000000000000000000000000000000000000000000000000000000000000';
  FVectors[0].Message := '0000000000000000000000000000000000000000000000000000000000000000';
  FVectors[0].Signature := 'E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0';
  FVectors[0].VerifyResult := True;
  FVectors[0].Comment := '';

  FVectors[1].SecretKey := 'B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF';
  FVectors[1].PublicKey := 'DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659';
  FVectors[1].AuxRand := '0000000000000000000000000000000000000000000000000000000000000001';
  FVectors[1].Message := '243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89';
  FVectors[1].Signature := '6896BD60EEAE296DB48A229FF71DFE071BDE413E6D43F917DC8DCF8C78DE33418906D11AC976ABCCB20B091292BFF4EA897EFCB639EA871CFA95F6DE339E4B0A';
  FVectors[1].VerifyResult := True;
  FVectors[1].Comment := '';

  FVectors[2].SecretKey := 'C90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B14E5C9';
  FVectors[2].PublicKey := 'DD308AFEC5777E13121FA72B9CC1B7CC0139715309B086C960E18FD969774EB8';
  FVectors[2].AuxRand := 'C87AA53824B4D7AE2EB035A2B5BBBCCC080E76CDC6D1692C4B0B62D798E6D906';
  FVectors[2].Message := '7E2D58D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A508B75C';
  FVectors[2].Signature := '5831AAEED7B44BB74E5EAB94BA9D4294C49BCF2A60728D8B4C200F50DD313C1BAB745879A5AD954A72C45A91C3A51D3C7ADEA98D82F8481E0E1E03674A6F3FB7';
  FVectors[2].VerifyResult := True;
  FVectors[2].Comment := '';

  FVectors[3].SecretKey := '0B432B2677937381AEF05BB02A66ECD012773062CF3FA2549E44F58ED2401710';
  FVectors[3].PublicKey := '25D1DFF95105F5253C4022F628A996AD3A0D95FBF21D468A1B33F8C160D8F517';
  FVectors[3].AuxRand := 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF';
  FVectors[3].Message := 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF';
  FVectors[3].Signature := '7EB0509757E246F19449885651611CB965ECC1A187DD51B64FDA1EDC9637D5EC97582B9CB13DB3933705B32BA982AF5AF25FD78881EBB32771FC5922EFC66EA3';
  FVectors[3].VerifyResult := True;
  FVectors[3].Comment := 'test fails if msg is reduced modulo p or n';

  FVectors[4].SecretKey := '';
  FVectors[4].PublicKey := 'D69C3509BB99E412E68B0FE8544E72837DFA30746D8BE2AA65975F29D22DC7B9';
  FVectors[4].AuxRand := '';
  FVectors[4].Message := '4DF3C3F68FCC83B27E9D42C90431A72499F17875C81A599B566C9889B9696703';
  FVectors[4].Signature := '00000000000000000000003B78CE563F89A0ED9414F5AA28AD0D96D6795F9C6376AFB1548AF603B3EB45C9F8207DEE1060CB71C04E80F593060B07D28308D7F4';
  FVectors[4].VerifyResult := True;
  FVectors[4].Comment := '';

  FVectors[5].SecretKey := '';
  FVectors[5].PublicKey := 'EEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34';
  FVectors[5].AuxRand := '';
  FVectors[5].Message := '243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89';
  FVectors[5].Signature := '6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E17776969E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B';
  FVectors[5].VerifyResult := False;
  FVectors[5].Comment := 'public key not on the curve';

  FVectors[6].SecretKey := '';
  FVectors[6].PublicKey := 'DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659';
  FVectors[6].AuxRand := '';
  FVectors[6].Message := '243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89';
  FVectors[6].Signature := 'FFF97BD5755EEEA420453A14355235D382F6472F8568A18B2F057A14602975563CC27944640AC607CD107AE10923D9EF7A73C643E166BE5EBEAFA34B1AC553E2';
  FVectors[6].VerifyResult := False;
  FVectors[6].Comment := 'has_even_y(R) is false';

  FVectors[7].SecretKey := '';
  FVectors[7].PublicKey := 'DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659';
  FVectors[7].AuxRand := '';
  FVectors[7].Message := '243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89';
  FVectors[7].Signature := '1FA62E331EDBC21C394792D2AB1100A7B432B013DF3F6FF4F99FCB33E0E1515F28890B3EDB6E7189B630448B515CE4F8622A954CFE545735AAEA5134FCCDB2BD';
  FVectors[7].VerifyResult := False;
  FVectors[7].Comment := 'negated message';

  FVectors[8].SecretKey := '';
  FVectors[8].PublicKey := 'DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659';
  FVectors[8].AuxRand := '';
  FVectors[8].Message := '243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89';
  FVectors[8].Signature := '6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E177769961764B3AA9B2FFCB6EF947B6887A226E8D7C93E00C5ED0C1834FF0D0C2E6DA6';
  FVectors[8].VerifyResult := False;
  FVectors[8].Comment := 'negated s value';

  FVectors[9].SecretKey := '';
  FVectors[9].PublicKey := 'DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659';
  FVectors[9].AuxRand := '';
  FVectors[9].Message := '243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89';
  FVectors[9].Signature := '0000000000000000000000000000000000000000000000000000000000000000123DDA8328AF9C23A94C1FEECFD123BA4FB73476F0D594DCB65C6425BD186051';
  FVectors[9].VerifyResult := False;
  FVectors[9].Comment := 'sG - eP is infinite. Test fails in single verification if has_even_y(inf) is defined as true and x(inf) as 0';

  FVectors[10].SecretKey := '';
  FVectors[10].PublicKey := 'DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659';
  FVectors[10].AuxRand := '';
  FVectors[10].Message := '243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89';
  FVectors[10].Signature := '00000000000000000000000000000000000000000000000000000000000000017615FBAF5AE28864013C099742DEADB4DBA87F11AC6754F93780D5A1837CF197';
  FVectors[10].VerifyResult := False;
  FVectors[10].Comment := 'sG - eP is infinite. Test fails in single verification if has_even_y(inf) is defined as true and x(inf) as 1';

  FVectors[11].SecretKey := '';
  FVectors[11].PublicKey := 'DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659';
  FVectors[11].AuxRand := '';
  FVectors[11].Message := '243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89';
  FVectors[11].Signature := '4A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1D69E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B';
  FVectors[11].VerifyResult := False;
  FVectors[11].Comment := 'sig[0:32] is not an X coordinate on the curve';

  FVectors[12].SecretKey := '';
  FVectors[12].PublicKey := 'DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659';
  FVectors[12].AuxRand := '';
  FVectors[12].Message := '243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89';
  FVectors[12].Signature := 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F69E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B';
  FVectors[12].VerifyResult := False;
  FVectors[12].Comment := 'sig[0:32] is equal to field size';

  FVectors[13].SecretKey := '';
  FVectors[13].PublicKey := 'DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659';
  FVectors[13].AuxRand := '';
  FVectors[13].Message := '243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89';
  FVectors[13].Signature := '6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E177769FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141';
  FVectors[13].VerifyResult := False;
  FVectors[13].Comment := 'sig[32:64] is equal to curve order';

  FVectors[14].SecretKey := '';
  FVectors[14].PublicKey := 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC30';
  FVectors[14].AuxRand := '';
  FVectors[14].Message := '243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89';
  FVectors[14].Signature := '6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E17776969E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B';
  FVectors[14].VerifyResult := False;
  FVectors[14].Comment := 'public key is not a valid X coordinate because it exceeds the field size';

  FVectors[15].SecretKey := '0340034003400340034003400340034003400340034003400340034003400340';
  FVectors[15].PublicKey := '778CAA53B4393AC467774D09497A87224BF9FAB6F6E68B23086497324D6FD117';
  FVectors[15].AuxRand := '0000000000000000000000000000000000000000000000000000000000000000';
  FVectors[15].Message := '';
  FVectors[15].Signature := '71535DB165ECD9FBBC046E5FFAEA61186BB6AD436732FCCC25291A55895464CF6069CE26BF03466228F19A3A62DB8A649F2D560FAC652827D1AF0574E427AB63';
  FVectors[15].VerifyResult := True;
  FVectors[15].Comment := 'message of size 0 (added 2022-12)';

  FVectors[16].SecretKey := '0340034003400340034003400340034003400340034003400340034003400340';
  FVectors[16].PublicKey := '778CAA53B4393AC467774D09497A87224BF9FAB6F6E68B23086497324D6FD117';
  FVectors[16].AuxRand := '0000000000000000000000000000000000000000000000000000000000000000';
  FVectors[16].Message := '11';
  FVectors[16].Signature := '08A20A0AFEF64124649232E0693C583AB1B9934AE63B4C3511F3AE1134C6A303EA3173BFEA6683BD101FA5AA5DBC1996FE7CACFC5A577D33EC14564CEC2BACBF';
  FVectors[16].VerifyResult := True;
  FVectors[16].Comment := 'message of size 1 (added 2022-12)';

  FVectors[17].SecretKey := '0340034003400340034003400340034003400340034003400340034003400340';
  FVectors[17].PublicKey := '778CAA53B4393AC467774D09497A87224BF9FAB6F6E68B23086497324D6FD117';
  FVectors[17].AuxRand := '0000000000000000000000000000000000000000000000000000000000000000';
  FVectors[17].Message := '0102030405060708090A0B0C0D0E0F1011';
  FVectors[17].Signature := '5130F39A4059B43BC7CAC09A19ECE52B5D8699D1A71E3C52DA9AFDB6B50AC370C4A482B77BF960F8681540E25B6771ECE1E5A37FD80E5A51897C5566A97EA5A5';
  FVectors[17].VerifyResult := True;
  FVectors[17].Comment := 'message of size 17 (added 2022-12)';

  FVectors[18].SecretKey := '0340034003400340034003400340034003400340034003400340034003400340';
  FVectors[18].PublicKey := '778CAA53B4393AC467774D09497A87224BF9FAB6F6E68B23086497324D6FD117';
  FVectors[18].AuxRand := '0000000000000000000000000000000000000000000000000000000000000000';
  FVectors[18].Message := '99999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999';
  FVectors[18].Signature := '403B12B0D8555A344175EA7EC746566303321E5DBFA8BE6F091635163ECA79A8585ED3E3170807E7C03B720FC54C7B23897FCBA0E9D0B4A06894CFD249F22367';
  FVectors[18].VerifyResult := True;
  FVectors[18].Comment := 'message of size 100 (added 2022-12)';
end;

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
begin
  LSigner := TSignerUtilities.GetSigner('BIP340Schnorr');

  for I := 0 to 18 do
  begin
    LPubBytes := DecodeHex(FVectors[I].PublicKey);
    LMsgBytes := DecodeHex(FVectors[I].Message);
    LSigBytes := DecodeHex(FVectors[I].Signature);

    if FVectors[I].SecretKey <> '' then
    begin
      LSecBytes := DecodeHex(FVectors[I].SecretKey);
      LPrivKey := TBip340SchnorrPrivateKeyParameters.Create(LSecBytes);
      if FVectors[I].AuxRand <> '' then
      begin
        LAuxBytes := DecodeHex(FVectors[I].AuxRand);
        LParams := TParametersWithRandom.Create(LPrivKey as ICipherParameters,
          TFixedSecureRandom.From(TCryptoLibMatrixByteArray.Create(LAuxBytes)));
      end
      else
        LParams := LPrivKey as ICipherParameters;

      LSigner.Init(True, LParams);
      if System.Length(LMsgBytes) > 0 then
        LSigner.BlockUpdate(LMsgBytes, 0, System.Length(LMsgBytes));
      LSig := LSigner.GenerateSignature();
      if FVectors[I].VerifyResult then
        Check(AreEqual(LSig, LSigBytes), Format('Vector %d: signature mismatch; expected %s actual %s%s', [I, EncodeHex(LSigBytes), EncodeHex(LSig), IfThen(FVectors[I].Comment <> '', ' (' + FVectors[I].Comment + ')', '')]));
    end;

    try
      LPubKey := TBip340SchnorrPublicKeyParameters.Create(LPubBytes);
    except
      on E: Exception do
      begin
        Check(not FVectors[I].VerifyResult, Format('Vector %d: invalid public key but expected verification TRUE%s', [I, IfThen(FVectors[I].Comment <> '', ' (' + FVectors[I].Comment + ')', '')]));
        continue;
      end;
    end;

    LSigner.Init(False, LPubKey as ICipherParameters);
    if System.Length(LMsgBytes) > 0 then
      LSigner.BlockUpdate(LMsgBytes, 0, System.Length(LMsgBytes));
    LVerify := LSigner.VerifySignature(LSigBytes);
    Check(LVerify = FVectors[I].VerifyResult, Format('Vector %d: verification result mismatch (got %s)%s', [I, SysUtils.BoolToStr(LVerify, True), IfThen(FVectors[I].Comment <> '', ' (' + FVectors[I].Comment + ')', '')]));
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
begin
  // Vector 0 is valid
  LEntry.PublicKey := DecodeHex(FVectors[0].PublicKey);
  LEntry.Message := DecodeHex(FVectors[0].Message);
  LEntry.Signature := DecodeHex(FVectors[0].Signature);
  LItems := TCryptoLibGenericArray<TBip340SchnorrVerificationEntry>.Create(LEntry);
  Check(TBip340SchnorrBatchVerifier.BatchVerify(LItems), 'Single-entry batch verify (vector 0) must succeed');
end;

procedure TTestBip340Schnorr.TestBip340BatchVerifyMultipleValid;
var
  LItems: TCryptoLibGenericArray<TBip340SchnorrVerificationEntry>;
  LEntry: TBip340SchnorrVerificationEntry;
  I: Int32;
begin
  // Vectors 0, 1, 2 are all valid
  System.SetLength(LItems, 3);
  for I := 0 to 2 do
  begin
    LEntry.PublicKey := DecodeHex(FVectors[I].PublicKey);
    LEntry.Message := DecodeHex(FVectors[I].Message);
    LEntry.Signature := DecodeHex(FVectors[I].Signature);
    LItems[I] := LEntry;
  end;
  Check(TBip340SchnorrBatchVerifier.BatchVerify(LItems), 'Multi-entry batch verify (vectors 0,1,2) must succeed');
end;

procedure TTestBip340Schnorr.TestBip340BatchVerifyOneInvalidSignature;
var
  LItems: TCryptoLibGenericArray<TBip340SchnorrVerificationEntry>;
  LEntry: TBip340SchnorrVerificationEntry;
  I: Int32;
  LSig: TCryptoLibByteArray;
begin
  System.SetLength(LItems, 3);
  for I := 0 to 2 do
  begin
    LEntry.PublicKey := DecodeHex(FVectors[I].PublicKey);
    LEntry.Message := DecodeHex(FVectors[I].Message);
    LEntry.Signature := DecodeHex(FVectors[I].Signature);
    LItems[I] := LEntry;
  end;
  // Flip one bit in the second signature
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
