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

unit PssTests;

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
  ClpBigInteger,
  ClpIRsaParameters,
  ClpRsaParameters,
  ClpParametersWithRandom,
  ClpIParametersWithRandom,
  ClpIRsaGenerators,
  ClpRsaGenerators,
  ClpRsaEngine,
  ClpRsaBlindedEngine,
  ClpPssSigner,
  ClpIPssSigner,
  ClpDigestUtilities,
  ClpIDigest,
  ClpIAsymmetricCipherKeyPair,
  ClpISigner,
  ClpSignerUtilities,
  ClpISecureRandom,
  ClpSecureRandom,
  ClpConverters,
  ClpEncoders,
  ClpCryptoLibTypes,
  CryptoLibTestBase,
  AsymmetricTestVectors;

type
  /// <summary>
  /// A SecureRandom that returns a fixed, pre-supplied byte sequence.
  /// </summary>
  IFixedRandom = interface(ISecureRandom)
    ['{B0E9B1D4-7E9D-4E2B-9C9C-2E0E6B2C7F7D}']
    procedure NextBytes(const ABuf: TCryptoLibByteArray); overload;
    procedure NextBytes(const ABuf: TCryptoLibByteArray; AOff, ALen: Int32); overload;
  end;

  /// <summary>
  /// Returns deterministic bytes by copying from FVals into the output buffer.
  /// </summary>
  TFixedRandom = class(TSecureRandom, IFixedRandom)
  private
    FVals: TCryptoLibByteArray;
  public
    constructor Create(const AVals: TCryptoLibByteArray);

    procedure NextBytes(const ABuf: TCryptoLibByteArray); override;
    procedure NextBytes(const ABuf: TCryptoLibByteArray; AOff, ALen: Int32); override;
  end;

type

  TTestPss = class(TCryptoLibAlgorithmTestCase)
  private
  const
    NumLoopTests = 50;

  class var
    FSecureRandom: ISecureRandom;

    class constructor CreateTestPss;

    procedure DoTestPssSignature(id: Integer; const pub, prv: IRsaKeyParameters;
      const salt, msg, sig: TCryptoLibByteArray);
    procedure DoTestLoopSha1;
    procedure DoTestLoopMixedDigest;
    procedure DoTestFixedSalt;
    procedure DoTestSha512ZeroSalt;
    procedure DoSignerUtilitiesSha1;
    procedure DoSignerUtilitiesSha256;
    procedure DoSignerUtilitiesSha384;
    procedure DoSignerUtilitiesSha512;
    procedure DoRawSignerTest;

  published
    procedure TestPssVectors;
    procedure TestLoopSha1;
    procedure TestLoopMixedDigest;
    procedure TestFixedSalt;
    procedure TestSha512ZeroSalt;
    procedure TestSignerUtilitiesSha1;
    procedure TestSignerUtilitiesSha256;
    procedure TestSignerUtilitiesSha384;
    procedure TestSignerUtilitiesSha512;
    procedure TestRawSigner;

  end;

implementation

{ TFixedRandom }

constructor TFixedRandom.Create(const AVals: TCryptoLibByteArray);
begin
  inherited Create;

  FVals := System.Copy(AVals);
end;

procedure TFixedRandom.NextBytes(const ABuf: TCryptoLibByteArray);
begin
  NextBytes(ABuf, 0, System.Length(ABuf));
end;

procedure TFixedRandom.NextBytes(const ABuf: TCryptoLibByteArray; AOff, ALen: Int32);
begin
  System.Move(FVals[0], ABuf[AOff], ALen);
end;

{ TTestPss }

class constructor TTestPss.CreateTestPss;
begin
  FSecureRandom := TSecureRandom.Create();
end;

procedure TTestPss.DoTestPssSignature(id: Integer; const pub, prv: IRsaKeyParameters;
  const salt, msg, sig: TCryptoLibByteArray);
var
  eng: IPssSigner;
  s: TCryptoLibByteArray;
begin
  eng := TPssSigner.Create(TRsaEngine.Create(), TDigestUtilities.GetDigest('SHA-1'), 20);

  eng.Init(True, TParametersWithRandom.Create(prv, TFixedRandom.Create(salt) as IFixedRandom) as IParametersWithRandom);
  eng.BlockUpdate(msg, 0, System.Length(msg));
  s := eng.GenerateSignature();

  CheckTrue(AreEqual(s, sig),
    Format('Test %d: PSS signature generation failed', [id]));

  eng.Init(False, pub);
  eng.BlockUpdate(msg, 0, System.Length(msg));
  CheckTrue(eng.VerifySignature(sig),
    Format('Test %d: PSS signature verification failed', [id]));
end;

procedure TTestPss.DoTestLoopSha1;
var
  eng: IPssSigner;
  data, s: TCryptoLibByteArray;
  failed, j: Integer;
  LKeyRow: TPssVectorRow;
  LPub8: IRsaKeyParameters;
  LPrv8: IRsaPrivateCrtKeyParameters;
begin
  LKeyRow := TPssVectors.GetExampleKeyRow('8');
  LPub8 := TPssVectors.CreatePublicKey(LKeyRow);
  LPrv8 := TPssVectors.CreatePrivateCrtKey(LKeyRow);
  eng := TPssSigner.Create(TRsaEngine.Create(), TDigestUtilities.GetDigest('SHA-1'), 20);
  failed := 0;
  SetLength(data, 1000);

  FSecureRandom.NextBytes(data);

  for j := 0 to NumLoopTests - 1 do
  begin
    eng.Init(True, TParametersWithRandom.Create(LPrv8, FSecureRandom) as IParametersWithRandom);
    eng.BlockUpdate(data, 0, System.Length(data));
    s := eng.GenerateSignature();

    eng.Init(False, LPub8);
    eng.BlockUpdate(data, 0, System.Length(data));

    if not eng.VerifySignature(s) then
      Inc(failed);
  end;

  CheckEquals(0, failed, Format('Loop test failed - failures: %d', [failed]));
end;

procedure TTestPss.DoTestLoopMixedDigest;
var
  eng: IPssSigner;
  data, s: TCryptoLibByteArray;
  failed, j: Integer;
  LKeyRow: TPssVectorRow;
  LPub8: IRsaKeyParameters;
  LPrv8: IRsaPrivateCrtKeyParameters;
begin
  LKeyRow := TPssVectors.GetExampleKeyRow('8');
  LPub8 := TPssVectors.CreatePublicKey(LKeyRow);
  LPrv8 := TPssVectors.CreatePrivateCrtKey(LKeyRow);
  // SHA-256 for content, SHA-1 for MGF
  eng := TPssSigner.Create(TRsaEngine.Create(),
    TDigestUtilities.GetDigest('SHA-256'),
    TDigestUtilities.GetDigest('SHA-1'), 20);
  failed := 0;
  SetLength(data, 1000);

  FSecureRandom.NextBytes(data);

  for j := 0 to NumLoopTests - 1 do
  begin
    eng.Init(True, TParametersWithRandom.Create(LPrv8, FSecureRandom) as IParametersWithRandom);
    eng.BlockUpdate(data, 0, System.Length(data));
    s := eng.GenerateSignature();

    eng.Init(False, LPub8);
    eng.BlockUpdate(data, 0, System.Length(data));

    if not eng.VerifySignature(s) then
      Inc(failed);
  end;

  CheckEquals(0, failed, Format('Mixed digest loop test failed - failures: %d', [failed]));
end;

procedure TTestPss.DoTestFixedSalt;
var
  eng: IPssSigner;
  data, fixedSalt, wrongSalt, s: TCryptoLibByteArray;
  LKeyRow: TPssVectorRow;
  LPub8: IRsaKeyParameters;
  LPrv8: IRsaPrivateCrtKeyParameters;
begin
  LKeyRow := TPssVectors.GetExampleKeyRow('8');
  LPub8 := TPssVectors.CreatePublicKey(LKeyRow);
  LPrv8 := TPssVectors.CreatePrivateCrtKey(LKeyRow);
  data := THexEncoder.Decode('010203040506070809101112131415');
  fixedSalt := THexEncoder.Decode('deadbeef');
  wrongSalt := THexEncoder.Decode('beefbeef');

  // Create signer with fixed salt
  eng := TPssSigner.Create(TRsaBlindedEngine.Create(),
    TDigestUtilities.GetDigest('SHA-256'),
    TDigestUtilities.GetDigest('SHA-1'),
    fixedSalt);

  eng.Init(True, LPrv8);
  eng.BlockUpdate(data, 0, System.Length(data));
  s := eng.GenerateSignature();

  eng.Init(False, LPub8);
  eng.BlockUpdate(data, 0, System.Length(data));
  CheckTrue(eng.VerifySignature(s), 'Fixed salt verification failed');

  // Test failure with wrong salt
  eng := TPssSigner.Create(TRsaBlindedEngine.Create(),
    TDigestUtilities.GetDigest('SHA-256'),
    TDigestUtilities.GetDigest('SHA-1'),
    wrongSalt);

  eng.Init(False, LPub8);
  eng.BlockUpdate(data, 0, System.Length(data));
  CheckFalse(eng.VerifySignature(s), 'Wrong salt should fail verification');
end;

procedure TTestPss.DoTestSha512ZeroSalt;
var
  eng: IPssSigner;
  s: TCryptoLibByteArray;
  LRow: TPssVectorRow;
  LPub1: IRsaKeyParameters;
  LPrv1: IRsaPrivateCrtKeyParameters;
  LMsg1a: TCryptoLibByteArray;
begin
  LRow := TPssVectors.GetRowByTestId(1);
  LPub1 := TPssVectors.CreatePublicKey(LRow);
  LPrv1 := TPssVectors.CreatePrivateCrtKey(LRow);
  LMsg1a := TPssVectors.DecodeMsg(LRow);
  // SHA-512 with zero salt length
  eng := TPssSigner.Create(TRsaEngine.Create(),
    TDigestUtilities.GetDigest('SHA-512'), 0, TPssSigner.TrailerImplicit);

  eng.Init(True, LPrv1);
  eng.BlockUpdate(LMsg1a, 0, System.Length(LMsg1a));
  s := eng.GenerateSignature();

  eng.Init(False, LPub1);
  eng.BlockUpdate(LMsg1a, 0, System.Length(LMsg1a));
  CheckTrue(eng.VerifySignature(s), 'SHA-512 zero salt verification failed');
end;

procedure TTestPss.DoSignerUtilitiesSha1;
var
  kpGen: IRsaKeyPairGenerator;
  kpParams: IRsaKeyGenerationParameters;
  keyPair: IAsymmetricCipherKeyPair;
  signer: ISigner;
  message, signature: TCryptoLibByteArray;
  verified: Boolean;
begin
  kpGen := TRsaKeyPairGenerator.Create();
  kpParams := TRsaKeyGenerationParameters.Create(
    TBigInteger.ValueOf(65537), TSecureRandom.Create(), 2048, 100);
  kpGen.Init(kpParams);
  keyPair := kpGen.GenerateKeyPair();

  message := TConverters.ConvertStringToBytes('Test PSS signature SHA-1',
    TEncoding.UTF8);

  signer := TSignerUtilities.GetSigner('SHA-1withRSAandMGF1');
  signer.Init(True, keyPair.Private);
  signer.BlockUpdate(message, 0, System.Length(message));
  signature := signer.GenerateSignature();

  CheckTrue(System.Length(signature) > 0, 'PSS SHA-1 signature is empty');

  signer.Init(False, keyPair.Public);
  signer.BlockUpdate(message, 0, System.Length(message));
  verified := signer.VerifySignature(signature);

  CheckTrue(verified, 'PSS SHA-1 signature verification failed');
end;

procedure TTestPss.DoSignerUtilitiesSha256;
var
  kpGen: IRsaKeyPairGenerator;
  kpParams: IRsaKeyGenerationParameters;
  keyPair: IAsymmetricCipherKeyPair;
  signer: ISigner;
  &message, signature: TCryptoLibByteArray;
  verified: Boolean;
begin
  kpGen := TRsaKeyPairGenerator.Create();
  kpParams := TRsaKeyGenerationParameters.Create(
    TBigInteger.ValueOf(65537), TSecureRandom.Create(), 2048, 100);
  kpGen.Init(kpParams);
  keyPair := kpGen.GenerateKeyPair();

  &message := TConverters.ConvertStringToBytes('Test PSS signature SHA-256',
    TEncoding.UTF8);

  signer := TSignerUtilities.GetSigner('SHA-256withRSAandMGF1');
  signer.Init(True, keyPair.Private);
  signer.BlockUpdate(&message, 0, System.Length(&message));
  signature := signer.GenerateSignature();

  CheckTrue(System.Length(signature) > 0, 'PSS SHA-256 signature is empty');

  signer.Init(False, keyPair.Public);
  signer.BlockUpdate(&message, 0, System.Length(&message));
  verified := signer.VerifySignature(signature);

  CheckTrue(verified, 'PSS SHA-256 signature verification failed');

  // Test with modified message (should fail)
  &message[0] := &message[0] xor $FF;
  signer.Init(False, keyPair.Public);
  signer.BlockUpdate(&message, 0, System.Length(&message));
  verified := signer.VerifySignature(signature);

  CheckFalse(verified, 'PSS modified message should fail verification');
end;

procedure TTestPss.DoSignerUtilitiesSha384;
var
  kpGen: IRsaKeyPairGenerator;
  kpParams: IRsaKeyGenerationParameters;
  keyPair: IAsymmetricCipherKeyPair;
  signer: ISigner;
  &message, signature: TCryptoLibByteArray;
  verified: Boolean;
begin
  kpGen := TRsaKeyPairGenerator.Create();
  kpParams := TRsaKeyGenerationParameters.Create(
    TBigInteger.ValueOf(65537), TSecureRandom.Create(), 2048, 100);
  kpGen.Init(kpParams);
  keyPair := kpGen.GenerateKeyPair();

  &message := TConverters.ConvertStringToBytes('Test PSS signature SHA-384',
    TEncoding.UTF8);

  signer := TSignerUtilities.GetSigner('SHA-384withRSAandMGF1');
  signer.Init(True, keyPair.Private);
  signer.BlockUpdate(&message, 0, System.Length(&message));
  signature := signer.GenerateSignature();

  CheckTrue(System.Length(signature) > 0, 'PSS SHA-384 signature is empty');

  signer.Init(False, keyPair.Public);
  signer.BlockUpdate(&message, 0, System.Length(&message));
  verified := signer.VerifySignature(signature);

  CheckTrue(verified, 'PSS SHA-384 signature verification failed');
end;

procedure TTestPss.DoSignerUtilitiesSha512;
var
  kpGen: IRsaKeyPairGenerator;
  kpParams: IRsaKeyGenerationParameters;
  keyPair: IAsymmetricCipherKeyPair;
  signer: ISigner;
  &message, signature: TCryptoLibByteArray;
  verified: Boolean;
begin
  kpGen := TRsaKeyPairGenerator.Create();
  kpParams := TRsaKeyGenerationParameters.Create(
    TBigInteger.ValueOf(65537), TSecureRandom.Create(), 2048, 100);
  kpGen.Init(kpParams);
  keyPair := kpGen.GenerateKeyPair();

  &message := TConverters.ConvertStringToBytes('Test PSS signature SHA-512',
    TEncoding.UTF8);

  signer := TSignerUtilities.GetSigner('SHA-512withRSAandMGF1');
  signer.Init(True, keyPair.Private);
  signer.BlockUpdate(&message, 0, System.Length(&message));
  signature := signer.GenerateSignature();

  CheckTrue(System.Length(signature) > 0, 'PSS SHA-512 signature is empty');

  signer.Init(False, keyPair.Public);
  signer.BlockUpdate(&message, 0, System.Length(&message));
  verified := signer.VerifySignature(signature);

  CheckTrue(verified, 'PSS SHA-512 signature verification failed');
end;

procedure TTestPss.DoRawSignerTest;
var
  kpGen: IRsaKeyPairGenerator;
  kpParams: IRsaKeyGenerationParameters;
  keyPair: IAsymmetricCipherKeyPair;
  signer: IPssSigner;
  digest: IDigest;
  hash, signature: TCryptoLibByteArray;
  verified: Boolean;
begin
  kpGen := TRsaKeyPairGenerator.Create();
  kpParams := TRsaKeyGenerationParameters.Create(
    TBigInteger.ValueOf(17), TSecureRandom.Create(), 1024, 100);
  kpGen.Init(kpParams);
  keyPair := kpGen.GenerateKeyPair();

  digest := TDigestUtilities.GetDigest('SHA-256');

  // Generate random hash
  hash := TSecureRandom.GetNextBytes(FSecureRandom, digest.GetDigestSize());

  // Sign with raw signer
  signer := TPssSigner.CreateRawSigner(TRsaBlindedEngine.Create(), digest);
  signer.Init(True, keyPair.Private);
  signer.BlockUpdate(hash, 0, System.Length(hash));
  signature := signer.GenerateSignature();

  // Verify
  signer.Init(False, keyPair.Public);
  signer.BlockUpdate(hash, 0, System.Length(hash));
  verified := signer.VerifySignature(signature);

  CheckTrue(verified, 'Raw signer verification failed');
end;

procedure TTestPss.TestPssVectors;
var
  LRows: TCryptoLibGenericArray<TPssVectorRow>;
  LI: Integer;
  LRow: TPssVectorRow;
begin
  LRows := TPssVectors.GetRows;
  for LI := 0 to High(LRows) do
  begin
    LRow := LRows[LI];
    DoTestPssSignature(LRow.TestId,
      TPssVectors.CreatePublicKey(LRow),
      TPssVectors.CreatePrivateCrtKey(LRow),
      TPssVectors.DecodeSalt(LRow),
      TPssVectors.DecodeMsg(LRow),
      TPssVectors.DecodeSig(LRow));
  end;
end;

procedure TTestPss.TestLoopSha1;
begin
  DoTestLoopSha1;
end;

procedure TTestPss.TestLoopMixedDigest;
begin
  DoTestLoopMixedDigest;
end;

procedure TTestPss.TestFixedSalt;
begin
  DoTestFixedSalt;
end;

procedure TTestPss.TestSha512ZeroSalt;
begin
  DoTestSha512ZeroSalt;
end;

procedure TTestPss.TestSignerUtilitiesSha1;
begin
  DoSignerUtilitiesSha1;
end;

procedure TTestPss.TestSignerUtilitiesSha256;
begin
  DoSignerUtilitiesSha256;
end;

procedure TTestPss.TestSignerUtilitiesSha384;
begin
  DoSignerUtilitiesSha384;
end;

procedure TTestPss.TestSignerUtilitiesSha512;
begin
  DoSignerUtilitiesSha512;
end;

procedure TTestPss.TestRawSigner;
begin
  DoRawSignerTest;
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestPss);
{$ELSE}
  RegisterTest(TTestPss.Suite);
{$ENDIF FPC}

end.
