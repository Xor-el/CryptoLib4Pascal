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

unit CryptoIOSinkTests;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  Classes,
  SysUtils,
{$IFDEF FPC}
  fpcunit,
  testregistry,
{$ELSE}
  TestFramework,
{$ENDIF FPC}
  ClpDigestSink,
  ClpMacSink,
  ClpSignerSink,
  ClpIDigest,
  ClpIMac,
  ClpISigner,
  ClpDigestUtilities,
  ClpMacUtilities,
  ClpSignerUtilities,
  ClpKeyParameter,
  ClpIKeyParameter,
  ClpRsaGenerators,
  ClpIRsaGenerators,
  ClpRsaParameters,
  ClpIRsaParameters,
  ClpSecureRandom,
  ClpISecureRandom,
  ClpBigInteger,
  ClpIAsymmetricCipherKeyPair,
  ClpCryptoLibTypes,
  CryptoLibTestBase;

type

  TTestDigestSink = class(TCryptoLibAlgorithmTestCase)
  strict private
    function DigestReference(const AData: TCryptoLibByteArray): TCryptoLibByteArray;
  published
    procedure TestWriteMatchesReference;
    procedure TestWriteByteMatchesReference;
    procedure TestNilDigestRaises;
  end;

  TTestMacSink = class(TCryptoLibAlgorithmTestCase)
  strict private
    function MacReference(const AKey, AData: TCryptoLibByteArray): TCryptoLibByteArray;
  published
    procedure TestWriteMatchesReference;
    procedure TestWriteByteMatchesReference;
    procedure TestNilMacRaises;
  end;

  TTestSignerSink = class(TCryptoLibAlgorithmTestCase)
  strict private
    function SignerReference(const AData: TCryptoLibByteArray;
      out ASignature: TCryptoLibByteArray): TCryptoLibByteArray;
  published
    procedure TestWriteMatchesReference;
    procedure TestWriteByteMatchesReference;
    procedure TestNilSignerRaises;
  end;

implementation

{ TTestDigestSink }

function TTestDigestSink.DigestReference(const AData: TCryptoLibByteArray): TCryptoLibByteArray;
var
  LDigest: IDigest;
begin
  LDigest := TDigestUtilities.GetDigest('SHA-256');
  LDigest.BlockUpdate(AData, 0, System.Length(AData));
  Result := LDigest.DoFinal();
end;

procedure TTestDigestSink.TestWriteMatchesReference;
var
  LDataBytes, LExpected, LActual: TCryptoLibByteArray;
  LDigest: IDigest;
  LSink: TDigestSink;
begin
  LDataBytes := TEncoding.UTF8.GetBytes('digest sink write test');
  LExpected := DigestReference(LDataBytes);

  LDigest := TDigestUtilities.GetDigest('SHA-256');
  LSink := TDigestSink.Create(LDigest);
  try
    LSink.Write(LDataBytes[0], System.Length(LDataBytes));
    LActual := LSink.Digest.DoFinal();
    CheckTrue(AreEqual(LExpected, LActual));
  finally
    LSink.Free;
  end;
end;

procedure TTestDigestSink.TestWriteByteMatchesReference;
var
  LDataBytes, LExpected, LActual: TCryptoLibByteArray;
  LDigest: IDigest;
  LSink: TDigestSink;
  LI: Int32;
begin
  LDataBytes := TEncoding.UTF8.GetBytes('abc');
  LExpected := DigestReference(LDataBytes);

  LDigest := TDigestUtilities.GetDigest('SHA-256');
  LSink := TDigestSink.Create(LDigest);
  try
    for LI := 0 to System.Length(LDataBytes) - 1 do
      LSink.WriteByte(LDataBytes[LI]);
    LActual := LSink.Digest.DoFinal();
    CheckTrue(AreEqual(LExpected, LActual));
  finally
    LSink.Free;
  end;
end;

procedure TTestDigestSink.TestNilDigestRaises;
begin
  try
    TDigestSink.Create(nil);
    Fail('Expected EArgumentNilCryptoLibException');
  except
    on E: EArgumentNilCryptoLibException do
      ;
  end;
end;

{ TTestMacSink }

function TTestMacSink.MacReference(const AKey, AData: TCryptoLibByteArray): TCryptoLibByteArray;
var
  LMac: IMac;
begin
  LMac := TMacUtilities.GetMac('HMAC/SHA-256');
  LMac.Init(TKeyParameter.Create(AKey) as IKeyParameter);
  LMac.BlockUpdate(AData, 0, System.Length(AData));
  Result := LMac.DoFinal();
end;

procedure TTestMacSink.TestWriteMatchesReference;
var
  LKey, LDataBytes, LExpected, LActual: TCryptoLibByteArray;
  LMac: IMac;
  LSink: TMacSink;
begin
  LKey := TEncoding.ASCII.GetBytes('0123456789ABCDEF');
  LDataBytes := TEncoding.UTF8.GetBytes('mac sink write test');
  LExpected := MacReference(LKey, LDataBytes);

  LMac := TMacUtilities.GetMac('HMAC/SHA-256');
  LMac.Init(TKeyParameter.Create(LKey) as IKeyParameter);
  LSink := TMacSink.Create(LMac);
  try
    LSink.Write(LDataBytes[0], System.Length(LDataBytes));
    LActual := LSink.Mac.DoFinal();
    CheckTrue(AreEqual(LExpected, LActual));
  finally
    LSink.Free;
  end;
end;

procedure TTestMacSink.TestWriteByteMatchesReference;
var
  LKey, LDataBytes, LExpected, LActual: TCryptoLibByteArray;
  LMac: IMac;
  LSink: TMacSink;
  LI: Int32;
begin
  LKey := TEncoding.ASCII.GetBytes('0123456789ABCDEF');
  LDataBytes := TEncoding.UTF8.GetBytes('xyz');
  LExpected := MacReference(LKey, LDataBytes);

  LMac := TMacUtilities.GetMac('HMAC/SHA-256');
  LMac.Init(TKeyParameter.Create(LKey) as IKeyParameter);
  LSink := TMacSink.Create(LMac);
  try
    for LI := 0 to System.Length(LDataBytes) - 1 do
      LSink.WriteByte(LDataBytes[LI]);
    LActual := LSink.Mac.DoFinal();
    CheckTrue(AreEqual(LExpected, LActual));
  finally
    LSink.Free;
  end;
end;

procedure TTestMacSink.TestNilMacRaises;
begin
  try
    TMacSink.Create(nil);
    Fail('Expected EArgumentNilCryptoLibException');
  except
    on E: EArgumentNilCryptoLibException do
      ;
  end;
end;

{ TTestSignerSink }

function TTestSignerSink.SignerReference(const AData: TCryptoLibByteArray;
  out ASignature: TCryptoLibByteArray): TCryptoLibByteArray;
var
  LKpGen: IRsaKeyPairGenerator;
  LKpParams: IRsaKeyGenerationParameters;
  LKeyPair: IAsymmetricCipherKeyPair;
  LSigner: ISigner;
begin
  LKpGen := TRsaKeyPairGenerator.Create();
  LKpParams := TRsaKeyGenerationParameters.Create(
    TBigInteger.ValueOf($10001),
    TSecureRandom.Create() as ISecureRandom,
    1024,
    80);
  LKpGen.Init(LKpParams);
  LKeyPair := LKpGen.GenerateKeyPair();

  LSigner := TSignerUtilities.GetSigner('SHA-256withRSA');
  LSigner.Init(True, LKeyPair.Private);
  LSigner.BlockUpdate(AData, 0, System.Length(AData));
  ASignature := LSigner.GenerateSignature();

  LSigner.Init(False, LKeyPair.Public);
  LSigner.BlockUpdate(AData, 0, System.Length(AData));
  if not LSigner.VerifySignature(ASignature) then
    Fail('Reference signature verification failed');

  Result := ASignature;
end;

procedure TTestSignerSink.TestWriteMatchesReference;
var
  LDataBytes, LSignature, LReferenceSignature: TCryptoLibByteArray;
  LKpGen: IRsaKeyPairGenerator;
  LKpParams: IRsaKeyGenerationParameters;
  LKeyPair: IAsymmetricCipherKeyPair;
  LSigner: ISigner;
  LSink: TSignerSink;
begin
  LDataBytes := TEncoding.UTF8.GetBytes('signer sink write test');
  LReferenceSignature := SignerReference(LDataBytes, LSignature);

  LKpGen := TRsaKeyPairGenerator.Create();
  LKpParams := TRsaKeyGenerationParameters.Create(
    TBigInteger.ValueOf($10001),
    TSecureRandom.Create() as ISecureRandom,
    1024,
    80);
  LKpGen.Init(LKpParams);
  LKeyPair := LKpGen.GenerateKeyPair();

  LSigner := TSignerUtilities.GetSigner('SHA-256withRSA');
  LSigner.Init(True, LKeyPair.Private);
  LSink := TSignerSink.Create(LSigner);
  try
    LSink.Write(LDataBytes[0], System.Length(LDataBytes));
    LSignature := LSink.Signer.GenerateSignature();

    LSigner.Init(False, LKeyPair.Public);
    LSigner.BlockUpdate(LDataBytes, 0, System.Length(LDataBytes));
    CheckTrue(LSigner.VerifySignature(LSignature));
  finally
    LSink.Free;
  end;

  CheckTrue(System.Length(LReferenceSignature) > 0);
end;

procedure TTestSignerSink.TestWriteByteMatchesReference;
var
  LDataBytes, LSignature: TCryptoLibByteArray;
  LKpGen: IRsaKeyPairGenerator;
  LKpParams: IRsaKeyGenerationParameters;
  LKeyPair: IAsymmetricCipherKeyPair;
  LSigner: ISigner;
  LSink: TSignerSink;
  LI: Int32;
begin
  LDataBytes := TEncoding.UTF8.GetBytes('ab');

  LKpGen := TRsaKeyPairGenerator.Create();
  LKpParams := TRsaKeyGenerationParameters.Create(
    TBigInteger.ValueOf($10001),
    TSecureRandom.Create() as ISecureRandom,
    1024,
    80);
  LKpGen.Init(LKpParams);
  LKeyPair := LKpGen.GenerateKeyPair();

  LSigner := TSignerUtilities.GetSigner('SHA-256withRSA');
  LSigner.Init(True, LKeyPair.Private);
  LSink := TSignerSink.Create(LSigner);
  try
    for LI := 0 to System.Length(LDataBytes) - 1 do
      LSink.WriteByte(LDataBytes[LI]);
    LSignature := LSink.Signer.GenerateSignature();

    LSigner.Init(False, LKeyPair.Public);
    LSigner.BlockUpdate(LDataBytes, 0, System.Length(LDataBytes));
    CheckTrue(LSigner.VerifySignature(LSignature));
  finally
    LSink.Free;
  end;
end;

procedure TTestSignerSink.TestNilSignerRaises;
begin
  try
    TSignerSink.Create(nil);
    Fail('Expected EArgumentNilCryptoLibException');
  except
    on E: EArgumentNilCryptoLibException do
      ;
  end;
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestDigestSink);
  RegisterTest(TTestMacSink);
  RegisterTest(TTestSignerSink);
{$ELSE}
  RegisterTest(TTestDigestSink.Suite);
  RegisterTest(TTestMacSink.Suite);
  RegisterTest(TTestSignerSink.Suite);
{$ENDIF FPC}

end.
