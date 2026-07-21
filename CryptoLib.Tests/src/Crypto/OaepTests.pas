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

unit OaepTests;

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
  ClpIRsaEngine,
  ClpOaepEncoding,
  ClpIAsymmetricBlockCipher,
  ClpIAsymmetricCipherKeyPair,
  ClpIAsymmetricKeyParameter,
  ClpICipherParameters,
  ClpIBufferedCipher,
  ClpCipherUtilities,
  ClpDigestUtilities,
  ClpISecureRandom,
  ClpSecureRandom,
  ClpCryptoLibTypes,
  ClpCryptoLibExceptions,
  CryptoLibTestBase,
  AsymmetricTestVectors;

type

  IVecRand = interface(ISecureRandom)
    ['{A8960FFA-FCD1-4C4E-B60F-D81E97819946}']
    procedure NextBytes(const ABuf: TCryptoLibByteArray); overload;
    procedure NextBytes(const ABuf: TCryptoLibByteArray; AOff, ALen: Int32); overload;
  end;

  TVecRand = class(TSecureRandom, IVecRand)
  private
    FSeed: TCryptoLibByteArray;
  public
    constructor Create(const ASeed: TCryptoLibByteArray);
    procedure NextBytes(const ABuf: TCryptoLibByteArray); override;
    procedure NextBytes(const ABuf: TCryptoLibByteArray; AOff, ALen: Int32); override;
  end;

type

  TTestOaep = class(TCryptoLibAlgorithmTestCase)
  private
    procedure DoEncDec(const ALabel: String;
      const APubParameters, APrivParameters: IAsymmetricKeyParameter;
      const ASeed, AInput, AOutput: TCryptoLibByteArray);

    procedure DoOaepVectorRow(const AVector: TOaepVectorRow);

    procedure DoTestForHighByteError(const ALabel: String; AKeySizeBits: Integer);

  published
    procedure TestBaseOaep;
    procedure TestOaepVectors1024;
    procedure TestOaepVectors1027;
    procedure TestHighByteError;
    procedure TestMixedDigest;
    procedure TestOaep2048Sha256;

  end;

implementation

{ TVecRand }

constructor TVecRand.Create(const ASeed: TCryptoLibByteArray);
begin
  inherited Create;
  FSeed := System.Copy(ASeed);
end;

procedure TVecRand.NextBytes(const ABuf: TCryptoLibByteArray);
begin
  NextBytes(ABuf, 0, System.Length(ABuf));
end;

procedure TVecRand.NextBytes(const ABuf: TCryptoLibByteArray; AOff, ALen: Int32);
begin
  System.Move(FSeed[0], ABuf[AOff], ALen);
end;

{ TTestOaep }

procedure TTestOaep.DoOaepVectorRow(const AVector: TOaepVectorRow);
var
  LKeySet: TOaepKeySetRow;
  LPubParam, LPrivParam: IAsymmetricKeyParameter;
  LSeed, LInput, LOutput: TCryptoLibByteArray;
begin
  LKeySet := TOaepVectors.GetKeySet(AVector.KeySetId);
  LPubParam := TOaepVectors.CreatePublicKey(LKeySet);
  LPrivParam := TOaepVectors.CreatePrivateKey(LKeySet);
  LSeed := TOaepVectors.ResolveSeedBytes(AVector, LKeySet);
  LInput := TOaepVectors.DecodeHexField(AVector.InputHex);
  LOutput := TOaepVectors.DecodeHexField(AVector.OutputHex);
  DoEncDec(AVector.VectorId,
    LPubParam, LPrivParam, LSeed, LInput, LOutput);
end;

procedure TTestOaep.DoEncDec(const ALabel: String;
  const APubParameters, APrivParameters: IAsymmetricKeyParameter;
  const ASeed, AInput, AOutput: TCryptoLibByteArray);
var
  LCipher: IAsymmetricBlockCipher;
  LOutBytes: TCryptoLibByteArray;
  i: Integer;
begin
  LCipher := TOaepEncoding.Create(TRsaEngine.Create() as IRsaEngine);

  LCipher.Init(True,
    TParametersWithRandom.Create(APubParameters as ICipherParameters,
      TVecRand.Create(ASeed) as IVecRand) as IParametersWithRandom);

  LOutBytes := LCipher.ProcessBlock(AInput, 0, System.Length(AInput));

  for i := 0 to System.Length(AOutput) - 1 do
  begin
    if LOutBytes[i] <> AOutput[i] then
    begin
      Fail(ALabel + ' failed encryption');
      Exit;
    end;
  end;

  LCipher.Init(False, APrivParameters as ICipherParameters);

  LOutBytes := LCipher.ProcessBlock(AOutput, 0, System.Length(AOutput));

  for i := 0 to System.Length(AInput) - 1 do
  begin
    if LOutBytes[i] <> AInput[i] then
    begin
      Fail(ALabel + ' failed decoding');
      Exit;
    end;
  end;
end;

procedure TTestOaep.DoTestForHighByteError(const ALabel: String;
  AKeySizeBits: Integer);
var
  LExp: TBigInteger;
  LKpGen: IRsaKeyPairGenerator;
  LKp: IAsymmetricCipherKeyPair;
  LCipher: IAsymmetricBlockCipher;
  LM, LC, LR: TCryptoLibByteArray;
  LKeySizeBytes, LI: Integer;
  LN: TBigInteger;
  LCV: TBigInteger;
  LKo: Boolean;
  LSeed: TCryptoLibByteArray;
begin
  LSeed := TOaepVectors.DecodeHexField(
    TOaepVectors.GetManifestRowsByKeySet('Base1')[0].SeedHex);

  LExp := TBigInteger.One.ShiftLeft(16).Add(TBigInteger.One);

  LKpGen := TRsaKeyPairGenerator.Create();
  LKpGen.Init(TRsaKeyGenerationParameters.Create(LExp,
    TSecureRandom.Create() as ISecureRandom, AKeySizeBits, 100));

  LKp := LKpGen.GenerateKeyPair();

  LCipher := TOaepEncoding.Create(TRsaEngine.Create() as IRsaEngine);

  LCipher.Init(True,
    TParametersWithRandom.Create(LKp.Public as ICipherParameters,
      TVecRand.Create(LSeed) as IVecRand) as IParametersWithRandom);

  SetLength(LM, 1);
  LM[0] := 42;
  LC := LCipher.ProcessBlock(LM, 0, System.Length(LM));

  LKeySizeBytes := (AKeySizeBits + 7) div 8;
  Check(System.Length(LC) = LKeySizeBytes, ALabel + ' failed ciphertext size');

  LN := (LKp.Private as IRsaPrivateCrtKeyParameters).Modulus;

  LCipher.Init(False, LKp.Private as ICipherParameters);
  LR := LCipher.ProcessBlock(LC, 0, LKeySizeBytes);
  Check((System.Length(LR) = 1) and (LR[0] = 42),
    ALabel + ' failed first decryption of test message');

  LR := LCipher.ProcessBlock(LC, 0, LKeySizeBytes);
  Check((System.Length(LR) = 1) and (LR[0] = 42),
    ALabel + ' failed second decryption of test message');

  for LI := (LKeySizeBytes * 8) - 1 downto 0 do
  begin
    LC[LI div 8] := LC[LI div 8] xor Byte(1 shl (LI and 7));
    LKo := True;
    try
      LCV := TBigInteger.Create(1, LC);
      if LCV.CompareTo(LN) < 0 then
      begin
        LR := LCipher.ProcessBlock(LC, 0, LKeySizeBytes);
      end
      else
      begin
        LKo := False;
      end;
    except
      on E: EInvalidCipherTextCryptoLibException do
        LKo := False;
    end;
    Check(not LKo, ALabel + ' invalid ciphertext caused no exception');
    LC[LI div 8] := LC[LI div 8] xor Byte(1 shl (LI and 7));
  end;
end;

procedure TTestOaep.TestBaseOaep;
var
  LRows: TCryptoLibGenericArray<TOaepVectorRow>;
  LI: Integer;
begin
  LRows := TOaepVectors.GetManifestRowsByKeySet('Base1');
  for LI := 0 to High(LRows) do
    DoOaepVectorRow(LRows[LI]);
  LRows := TOaepVectors.GetManifestRowsByKeySet('Base2');
  for LI := 0 to High(LRows) do
    DoOaepVectorRow(LRows[LI]);
  LRows := TOaepVectors.GetManifestRowsByKeySet('Base3');
  for LI := 0 to High(LRows) do
    DoOaepVectorRow(LRows[LI]);
end;

procedure TTestOaep.TestOaepVectors1024;
var
  LRows: TCryptoLibGenericArray<TOaepVectorRow>;
  LI: Integer;
begin
  LRows := TOaepVectors.GetManifestRowsByKeySet('Key1024');
  for LI := 0 to High(LRows) do
    DoOaepVectorRow(LRows[LI]);
end;

procedure TTestOaep.TestOaepVectors1027;
var
  LRows: TCryptoLibGenericArray<TOaepVectorRow>;
  LI: Integer;
begin
  LRows := TOaepVectors.GetManifestRowsByKeySet('Key1027');
  for LI := 0 to High(LRows) do
    DoOaepVectorRow(LRows[LI]);
end;

procedure TTestOaep.TestHighByteError;
begin
  DoTestForHighByteError('invalidCiphertextOaepTest 1024', 1024);
end;

procedure TTestOaep.TestMixedDigest;
var
  LKeySet: TOaepKeySetRow;
  LPubParam, LPrivParam: IAsymmetricKeyParameter;
  LCipher: IAsymmetricBlockCipher;
  LInput, LEnc, LOutput: TCryptoLibByteArray;
  LCBuf: IBufferedCipher;
  LI: Integer;
begin
  LKeySet := TOaepVectors.GetKeySet('Key1027');
  LPubParam := TOaepVectors.CreatePublicKey(LKeySet);
  LPrivParam := TOaepVectors.CreatePrivateKey(LKeySet);

  // SHA-256 hash, SHA-1 MGF1
  LCipher := TOaepEncoding.Create(TRsaEngine.Create() as IRsaEngine,
    TDigestUtilities.GetDigest('SHA-256'),
    TDigestUtilities.GetDigest('SHA-1'), nil);

  LCipher.Init(True,
    TParametersWithRandom.Create(LPubParam as ICipherParameters,
      TSecureRandom.Create() as ISecureRandom) as IParametersWithRandom);

  SetLength(LInput, 10);
  LEnc := LCipher.ProcessBlock(LInput, 0, System.Length(LInput));

  LCipher.Init(False, LPrivParam as ICipherParameters);
  LOutput := LCipher.ProcessBlock(LEnc, 0, System.Length(LEnc));

  for LI := 0 to System.Length(LInput) - 1 do
  begin
    if LOutput[LI] <> LInput[LI] then
    begin
      Fail('mixed digest failed decoding');
      Exit;
    end;
  end;

  // Verify CipherUtilities string-based mixed digest
  LCBuf := TCipherUtilities.GetCipher(
    'RSA/NONE/OAEPWITHSHA-256ANDMGF1WITHSHA-1PADDING');

  LCBuf.Init(False, LPrivParam as ICipherParameters);
  LOutput := LCBuf.DoFinal(LEnc, 0, System.Length(LEnc));

  CheckTrue(AreEqual(LInput, LOutput),
    'CipherUtilities mixed digest failed decoding');

  // SHA-1 hash, SHA-256 MGF1, with encoding params
  LCipher := TOaepEncoding.Create(TRsaEngine.Create() as IRsaEngine,
    TDigestUtilities.GetDigest('SHA-1'),
    TDigestUtilities.GetDigest('SHA-256'),
    DecodeHex('00000000000000000000'));

  LCipher.Init(True,
    TParametersWithRandom.Create(LPubParam as ICipherParameters,
      TSecureRandom.Create() as ISecureRandom) as IParametersWithRandom);

  LOutput := LCipher.ProcessBlock(LInput, 0, System.Length(LInput));

  LCipher.Init(False, LPrivParam as ICipherParameters);
  LOutput := LCipher.ProcessBlock(LOutput, 0, System.Length(LOutput));

  for LI := 0 to System.Length(LInput) - 1 do
  begin
    if LOutput[LI] <> LInput[LI] then
    begin
      Fail('mixed digest with encoding params failed decoding');
      Exit;
    end;
  end;
end;

procedure TTestOaep.TestOaep2048Sha256;
var
  LKeySet: TOaepKeySetRow;
  LVector: TOaepVectorRow;
  LPub2048, LPri2048: IAsymmetricKeyParameter;
  LCipher: IAsymmetricBlockCipher;
  LInput, LOutput, LSeed: TCryptoLibByteArray;
begin
  LKeySet := TOaepVectors.GetKeySet('Key2048');
  LVector := TOaepVectors.GetManifestRowsByKeySet('Key2048')[0];
  LPub2048 := TOaepVectors.CreatePublicKey(LKeySet);
  LPri2048 := TOaepVectors.CreatePrivateKey(LKeySet);

  LInput := TOaepVectors.DecodeHexField(LVector.InputHex);
  LSeed := TOaepVectors.ResolveSeedBytes(LVector, LKeySet);
  LCipher := TOaepEncoding.Create(TRsaEngine.Create() as IRsaEngine,
    TDigestUtilities.GetDigest('SHA-256'));

  LCipher.Init(True,
    TParametersWithRandom.Create(LPub2048 as ICipherParameters,
      TVecRand.Create(LSeed) as IVecRand) as IParametersWithRandom);

  LOutput := LCipher.ProcessBlock(LInput, 0, System.Length(LInput));

  CheckTrue(AreEqual(TOaepVectors.DecodeHexField(LVector.OutputHex), LOutput),
    '2048-bit SHA-256 OAEP encryption failed');

  LCipher.Init(False, LPri2048 as ICipherParameters);
  LOutput := LCipher.ProcessBlock(LOutput, 0, System.Length(LOutput));

  CheckTrue(AreEqual(LInput, LOutput),
    '2048-bit SHA-256 OAEP decryption failed');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestOaep);
{$ELSE}
  RegisterTest(TTestOaep.Suite);
{$ENDIF FPC}

end.
