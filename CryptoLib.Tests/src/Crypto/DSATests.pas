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

unit DSATests;

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
  ClpAsn1Core,
  ClpISigner,
  ClpIDsaSigner,
  ClpDsaSigner,
  ClpIDsaParameters,
  ClpDsaParameters,
  ClpECCurve,
  ClpECParameters,
  ClpIECParameters,
  ClpIAsn1Objects,
  ClpDsaGenerators,
  ClpIDsaGenerators,
  ClpIAsymmetricCipherKeyPairGenerator,
  ClpIAsymmetricCipherKeyPair,
  ClpIAsymmetricKeyParameter,
  ClpParametersWithRandom,
  ClpIParametersWithRandom,
  ClpSignerUtilities,
  ClpDigestUtilities,
  ClpGeneratorUtilities,
  ClpTeleTrusTObjectIdentifiers,
  ClpX9ObjectIdentifiers,
  ClpBigInteger,
  ClpAsn1Objects,
  ClpIDSADigestSigner,
  ClpX509DsaAsn1Objects,
  ClpIX509DsaAsn1Objects,
  ClpISecureRandom,
  ClpSecureRandom,
  FixedSecureRandom,
  ClpConverters,
  ClpCryptoLibTypes,
  CryptoLibTestBase,
  AsymmetricTestVectors;

type
  IDSATestSecureRandom = interface(IFixedSecureRandom)
    ['{EE74B77E-4383-4C78-98FD-572482A5CAC3}']
  end;

type
  TDSATestSecureRandom = class(TFixedSecureRandom, IDSATestSecureRandom)

  strict private
    Ffirst: Boolean;

  public
    constructor Create(const value: TBytes);

    procedure NextBytes(const bytes: TBytes); override;

  end;

type

  /// <summary>
  /// Test based on FIPS 186-2, Appendix 5, an example of DSA, and FIPS 168-3 test vectors.
  /// </summary>
  TTestDSA = class(TCryptoLibAlgorithmTestCase)

  private

    procedure RunFips1862GoldenCase(const ACase: TDsaFips1862GoldenCase);
    procedure RunTestDsa512GenCase;
    procedure RunFips1863Row(const ARow: TDsaFips1863Row);
    procedure RunDsa2ParametersCase;
    procedure RunParametersSmokeCase;
    procedure RunEcdsaSignVerifyVector(const AVector: TEcdsaVectorRow);
    procedure RunEcdsaDigestBinaryVector(const AVector: TEcdsaVectorRow;
      const AOid: IDerObjectIdentifier);

    procedure DoCheckMessage(const sgr: ISigner;
      const sKey: IECPrivateKeyParameters; const vKey: IECPublicKeyParameters;
      const &message, sig: TBytes);

    procedure DoTestKeyGeneration(keysize: Int32);
    procedure DoTestBadStrength(strength: Int32);

    function DoDerDecode(const encoding: TBytes)
      : TCryptoLibGenericArray<TBigInteger>;

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published

    procedure TestDSA;
    procedure TestNONEwithDSA;
    procedure TestNONEwithECDSA239bitPrime;
    procedure TestECDsa239BitBinaryRipeMD160;
    procedure TestECDsa239BitBinarySha1;
    procedure TestECDsa239BitBinarySha224;
    procedure TestECDsa239BitBinarySha256;
    procedure TestECDsa239BitBinarySha384;
    procedure TestECDsa239BitBinarySha512;
    procedure TestGeneration;
    procedure TestDsa2Parameters;
    procedure TestKeyGenerationAll;
    procedure TestParameters;
    procedure TestModulusSizeBound;

    /// <summary>
    /// <para>
    /// X9.62 - 1998, J.3.2, Page 155, ECDSA over the field <c>Fp</c>
    /// </para>
    /// <para>
    /// <c>an example with 239 bit prime</c>
    /// </para>
    /// </summary>
    procedure TestECDsa239BitPrime;

    /// <summary>
    /// <para>
    /// X9.62 - 1998, J.2.1, Page 100, ECDSA over the field F2m
    /// </para>
    /// <para>
    /// an example with 191 bit binary field
    /// </para>
    /// </summary>
    procedure TestECDsa239BitBinary;

  end;

implementation

{ TTestDSA }

procedure TTestDSA.DoCheckMessage(const sgr: ISigner;
  const sKey: IECPrivateKeyParameters; const vKey: IECPublicKeyParameters;
  const &message, sig: TBytes);
var
  kData, sigBytes: TBytes;
  k: ISecureRandom;
begin

  kData := TBigInteger.Create
    ('700000017569056646655505781757157107570501575775705779575555657156756655')
    .ToByteArrayUnsigned;

  k := TFixedSecureRandom.From(TCryptoLibMatrixByteArray.Create(kData));

  sgr.Init(true, TParametersWithRandom.Create(sKey, k)
    as IParametersWithRandom);

  sgr.BlockUpdate(&message, 0, System.Length(&message));

  sigBytes := sgr.GenerateSignature();

  if (not AreEqual(sigBytes, sig)) then
  begin
    Fail(Format('%s %s', [TConverters.ConvertBytesToString(&message,
      TEncoding.UTF8), 'signature incorrect']));
  end;

  sgr.Init(false, vKey);

  sgr.BlockUpdate(&message, 0, System.Length(&message));

  if (not(sgr.VerifySignature(sigBytes))) then
  begin
    Fail(Format('%s %s', [TConverters.ConvertBytesToString(&message,
      TEncoding.UTF8), 'verification failed']));
  end;
end;

function TTestDSA.DoDerDecode(const encoding: TBytes)
  : TCryptoLibGenericArray<TBigInteger>;
var
  s: IAsn1Sequence;
begin
  s := TAsn1Object.FromByteArray(encoding) as IAsn1Sequence;

  result := TCryptoLibGenericArray<TBigInteger>.Create
    ((s[0] as IDerInteger).value, (s[1] as IDerInteger).value);
end;

procedure TTestDSA.DoTestBadStrength(strength: Int32);
var
  rand: ISecureRandom;
  pGen: IDsaParametersGenerator;
begin
  try

    rand := TSecureRandom.Create();
    pGen := TDsaParametersGenerator.Create();
    pGen.Init(strength, 80, rand);
    Fail('illegal parameter ' + IntToStr(strength) + ' check failed.');

  except
    on e: EArgumentCryptoLibException do
    begin
      // expected
    end;

  end;
end;

procedure TTestDSA.RunFips1862GoldenCase(const ACase: TDsaFips1862GoldenCase);
var
  LSeed, LMsg: TBytes;
  LPGen: IDsaParametersGenerator;
  LParams: IDSAParameters;
  LPv: IDSAValidationParameters;
  LKpGen: IDSAKeyPairGenerator;
  LKp: IAsymmetricCipherKeyPair;
  LPub: IDSAPublicKeyParameters;
  LPriv: IDSAPrivateKeyParameters;
  LSigner: IDSASigner;
  LSig: TCryptoLibGenericArray<TBigInteger>;
  LKeyRandom: ISecureRandom;
begin
  LSeed := TDsaVectors.DecodeHexField(ACase.ParamGen.SeedHex);

  if ACase.ParamGen.DigestName = '' then
    LPGen := TDsaParametersGenerator.Create()
  else
    LPGen := TDsaParametersGenerator.Create(
      TDigestUtilities.GetDigest(ACase.ParamGen.DigestName));

  LPGen.Init(TDSAParameterGenerationParameters.Create(ACase.ParamGen.L,
    ACase.ParamGen.N, ACase.ParamGen.Certainty,
    TDSATestSecureRandom.Create(LSeed)) as IDSAParameterGenerationParameters);

  LParams := LPGen.GenerateParameters();
  LPv := LParams.getValidationParameters();

  if (LPv.GetCounter() <> ACase.ParamGen.Expected.Counter) then
    Fail('counter incorrect');

  if (not AreEqual(LSeed, LPv.seed)) then
    Fail('seed incorrect');

  if (not LParams.Q.Equals(TBigInteger.Create(ACase.ParamGen.Expected.QHex, 16))) then
    Fail('Q incorrect');

  if (not LParams.p.Equals(TBigInteger.Create(ACase.ParamGen.Expected.PHex, 16))) then
    Fail('P incorrect');

  if (not LParams.G.Equals(TBigInteger.Create(ACase.ParamGen.Expected.GHex, 16))) then
    Fail('G incorrect');

  LKpGen := TDSAKeyPairGenerator.Create();

  if SameText(ACase.KeyGen.RandomType, 'BigIntegerByteArray') then
  begin
    LKeyRandom := TFixedSecureRandom.Create(TCryptoLibGenericArray<ISource>.Create
      (TFixedSecureRandom.TBigIntegerSource.Create(TBigInteger.Create
      (ACase.KeyGen.PrivateSeedHex, 16).ToByteArrayUnsigned)));
  end
  else
  begin
    if ACase.KeyGen.PrivateSeedHex <> '' then
      LKeyRandom := TFixedSecureRandom.Create(TCryptoLibGenericArray<ISource>.Create
        (TFixedSecureRandom.TData.Create(
        TDsaVectors.DecodeHexField(ACase.KeyGen.PrivateSeedHex))))
    else
      LKeyRandom := TFixedSecureRandom.Create(TCryptoLibGenericArray<ISource>.Create
        (TFixedSecureRandom.TData.Create(
        TDsaVectors.DecodeHexField(ACase.KeyGen.ExpectedXHex))));
  end;

  LKpGen.Init(TDSAKeyGenerationParameters.Create(LKeyRandom, LParams)
    as IDSAKeyGenerationParameters);

  LKp := LKpGen.GenerateKeyPair();
  LPub := LKp.Public as IDSAPublicKeyParameters;
  LPriv := LKp.Private as IDSAPrivateKeyParameters;

  if (not LPub.Y.Equals(TBigInteger.Create(ACase.KeyGen.ExpectedYHex, 16))) then
    Fail('Y value incorrect');

  if (not LPriv.X.Equals(TBigInteger.Create(ACase.KeyGen.ExpectedXHex, 16))) then
    Fail('X value incorrect');

  LSigner := TDSASigner.Create();
  LSigner.Init(true, TParametersWithRandom.Create(LKp.Private,
    TFixedSecureRandom.Create(TCryptoLibGenericArray<ISource>.Create
    (TFixedSecureRandom.TBigIntegerSource.Create(ACase.Sign.KBigInt),
    TFixedSecureRandom.TData.Create(
    TDsaVectors.DecodeHexField(ACase.Sign.KPadHex))))) as IParametersWithRandom);

  LMsg := TDsaVectors.DecodeHexField(ACase.Sign.MessageHex);
  LSig := LSigner.GenerateSignature(LMsg);

  if (not LSig[0].Equals(TBigInteger.Create(ACase.Sign.ExpectedRHex, 16))) then
    Fail('R value incorrect');

  if (not LSig[1].Equals(TBigInteger.Create(ACase.Sign.ExpectedSHex, 16))) then
    Fail('S value incorrect');

  LSigner.Init(false, LKp.Public);

  if (not LSigner.VerifySignature(LMsg, LSig[0], LSig[1])) then
    Fail('signature not verified');
end;

procedure TTestDSA.RunTestDsa512GenCase;
var
  LCase: TDsa512GenCase;
  LRandom, LKeyRandom: ISecureRandom;
  LSig: TCryptoLibGenericArray<TBigInteger>;
  LPValue, LQValue, LR, LS: TBigInteger;
  LPGen: IDsaParametersGenerator;
  LParams: IDSAParameters;
  LPValid: IDSAValidationParameters;
  LDsaKeyGen: IDSAKeyPairGenerator;
  LGenParam: IDSAKeyGenerationParameters;
  LPair: IAsymmetricCipherKeyPair;
  LParam: IParametersWithRandom;
  LDsa: IDSASigner;
  LMessage: TBytes;
begin
  LCase := TDsaVectors.GetTestDsa512GenCase;

  LRandom := TFixedSecureRandom.Create(TCryptoLibGenericArray<ISource>.Create
    (TFixedSecureRandom.TData.Create(TDsaVectors.DecodeHexField(LCase.ParamGenRandom[0])),
    TFixedSecureRandom.TData.Create(TDsaVectors.DecodeHexField(LCase.ParamGenRandom[1]))));

  LKeyRandom := TFixedSecureRandom.Create(TCryptoLibGenericArray<ISource>.Create
    (TFixedSecureRandom.TData.Create(TDsaVectors.DecodeHexField(LCase.KeyGenRandom[0])),
    TFixedSecureRandom.TData.Create(TDsaVectors.DecodeHexField(LCase.KeyGenRandom[1])),
    TFixedSecureRandom.TData.Create(TDsaVectors.DecodeHexField(LCase.KeyGenPadHex))));

  LPValue := TBigInteger.Create(LCase.ExpectedPHex, 16);
  LQValue := TBigInteger.Create(LCase.ExpectedQHex, 16);
  LR := TBigInteger.Create(LCase.ExpectedR);
  LS := TBigInteger.Create(LCase.ExpectedS);

  LPGen := TDsaParametersGenerator.Create();
  LPGen.Init(LCase.L, LCase.Certainty, LRandom);
  LParams := LPGen.GenerateParameters();
  LPValid := LParams.ValidationParameters;

  if (LPValid.GetCounter() <> LCase.ExpectedCounter) then
    Fail('Counter wrong');

  if ((not LPValue.Equals(LParams.p)) or (not LQValue.Equals(LParams.Q))) then
    Fail('p or q wrong');

  LDsaKeyGen := TDSAKeyPairGenerator.Create();
  LGenParam := TDSAKeyGenerationParameters.Create(LKeyRandom, LParams);
  LDsaKeyGen.Init(LGenParam);
  LPair := LDsaKeyGen.GenerateKeyPair();
  LParam := TParametersWithRandom.Create(LPair.Private, LKeyRandom);
  LDsa := TDSASigner.Create();
  LDsa.Init(true, LParam);

  LMessage := TBigInteger.Create(LCase.MessageDecimal).ToByteArrayUnsigned;
  LSig := LDsa.GenerateSignature(LMessage);

  if (not LR.Equals(LSig[0])) then
    Fail('r component wrong. expected ' + LR.toString + ' but got ' + LSig[0].toString);

  if (not LS.Equals(LSig[1])) then
    Fail('s component wrong. expected ' + LS.toString + ' but got ' + LSig[1].toString);

  LDsa.Init(false, LPair.Public);

  if (not LDsa.VerifySignature(LMessage, LSig[0], LSig[1])) then
    Fail('verification fails');
end;

procedure TTestDSA.RunFips1863Row(const ARow: TDsaFips1863Row);
var
  LDsaParams: IDSAParameters;
  LPriKey: IDSAPrivateKeyParameters;
  LPubKey: IDSAPublicKeyParameters;
  LK: ISecureRandom;
  LM, LEncSig: TBytes;
  LDsa: IDSADigestSigner;
  LRS: TCryptoLibGenericArray<TBigInteger>;
  LR: TBigInteger;
begin
  LDsaParams := TDsaVectors.BuildParametersFromFips1863Row(ARow);
  LPriKey := TDsaVectors.BuildPrivateKey(ARow.XHex, LDsaParams);
  LPubKey := TDsaVectors.BuildPublicKey(ARow.YHex, LDsaParams);

  LK := TFixedSecureRandom.Create(TCryptoLibGenericArray<ISource>.Create
    (TFixedSecureRandom.TBigIntegerSource.Create(TBigInteger.Create(ARow.KBigInt)
    .ToByteArrayUnsigned), TFixedSecureRandom.TData.Create(
    TDsaVectors.DecodeHexField(ARow.KPadHex))));

  LM := TDsaVectors.DecodeHexField(ARow.MessageHex);
  LDsa := TDsaVectors.BuildDigestSigner(ARow.DigestName);
  LDsa.Init(true, TParametersWithRandom.Create(LPriKey, LK) as IParametersWithRandom);
  LDsa.BlockUpdate(LM, 0, System.Length(LM));
  LEncSig := LDsa.GenerateSignature();
  LRS := DoDerDecode(LEncSig);
  LR := TBigInteger.Create(ARow.ExpectedRHex, 16);

  if (not LR.Equals(LRS[0])) then
    Fail('r component wrong.' + sLineBreak + ' expecting: ' + LR.toString(16) +
      sLineBreak + ' got      : ' + LRS[0].toString(16));

  if (not TBigInteger.Create(ARow.ExpectedSHex, 16).Equals(LRS[1])) then
    Fail('s component wrong.' + sLineBreak + ' expecting: ' + ARow.ExpectedSHex +
      sLineBreak + ' got      : ' + LRS[1].toString(16));

  LDsa.Init(false, LPubKey);
  LDsa.BlockUpdate(LM, 0, System.Length(LM));

  if (not LDsa.VerifySignature(LEncSig)) then
    Fail('signature fails');
end;

procedure TTestDSA.RunDsa2ParametersCase;
var
  LCase: TDsa2ParametersCase;
  LSeed, LEncodeParams, LEncodeParams2, LData, LSigBytes: TBytes;
  LA: IDsaParametersGenerator;
  LDsaP: IDSAParameters;
  LG: IAsymmetricCipherKeyPairGenerator;
  LP: IAsymmetricCipherKeyPair;
  LSKey: IDSAPrivateKeyParameters;
  LVKey: IDSAPublicKeyParameters;
  LP2: IDSAParameters;
  LS: ISigner;
  LI: Integer;
begin
  LCase := TDsaVectors.GetDsa2ParametersCase;
  LSeed := TDsaVectors.DecodeHexField(LCase.SeedHex);

  LA := TDsaParametersGenerator.Create(TDigestUtilities.GetDigest(LCase.DigestName));
  LA.Init(TDSAParameterGenerationParameters.Create(LCase.L, LCase.N, LCase.Certainty,
    TDSATestSecureRandom.Create(LSeed) as ISecureRandom)
    as IDSAParameterGenerationParameters);

  LDsaP := LA.GenerateParameters();

  if (not LDsaP.Q.Equals(TBigInteger.Create(LCase.ExpectedQHex, 16))) then
    Fail('Q incorrect');

  if (not LDsaP.p.Equals(TBigInteger.Create(LCase.ExpectedPHex, 16))) then
    Fail('P incorrect');

  if (not LDsaP.G.Equals(TBigInteger.Create(LCase.ExpectedGHex, 16))) then
    Fail('G incorrect');

  LG := TGeneratorUtilities.GetKeyPairGenerator('DSA');
  LG.Init(TDSAKeyGenerationParameters.Create(TFixedSecureRandom.From
    (TCryptoLibMatrixByteArray.Create(
    TDsaVectors.DecodeHexField(LCase.KeyGenPrivateSeedHex))), LDsaP)
    as IDSAKeyGenerationParameters);

  LP := LG.GenerateKeyPair();
  LSKey := LP.Private as IDSAPrivateKeyParameters;
  LVKey := LP.Public as IDSAPublicKeyParameters;

  if (not LVKey.Y.Equals(TBigInteger.Create(LCase.ExpectedYHex, 16))) then
    Fail('Y value incorrect');

  if (not LSKey.X.Equals(TBigInteger.Create(LCase.ExpectedXHex, 16))) then
    Fail('X value incorrect');

  LEncodeParams := (TDsaParameter.Create(LDsaP.p, LDsaP.Q, LDsaP.G) as IDsaParameter).GetDerEncoded();
  LP2 := TDSAParameters.Create(LDsaP.p, LDsaP.Q, LDsaP.G);
  LEncodeParams2 := (TDsaParameter.Create(LP2.p, LP2.Q, LP2.G) as IDsaParameter).GetDerEncoded();

  if (not AreEqual(LEncodeParams, LEncodeParams2)) then
    Fail('encode/decode parameters failed');

  LS := TSignerUtilities.GetSigner('DSA');
  SetLength(LData, Length(LCase.SignMessageBytes));
  for LI := 0 to High(LCase.SignMessageBytes) do
    LData[LI] := LCase.SignMessageBytes[LI];

  LS.Init(true, LSKey);
  LS.BlockUpdate(LData, 0, System.Length(LData));
  LSigBytes := LS.GenerateSignature();

  LS := TSignerUtilities.GetSigner('DSA');
  LS.Init(false, LVKey);
  LS.BlockUpdate(LData, 0, System.Length(LData));

  if (not LS.VerifySignature(LSigBytes)) then
    Fail('DSA verification failed');
end;

procedure TTestDSA.RunParametersSmokeCase;
var
  LCase: TDsaParametersSmokeCase;
  LRandom: ISecureRandom;
  LA: IDsaParametersGenerator;
  LP: IDSAParameters;
  LEncodeParams, LEncodeParams2, LData, LSigBytes: TBytes;
  LDsaP: IDsaParameter;
  LP2: IDSAParameters;
  LG: IAsymmetricCipherKeyPairGenerator;
  LPair: IAsymmetricCipherKeyPair;
  LSKey, LVKey: IAsymmetricKeyParameter;
  LS: ISigner;
  LChunks: TCryptoLibMatrixByteArray;
  LI: Integer;
begin
  LCase := TDsaVectors.GetParametersSmokeCase;
  SetLength(LChunks, Length(LCase.RandomHexChunks));
  for LI := 0 to High(LCase.RandomHexChunks) do
    LChunks[LI] := TDsaVectors.DecodeHexField(LCase.RandomHexChunks[LI]);

  LRandom := TFixedSecureRandom.From(LChunks);
  LA := TDsaParametersGenerator.Create();
  LA.Init(LCase.L, LCase.N, LRandom);
  LP := LA.GenerateParameters();

  LEncodeParams := (TDsaParameter.Create(LP.p, LP.Q, LP.G) as IDsaParameter).GetDerEncoded();
  LDsaP := TDsaParameter.GetInstance(TAsn1Object.FromByteArray(LEncodeParams));
  LP2 := TDSAParameters.Create(LDsaP.p, LDsaP.Q, LDsaP.G);
  LEncodeParams2 := (TDsaParameter.Create(LP2.p, LP2.Q, LP2.G) as IDsaParameter).GetDerEncoded();

  if (not AreEqual(LEncodeParams, LEncodeParams2)) then
    Fail('encode/Decode parameters failed');

  LG := TGeneratorUtilities.GetKeyPairGenerator('DSA');
  LG.Init(TDSAKeyGenerationParameters.Create(TSecureRandom.Create() as ISecureRandom, LP)
    as IDSAKeyGenerationParameters);
  LPair := LG.GenerateKeyPair();
  LSKey := LPair.Private;
  LVKey := LPair.Public;

  LS := TSignerUtilities.GetSigner('DSA');
  LData := TBytes.Create(1, 2, 3, 4, 5, 6, 7, 8, 9, 0);
  LS.Init(true, LSKey);
  LS.BlockUpdate(LData, 0, System.Length(LData));
  LSigBytes := LS.GenerateSignature();

  LS := TSignerUtilities.GetSigner('DSA');
  LS.Init(false, LVKey);
  LS.BlockUpdate(LData, 0, System.Length(LData));

  if (not LS.VerifySignature(LSigBytes)) then
    Fail('dsa verification failed');
end;

procedure TTestDSA.RunEcdsaSignVerifyVector(const AVector: TEcdsaVectorRow);
var
  LCurve: TEcdsaCurveRow;
  LSpec: IECDomainParameters;
  LSKey, LVKey: IAsymmetricKeyParameter;
  LSgr: ISigner;
  LMessage, LSigBytes: TBytes;
  LSig: TCryptoLibGenericArray<TBigInteger>;
  LR, LS: TBigInteger;
begin
  LCurve := TEcdsaVectors.GetCurve(AVector.CurveId);
  LSpec := TEcdsaVectors.BuildDomainParameters(LCurve);
  LSKey := TEcdsaVectors.BuildPrivateKey(AVector, LSpec);
  LVKey := TEcdsaVectors.BuildPublicKey(AVector, LSpec);
  LSgr := TSignerUtilities.GetSigner(AVector.Algorithm);

  LSgr.Init(true, TParametersWithRandom.Create(LSKey,
    TEcdsaVectors.BuildFixedK(AVector.KDecimal)) as IParametersWithRandom);

  LMessage := TEcdsaVectors.DecodeMessage(AVector);
  LSgr.BlockUpdate(LMessage, 0, System.Length(LMessage));
  LSigBytes := LSgr.GenerateSignature();

  LSgr.Init(false, LVKey);
  LSgr.BlockUpdate(LMessage, 0, System.Length(LMessage));

  if (not LSgr.VerifySignature(LSigBytes)) then
    Fail('239 Bit EC verification failed');

  if (AVector.ExpectedR <> '') and (AVector.ExpectedS <> '') then
  begin
    LSig := DoDerDecode(LSigBytes);
    LR := TBigInteger.Create(AVector.ExpectedR);
    LS := TBigInteger.Create(AVector.ExpectedS);

    if (not LR.Equals(LSig[0])) then
      Fail('r component wrong.' + sLineBreak + ' expecting: ' + LR.toString +
        sLineBreak + ' got      : ' + LSig[0].toString);

    if (not LS.Equals(LSig[1])) then
      Fail('s component wrong.' + sLineBreak + ' expecting: ' + LS.toString +
        sLineBreak + ' got      : ' + LSig[1].toString);
  end;
end;

procedure TTestDSA.RunEcdsaDigestBinaryVector(const AVector: TEcdsaVectorRow;
  const AOid: IDerObjectIdentifier);
var
  LCurve: TEcdsaCurveRow;
  LSpec: IECDomainParameters;
  LSKey, LVKey: IAsymmetricKeyParameter;
  LSgr: ISigner;
  LMessage, LSigBytes: TBytes;
begin
  LCurve := TEcdsaVectors.GetCurve(AVector.CurveId);
  LSpec := TEcdsaVectors.BuildDomainParameters(LCurve);
  LSKey := TEcdsaVectors.BuildPrivateKey(AVector, LSpec);
  LVKey := TEcdsaVectors.BuildPublicKey(AVector, LSpec);
  LSgr := TSignerUtilities.GetSigner(AVector.Algorithm);

  LSgr.Init(true, TParametersWithRandom.Create(LSKey,
    TEcdsaVectors.BuildFixedK(AVector.KDecimal)) as IParametersWithRandom);

  LMessage := TEcdsaVectors.DecodeMessage(AVector);
  LSgr.BlockUpdate(LMessage, 0, System.Length(LMessage));
  LSigBytes := LSgr.GenerateSignature();

  LSgr := TSignerUtilities.GetSigner(AOid.Id);
  LSgr.Init(false, LVKey);
  LSgr.BlockUpdate(LMessage, 0, System.Length(LMessage));

  if (not LSgr.VerifySignature(LSigBytes)) then
    Fail('239 Bit ' + AVector.Algorithm + ' verification failed');
end;
procedure TTestDSA.DoTestKeyGeneration(keysize: Int32);
var
  rand: ISecureRandom;
  generator: IDSAKeyPairGenerator;
  dsapGen: IDsaParametersGenerator;
  p: IAsymmetricCipherKeyPair;
  params: IDSAParameters;
  priv: IDSAPrivateKeyParameters;
  qsize: Int32;
begin
  rand := TSecureRandom.Create();
  generator := TGeneratorUtilities.GetKeyPairGenerator('DSA')
    as IDSAKeyPairGenerator;

  // The NIST standard does not fully specify the size of q that
  // must be used for a given key size. Hence there are differences.
  // For example if keysize = 2048, then OpenSSL uses 256 bit q's by default,
  // but the SUN provider uses 224 bits. Both are acceptable sizes.
  // The tests below simply asserts that the size of q does not decrease the
  // overall security of the DSA.

  // Also We Check the length of the private key.
  // For example GPG4Browsers or the KJUR library derived from it use
  // q.BitCount instead of q.BitLength to determine the size of the private key
  // and hence would generate keys that are much too small.
  case keysize of
    1024:
      begin
        dsapGen := TDsaParametersGenerator.Create(); // SHA-1 Default
        dsapGen.Init(TDSAParameterGenerationParameters.Create(keysize, 160, 80,
          rand) as IDSAParameterGenerationParameters);

        params := dsapGen.GenerateParameters();

        generator.Init(TDSAKeyGenerationParameters.Create(rand, params)
          as IDSAKeyGenerationParameters);

        p := generator.GenerateKeyPair();

        priv := p.Private as IDSAPrivateKeyParameters;
        params := priv.parameters;

        CheckTrue(keysize = params.p.BitLength, 'keysize mismatch');
        qsize := params.Q.BitLength;

        CheckTrue(qsize = 160, 'Invalid qsize for 1024 bit key: ' +
          IntToStr(qsize));

        CheckTrue(priv.X.BitLength >= (qsize - 32), 'privkey error');
      end;

    2048:
      begin
        dsapGen := TDsaParametersGenerator.Create
          (TDigestUtilities.GetDigest('SHA-224'));
        dsapGen.Init(TDSAParameterGenerationParameters.Create(keysize, 224, 80,
          rand) as IDSAParameterGenerationParameters);

        params := dsapGen.GenerateParameters();

        generator.Init(TDSAKeyGenerationParameters.Create(rand, params)
          as IDSAKeyGenerationParameters);

        p := generator.GenerateKeyPair();

        priv := p.Private as IDSAPrivateKeyParameters;
        params := priv.parameters;

        CheckTrue(keysize = params.p.BitLength, 'keysize mismatch');

        qsize := params.Q.BitLength;
        CheckTrue(qsize = 224, 'Invalid qsize for 2048 bit key: ' +
          IntToStr(qsize));

        CheckTrue(priv.X.BitLength >= (qsize - 32), 'privkey error');
        //
        // .....
        //
        dsapGen := TDsaParametersGenerator.Create
          (TDigestUtilities.GetDigest('SHA-256'));
        dsapGen.Init(TDSAParameterGenerationParameters.Create(keysize, 256, 80,
          rand) as IDSAParameterGenerationParameters);

        params := dsapGen.GenerateParameters();

        generator.Init(TDSAKeyGenerationParameters.Create(rand, params)
          as IDSAKeyGenerationParameters);

        p := generator.GenerateKeyPair();

        priv := p.Private as IDSAPrivateKeyParameters;
        params := priv.parameters;

        CheckTrue(keysize = params.p.BitLength, 'keysize mismatch');

        qsize := params.Q.BitLength;
        CheckTrue(qsize = 256, 'Invalid qsize for 2048 bit key: ' +
          IntToStr(qsize));

        CheckTrue(priv.X.BitLength >= (qsize - 32), 'privkey error');
      end;

    3072:
      begin

        dsapGen := TDsaParametersGenerator.Create
          (TDigestUtilities.GetDigest('SHA-256'));
        dsapGen.Init(TDSAParameterGenerationParameters.Create(keysize, 256, 80,
          rand) as IDSAParameterGenerationParameters);

        params := dsapGen.GenerateParameters();

        generator.Init(TDSAKeyGenerationParameters.Create(rand, params)
          as IDSAKeyGenerationParameters);

        p := generator.GenerateKeyPair();

        priv := p.Private as IDSAPrivateKeyParameters;
        params := priv.parameters;

        CheckTrue(keysize = params.p.BitLength, 'keysize mismatch');

        qsize := params.Q.BitLength;
        CheckTrue(qsize = 256, 'Invalid qsize for 3072 bit key: ' +
          IntToStr(qsize));

        CheckTrue(priv.X.BitLength >= (qsize - 32), 'privkey error');
      end

  else
    begin
      Fail('Invalid key size: ' + IntToStr(keysize));
    end;

  end;

end;

procedure TTestDSA.SetUp;
begin
  inherited;

end;

procedure TTestDSA.TearDown;
begin
  inherited;

end;

procedure TTestDSA.TestDSA;
var
  LI: Integer;
  LRows: TCryptoLibGenericArray<TDsaFips1863Row>;
  LCases: TCryptoLibGenericArray<TDsaFips1862GoldenCase>;
begin
  RunTestDsa512GenCase();
  LCases := TDsaVectors.GetFips1862GoldenCases();
  for LI := 0 to High(LCases) do
    RunFips1862GoldenCase(LCases[LI]);
  LRows := TDsaVectors.GetFips1863Rows();
  for LI := 0 to High(LRows) do
    RunFips1863Row(LRows[LI]);
end;

procedure TTestDSA.TestDsa2Parameters;
begin
  RunDsa2ParametersCase();
end;

procedure TTestDSA.TestECDsa239BitPrime;
begin
  RunEcdsaSignVerifyVector(TEcdsaVectors.GetVectorById('FpPrime_ECDSA'));
end;

procedure TTestDSA.TestGeneration;
var
  s: ISigner;
  data, sigBytes: TBytes;
  rand: ISecureRandom;
  G: IAsymmetricCipherKeyPairGenerator;
  pGen: IDsaParametersGenerator;
  p: IAsymmetricCipherKeyPair;
  sKey, vKey: IAsymmetricKeyParameter;
  ecSpec: IECDomainParameters;
begin
  DoTestBadStrength(513);
  DoTestBadStrength(510);
  DoTestBadStrength(1025);

  s := TSignerUtilities.GetSigner('DSA');
  data := TBytes.Create(1, 2, 3, 4, 5, 6, 7, 8, 9, 0);
  rand := TSecureRandom.Create();

  G := TGeneratorUtilities.GetKeyPairGenerator('DSA');
  pGen := TDsaParametersGenerator.Create();
  pGen.Init(512, 80, rand);
  G.Init(TDSAKeyGenerationParameters.Create(rand, pGen.GenerateParameters())
    as IDSAKeyGenerationParameters);
  p := G.GenerateKeyPair();
  sKey := p.Private;
  vKey := p.Public;

  s.Init(true, sKey);
  s.BlockUpdate(data, 0, System.Length(data));
  sigBytes := s.GenerateSignature();
  s := TSignerUtilities.GetSigner('DSA');
  s.Init(false, vKey);
  s.BlockUpdate(data, 0, System.Length(data));
  if (not s.VerifySignature(sigBytes)) then
    Fail('DSA verification failed');

  s := TSignerUtilities.GetSigner('ECDSA');
  ecSpec := TEcdsaVectors.BuildDomainParameters(
    TEcdsaVectors.GetCurve('X962_239Fp'));
  G := TGeneratorUtilities.GetKeyPairGenerator('ECDSA');
  G.Init(TECKeyGenerationParameters.Create(ecSpec, rand)
    as IECKeyGenerationParameters);
  p := G.GenerateKeyPair();
  sKey := p.Private;
  vKey := p.Public;
  s.Init(true, sKey);
  s.BlockUpdate(data, 0, System.Length(data));
  sigBytes := s.GenerateSignature();
  s := TSignerUtilities.GetSigner('ECDSA');
  s.Init(false, vKey);
  s.BlockUpdate(data, 0, System.Length(data));
  if (not s.VerifySignature(sigBytes)) then
    Fail('ECDSA verification failed');

  s := TSignerUtilities.GetSigner('ECDSA');
  ecSpec := TEcdsaVectors.BuildDomainParameters(
    TEcdsaVectors.GetCurve('X962_239F2m'));
  G := TGeneratorUtilities.GetKeyPairGenerator('ECDSA');
  G.Init(TECKeyGenerationParameters.Create(ecSpec, rand)
    as IECKeyGenerationParameters);
  p := G.GenerateKeyPair();
  sKey := p.Private;
  vKey := p.Public;
  s.Init(true, sKey);
  s.BlockUpdate(data, 0, System.Length(data));
  sigBytes := s.GenerateSignature();
  s := TSignerUtilities.GetSigner('ECDSA');
  s.Init(false, vKey);
  s.BlockUpdate(data, 0, System.Length(data));
  if (not s.VerifySignature(sigBytes)) then
    Fail('ECDSA verification failed');
end;

procedure TTestDSA.TestKeyGenerationAll;
begin
  DoTestKeyGeneration(1024);
  DoTestKeyGeneration(2048);
  DoTestKeyGeneration(3072);
end;

procedure TTestDSA.TestECDsa239BitBinary;
begin
  RunEcdsaSignVerifyVector(TEcdsaVectors.GetVectorById('F2mBinary_ECDSA'));
end;

procedure TTestDSA.TestECDsa239BitBinaryRipeMD160;
begin
  RunEcdsaDigestBinaryVector(TEcdsaVectors.GetVectorById('F2mBinary_RipeMD160'), TTeleTrusTObjectIdentifiers.ECSignWithRipeMD160);
end;

procedure TTestDSA.TestECDsa239BitBinarySha1;
begin
  RunEcdsaDigestBinaryVector(TEcdsaVectors.GetVectorById('F2mBinary_Sha1'), TTeleTrusTObjectIdentifiers.ECSignWithSha1);
end;

procedure TTestDSA.TestECDsa239BitBinarySha224;
begin
  RunEcdsaDigestBinaryVector(TEcdsaVectors.GetVectorById('F2mBinary_Sha224'), TX9ObjectIdentifiers.ECDsaWithSha224);
end;

procedure TTestDSA.TestECDsa239BitBinarySha256;
begin
  RunEcdsaDigestBinaryVector(TEcdsaVectors.GetVectorById('F2mBinary_Sha256'), TX9ObjectIdentifiers.ECDsaWithSha256);
end;

procedure TTestDSA.TestECDsa239BitBinarySha384;
begin
  RunEcdsaDigestBinaryVector(TEcdsaVectors.GetVectorById('F2mBinary_Sha384'), TX9ObjectIdentifiers.ECDsaWithSha384);
end;

procedure TTestDSA.TestECDsa239BitBinarySha512;
begin
  RunEcdsaDigestBinaryVector(TEcdsaVectors.GetVectorById('F2mBinary_Sha512'), TX9ObjectIdentifiers.ECDsaWithSha512);
end;

procedure TTestDSA.TestNONEwithDSA;
var
  dummySha1, sigBytes: TBytes;
  rand: ISecureRandom;
  pGen: IDsaParametersGenerator;
  G: IAsymmetricCipherKeyPairGenerator;
  kp: IAsymmetricCipherKeyPair;
  sig: ISigner;
  signer: IDSASigner;
  RS: TCryptoLibGenericArray<TBigInteger>;
begin
  dummySha1 := DecodeHex('01020304050607080910111213141516');

  rand := TSecureRandom.Create();

  pGen := TDsaParametersGenerator.Create();
  pGen.Init(512, 80, rand);

  G := TGeneratorUtilities.GetKeyPairGenerator('DSA');
  G.Init(TDSAKeyGenerationParameters.Create(rand, pGen.GenerateParameters())
    as IDSAKeyGenerationParameters);

  kp := G.GenerateKeyPair();

  sig := TSignerUtilities.GetSigner('NONEwithDSA');
  sig.Init(true, kp.Private);
  sig.BlockUpdate(dummySha1, 0, System.Length(dummySha1));
  sigBytes := sig.GenerateSignature();

  sig.Init(false, kp.Public);
  sig.BlockUpdate(dummySha1, 0, System.Length(dummySha1));
  sig.VerifySignature(sigBytes);

  // reset test

  sig.BlockUpdate(dummySha1, 0, System.Length(dummySha1));

  if (not(sig.VerifySignature(sigBytes))) then
  begin
    Fail('NONEwithDSA failed to reset');
  end;

  // lightweight test
  signer := TDSASigner.Create();
  signer.Init(false, kp.Public);
  RS := DoDerDecode(sigBytes);

  if (not(signer.VerifySignature(dummySha1, RS[0], RS[1]))) then
  begin
    Fail('NONEwithDSA not really NONE!');
  end;
end;

procedure TTestDSA.TestNONEwithECDSA239bitPrime;
var
  LI: Integer;
  LVectors: TCryptoLibGenericArray<TEcdsaVectorRow>;
  LCurve: TEcdsaCurveRow;
  LSpec: IECDomainParameters;
  LPriKey: IECPrivateKeyParameters;
  LPubKey: IECPublicKeyParameters;
  LSgr: ISigner;
  LMessage, LSig: TBytes;
begin
  LCurve := TEcdsaVectors.GetCurve('X962_239Fp');
  LSpec := TEcdsaVectors.BuildDomainParameters(LCurve);
  LSgr := TSignerUtilities.GetSigner('NONEwithECDSA');
  LVectors := TEcdsaVectors.GetVectors();
  for LI := 0 to High(LVectors) do
  begin
    if not SameText(LVectors[LI].Algorithm, 'NONEwithECDSA') then
      Continue;
    LPriKey := TEcdsaVectors.BuildPrivateKey(LVectors[LI], LSpec);
    LPubKey := TEcdsaVectors.BuildPublicKey(LVectors[LI], LSpec);
    LMessage := TEcdsaVectors.DecodeMessage(LVectors[LI]);
    LSig := TEcdsaVectors.DecodeSigDer(LVectors[LI]);
    DoCheckMessage(LSgr, LPriKey, LPubKey, LMessage, LSig);
  end;
end;

procedure TTestDSA.TestParameters;
begin
  RunParametersSmokeCase();
end;

procedure TTestDSA.TestModulusSizeBound;
var
  LHugeP: TBigInteger;
begin
  LHugeP := TBigInteger.One.ShiftLeft(20000);
  try
    TDsaPublicKeyParameters.Create(TBigInteger.Two,
      TDsaParameters.Create(LHugeP, TBigInteger.ValueOf(11), TBigInteger.Two));
    Fail('oversized DSA modulus accepted');
  except
    on E: EArgumentCryptoLibException do
      CheckEquals('DSA modulus out of range', E.Message);
  end;
end;

{ TDSATestSecureRandom }

constructor TDSATestSecureRandom.Create(const value: TBytes);
begin
  Inherited Create(System.Copy(value));
  Ffirst := true;
end;

procedure TDSATestSecureRandom.NextBytes(const bytes: TBytes);
begin
  if (Ffirst) then
  begin
    Inherited NextBytes(bytes);
    Ffirst := false;
  end
  else
  begin
    bytes[System.Length(bytes) - 1] := 2;
  end;

end;

initialization

// Register any test cases with the test runner

{$IFDEF FPC}
  RegisterTest(TTestDSA);
{$ELSE}
  RegisterTest(TTestDSA.Suite);
{$ENDIF FPC}

end.
