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

unit ECNRTests;

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
  ClpAsn1Objects,
  ClpIAsn1Objects,
  ClpIECC,
  ClpECC,
  ClpIDigest,
  ClpECNRSigner,
  ClpIECNRSigner,
  ClpECDomainParameters,
  ClpIECDomainParameters,
  ClpIECKeyGenerationParameters,
  ClpECKeyGenerationParameters,
  ClpECPrivateKeyParameters,
  ClpIECPrivateKeyParameters,
  ClpECPublicKeyParameters,
  ClpIECPublicKeyParameters,
  ClpECKeyPairGenerator,
  ClpIECKeyPairGenerator,
  ClpISigner,
  ClpIX9ECParameters,
  ClpIAsymmetricCipherKeyPair,
  ClpECNamedCurveTable,
  ClpParametersWithRandom,
  ClpIParametersWithRandom,
  ClpSecureRandom,
  ClpISecureRandom,
  ClpFixedSecureRandom,
  ClpSignerUtilities,
  ClpBigInteger,
  ClpBigIntegers,
  ClpConverters,
  ClpCryptoLibTypes,
  ClpDigestUtilities,
  CryptoLibTestBase;

type

  /// <summary>
  /// ECNR tests.
  /// </summary>
  TTestECNR = class(TCryptoLibAlgorithmTestCase)
  private

    procedure DoCheckSignature(size: Int32; const sKey: IECPrivateKeyParameters;
      const vKey: IECPublicKeyParameters; const sgr: ISigner;
      const k: ISecureRandom; const &message: TBytes; const r, s: TBigInteger);

    function DoDerDecode(const encoding: TBytes)
      : TCryptoLibGenericArray<TBigInteger>;

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published

    /// <summary>
    /// a basic regression test with 239 bit prime
    /// </summary>
    procedure TestECNR239bitPrime;

    /// <summary>
    /// <para>
    /// X9.62 - 1998,
    /// </para>
    /// <para>
    /// <br />J.3.2, Page 155, ECDSA over the field <c>Fp</c>
    /// </para>
    /// <para>
    /// <br />an example with 239 bit prime
    /// </para>
    /// </summary>
    procedure TestECNR239bitPrimeSHA1; // Prime239v1

    /// <summary>
    /// <para>
    /// 9.62 - 1998,
    /// </para>
    /// <para>
    /// Page 104-105, ECDSA over the field <c>Fp</c>
    /// </para>
    /// <para>
    /// <c>an example with 192 bit prime</c>
    /// </para>
    /// </summary>
    procedure TestECNR192bitPrimeSHA1; // Prime192v1

    /// <summary>
    /// <para>
    /// SEC 2: Recommended Elliptic Curve Domain Parameters - September
    /// 2000,
    /// </para>
    /// <para>
    /// Page 17-19, Recommended 521-bit Elliptic Curve Domain Parameters
    /// over <c>Fp</c>
    /// </para>
    /// <para>
    /// <c>an ECC example with a 521 bit prime and a 512 bit hash</c>
    /// </para>
    /// </summary>
    procedure TestECNR521bitPrimeSHA512; // SecP521r1

    procedure TestRange;

  end;

implementation

{ TTestECNR }

procedure TTestECNR.DoCheckSignature(size: Int32;
  const sKey: IECPrivateKeyParameters; const vKey: IECPublicKeyParameters;
  const sgr: ISigner; const k: ISecureRandom; const &message: TBytes;
  const r, s: TBigInteger);
var
  sigBytes: TBytes;
  sig: TCryptoLibGenericArray<TBigInteger>;
begin
  sgr.Init(true, TParametersWithRandom.Create(sKey, k)
    as IParametersWithRandom);

  sgr.BlockUpdate(&message, 0, System.Length(&message));

  sigBytes := sgr.GenerateSignature();

  sgr.Init(false, vKey);

  sgr.BlockUpdate(&message, 0, System.Length(&message));

  if (not(sgr.VerifySignature(sigBytes))) then
  begin
    Fail(IntToStr(size) + ' bit EC verification failed');
  end;

  sig := DoDerDecode(sigBytes);

  if (not(r.Equals(sig[0]))) then
  begin
    Fail(IntToStr(size) + 'bit' + ': r component wrong.' + sLineBreak +
      ' expecting: ' + r.ToString() + sLineBreak + ' got      : ' +
      sig[0].ToString());
  end;

  if (not(s.Equals(sig[1]))) then
  begin
    Fail(IntToStr(size) + 'bit' + ': s component wrong.' + sLineBreak +
      ' expecting: ' + s.ToString() + sLineBreak + ' got      : ' +
      sig[1].ToString());
  end;
end;

function TTestECNR.DoDerDecode(const encoding: TBytes)
  : TCryptoLibGenericArray<TBigInteger>;
var
  s: IAsn1Sequence;
begin
  s := TAsn1Object.FromByteArray(encoding) as IAsn1Sequence;

  result := TCryptoLibGenericArray<TBigInteger>.Create
    ((s[0] as IDerInteger).Value, (s[1] as IDerInteger).Value);
end;

procedure TTestECNR.SetUp;
begin
  inherited;

end;

procedure TTestECNR.TearDown;
begin
  inherited;

end;

procedure TTestECNR.TestECNR192bitPrimeSHA1;
var
  r, s: TBigInteger;
  kData, &message: TBytes;
  k: ISecureRandom;
  curve: IFpCurve;
  parameters: IECDomainParameters;
  priKey: IECPrivateKeyParameters;
  pubKey: IECPublicKeyParameters;
  sgr: ISigner;
begin
  r := TBigInteger.Create
    ('2474388605162950674935076940284692598330235697454145648371');
  s := TBigInteger.Create
    ('2997192822503471356158280167065034437828486078932532073836');

  kData := TBigInteger.Create
    ('dcc5d1f1020906df2782360d36b2de7a17ece37d503784af', 16)
    .ToByteArrayUnsigned();
  k := TFixedSecureRandom.From(TCryptoLibMatrixByteArray.Create(kData));

  curve := TFpCurve.Create
    (TBigInteger.Create
    ('6277101735386680763835789423207666416083908700390324961279'),
    // q (or p)
    TBigInteger.Create('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFC', 16),
    // a
    TBigInteger.Create('64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1', 16),
    // b
    TBigInteger.Create
    ('6277101735386680763835789423176059013767194773182842284081'),
    TBigInteger.One);

  parameters := TECDomainParameters.Create(curve,
    curve.DecodePoint
    (DecodeHex('03188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012')), // G
    TBigInteger.Create
    ('6277101735386680763835789423176059013767194773182842284081')
    // n
    );

  priKey := TECPrivateKeyParameters.Create
    (TBigInteger.Create
    ('651056770906015076056810763456358567190100156695615665659'),
    // d
    parameters);

  pubKey := TECPublicKeyParameters.Create
    (curve.DecodePoint
    (DecodeHex('0262B12D60690CDCF330BABAB6E69763B471F994DD702D16A5')), // Q
    parameters);

  sgr := TSignerUtilities.GetSigner('SHA1withECNR');
  &message := TConverters.ConvertStringToBytes('abc', TEncoding.UTF8);

  DoCheckSignature(192, priKey, pubKey, sgr, k, &message, r, s);
end;

procedure TTestECNR.TestECNR239bitPrime;
var
  r, s, n: TBigInteger;
  kData, &message: TBytes;
  k: ISecureRandom;
  curve: IFpCurve;
  parameters: IECDomainParameters;
  priKey: IECPrivateKeyParameters;
  pubKey: IECPublicKeyParameters;
  ecnr: IECNRSigner;
  param: IParametersWithRandom;
  sig: TCryptoLibGenericArray<TBigInteger>;
begin
  r := TBigInteger.Create
    ('308636143175167811492623515537541734843573549327605293463169625072911693');
  s := TBigInteger.Create
    ('852401710738814635664888632022555967400445256405412579597015412971797143');

  kData := TBigInteger.Create
    ('700000017569056646655505781757157107570501575775705779575555657156756655')
    .ToByteArrayUnsigned();
  k := TFixedSecureRandom.From(TCryptoLibMatrixByteArray.Create(kData));

  n := TBigInteger.Create
    ('883423532389192164791648750360308884807550341691627752275345424702807307');

  curve := TFpCurve.Create
    (TBigInteger.Create
    ('883423532389192164791648750360308885314476597252960362792450860609699839'),
    // q
    TBigInteger.Create
    ('7fffffffffffffffffffffff7fffffffffff8000000000007ffffffffffc', 16), // a
    TBigInteger.Create
    ('6b016c3bdcf18941d0d654921475ca71a9db2fb27d1d37796185c2942c0a', 16), // b
    TBigInteger.Create
    ('7fffffffffffffffffffffff7fffff9e5e9a9f5d9071fbd1522688909d0b', 16),
    TBigInteger.One);

  parameters := TECDomainParameters.Create(curve,
    curve.DecodePoint
    (DecodeHex
    ('020ffa963cdca8816ccc33b8642bedf905c3d358573d3f27fbbd3b3cb9aaaf')), // G
    n, TBigInteger.One);

  priKey := TECPrivateKeyParameters.Create
    (TBigInteger.Create
    ('876300101507107567501066130761671078357010671067781776716671676178726717'),
    // d
    parameters);

  ecnr := TECNRSigner.Create();
  param := TParametersWithRandom.Create(priKey, k);

  ecnr.Init(true, param);

  &message := TBigInteger.Create
    ('968236873715988614170569073515315707566766479517').ToByteArray();
  sig := ecnr.GenerateSignature(&message);

  if (not(r.Equals(sig[0]))) then
  begin
    Fail('r component wrong. ' + r.ToString + ' expected but ' + sig[0].ToString
      + ' gotten');
  end;

  if (not(s.Equals(sig[1]))) then
  begin
    Fail('s component wrong. ' + s.ToString + ' expected but ' + sig[1].ToString
      + ' gotten');
  end;

  // Verify the signature
  pubKey := TECPublicKeyParameters.Create
    (curve.DecodePoint
    (DecodeHex
    ('025b6dc53bc61a2548ffb0f671472de6c9521a9d2d2534e65abfcbd5fe0c70')), // Q
    parameters);

  ecnr.Init(false, pubKey);
  if (not(ecnr.VerifySignature(&message, sig[0], sig[1]))) then
  begin
    Fail('signature fails');
  end;
end;

procedure TTestECNR.TestECNR239bitPrimeSHA1;
var
  r, s: TBigInteger;
  kData, &message: TBytes;
  k: ISecureRandom;
  curve: IFpCurve;
  parameters: IECDomainParameters;
  priKey: IECPrivateKeyParameters;
  pubKey: IECPublicKeyParameters;
  sgr: ISigner;
begin
  r := TBigInteger.Create
    ('308636143175167811492623515537541734843573549327605293463169625072911693');
  s := TBigInteger.Create
    ('852401710738814635664888632022555967400445256405412579597015412971797143');

  kData := TBigInteger.Create
    ('700000017569056646655505781757157107570501575775705779575555657156756655')
    .ToByteArrayUnsigned();
  k := TFixedSecureRandom.From(TCryptoLibMatrixByteArray.Create(kData));

  curve := TFpCurve.Create
    (TBigInteger.Create
    ('883423532389192164791648750360308885314476597252960362792450860609699839'),
    // q
    TBigInteger.Create
    ('7fffffffffffffffffffffff7fffffffffff8000000000007ffffffffffc', 16), // a
    TBigInteger.Create
    ('6b016c3bdcf18941d0d654921475ca71a9db2fb27d1d37796185c2942c0a', 16), // b
    TBigInteger.Create
    ('7fffffffffffffffffffffff7fffff9e5e9a9f5d9071fbd1522688909d0b', 16),
    TBigInteger.One);

  parameters := TECDomainParameters.Create(curve,
    curve.DecodePoint
    (DecodeHex
    ('020ffa963cdca8816ccc33b8642bedf905c3d358573d3f27fbbd3b3cb9aaaf')), // G
    TBigInteger.Create
    ('883423532389192164791648750360308884807550341691627752275345424702807307'),
    // n
    TBigInteger.One);

  priKey := TECPrivateKeyParameters.Create
    (TBigInteger.Create
    ('876300101507107567501066130761671078357010671067781776716671676178726717'),
    // d
    parameters);

  pubKey := TECPublicKeyParameters.Create
    (curve.DecodePoint
    (DecodeHex
    ('025b6dc53bc61a2548ffb0f671472de6c9521a9d2d2534e65abfcbd5fe0c70')), // Q
    parameters);

  sgr := TSignerUtilities.GetSigner('SHA1withECNR');
  &message := TConverters.ConvertStringToBytes('abc', TEncoding.UTF8);

  DoCheckSignature(239, priKey, pubKey, sgr, k, &message, r, s);
end;

procedure TTestECNR.TestECNR521bitPrimeSHA512;
var
  r, s: TBigInteger;
  kData, &message: TBytes;
  k: ISecureRandom;
  curve: IFpCurve;
  parameters: IECDomainParameters;
  priKey: IECPrivateKeyParameters;
  pubKey: IECPublicKeyParameters;
  sgr: ISigner;
begin
  r := TBigInteger.Create
    ('1820641608112320695747745915744708800944302281118541146383656165330049339564439316345159057453301092391897040509935100825960342573871340486684575368150970954');
  s := TBigInteger.Create
    ('6358277176448326821136601602749690343031826490505780896013143436153111780706227024847359990383467115737705919410755190867632280059161174165591324242446800763');

  kData := TBigInteger.Create
    ('cdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef',
    16).ToByteArrayUnsigned();
  k := TFixedSecureRandom.From(TCryptoLibMatrixByteArray.Create(kData));

  curve := TFpCurve.Create
    (TBigInteger.Create
    ('6864797660130609714981900799081393217269435300143305409394463459185543183397656052122559640661454554977296311391480858037121987999716643812574028291115057151'),
    // q (or p)
    TBigInteger.Create
    ('01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC',
    16),
    // a
    TBigInteger.Create
    ('0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00',
    16), // b
    TBigInteger.Create(1,
    DecodeHex(
    '01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409')
    ), TBigInteger.One);
  // b

  parameters := TECDomainParameters.Create(curve,
    curve.DecodePoint
    (DecodeHex
    ('0200C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66')),
    // G
    TBigInteger.Create
    ('01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409',
    16)
    // n
    );

  priKey := TECPrivateKeyParameters.Create
    (TBigInteger.Create
    ('5769183828869504557786041598510887460263120754767955773309066354712783118202294874205844512909370791582896372147797293913785865682804434049019366394746072023'),
    // d
    parameters);

  pubKey := TECPublicKeyParameters.Create
    (curve.DecodePoint
    (DecodeHex
    ('02006BFDD2C9278B63C92D6624F151C9D7A822CC75BD983B17D25D74C26740380022D3D8FAF304781E416175EADF4ED6E2B47142D2454A7AC7801DD803CF44A4D1F0AC')),
    // Q
    parameters);

  sgr := TSignerUtilities.GetSigner('SHA512withECNR');
  &message := TConverters.ConvertStringToBytes('abc', TEncoding.UTF8);

  DoCheckSignature(521, priKey, pubKey, sgr, k, &message, r, s);
end;

procedure TTestECNR.TestRange;
var
  myGenerator: IECKeyPairGenerator;
  myRandom: ISecureRandom;
  myCurve: String;
  x9: IX9ECParameters;
  myDomain: IECDomainParameters;
  myParams: IECKeyGenerationParameters;
  myPair: IAsymmetricCipherKeyPair;
  myDigest: IDigest;
  myArtifact, myMessage, msg: TCryptoLibByteArray;
  signer: IECNRSigner;
  order: TBigInteger;
  sig: TCryptoLibGenericArray<TBigInteger>;
begin
  // Create the generator
  myGenerator := TECKeyPairGenerator.Create();
  myRandom := TSecureRandom.Create();
  myCurve := 'brainpoolP192t1';

  // Lookup the parameters
  x9 := TECNamedCurveTable.GetByName(myCurve);

  // Initialise the generator
  myDomain := TECDomainParameters.Create(x9.curve, x9.G, x9.n, x9.H,
    x9.GetSeed());
  myParams := TECKeyGenerationParameters.Create(myDomain, myRandom);
  myGenerator.Init(myParams);

  // Create the key Pair
  myPair := myGenerator.GenerateKeyPair();

  // Create the digest and the output buffer
  myDigest := TDigestUtilities.GetDigest('TIGER');
  System.SetLength(myArtifact, myDigest.GetDigestSize);
  myMessage := TConverters.ConvertStringToBytes
    ('Hello there. How is life treating you?', TEncoding.ASCII);

  myDigest.BlockUpdate(myMessage, 0, System.Length(myMessage));
  myDigest.DoFinal(myArtifact, 0);

  // Create signer
  signer := TECNRSigner.Create();
  signer.Init(true, myPair.Private);

  try
    signer.GenerateSignature(myArtifact);
    Fail('out of range input not caught');
  except
    on e: EDataLengthCryptoLibException do
    begin
      CheckEquals(e.Message, 'Input Too Large For ECNR Key.');
    end;

  end;

  //
  // check upper bound
  order := (myPair.Public as IECPublicKeyParameters).parameters.n;

  signer.Init(true, myPair.Private);
  msg := TBigIntegers.AsUnsignedByteArray(order.Subtract(TBigInteger.One));
  sig := signer.GenerateSignature(msg);

  signer.Init(false, myPair.getPublic());
  if (not signer.VerifySignature(msg, sig[0], sig[1])) then
  begin
    Fail('ECNR failed 2');
  end;

  CheckTrue(AreEqual(msg, signer.getRecoveredMessage(sig[0], sig[1])));
end;

initialization

// Register any test cases with the test runner

{$IFDEF FPC}
  RegisterTest(TTestECNR);
{$ELSE}
  RegisterTest(TTestECNR.Suite);
{$ENDIF FPC}

end.
