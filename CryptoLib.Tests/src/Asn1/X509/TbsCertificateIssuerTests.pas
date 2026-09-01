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

unit TbsCertificateIssuerTests;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
{$IFDEF FPC}
  fpcunit,
  testregistry,
{$ELSE}
  TestFramework,
{$ENDIF FPC}
  ClpAsn1Core,
  ClpIAsn1Core,
  ClpAsn1Objects,
  ClpIAsn1Objects,
  ClpX509Asn1Objects,
  ClpIX509Asn1Objects,
  ClpX509Asn1Generators,
  ClpIX509Asn1Generators,
  ClpCryptoLibTypes,
  ClpCryptoLibExceptions,
  ClpCryptoLibConfig,
  CryptoLibTestBase;

type

  // RFC 5280 sec. 4.1.2.4: a certificate issuer MUST be a non-empty distinguished name.
  TTbsCertificateIssuerTest = class(TCryptoLibAlgorithmTestCase)
  strict private
    function SigAlg: IAlgorithmIdentifier;
    function EmptyName: IX509Name;
    function SubjectName: IX509Name;
    function NotBefore: ITime;
    function NotAfter: ITime;
    function BuildValidity: IValidity;
    function Spki: ISubjectPublicKeyInfo;
    function CreateEmptyIssuerTbs: TCryptoLibByteArray;
    procedure ImplPublicConstructorRejectsEmptyIssuer;
    procedure ImplV1GeneratorRejectsEmptyIssuer;
    procedure ImplV3GeneratorRejectsEmptyIssuer;
  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestParseRejectsEmptyIssuer;
    procedure TestPublicConstructorRejectsEmptyIssuer;
    procedure TestV1GeneratorRejectsEmptyIssuer;
    procedure TestV3GeneratorRejectsEmptyIssuer;
    procedure TestParseAcceptsEmptyIssuerWhenAllowed;
  end;

implementation

{ TTbsCertificateIssuerTest }

procedure TTbsCertificateIssuerTest.SetUp;
begin
  inherited SetUp;
  TCryptoLibConfig.X509.ResetToDefaults();
end;

procedure TTbsCertificateIssuerTest.TearDown;
begin
  TCryptoLibConfig.X509.ResetToDefaults();
  inherited TearDown;
end;

function TTbsCertificateIssuerTest.SigAlg: IAlgorithmIdentifier;
begin
  Result := TAlgorithmIdentifier.Create(
    TDerObjectIdentifier.Create('1.2.840.113549.1.1.11') as IDerObjectIdentifier);
end;

function TTbsCertificateIssuerTest.EmptyName: IX509Name;
begin
  Result := TX509Name.GetInstance(TDerSequence.Empty as IAsn1Convertible);
end;

function TTbsCertificateIssuerTest.SubjectName: IX509Name;
begin
  Result := TX509Name.Create('CN=Subject');
end;

function TTbsCertificateIssuerTest.NotBefore: ITime;
begin
  Result := TTime.Create(TAsn1UtcTime.Create('250101000000Z') as IAsn1UtcTime);
end;

function TTbsCertificateIssuerTest.NotAfter: ITime;
begin
  Result := TTime.Create(TAsn1UtcTime.Create('260101000000Z') as IAsn1UtcTime);
end;

function TTbsCertificateIssuerTest.BuildValidity: IValidity;
begin
  Result := TValidity.Create(NotBefore, NotAfter);
end;

function TTbsCertificateIssuerTest.Spki: ISubjectPublicKeyInfo;
begin
  Result := TSubjectPublicKeyInfo.Create(
    TAlgorithmIdentifier.Create(TDerObjectIdentifier.Create('1.2.840.113549.1.1.1') as IDerObjectIdentifier),
    TDerBitString.Create(TCryptoLibByteArray.Create(0)) as IDerBitString);
end;

function TTbsCertificateIssuerTest.CreateEmptyIssuerTbs: TCryptoLibByteArray;
var
  LVec: IAsn1EncodableVector;
  LSeq: IDerSequence;
begin
  // v1 TBSCertificate carrying an empty issuer DN
  LVec := TAsn1EncodableVector.Create();
  LVec.Add(TDerInteger.One); // serialNumber (version omitted => v1)
  LVec.Add(SigAlg);
  LVec.Add(EmptyName);
  LVec.Add(BuildValidity);
  LVec.Add(SubjectName);
  LVec.Add(Spki);
  LSeq := TDerSequence.Create(LVec);
  Result := LSeq.GetEncoded(TAsn1Encodable.Der);
end;

procedure TTbsCertificateIssuerTest.TestParseRejectsEmptyIssuer;
var
  LEncoded: TCryptoLibByteArray;
begin
  LEncoded := CreateEmptyIssuerTbs;

  try
    TTbsCertificateStructure.GetInstance(LEncoded);
    Fail('empty issuer DN accepted on parse');
  except
    on E: EArgumentCryptoLibException do
      ; // expected
  end;
end;

procedure TTbsCertificateIssuerTest.TestParseAcceptsEmptyIssuerWhenAllowed;
var
  LEncoded: TCryptoLibByteArray;
  LTbs: ITbsCertificateStructure;
begin
  LEncoded := CreateEmptyIssuerTbs;

  TCryptoLibConfig.X509.AllowEmptyIssuerCert := True;

  // the read-side concession: the parse accepts the empty issuer and preserves the encoding
  LTbs := TTbsCertificateStructure.GetInstance(LEncoded);
  CheckTrue(LTbs.Issuer.IsEmpty, 'issuer not empty');
  CheckTrue(AreEqual(LEncoded, LTbs.GetEncoded(TAsn1Encodable.Der)), 'encoding not preserved');

  // generation stays strict regardless of the switch
  ImplPublicConstructorRejectsEmptyIssuer;
  ImplV1GeneratorRejectsEmptyIssuer;
  ImplV3GeneratorRejectsEmptyIssuer;
end;

procedure TTbsCertificateIssuerTest.TestPublicConstructorRejectsEmptyIssuer;
begin
  ImplPublicConstructorRejectsEmptyIssuer;
end;

procedure TTbsCertificateIssuerTest.TestV1GeneratorRejectsEmptyIssuer;
begin
  ImplV1GeneratorRejectsEmptyIssuer;
end;

procedure TTbsCertificateIssuerTest.TestV3GeneratorRejectsEmptyIssuer;
begin
  ImplV3GeneratorRejectsEmptyIssuer;
end;

procedure TTbsCertificateIssuerTest.ImplPublicConstructorRejectsEmptyIssuer;
begin
  try
    TTbsCertificateStructure.Create(TDerInteger.Two, TDerInteger.One, SigAlg,
      EmptyName, BuildValidity, SubjectName, Spki, nil, nil, nil);
    Fail('public constructor accepted empty issuer');
  except
    on E: EArgumentCryptoLibException do
      ; // expected
  end;
end;

procedure TTbsCertificateIssuerTest.ImplV1GeneratorRejectsEmptyIssuer;
var
  LGen: IV1TbsCertificateGenerator;
begin
  LGen := TV1TbsCertificateGenerator.Create;
  LGen.SetSerialNumber(TDerInteger.One);
  LGen.SetSignature(SigAlg);
  LGen.SetIssuer(EmptyName);
  LGen.SetStartDate(NotBefore);
  LGen.SetEndDate(NotAfter);
  LGen.SetSubject(SubjectName);
  LGen.SetSubjectPublicKeyInfo(Spki);

  try
    LGen.GenerateTbsCertificate;
    Fail('V1 generator accepted empty issuer');
  except
    on E: EInvalidOperationCryptoLibException do
      ; // expected
  end;
end;

procedure TTbsCertificateIssuerTest.ImplV3GeneratorRejectsEmptyIssuer;
var
  LGen: IV3TbsCertificateGenerator;
begin
  LGen := TV3TbsCertificateGenerator.Create;
  LGen.SetSerialNumber(TDerInteger.One);
  LGen.SetSignature(SigAlg);
  LGen.SetIssuer(EmptyName);
  LGen.SetStartDate(NotBefore);
  LGen.SetEndDate(NotAfter);
  LGen.SetSubject(SubjectName);
  LGen.SetSubjectPublicKeyInfo(Spki);

  try
    LGen.GenerateTbsCertificate;
    Fail('V3 generator accepted empty issuer');
  except
    on E: EInvalidOperationCryptoLibException do
      ; // expected
  end;
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTbsCertificateIssuerTest);
{$ELSE}
  RegisterTest(TTbsCertificateIssuerTest.Suite);
{$ENDIF FPC}

end.
