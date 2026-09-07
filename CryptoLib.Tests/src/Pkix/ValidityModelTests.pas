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

unit ValidityModelTests;

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
  ClpIPkixTypes,
  ClpTrustAnchor,
  ClpPkixCertPath,
  ClpPkixParameters,
  ClpPkixCertPathValidator,
  ClpIX509Certificate,
  ClpIX509Generators,
  ClpX509Generators,
  ClpIX509Asn1Objects,
  ClpX509Asn1Objects,
  ClpIAsn1Core,
  ClpIAsn1Objects,
  ClpAsn1Objects,
  ClpISignatureFactory,
  ClpAsn1SignatureFactory,
  ClpIAsymmetricCipherKeyPair,
  ClpIAsymmetricKeyParameter,
  ClpNullable,
  ClpCryptoLibTypes,
  ClpCryptoLibExceptions,
  CertTestUtilities,
  CryptoLibTestBase;

type

  /// <summary>
  /// TPkixCertPathValidator honours the validation date under both the shell model
  /// (TPkixParameters.PkixValidityModel) and the chain model (TPkixParameters.ChainValidityModel).
  /// </summary>
  /// <remarks>
  /// Shell model: every certificate in the path is checked against the validation date. Chain model:
  /// only the end-entity is checked against the validation date; each CA certificate is checked at the
  /// time its subordinate was issued (the subordinate's NotBefore, or the end-entity's ISIS-MTT
  /// dateOfCertGen extension when present).
  /// </remarks>
  TValidityModelTest = class(TCryptoLibAlgorithmTestCase)
  strict private
    function Utc(AYear, AMonth, ADay: Word): TDateTime;
    function GenKeyPair: IAsymmetricCipherKeyPair;
    function AnchorsOf(const ACert: IX509Certificate): TCryptoLibGenericArray<ITrustAnchor>;
    function MakeCert(const ASubject: String; const ASubjectKey: IAsymmetricKeyParameter;
      const AIssuer: String; const AIssuerKey: IAsymmetricKeyParameter;
      const ANotBefore, ANotAfter: TDateTime; AIsCa: Boolean;
      AHasDateOfCertGen: Boolean; const ADateOfCertGen: TDateTime): IX509Certificate;
    procedure DoValidate(const ARoot, AInter, AEe: IX509Certificate;
      const ADate: TNullable<TDateTime>; AValidityModel: Int32);
    procedure ExpectFailure(const ARoot, AInter, AEe: IX509Certificate;
      const ADate: TNullable<TDateTime>; AValidityModel: Int32; const AExpect: String);
  published
    procedure TestShellModelChecksEndEntityAgainstDate;
    procedure TestChainModelChecksIssuerAtSubordinateNotBefore;
    procedure TestChainModelUsesDateOfCertGenWhenPresent;
  end;

implementation

{ TValidityModelTest }

function TValidityModelTest.Utc(AYear, AMonth, ADay: Word): TDateTime;
begin
  Result := EncodeDate(AYear, AMonth, ADay);
end;

function TValidityModelTest.GenKeyPair: IAsymmetricCipherKeyPair;
begin
  Result := TCertTestUtilities.GenerateRsaKeyPair(1024);
end;

function TValidityModelTest.AnchorsOf(const ACert: IX509Certificate)
  : TCryptoLibGenericArray<ITrustAnchor>;
begin
  Result := TCryptoLibGenericArray<ITrustAnchor>.Create(TTrustAnchor.Create(ACert, nil) as ITrustAnchor);
end;

function TValidityModelTest.MakeCert(const ASubject: String; const ASubjectKey: IAsymmetricKeyParameter;
  const AIssuer: String; const AIssuerKey: IAsymmetricKeyParameter;
  const ANotBefore, ANotAfter: TDateTime; AIsCa: Boolean;
  AHasDateOfCertGen: Boolean; const ADateOfCertGen: TDateTime): IX509Certificate;
var
  LGen: IX509V3CertificateGenerator;
  LFactory: ISignatureFactory;
begin
  LGen := TX509V3CertificateGenerator.Create;
  LGen.SetSerialNumber(TBigInteger.One);
  LGen.SetIssuerDN(TX509Name.Create(AIssuer) as IX509Name);
  LGen.SetSubjectDN(TX509Name.Create(ASubject) as IX509Name);
  LGen.SetNotBeforeUtc(ANotBefore);
  LGen.SetNotAfterUtc(ANotAfter);
  LGen.SetPublicKey(ASubjectKey);
  LGen.AddExtension(TX509Extensions.BasicConstraints, True,
    TBasicConstraints.Create(AIsCa) as IBasicConstraints);

  if AHasDateOfCertGen then
    // ISIS-MTT id-isismtt-at-dateOfCertGen (1.3.36.8.3.1); under the chain model the validator reads
    // it from the end-entity to time the issuer's validity check.
    LGen.AddExtension(TDerObjectIdentifier.Create('1.3.36.8.3.1') as IDerObjectIdentifier, False,
      TAsn1GeneralizedTime.CreateFromUtc(ADateOfCertGen) as IAsn1Encodable);

  LFactory := TAsn1SignatureFactory.Create('SHA256WITHRSA', AIssuerKey, nil) as ISignatureFactory;
  Result := LGen.Generate(LFactory);
end;

procedure TValidityModelTest.DoValidate(const ARoot, AInter, AEe: IX509Certificate;
  const ADate: TNullable<TDateTime>; AValidityModel: Int32);
var
  LPath: IPkixCertPath;
  LParams: IPkixParameters;
  LValidator: IPkixCertPathValidator;
begin
  LPath := TPkixCertPath.Create(
    TCryptoLibGenericArray<IX509Certificate>.Create(AEe, AInter)) as IPkixCertPath;

  LParams := TPkixParameters.Create(AnchorsOf(ARoot)) as IPkixParameters;
  LParams.Date := ADate;
  LParams.ValidityModel := AValidityModel;
  LParams.IsRevocationEnabled := False;

  LValidator := TPkixCertPathValidator.Create() as IPkixCertPathValidator;
  LValidator.Validate(LPath, LParams);
end;

procedure TValidityModelTest.ExpectFailure(const ARoot, AInter, AEe: IX509Certificate;
  const ADate: TNullable<TDateTime>; AValidityModel: Int32; const AExpect: String);
var
  LRaised: Boolean;
  LMessage: String;
begin
  LRaised := False;
  LMessage := '';
  try
    DoValidate(ARoot, AInter, AEe, ADate, AValidityModel);
  except
    on E: EPkixCertPathValidatorCryptoLibException do
    begin
      LRaised := True;
      LMessage := E.Message;
    end;
  end;

  CheckTrue(LRaised, 'the validation was expected to fail');
  CheckTrue(Pos(AExpect, LMessage) > 0,
    Format('expected a failure containing "%s", got "%s"', [AExpect, LMessage]));
end;

procedure TValidityModelTest.TestShellModelChecksEndEntityAgainstDate;
var
  LRootKp, LInterKp, LEeKp: IAsymmetricCipherKeyPair;
  LRoot, LInter, LEe: IX509Certificate;
begin
  LRootKp := GenKeyPair;
  LInterKp := GenKeyPair;
  LEeKp := GenKeyPair;

  LRoot := MakeCert('CN=Root', LRootKp.Public as IAsymmetricKeyParameter,
    'CN=Root', LRootKp.Private as IAsymmetricKeyParameter, Utc(2020, 1, 1), Utc(2040, 1, 1), True, False, 0);
  LInter := MakeCert('CN=Inter', LInterKp.Public as IAsymmetricKeyParameter,
    'CN=Root', LRootKp.Private as IAsymmetricKeyParameter, Utc(2020, 1, 1), Utc(2040, 1, 1), True, False, 0);
  // the end-entity is valid only during 2021-03 .. 2021-06
  LEe := MakeCert('CN=EE', LEeKp.Public as IAsymmetricKeyParameter,
    'CN=Inter', LInterKp.Private as IAsymmetricKeyParameter, Utc(2021, 3, 1), Utc(2021, 6, 1), False, False, 0);

  // inside the end-entity window
  DoValidate(LRoot, LInter, LEe, TNullable<TDateTime>.Some(Utc(2021, 5, 1)), TPkixParameters.PkixValidityModel);

  // after the end-entity window
  ExpectFailure(LRoot, LInter, LEe, TNullable<TDateTime>.Some(Utc(2021, 7, 1)),
    TPkixParameters.PkixValidityModel, 'expired');

  // before the end-entity window
  ExpectFailure(LRoot, LInter, LEe, TNullable<TDateTime>.Some(Utc(2020, 1, 1)),
    TPkixParameters.PkixValidityModel, 'not valid until');

  // no date set => current time (well past 2021-06) => expired
  ExpectFailure(LRoot, LInter, LEe, TNullable<TDateTime>.None,
    TPkixParameters.PkixValidityModel, 'expired');
end;

procedure TValidityModelTest.TestChainModelChecksIssuerAtSubordinateNotBefore;
var
  LRootKp, LInterKp, LEeKp: IAsymmetricCipherKeyPair;
  LRoot, LInter, LEe: IX509Certificate;
begin
  LRootKp := GenKeyPair;
  LInterKp := GenKeyPair;
  LEeKp := GenKeyPair;

  LRoot := MakeCert('CN=Root', LRootKp.Public as IAsymmetricKeyParameter,
    'CN=Root', LRootKp.Private as IAsymmetricKeyParameter, Utc(2020, 1, 1), Utc(2040, 1, 1), True, False, 0);
  // the intermediate expires 2021-06
  LInter := MakeCert('CN=Inter', LInterKp.Public as IAsymmetricKeyParameter,
    'CN=Root', LRootKp.Private as IAsymmetricKeyParameter, Utc(2020, 1, 1), Utc(2021, 6, 1), True, False, 0);
  // the end-entity is issued 2021-03 (while the intermediate is still valid) and lasts until 2030
  LEe := MakeCert('CN=EE', LEeKp.Public as IAsymmetricKeyParameter,
    'CN=Inter', LInterKp.Private as IAsymmetricKeyParameter, Utc(2021, 3, 1), Utc(2030, 1, 1), False, False, 0);

  // shell model at 2021-07: the intermediate has already expired
  ExpectFailure(LRoot, LInter, LEe, TNullable<TDateTime>.Some(Utc(2021, 7, 1)),
    TPkixParameters.PkixValidityModel, 'expired');

  // chain model at 2021-07: end-entity checked at the date, intermediate checked at end-entity NotBefore
  DoValidate(LRoot, LInter, LEe, TNullable<TDateTime>.Some(Utc(2021, 7, 1)),
    TPkixParameters.ChainValidityModel);

  // chain model with a date after end-entity expiry: the end-entity itself is still checked against it
  ExpectFailure(LRoot, LInter, LEe, TNullable<TDateTime>.Some(Utc(2040, 1, 1)),
    TPkixParameters.ChainValidityModel, 'expired');
end;

procedure TValidityModelTest.TestChainModelUsesDateOfCertGenWhenPresent;
var
  LRootKp, LInterKp, LEeKp: IAsymmetricCipherKeyPair;
  LRoot, LInter, LEeNoExt, LEeExt: IX509Certificate;
begin
  LRootKp := GenKeyPair;
  LInterKp := GenKeyPair;
  LEeKp := GenKeyPair;

  LRoot := MakeCert('CN=Root', LRootKp.Public as IAsymmetricKeyParameter,
    'CN=Root', LRootKp.Private as IAsymmetricKeyParameter, Utc(2019, 1, 1), Utc(2040, 1, 1), True, False, 0);
  // the intermediate is valid from 2020
  LInter := MakeCert('CN=Inter', LInterKp.Public as IAsymmetricKeyParameter,
    'CN=Root', LRootKp.Private as IAsymmetricKeyParameter, Utc(2020, 1, 1), Utc(2040, 1, 1), True, False, 0);

  // end-entity NotBefore (2019) predates the intermediate's NotBefore; without dateOfCertGen the chain
  // model checks the intermediate at 2019, where it is not yet valid
  LEeNoExt := MakeCert('CN=EE', LEeKp.Public as IAsymmetricKeyParameter,
    'CN=Inter', LInterKp.Private as IAsymmetricKeyParameter, Utc(2019, 1, 1), Utc(2030, 1, 1), False, False, 0);
  ExpectFailure(LRoot, LInter, LEeNoExt, TNullable<TDateTime>.Some(Utc(2021, 7, 1)),
    TPkixParameters.ChainValidityModel, 'not valid until');

  // the same end-entity carrying dateOfCertGen = 2021-05: the intermediate is checked at 2021-05 instead
  LEeExt := MakeCert('CN=EE', LEeKp.Public as IAsymmetricKeyParameter,
    'CN=Inter', LInterKp.Private as IAsymmetricKeyParameter, Utc(2019, 1, 1), Utc(2030, 1, 1), False, True, Utc(2021, 5, 1));
  DoValidate(LRoot, LInter, LEeExt, TNullable<TDateTime>.Some(Utc(2021, 7, 1)),
    TPkixParameters.ChainValidityModel);
end;

initialization

{$IFDEF FPC}
  RegisterTest(TValidityModelTest);
{$ELSE}
  RegisterTest(TValidityModelTest.Suite);
{$ENDIF FPC}

end.
