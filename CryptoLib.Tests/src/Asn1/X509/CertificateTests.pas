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

unit CertificateTests;

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
  ClpX509Asn1Objects,
  ClpIX509Asn1Objects,
  ClpAsn1Objects,
  ClpIAsn1Objects,
  ClpIAsn1Core,
  ClpIX509Extension,
  ClpCryptoLibTypes,
  CryptoLibTestBase,
  CertVectors;

type

  TCertificateTest = class(TCryptoLibAlgorithmTestCase)
  strict private
    var
      FCert1, FCert2, FCert3, FCert4, FCert5, FCert6, FCert7, FDudCert, FBangerCert: TCryptoLibByteArray;
      FSubjects: TCryptoLibStringArray;

    procedure SetUpTestData;
    procedure CheckCertificate(AId: Int32; const ACert: TCryptoLibByteArray);
    procedure CheckDudCertificate;
    procedure CheckMalformed;

  protected
    procedure SetUp; override;

  published
    procedure TestCertificate1;
    procedure TestCertificate2;
    procedure TestCertificate3;
    procedure TestCertificate4;
    procedure TestCertificate5;
    procedure TestCertificate6;
    procedure TestCertificate7;
    procedure TestDudCertificate;
    procedure TestMalformedCertificate;

  end;

implementation

{ TCertificateTest }

procedure TCertificateTest.SetUpTestData;
begin
  // server.crt
  FCert1 := TCertVectors.LoadDer('Connect4Server');

  // ca.crt
  FCert2 := TCertVectors.LoadDer('Connect4Ca');

  // testx509.pem
  FCert3 := TCertVectors.LoadDer('LegacyTestX509Ssleay');

  // v3-cert1.pem
  FCert4 := TCertVectors.LoadDer('LegacyV3Cert1Nasa');

  // v3-cert2.pem
  FCert5 := TCertVectors.LoadDer('LegacyV3Cert2Entrust');

  FCert6 := TCertVectors.LoadDer('ExtensionSunStoreSunCom');

  FCert7 := TCertVectors.LoadDer('ExtensionPixfirewall');

  // bad issuer certificate
  FDudCert := TCertVectors.LoadDer('ExtensionDudBadIssuer');

  // malformed cert
  FBangerCert := TCertVectors.LoadDer('ExtensionMalformedBanger');

  System.SetLength(FSubjects, 7);
  FSubjects[0] := TCertVectors.GetExpectedSubject('Connect4Server');
  FSubjects[1] := TCertVectors.GetExpectedSubject('Connect4Ca');
  FSubjects[2] := TCertVectors.GetExpectedSubject('LegacyTestX509Ssleay');
  FSubjects[3] := TCertVectors.GetExpectedSubject('LegacyV3Cert1Nasa');
  FSubjects[4] := TCertVectors.GetExpectedSubject('LegacyV3Cert2Entrust');
  FSubjects[5] := TCertVectors.GetExpectedSubject('ExtensionSunStoreSunCom');
  FSubjects[6] := TCertVectors.GetExpectedSubject('ExtensionPixfirewall');
end;

procedure TCertificateTest.SetUp;
begin
  inherited SetUp;
  SetUpTestData;
end;

procedure TCertificateTest.CheckCertificate(AId: Int32; const ACert: TCryptoLibByteArray);
var
  LObj: IX509CertificateStructure;
  LTbsCert: ITbsCertificateStructure;
  LExt: IX509Extensions;
  LOid: IDerObjectIdentifier;
  LExtVal: IX509Extension;
  LExtObj: IAsn1Object;
  LExtBytes: TCryptoLibByteArray;
  LExtendedKeyUsage: IExtendedKeyUsage;
  LSeq: IAsn1Sequence;
  I: Int32;
  LGeneralNames: IGeneralNames;
  LCrlDistPoint: ICrlDistPoint;
  LPoints: TCryptoLibGenericArray<IDistributionPoint>;
  LPolicyInfo: IPolicyInformation;
  LPolicySeq: IAsn1Sequence;
begin
  LObj := TX509CertificateStructure.GetInstance(ACert);
  LTbsCert := LObj.TbsCertificate;

  if LTbsCert.Subject.ToString() <> FSubjects[AId - 1] then
  begin
    Fail(Format('failed subject test for certificate id %d got %s', [AId, LTbsCert.Subject.ToString()]));
  end;

  if LTbsCert.Version >= 3 then
  begin
    LExt := LTbsCert.Extensions;
    if LExt <> nil then
    begin
      for LOid in LExt.ExtensionOids do
      begin
        LExtVal := LExt.GetExtension(LOid);
        LExtBytes := LExtVal.Value.GetOctets();
        LExtObj := TAsn1Object.FromByteArray(LExtBytes);

        if LOid.Equals(TX509Extensions.SubjectKeyIdentifier) then
        begin
          TSubjectKeyIdentifier.GetInstance(LExtObj);
        end
        else if LOid.Equals(TX509Extensions.KeyUsage) then
        begin
          TKeyUsage.GetKeyUsageInstance(LExtObj);
        end
        else if LOid.Equals(TX509Extensions.ExtendedKeyUsage) then
        begin
          LExtendedKeyUsage := TExtendedKeyUsage.GetInstance(LExtObj);
          LSeq := LExtendedKeyUsage.ToAsn1Object() as IAsn1Sequence;
          for I := 0 to LSeq.Count - 1 do
          begin
            TDerObjectIdentifier.GetInstance(LSeq[I]);
          end;
        end
        else if LOid.Equals(TX509Extensions.SubjectAlternativeName) then
        begin
          LGeneralNames := TGeneralNames.GetInstance(LExtObj);
          LSeq := LGeneralNames.ToAsn1Object() as IAsn1Sequence;
          for I := 0 to LSeq.Count - 1 do
          begin
            TGeneralName.GetInstance(LSeq[I]);
          end;
        end
        else if LOid.Equals(TX509Extensions.IssuerAlternativeName) then
        begin
          LGeneralNames := TGeneralNames.GetInstance(LExtObj);
          LSeq := LGeneralNames.ToAsn1Object() as IAsn1Sequence;
          for I := 0 to LSeq.Count - 1 do
          begin
            TGeneralName.GetInstance(LSeq[I]);
          end;
        end
        else if LOid.Equals(TX509Extensions.CrlDistributionPoints) then
        begin
          LCrlDistPoint := TCrlDistPoint.GetInstance(LExtObj);
          LPoints := LCrlDistPoint.GetDistributionPoints();
          // do nothing - just verify it parses
        end
        else if LOid.Equals(TX509Extensions.CertificatePolicies) then
        begin
          LPolicySeq := LExtObj as IAsn1Sequence;
          for I := 0 to LPolicySeq.Count - 1 do
          begin
            LPolicyInfo := TPolicyInformation.GetInstance(LPolicySeq[I]);
          end;
        end
        else if LOid.Equals(TX509Extensions.AuthorityKeyIdentifier) then
        begin
          TAuthorityKeyIdentifier.GetInstance(LExtObj);
        end
        else if LOid.Equals(TX509Extensions.BasicConstraints) then
        begin
          TBasicConstraints.GetInstance(LExtObj);
        end;
      end;
    end;
  end;
end;

procedure TCertificateTest.CheckDudCertificate;
var
  LCert: IX509CertificateStructure;
begin
  LCert := TX509CertificateStructure.GetInstance(FDudCert);

  if LCert.Issuer.ToString() <> '' then
  begin
    Fail('empty issuer not recognised correctly');
  end;
end;

procedure TCertificateTest.CheckMalformed;
begin
  try
    TTbsCertificateStructure.GetInstance(FBangerCert);
    Fail('Expected exception for malformed certificate');
  except
    on E: EArgumentCryptoLibException do
    begin
      // expected - anything else is not!
    end;
  end;
end;

procedure TCertificateTest.TestCertificate1;
begin
  CheckCertificate(1, FCert1);
end;

procedure TCertificateTest.TestCertificate2;
begin
  CheckCertificate(2, FCert2);
end;

procedure TCertificateTest.TestCertificate3;
begin
  CheckCertificate(3, FCert3);
end;

procedure TCertificateTest.TestCertificate4;
begin
  CheckCertificate(4, FCert4);
end;

procedure TCertificateTest.TestCertificate5;
begin
  CheckCertificate(5, FCert5);
end;

procedure TCertificateTest.TestCertificate6;
begin
  CheckCertificate(6, FCert6);
end;

procedure TCertificateTest.TestCertificate7;
begin
  CheckCertificate(7, FCert7);
end;

procedure TCertificateTest.TestDudCertificate;
begin
  CheckDudCertificate();
end;

procedure TCertificateTest.TestMalformedCertificate;
begin
  CheckMalformed();
end;

initialization

// Register any test cases with the test runner

{$IFDEF FPC}
  RegisterTest(TCertificateTest);
{$ELSE}
  RegisterTest(TCertificateTest.Suite);
{$ENDIF FPC}

end.
