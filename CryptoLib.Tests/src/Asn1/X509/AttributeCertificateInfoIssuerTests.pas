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

unit AttributeCertificateInfoIssuerTests;

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
  ClpCryptoLibTypes,
  ClpCryptoLibExceptions,
  CryptoLibTestBase;

type

  // RFC 3281 sec. 4.2.3: an AttCertIssuer MUST identify the issuer; an empty AttCertIssuer is invalid.
  TAttributeCertificateInfoIssuerTest = class(TCryptoLibAlgorithmTestCase)
  strict private
    function SigAlg: IAlgorithmIdentifier;
    function CreateHolder: IHolder;
    function BuildAttrCertInfo(const AIssuer: IAsn1Encodable): TCryptoLibByteArray;
  published
    procedure TestParseRejectsEmptyV1Issuer;
    procedure TestParseRejectsEmptyV2Issuer;
  end;

implementation

{ TAttributeCertificateInfoIssuerTest }

function TAttributeCertificateInfoIssuerTest.SigAlg: IAlgorithmIdentifier;
begin
  Result := TAlgorithmIdentifier.Create(
    TDerObjectIdentifier.Create('1.2.840.113549.1.1.11') as IDerObjectIdentifier);
end;

function TAttributeCertificateInfoIssuerTest.CreateHolder: IHolder;
begin
  Result := THolder.Create(
    TGeneralNames.Create(
      TGeneralName.Create(TX509Name.Create('CN=Holder') as IX509Name) as IGeneralName) as IGeneralNames);
end;

function TAttributeCertificateInfoIssuerTest.BuildAttrCertInfo(
  const AIssuer: IAsn1Encodable): TCryptoLibByteArray;
var
  LVec: IAsn1EncodableVector;
  LSeq: IDerSequence;
begin
  LVec := TAsn1EncodableVector.Create();
  LVec.Add(TDerInteger.One);          // version v2
  LVec.Add(CreateHolder.ToAsn1Object); // holder
  LVec.Add(AIssuer);                  // issuer (CHOICE)
  LVec.Add(SigAlg);                   // signature
  LVec.Add(TDerInteger.One);          // serialNumber
  LVec.Add(TAttCertValidityPeriod.Create(
    TAsn1GeneralizedTime.Create('20250101000000Z') as IAsn1GeneralizedTime,
    TAsn1GeneralizedTime.Create('20260101000000Z') as IAsn1GeneralizedTime) as IAttCertValidityPeriod);
  LVec.Add(TDerSequence.Empty as IAsn1Encodable); // attributes (empty seq OK at parse time)
  LSeq := TDerSequence.Create(LVec);
  Result := LSeq.GetEncoded(TAsn1Encodable.Der);
end;

procedure TAttributeCertificateInfoIssuerTest.TestParseRejectsEmptyV1Issuer;
var
  LEncoded: TCryptoLibByteArray;
begin
  // v1 form: AttCertIssuer = empty GeneralNames sequence
  LEncoded := BuildAttrCertInfo(TDerSequence.Empty as IAsn1Encodable);
  try
    TAttributeCertificateInfo.GetInstance(LEncoded);
    Fail('empty v1 GeneralNames issuer accepted');
  except
    on E: EArgumentCryptoLibException do
      ; // expected
  end;
end;

procedure TAttributeCertificateInfoIssuerTest.TestParseRejectsEmptyV2Issuer;
var
  LEncoded: TCryptoLibByteArray;
begin
  // v2 form: V2Form [0] with no issuerName/baseCertificateID/objectDigestInfo
  LEncoded := BuildAttrCertInfo(
    TDerTaggedObject.Create(False, 0, TDerSequence.Empty) as IAsn1Encodable);
  try
    TAttributeCertificateInfo.GetInstance(LEncoded);
    Fail('empty v2 V2Form issuer accepted');
  except
    on E: EArgumentCryptoLibException do
      ; // expected
  end;
end;

initialization

{$IFDEF FPC}
  RegisterTest(TAttributeCertificateInfoIssuerTest);
{$ELSE}
  RegisterTest(TAttributeCertificateInfoIssuerTest.Suite);
{$ENDIF FPC}

end.
