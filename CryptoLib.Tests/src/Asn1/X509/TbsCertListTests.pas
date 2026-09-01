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

unit TbsCertListTests;

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
  CryptoLibTestBase;

type

  // RFC 5280 sec. 5.1.2.3: a CRL issuer field MUST contain a non-empty distinguished name.
  TTbsCertListTest = class(TCryptoLibAlgorithmTestCase)
  strict private
    function SigAlg: IAlgorithmIdentifier;
    function EmptyName: IX509Name;
    function BuildCrlBody(const AIssuer: IX509Name): TCryptoLibByteArray;
  published
    procedure TestEmptyIssuerDNRejected;
    procedure TestNonEmptyIssuerDNAccepted;
    procedure TestV2GeneratorRejectsEmptyIssuer;
  end;

implementation

{ TTbsCertListTest }

function TTbsCertListTest.SigAlg: IAlgorithmIdentifier;
begin
  Result := TAlgorithmIdentifier.Create(
    TDerObjectIdentifier.Create('1.2.840.113549.1.1.11') as IDerObjectIdentifier);
end;

function TTbsCertListTest.EmptyName: IX509Name;
begin
  Result := TX509Name.GetInstance(TDerSequence.Empty as IAsn1Convertible);
end;

function TTbsCertListTest.BuildCrlBody(const AIssuer: IX509Name): TCryptoLibByteArray;
var
  LVec: IAsn1EncodableVector;
  LSeq: IDerSequence;
begin
  LVec := TAsn1EncodableVector.Create();
  LVec.Add(TDerInteger.One); // version v2
  LVec.Add(SigAlg);
  LVec.Add(AIssuer);
  LVec.Add(TAsn1UtcTime.Create('250101000000Z') as IAsn1UtcTime); // thisUpdate
  LSeq := TDerSequence.Create(LVec);
  Result := LSeq.GetEncoded(TAsn1Encodable.Der);
end;

procedure TTbsCertListTest.TestEmptyIssuerDNRejected;
var
  LEncoded: TCryptoLibByteArray;
begin
  LEncoded := BuildCrlBody(EmptyName);
  try
    TTbsCertificateList.GetInstance(LEncoded);
    Fail('empty issuer DN accepted');
  except
    on E: EArgumentCryptoLibException do
      ; // expected
  end;
end;

procedure TTbsCertListTest.TestNonEmptyIssuerDNAccepted;
var
  LIssuer: IX509Name;
  LTbs: ITbsCertificateList;
begin
  LIssuer := TX509Name.Create('CN=Test CA');
  LTbs := TTbsCertificateList.GetInstance(BuildCrlBody(LIssuer));
  CheckTrue(LTbs.Issuer.Equivalent(LIssuer), 'issuer mismatch on roundtrip');
end;

procedure TTbsCertListTest.TestV2GeneratorRejectsEmptyIssuer;
var
  LGen: IV2TbsCertListGenerator;
begin
  LGen := TV2TbsCertListGenerator.Create;
  LGen.SetSignature(SigAlg);
  LGen.SetIssuer(EmptyName);
  LGen.SetThisUpdate(TAsn1UtcTime.Create('250101000000Z') as IAsn1UtcTime);

  try
    LGen.GenerateTbsCertList;
    Fail('V2 CRL generator accepted empty issuer');
  except
    on E: EInvalidOperationCryptoLibException do
      ; // expected
  end;
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTbsCertListTest);
{$ELSE}
  RegisterTest(TTbsCertListTest.Suite);
{$ENDIF FPC}

end.
