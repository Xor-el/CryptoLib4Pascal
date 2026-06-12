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

unit IdpRelativeNameTests;

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
  ClpIAsn1Core,
  ClpIX509Asn1Objects,
  ClpX509Asn1Objects,
  CryptoLibTestBase;

type

  /// <summary>Tests for IssuingDistributionPoint relative names (ASN.1 encoding).</summary>
  /// <remarks>
  /// Per RFC 5280 sec. 4.2.1.13, IssuingDistributionPoint's nameRelativeToCRLIssuer is a single
  /// RelativeDistinguishedName (a SET of AttributeTypeAndValue) that, per sec. 5.2.5, is appended as one element
  /// to the CRL issuer's RDNSequence to form the full distribution-point DN.
  /// </remarks>
  TIdpRelativeNameTest = class(TCryptoLibAlgorithmTestCase)
  published
    procedure TestSequenceShapedRelativeNameRejected;
  end;

implementation

{ TIdpRelativeNameTest }

procedure TIdpRelativeNameTest.TestSequenceShapedRelativeNameRejected;
var
  LName: IX509Name;
  LInner: IAsn1Encodable;
  LTagged: IAsn1TaggedObject;
  LDpName: IDistributionPointName;
  LRejected: Boolean;
begin
  LName := TX509Name.Create('O=ExampleOrg,OU=Test');
  LInner := LName.ToAsn1Object() as IAsn1Encodable;
  LTagged := TDerTaggedObject.Create(False, TDistributionPointName.NameRelativeToCrlIssuer, LInner);

  LRejected := False;
  try
    LDpName := TDistributionPointName.GetOptional(LTagged);
    if LDpName = nil then
      LRejected := True;
  except
    on E: Exception do
      LRejected := True;
  end;
  if not LRejected then
    Fail('sequence-shaped nameRelativeToCRLIssuer accepted by GetOptional');

  LRejected := False;
  try
    TDistributionPointName.GetInstance(LTagged, False);
  except
    on E: Exception do
      LRejected := True;
  end;
  if not LRejected then
    Fail('sequence-shaped nameRelativeToCRLIssuer accepted by GetInstance');
end;

initialization

{$IFDEF FPC}
RegisterTest(TIdpRelativeNameTest);
{$ELSE}
RegisterTest(TIdpRelativeNameTest.Suite);
{$ENDIF FPC}

end.
