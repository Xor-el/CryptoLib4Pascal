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

unit KeyPurposeIDTests;

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
  ClpX509Asn1Objects,
  ClpAsn1Objects,
  ClpIAsn1Objects,
  CryptoLibTestBase;

type

  TKeyPurposeIDTest = class(TCryptoLibAlgorithmTestCase)
  strict private
    procedure CheckKeyPurposeID(const AKeyPurposeID: IDerObjectIdentifier;
      const AExpectedID: String);

  published
    procedure TestKeyPurposeIDs;
  end;

implementation

{ TKeyPurposeIDTest }

procedure TKeyPurposeIDTest.CheckKeyPurposeID(const AKeyPurposeID: IDerObjectIdentifier;
  const AExpectedID: String);
var
  LRecoveredOid: IDerObjectIdentifier;
begin
  if not SameText(AExpectedID, AKeyPurposeID.ID) then
    Fail(Format('wrong ID for KeyPurposeID: expected %s but got %s',
      [AExpectedID, AKeyPurposeID.ID]));

  LRecoveredOid := TDerObjectIdentifier.GetInstance(AKeyPurposeID.GetEncoded());
  if not SameText(AExpectedID, LRecoveredOid.ID) then
    Fail(Format('KeyPurposeID did not round-trip: expected %s but got %s',
      [AExpectedID, LRecoveredOid.ID]));
end;

procedure TKeyPurposeIDTest.TestKeyPurposeIDs;
begin
  CheckKeyPurposeID(TKeyPurposeId.IdKpDocumentSigning, '1.3.6.1.5.5.7.3.36');
  CheckKeyPurposeID(TKeyPurposeId.IdKpImUri, '1.3.6.1.5.5.7.3.40');
  CheckKeyPurposeID(TKeyPurposeId.IdKpConfigSigning, '1.3.6.1.5.5.7.3.41');
  CheckKeyPurposeID(TKeyPurposeId.IdKpTrustAnchorConfigSigning, '1.3.6.1.5.5.7.3.42');
  CheckKeyPurposeID(TKeyPurposeId.IdKpUpdatePackageSigning, '1.3.6.1.5.5.7.3.43');
  CheckKeyPurposeID(TKeyPurposeId.IdKpSafetyCommunication, '1.3.6.1.5.5.7.3.44');
end;

initialization

{$IFDEF FPC}
RegisterTest(TKeyPurposeIDTest);
{$ELSE}
RegisterTest(TKeyPurposeIDTest.Suite);
{$ENDIF FPC}

end.
