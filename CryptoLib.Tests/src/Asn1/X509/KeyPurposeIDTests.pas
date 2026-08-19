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
  CheckKeyPurposeID(TKeyPurposeId.IdKpSecureShellClient, '1.3.6.1.5.5.7.3.21');
  CheckKeyPurposeID(TKeyPurposeId.IdKpSecureShellServer, '1.3.6.1.5.5.7.3.22');
  CheckKeyPurposeID(TKeyPurposeId.IdKpCmcArchive, '1.3.6.1.5.5.7.3.29');
  CheckKeyPurposeID(TKeyPurposeId.IdKpBundleSecurity, '1.3.6.1.5.5.7.3.35');
  CheckKeyPurposeID(TKeyPurposeId.IdKpDocumentSigning, '1.3.6.1.5.5.7.3.36');
  CheckKeyPurposeID(TKeyPurposeId.IdKpJwt, '1.3.6.1.5.5.7.3.37');
  CheckKeyPurposeID(TKeyPurposeId.IdKpHttpContentEncrypt, '1.3.6.1.5.5.7.3.38');
  CheckKeyPurposeID(TKeyPurposeId.IdKpOauthAccessTokenSigning, '1.3.6.1.5.5.7.3.39');
  CheckKeyPurposeID(TKeyPurposeId.IdKpImUri, '1.3.6.1.5.5.7.3.40');
  CheckKeyPurposeID(TKeyPurposeId.IdKpConfigSigning, '1.3.6.1.5.5.7.3.41');
  CheckKeyPurposeID(TKeyPurposeId.IdKpTrustAnchorConfigSigning, '1.3.6.1.5.5.7.3.42');
  CheckKeyPurposeID(TKeyPurposeId.IdKpUpdatePackageSigning, '1.3.6.1.5.5.7.3.43');
  CheckKeyPurposeID(TKeyPurposeId.IdKpSafetyCommunication, '1.3.6.1.5.5.7.3.44');
  // Kerberos PKINIT: id-pkinit arc rather than id-kp
  CheckKeyPurposeID(TKeyPurposeId.IdKpPkinitClientAuth, '1.3.6.1.5.2.3.4');
  CheckKeyPurposeID(TKeyPurposeId.IdKpPkinitKdc, '1.3.6.1.5.2.3.5');
end;

initialization

{$IFDEF FPC}
RegisterTest(TKeyPurposeIDTest);
{$ELSE}
RegisterTest(TKeyPurposeIDTest.Suite);
{$ENDIF FPC}

end.
