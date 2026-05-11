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

unit AuthorityKeyIdentifierTests;

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
  ClpCryptoLibTypes,
  ClpBigInteger,
  ClpAsn1Objects,
  ClpIAsn1Objects,
  ClpIAsn1Core,
  ClpIX509Asn1Objects,
  ClpX509Asn1Objects,
  CryptoLibTestBase;

type

  TAuthorityKeyIdentifierTest = class(TCryptoLibAlgorithmTestCase)
  strict private
    procedure AllocZeroKeyIdentifier20(var AOctets: TCryptoLibByteArray);
  published
    procedure TestValidCombinationsParse;
    procedure TestInvalidCombinationsRejected;
    procedure TestPublicConstructorsRejectMismatchedIssuerAndSerial;
  end;

implementation

{ TAuthorityKeyIdentifierTest }

procedure TAuthorityKeyIdentifierTest.AllocZeroKeyIdentifier20(var AOctets: TCryptoLibByteArray);
begin
  System.SetLength(AOctets, 20);
  ZeroFill(AOctets);
end;

procedure TAuthorityKeyIdentifierTest.TestValidCombinationsParse;
var
  LKeyIdOctets: TCryptoLibByteArray;
  LIssuer: IGeneralNames;
  LOct: IDerOctetString;
  LTagged0, LTagged1, LTagged2: IAsn1Encodable;
  LIdentifier: IAuthorityKeyIdentifier;
begin
  LIdentifier := TAuthorityKeyIdentifier.Create(TDerSequence.Empty);

  AllocZeroKeyIdentifier20(LKeyIdOctets);
  LOct := TDerOctetString.Create(LKeyIdOctets);
  LTagged0 := TDerTaggedObject.Create(False, 0, LOct);
  LIdentifier := TAuthorityKeyIdentifier.Create(TDerSequence.FromElements([LTagged0]));

  LIssuer := TGeneralNames.Create(TGeneralName.Create(TX509Name.Create('CN=Test') as IX509Name) as IGeneralName);
  LTagged1 := TDerTaggedObject.Create(False, 1, LIssuer);
  LTagged2 := TDerTaggedObject.Create(False, 2, TDerInteger.One);
  LIdentifier := TAuthorityKeyIdentifier.Create(TDerSequence.FromElements([LTagged1, LTagged2]));

  AllocZeroKeyIdentifier20(LKeyIdOctets);
  LOct := TDerOctetString.Create(LKeyIdOctets);
  LTagged0 := TDerTaggedObject.Create(False, 0, LOct);
  LTagged1 := TDerTaggedObject.Create(False, 1, LIssuer);
  LTagged2 := TDerTaggedObject.Create(False, 2, TDerInteger.One);
  LIdentifier := TAuthorityKeyIdentifier.Create(TDerSequence.FromElements([LTagged0, LTagged1, LTagged2]));
end;

procedure TAuthorityKeyIdentifierTest.TestInvalidCombinationsRejected;
var
  LKeyIdOctets: TCryptoLibByteArray;
  LIssuer: IGeneralNames;
  LOct: IDerOctetString;
  LSeen: Boolean;
begin
  LSeen := False;
  try
    TAuthorityKeyIdentifier.Create(TDerSequence.FromElements(
      [TDerTaggedObject.Create(False, 2, TDerInteger.One) as IDerTaggedObject]));
  except
    on E: EArgumentCryptoLibException do
    begin
      if Pos('MUST both be present', E.Message) = 0 then
        Fail('unexpected message: ' + E.Message);
      LSeen := True;
    end;
  end;
  if not LSeen then
    Fail('authorityCertSerialNumber-only AKI accepted');

  LIssuer := TGeneralNames.Create(TGeneralName.Create(TX509Name.Create('CN=Test') as IX509Name) as IGeneralName);

  LSeen := False;
  try
    TAuthorityKeyIdentifier.Create(TDerSequence.FromElements(
      [TDerTaggedObject.Create(False, 1, LIssuer) as IDerTaggedObject]));
  except
    on E: EArgumentCryptoLibException do
    begin
      if Pos('MUST both be present', E.Message) = 0 then
        Fail('unexpected message: ' + E.Message);
      LSeen := True;
    end;
  end;
  if not LSeen then
    Fail('authorityCertIssuer-only AKI accepted');

  AllocZeroKeyIdentifier20(LKeyIdOctets);
  LOct := TDerOctetString.Create(LKeyIdOctets);
  LSeen := False;
  try
    TAuthorityKeyIdentifier.Create(TDerSequence.FromElements([
      TDerTaggedObject.Create(False, 0, LOct) as IDerTaggedObject,
      TDerTaggedObject.Create(False, 2, TDerInteger.One) as IDerTaggedObject
    ]));
  except
    on E: EArgumentCryptoLibException do
      LSeen := True;
    else
      raise;
  end;
  if not LSeen then
    Fail('keyId + serial-only AKI accepted');
end;

procedure TAuthorityKeyIdentifierTest.TestPublicConstructorsRejectMismatchedIssuerAndSerial;
var
  LKeyId: TCryptoLibByteArray;
  LIssuer: IGeneralNames;
  LNilIssuer: IGeneralNames;
  LOk: Boolean;
  LIdentifier: IAuthorityKeyIdentifier;
begin
  AllocZeroKeyIdentifier20(LKeyId);
  LIssuer := TGeneralNames.Create(TGeneralName.Create(TX509Name.Create('CN=Test') as IX509Name) as IGeneralName);

  LOk := False;
  try
    TAuthorityKeyIdentifier.Create(LKeyId, LIssuer, TBigInteger.GetDefault);
  except
    on E: EArgumentCryptoLibException do
      LOk := True;
    else
      raise;
  end;
  if not LOk then
    Fail('(TBytes, GeneralNames, default serial) accepted');

  LOk := False;
  try
    TAuthorityKeyIdentifier.Create(LKeyId, nil, TBigInteger.One);
  except
    on E: EArgumentCryptoLibException do
      LOk := True;
    else
      raise;
  end;
  if not LOk then
    Fail('(TBytes, nil, BigInteger) accepted');

  LOk := False;
  try
    TAuthorityKeyIdentifier.Create(LIssuer, TBigInteger.GetDefault);
  except
    on E: EArgumentCryptoLibException do
      LOk := True;
    else
      raise;
  end;
  if not LOk then
    Fail('(GeneralNames, default serial) accepted');

  LOk := False;
  LNilIssuer := nil;
  try
    TAuthorityKeyIdentifier.Create(LNilIssuer, TBigInteger.One);
  except
    on E: EArgumentCryptoLibException do
      LOk := True;
    else
      raise;
  end;
  if not LOk then
    Fail('(nil issuer, BigInteger) accepted');

  LIdentifier := TAuthorityKeyIdentifier.Create(LKeyId);
  LIdentifier := TAuthorityKeyIdentifier.Create(LKeyId, nil, TBigInteger.GetDefault);
  LIdentifier := TAuthorityKeyIdentifier.Create(LKeyId, LIssuer, TBigInteger.One);
  LIdentifier := TAuthorityKeyIdentifier.Create(LIssuer, TBigInteger.One);
end;

initialization

{$IFDEF FPC}
RegisterTest(TAuthorityKeyIdentifierTest);
{$ELSE}
RegisterTest(TAuthorityKeyIdentifierTest.Suite);
{$ENDIF FPC}

end.
