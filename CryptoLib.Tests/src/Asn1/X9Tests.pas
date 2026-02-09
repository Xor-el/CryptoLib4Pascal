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

unit X9Tests;

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
  ClpIAsn1Objects,
  ClpAsn1Objects,
  ClpIX9ECAsn1Objects,
  ClpX9ECAsn1Objects,
  ClpX9IntegerConverter,
  ClpX962NamedCurves,
  ClpX9ObjectIdentifiers,
  ClpIX509Asn1Objects,
  ClpX509Asn1Objects,
  ClpIPkcsAsn1Objects,
  ClpPkcsAsn1Objects,
  ClpISecECAsn1Objects,
  ClpSecECAsn1Objects,
  ClpIECCommon,
  ClpCryptoLibTypes,
  CryptoLibTestBase;

type

  TX9Test = class(TCryptoLibAlgorithmTestCase)
  strict private
  var
    FNamedPub: TCryptoLibByteArray;
    FExpPub: TCryptoLibByteArray;
    FNamedPriv: TCryptoLibByteArray;
    FExpPriv: TCryptoLibByteArray;

    procedure SetUpTestData;
    procedure EncodePublicKey;
    procedure EncodePrivateKey;

  protected
    procedure SetUp; override;

  published
    procedure TestEncodePublicKey;
    procedure TestEncodePrivateKey;

  end;

implementation

{ TX9Test }

procedure TX9Test.SetUpTestData;
begin
  FNamedPub := DecodeBase64('MDcwEwYHKoZIzj0CAQYIKoZIzj0DAQEDIAADG5xRI+Iki/JrvL20hoDUa7Cggzorv5B9yyqSMjYu');

  FExpPub := DecodeBase64(
    'MIH8MIHXBgcqhkjOPQIBMIHLAgEBMCkGByqGSM49AQECHn///////////////3///////4AAAA'
    + 'AAAH///////zBXBB5///////////////9///////+AAAAAAAB///////wEHiVXBfoqMGZUsfTL'
    + 'A9anUKMMJQEC1JiHF9m6FattPgMVAH1zdBaP/jRxtgqFdoahlHXTv6L/BB8DZ2iujhi7ks/PAF'
    + 'yUmqLG2UhT0OZgu/hUsclQX+laAh5///////////////9///+XXetBs6YFfDxDIUZSZVECAQED'
    + 'IAADG5xRI+Iki/JrvL20hoDUa7Cggzorv5B9yyqSMjYu');

  FNamedPriv := DecodeBase64('MDkCAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQEEHzAdAgEBBBgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAo=');

  FExpPriv := DecodeBase64(
    'MIIBBAIBADCB1wYHKoZIzj0CATCBywIBATApBgcqhkjOPQEBAh5///////////////9///////'
    + '+AAAAAAAB///////8wVwQef///////////////f///////gAAAAAAAf//////8BB4lVwX6KjBmVL'
    + 'H0ywPWp1CjDCUBAtSYhxfZuhWrbT4DFQB9c3QWj/40cbYKhXaGoZR107+i/wQfA2doro4Yu5LPzw'
    + 'BclJqixtlIU9DmYLv4VLHJUF/pWgIef///////////////f///l13rQbOmBXw8QyFGUmVRAgEBBC'
    + 'UwIwIBAQQeAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAU');
end;

procedure TX9Test.SetUp;
begin
  inherited;
  SetUpTestData;
end;

procedure TX9Test.EncodePublicKey;
var
  LEcP: IX9ECParameters;
  LX962: IX962Parameters;
  LPoint: IECPoint;
  LP: IAsn1OctetString;
  LEncoded: TCryptoLibByteArray;
  LInfo: ISubjectPublicKeyInfo;
  LAlgId: IAlgorithmIdentifier;
  LX9P: IX9ECPoint;
  LObj: ISubjectPublicKeyInfo;
begin
  LEcP := TX962NamedCurves.GetByOid(TX9ObjectIdentifiers.Prime239v3);

  if TX9IntegerConverter.GetByteLength(LEcP.Curve) <> 30 then
    Fail('wrong byte length reported for curve');

  if LEcP.Curve.FieldSize <> 239 then
    Fail('wrong field size reported for curve');

  // named curve
  LX962 := TX962Parameters.Create(TX9ObjectIdentifiers.Prime192v1);
  LPoint := LEcP.G.Multiply(TBigInteger.ValueOf(100));
  LEncoded := LPoint.GetEncoded(True);
  LP := TDerOctetString.Create(LEncoded);

  LAlgId := TAlgorithmIdentifier.Create(TX9ObjectIdentifiers.IdECPublicKey, LX962);
  LInfo := TSubjectPublicKeyInfo.Create(LAlgId, LP.GetOctets());

  if not AreEqual(LInfo.GetEncoded(), FNamedPub) then
    Fail('failed public named generation');

  LX9P := TX9ECPoint.Create(LEcP.Curve, LP);
  if not AreEqual(LP.GetOctets(), LX9P.PointEncoding.GetOctets()) then
    Fail('point encoding not preserved');

  LObj := TSubjectPublicKeyInfo.GetInstance(FNamedPub);
  if not AreEqual(LObj.GetEncoded(), FNamedPub) then
    Fail('failed public named equality');

  // explicit curve parameters
  LX962 := TX962Parameters.Create(LEcP);
  LAlgId := TAlgorithmIdentifier.Create(TX9ObjectIdentifiers.IdECPublicKey, LX962);
  LInfo := TSubjectPublicKeyInfo.Create(LAlgId, LP.GetOctets());

  if not AreEqual(LInfo.GetEncoded(), FExpPub) then
    Fail('failed public explicit generation');

  LObj := TSubjectPublicKeyInfo.GetInstance(FExpPub);
  if not AreEqual(LObj.GetEncoded(), FExpPub) then
    Fail('failed public explicit equality');
end;

procedure TX9Test.EncodePrivateKey;
var
  LEcP: IX9ECParameters;
  LX962: IX962Parameters;
  LEcPriv: IECPrivateKeyStructure;
  LInfo: IPrivateKeyInfo;
  LAlgId: IAlgorithmIdentifier;
  LObj: IPrivateKeyInfo;
begin
  // named curve
  LEcP := TX962NamedCurves.GetByOid(TX9ObjectIdentifiers.Prime192v1);
  LX962 := TX962Parameters.Create(TX9ObjectIdentifiers.Prime192v1);
  LEcPriv := TECPrivateKeyStructure.Create(LEcP.N.BitLength, TBigInteger.Ten);

  LAlgId := TAlgorithmIdentifier.Create(TX9ObjectIdentifiers.IdECPublicKey, LX962);
  LInfo := TPrivateKeyInfo.Create(LAlgId, LEcPriv);

  if not AreEqual(LInfo.GetEncoded(), FNamedPriv) then
    Fail('failed private named generation');

  LObj := TPrivateKeyInfo.GetInstance(FNamedPriv);
  if not AreEqual(LObj.GetEncoded(), FNamedPriv) then
    Fail('failed private named equality');

  // explicit curve parameters
  LEcP := TX962NamedCurves.GetByOid(TX9ObjectIdentifiers.Prime239v3);
  LX962 := TX962Parameters.Create(LEcP);
  LEcPriv := TECPrivateKeyStructure.Create(LEcP.N.BitLength, TBigInteger.ValueOf(20));

  LAlgId := TAlgorithmIdentifier.Create(TX9ObjectIdentifiers.IdECPublicKey, LX962);
  LInfo := TPrivateKeyInfo.Create(LAlgId, LEcPriv);

  if not AreEqual(LInfo.GetEncoded(), FExpPriv) then
    Fail('failed private explicit generation');

  LObj := TPrivateKeyInfo.GetInstance(FExpPriv);
  if not AreEqual(LObj.GetEncoded(), FExpPriv) then
    Fail('failed private explicit equality');
end;

procedure TX9Test.TestEncodePublicKey;
begin
  EncodePublicKey;
end;

procedure TX9Test.TestEncodePrivateKey;
begin
  EncodePrivateKey;
end;

initialization

{$IFDEF FPC}
  RegisterTest(TX9Test);
{$ELSE}
  RegisterTest(TX9Test.Suite);
{$ENDIF FPC}

end.
