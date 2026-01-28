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

unit OIDTests;

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
  ClpEncoders,
  ClpCryptoLibTypes,
  CryptoLibTestBase;

type

  TOIDTest = class(TCryptoLibAlgorithmTestCase)
  strict private
    FReq1, FReq2: TCryptoLibByteArray;
  protected
    procedure SetUp; override;
    procedure TearDown; override;

    procedure RecodeCheck(const AOid: String; const AEnc: TCryptoLibByteArray);
    procedure CheckValid(const AOid: String);
    procedure CheckInvalid(const AOid: String);
    procedure BranchCheck(const AStem, ABranch: String);
    procedure OnCheck(const AStem, ATest: String; AExpected: Boolean);

  published
    procedure TestOID;
  end;

implementation

{ TOIDTest }

procedure TOIDTest.SetUp;
begin
  inherited;
  FReq1 := THex.Decode('0603813403');
  FReq2 := THex.Decode('06082A36FFFFFFDD6311');
end;

procedure TOIDTest.TearDown;
begin
  FReq1 := nil;
  FReq2 := nil;
  inherited;
end;

procedure TOIDTest.BranchCheck(const AStem, ABranch: String);
var
  LExpected, LActual: String;
  LInstance: IDerObjectIdentifier;
begin
  LExpected := AStem + '.' + ABranch;
  LInstance := TDerObjectIdentifier.Create(AStem);
  LActual := LInstance.Branch(ABranch).Id;

  if LExpected <> LActual then
  begin
    Fail(Format('failed "branch" check for %s/%s', [AStem, ABranch]));
  end;
end;

procedure TOIDTest.CheckInvalid(const AOid: String);
var
  LIgnore: IDerObjectIdentifier;
begin
  CheckFalse(TDerObjectIdentifier.TryFromID(AOid, LIgnore), Format('TryFromID should return False for invalid OID: %s', [AOid]));

  try
    TDerObjectIdentifier.Create(AOid);
    Fail(Format('failed to catch bad oid: %s', [AOid]));
  except
    on E: EFormatCryptoLibException do
    begin
      // expected
    end;
  end;
end;

procedure TOIDTest.CheckValid(const AOid: String);
var
  LOid: IDerObjectIdentifier;
begin
  CheckTrue(TDerObjectIdentifier.TryFromID(AOid, LOid), Format('TryFromID should return True for valid OID: %s', [AOid]));

  LOid := TDerObjectIdentifier.Create(AOid);
  LOid := TDerObjectIdentifier.GetInstance(TAsn1Object.FromByteArray(LOid.GetEncoded()));

  if not LOid.Id.Equals(AOid) then
  begin
    Fail(Format('failed oid check: %s', [AOid]));
  end;
end;

procedure TOIDTest.OnCheck(const AStem, ATest: String; AExpected: Boolean);
var
  LTempDer, LTempDer2: IDerObjectIdentifier;
  LActual: Boolean;
begin
  LTempDer := TDerObjectIdentifier.Create(ATest);
  LTempDer2 := TDerObjectIdentifier.Create(AStem);
  LActual := LTempDer.On(LTempDer2);
  if AExpected <> LActual then
  begin
    Fail(Format('failed "on" check for %s"/"%s', [AStem, ATest]));
  end;
end;

procedure TOIDTest.RecodeCheck(const AOid: String; const AEnc: TCryptoLibByteArray);
var
  LOid, LEncOid: IDerObjectIdentifier;
  LBytes: TCryptoLibByteArray;
begin
  LOid := TDerObjectIdentifier.Create(AOid);
  LEncOid := TDerObjectIdentifier.GetInstance(TAsn1Object.FromByteArray(AEnc));

  if not LOid.Equals(LEncOid) then
  begin
    Fail('oid ID didn''t match');
  end;

  LBytes := LOid.GetDerEncoded();

  if not AreEqual(LBytes, AEnc) then
  begin
    Fail(Format('failed comparison test: expected %s but got %s', [THex.Encode(AEnc), THex.Encode(LBytes)]));
  end;
end;

procedure TOIDTest.TestOID;
begin
  RecodeCheck('2.100.3', FReq1);
  RecodeCheck('1.2.54.34359733987.17', FReq2);

  CheckValid('0.1');
  CheckValid('1.0');
  CheckValid('1.0.2');
  CheckValid('1.0.20');
  CheckValid('1.0.200');
  CheckValid('1.1.127.32512.8323072.2130706432.545460846592.139637976727552.35747322042253312.9151314442816847872');
  CheckValid('1.2.123.12345678901.1.1.1');
  CheckValid('2.25.196556539987194312349856245628873852187.1');
  CheckValid('0.0');
  CheckValid('0.0.1');
  CheckValid('0.39');
  CheckValid('0.39.1');
  CheckValid('1.0');
  CheckValid('1.0.1');
  CheckValid('1.39');
  CheckValid('1.39.1');
  CheckValid('2.0');
  CheckValid('2.0.1');
  CheckValid('2.40');
  CheckValid('2.40.1');

  CheckInvalid('0');
  CheckInvalid('1');
  CheckInvalid('2');
  CheckInvalid('3.1');
  CheckInvalid('..1');
  CheckInvalid('192.168.1.1');
  CheckInvalid('.123452');
  CheckInvalid('1.');
  CheckInvalid('1.345.23.34..234');
  CheckInvalid('1.345.23.34.234.');
  CheckInvalid('.12.345.77.234');
  CheckInvalid('.12.345.77.234.');
  CheckInvalid('1.2.3.4.A.5');
  CheckInvalid('1,2');
  CheckInvalid('0.40');
  CheckInvalid('0.40.1');
  CheckInvalid('0.100');
  CheckInvalid('0.100.1');
  CheckInvalid('1.40');
  CheckInvalid('1.40.1');
  CheckInvalid('1.100');
  CheckInvalid('1.100.1');

  BranchCheck('1.1', '2.2');

  OnCheck('1.1', '1.1', False);
  OnCheck('1.1', '1.2', False);
  OnCheck('1.1', '1.2.1', False);
  OnCheck('1.1', '2.1', False);
  OnCheck('1.1', '1.11', False);
  OnCheck('1.12', '1.1.2', False);
  OnCheck('1.1', '1.1.1', True);
  OnCheck('1.1', '1.1.2', True);
  OnCheck('1.2.3.4.5.6', '1.2.3.4.5.6', False);
  OnCheck('1.2.3.4.5.6', '1.2.3.4.5.6.7', True);
  OnCheck('1.2.3.4.5.6', '1.2.3.4.5.6.7.8', True);
end;

initialization

// Register any test cases with the test runner

{$IFDEF FPC}
  RegisterTest(TOIDTest);
{$ELSE}
  RegisterTest(TOIDTest.Suite);
{$ENDIF FPC}

end.
