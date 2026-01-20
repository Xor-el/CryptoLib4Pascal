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

unit RelativeOidTests;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  Classes,
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

  TRelativeOidTest = class(TCryptoLibAlgorithmTestCase)
  strict private
    FReq1, FReq2: TCryptoLibByteArray;
  protected
    procedure SetUp; override;
    procedure TearDown; override;

    procedure RecodeCheck(const AOid: String; const AEnc: TCryptoLibByteArray);
    procedure CheckValid(const AOid: String);
    procedure CheckInvalid(const AOid: String);
    procedure BranchCheck(const AStem, ABranch: String);

  published
    procedure TestRelativeOid;
  end;

implementation

{ TRelativeOidTest }

procedure TRelativeOidTest.SetUp;
begin
  inherited;
  FReq1 := THex.Decode('0D03813403');
  FReq2 := THex.Decode('0D082A36FFFFFFDD6311');
end;

procedure TRelativeOidTest.TearDown;
begin
  FReq1 := nil;
  FReq2 := nil;
  inherited;
end;

procedure TRelativeOidTest.BranchCheck(const AStem, ABranch: String);
var
  LExpected, LActual: String;
  LInstance: IAsn1RelativeOid;
begin
  LExpected := AStem + '.' + ABranch;
  LInstance := TAsn1RelativeOid.Create(AStem);
  LActual := LInstance.Branch(ABranch).Id;

  if LExpected <> LActual then
  begin
    Fail(Format('failed "branch" check for %s/%s', [AStem, ABranch]));
  end;
end;

procedure TRelativeOidTest.CheckInvalid(const AOid: String);
var
  LIgnore: IAsn1RelativeOid;
begin
  CheckFalse(TAsn1RelativeOid.TryFromID(AOid, LIgnore), Format('TryFromID should return False for invalid OID: %s', [AOid]));

  try
    TAsn1RelativeOid.Create(AOid);
    Fail(Format('failed to catch bad relative oid: %s', [AOid]));
  except
    on E: EFormatCryptoLibException do
    begin
      // expected
    end;
  end;
end;

procedure TRelativeOidTest.CheckValid(const AOid: String);
var
  LOid: IAsn1RelativeOid;
begin
  CheckTrue(TAsn1RelativeOid.TryFromID(AOid, LOid), Format('TryFromID should return True for valid OID: %s', [AOid]));

  LOid := TAsn1RelativeOid.Create(AOid);
  LOid := TAsn1RelativeOid.GetInstance(TAsn1Object.FromByteArray(LOid.GetEncoded()));

  if not LOid.Id.Equals(AOid) then
  begin
    Fail(Format('failed relative oid check for %s', [AOid]));
  end;
end;

procedure TRelativeOidTest.RecodeCheck(const AOid: String; const AEnc: TCryptoLibByteArray);
var
  LOid, LEncOid: IAsn1RelativeOid;
  LBytes: TCryptoLibByteArray;
begin
  LOid := TAsn1RelativeOid.Create(AOid);
  LEncOid := TAsn1RelativeOid.GetInstance(TAsn1Object.FromByteArray(AEnc));

  if not LOid.Equals(LEncOid) then
  begin
    Fail('relative OID didn''t match');
  end;

  LBytes := LOid.GetDerEncoded();

  if not AreEqual(LBytes, AEnc) then
  begin
    Fail(Format('failed comparison test: expected %s but got %s', [THex.Encode(AEnc), THex.Encode(LBytes)]));
  end;
end;

procedure TRelativeOidTest.TestRelativeOid;
begin
  RecodeCheck('180.3', FReq1);
  RecodeCheck('42.54.34359733987.17', FReq2);

  CheckValid('0');
  CheckValid('37');
  CheckValid('0.1');
  CheckValid('1.0');
  CheckValid('1.0.2');
  CheckValid('1.0.20');
  CheckValid('1.0.200');
  CheckValid('1.1.127.32512.8323072.2130706432.545460846592.139637976727552.35747322042253312.9151314442816847872');
  CheckValid('1.2.123.12345678901.1.1.1');
  CheckValid('2.25.196556539987194312349856245628873852187.1');
  CheckValid('3.1');
  CheckValid('37.196556539987194312349856245628873852187.100');
  CheckValid('192.168.1.1');

  CheckInvalid('00');
  CheckInvalid('0.01');
  CheckInvalid('00.1');
  CheckInvalid('1.00.2');
  CheckInvalid('1.0.02');
  CheckInvalid('1.2.00');
  CheckInvalid('.1');
  CheckInvalid('..1');
  CheckInvalid('3..1');
  CheckInvalid('.123452');
  CheckInvalid('1.');
  CheckInvalid('1.345.23.34..234');
  CheckInvalid('1.345.23.34.234.');
  CheckInvalid('.12.345.77.234');
  CheckInvalid('.12.345.77.234.');
  CheckInvalid('1.2.3.4.A.5');
  CheckInvalid('1,2');

  BranchCheck('1.1', '2.2');
end;

initialization

// Register any test cases with the test runner

{$IFDEF FPC}
  RegisterTest(TRelativeOidTest);
{$ELSE}
  RegisterTest(TRelativeOidTest.Suite);
{$ENDIF FPC}

end.
