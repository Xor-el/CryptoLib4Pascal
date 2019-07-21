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
  ClpCryptoLibTypes,
  CryptoLibTestBase;

type

  TTestOID = class(TCryptoLibAlgorithmTestCase)
  private

  var
    Freq1, Freq2: TBytes;

    procedure DoRecodeCheck(const oid: String; const enc: TBytes);
    procedure DoValidOidCheck(const oid: String);
    procedure DoInvalidOidCheck(const oid: String);
    procedure DoBranchCheck(const stem, branch: String);
    procedure DoOnCheck(const stem, test: String; expected: Boolean);

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestOID;

  end;

implementation

{ TTestOID }

procedure TTestOID.DoBranchCheck(const stem, branch: String);
var
  expected, actual: String;
  instance: IDerObjectIdentifier;
begin
  expected := stem + '.' + branch;
  instance := TDerObjectIdentifier.Create(stem);
  actual := instance.branch(branch).Id;

  CheckEquals(expected, actual, 'failed "branch" check for ' + stem + '/'
    + branch);
end;

procedure TTestOID.DoInvalidOidCheck(const oid: String);
begin
  try
    TDerObjectIdentifier.Create(oid);
    Fail(Format('failed to catch bad oid: %s', [oid]));

  except
    on e: EFormatCryptoLibException do
    begin
      // expected
    end;
  end;
end;

procedure TTestOID.DoOnCheck(const stem, test: String; expected: Boolean);
var
  tempDer, tempDer2: IDerObjectIdentifier;
  actual: Boolean;
begin
  tempDer := TDerObjectIdentifier.Create(test);
  tempDer2 := TDerObjectIdentifier.Create(stem);
  actual := tempDer.On(tempDer2);
  CheckEquals(expected, actual, 'failed "on" check for ' + stem + '"/"' + test);
end;

procedure TTestOID.DoRecodeCheck(const oid: String; const enc: TBytes);
var
  o, encO: IDerObjectIdentifier;
  bytes: TBytes;
begin
  o := TDerObjectIdentifier.Create(oid);
  encO := TAsn1Object.FromByteArray(enc) as IDerObjectIdentifier;

  bytes := o.GetDerEncoded();

  CheckEquals(o.Id, encO.Id, Format('Expected %s but got %s. on recodeCheck',
    [o.Id, encO.Id]));

  CheckEquals(true, o.Equals(encO), 'object comparison failed');

  CheckEquals(true, AreEqual(bytes, enc), 'bytearray comparison failed');
end;

procedure TTestOID.SetUp;
begin
  inherited;
  Freq1 := DecodeHex('0603813403');
  Freq2 := DecodeHex('06082A36FFFFFFDD6311');
end;

procedure TTestOID.TearDown;
begin
  inherited;

end;

procedure TTestOID.TestOID;
begin
  DoRecodeCheck('2.100.3', Freq1);
  DoRecodeCheck('1.2.54.34359733987.17', Freq2);

  DoValidOidCheck('0.1');
  DoValidOidCheck('1.0');
  DoValidOidCheck('1.0.2');
  DoValidOidCheck('1.0.20');
  DoValidOidCheck('1.0.200');
  DoValidOidCheck
    ('1.1.127.32512.8323072.2130706432.545460846592.139637976727552.35747322042253312.9151314442816847872');
  DoValidOidCheck('1.2.123.12345678901.1.1.1');

  DoValidOidCheck('2.25.196556539987194312349856245628873852187.1');

  DoInvalidOidCheck('0');
  DoInvalidOidCheck('1');
  DoInvalidOidCheck('2');
  DoInvalidOidCheck('3.1');
  DoInvalidOidCheck('0.01');
  DoInvalidOidCheck('00.1');
  DoInvalidOidCheck('1.00.2');
  DoInvalidOidCheck('1.0.02');
  DoInvalidOidCheck('1.2.00');
  DoInvalidOidCheck('..1');
  DoInvalidOidCheck('192.168.1.1');
  DoInvalidOidCheck('.123452');
  DoInvalidOidCheck('1.');
  DoInvalidOidCheck('1.345.23.34..234');
  DoInvalidOidCheck('1.345.23.34.234.');
  DoInvalidOidCheck('.12.345.77.234');
  DoInvalidOidCheck('.12.345.77.234.');
  DoInvalidOidCheck('1.2.3.4.A.5');
  DoInvalidOidCheck('1,2');

  DoBranchCheck('1.1', '2.2');

  DoOnCheck('1.1', '1.1', false);
  DoOnCheck('1.1', '1.2', false);
  DoOnCheck('1.1', '1.2.1', false);
  DoOnCheck('1.1', '2.1', false);
  DoOnCheck('1.1', '1.11', false);
  DoOnCheck('1.12', '1.1.2', false);
  DoOnCheck('1.1', '1.1.1', true);
  DoOnCheck('1.1', '1.1.2', true);
end;

procedure TTestOID.DoValidOidCheck(const oid: String);
var
  o: IDerObjectIdentifier;
begin
  o := TDerObjectIdentifier.Create(oid);
  o := TAsn1Object.FromByteArray(o.GetEncoded()) as IDerObjectIdentifier;
  CheckEquals(oid, o.Id, Format('Expected %s but got %s.', [oid, o.Id]));

end;

initialization

// Register any test cases with the test runner

{$IFDEF FPC}
  RegisterTest(TTestOID);
{$ELSE}
  RegisterTest(TTestOID.Suite);
{$ENDIF FPC}

end.
