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
  ClpHex,
  ClpArrayUtils,
  ClpCryptoLibTypes,
  ClpAsn1Object,
  ClpDerObjectIdentifier,
  ClpIDerObjectIdentifier;

type

  TCryptoLibTestCase = class abstract(TTestCase)

  end;

type

  TTestOID = class(TCryptoLibTestCase)
  private

  var
    Foid: string;
    Freq1, Freq2: TCryptoLibByteArray;

    procedure recodeCheck(const oid: String; const enc: TBytes);
    procedure validOidCheck(const oid: String);
    procedure invalidOidCheck;
    procedure branchCheck(const stem, branch: String);
    procedure onCheck(const stem, test: String; expected: Boolean);
    procedure constructorMethod;

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestOID;

  end;

implementation

{ TTestOID }

procedure TTestOID.branchCheck(const stem, branch: String);
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

procedure TTestOID.constructorMethod;
begin
  TDerObjectIdentifier.Create(Foid);
end;

procedure TTestOID.invalidOidCheck;
var
{$IFNDEF FPC}
  Method: TTestMethod;
{$ELSE}
  Method: TRunMethod;
{$ENDIF FPC}
begin

  Method := constructorMethod;
  CheckException(Method, EFormatCryptoLibException,
    'Expected "EFormatCryptoLibException" But None Gotten');
end;

procedure TTestOID.onCheck(const stem, test: String; expected: Boolean);
var
  tempDer, tempDer2: IDerObjectIdentifier;
  actual: Boolean;
begin
  tempDer := TDerObjectIdentifier.Create(test);
  tempDer2 := TDerObjectIdentifier.Create(stem);
  actual := tempDer.On(tempDer2);
  CheckEquals(expected, actual, 'failed "on" check for ' + stem + '"/"' + test);
end;

procedure TTestOID.recodeCheck(const oid: String; const enc: TBytes);
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

  CheckEquals(true, TArrayUtils.AreEqual(bytes, enc),
    'bytearray comparison failed');
end;

procedure TTestOID.SetUp;
begin
  Freq1 := THex.Decode('0603813403');
  Freq2 := THex.Decode('06082A36FFFFFFDD6311');
end;

procedure TTestOID.TearDown;
begin
  inherited;

end;

procedure TTestOID.TestOID;
begin
  recodeCheck('2.100.3', Freq1);
  recodeCheck('1.2.54.34359733987.17', Freq2);

  validOidCheck('0.1');
  validOidCheck
    ('1.1.127.32512.8323072.2130706432.545460846592.139637976727552.35747322042253312.9151314442816847872');
  validOidCheck('1.2.123.12345678901.1.1.1');

  validOidCheck('2.25.196556539987194312349856245628873852187.1');

  Foid := '0';
  invalidOidCheck;
  Foid := '1';
  invalidOidCheck;
  Foid := '2';
  invalidOidCheck;
  Foid := '3.1';
  invalidOidCheck;
  Foid := '..1';
  invalidOidCheck;
  Foid := '192.168.1.1';
  invalidOidCheck;
  Foid := '.123452';
  invalidOidCheck;
  Foid := '1.';
  invalidOidCheck;
  Foid := '1.345.23.34..234';
  invalidOidCheck;
  Foid := '1.345.23.34.234.';
  invalidOidCheck;
  Foid := '.12.345.77.234';
  invalidOidCheck;
  Foid := '.12.345.77.234.';
  invalidOidCheck;
  Foid := '1.2.3.4.A.5';
  invalidOidCheck;
  Foid := '1,2';
  invalidOidCheck;

  branchCheck('1.1', '2.2');

  onCheck('1.1', '1.1', false);
  onCheck('1.1', '1.2', false);
  onCheck('1.1', '1.2.1', false);
  onCheck('1.1', '2.1', false);
  onCheck('1.1', '1.11', false);
  onCheck('1.12', '1.1.2', false);
  onCheck('1.1', '1.1.1', true);
  onCheck('1.1', '1.1.2', true);
end;

procedure TTestOID.validOidCheck(const oid: String);
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
