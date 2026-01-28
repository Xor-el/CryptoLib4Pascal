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

unit X509NameTests;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  SysUtils,
  Generics.Collections,
{$IFDEF FPC}
  fpcunit,
  testregistry,
{$ELSE}
  TestFramework,
{$ENDIF FPC}
  ClpX509Asn1Objects,
  ClpIX509Asn1Objects,
  ClpCryptoLibTypes,
  CryptoLibTestBase;

type

  TX509NameTest = class(TCryptoLibAlgorithmTestCase)
  strict private
    var
      FSubjects: TCryptoLibStringArray;
      FHexSubjects: TCryptoLibStringArray;

    procedure SetUpTestData;
    function FromBytes(const ABytes: TCryptoLibByteArray): IX509Name;

  protected
    procedure SetUp; override;

  published
    procedure TestBasicEncoding;
    procedure TestRegeneration;
    procedure TestHexRegeneration;
    procedure TestEquality;

  end;

implementation

{ TX509NameTest }

procedure TX509NameTest.SetUpTestData;
begin
  System.SetLength(FSubjects, 12);
  FSubjects[0] := 'C=AU,ST=Victoria,L=South Melbourne,O=Connect 4 Pty Ltd,OU=Webserver Team,CN=www2.connect4.com.au,E=webmaster@connect4.com.au';
  FSubjects[1] := 'C=AU,ST=Victoria,L=South Melbourne,O=Connect 4 Pty Ltd,OU=Certificate Authority,CN=Connect 4 CA,E=webmaster@connect4.com.au';
  FSubjects[2] := 'C=AU,ST=QLD,CN=SSLeay/rsa test cert';
  FSubjects[3] := 'C=US,O=National Aeronautics and Space Administration,SERIALNUMBER=16+CN=Steve Schoch';
  FSubjects[4] := 'E=cooke@issl.atl.hp.com,C=US,OU=Hewlett Packard Company (ISSL),CN=Paul A. Cooke';
  FSubjects[5] := 'O=Sun Microsystems Inc,CN=store.sun.com';
  FSubjects[6] := 'unstructuredAddress=192.168.1.33,unstructuredName=pixfirewall.ciscopix.com,CN=pixfirewall.ciscopix.com';
  FSubjects[7] := 'CN=*.canal-plus.com,OU=Provided by TBS INTERNET https://www.tbs-certificats.com/,OU=\ CANAL \+,O=CANAL\+DISTRIBUTION,L=issy les moulineaux,ST=Hauts de Seine,C=FR';
  FSubjects[8] := 'O=Bouncy Castle,CN=www.bouncycastle.org\ ';
  FSubjects[9] := 'O=Bouncy Castle,CN=c:\\fred\\bob';
  FSubjects[10] := 'C=0,O=1,OU=2,T=3,CN=4,SERIALNUMBER=5,STREET=6,SERIALNUMBER=7,L=8,ST=9,SURNAME=10,GIVENNAME=11,INITIALS=12,' +
    'GENERATION=13,UniqueIdentifier=14,BusinessCategory=15,PostalCode=16,DN=17,Pseudonym=18,PlaceOfBirth=19,' +
    'Gender=20,CountryOfCitizenship=21,CountryOfResidence=22,NameAtBirth=23,PostalAddress=24,2.5.4.54=25,' +
    'TelephoneNumber=26,Name=27,E=28,unstructuredName=29,unstructuredAddress=30,E=31,DC=32,UID=33';
  FSubjects[11] := 'C=DE,L=Berlin,O=Wohnungsbaugenossenschaft \"Humboldt-Universität\" eG,CN=transfer.wbg-hub.de';

  System.SetLength(FHexSubjects, 4);
  FHexSubjects[0] := 'CN=\20Test\20X,O=\20Test,C=GB';         // input
  FHexSubjects[1] := 'CN=\ Test X,O=\ Test,C=GB';              // expected
  FHexSubjects[2] := 'CN=\20Test\20X\20,O=\20Test,C=GB';     // input
  FHexSubjects[3] := 'CN=\ Test X\ ,O=\ Test,C=GB';           // expected
end;

procedure TX509NameTest.SetUp;
begin
  inherited SetUp;
  SetUpTestData;
end;

function TX509NameTest.FromBytes(const ABytes: TCryptoLibByteArray): IX509Name;
begin
  Result := TX509Name.GetInstance(ABytes);
end;

procedure TX509NameTest.TestBasicEncoding;
var
  LName1, LName2: IX509Name;
begin
  LName1 := TX509Name.Create('CN=Test');
  LName2 := FromBytes(LName1.GetEncoded());
  CheckTrue(LName1.Equivalent(LName2), 'Basic encoding test failed');
end;

procedure TX509NameTest.TestRegeneration;
var
  I: Int32;
  LSubject: String;
  LName: IX509Name;
  LDecodedName: IX509Name;
  LDecodedSubject: String;
begin
  for I := 0 to System.Length(FSubjects) - 1 do
  begin
    LSubject := FSubjects[I];

    LName := TX509Name.Create(LSubject);

    LDecodedName := FromBytes(LName.GetEncoded());

    LDecodedSubject := LDecodedName.ToString();

    if not LSubject.Equals(LDecodedSubject) then
    begin
      Fail(Format('Failed regeneration test %d got: %s expected %s', [I, LDecodedSubject, LSubject]));
    end;
  end;
end;

procedure TX509NameTest.TestHexRegeneration;
var
  I: Int32;
  LSubject, LExpected: String;
  LName: IX509Name;
  LDecodedName: IX509Name;
  LDecodedSubject: String;
begin
  I := 0;
  while I < System.Length(FHexSubjects) do
  begin
    LSubject := FHexSubjects[I];
    LExpected := FHexSubjects[I + 1];

    LName := TX509Name.Create(LSubject);

    LDecodedName := FromBytes(LName.GetEncoded());

    LDecodedSubject := LDecodedName.ToString();

    if not LExpected.Equals(LDecodedSubject) then
    begin
      Fail(Format('Failed hex regeneration test %d got: %s expected %s', [I, LDecodedSubject, LExpected]));
    end;

    System.Inc(I, 2);
  end;
end;

procedure TX509NameTest.TestEquality;
var
  LName1, LName2: IX509Name;
begin
  LName1 := TX509Name.Create('CN=The     Legion');
  LName2 := TX509Name.Create('CN=The Legion');
  CheckTrue(LName1.Equivalent(LName2), 'Equality test 1 failed');

  LName1 := TX509Name.Create('CN=   The Legion');
  LName2 := TX509Name.Create('CN=The Legion');
  CheckTrue(LName1.Equivalent(LName2), 'Equality test 2 failed');

  LName1 := TX509Name.Create('CN=The Legion   ');
  LName2 := TX509Name.Create('CN=The Legion');
  CheckTrue(LName1.Equivalent(LName2), 'Equality test 3 failed');

  LName1 := TX509Name.Create('CN=  The     Legion ');
  LName2 := TX509Name.Create('CN=The Legion');
  CheckTrue(LName1.Equivalent(LName2), 'Equality test 4 failed');

  LName1 := TX509Name.Create('CN=  the     legion ');
  LName2 := TX509Name.Create('CN=The Legion');
  CheckTrue(LName1.Equivalent(LName2), 'Equality test 5 failed');
end;

initialization

{$IFDEF FPC}
RegisterTest(TX509NameTest);
{$ELSE}
RegisterTest(TX509NameTest.Suite);
{$ENDIF FPC}

end.
