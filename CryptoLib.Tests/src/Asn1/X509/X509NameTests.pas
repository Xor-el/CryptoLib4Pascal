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

unit X509NameTests;

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
  ClpIAsn1Core,
  ClpIAsn1Objects,
  ClpX509Asn1Objects,
  ClpIX509Asn1Objects,
  ClpAsn1Objects,
  ClpIetfUtilities,
  ClpX509DefaultEntryConverter,
  ClpCryptoLibTypes,
  ClpCryptoLibExceptions,
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
    procedure TestRfc4514UnescapedEqualsInAttributeValue;
    procedure TestInvalidHexDnFailsAtConstruction;
    procedure TestCountryCodeLength;
    procedure TestCommonNameLength;
    procedure TestDnQualifierAttributeAliases;
    procedure TestStateOrProvinceAttributeAliases;
    procedure TestHexEscapedUtf8Parse;
    procedure TestEscapeRoundTrip;
    procedure TestInvariantCaseFolding;

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
  FSubjects[8] := 'O=CryptoLib4Pascal,CN=www.cryptolib4pascal.org\ ';
  FSubjects[9] := 'O=CryptoLib4Pascal,CN=c:\\fred\\bob';
  FSubjects[10] := 'C=AU,O=1,OU=2,T=3,CN=4,SERIALNUMBER=5,STREET=6,SERIALNUMBER=7,L=8,ST=9,SURNAME=10,GIVENNAME=11,INITIALS=12,' +
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

procedure TX509NameTest.TestRfc4514UnescapedEqualsInAttributeValue;
var
  LSubjects: array [0 .. 3] of String;
  LExpectedValues: array [0 .. 3] of String;
  I: Int32;
  LName: IX509Name;
begin
  // RFC 4514 allows '=' in attributeValue; only the first '=' separates type from value.
  LSubjects[0] := 'CN=foo=bar';
  LSubjects[1] := 'CN==^_^=';
  LSubjects[2] := 'CN=a=b=c';
  LSubjects[3] := 'CN=\=^_^\=';

  LExpectedValues[0] := 'foo=bar';
  LExpectedValues[1] := '=^_^=';
  LExpectedValues[2] := 'a=b=c';
  LExpectedValues[3] := '=^_^=';

  for I := Low(LSubjects) to High(LSubjects) do
  begin
    LName := TX509Name.Create(LSubjects[I]);
    CheckEquals(LExpectedValues[I], LName.GetValueList()[0],
      'unexpected CN value for ' + LSubjects[I]);
  end;

  try
    TX509Name.Create('CN');
    Fail('malformed DN without ''='' should raise');
  except
    on EArgumentCryptoLibException do
      ; // expected
  end;
end;

procedure TX509NameTest.TestInvalidHexDnFailsAtConstruction;
begin
  try
    TX509Name.Create('CN=#GG');
    Fail('invalid hex-encoded DN value should raise during construction');
  except
    on E: ECryptoLibException do
      CheckTrue(Pos('cannot recode value', E.Message) > 0,
        'unexpected exception message: ' + E.Message);
  end;
end;

procedure TX509NameTest.TestCountryCodeLength;
var
  LConverter: TX509DefaultEntryConverter;
  LCountryOids: array [0 .. 1] of IDerObjectIdentifier;
  LBadValues: array [0 .. 2] of String;
  I, J: Int32;
  LParsed: IX509Name;
  LOid: IDerObjectIdentifier;
begin
  CheckTrue(TX509Name.DefaultLookup.TryGetValue('jurisdictionCountry', LOid),
    'DefaultLookup should contain jurisdictionCountry');
  CheckTrue(LOid.Equals(TX509Name.JurisdictionC),
    'DefaultLookup[jurisdictionCountry] should be JurisdictionC');
  CheckTrue(TX509Name.DefaultLookup.TryGetValue('jurisdictionState', LOid),
    'DefaultLookup should contain jurisdictionState');
  CheckTrue(LOid.Equals(TX509Name.JurisdictionST),
    'DefaultLookup[jurisdictionState] should be JurisdictionST');
  CheckTrue(TX509Name.DefaultLookup.TryGetValue('jurisdictionLocality', LOid),
    'DefaultLookup should contain jurisdictionLocality');
  CheckTrue(LOid.Equals(TX509Name.JurisdictionL),
    'DefaultLookup[jurisdictionLocality] should be JurisdictionL');

  LCountryOids[0] := TX509Name.C;
  LCountryOids[1] := TX509Name.JurisdictionC;
  LBadValues[0] := 'USA';
  LBadValues[1] := 'U';
  LBadValues[2] := '';

  LConverter := TX509DefaultEntryConverter.Create();
  try
    LConverter.GetConvertedValue(TX509Name.C, 'US');
    LConverter.GetConvertedValue(TX509Name.JurisdictionC, 'US');

    for I := Low(LCountryOids) to High(LCountryOids) do
      for J := Low(LBadValues) to High(LBadValues) do
      begin
        try
          LConverter.GetConvertedValue(LCountryOids[I], LBadValues[J]);
          Fail(Format('country code attribute %s accepted ''%s''',
            [LCountryOids[I].Id, LBadValues[J]]));
        except
          on EArgumentCryptoLibException do
            ; // expected
        end;
      end;
  finally
    LConverter.Free;
  end;

  LParsed := TX509Name.Create('C=AU');

  try
    LParsed := TX509Name.Create('C=USA');
    Fail('X509Name(''C=USA'') accepted 3-character country code');
  except
    on EArgumentCryptoLibException do
      ; // expected
  end;

  // Lenient parse of existing DER with non-conforming C length (do not block reading wild certs).
  LParsed := TX509Name.GetInstance(
    TDerSequence.FromElement(
      TDerSet.FromElement(
        TDerSequence.Create([
          TX509Name.C,
          TDerPrintableString.Create('USA') as IDerPrintableString]) as IDerSequence)));
  CheckEquals('USA', LParsed.GetValueList(TX509Name.C)[0],
    'lenient parse of 3-character C failed');
end;

procedure TX509NameTest.TestCommonNameLength;
var
  LCn64, LCn65: String;
  LName, LParsed: IX509Name;
begin
  LCn64 := StringOfChar('A', 64);
  LCn65 := StringOfChar('A', 65);

  LName := TX509Name.Create('CN=' + LCn64);

  try
    LName := TX509Name.Create('CN=' + LCn65);
    Fail('X509Name(''CN=...'') accepted 65-char CN');
  except
    on EArgumentCryptoLibException do
      ; // expected
  end;

  // Lenient parse of existing DER with an over-length CN (do not block reading wild certs).
  LParsed := TX509Name.GetInstance(
    TDerSequence.FromElement(
      TDerSet.FromElement(
        TDerSequence.Create([
          TX509Name.CN,
          TDerUtf8String.Create(LCn65) as IDerUtf8String]) as IDerSequence)));
  CheckEquals(LCn65, LParsed.GetValueList(TX509Name.CN)[0],
    'lenient parse of 65-char CN failed');
end;

procedure TX509NameTest.TestDnQualifierAttributeAliases;
var
  LAliases: array [0 .. 5] of String;
  LName: IX509Name;
  LList: TCryptoLibStringArray;
  I: Int32;
begin
  // PKIX subject strings vary in spelling for oid 2.5.4.46; ensure each maps to dnQualifier via DefaultLookup.
  LAliases[0] := 'DN';
  LAliases[1] := 'DNQ';
  LAliases[2] := 'dnQualifier';
  LAliases[3] := 'dn';
  LAliases[4] := 'dnq';
  LAliases[5] := 'dnqualifier';

  for I := Low(LAliases) to High(LAliases) do
  begin
    LName := TX509Name.Create('CN=Foo,' + LAliases[I] + '=ABC123');
    LList := LName.GetValueList(TX509Name.DnQualifier);
    CheckEquals(Int32(1), Int32(System.Length(LList)),
      'unexpected dnQualifier RDN count for attribute label ''' + LAliases[I] + '''');
    CheckEquals('ABC123', LList[0],
      'unexpected dnQualifier value for attribute label ''' + LAliases[I] + '''');
  end;
end;

procedure TX509NameTest.TestStateOrProvinceAttributeAliases;
var
  LAliases: array [0 .. 3] of String;
  LName: IX509Name;
  LList: TCryptoLibStringArray;
  I: Int32;
begin
  LAliases[0] := 'ST';
  LAliases[1] := 'st';
  LAliases[2] := 'S';
  LAliases[3] := 's';

  for I := Low(LAliases) to High(LAliases) do
  begin
    LName := TX509Name.Create('CN=Foo,' + LAliases[I] + '=California');
    LList := LName.GetValueList(TX509Name.ST);
    CheckEquals(Int32(1), Int32(System.Length(LList)),
      'Alias ''' + LAliases[I] + ''' did not parse to a single stateOrProvinceName RDN');
    CheckEquals('California', LList[0],
      'unexpected stateOrProvinceName value for alias ''' + LAliases[I] + '''');
  end;

  LName := TX509Name.Create('CN=Foo,S=California');
  CheckEquals('CN=Foo,ST=California', LName.ToString(),
    '''S'' alias did not normalise to ST on output');
end;

procedure TX509NameTest.TestHexEscapedUtf8Parse;
var
  LSubjects: array [0 .. 3] of String;
  LExpectedValues: array [0 .. 3] of String;
  I: Int32;
  LName, LReparsed: IX509Name;
  LVal, LReVal: String;
begin
  LSubjects[0] := 'CN=Lu\C4\8Di\C4\87';
  LSubjects[1] := 'CN=M\C3\B6rsky';
  LSubjects[2] := 'CN=\E6\97\A5\E6\9C\AC';
  LSubjects[3] := 'CN=Lu\C4\8Di\C4\87,O=Acme';

  LExpectedValues[0] := 'Lučić';
  LExpectedValues[1] := 'Mörsky';
  LExpectedValues[2] := '日本';
  LExpectedValues[3] := 'Lučić';

  for I := Low(LSubjects) to High(LSubjects) do
  begin
    LName := TX509Name.Create(LSubjects[I]);
    LVal := LName.GetValueList(TX509Name.CN)[0];
    CheckEquals(LExpectedValues[I], LVal,
      'unexpected CN value for ' + LSubjects[I]);

    LReparsed := FromBytes(LName.GetEncoded());
    LReVal := LReparsed.GetValueList(TX509Name.CN)[0];
    CheckEquals(LExpectedValues[I], LReVal,
      'round-trip lost data for ' + LSubjects[I]);
  end;

  // Lone leading byte without continuation is malformed UTF-8.
  // TODO: Enable on FPC when TEncoding.UTF8 rejects invalid sequences (currently lenient;
  // lone $C4 decodes as '?' instead of throwing). Delphi: expect EEncodingError.
{$IFNDEF FPC}
  try
    TX509Name.Create('CN=Lu\C4');
    Fail('malformed UTF-8 escape sequence not rejected');
  except
    on E: EEncodingError do
      ; // expected
  end;
{$ENDIF FPC}
end;

procedure TX509NameTest.TestEscapeRoundTrip;
const
  CASE_COUNT = 15;
var
  LInputs: array [0 .. CASE_COUNT - 1] of String;
  LValues: array [0 .. CASE_COUNT - 1] of String;
  LStrings: array [0 .. CASE_COUNT - 1] of String;
  LMalformed: array [0 .. 10] of String;
  I: Int32;
  LName, LReparsed: IX509Name;
  LEmpty: IX509Name;
begin
  LInputs[0] := 'CN=a\,b';
  LInputs[1] := 'CN=a\;b';
  LInputs[2] := 'CN=a\<b';
  LInputs[3] := 'CN=a\>b';
  LInputs[4] := 'CN=a\\b';
  LInputs[5] := 'CN=a\+b';
  LInputs[6] := 'CN=a\=b';
  LInputs[7] := 'CN=a\"b';
  LInputs[8] := 'CN=a\ b';
  LInputs[9] := 'CN="a,b"';
  LInputs[10] := 'CN="a;b"';
  LInputs[11] := 'CN="a+b"';
  LInputs[12] := 'CN="a\b"';
  LInputs[13] := 'CN=   a\+b';
  LInputs[14] := 'CN=\C3\A9\+';

  LValues[0] := 'a,b';
  LValues[1] := 'a;b';
  LValues[2] := 'a<b';
  LValues[3] := 'a>b';
  LValues[4] := 'a\b';
  LValues[5] := 'a+b';
  LValues[6] := 'a=b';
  LValues[7] := 'a"b';
  LValues[8] := 'a b';
  LValues[9] := 'a,b';
  LValues[10] := 'a;b';
  LValues[11] := 'a+b';
  LValues[12] := 'a\b';
  LValues[13] := 'a+b';
  LValues[14] := 'é+';

  LStrings[0] := 'CN=a\,b';
  LStrings[1] := 'CN=a\;b';
  LStrings[2] := 'CN=a\<b';
  LStrings[3] := 'CN=a\>b';
  LStrings[4] := 'CN=a\\b';
  LStrings[5] := 'CN=a\+b';
  LStrings[6] := 'CN=a\=b';
  LStrings[7] := 'CN=a\"b';
  LStrings[8] := 'CN=a b';
  LStrings[9] := 'CN=a\,b';
  LStrings[10] := 'CN=a\;b';
  LStrings[11] := 'CN=a\+b';
  LStrings[12] := 'CN=a\\b';
  LStrings[13] := 'CN=a\+b';
  LStrings[14] := 'CN=é\+';

  for I := 0 to CASE_COUNT - 1 do
  begin
    LName := TX509Name.Create(LInputs[I]);
    CheckEquals(LValues[I], LName.GetValueList(TX509Name.CN)[0],
      'unescape value for [' + LInputs[I] + ']');
    CheckEquals(LStrings[I], LName.ToString(),
      'ToString for [' + LInputs[I] + ']');

    LReparsed := TX509Name.Create(LName.ToString());
    CheckEquals(LValues[I], LReparsed.GetValueList(TX509Name.CN)[0],
      'round-trip value for [' + LInputs[I] + ']');
  end;

  LEmpty := TX509Name.Create('CN=');
  CheckEquals('', LEmpty.GetValueList(TX509Name.CN)[0], 'empty value');

  LMalformed[0] := 'CN=a\Cz';
  LMalformed[1] := 'CN=a\C,O=x';
  LMalformed[2] := 'CN=a\C b';
  LMalformed[3] := 'CN=ab\C';
  LMalformed[4] := 'CN=a\C"b"';
  LMalformed[5] := 'CN=\Cz\AB';
  LMalformed[6] := 'CN=abc\';
  LMalformed[7] := 'O=x,CN=abc\';
  LMalformed[8] := 'CN="abc';
  LMalformed[9] := 'CN="abc,O=x';
  LMalformed[10] := 'CN="';

  for I := Low(LMalformed) to High(LMalformed) do
  begin
    try
      TX509Name.Create(LMalformed[I]);
      Fail('malformed hex escape not rejected: ' + LMalformed[I]);
    except
      on E: EArgumentCryptoLibException do
        ; // expected
    end;
  end;
end;

procedure TX509NameTest.TestInvariantCaseFolding;
var
  LUpper, LLower: IX509Name;
begin
  CheckEquals('it', TIetfUtilities.Canonicalize('IT'),
    'Canonicalize must use invariant case folding');

  LUpper := TX509Name.Create('CN=ITALY,C=IT');
  LLower := TX509Name.Create('CN=italy,C=it');
  CheckTrue(LUpper.Equivalent(LLower),
    'Equivalent must use invariant case folding');
end;

initialization

{$IFDEF FPC}
RegisterTest(TX509NameTest);
{$ELSE}
RegisterTest(TX509NameTest.Suite);
{$ENDIF FPC}

end.
