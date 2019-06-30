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

unit Pkcs5Tests;

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
  ClpIKeyParameter,
  ClpPkcs5S2ParametersGenerator,
  ClpIPkcs5S2ParametersGenerator,
  ClpDigestUtilities,
  ClpConverters,
  CryptoLibTestBase;

type

  /// <summary>
  /// A test class for Pkcs5 PbeS2 with PBKDF2(Pkcs5 v2.0).
  /// </summary>
  TTestPkcs5 = class(TCryptoLibAlgorithmTestCase)

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published

    /// <summary>
    /// Test Vectors gotten from <see href="https://github.com/ircmaxell/PHP-PasswordLib/blob/master/test/Data/Vectors/pbkdf2-draft-josefsson-sha1.test-vectors">
    /// PKDF2 Test Vectors</see> and some other sources.
    /// </summary>
    procedure TestPkcs5_WITH_SHA1;

    /// <summary>
    /// Test Vectors gotten from <see href="https://github.com/ircmaxell/quality-checker/blob/master/tmp/gh_18/PHP-PasswordLib-master/test/Data/Vectors/pbkdf2-draft-josefsson-sha256.test-vectors">
    /// PKDF2 Test Vectors</see> and some other sources.
    /// </summary>
    procedure TestPkcs5_WITH_SHA256;

  end;

implementation

{ TTestPkcs5 }

procedure TTestPkcs5.SetUp;
begin
  inherited;

end;

procedure TTestPkcs5.TearDown;
begin
  inherited;

end;

procedure TTestPkcs5.TestPkcs5_WITH_SHA1;
var
  PasswordString, SaltString: String;
  PasswordBytes, SaltBytes: TBytes;
  generator: IPkcs5S2ParametersGenerator;
  iteration_count, dkLen: Int32;
begin
  //
  // RFC 3211 tests
  //
  SaltBytes := DecodeHex('1234567878563412');

  PasswordString := 'password';
  PasswordBytes := TConverters.ConvertStringToBytes(PasswordString,
    TEncoding.UTF8);
  generator := TPkcs5S2ParametersGenerator.Create
    (TDigestUtilities.GetDigest('SHA-1'));

  generator.Init(PasswordBytes, SaltBytes, 5);

  if (not AreEqual((generator.GenerateDerivedMacParameters(64) as IKeyParameter)
    .GetKey(), DecodeHex('D1DAA78615F287E6'))) then
  begin
    Fail('PBKDF2 HMAC-SHA1 with iteration count "5", 64 bits key generation test failed');
  end;

  generator.Clear();

  PasswordString :=
    'All n-entities must communicate with other n-entities via n-1 entiteeheehees';
  PasswordBytes := TConverters.ConvertStringToBytes(PasswordString,
    TEncoding.UTF8);

  generator.Init(PasswordBytes, SaltBytes, 500);

  if (not AreEqual((generator.GenerateDerivedMacParameters(192)
    as IKeyParameter).GetKey(),
    DecodeHex('6A8970BF68C92CAEA84A8DF28510858607126380CC47AB2D'))) then
  begin
    Fail('PBKDF2 HMAC-SHA1 with iteration count "500", 192 bits key generation test failed');
  end;

  generator.Clear();

  generator.Init(PasswordBytes, SaltBytes, 60000);

  if (not AreEqual((generator.GenerateDerivedMacParameters(192)
    as IKeyParameter).GetKey(),
    DecodeHex('29AAEF810C12ECD2236BBCFB55407F9852B5573DC1C095BB'))) then
  begin
    Fail('PBKDF2 HMAC-SHA1 with iteration count "60000", 192 bits key generation test failed');
  end;

  generator.Clear();

  // https://github.com/ircmaxell/PHP-PasswordLib/blob/master/test/Data/Vectors/pbkdf2-draft-josefsson-sha1.test-vectors

  generator := TPkcs5S2ParametersGenerator.Create
    (TDigestUtilities.GetDigest('SHA-1'));

  PasswordString := 'password';
  PasswordBytes := TConverters.ConvertStringToBytes(PasswordString,
    TEncoding.UTF8);

  SaltString := 'salt';
  SaltBytes := TConverters.ConvertStringToBytes(SaltString, TEncoding.UTF8);

  // 1

  iteration_count := 1;

  dkLen := 20 * 8; // multiplied by 8 to get it in bits

  generator.Init(PasswordBytes, SaltBytes, iteration_count);

  if (not AreEqual((generator.GenerateDerivedMacParameters(dkLen)
    as IKeyParameter).GetKey(),
    DecodeHex('0C60C80F961F0E71F3A9B524AF6012062FE037A6'))) then
  begin
    Fail(Format
      ('PBKDF2 HMAC-SHA1 with iteration count "%u", %u bits key generation test failed',
      [iteration_count, dkLen]));
  end;

  generator.Clear();

  // 2

  iteration_count := 2;

  dkLen := 20 * 8; // multiplied by 8 to get it in bits

  generator.Init(PasswordBytes, SaltBytes, iteration_count);

  if (not AreEqual((generator.GenerateDerivedMacParameters(dkLen)
    as IKeyParameter).GetKey(),
    DecodeHex('EA6C014DC72D6F8CCD1ED92ACE1D41F0D8DE8957'))) then
  begin
    Fail(Format
      ('PBKDF2 HMAC-SHA1 with iteration count "%u", %u bits key generation test failed',
      [iteration_count, dkLen]));
  end;

  generator.Clear();


  // 3

  iteration_count := 4096;

  dkLen := 20 * 8; // multiplied by 8 to get it in bits

  generator.Init(PasswordBytes, SaltBytes, iteration_count);

  if (not AreEqual((generator.GenerateDerivedMacParameters(dkLen)
    as IKeyParameter).GetKey(),
    DecodeHex('4B007901B765489ABEAD49D926F721D065A429C1'))) then
  begin
    Fail(Format
      ('PBKDF2 HMAC-SHA1 with iteration count "%u", %u bits key generation test failed',
      [iteration_count, dkLen]));
  end;

  generator.Clear();

  // 4
  // commented out because iteration_count is very large
  // iteration_count := 16777216;
  //
  // dkLen := 20 * 8; // multiplied by 8 to get it in bits
  //
  // generator.Init(PasswordBytes, SaltBytes, iteration_count);
  //
  // if (not AreEqual((generator.GenerateDerivedMacParameters(dkLen)
  // as IKeyParameter).GetKey(),
  // DecodeHex('EEFE3D61CD4DA4E4E9945B3D6BA2158C2634E984'))) then
  // begin
  // Fail(Format
  // ('PBKDF2 HMAC-SHA1 with iteration count "%u", %u bits key generation test failed',
  // [iteration_count, dkLen]));
  // end;
  //
  // generator.Clear();


  // 5

  PasswordString := 'passwordPASSWORDpassword';
  PasswordBytes := TConverters.ConvertStringToBytes(PasswordString,
    TEncoding.UTF8);

  SaltString := 'saltSALTsaltSALTsaltSALTsaltSALTsalt';
  SaltBytes := TConverters.ConvertStringToBytes(SaltString, TEncoding.UTF8);

  iteration_count := 4096;

  dkLen := 25 * 8; // multiplied by 8 to get it in bits

  generator.Init(PasswordBytes, SaltBytes, iteration_count);

  if (not AreEqual((generator.GenerateDerivedMacParameters(dkLen)
    as IKeyParameter).GetKey(),
    DecodeHex('3D2EEC4FE41C849B80C8D83662C0E44A8B291A964CF2F07038'))) then
  begin
    Fail(Format
      ('PBKDF2 HMAC-SHA1 with iteration count "%u", %u bits key generation test failed',
      [iteration_count, dkLen]));
  end;

  generator.Clear();


  // 6

  PasswordString := 'pass' + Char(0) + 'word';
  // Char(0) represents #0 (null char)
  PasswordBytes := TConverters.ConvertStringToBytes(PasswordString,
    TEncoding.UTF8);

  SaltString := 'sa' + Char(0) + 'lt'; // Char(0) represents #0 (null char)
  SaltBytes := TConverters.ConvertStringToBytes(SaltString, TEncoding.UTF8);

  iteration_count := 4096;

  dkLen := 16 * 8; // multiplied by 8 to get it in bits

  generator.Init(PasswordBytes, SaltBytes, iteration_count);

  if (not AreEqual((generator.GenerateDerivedMacParameters(dkLen)
    as IKeyParameter).GetKey(), DecodeHex('56FA6AA75548099DCC37D7F03425E0C3')))
  then
  begin
    Fail(Format
      ('PBKDF2 HMAC-SHA1 with iteration count "%u", %u bits key generation test failed',
      [iteration_count, dkLen]));
  end;

  generator.Clear();

end;

procedure TTestPkcs5.TestPkcs5_WITH_SHA256;
var
  PasswordString, SaltString: String;
  PasswordBytes, SaltBytes: TBytes;
  generator: IPkcs5S2ParametersGenerator;
  iteration_count, dkLen: Int32;
begin

  // https://github.com/ircmaxell/quality-checker/blob/master/tmp/gh_18/PHP-PasswordLib-master/test/Data/Vectors/pbkdf2-draft-josefsson-sha256.test-vectors

  generator := TPkcs5S2ParametersGenerator.Create
    (TDigestUtilities.GetDigest('SHA-256'));

  PasswordString := 'password';
  PasswordBytes := TConverters.ConvertStringToBytes(PasswordString,
    TEncoding.UTF8);

  SaltString := 'salt';
  SaltBytes := TConverters.ConvertStringToBytes(SaltString, TEncoding.UTF8);

  // 1

  iteration_count := 1;

  dkLen := 32 * 8; // multiplied by 8 to get it in bits

  generator.Init(PasswordBytes, SaltBytes, iteration_count);

  if (not AreEqual((generator.GenerateDerivedMacParameters(dkLen)
    as IKeyParameter).GetKey(),
    DecodeHex(
    '120FB6CFFCF8B32C43E7225256C4F837A86548C92CCC35480805987CB70BE17B'))) then
  begin
    Fail(Format
      ('PBKDF2 HMAC-SHA256 with iteration count "%u", %u bits key generation test failed',
      [iteration_count, dkLen]));
  end;

  generator.Clear();

  // 2

  iteration_count := 2;

  dkLen := 32 * 8; // multiplied by 8 to get it in bits

  generator.Init(PasswordBytes, SaltBytes, iteration_count);

  if (not AreEqual((generator.GenerateDerivedMacParameters(dkLen)
    as IKeyParameter).GetKey(),
    DecodeHex(
    'AE4D0C95AF6B46D32D0ADFF928F06DD02A303F8EF3C251DFD6E2D85A95474C43'))) then
  begin
    Fail(Format
      ('PBKDF2 HMAC-SHA256 with iteration count "%u", %u bits key generation test failed',
      [iteration_count, dkLen]));
  end;

  generator.Clear();

  // 3

  iteration_count := 4096;

  dkLen := 32 * 8; // multiplied by 8 to get it in bits

  generator.Init(PasswordBytes, SaltBytes, iteration_count);

  if (not AreEqual((generator.GenerateDerivedMacParameters(dkLen)
    as IKeyParameter).GetKey(),
    DecodeHex(
    'C5E478D59288C841AA530DB6845C4C8D962893A001CE4E11A4963873AA98134A'))) then
  begin
    Fail(Format
      ('PBKDF2 HMAC-SHA256 with iteration count "%u", %u bits key generation test failed',
      [iteration_count, dkLen]));
  end;

  generator.Clear();

  // 4
  // commented out because iteration_count is very large
  // iteration_count := 16777216;
  //
  // dkLen := 32 * 8; // multiplied by 8 to get it in bits
  //
  // generator.Init(PasswordBytes, SaltBytes, iteration_count);
  //
  // if (not AreEqual((generator.GenerateDerivedMacParameters(dkLen)
  // as IKeyParameter).GetKey(),
  // DecodeHex
  // ('CF81C66FE8CFC04D1F31ECB65DAB4089F7F179E89B3B0BCB17AD10E3AC6EBA46'))) then
  // begin
  // Fail(Format
  // ('PBKDF2 HMAC-SHA256 with iteration count "%u", %u bits key generation test failed',
  // [iteration_count, dkLen]));
  // end;
  //
  // generator.Clear();

  // 5

  PasswordString := 'passwordPASSWORDpassword';
  PasswordBytes := TConverters.ConvertStringToBytes(PasswordString,
    TEncoding.UTF8);

  SaltString := 'saltSALTsaltSALTsaltSALTsaltSALTsalt';
  SaltBytes := TConverters.ConvertStringToBytes(SaltString, TEncoding.UTF8);

  iteration_count := 4096;

  dkLen := 40 * 8; // multiplied by 8 to get it in bits

  generator.Init(PasswordBytes, SaltBytes, iteration_count);

  if (not AreEqual((generator.GenerateDerivedMacParameters(dkLen)
    as IKeyParameter).GetKey(),
    DecodeHex(
    '348C89DBCBD32B2F32D814B8116E84CF2B17347EBC1800181C4E2A1FB8DD53E1C635518C7DAC47E9'))
    ) then
  begin
    Fail(Format
      ('PBKDF2 HMAC-SHA256 with iteration count "%u", %u bits key generation test failed',
      [iteration_count, dkLen]));
  end;

  generator.Clear();

  // 6

  PasswordString := 'pass' + Char(0) + 'word';
  // Char(0) represents #0 (null char)
  PasswordBytes := TConverters.ConvertStringToBytes(PasswordString,
    TEncoding.UTF8);

  SaltString := 'sa' + Char(0) + 'lt'; // Char(0) represents #0 (null char)
  SaltBytes := TConverters.ConvertStringToBytes(SaltString, TEncoding.UTF8);

  iteration_count := 4096;

  dkLen := 16 * 8; // multiplied by 8 to get it in bits

  generator.Init(PasswordBytes, SaltBytes, iteration_count);

  if (not AreEqual((generator.GenerateDerivedMacParameters(dkLen)
    as IKeyParameter).GetKey(), DecodeHex('89B69D0516F829893C696226650A8687')))
  then
  begin
    Fail(Format
      ('PBKDF2 HMAC-SHA256 with iteration count "%u", %u bits key generation test failed',
      [iteration_count, dkLen]));
  end;

  generator.Clear();

end;

initialization

// Register any test cases with the test runner

{$IFDEF FPC}
  RegisterTest(TTestPkcs5);
{$ELSE}
  RegisterTest(TTestPkcs5.Suite);
{$ENDIF FPC}

end.
