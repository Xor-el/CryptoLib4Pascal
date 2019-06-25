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

unit HkdfGeneratorTests;

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
  ClpIDigest,
  ClpDigestUtilities,
  ClpHkdfParameters,
  ClpIHkdfParameters,
  ClpHkdfBytesGenerator,
  ClpIHkdfBytesGenerator,
  CryptoLibTestBase;

type

  /// <summary>
  /// HKDF tests - vectors from RFC 5869, + 2 more, 101 and 102
  /// </summary>
  TTestHkdfGenerator = class(TCryptoLibAlgorithmTestCase)
  private

    procedure CompareOkm(test: Int32; const calculatedOkm, testOkm: TBytes);
    procedure DoTestHKDF();

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published

    procedure TestHkdfGenerator;

  end;

implementation

{ TTestHkdfGenerator }

procedure TTestHkdfGenerator.CompareOkm(test: Int32;
  const calculatedOkm, testOkm: TBytes);
begin
  if (not AreEqual(calculatedOkm, testOkm)) then
  begin
    Fail('HKDF failed generator test ' + IntToStr(test));
  end;
end;

procedure TTestHkdfGenerator.DoTestHKDF;
var
  hash: IDigest;
  ikm, salt, info, okm: TBytes;
  l, zeros, i: Int32;
  parameters: IHkdfParameters;
  hkdf: IHkdfBytesGenerator;
begin
  // === A.1. Test Case 1 - Basic test case with SHA-256 ===

  hash := TDigestUtilities.GetDigest('SHA-256');
  ikm := DecodeHex('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b');
  salt := DecodeHex('000102030405060708090a0b0c');
  info := DecodeHex('f0f1f2f3f4f5f6f7f8f9');
  l := 42;
  System.SetLength(okm, l);

  parameters := THkdfParameters.Create(ikm, salt, info);

  hkdf := THkdfBytesGenerator.Create(hash);
  hkdf.Init(parameters);
  hkdf.GenerateBytes(okm, 0, l);

  CompareOkm(1, okm, DecodeHex('3cb25f25faacd57a90434f64d0362f2a' +
    '2d2d0a90cf1a5a4c5db02d56ecc4c5bf' + '34007208d5b887185865'));


  // === A.2. Test Case 2 - Test with SHA-256 and longer inputs/outputs
  // ===

  hash := TDigestUtilities.GetDigest('SHA-256');
  ikm := DecodeHex('000102030405060708090a0b0c0d0e0f' +
    '101112131415161718191a1b1c1d1e1f' + '202122232425262728292a2b2c2d2e2f' +
    '303132333435363738393a3b3c3d3e3f' + '404142434445464748494a4b4c4d4e4f');
  salt := DecodeHex('606162636465666768696a6b6c6d6e6f' +
    '707172737475767778797a7b7c7d7e7f' + '808182838485868788898a8b8c8d8e8f' +
    '909192939495969798999a9b9c9d9e9f' + 'a0a1a2a3a4a5a6a7a8a9aaabacadaeaf');
  info := DecodeHex('b0b1b2b3b4b5b6b7b8b9babbbcbdbebf' +
    'c0c1c2c3c4c5c6c7c8c9cacbcccdcecf' + 'd0d1d2d3d4d5d6d7d8d9dadbdcdddedf' +
    'e0e1e2e3e4e5e6e7e8e9eaebecedeeef' + 'f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff');
  l := 82;
  System.SetLength(okm, l);

  parameters := THkdfParameters.Create(ikm, salt, info);

  hkdf := THkdfBytesGenerator.Create(hash);
  hkdf.Init(parameters);
  hkdf.GenerateBytes(okm, 0, l);

  CompareOkm(2, okm, DecodeHex('b11e398dc80327a1c8e7f78c596a4934' +
    '4f012eda2d4efad8a050cc4c19afa97c' + '59045a99cac7827271cb41c65e590e09' +
    'da3275600c2f09b8367793a9aca3db71' + 'cc30c58179ec3e87c14c01d5c1f3434f'
    + '1d87'));



  // === A.3. Test Case 3 - Test with SHA-256 and zero-length
  // salt/info ===

  // setting salt to an empty byte array means that the salt is set to
  // HashLen zero valued bytes
  // setting info to Nil generates an empty byte array as info
  // structure

  hash := TDigestUtilities.GetDigest('SHA-256');
  ikm := DecodeHex('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b');
  System.SetLength(salt, 0);
  info := Nil;
  l := 42;
  System.SetLength(okm, l);

  parameters := THkdfParameters.Create(ikm, salt, info);

  hkdf := THkdfBytesGenerator.Create(hash);
  hkdf.Init(parameters);
  hkdf.GenerateBytes(okm, 0, l);

  CompareOkm(3, okm, DecodeHex('8da4e775a563c18f715f802a063c5a31' +
    'b8a11f5c5ee1879ec3454e5f3c738d2d' + '9d201395faa4b61a96c8'));



  // === A.4. Test Case 4 - Basic test case with SHA-1 ===

  hash := TDigestUtilities.GetDigest('SHA-1');
  ikm := DecodeHex('0b0b0b0b0b0b0b0b0b0b0b');
  salt := DecodeHex('000102030405060708090a0b0c');
  info := DecodeHex('f0f1f2f3f4f5f6f7f8f9');
  l := 42;
  System.SetLength(okm, l);

  parameters := THkdfParameters.Create(ikm, salt, info);

  hkdf := THkdfBytesGenerator.Create(hash);
  hkdf.Init(parameters);
  hkdf.GenerateBytes(okm, 0, l);

  CompareOkm(4, okm, DecodeHex('085a01ea1b10f36933068b56efa5ad81' +
    'a4f14b822f5b091568a9cdd4f155fda2' + 'c22e422478d305f3f896'));


  // === A.5. Test Case 5 - Test with SHA-1 and longer inputs/outputs ===

  hash := TDigestUtilities.GetDigest('SHA-1');
  ikm := DecodeHex('000102030405060708090a0b0c0d0e0f' +
    '101112131415161718191a1b1c1d1e1f' + '202122232425262728292a2b2c2d2e2f' +
    '303132333435363738393a3b3c3d3e3f' + '404142434445464748494a4b4c4d4e4f');
  salt := DecodeHex('606162636465666768696a6b6c6d6e6f' +
    '707172737475767778797a7b7c7d7e7f' + '808182838485868788898a8b8c8d8e8f' +
    '909192939495969798999a9b9c9d9e9f' + 'a0a1a2a3a4a5a6a7a8a9aaabacadaeaf');
  info := DecodeHex('b0b1b2b3b4b5b6b7b8b9babbbcbdbebf' +
    'c0c1c2c3c4c5c6c7c8c9cacbcccdcecf' + 'd0d1d2d3d4d5d6d7d8d9dadbdcdddedf' +
    'e0e1e2e3e4e5e6e7e8e9eaebecedeeef' + 'f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff');
  l := 82;
  System.SetLength(okm, l);

  parameters := THkdfParameters.Create(ikm, salt, info);

  hkdf := THkdfBytesGenerator.Create(hash);
  hkdf.Init(parameters);
  hkdf.GenerateBytes(okm, 0, l);

  CompareOkm(5, okm, DecodeHex('0bd770a74d1160f7c9f12cd5912a06eb' +
    'ff6adcae899d92191fe4305673ba2ffe' + '8fa3f1a4e5ad79f3f334b3b202b2173c' +
    '486ea37ce3d397ed034c7f9dfeb15c5e' + '927336d0441f4c4300e2cff0d0900b52'
    + 'd3b4'));



  // === A.6. Test Case 6 - Test with SHA-1 and zero-length salt/info
  // ===

  // setting salt to Nil should generate a new salt of HashLen zero
  // valued bytes

  hash := TDigestUtilities.GetDigest('SHA-1');
  ikm := DecodeHex('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b');
  salt := Nil;
  System.SetLength(info, 0);
  l := 42;
  System.SetLength(okm, l);

  parameters := THkdfParameters.Create(ikm, salt, info);

  hkdf := THkdfBytesGenerator.Create(hash);
  hkdf.Init(parameters);
  hkdf.GenerateBytes(okm, 0, l);

  CompareOkm(6, okm, DecodeHex('0ac1af7002b3d761d1e55298da9d0506' +
    'b9ae52057220a306e07b6b87e8df21d0' + 'ea00033de03984d34918'));



  // === A.7. Test Case 7 - Test with SHA-1, salt not provided,
  // zero-length info ===
  // (salt defaults to HashLen zero octets)

  // this test is identical to test 6 in all ways bar the IKM value

  hash := TDigestUtilities.GetDigest('SHA-1');
  ikm := DecodeHex('0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c');
  salt := Nil;
  System.SetLength(info, 0);
  l := 42;
  System.SetLength(okm, l);

  parameters := THkdfParameters.Create(ikm, salt, info);

  hkdf := THkdfBytesGenerator.Create(hash);
  hkdf.Init(parameters);
  hkdf.GenerateBytes(okm, 0, l);

  CompareOkm(7, okm, DecodeHex('2c91117204d745f3500d636a62f64f0a' +
    'b3bae548aa53d423b0d1f27ebba6f5e5' + '673a081d70cce7acfc48'));



  // === A.101. Additional Test Case - Test with SHA-1, skipping extract
  // zero-length info ===
  // (salt defaults to HashLen zero octets)

  // this test is identical to test 7 in all ways bar the IKM value
  // which is set to the PRK value

  hash := TDigestUtilities.GetDigest('SHA-1');
  ikm := DecodeHex('2adccada18779e7c2077ad2eb19d3f3e731385dd');
  System.SetLength(info, 0);
  l := 42;
  System.SetLength(okm, l);

  parameters := THkdfParameters.SkipExtractParameters(ikm, info);

  hkdf := THkdfBytesGenerator.Create(hash);
  hkdf.Init(parameters);
  hkdf.GenerateBytes(okm, 0, l);

  CompareOkm(101, okm, DecodeHex('2c91117204d745f3500d636a62f64f0a' +
    'b3bae548aa53d423b0d1f27ebba6f5e5' + '673a081d70cce7acfc48'));

  // === A.102. Additional Test Case - Test with SHA-1, maximum output ===
  // (salt defaults to HashLen zero octets)

  // this test is identical to test 7 in all ways bar the IKM value

  hash := TDigestUtilities.GetDigest('SHA-1');
  ikm := DecodeHex('2adccada18779e7c2077ad2eb19d3f3e731385dd');
  System.SetLength(info, 0);
  l := 255 * hash.GetDigestSize();
  System.SetLength(okm, l);

  parameters := THkdfParameters.SkipExtractParameters(ikm, info);

  hkdf := THkdfBytesGenerator.Create(hash);
  hkdf.Init(parameters);
  hkdf.GenerateBytes(okm, 0, l);

  zeros := 0;
  for i := 0 to System.Pred(hash.GetDigestSize()) do
  begin
    if (okm[i] = 0) then
    begin
      System.Inc(zeros);
    end;
  end;

  if (zeros = hash.GetDigestSize()) then
  begin
    Fail('HKDF failed generator test ' + IntToStr(102));
  end;

end;

procedure TTestHkdfGenerator.SetUp;
begin
  inherited;

end;

procedure TTestHkdfGenerator.TearDown;
begin
  inherited;

end;

procedure TTestHkdfGenerator.TestHkdfGenerator;
begin
  DoTestHKDF();
end;

initialization

// Register any test cases with the test runner

{$IFDEF FPC}
  RegisterTest(TTestHkdfGenerator);
{$ELSE}
  RegisterTest(TTestHkdfGenerator.Suite);
{$ENDIF FPC}

end.
