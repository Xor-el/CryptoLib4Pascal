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

unit SHA384HMacTests;

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
  ClpKeyParameter,
  ClpHMac,
  ClpIMac,
  ClpDigestUtilities,
  ClpStringUtils,
  ClpConverters,
  ClpCryptoLibTypes,
  CryptoLibTestBase;

type

  /// <summary>
  /// SHA384 HMac Test, test vectors from RFC 2202
  /// </summary>
  TTestSHA384HMac = class(TCryptoLibAlgorithmTestCase)
  private
  var
    Fkeys, Fdigests, Fmessages: TCryptoLibStringArray;
  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published

    procedure TestSHA384HMac;

  end;

implementation

{ TTestSHA384HMac }

procedure TTestSHA384HMac.SetUp;
begin
  inherited;
  Fkeys := TCryptoLibStringArray.Create
    ('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b', '4a656665',
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    '0102030405060708090a0b0c0d0e0f10111213141516171819',
    '0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c',
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
    + 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
    + 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');

  Fdigests := TCryptoLibStringArray.Create
    ('afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6',
    'af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649',
    '88062608d3e6ad8a0aa2ace014c8a86f0aa635d947ac9febe83ef4e55966144b2a5ab39dc13814b94e3ab6e101a34f27',
    '3e8a69b7783c25851933ab6290af6ca77a9981480850009cc5577c6e1f573b4e6801dd23c4a7d679ccf8a386c674cffb',
    '3abf34c3503b2a23a46efc619baef897f4c8e42c934ce55ccbae9740fcbc1af4ca62269e2a37cd88ba926341efe4aeea',
    '4ece084485813e9088d2c63a041bc5b44f9ef1012a2b588f3cd11f05033ac4c60c2ef6ab4030fe8296248df163f44952',
    '6617178e941f020d351e2f254e8fd32c602420feb0b8fb9adccebb82461e99c5a678cc31e799176d3860e6110c46523e');

  Fmessages := TCryptoLibStringArray.Create('Hi There',
    'what do ya want for nothing?',
    '0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd',
    '0xcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd',
    'Test With Truncation',
    'Test Using Larger Than Block-Size Key - Hash Key First',
    'This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.');
end;

procedure TTestSHA384HMac.TearDown;
begin
  inherited;

end;

procedure TTestSHA384HMac.TestSHA384HMac;
var
  hmac: IMac;
  resBuf, m, m2: TBytes;
  i, vector: Int32;
begin
  hmac := THMac.Create(TDigestUtilities.GetDigest('SHA-384'));
  System.SetLength(resBuf, hmac.GetMacSize());

  for i := 0 to System.Pred(System.Length(Fmessages)) do
  begin
    m := TConverters.ConvertStringToBytes(Fmessages[i], TEncoding.ASCII);
    if (TStringUtils.BeginsWith(Fmessages[i], '0x', True)) then
    begin
      m := DecodeHex(System.Copy(Fmessages[i], 3,
        System.Length(Fmessages[i]) - 2));
    end;
    hmac.Init(TKeyParameter.Create(DecodeHex(Fkeys[i])));
    hmac.BlockUpdate(m, 0, System.Length(m));
    hmac.DoFinal(resBuf, 0);

    if (not AreEqual(resBuf, DecodeHex(Fdigests[i]))) then
    begin
      Fail('Vector ' + IntToStr(i) + ' failed');
    end;
  end;

  // test reset
  vector := 0; // vector used for test
  m2 := TConverters.ConvertStringToBytes(Fmessages[vector], TEncoding.ASCII);

  if (TStringUtils.BeginsWith(Fmessages[vector], '0x', True)) then
  begin
    m2 := DecodeHex(System.Copy(Fmessages[vector], 3,
      System.Length(Fmessages[vector]) - 2));
  end;

  hmac.Init(TKeyParameter.Create(DecodeHex(Fkeys[vector])));
  hmac.BlockUpdate(m2, 0, System.Length(m2));
  hmac.DoFinal(resBuf, 0);
  hmac.Reset();
  hmac.BlockUpdate(m2, 0, System.Length(m2));
  hmac.DoFinal(resBuf, 0);

  if (not AreEqual(resBuf, DecodeHex(Fdigests[vector]))) then
  begin
    Fail('Reset with vector ' + IntToStr(vector) + ' failed');
  end;

end;

initialization

// Register any test cases with the test runner

{$IFDEF FPC}
  RegisterTest(TTestSHA384HMac);
{$ELSE}
  RegisterTest(TTestSHA384HMac.Suite);
{$ENDIF FPC}

end.
