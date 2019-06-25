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

unit SHA512HMacTests;

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
  /// SHA512 HMac Test, test vectors from RFC 2202
  /// </summary>
  TTestSHA512HMac = class(TCryptoLibAlgorithmTestCase)
  private
  var
    Fkeys, Fdigests, Fmessages: TCryptoLibStringArray;
  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published

    procedure TestSHA512HMac;

  end;

implementation

{ TTestSHA512HMac }

procedure TTestSHA512HMac.SetUp;
begin
  inherited;
  Fkeys := TCryptoLibStringArray.Create
    ('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b', '4a656665',
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    '0102030405060708090a0b0c0d0e0f10111213141516171819',
    '0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c',
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
    + 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
    + 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');

  Fdigests := TCryptoLibStringArray.Create
    ('87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854',
    '164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737',
    'fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb',
    'b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3dba91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd',
    '415fad6271580a531d4179bc891d87a650188707922a4fbb36663a1eb16da008711c5b50ddd0fc235084eb9d3364a1454fb2ef67cd1d29fe6773068ea266e96b',
    '80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f3526b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598',
    'e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc944b6022cac3c4982b10d5eeb55c3e4de15134676fb6de0446065c97440fa8c6a58');

  Fmessages := TCryptoLibStringArray.Create('Hi There',
    'what do ya want for nothing?',
    '0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd',
    '0xcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd',
    'Test With Truncation',
    'Test Using Larger Than Block-Size Key - Hash Key First',
    'This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.');
end;

procedure TTestSHA512HMac.TearDown;
begin
  inherited;

end;

procedure TTestSHA512HMac.TestSHA512HMac;
var
  hmac: IMac;
  resBuf, m, m2: TBytes;
  i, vector: Int32;
begin
  hmac := THMac.Create(TDigestUtilities.GetDigest('SHA-512'));
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
  RegisterTest(TTestSHA512HMac);
{$ELSE}
  RegisterTest(TTestSHA512HMac.Suite);
{$ENDIF FPC}

end.
