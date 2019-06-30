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

unit SHA224HMacTests;

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
  /// SHA224 HMac Test, test vectors from RFC 2202
  /// </summary>
  TTestSHA224HMac = class(TCryptoLibAlgorithmTestCase)
  private
  var
    Fkeys, Fdigests, Fmessages: TCryptoLibStringArray;
  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published

    procedure TestSHA224HMac;

  end;

implementation

{ TTestSHA224HMac }

procedure TTestSHA224HMac.SetUp;
begin
  inherited;
  Fkeys := TCryptoLibStringArray.Create
    ('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b', '4a656665',
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    '0102030405060708090a0b0c0d0e0f10111213141516171819',
    '0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c',
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
    + 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
    + 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');

  Fdigests := TCryptoLibStringArray.Create
    ('896fb1128abbdf196832107cd49df33f47b4b1169912ba4f53684b22',
    'a30e01098bc6dbbf45690f3a7e9e6d0f8bbea2a39e6148008fd05e44',
    '7fb3cb3588c6c1f6ffa9694d7d6ad2649365b0c1f65d69d1ec8333ea',
    '6c11506874013cac6a2abc1bb382627cec6a90d86efc012de7afec5a',
    '0e2aea68a90c8d37c988bcdb9fca6fa8099cd857c7ec4a1815cac54c',
    '95e9a0db962095adaebe9b2d6f0dbce2d499f112f2d2b7273fa6870e',
    '3a854166ac5d9f023f54d517d0b39dbd946770db9c2b95c9f6f565d1');

  Fmessages := TCryptoLibStringArray.Create('Hi There',
    'what do ya want for nothing?',
    '0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd',
    '0xcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd',
    'Test With Truncation',
    'Test Using Larger Than Block-Size Key - Hash Key First',
    'This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.');
end;

procedure TTestSHA224HMac.TearDown;
begin
  inherited;

end;

procedure TTestSHA224HMac.TestSHA224HMac;
var
  hmac: IMac;
  resBuf, m, m2: TBytes;
  i, vector: Int32;
begin
  hmac := THMac.Create(TDigestUtilities.GetDigest('SHA-224'));
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
  RegisterTest(TTestSHA224HMac);
{$ELSE}
  RegisterTest(TTestSHA224HMac.Suite);
{$ENDIF FPC}

end.
