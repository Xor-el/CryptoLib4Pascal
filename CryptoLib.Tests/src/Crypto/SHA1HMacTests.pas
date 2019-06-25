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

unit SHA1HMacTests;

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
  /// SHA1 HMac Test, test vectors from RFC 2202
  /// </summary>
  TTestSHA1HMac = class(TCryptoLibAlgorithmTestCase)
  private
  var
    Fkeys, Fdigests, Fmessages: TCryptoLibStringArray;
  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published

    procedure TestSHA1HMac;

  end;

implementation

{ TTestSHA1HMac }

procedure TTestSHA1HMac.SetUp;
begin
  inherited;
  Fkeys := TCryptoLibStringArray.Create
    ('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b', '4a656665',
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    '0102030405060708090a0b0c0d0e0f10111213141516171819',
    '0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c',
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');
  Fdigests := TCryptoLibStringArray.Create
    ('b617318655057264e28bc0b6fb378c8ef146be00',
    'effcdf6ae5eb2fa2d27416d5f184df9c259a7c79',
    '125d7342b9ac11cd91a39af48aa17b4f63f175d3',
    '4c9007f4026250c6bc8414f9bf50c86c2d7235da',
    '4c1a03424b55e07fe7f27be1d58bb9324a9a5a04',
    'aa4ae5e15272d00e95705637ce8a3b55ed402112',
    'e8e99d0f45237d786d6bbaa7965c7808bbff1a91',
    '4c1a03424b55e07fe7f27be1d58bb9324a9a5a04',
    'aa4ae5e15272d00e95705637ce8a3b55ed402112',
    'e8e99d0f45237d786d6bbaa7965c7808bbff1a91');
  Fmessages := TCryptoLibStringArray.Create('Hi There',
    'what do ya want for nothing?',
    '0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd',
    '0xcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd',
    'Test With Truncation',
    'Test Using Larger Than Block-Size Key - Hash Key First',
    'Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data');
end;

procedure TTestSHA1HMac.TearDown;
begin
  inherited;

end;

procedure TTestSHA1HMac.TestSHA1HMac;
var
  hmac: IMac;
  resBuf, m, m2: TBytes;
  i, vector: Int32;
begin
  hmac := THMac.Create(TDigestUtilities.GetDigest('SHA-1'));
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
  RegisterTest(TTestSHA1HMac);
{$ELSE}
  RegisterTest(TTestSHA1HMac.Suite);
{$ENDIF FPC}

end.
