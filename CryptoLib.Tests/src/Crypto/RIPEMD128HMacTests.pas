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

unit RIPEMD128HMacTests;

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
  /// RIPEMD128 HMac Test, test vectors from RFC 2202
  /// </summary>
  TTestRIPEMD128HMac = class(TCryptoLibAlgorithmTestCase)
  private
  var
    Fkeys, Fdigests, Fmessages: TCryptoLibStringArray;
  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published

    procedure TestRIPEMD128HMac;

  end;

implementation

{ TTestRIPEMD128HMac }

procedure TTestRIPEMD128HMac.SetUp;
begin
  inherited;
  Fkeys := TCryptoLibStringArray.Create('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b',
    '4a656665', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    '0102030405060708090a0b0c0d0e0f10111213141516171819',
    '0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c',
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');

  Fdigests := TCryptoLibStringArray.Create('fbf61f9492aa4bbf81c172e84e0734db',
    '875f828862b6b334b427c55f9f7ff09b', '09f0b2846d2f543da363cbec8d62a38d',
    'bdbbd7cf03e44b5aa60af815be4d2294', 'e79808f24b25fd031c155f0d551d9a3a',
    'dc732928de98104a1f59d373c150acbb', '5c6bec96793e16d40690c237635f30c5');

  Fmessages := TCryptoLibStringArray.Create('Hi There',
    'what do ya want for nothing?',
    '0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd',
    '0xcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd',
    'Test With Truncation',
    'Test Using Larger Than Block-Size Key - Hash Key First',
    'Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data');
end;

procedure TTestRIPEMD128HMac.TearDown;
begin
  inherited;

end;

procedure TTestRIPEMD128HMac.TestRIPEMD128HMac;
var
  hmac: IMac;
  resBuf, m, m2: TBytes;
  i, vector: Int32;
begin
  hmac := THMac.Create(TDigestUtilities.GetDigest('RIPEMD128'));
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
  RegisterTest(TTestRIPEMD128HMac);
{$ELSE}
  RegisterTest(TTestRIPEMD128HMac.Suite);
{$ENDIF FPC}

end.
