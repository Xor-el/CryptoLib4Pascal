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

unit XChaCha20Tests;

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
  ClpXChaCha20Engine,
  ClpIXChaCha20Engine,
  ClpIStreamCipher,
  ClpKeyParameter,
  ClpIKeyParameter,
  ClpParametersWithIV,
  ClpIParametersWithIV,
  ClpEncoders,
  ClpIBufferedCipher,
  ClpCipherUtilities,
  ClpCryptoLibTypes,
  CryptoLibTestBase;

type
  TTestXChaCha20 = class(TCryptoLibAlgorithmTestCase)
  published
    procedure TestAppendixA2_1KeystreamFirst288;
    procedure TestGetCipherXChaCha20Aliases;
  end;

implementation

{ TTestXChaCha20 }

procedure TTestXChaCha20.TestAppendixA2_1KeystreamFirst288;
var
  LKey, LIv, LZero, LExpectedKs, LOut: TCryptoLibByteArray;
  LEng: IXChaCha20Engine;
  LParams: IParametersWithIV;
begin
  LKey := THexEncoder.Decode(
    '808182838485868788898a8b8c8d8e8f' +
    '909192939495969798999a9b9c9d9e9f');
  LIv := THexEncoder.Decode(
    '404142434445464748494a4b4c4d4e4f5051525354555658');
  LExpectedKs := THexEncoder.Decode(
    '1131ce9a2a20ae0d67c8935c7789fa10' +
    '25c9e5bb720fb96f11354fb97af0bd9a' +
    'adec0863ba60cac8582c48f86cdfc48e' +
    'dd46a48642c5de62ccf11c7b21bf337d' +
    '29624b4b1b140ace53740e405b216854' +
    '0fd7d630c1f536fecd722fc3cddba7f4' +
    'cca98cf9e47e5e64d115450f9b125b54' +
    '449ff76141ca620a1f9cfcab2a1a8a25' +
    '5e766a5266b878846120ea64ad99aa47' +
    '9471e63befcbd37cd1c22a221fe46221' +
    '5cf32c74895bf505863ccddd48f62916' +
    'dc6521f1ec50a5ae08903aa259d9bf60' +
    '7cd8026fba548604f1b6072d91bc9124' +
    '3a5b845f7fd171b02edc5a0a84cf28dd' +
    '241146bc376e3f48df5e7fee1d11048c' +
    '190a3d3deb0feb64b42d9c6fdeee290f' +
    'a0e6ae2c26c0249ea8c181f7e2ffd100' +
    'cbe5fd3c4f8271d62b15330cb8fdcf00');
  System.SetLength(LZero, System.Length(LExpectedKs));
  System.FillChar(LZero[0], System.Length(LZero), 0);
  System.SetLength(LOut, System.Length(LExpectedKs));

  LEng := TXChaCha20Engine.Create;
  LParams := TParametersWithIV.Create(TKeyParameter.Create(LKey) as IKeyParameter,
    LIv);
  LEng.Init(True, LParams);
  LEng.ProcessBytes(LZero, 0, System.Length(LZero), LOut, 0);

  if not AreEqual(LExpectedKs, LOut) then
    Fail(Format('XChaCha20 A.2.1 keystream mismatch: expected %s got %s',
      [EncodeHex(LExpectedKs), EncodeHex(LOut)]));
end;

procedure TTestXChaCha20.TestGetCipherXChaCha20Aliases;
var
  LCipher: IBufferedCipher;
begin
  LCipher := TCipherUtilities.GetCipher('XCHACHA20');
  if LCipher = nil then
    Fail('TCipherUtilities.GetCipher(XCHACHA20) returned nil');
  LCipher := TCipherUtilities.GetCipher('XChaCha20');
  if LCipher = nil then
    Fail('TCipherUtilities.GetCipher(XChaCha20) returned nil');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestXChaCha20);
{$ELSE}
  RegisterTest(TTestXChaCha20.Suite);
{$ENDIF FPC}

end.
