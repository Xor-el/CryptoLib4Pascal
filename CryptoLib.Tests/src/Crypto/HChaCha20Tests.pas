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

unit HChaCha20Tests;

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
  ClpChaChaEngine,
  ClpEncoders,
  ClpCryptoLibTypes,
  CryptoLibTestBase;

type
  TTestHChaCha20 = class(TCryptoLibAlgorithmTestCase)
  published
    procedure TestDraftBlockVector;
  end;

implementation

{ TTestHChaCha20 }

procedure TTestHChaCha20.TestDraftBlockVector;
var
  LKey, LNonce, LExpected, LOut: TCryptoLibByteArray;
begin
  LKey := THexEncoder.Decode(
    '000102030405060708090a0b0c0d0e0f' +
    '101112131415161718191a1b1c1d1e1f');
  LNonce := THexEncoder.Decode(
    '000000090000004a0000000031415927');
  LExpected := THexEncoder.Decode(
    '82413b4227b27bfed30e42508a877d73' +
    'a0f9e4d58a74a853c12ec41326d3ecdc');
  System.SetLength(LOut, 32);
  TChaChaEngine.HChaCha20(LKey, LNonce, LOut, 0);
  if not AreEqual(LExpected, LOut) then
    Fail(Format('HChaCha20 subkey mismatch: expected %s got %s',
      [EncodeHex(LExpected), EncodeHex(LOut)]));
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestHChaCha20);
{$ELSE}
  RegisterTest(TTestHChaCha20.Suite);
{$ENDIF FPC}

end.
