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

unit XChaCha20Poly1305Tests;

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
  ClpIXChaCha20Poly1305,
  ClpXChaCha20Poly1305,
  ClpICipherParameters,
  ClpAeadParameters,
  ClpIAeadParameters,
  ClpKeyParameter,
  ClpIKeyParameter,
  ClpEncoders,
  ClpIBufferedCipher,
  ClpCipherUtilities,
  ClpCryptoLibTypes,
  CryptoLibTestBase;

type
  TTestXChaCha20Poly1305 = class(TCryptoLibAlgorithmTestCase)
  strict private
    procedure CheckEqual(const AName: string; const AExpected, AActual: TBytes);
    function InitCipher(AForEncryption: Boolean;
      const AParams: IAeadParameters): IXChaCha20Poly1305;
  published
    procedure TestAppendixA1;
    procedure TestGetCipherRegistry;
  end;

implementation

{ TTestXChaCha20Poly1305 }

procedure TTestXChaCha20Poly1305.CheckEqual(const AName: string;
  const AExpected, AActual: TBytes);
begin
  if not AreEqual(AExpected, AActual) then
    Fail(Format('%s Failed - expected %s got %s',
      [AName, EncodeHex(AExpected), EncodeHex(AActual)]));
end;

function TTestXChaCha20Poly1305.InitCipher(AForEncryption: Boolean;
  const AParams: IAeadParameters): IXChaCha20Poly1305;
var
  LCipher: IXChaCha20Poly1305;
begin
  LCipher := TXChaCha20Poly1305.Create;
  LCipher.Init(AForEncryption, AParams as ICipherParameters);
  Result := LCipher;
end;

procedure TTestXChaCha20Poly1305.TestAppendixA1;
var
  LK, LP, LA, LN, LC, LT, LEnc, LMac, LPlain: TBytes;
  LParams: IAeadParameters;
  LEncCipher, LDecCipher: IXChaCha20Poly1305;
  LLen: Int32;
begin
  LK := THexEncoder.Decode(
    '808182838485868788898a8b8c8d8e8f' +
    '909192939495969798999a9b9c9d9e9f');
  LP := THexEncoder.Decode(
    '4c616469657320616e642047656e746c' +
    '656d656e206f662074686520636c6173' +
    '73206f66202739393a20496620492063' +
    '6f756c64206f6666657220796f75206f' +
    '6e6c79206f6e652074697020666f7220' +
    '746865206675747572652c2073756e73' +
    '637265656e20776f756c642062652069' +
    '742e');
  LA := THexEncoder.Decode('50515253c0c1c2c3c4c5c6c7');
  LN := THexEncoder.Decode(
    '404142434445464748494a4b4c4d4e4f5051525354555657');
  LC := THexEncoder.Decode(
    'bd6d179d3e83d43b9576579493c0e939' +
    '572a1700252bfaccbed2902c21396cbb' +
    '731c7f1b0b4aa6440bf3a82f4eda7e39' +
    'ae64c6708c54c216cb96b72e1213b452' +
    '2f8c9ba40db5d945b11b69b982c1bb9e' +
    '3f3fac2bc369488f76b2383565d3fff9' +
    '21f9664c97637da9768812f615c68b13' +
    'b52e');
  LT := THexEncoder.Decode('c0875924c1c7987947deafd8780acf49');

  LParams := TAeadParameters.Create(TKeyParameter.Create(LK) as IKeyParameter,
    System.Length(LT) * 8, LN, LA);

  LEncCipher := InitCipher(True, LParams);
  System.SetLength(LEnc, LEncCipher.GetOutputSize(System.Length(LP)));
  LLen := LEncCipher.ProcessBytes(LP, 0, System.Length(LP), LEnc, 0);
  LEncCipher.DoFinal(LEnc, LLen);

  CheckEqual('XChaCha20Poly1305 A.1 ciphertext', LC,
    CopyOfRange(LEnc, 0, System.Length(LC)));
  LMac := LEncCipher.GetMac;
  CheckEqual('XChaCha20Poly1305 A.1 tag', LT, LMac);

  LDecCipher := InitCipher(False, LParams);
  System.SetLength(LPlain, LDecCipher.GetOutputSize(System.Length(LEnc)));
  LLen := LDecCipher.ProcessBytes(LEnc, 0, System.Length(LEnc), LPlain, 0);
  LDecCipher.DoFinal(LPlain, LLen);
  CheckEqual('XChaCha20Poly1305 A.1 roundtrip plaintext', LP,
    CopyOfRange(LPlain, 0, System.Length(LP)));
end;

procedure TTestXChaCha20Poly1305.TestGetCipherRegistry;
var
  LCipher: IBufferedCipher;
begin
  LCipher := TCipherUtilities.GetCipher('XCHACHA20-POLY1305');
  if LCipher = nil then
    Fail('GetCipher(XCHACHA20-POLY1305) nil');
  LCipher := TCipherUtilities.GetCipher('XChaCha20-Poly1305');
  if LCipher = nil then
    Fail('GetCipher(XChaCha20-Poly1305) nil');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestXChaCha20Poly1305);
{$ELSE}
  RegisterTest(TTestXChaCha20Poly1305.Suite);
{$ENDIF FPC}

end.
