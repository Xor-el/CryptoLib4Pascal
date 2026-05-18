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
  ClpParametersWithIV,
  ClpIParametersWithIV,
  ClpEncoders,
  ClpIBufferedCipher,
  ClpCipherUtilities,
  ClpChaChaEngine,
  ClpChaCha7539Engine,
  ClpArrayUtilities,
  ClpCryptoLibTypes,
  CryptoLibTestBase;

type
  TTestXChaCha20Poly1305 = class(TCryptoLibAlgorithmTestCase)
  strict private
    procedure CheckEqual(const AName: string; const AExpected, AActual: TBytes);
    procedure DeterministicFill(var AState: UInt32;
      const ADest: TCryptoLibByteArray; ALen: Int32); inline;
    function InitCipher(AForEncryption: Boolean;
      const AParams: IAeadParameters): IXChaCha20Poly1305;
  published
    procedure TestAppendixA1;
    procedure TestAppendixA1Poly1305OneTimeKey;
    procedure TestDeterministicRoundTrip2048;
    procedure TestTamperedTagMacFailure;
    procedure TestRejectNonce12Byte;
    procedure TestReuseNonceEncryptionRejected;
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

procedure TTestXChaCha20Poly1305.DeterministicFill(var AState: UInt32;
  const ADest: TCryptoLibByteArray; ALen: Int32);
var
  i: Int32;
begin
  for i := 0 to ALen - 1 do
  begin
    AState := UInt32(UInt64(AState) * 1664525 + 1013904223);
    ADest[i] := Byte(AState shr 16);
  end;
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

procedure TTestXChaCha20Poly1305.TestAppendixA1Poly1305OneTimeKey;
var
  LK, LN, LNoncePrefix, LSubKey, LInnerIv, LZero, LFirstBlock, LExpected: TBytes;
  LE: TChaCha7539Engine;
  LParams: IParametersWithIV;
  LIdx: Int32;
begin
  { draft-irtf-cfrg-xchacha A.3.1 - 32-byte Poly1305 key from first ChaCha block (RFC 8439). }
  LK := THexEncoder.Decode(
    '808182838485868788898a8b8c8d8e8f' +
    '909192939495969798999a9b9c9d9e9f');
  LN := THexEncoder.Decode(
    '404142434445464748494a4b4c4d4e4f5051525354555657');
  LExpected := THexEncoder.Decode(
    '7b191f80f361f099094f6f4b8fb97df847cc6873a8f2b190dd73807183f907d5');

  System.SetLength(LNoncePrefix, 16);
  System.Move(LN[0], LNoncePrefix[0], 16);
  System.SetLength(LSubKey, 32);
  TChaChaEngine.HChaCha20(LK, LNoncePrefix, LSubKey, 0);
  TArrayUtilities.Fill<Byte>(LNoncePrefix, 0, 16, 0);

  System.SetLength(LInnerIv, 12);
  System.FillChar(LInnerIv[0], 4, 0);
  System.Move(LN[16], LInnerIv[4], 8);

  LE := TChaCha7539Engine.Create;
  try
    LParams := TParametersWithIV.Create(TKeyParameter.Create(LSubKey) as IKeyParameter,
      LInnerIv);
    LE.Init(True, LParams);
    System.SetLength(LZero, 64);
    for LIdx := 0 to 63 do
      LZero[LIdx] := 0;
    System.SetLength(LFirstBlock, 64);
    LE.ProcessBytes(LZero, 0, 64, LFirstBlock, 0);
  finally
    LE.Free;
    TArrayUtilities.Fill<Byte>(LSubKey, 0, 32, 0);
    TArrayUtilities.Fill<Byte>(LInnerIv, 0, 12, 0);
  end;

  CheckEqual('XChaCha20Poly1305 A.3.1 Poly1305 one-time key', LExpected,
    CopyOfRange(LFirstBlock, 0, 32));
end;

procedure TTestXChaCha20Poly1305.TestDeterministicRoundTrip2048;
var
  LState: UInt32;
  LK, LN, LA, LP, LCipherStream, LOut, LRecover: TCryptoLibByteArray;
  LParams: IAeadParameters;
  LCipherEnc, LCipherDec: IXChaCha20Poly1305;
  Len: Int32;
begin
  System.SetLength(LK, 32);
  System.SetLength(LN, 24);
  System.SetLength(LA, 33);
  System.SetLength(LP, 2048);
  LState := UInt32($9E3779B9);
  DeterministicFill(LState, LK, System.Length(LK));
  DeterministicFill(LState, LN, System.Length(LN));
  DeterministicFill(LState, LA, System.Length(LA));
  DeterministicFill(LState, LP, System.Length(LP));

  LParams := TAeadParameters.Create(TKeyParameter.Create(LK) as IKeyParameter,
    128, LN, LA);

  LCipherEnc := InitCipher(True, LParams);
  System.SetLength(LCipherStream,
    LCipherEnc.GetOutputSize(System.Length(LP)));
  Len := LCipherEnc.ProcessBytes(LP, 0, System.Length(LP),
    LCipherStream, 0);
  Len := Len + LCipherEnc.DoFinal(LCipherStream, Len);

  LCipherDec := InitCipher(False, LParams);
  System.SetLength(LOut, LCipherDec.GetOutputSize(Len));
  Len := LCipherDec.ProcessBytes(LCipherStream, 0, Len, LOut, 0);
  Len := Len + LCipherDec.DoFinal(LOut, Len);
  SetLength(LRecover, Len);
  System.Move(LOut[0], LRecover[0], Len);
  CheckEqual('XChaCha20Poly1305 deterministic 2048B round-trip', LP, LRecover);
end;

procedure TTestXChaCha20Poly1305.TestTamperedTagMacFailure;
var
  LK, LP, LA, LN, LEnc, LDecBuf: TCryptoLibByteArray;
  LParams: IAeadParameters;
  LCipher: IXChaCha20Poly1305;
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

  LParams := TAeadParameters.Create(TKeyParameter.Create(LK) as IKeyParameter,
    128, LN, LA);

  LCipher := InitCipher(True, LParams);
  System.SetLength(LEnc, LCipher.GetOutputSize(System.Length(LP)));
  LLen := LCipher.ProcessBytes(LP, 0, System.Length(LP), LEnc, 0);
  LLen := LLen + LCipher.DoFinal(LEnc, LLen);

  LEnc[System.High(LEnc)] :=
    Byte(LEnc[System.High(LEnc)] xor $01);

  LCipher := InitCipher(False, LParams);
  System.SetLength(LDecBuf, LCipher.GetOutputSize(LLen));
  LLen := LCipher.ProcessBytes(LEnc, 0, System.Length(LEnc), LDecBuf, 0);
  try
    LCipher.DoFinal(LDecBuf, LLen);
    Fail('Tampered tag should fail AEAD decryption');
  except
    on E: EInvalidCipherTextCryptoLibException do
    begin
      if E.Message <>
        'mac check in XChaCha20Poly1305 failed' then
        Fail('unexpected decrypt message: ' + E.Message);
    end;
  end;
end;

procedure TTestXChaCha20Poly1305.TestRejectNonce12Byte;
var
  LK, LN12: TCryptoLibByteArray;
  LParams: IAeadParameters;
  LCipher: IXChaCha20Poly1305;
begin
  System.SetLength(LK, 32);
  System.SetLength(LN12, 12);
  LParams := TAeadParameters.Create(TKeyParameter.Create(LK) as IKeyParameter,
    128, LN12, nil);
  LCipher := TXChaCha20Poly1305.Create;
  try
    LCipher.Init(True, LParams as ICipherParameters);
    Fail('XChaCha20Poly1305 unexpectedly accepted a 96-bit nonce');
  except
    on E: EArgumentCryptoLibException do
    begin
      if E.Message <> 'Nonce must be 192 bits' then
        Fail('unexpected nonce length message: ' + E.Message);
    end;
  end;
end;

procedure TTestXChaCha20Poly1305.TestReuseNonceEncryptionRejected;
var
  LK, LN, LOut: TCryptoLibByteArray;
  LParams1, LParams2: IAeadParameters;
  LCipher: IXChaCha20Poly1305;
begin
  LK := THexEncoder.Decode(
    '808182838485868788898a8b8c8d8e8f' +
    '909192939495969798999a9b9c9d9e9f');
  LN := THexEncoder.Decode(
    '404142434445464748494a4b4c4d4e4f5051525354555657');

  LParams1 := TAeadParameters.Create(TKeyParameter.Create(LK) as IKeyParameter,
    128, LN, nil);
  LParams2 := TAeadParameters.Create(TKeyParameter.Create(LK) as IKeyParameter,
    128, LN, nil);

  LCipher := TXChaCha20Poly1305.Create;
  LCipher.Init(True, LParams1 as ICipherParameters);
  System.SetLength(LOut, LCipher.GetOutputSize(0));
  LCipher.DoFinal(LOut, 0);

  try
    LCipher.Init(True, LParams2 as ICipherParameters);
    Fail('XChaCha20Poly1305 unexpectedly allowed nonce reuse for encryption');
  except
    on E: EArgumentCryptoLibException do
    begin
      if E.Message <>
        'cannot reuse nonce for XChaCha20Poly1305 encryption' then
        Fail('unexpected nonce reuse message: ' + E.Message);
    end;
  end;
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
