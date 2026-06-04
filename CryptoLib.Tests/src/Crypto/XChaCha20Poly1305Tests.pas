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
  ClpGeneratorUtilities,
  ClpICipherKeyGenerator,
  ClpParameterUtilities,
  ClpIAsn1Core,
  ClpIAsn1Objects,
  ClpChaChaEngine,
  ClpChaCha7539Engine,
  ClpIChaCha7539Engine,
  ClpSecureRandom,
  ClpISecureRandom,
  ClpArrayUtilities,
  ClpCryptoLibTypes,
  CryptoLibTestBase,
  ChaChaPoly1305Vectors;

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
    procedure TestRandomRoundTrip;
    procedure TestRejectInvalidKeySize;
    procedure TestKeyGenerator256Bit;
    procedure TestParameterUtilitiesIv24Bytes;
    procedure TestCipherUtilitiesStreamRoundTrip;
    procedure TestCipherUtilitiesAeadDraftVector;
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
  LCipher := TXChaCha20Poly1305.Create();
  LCipher.Init(AForEncryption, AParams as ICipherParameters);
  Result := LCipher;
end;

procedure TTestXChaCha20Poly1305.TestAppendixA1;
var
  LRow: TChaChaAeadRow;
  LK, LP, LA, LN, LC, LT, LEnc, LMac, LPlain: TBytes;
  LParams: IAeadParameters;
  LEncCipher, LDecCipher: IXChaCha20Poly1305;
  LLen: Int32;
begin
  LRow := TChaChaVectors.GetXChaCha20Poly1305Row('AppendixA1');
  LK := THexEncoder.Decode(LRow.Key);
  LP := THexEncoder.Decode(LRow.Plaintext);
  LA := THexEncoder.Decode(LRow.Aad);
  LN := THexEncoder.Decode(LRow.Nonce);
  LC := THexEncoder.Decode(LRow.Ciphertext);
  LT := THexEncoder.Decode(LRow.Tag);

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
  LRow: TChaChaAeadRow;
  LK, LN, LNoncePrefix, LSubKey, LInnerIv, LZero, LFirstBlock, LExpected: TBytes;
  LE: IChaCha7539Engine;
  LParams: IParametersWithIV;
  LIdx: Int32;
begin
  { draft-irtf-cfrg-xchacha A.3.1 - 32-byte Poly1305 key from first ChaCha block (RFC 8439). }
  LRow := TChaChaVectors.GetXChaCha20Poly1305Row('AppendixA3_1');
  LK := THexEncoder.Decode(LRow.Key);
  LN := THexEncoder.Decode(LRow.Nonce);
  LExpected := THexEncoder.Decode(LRow.Tag);

  System.SetLength(LNoncePrefix, 16);
  System.Move(LN[0], LNoncePrefix[0], 16);
  System.SetLength(LSubKey, 32);
  TChaChaEngine.HChaCha20(LK, LNoncePrefix, LSubKey, 0);
  TArrayUtilities.Fill<Byte>(LNoncePrefix, 0, 16, 0);

  System.SetLength(LInnerIv, 12);
  System.FillChar(LInnerIv[0], 4, 0);
  System.Move(LN[16], LInnerIv[4], 8);

  LE := TChaCha7539Engine.Create;
  LParams := TParametersWithIV.Create(TKeyParameter.Create(LSubKey) as IKeyParameter,
    LInnerIv);
  LE.Init(True, LParams);
  System.SetLength(LZero, 64);
  for LIdx := 0 to 63 do
    LZero[LIdx] := 0;
  System.SetLength(LFirstBlock, 64);
  LE.ProcessBytes(LZero, 0, 64, LFirstBlock, 0);
  TArrayUtilities.Fill<Byte>(LSubKey, 0, 32, 0);
  TArrayUtilities.Fill<Byte>(LInnerIv, 0, 12, 0);

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
  LRow: TChaChaAeadRow;
  LK, LP, LA, LN, LEnc, LDecBuf: TCryptoLibByteArray;
  LParams: IAeadParameters;
  LCipher: IXChaCha20Poly1305;
  LLen: Int32;
begin
  LRow := TChaChaVectors.GetXChaCha20Poly1305Row('AppendixA1');
  LK := THexEncoder.Decode(LRow.Key);
  LP := THexEncoder.Decode(LRow.Plaintext);
  LA := THexEncoder.Decode(LRow.Aad);
  LN := THexEncoder.Decode(LRow.Nonce);

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
  LRow: TChaChaAeadRow;
  LK, LN, LOut: TCryptoLibByteArray;
  LParams1, LParams2: IAeadParameters;
  LCipher: IXChaCha20Poly1305;
begin
  LRow := TChaChaVectors.GetXChaCha20Poly1305Row('AppendixA1');
  LK := THexEncoder.Decode(LRow.Key);
  LN := THexEncoder.Decode(LRow.Nonce);

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

procedure TTestXChaCha20Poly1305.TestRandomRoundTrip;
var
  LRandom: ISecureRandom;
  LI, LPLen, LALen, LLen, EL, DL, LTamperIdx: Int32;
  LKey, LNonce, LPlain, LAad, LCt, LPt, LJunk: TCryptoLibByteArray;
  LParams: IAeadParameters;
  LEnc, LDec, LBad: IXChaCha20Poly1305;
begin
  LRandom := TSecureRandom.Create;
  for LI := 0 to 49 do
  begin
    System.SetLength(LKey, 32);
    LRandom.NextBytes(LKey);
    System.SetLength(LNonce, 24);
    LRandom.NextBytes(LNonce);
    LPLen := LRandom.Next(1, 4096);
    System.SetLength(LPlain, LPLen);
    if LPLen > 0 then
      LRandom.NextBytes(LPlain);
    LALen := LRandom.Next(1, 256);
    System.SetLength(LAad, LALen);
    if LALen > 0 then
      LRandom.NextBytes(LAad);

    LParams := TAeadParameters.Create(TKeyParameter.Create(LKey) as IKeyParameter,
      128, LNonce, LAad);

    LEnc := InitCipher(True, LParams);
    System.SetLength(LCt, LEnc.GetOutputSize(LPLen));
    LLen := LEnc.ProcessBytes(LPlain, 0, LPLen, LCt, 0);
    LLen := LLen + LEnc.DoFinal(LCt, LLen);
    if System.Length(LCt) <> LLen then
      Fail('round-trip: encryption length mismatch');

    LDec := InitCipher(False, LParams);
    System.SetLength(LPt, LDec.GetOutputSize(LLen));
    DL := LDec.ProcessBytes(LCt, 0, LLen, LPt, 0);
    DL := DL + LDec.DoFinal(LPt, DL);
    if DL <> LPLen then
      Fail('round-trip: decryption length mismatch');
    CheckEqual('round-trip: plaintext mismatch', LPlain,
      CopyOfRange(LPt, 0, LPLen));

    if LLen > 0 then
    begin
      LTamperIdx := LRandom.Next(1, LLen);
      LCt[LTamperIdx] := Byte(LCt[LTamperIdx] xor $01);
      LBad := InitCipher(False, LParams);
      System.SetLength(LJunk, LBad.GetOutputSize(LLen));
      try
        EL := LBad.ProcessBytes(LCt, 0, LLen, LJunk, 0);
        LBad.DoFinal(LJunk, EL);
        Fail('round-trip: tampered ciphertext was accepted');
      except
        on E: EInvalidCipherTextCryptoLibException do
          ; // expected
      end;
    end;
  end;
end;

procedure TTestXChaCha20Poly1305.TestRejectInvalidKeySize;
var
  LKey16, LNonce: TCryptoLibByteArray;
  LParams: IAeadParameters;
  LCipher: IXChaCha20Poly1305;
begin
  System.SetLength(LKey16, 16);
  System.SetLength(LNonce, 24);
  LParams := TAeadParameters.Create(TKeyParameter.Create(LKey16) as IKeyParameter,
    128, LNonce, nil);
  LCipher := TXChaCha20Poly1305.Create();
  try
    LCipher.Init(True, LParams as ICipherParameters);
    Fail('XChaCha20Poly1305 unexpectedly accepted a 128-bit key');
  except
    on E: EArgumentCryptoLibException do
    begin
      if E.Message <> 'Key must be 256 bits' then
        Fail('unexpected key size message: ' + E.Message);
    end;
  end;
end;

procedure TTestXChaCha20Poly1305.TestKeyGenerator256Bit;
var
  LKg1, LKg2: ICipherKeyGenerator;
begin
  LKg1 := TGeneratorUtilities.GetKeyGenerator('XCHACHA20');
  if LKg1.DefaultStrength <> 256 then
    Fail('GeneratorUtilities default key size for XCHACHA20 is wrong');
  LKg2 := TGeneratorUtilities.GetKeyGenerator('XCHACHA20-POLY1305');
  if LKg2.DefaultStrength <> 256 then
    Fail('GeneratorUtilities default key size for XCHACHA20-POLY1305 is wrong');
end;

procedure TTestXChaCha20Poly1305.TestParameterUtilitiesIv24Bytes;
var
  LRandom: ISecureRandom;
  LParams: IAsn1Encodable;
  LOctet: IAsn1OctetString;
begin
  LRandom := TSecureRandom.Create;
  LParams := TParameterUtilities.GenerateParameters('XCHACHA20', LRandom);
  if not Supports(LParams, IAsn1OctetString, LOctet) then
    Fail('ParameterUtilities did not return an octet string for XCHACHA20');
  if System.Length(LOctet.GetOctets) <> 24 then
    Fail('ParameterUtilities generated wrong IV length for XCHACHA20');
end;

procedure TTestXChaCha20Poly1305.TestCipherUtilitiesStreamRoundTrip;
var
  LRow: TChaChaAeadRow;
  LKey, LNonce, LPlain, LCt, LPt: TCryptoLibByteArray;
  LParams: IParametersWithIV;
  LEnc, LDec: IBufferedCipher;
begin
  LRow := TChaChaVectors.GetXChaCha20Poly1305Row('AppendixA1');
  LKey := THexEncoder.Decode(LRow.Key);
  LNonce := THexEncoder.Decode(LRow.Nonce);
  LPlain := THexEncoder.Decode(LRow.Plaintext);

  LParams := TParametersWithIV.Create(TKeyParameter.Create(LKey) as IKeyParameter,
    LNonce);
  LEnc := TCipherUtilities.GetCipher('XCHACHA20');
  LEnc.Init(True, LParams);
  LCt := LEnc.DoFinal(LPlain);
  LDec := TCipherUtilities.GetCipher('XCHACHA20');
  LDec.Init(False, LParams);
  LPt := LDec.DoFinal(LCt);
  CheckEqual('CipherUtilities XCHACHA20 round-trip', LPlain, LPt);
end;

procedure TTestXChaCha20Poly1305.TestCipherUtilitiesAeadDraftVector;
var
  LRow: TChaChaAeadRow;
  LKey, LNonce, LAad, LPlain, LExpectedCipher, LExpectedTag, LExpected, LCt: TBytes;
  LParams: IAeadParameters;
  LCipher: IBufferedCipher;
begin
  LRow := TChaChaVectors.GetXChaCha20Poly1305Row('AppendixA1');
  LKey := THexEncoder.Decode(LRow.Key);
  LNonce := THexEncoder.Decode(LRow.Nonce);
  LAad := THexEncoder.Decode(LRow.Aad);
  LPlain := THexEncoder.Decode(LRow.Plaintext);
  LExpectedCipher := THexEncoder.Decode(LRow.Ciphertext);
  LExpectedTag := THexEncoder.Decode(LRow.Tag);
  System.SetLength(LExpected, System.Length(LExpectedCipher) +
    System.Length(LExpectedTag));
  System.Move(LExpectedCipher[0], LExpected[0], System.Length(LExpectedCipher));
  System.Move(LExpectedTag[0], LExpected[System.Length(LExpectedCipher)],
    System.Length(LExpectedTag));

  LParams := TAeadParameters.Create(TKeyParameter.Create(LKey) as IKeyParameter,
    System.Length(LExpectedTag) * 8, LNonce, LAad);
  LCipher := TCipherUtilities.GetCipher('XCHACHA20-POLY1305');
  LCipher.Init(True, LParams as ICipherParameters);
  LCt := LCipher.DoFinal(LPlain);
  CheckEqual('CipherUtilities XCHACHA20-POLY1305 draft vector', LExpected, LCt);
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestXChaCha20Poly1305);
{$ELSE}
  RegisterTest(TTestXChaCha20Poly1305.Suite);
{$ENDIF FPC}

end.
