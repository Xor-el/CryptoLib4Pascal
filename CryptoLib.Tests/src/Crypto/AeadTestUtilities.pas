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

unit AeadTestUtilities;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  SysUtils,
  ClpIAeadCipher,
  ClpIAeadBlockCipher,
  ClpICipherParameters,
  ClpIAeadParameters,
  ClpAeadParameters,
  ClpCryptoLibTypes,
  ClpCryptoLibExceptions;

type
  TAeadTestUtilities = class sealed(TObject)
  strict private
    class procedure Crypt(const ACipher: IAeadCipher;
      const APretext, AOutput: TCryptoLibByteArray); static;
    class function VaryNonce(const AAeadParameters: IAeadParameters;
      ACounter: Int32): IAeadParameters; static;
    class procedure ResetForCheck(const ACipher: IAeadCipher;
      const AParameters: ICipherParameters; AEncrypt: Boolean); static;
    class procedure CheckReset(const ATestName: string; const ACipher: IAeadCipher;
      const AParameters: ICipherParameters; AEncrypt: Boolean;
      const APretext, APosttext: TCryptoLibByteArray); static;
  public
    class procedure TestTampering(const ATestName: string;
      const ACipher: IAeadCipher; const AParameters: ICipherParameters); static;

    class procedure TestReset(const ATestName: string;
      const ACipher1, ACipher2: IAeadCipher;
      const AParameters: ICipherParameters); static;

    class procedure TestOutputSizes(const ATestName: string;
      const ACipher: IAeadBlockCipher; const AAeadParameters: IAeadParameters); static;

    class procedure TestBufferSizeChecks(const ATestName: string;
      const ACipher: IAeadBlockCipher; const AAeadParameters: IAeadParameters); static;

    class function ReuseKey(const AParameters: IAeadParameters)
      : IAeadParameters; static;
  end;

implementation

uses
  ClpArrayUtilities,
  ClpEncoders;

{ TAeadTestUtilities }

class procedure TAeadTestUtilities.TestTampering(const ATestName: string;
  const ACipher: IAeadCipher; const AParameters: ICipherParameters);
var
  LPlaintext, LCiphertext, LTampered, LTruncated, LOutput: TCryptoLibByteArray;
  LLen, LMacLength: Int32;
begin
  // prepare plaintext 0..999
  System.SetLength(LPlaintext, 1000);
  for LLen := 0 to System.Pred(System.Length(LPlaintext)) do
  begin
    LPlaintext[LLen] := Byte(LLen);
  end;

  // encrypt once
  ACipher.Init(True, AParameters);
  System.SetLength(LCiphertext, ACipher.GetOutputSize(System.Length(LPlaintext)));
  LLen := ACipher.ProcessBytes(LPlaintext, 0, System.Length(LPlaintext),
    LCiphertext, 0);
  LLen := LLen + ACipher.DoFinal(LCiphertext, LLen);

  // cache current tag length
  LMacLength := System.Length(ACipher.GetMac);

  // Test tampering with a single byte
  ACipher.Init(False, AParameters);
  System.SetLength(LTampered, LLen);
  System.Move(LCiphertext[0], LTampered[0], LLen);
  LTampered[0] := Byte(LTampered[0] + 1);

  System.SetLength(LOutput, System.Length(LPlaintext));
  ACipher.ProcessBytes(LTampered, 0, LLen, LOutput, 0);
  try
    ACipher.DoFinal(LOutput, 0);
    raise Exception.CreateFmt('%s : tampering of ciphertext not detected.',
      [ATestName]);
  except
    on E: EInvalidCipherTextCryptoLibException do
    begin
      // expected
    end;
  end;

  // Test truncation of ciphertext to < tag length
  ACipher.Init(False, AParameters);
  if LMacLength > 0 then
  begin
    System.SetLength(LTruncated, LMacLength - 1);
    System.Move(LCiphertext[0], LTruncated[0], System.Length(LTruncated));

    ACipher.ProcessBytes(LTruncated, 0, System.Length(LTruncated), LOutput, 0);
    try
      ACipher.DoFinal(LOutput, 0);
      raise Exception.CreateFmt('%s : tampering of ciphertext not detected.',
        [ATestName]);
    except
      on E: EInvalidCipherTextCryptoLibException do
      begin
        // expected
      end;
    end;
  end;
end;

class function TAeadTestUtilities.ReuseKey(const AParameters: IAeadParameters)
  : IAeadParameters;
begin
  Result := TAeadParameters.Create(nil, AParameters.MacSize,
    AParameters.GetNonce, AParameters.GetAssociatedText);
end;

class procedure TAeadTestUtilities.Crypt(const ACipher: IAeadCipher;
  const APretext: TCryptoLibByteArray; const AOutput: TCryptoLibByteArray);
var
  LLen: Int32;
begin
  LLen := ACipher.ProcessBytes(APretext, 0, System.Length(APretext), AOutput, 0);
  ACipher.DoFinal(AOutput, LLen);
end;

class function TAeadTestUtilities.VaryNonce(const AAeadParameters: IAeadParameters;
  ACounter: Int32): IAeadParameters;
var
  LNonce: TCryptoLibByteArray;
  LI: Int32;
begin
  LNonce := System.Copy(AAeadParameters.GetNonce());
  for LI := 0 to System.Pred(System.Length(LNonce)) do
  begin
    if LI >= 4 then
      Break;
    LNonce[LI] := LNonce[LI] xor Byte(UInt32(ACounter) shr (8 * LI));
  end;
  Result := TAeadParameters.Create(AAeadParameters.Key, AAeadParameters.MacSize,
    LNonce, AAeadParameters.GetAssociatedText());
end;

class procedure TAeadTestUtilities.ResetForCheck(const ACipher: IAeadCipher;
  const AParameters: ICipherParameters; AEncrypt: Boolean);
begin
  if AEncrypt then
    ACipher.Reset()
  else
    ACipher.Init(False, AParameters);
end;

class procedure TAeadTestUtilities.CheckReset(const ATestName: string;
  const ACipher: IAeadCipher; const AParameters: ICipherParameters;
  AEncrypt: Boolean; const APretext, APosttext: TCryptoLibByteArray);
var
  LOutput: TCryptoLibByteArray;
  LDir: string;
begin
  if AEncrypt then
    LDir := 'Encrypt'
  else
    LDir := 'Decrypt';

  System.SetLength(LOutput, System.Length(APosttext));
  Crypt(ACipher, APretext, LOutput);

  Crypt(ACipher, APretext, LOutput);
  if not TArrayUtilities.AreEqual(LOutput, APosttext) then
    raise Exception.CreateFmt('%s : %s did not reset cipher.', [ATestName, LDir]);

  ACipher.ProcessBytes(APretext, 0, 100, LOutput, 0);
  ResetForCheck(ACipher, AParameters, AEncrypt);

  try
    Crypt(ACipher, APretext, LOutput);
  except
    on E: EDataLengthCryptoLibException do
      raise Exception.CreateFmt('%s : Init did not reset data.', [ATestName]);
  end;
  if not TArrayUtilities.AreEqual(LOutput, APosttext) then
    raise Exception.CreateFmt('%s : Init did not reset data. expected %s got %s',
      [ATestName, THexEncoder.Encode(APosttext, True),
      THexEncoder.Encode(LOutput, True)]);

  ACipher.ProcessAadBytes(APretext, 0, 100);
  ResetForCheck(ACipher, AParameters, AEncrypt);

  try
    Crypt(ACipher, APretext, LOutput);
  except
    on E: EDataLengthCryptoLibException do
      raise Exception.CreateFmt('%s : Init did not reset additional data.',
        [ATestName]);
  end;
  if not TArrayUtilities.AreEqual(LOutput, APosttext) then
    raise Exception.CreateFmt('%s : Init did not reset additional data.',
      [ATestName]);

  ACipher.ProcessBytes(APretext, 0, 100, LOutput, 0);
  ACipher.Reset();

  try
    Crypt(ACipher, APretext, LOutput);
  except
    on E: EDataLengthCryptoLibException do
      raise Exception.CreateFmt('%s : Reset did not reset data.', [ATestName]);
  end;
  if not TArrayUtilities.AreEqual(LOutput, APosttext) then
    raise Exception.CreateFmt('%s : Reset did not reset data.', [ATestName]);

  ACipher.ProcessAadBytes(APretext, 0, 100);
  ACipher.Reset();

  try
    Crypt(ACipher, APretext, LOutput);
  except
    on E: EDataLengthCryptoLibException do
      raise Exception.CreateFmt('%s : Reset did not reset additional data.',
        [ATestName]);
  end;
  if not TArrayUtilities.AreEqual(LOutput, APosttext) then
    raise Exception.CreateFmt('%s : Reset did not reset additional data.',
      [ATestName]);
end;

class procedure TAeadTestUtilities.TestReset(const ATestName: string;
  const ACipher1, ACipher2: IAeadCipher; const AParameters: ICipherParameters);
var
  LPlaintext, LCiphertext: TCryptoLibByteArray;
begin
  ACipher1.Init(True, AParameters);

  System.SetLength(LPlaintext, 1000);
  System.SetLength(LCiphertext, ACipher1.GetOutputSize(System.Length(LPlaintext)));

  Crypt(ACipher1, LPlaintext, LCiphertext);

  CheckReset(ATestName, ACipher1, AParameters, True, LPlaintext, LCiphertext);

  ACipher2.Init(False, AParameters);
  CheckReset(ATestName, ACipher2, AParameters, False, LCiphertext, LPlaintext);
end;

class procedure TAeadTestUtilities.TestOutputSizes(const ATestName: string;
  const ACipher: IAeadBlockCipher; const AAeadParameters: IAeadParameters);
var
  LMaxPlaintext: Int32;
  LPlaintext, LCiphertext: TCryptoLibByteArray;
  LMacLength, LI, LExpectedCTUpdateSize, LExpectedCTOutputSize, LActualCTSize,
    LExpectedPTUpdateSize, LExpectedPTOutputSize, LActualPTSize: Int32;
  LParamsI: IAeadParameters;
begin
  LMaxPlaintext := ACipher.GetUnderlyingCipher.GetBlockSize() * 10;
  System.SetLength(LPlaintext, LMaxPlaintext);
  System.SetLength(LCiphertext, LMaxPlaintext * 2);

  ACipher.Init(True, AAeadParameters as ICipherParameters);
  ACipher.DoFinal(LCiphertext, 0);
  LMacLength := System.Length(ACipher.GetMac());

  ACipher.Init(False, AAeadParameters as ICipherParameters);
  for LI := 0 to LMacLength - 1 do
  begin
    ACipher.Reset();
    if ACipher.GetUpdateOutputSize(LI) <> 0 then
      raise Exception.CreateFmt(
        '%s : AE cipher should not produce update output with ciphertext length <= macSize',
        [ATestName]);
    if ACipher.GetOutputSize(LI) <> 0 then
      raise Exception.CreateFmt(
        '%s : AE cipher should not produce output with ciphertext length <= macSize',
        [ATestName]);
  end;

  for LI := 0 to System.Pred(LMaxPlaintext) do
  begin
    LParamsI := VaryNonce(AAeadParameters, LI + 1);
    ACipher.Init(True, LParamsI as ICipherParameters);
    LExpectedCTUpdateSize := ACipher.GetUpdateOutputSize(LI);
    LExpectedCTOutputSize := ACipher.GetOutputSize(LI);

    if LExpectedCTUpdateSize < 0 then
      raise Exception.CreateFmt(
        '%s : Encryption update output size should not be < 0 for size %d',
        [ATestName, LI]);
    if LExpectedCTOutputSize < 0 then
      raise Exception.CreateFmt(
        '%s : Encryption output size should not be < 0 for size %d',
        [ATestName, LI]);

    LActualCTSize := ACipher.ProcessBytes(LPlaintext, 0, LI, LCiphertext, 0);

    if LExpectedCTUpdateSize <> LActualCTSize then
      raise Exception.CreateFmt(
        '%s : Encryption update output size did not match calculated for plaintext length %d expected %d got %d',
        [ATestName, LI, LExpectedCTUpdateSize, LActualCTSize]);

    LActualCTSize := LActualCTSize + ACipher.DoFinal(LCiphertext, LActualCTSize);

    if LExpectedCTOutputSize <> LActualCTSize then
      raise Exception.CreateFmt(
        '%s : Encryption actual final output size did not match calculated for plaintext length %d expected %d got %d',
        [ATestName, LI, LExpectedCTOutputSize, LActualCTSize]);

    ACipher.Init(False, LParamsI as ICipherParameters);
    LExpectedPTUpdateSize := ACipher.GetUpdateOutputSize(LActualCTSize);
    LExpectedPTOutputSize := ACipher.GetOutputSize(LActualCTSize);

    if LExpectedPTOutputSize <> LI then
      raise Exception.CreateFmt(
        '%s : Decryption output size did not match original plaintext length %d expected %d got %d',
        [ATestName, LI, LI, LExpectedPTOutputSize]);

    LActualPTSize := ACipher.ProcessBytes(LCiphertext, 0, LActualCTSize,
      LPlaintext, 0);

    if LExpectedPTUpdateSize <> LActualPTSize then
      raise Exception.CreateFmt(
        '%s : Decryption update output size did not match calculated for plaintext length %d expected %d got %d',
        [ATestName, LI, LExpectedPTUpdateSize, LActualPTSize]);

    LActualPTSize := LActualPTSize + ACipher.DoFinal(LPlaintext, LActualPTSize);

    if LExpectedPTOutputSize <> LActualPTSize then
      raise Exception.CreateFmt(
        '%s : Decryption actual final output size did not match calculated for plaintext length %d expected %d got %d',
        [ATestName, LI, LExpectedPTOutputSize, LActualPTSize]);
  end;
end;

class procedure TAeadTestUtilities.TestBufferSizeChecks(const ATestName: string;
  const ACipher: IAeadBlockCipher; const AAeadParameters: IAeadParameters);
var
  LBlockSize, LMaxPlaintext, LExpectedUpdateOutputSize, LOutputTrigger, LI,
    LActualOutputSize, LMacSize, LEncrypted: Int32;
  LPlaintext, LCiphertext, LShortIn, LShortOut, LEmpty: TCryptoLibByteArray;
  LParamsI: IAeadParameters;
begin
  LBlockSize := ACipher.GetUnderlyingCipher.GetBlockSize();
  LMaxPlaintext := LBlockSize * 10;
  System.SetLength(LPlaintext, LMaxPlaintext);

  ACipher.Init(True, AAeadParameters as ICipherParameters);

  LExpectedUpdateOutputSize := ACipher.GetUpdateOutputSize(LMaxPlaintext);
  System.SetLength(LCiphertext, ACipher.GetOutputSize(LMaxPlaintext));

  System.SetLength(LShortIn, LMaxPlaintext - 1);
  System.SetLength(LShortOut, LExpectedUpdateOutputSize);
  try
    ACipher.ProcessBytes(LShortIn, 0, LMaxPlaintext, LShortOut, 0);
    raise Exception.CreateFmt('%s : ProcessBytes should validate input buffer length',
      [ATestName]);
  except
    on E: EDataLengthCryptoLibException do
    begin
      // expected
    end;
  end;
  ACipher.Reset();

  if LExpectedUpdateOutputSize > 0 then
  begin
    LOutputTrigger := 0;
    for LI := 0 to System.Pred(LMaxPlaintext) do
    begin
      if ACipher.GetUpdateOutputSize(1) <> 0 then
      begin
        LOutputTrigger := LI + 1;
        Break;
      end;
      ACipher.ProcessByte(LPlaintext[LI], LCiphertext, 0);
    end;
    if LOutputTrigger = 0 then
      raise Exception.CreateFmt('%s : Failed to find output trigger size', [ATestName]);

    System.SetLength(LShortOut, ACipher.GetUpdateOutputSize(1) - 1);
    try
      ACipher.ProcessByte(LPlaintext[0], LShortOut, 0);
      raise Exception.CreateFmt(
        '%s : Encrypt ProcessByte should validate output buffer length',
        [ATestName]);
    except
      on E: EOutputLengthCryptoLibException do
      begin
        // expected
      end;
    end;
    ACipher.Reset();

    System.SetLength(LShortOut, ACipher.GetUpdateOutputSize(LOutputTrigger) - 1);
    try
      ACipher.ProcessBytes(LPlaintext, 0, LOutputTrigger, LShortOut, 0);
      raise Exception.CreateFmt(
        '%s : Encrypt ProcessBytes should validate output buffer length',
        [ATestName]);
    except
      on E: EOutputLengthCryptoLibException do
      begin
        // expected
      end;
    end;
    ACipher.Reset();
  end;

  LActualOutputSize := ACipher.ProcessBytes(LPlaintext, 0, LMaxPlaintext,
    LCiphertext, 0);
  LActualOutputSize := LActualOutputSize +
    ACipher.DoFinal(LCiphertext, LActualOutputSize);
  LMacSize := System.Length(ACipher.GetMac());

  ACipher.Reset();
  System.SetLength(LShortOut, ACipher.GetOutputSize(0) - 1);
  try
    ACipher.ProcessBytes(LPlaintext, 0, LMaxPlaintext, LCiphertext, 0);
    ACipher.DoFinal(LShortOut, 0);
    raise Exception.CreateFmt('%s : Encrypt DoFinal should validate output buffer length',
      [ATestName]);
  except
    on E: EOutputLengthCryptoLibException do
    begin
      // expected
    end;
  end;

  ACipher.Init(False, AAeadParameters as ICipherParameters);
  LExpectedUpdateOutputSize := ACipher.GetUpdateOutputSize(LActualOutputSize);

  if LExpectedUpdateOutputSize > 0 then
  begin
    LOutputTrigger := 0;
    for LI := 0 to System.Pred(LMaxPlaintext) do
    begin
      if ACipher.GetUpdateOutputSize(1) <> 0 then
      begin
        LOutputTrigger := LI + 1;
        Break;
      end;
      ACipher.ProcessByte(LCiphertext[LI], LPlaintext, 0);
    end;
    if LOutputTrigger = 0 then
      raise Exception.CreateFmt('%s : Failed to find output trigger size', [ATestName]);

    System.SetLength(LShortOut, ACipher.GetUpdateOutputSize(1) - 1);
    try
      ACipher.ProcessByte(LCiphertext[0], LShortOut, 0);
      raise Exception.CreateFmt(
        '%s : Decrypt ProcessByte should validate output buffer length',
        [ATestName]);
    except
      on E: EOutputLengthCryptoLibException do
      begin
        // expected
      end;
    end;
    ACipher.Reset();

    System.SetLength(LShortOut, ACipher.GetUpdateOutputSize(LOutputTrigger) - 1);
    try
      ACipher.ProcessBytes(LCiphertext, 0, LOutputTrigger, LShortOut, 0);
      raise Exception.CreateFmt(
        '%s : Decrypt ProcessBytes should validate output buffer length',
        [ATestName]);
    except
      on E: EOutputLengthCryptoLibException do
      begin
        // expected
      end;
    end;
  end;

  ACipher.Reset();
  System.SetLength(LEmpty, 0);
  try
    if ACipher.ProcessBytes(LCiphertext, 0, LMacSize - 1, LPlaintext, 0) <> 0 then
      raise Exception.CreateFmt('%s : AE cipher unexpectedly produced output',
        [ATestName]);
    ACipher.DoFinal(LEmpty, 0);
    raise Exception.CreateFmt('%s : Decrypt DoFinal should check ciphertext length',
      [ATestName]);
  except
    on E: EInvalidCipherTextCryptoLibException do
    begin
      // expected
    end;
  end;

  try
    for LI := 2 to System.Pred(LMaxPlaintext) do
    begin
      LParamsI := VaryNonce(AAeadParameters, LI);
      ACipher.Init(True, LParamsI as ICipherParameters);
      LEncrypted := ACipher.ProcessBytes(LPlaintext, 0, LI, LCiphertext, 0);
      LEncrypted := LEncrypted + ACipher.DoFinal(LCiphertext, LEncrypted);

      ACipher.Init(False, LParamsI as ICipherParameters);
      ACipher.ProcessBytes(LCiphertext, 0, LEncrypted - 1, LPlaintext, 0);
      if ACipher.ProcessByte(LCiphertext[LEncrypted - 1], LPlaintext, 0) = 0 then
      begin
        System.SetLength(LShortOut, ACipher.GetOutputSize(0) - 1);
        ACipher.DoFinal(LShortOut, 0);
        raise Exception.CreateFmt('%s : Decrypt DoFinal should check output length',
          [ATestName]);
      end;
    end;
    raise Exception.CreateFmt(
      '%s : Decrypt DoFinal test couldn''t find a ciphertext length that buffered for DoFinal',
      [ATestName]);
  except
    on E: EOutputLengthCryptoLibException do
    begin
      // expected
    end;
  end;
end;

end.
