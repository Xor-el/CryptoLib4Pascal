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

unit BlockCipherTestBase;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  SysUtils,
  ClpIBlockCipher,
  ClpICipherParameters,
  ClpIKeyParameter,
  ClpKeyParameter,
  ClpIParametersWithIV,
  ClpParametersWithIV,
  ClpIBufferedBlockCipher,
  ClpBufferedBlockCipher,
  ClpCryptoLibTypes,
  CryptoLibTestBase;

type
  // shared factory shape for every block-cipher test suite
  TBlockCipherFactory = function: IBlockCipher;

  /// <summary>
  /// Common scaffolding for block-cipher known-answer test suites: a single
  /// encrypt/decrypt round-trip primitive and a data-driven runner over
  /// parallel key/input/output vectors. Family-specific bases (AES, Speck)
  /// inherit from this.
  /// </summary>
  TBlockCipherTestBase = class abstract(TCryptoLibAlgorithmTestCase)
  strict protected
    procedure DoBlockCipherVectorTest(const AEngine: IBlockCipher;
      const AParam: ICipherParameters; const AInput, AOutput: String;
      const APreface: String = '');

    procedure RunBlockCipherVectorTests(const ACreateEngine: TBlockCipherFactory;
      const AEngineLabel: String;
      const AKeys, AInputs, AOutputs: TCryptoLibStringArray);

    // engine-agnostic IBlockCipher contract checks
    procedure AssertEngineRejectsBadParameters(const ACreateEngine
      : TBlockCipherFactory; const AEngineLabel: String);

    procedure RunCipherEngineChecks(const AEngine: IBlockCipher;
      const AValidKey: IKeyParameter; const AContext: String);
  end;

implementation

{ TBlockCipherTestBase }

procedure TBlockCipherTestBase.DoBlockCipherVectorTest(const AEngine: IBlockCipher;
  const AParam: ICipherParameters; const AInput, AOutput: String;
  const APreface: String);
var
  LCipher: IBufferedBlockCipher;
  LLen1, LLen2: Int32;
  LInput, LOutput, LOutBytes: TBytes;
  LPrefix: String;
begin
  LInput := DecodeHex(AInput);
  LOutput := DecodeHex(AOutput);

  if APreface <> '' then
    LPrefix := '[' + APreface + '] '
  else
    LPrefix := '';

  LCipher := TBufferedBlockCipher.Create(AEngine);

  LCipher.Init(True, AParam);

  System.SetLength(LOutBytes, System.Length(LInput));

  LLen1 := LCipher.ProcessBytes(LInput, 0, System.Length(LInput), LOutBytes, 0);

  LCipher.DoFinal(LOutBytes, LLen1);

  if (not AreEqual(LOutBytes, LOutput)) then
  begin
    Fail(LPrefix + Format('Encryption Failed - Expected %s but got %s',
      [EncodeHex(LOutput), EncodeHex(LOutBytes)]));
  end;

  LCipher.Init(False, AParam);

  LLen2 := LCipher.ProcessBytes(LOutput, 0, System.Length(LOutput),
    LOutBytes, 0);

  LCipher.DoFinal(LOutBytes, LLen2);

  if (not AreEqual(LInput, LOutBytes)) then
  begin
    Fail(LPrefix + Format('Decryption Failed - Expected %s but got %s',
      [EncodeHex(LInput), EncodeHex(LOutBytes)]));
  end;
end;

procedure TBlockCipherTestBase.RunBlockCipherVectorTests(const ACreateEngine
  : TBlockCipherFactory; const AEngineLabel: String;
  const AKeys, AInputs, AOutputs: TCryptoLibStringArray);
var
  LI: Int32;
  LPreface: String;
begin
  for LI := System.Low(AKeys) to System.High(AKeys) do
  begin
    LPreface := Format('%s block vector index %d', [AEngineLabel, LI]);
    DoBlockCipherVectorTest(ACreateEngine(),
      TKeyParameter.Create(DecodeHex(AKeys[LI])) as IKeyParameter,
      AInputs[LI], AOutputs[LI], LPreface);
  end;
end;

procedure TBlockCipherTestBase.AssertEngineRejectsBadParameters(const ACreateEngine
  : TBlockCipherFactory; const AEngineLabel: String);
var
  LDudKey, LIV: TBytes;
  LEngine: IBlockCipher;
begin
  LEngine := ACreateEngine();

  try
    System.SetLength(LDudKey, 6);
    LEngine.Init(True, TKeyParameter.Create(LDudKey) as IKeyParameter);
    Fail(Format('[%s] failed key length check', [AEngineLabel]));
  except
    on e: EArgumentCryptoLibException do
    begin
      // expected
    end;
  end;

  LEngine := ACreateEngine();

  try
    System.SetLength(LIV, 16);
    LEngine.Init(True, TParametersWithIV.Create(nil, LIV) as IParametersWithIV);
    Fail(Format('[%s] failed parameter check', [AEngineLabel]));
  except
    on e: EArgumentCryptoLibException do
    begin
      // expected
    end;
  end;
end;

procedure TBlockCipherTestBase.RunCipherEngineChecks(const AEngine: IBlockCipher;
  const AValidKey: IKeyParameter; const AContext: String);
var
  LCorrectBuf, LShortBuf: TBytes;
  LBlockSize: Int32;
begin
  LBlockSize := AEngine.GetBlockSize();
  System.SetLength(LCorrectBuf, LBlockSize);
  System.SetLength(LShortBuf, LBlockSize div 2);

  try
    AEngine.ProcessBlock(LCorrectBuf, 0, LCorrectBuf, 0);
    Fail(Format('[%s] failed initialisation check', [AContext]));
  except
    on E: EInvalidOperationCryptoLibException do
    begin
      // expected
    end;
  end;

  AEngine.Init(True, AValidKey as ICipherParameters);

  try
    AEngine.ProcessBlock(LShortBuf, 0, LCorrectBuf, 0);
    Fail(Format('[%s] failed short input check (encrypt)', [AContext]));
  except
    on E: EDataLengthCryptoLibException do
    begin
      // expected (includes EOutputLengthCryptoLibException)
    end;
  end;

  try
    AEngine.ProcessBlock(LCorrectBuf, 0, LShortBuf, 0);
    Fail(Format('[%s] failed short output check (encrypt)', [AContext]));
  except
    on E: EDataLengthCryptoLibException do
    begin
      // expected
    end;
  end;

  AEngine.Init(False, AValidKey as ICipherParameters);

  try
    AEngine.ProcessBlock(LShortBuf, 0, LCorrectBuf, 0);
    Fail(Format('[%s] failed short input check (decrypt)', [AContext]));
  except
    on E: EDataLengthCryptoLibException do
    begin
      // expected
    end;
  end;

  try
    AEngine.ProcessBlock(LCorrectBuf, 0, LShortBuf, 0);
    Fail(Format('[%s] failed short output check (decrypt)', [AContext]));
  except
    on E: EDataLengthCryptoLibException do
    begin
      // expected
    end;
  end;
end;

end.
