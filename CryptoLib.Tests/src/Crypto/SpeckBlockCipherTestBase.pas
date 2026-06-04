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

unit SpeckBlockCipherTestBase;

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
  ClpIBufferedCipher,
  ClpIBufferedBlockCipher,
  ClpBufferedBlockCipher,
  ClpCbcBlockCipher,
  ClpICbcBlockCipher,
  ClpSicBlockCipher,
  ClpISicBlockCipher,
  ClpSpeckEngine,
  ClpISpeckEngine,
  ClpISpeckLegacyEngine,
  ClpCryptoLibTypes,
  CryptoLibTestBase,
  SymmetricBlockVectors;

type

  TSpeckBlockCipherTestBase = class abstract(TCryptoLibAlgorithmTestCase)
  strict private
    procedure DoBlockCipherVectorTest(const AEngine: IBlockCipher;
      const AParam: ICipherParameters; const AInput, AOutput: String;
      const APreface: String = '');

    procedure DoSPECKTest(const ACipher: IBufferedCipher;
      const AParam: ICipherParameters; const AInput, AOutput: String;
      AWithPadding: Boolean = False);

  strict protected
    procedure RunSpeckBlockCipherVectorTests(const ACreateEngine
      : TCryptoLibFunc<ISpeckEngine>; const AEngineLabel: String;
      const AKeys, AInputs, AOutputs: TCryptoLibStringArray);

    procedure RunSpeckLegacyBlockCipherVectorTests(const ACreateEngine
      : TCryptoLibFunc<ISpeckLegacyEngine>; const AEngineLabel: String;
      const AKeys, AInputs, AOutputs: TCryptoLibStringArray);

    procedure RunCryptoPPSpeckModeTests(const AMode: string; AWithIV: Boolean;
      ACreateEngine: TCryptoLibFunc<ISpeckEngine>);

    procedure RunCryptoPPSpeck64EcbTests;
    procedure RunCryptoPPSpeck128EcbTests;
    procedure RunCryptoPPSpeck64CbcTests;
    procedure RunCryptoPPSpeck128CbcTests;
    procedure RunCryptoPPSpeck64CtrTests;
    procedure RunCryptoPPSpeck128CtrTests;
  end;

implementation

function CreateSpeck64EngineForCryptoPP: ISpeckEngine;
begin
  Result := TSpeck64Engine.Create();
end;

function CreateSpeck128EngineForCryptoPP: ISpeckEngine;
begin
  Result := TSpeck128Engine.Create();
end;

{ TSpeckBlockCipherTestBase }

procedure TSpeckBlockCipherTestBase.DoBlockCipherVectorTest(const AEngine: IBlockCipher;
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

  LLen1 := LCipher.ProcessBytes(LInput, 0, System.Length(LInput),
    LOutBytes, 0);

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

procedure TSpeckBlockCipherTestBase.DoSPECKTest(const ACipher: IBufferedCipher;
  const AParam: ICipherParameters; const AInput, AOutput: String;
  AWithPadding: Boolean);
var
  LInput, LOutput, LEncryptionResult, LDecryptionResult: TBytes;
begin
  LInput := DecodeHex(AInput);
  LOutput := DecodeHex(AOutput);

  ACipher.Init(True, AParam);

  LEncryptionResult := ACipher.DoFinal(LInput);

  if not AWithPadding then
  begin
    if (not AreEqual(LOutput, LEncryptionResult)) then
    begin
      Fail(Format('Encryption Failed - Expected %s but got %s',
        [EncodeHex(LOutput), EncodeHex(LEncryptionResult)]));
    end;
  end;

  ACipher.Init(False, AParam);

  LDecryptionResult := ACipher.DoFinal(LEncryptionResult);

  if (not AreEqual(LInput, LDecryptionResult)) then
  begin
    Fail(Format('Decryption Failed - Expected %s but got %s',
      [EncodeHex(LInput), EncodeHex(LDecryptionResult)]));
  end;
end;

procedure TSpeckBlockCipherTestBase.RunSpeckBlockCipherVectorTests(const ACreateEngine
  : TCryptoLibFunc<ISpeckEngine>; const AEngineLabel: String;
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

procedure TSpeckBlockCipherTestBase.RunSpeckLegacyBlockCipherVectorTests(const ACreateEngine
  : TCryptoLibFunc<ISpeckLegacyEngine>; const AEngineLabel: String;
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

procedure TSpeckBlockCipherTestBase.RunCryptoPPSpeckModeTests(const AMode: string;
  AWithIV: Boolean; ACreateEngine: TCryptoLibFunc<ISpeckEngine>);
var
  LRows: TCryptoLibGenericArray<TSpeckVectorRow>;
  LKeyParametersWithIV: IParametersWithIV;
  LKeyParameter: IKeyParameter;
  LKeyBytes, LIVBytes: TBytes;
  LCipher: IBufferedCipher;
  LI: Int32;
  LEngine: ISpeckEngine;
  LBlockCipher: IBlockCipher;
  LCbcBlockCipher: ICbcBlockCipher;
  LSicBlockCipher: ISicBlockCipher;
begin
  LRows := TSpeckVectors.GetRows(AMode);
  if Length(LRows) = 0 then
    raise Exception.CreateFmt('No Speck vectors for mode: %s', [AMode]);

  LEngine := ACreateEngine();
  if AWithIV then
  begin
    if SameText(Copy(AMode, 1, 3), 'Cbc') then
    begin
      LCbcBlockCipher := TCbcBlockCipher.Create(LEngine);
      LCipher := TBufferedBlockCipher.Create(LCbcBlockCipher);
    end
    else
    begin
      LSicBlockCipher := TSicBlockCipher.Create(LEngine);
      LCipher := TBufferedBlockCipher.Create(LSicBlockCipher);
    end;
  end
  else
  begin
    LBlockCipher := LEngine;
    LCipher := TBufferedBlockCipher.Create(LBlockCipher);
  end;

  for LI := System.Low(LRows) to System.High(LRows) do
  begin
    LKeyBytes := DecodeHex(LRows[LI].Key);
    if AWithIV then
    begin
      LIVBytes := DecodeHex(LRows[LI].IV);
      LKeyParametersWithIV := TParametersWithIV.Create
        (TKeyParameter.Create(LKeyBytes) as IKeyParameter, LIVBytes);
      DoSPECKTest(LCipher, LKeyParametersWithIV as ICipherParameters,
        LRows[LI].Input, LRows[LI].Output);
    end
    else
    begin
      LKeyParameter := TKeyParameter.Create(LKeyBytes);
      DoSPECKTest(LCipher, LKeyParameter as ICipherParameters,
        LRows[LI].Input, LRows[LI].Output);
    end;
  end;
end;

procedure TSpeckBlockCipherTestBase.RunCryptoPPSpeck64EcbTests;
begin
  RunCryptoPPSpeckModeTests('Ecb64', False, @CreateSpeck64EngineForCryptoPP);
end;

procedure TSpeckBlockCipherTestBase.RunCryptoPPSpeck128EcbTests;
begin
  RunCryptoPPSpeckModeTests('Ecb128', False, @CreateSpeck128EngineForCryptoPP);
end;

procedure TSpeckBlockCipherTestBase.RunCryptoPPSpeck64CbcTests;
begin
  RunCryptoPPSpeckModeTests('Cbc64', True, @CreateSpeck64EngineForCryptoPP);
end;

procedure TSpeckBlockCipherTestBase.RunCryptoPPSpeck128CbcTests;
begin
  RunCryptoPPSpeckModeTests('Cbc128', True, @CreateSpeck128EngineForCryptoPP);
end;

procedure TSpeckBlockCipherTestBase.RunCryptoPPSpeck64CtrTests;
begin
  RunCryptoPPSpeckModeTests('Ctr64', True, @CreateSpeck64EngineForCryptoPP);
end;

procedure TSpeckBlockCipherTestBase.RunCryptoPPSpeck128CtrTests;
begin
  RunCryptoPPSpeckModeTests('Ctr128', True, @CreateSpeck128EngineForCryptoPP);
end;

end.
