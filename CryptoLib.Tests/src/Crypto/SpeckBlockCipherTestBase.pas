{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                           Author - Ugochukwu Mmaduekwe                          * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }

{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }

{ *                              Acknowledgements:                                  * }
{ *                                                                                 * }
{ *      Thanks to Sphere 10 Software (http://www.sphere10.com/) for sponsoring     * }
{ *                           development of this library                           * }

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
  SpeckCryptoPPTestData;

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

    procedure RunCryptoPPSpeck64EcbTests;
    procedure RunCryptoPPSpeck128EcbTests;
    procedure RunCryptoPPSpeck64CbcTests;
    procedure RunCryptoPPSpeck128CbcTests;
    procedure RunCryptoPPSpeck64CtrTests;
    procedure RunCryptoPPSpeck128CtrTests;
  end;

implementation

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

procedure TSpeckBlockCipherTestBase.RunCryptoPPSpeck64EcbTests;
var
  LKeyParameter: IKeyParameter;
  LKeyBytes: TBytes;
  LCipher: IBufferedCipher;
  LInput, LOutput: String;
  LI: Int32;
  LEngine: ISpeckEngine;
  LBlockCipher: IBlockCipher;
begin
  LEngine := TSpeck64Engine.Create();
  LBlockCipher := LEngine as IBlockCipher;
  LCipher := TBufferedBlockCipher.Create(LBlockCipher) as IBufferedBlockCipher;

  for LI := System.Low(TSpeckCryptoPPTestData.Keys64Ecb)
    to System.High(TSpeckCryptoPPTestData.Keys64Ecb) do
  begin
    LKeyBytes := DecodeHex(TSpeckCryptoPPTestData.Keys64Ecb[LI]);
    LInput := TSpeckCryptoPPTestData.Inputs64Ecb[LI];
    LOutput := TSpeckCryptoPPTestData.Outputs64Ecb[LI];

    LKeyParameter := TKeyParameter.Create(LKeyBytes);

    DoSPECKTest(LCipher, LKeyParameter as ICipherParameters,
      LInput, LOutput);
  end;
end;

procedure TSpeckBlockCipherTestBase.RunCryptoPPSpeck128EcbTests;
var
  LKeyParameter: IKeyParameter;
  LKeyBytes: TBytes;
  LCipher: IBufferedCipher;
  LInput, LOutput: String;
  LI: Int32;
  LEngine: ISpeckEngine;
  LBlockCipher: IBlockCipher;
begin
  LEngine := TSpeck128Engine.Create();
  LBlockCipher := LEngine as IBlockCipher;
  LCipher := TBufferedBlockCipher.Create(LBlockCipher) as IBufferedBlockCipher;

  for LI := System.Low(TSpeckCryptoPPTestData.Keys128Ecb)
    to System.High(TSpeckCryptoPPTestData.Keys128Ecb) do
  begin
    LKeyBytes := DecodeHex(TSpeckCryptoPPTestData.Keys128Ecb[LI]);
    LInput := TSpeckCryptoPPTestData.Inputs128Ecb[LI];
    LOutput := TSpeckCryptoPPTestData.Outputs128Ecb[LI];

    LKeyParameter := TKeyParameter.Create(LKeyBytes);

    DoSPECKTest(LCipher, LKeyParameter as ICipherParameters,
      LInput, LOutput);
  end;
end;

procedure TSpeckBlockCipherTestBase.RunCryptoPPSpeck64CbcTests;
var
  LKeyParametersWithIV: IParametersWithIV;
  LKeyBytes, LIVBytes: TBytes;
  LCipher: IBufferedCipher;
  LInput, LOutput: String;
  LI: Int32;
  LEngine: ISpeckEngine;
  LBlockCipher: ICbcBlockCipher;
begin
  LEngine := TSpeck64Engine.Create();
  LBlockCipher := TCbcBlockCipher.Create(LEngine);
  LCipher := TBufferedBlockCipher.Create(LBlockCipher) as IBufferedBlockCipher;

  for LI := System.Low(TSpeckCryptoPPTestData.Keys64Cbc)
    to System.High(TSpeckCryptoPPTestData.Keys64Cbc) do
  begin
    LKeyBytes := DecodeHex(TSpeckCryptoPPTestData.Keys64Cbc[LI]);
    LIVBytes := DecodeHex(TSpeckCryptoPPTestData.Ivs64Cbc[LI]);
    LInput := TSpeckCryptoPPTestData.Inputs64Cbc[LI];
    LOutput := TSpeckCryptoPPTestData.Outputs64Cbc[LI];

    LKeyParametersWithIV := TParametersWithIV.Create
      (TKeyParameter.Create(LKeyBytes) as IKeyParameter, LIVBytes);

    DoSPECKTest(LCipher, LKeyParametersWithIV as ICipherParameters,
      LInput, LOutput);
  end;
end;

procedure TSpeckBlockCipherTestBase.RunCryptoPPSpeck128CbcTests;
var
  LKeyParametersWithIV: IParametersWithIV;
  LKeyBytes, LIVBytes: TBytes;
  LCipher: IBufferedCipher;
  LInput, LOutput: String;
  LI: Int32;
  LEngine: ISpeckEngine;
  LBlockCipher: ICbcBlockCipher;
begin
  LEngine := TSpeck128Engine.Create();
  LBlockCipher := TCbcBlockCipher.Create(LEngine);
  LCipher := TBufferedBlockCipher.Create(LBlockCipher) as IBufferedBlockCipher;

  for LI := System.Low(TSpeckCryptoPPTestData.Keys128Cbc)
    to System.High(TSpeckCryptoPPTestData.Keys128Cbc) do
  begin
    LKeyBytes := DecodeHex(TSpeckCryptoPPTestData.Keys128Cbc[LI]);
    LIVBytes := DecodeHex(TSpeckCryptoPPTestData.Ivs128Cbc[LI]);
    LInput := TSpeckCryptoPPTestData.Inputs128Cbc[LI];
    LOutput := TSpeckCryptoPPTestData.Outputs128Cbc[LI];

    LKeyParametersWithIV := TParametersWithIV.Create
      (TKeyParameter.Create(LKeyBytes) as IKeyParameter, LIVBytes);

    DoSPECKTest(LCipher, LKeyParametersWithIV as ICipherParameters,
      LInput, LOutput);
  end;
end;

procedure TSpeckBlockCipherTestBase.RunCryptoPPSpeck64CtrTests;
var
  LKeyParametersWithIV: IParametersWithIV;
  LKeyBytes, LIVBytes: TBytes;
  LCipher: IBufferedCipher;
  LInput, LOutput: String;
  LI: Int32;
  LEngine: ISpeckEngine;
  LBlockCipher: ISicBlockCipher;
begin
  LEngine := TSpeck64Engine.Create();
  LBlockCipher := TSicBlockCipher.Create(LEngine);
  LCipher := TBufferedBlockCipher.Create(LBlockCipher) as IBufferedBlockCipher;

  for LI := System.Low(TSpeckCryptoPPTestData.Keys64Ctr)
    to System.High(TSpeckCryptoPPTestData.Keys64Ctr) do
  begin
    LKeyBytes := DecodeHex(TSpeckCryptoPPTestData.Keys64Ctr[LI]);
    LIVBytes := DecodeHex(TSpeckCryptoPPTestData.Ivs64Ctr[LI]);
    LInput := TSpeckCryptoPPTestData.Inputs64Ctr[LI];
    LOutput := TSpeckCryptoPPTestData.Outputs64Ctr[LI];

    LKeyParametersWithIV := TParametersWithIV.Create
      (TKeyParameter.Create(LKeyBytes) as IKeyParameter, LIVBytes);

    DoSPECKTest(LCipher, LKeyParametersWithIV as ICipherParameters,
      LInput, LOutput);
  end;
end;

procedure TSpeckBlockCipherTestBase.RunCryptoPPSpeck128CtrTests;
var
  LKeyParametersWithIV: IParametersWithIV;
  LKeyBytes, LIVBytes: TBytes;
  LCipher: IBufferedCipher;
  LInput, LOutput: String;
  LI: Int32;
  LEngine: ISpeckEngine;
  LBlockCipher: ISicBlockCipher;
begin
  LEngine := TSpeck128Engine.Create();
  LBlockCipher := TSicBlockCipher.Create(LEngine);
  LCipher := TBufferedBlockCipher.Create(LBlockCipher) as IBufferedBlockCipher;

  for LI := System.Low(TSpeckCryptoPPTestData.Keys128Ctr)
    to System.High(TSpeckCryptoPPTestData.Keys128Ctr) do
  begin
    LKeyBytes := DecodeHex(TSpeckCryptoPPTestData.Keys128Ctr[LI]);
    LIVBytes := DecodeHex(TSpeckCryptoPPTestData.Ivs128Ctr[LI]);
    LInput := TSpeckCryptoPPTestData.Inputs128Ctr[LI];
    LOutput := TSpeckCryptoPPTestData.Outputs128Ctr[LI];

    LKeyParametersWithIV := TParametersWithIV.Create
      (TKeyParameter.Create(LKeyBytes) as IKeyParameter, LIVBytes);

    DoSPECKTest(LCipher, LKeyParametersWithIV as ICipherParameters,
      LInput, LOutput);
  end;
end;

end.
