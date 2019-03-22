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

unit BlockCipherVectorTests;

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
  AESTestVectors,
  BlowfishTestVectors,
  SpeckTestVectors,
  RijndaelTestVectors,
  ClpIBlockCipher,
  ClpICipherParameters,
  ClpAesEngine,
  ClpIAesEngine,
  ClpAesLightEngine,
  ClpIAesLightEngine,
  ClpBlowfishEngine,
  ClpIBlowfishEngine,
  ClpSpeckEngine,
  ClpISpeckEngine,
  ClpRijndaelEngine,
  ClpIRijndaelEngine,
  ClpKeyParameter,
  ClpIKeyParameter,
  ClpParametersWithIV,
  ClpIParametersWithIV,
  ClpBufferedBlockCipher,
  ClpIBufferedBlockCipher,
  ClpEncoders,
  ClpArrayUtils,
  ClpCryptoLibTypes;

type

  TCryptoLibTestCase = class abstract(TTestCase)

  end;

type

  /// <summary>
  /// a basic test that takes a cipher, key parameter, and an input and
  /// output string. This test wraps the engine in a buffered block cipher
  /// with padding disabled.
  /// </summary>
  TTestBlockCipherVector = class(TCryptoLibTestCase)
  private

    procedure DoBlockCipherVectorTest(const engine: IBlockCipher;
      const param: ICipherParameters; const input, output: String);

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published

    procedure TestBlockCipherAESEngine;
    procedure TestBlockCipherAESLightEngine;
    procedure TestBlockCipherBlowfishEngine;
    procedure TestBlockCipherSpeck32Engine;
    procedure TestBlockCipherSpeck48Engine;
    procedure TestBlockCipherSpeck64Engine;
    procedure TestBlockCipherSpeck96Engine;
    procedure TestBlockCipherSpeck128Engine;
    procedure TestBlockCipherRijndaelEngine;
    procedure TestBadParameters;

  end;

implementation

{ TTestBlockCipherVector }

procedure TTestBlockCipherVector.DoBlockCipherVectorTest
  (const engine: IBlockCipher; const param: ICipherParameters;
  const input, output: String);
var
  cipher: IBufferedBlockCipher;
  len1, len2: Int32;
  LInput, LOutput, outBytes: TBytes;
begin
  LInput := THex.Decode(input);
  LOutput := THex.Decode(output);

  cipher := TBufferedBlockCipher.Create(engine);

  cipher.Init(true, param);

  System.SetLength(outBytes, System.Length(LInput));

  len1 := cipher.ProcessBytes(LInput, 0, System.Length(LInput), outBytes, 0);

  cipher.DoFinal(outBytes, len1);

  if (not TArrayUtils.AreEqual(outBytes, LOutput)) then
  begin
    Fail(Format('Encryption Failed - Expected %s but got %s',
      [THex.Encode(LOutput), THex.Encode(outBytes)]));
  end;

  cipher.Init(false, param);

  len2 := cipher.ProcessBytes(LOutput, 0, System.Length(LOutput), outBytes, 0);

  cipher.DoFinal(outBytes, len2);

  if (not TArrayUtils.AreEqual(LInput, outBytes)) then
  begin
    Fail(Format('Decryption Failed - Expected %s but got %s',
      [THex.Encode(LInput), THex.Encode(outBytes)]));
  end;
end;

procedure TTestBlockCipherVector.SetUp;
begin
  inherited;
end;

procedure TTestBlockCipherVector.TearDown;
begin
  inherited;

end;

procedure TTestBlockCipherVector.TestBadParameters;
var
  dudKey, iv: TBytes;
  engine: IAesEngine;
  engine2: IAesLightEngine;
begin

  engine := TAesEngine.Create();
  //
  // init tests
  //

  try
    System.SetLength(dudKey, 6);
    engine.Init(true, TKeyParameter.Create(dudKey) as IKeyParameter);
    Fail('failed key length check');
  except
    on e: EArgumentCryptoLibException do
    begin
      // expected
    end;

  end;

  try
    System.SetLength(iv, 16);
    engine.Init(true, TParametersWithIV.Create(nil, iv) as IParametersWithIV);
    Fail('failed parameter check');
  except
    on e: EArgumentCryptoLibException do
    begin
      // expected
    end;

  end;

  engine2 := TAesLightEngine.Create();
  //
  // init tests
  //

  try
    System.SetLength(dudKey, 6);
    engine2.Init(true, TKeyParameter.Create(dudKey) as IKeyParameter);
    Fail('failed key length check');
  except
    on e: EArgumentCryptoLibException do
    begin
      // expected
    end;

  end;

  try
    System.SetLength(iv, 16);
    engine2.Init(true, TParametersWithIV.Create(nil, iv) as IParametersWithIV);
    Fail('failed parameter check');
  except
    on e: EArgumentCryptoLibException do
    begin
      // expected
    end;

  end;
end;

procedure TTestBlockCipherVector.TestBlockCipherAESEngine;
var
  I: Int32;
begin
  for I := System.Low(TAESTestVectors.FBlockCipherVectorKeys)
    to System.High(TAESTestVectors.FBlockCipherVectorKeys) do
  begin
    DoBlockCipherVectorTest(TAesEngine.Create() as IAesEngine,
      TKeyParameter.Create(THex.Decode(TAESTestVectors.FBlockCipherVectorKeys[I]
      )) as IKeyParameter, TAESTestVectors.FBlockCipherVectorInputs[I],
      TAESTestVectors.FBlockCipherVectorOutputs[I]);
  end;

end;

procedure TTestBlockCipherVector.TestBlockCipherAESLightEngine;
var
  I: Int32;
begin
  for I := System.Low(TAESTestVectors.FBlockCipherVectorKeys)
    to System.High(TAESTestVectors.FBlockCipherVectorKeys) do
  begin
    DoBlockCipherVectorTest(TAesLightEngine.Create() as IAesLightEngine,
      TKeyParameter.Create(THex.Decode(TAESTestVectors.FBlockCipherVectorKeys[I]
      )) as IKeyParameter, TAESTestVectors.FBlockCipherVectorInputs[I],
      TAESTestVectors.FBlockCipherVectorOutputs[I]);
  end;

end;

procedure TTestBlockCipherVector.TestBlockCipherBlowfishEngine;
var
  I: Int32;
begin
  for I := System.Low(TBlowfishTestVectors.FBlockCipherVectorKeys)
    to System.High(TBlowfishTestVectors.FBlockCipherVectorKeys) do
  begin
    DoBlockCipherVectorTest(TBlowfishEngine.Create() as IBlowfishEngine,
      TKeyParameter.Create
      (THex.Decode(TBlowfishTestVectors.FBlockCipherVectorKeys[I]))
      as IKeyParameter, TBlowfishTestVectors.FBlockCipherVectorInputs[I],
      TBlowfishTestVectors.FBlockCipherVectorOutputs[I]);
  end;

end;

procedure TTestBlockCipherVector.TestBlockCipherRijndaelEngine;
var
  I: Int32;
begin
  for I := System.Low(TRijndaelTestVectors.FBlockCipherVectorKeys)
    to System.High(TRijndaelTestVectors.FBlockCipherVectorKeys) do
  begin
    DoBlockCipherVectorTest
      (TRijndaelEngine.Create
      (StrToInt(TRijndaelTestVectors.FBlockCipherVectorBlockSizes[I]))
      as IRijndaelEngine,
      TKeyParameter.Create
      (THex.Decode(TRijndaelTestVectors.FBlockCipherVectorKeys[I]))
      as IKeyParameter, TRijndaelTestVectors.FBlockCipherVectorInputs[I],
      TRijndaelTestVectors.FBlockCipherVectorOutputs[I]);
  end;

end;

procedure TTestBlockCipherVector.TestBlockCipherSpeck32Engine;
var
  I: Int32;
begin
  for I := System.Low(TSpeckTestVectors.FSpeck32BlockCipherVectorKeys)
    to System.High(TSpeckTestVectors.FSpeck32BlockCipherVectorKeys) do
  begin
    DoBlockCipherVectorTest(TSpeck32Engine.Create() as ISpeckEngine,
      TKeyParameter.Create
      (THex.Decode(TSpeckTestVectors.FSpeck32BlockCipherVectorKeys[I]))
      as IKeyParameter, TSpeckTestVectors.FSpeck32BlockCipherVectorInputs[I],
      TSpeckTestVectors.FSpeck32BlockCipherVectorOutputs[I]);
  end;

end;

procedure TTestBlockCipherVector.TestBlockCipherSpeck48Engine;
var
  I: Int32;
begin
  for I := System.Low(TSpeckTestVectors.FSpeck48BlockCipherVectorKeys)
    to System.High(TSpeckTestVectors.FSpeck48BlockCipherVectorKeys) do
  begin
    DoBlockCipherVectorTest(TSpeck48Engine.Create() as ISpeckEngine,
      TKeyParameter.Create
      (THex.Decode(TSpeckTestVectors.FSpeck48BlockCipherVectorKeys[I]))
      as IKeyParameter, TSpeckTestVectors.FSpeck48BlockCipherVectorInputs[I],
      TSpeckTestVectors.FSpeck48BlockCipherVectorOutputs[I]);
  end;

end;

procedure TTestBlockCipherVector.TestBlockCipherSpeck64Engine;
var
  I: Int32;
begin
  for I := System.Low(TSpeckTestVectors.FSpeck64BlockCipherVectorKeys)
    to System.High(TSpeckTestVectors.FSpeck64BlockCipherVectorKeys) do
  begin
    DoBlockCipherVectorTest(TSpeck64Engine.Create() as ISpeckEngine,
      TKeyParameter.Create
      (THex.Decode(TSpeckTestVectors.FSpeck64BlockCipherVectorKeys[I]))
      as IKeyParameter, TSpeckTestVectors.FSpeck64BlockCipherVectorInputs[I],
      TSpeckTestVectors.FSpeck64BlockCipherVectorOutputs[I]);
  end;

end;

procedure TTestBlockCipherVector.TestBlockCipherSpeck96Engine;
var
  I: Int32;
begin
  for I := System.Low(TSpeckTestVectors.FSpeck96BlockCipherVectorKeys)
    to System.High(TSpeckTestVectors.FSpeck96BlockCipherVectorKeys) do
  begin
    DoBlockCipherVectorTest(TSpeck96Engine.Create() as ISpeckEngine,
      TKeyParameter.Create
      (THex.Decode(TSpeckTestVectors.FSpeck96BlockCipherVectorKeys[I]))
      as IKeyParameter, TSpeckTestVectors.FSpeck96BlockCipherVectorInputs[I],
      TSpeckTestVectors.FSpeck96BlockCipherVectorOutputs[I]);
  end;

end;

procedure TTestBlockCipherVector.TestBlockCipherSpeck128Engine;
var
  I: Int32;
begin
  for I := System.Low(TSpeckTestVectors.FSpeck128BlockCipherVectorKeys)
    to System.High(TSpeckTestVectors.FSpeck128BlockCipherVectorKeys) do
  begin
    DoBlockCipherVectorTest(TSpeck128Engine.Create() as ISpeckEngine,
      TKeyParameter.Create
      (THex.Decode(TSpeckTestVectors.FSpeck128BlockCipherVectorKeys[I]))
      as IKeyParameter, TSpeckTestVectors.FSpeck128BlockCipherVectorInputs[I],
      TSpeckTestVectors.FSpeck128BlockCipherVectorOutputs[I]);
  end;

end;

initialization

// Register any test cases with the test runner

{$IFDEF FPC}
  RegisterTest(TTestBlockCipherVector);
{$ELSE}
  RegisterTest(TTestBlockCipherVector.Suite);
{$ENDIF FPC}

end.
