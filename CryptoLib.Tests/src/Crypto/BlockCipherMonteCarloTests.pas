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

unit BlockCipherMonteCarloTests;

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
  ClpIBlockCipher,
  ClpICipherParameters,
  ClpAesEngine,
  ClpIAesEngine,
  ClpAesLightEngine,
  ClpIAesLightEngine,
  ClpKeyParameter,
  ClpIKeyParameter,
  ClpBufferedBlockCipher,
  ClpIBufferedBlockCipher,
  ClpHex,
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
  TTestBlockCipherMonteCarlo = class(TCryptoLibTestCase)
  private

    procedure DoBlockCipherMonteCarloTest(const iteration: string;
      const engine: IBlockCipher; const param: ICipherParameters;
      const input, output: String);

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published

    procedure TestBlockCipherAESEngine;
    procedure TestBlockCipherAESLightEngine;

  end;

implementation

{ TTestBlockCipherMonteCarlo }

procedure TTestBlockCipherMonteCarlo.DoBlockCipherMonteCarloTest(const iteration
  : string; const engine: IBlockCipher; const param: ICipherParameters;
  const input, output: String);
var
  cipher: IBufferedBlockCipher;
  len1, len2, i, iterations: Int32;
  LInput, LOutput, outBytes: TBytes;
begin
  LInput := THex.Decode(input);
  LOutput := THex.Decode(output);
  iterations := StrToInt(iteration);

  cipher := TBufferedBlockCipher.Create(engine);

  cipher.Init(true, param);

  System.SetLength(outBytes, System.Length(LInput));

  System.Move(LInput[0], outBytes[0], System.Length(outBytes) *
    System.SizeOf(Byte));

  i := 0;
  while i <> iterations do
  begin
    len1 := cipher.ProcessBytes(outBytes, 0, System.Length(outBytes),
      outBytes, 0);

    cipher.DoFinal(outBytes, len1);
    System.Inc(i);
  end;

  if (not TArrayUtils.AreEqual(outBytes, LOutput)) then
  begin
    Fail(Format('Encryption Failed - Expected %s but got %s',
      [THex.Encode(LOutput), THex.Encode(outBytes)]));
  end;

  cipher.Init(false, param);

  i := 0;
  while i <> iterations do
  begin
    len2 := cipher.ProcessBytes(outBytes, 0, System.Length(outBytes),
      outBytes, 0);

    cipher.DoFinal(outBytes, len2);
    System.Inc(i);
  end;

  if (not TArrayUtils.AreEqual(LInput, outBytes)) then
  begin
    Fail(Format('Decryption Failed - Expected %s but got %s',
      [THex.Encode(LInput), THex.Encode(outBytes)]));
  end;
end;

procedure TTestBlockCipherMonteCarlo.SetUp;
begin
  inherited;
end;

procedure TTestBlockCipherMonteCarlo.TearDown;
begin
  inherited;

end;

procedure TTestBlockCipherMonteCarlo.TestBlockCipherAESEngine;
var
  i: Int32;
begin
  for i := System.Low(TAESTestVectors.FBlockCipherMonteCarloKeys)
    to System.High(TAESTestVectors.FBlockCipherMonteCarloKeys) do
  begin
    DoBlockCipherMonteCarloTest(TAESTestVectors.FBlockCipherMonteCarloIterations
      [i], TAesEngine.Create() as IAesEngine,
      TKeyParameter.Create
      (THex.Decode(TAESTestVectors.FBlockCipherMonteCarloKeys[i]))
      as IKeyParameter, TAESTestVectors.FBlockCipherMonteCarloInputs[i],
      TAESTestVectors.FBlockCipherMonteCarloOutputs[i]);
  end;

end;

procedure TTestBlockCipherMonteCarlo.TestBlockCipherAESLightEngine;
var
  i: Int32;
begin
  for i := System.Low(TAESTestVectors.FBlockCipherMonteCarloKeys)
    to System.High(TAESTestVectors.FBlockCipherMonteCarloKeys) do
  begin
    DoBlockCipherMonteCarloTest(TAESTestVectors.FBlockCipherMonteCarloIterations
      [i], TAesLightEngine.Create() as IAesLightEngine,
      TKeyParameter.Create
      (THex.Decode(TAESTestVectors.FBlockCipherMonteCarloKeys[i]))
      as IKeyParameter, TAESTestVectors.FBlockCipherMonteCarloInputs[i],
      TAESTestVectors.FBlockCipherMonteCarloOutputs[i]);
  end;

end;

initialization

// Register any test cases with the test runner

{$IFDEF FPC}
  RegisterTest(TTestBlockCipherMonteCarlo);
{$ELSE}
  RegisterTest(TTestBlockCipherMonteCarlo.Suite);
{$ENDIF FPC}

end.
