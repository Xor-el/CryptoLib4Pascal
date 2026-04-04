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

unit StreamCipherResetTests;

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
  ClpSalsa20Engine,
  ClpISalsa20Engine,
  ClpXSalsa20Engine,
  ClpIXSalsa20Engine,
  ClpChaChaEngine,
  ClpIChaChaEngine,
  ClpIStreamCipher,
  ClpICipherParameters,
  ClpKeyParameter,
  ClpIKeyParameter,
  ClpParametersWithIV,
  ClpIParametersWithIV,
  ClpSecureRandom,
  ClpCryptoServicesRegistrar,
  ClpISecureRandom,
  CryptoLibTestBase;

type
{$SCOPEDENUMS ON}
  TCipherEngine = (Salsa20Engine, XSalsa20Engine, ChaChaEngine);
{$SCOPEDENUMS OFF}

type

  /// <summary>
  /// Test whether stream ciphers implement reset contract on init,
  /// encrypt/decrypt and reset.
  /// </summary>
  TTestStreamCipherReset = class(TCryptoLibAlgorithmTestCase)
  private
  var
    FSecureRandom: ISecureRandom;

    procedure DoCheckReset(const ACipher: IStreamCipher;
      const ACipherParams: ICipherParameters; AEncrypt: Boolean;
      const APretext, APosttext: TBytes);

    function DoMake(ACipherEngine: TCipherEngine): IStreamCipher;

    function DoRandom(ASize: Int32): TBytes;
    procedure DoTestReset(ACipherEngine: TCipherEngine;
      AKeyLen, AIvLen: Int32); overload;
    procedure DoTestReset(const ACipher1, ACipher2: IStreamCipher;
      const ACipherParams: ICipherParameters); overload;

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published

    procedure TestReset;

  end;

implementation

{ TTestStreamCipherReset }

procedure TTestStreamCipherReset.DoCheckReset(const ACipher: IStreamCipher;
  const ACipherParams: ICipherParameters; AEncrypt: Boolean;
  const APretext, APosttext: TBytes);
var
  LOutput: TBytes;
begin
  // Do initial run
  System.SetLength(LOutput, System.Length(APosttext));
  ACipher.ProcessBytes(APretext, 0, System.Length(APretext), LOutput, 0);

  // Check encrypt resets cipher
  ACipher.Init(AEncrypt, ACipherParams);
  try
    ACipher.ProcessBytes(APretext, 0, System.Length(APretext), LOutput, 0);
  except
    on E: Exception do
    begin
      Fail(Format('%s init did not reset: %s', [ACipher.AlgorithmName,
        E.Message]));
    end;
  end;

  if not(AreEqual(LOutput, APosttext)) then
  begin
    Fail(Format('%s init did not reset. Expected %s But Got %s',
      [ACipher.AlgorithmName, EncodeHex(APosttext), EncodeHex(LOutput)]));
  end;

  // Check reset resets data
  ACipher.Reset();

  try
    ACipher.ProcessBytes(APretext, 0, System.Length(APretext), LOutput, 0);
  except
    on E: Exception do
    begin
      Fail(Format('%s reset did not reset: %s', [ACipher.AlgorithmName,
        E.Message]));
    end;
  end;

  if not(AreEqual(LOutput, APosttext)) then
  begin
    Fail(Format('%s reset did not reset.', [ACipher.AlgorithmName]));
  end;
end;

function TTestStreamCipherReset.DoMake(ACipherEngine: TCipherEngine)
  : IStreamCipher;
begin
  case ACipherEngine of
    TCipherEngine.Salsa20Engine:
      Result := TSalsa20Engine.Create() as ISalsa20Engine;
    TCipherEngine.XSalsa20Engine:
      Result := TXSalsa20Engine.Create() as IXSalsa20Engine;
    TCipherEngine.ChaChaEngine:
      Result := TChaChaEngine.Create() as IChaChaEngine
  else
    begin
      raise Exception.Create('Unsupported Cipher Engine');
    end;
  end;
end;

function TTestStreamCipherReset.DoRandom(ASize: Int32): TBytes;
begin
  Result := TSecureRandom.GetNextBytes(FSecureRandom, ASize);
end;

procedure TTestStreamCipherReset.DoTestReset(ACipherEngine: TCipherEngine;
  AKeyLen, AIvLen: Int32);
begin
  DoTestReset(DoMake(ACipherEngine), DoMake(ACipherEngine),
    TParametersWithIV.Create(TKeyParameter.Create(DoRandom(AKeyLen))
    as IKeyParameter, DoRandom(AIvLen)) as IParametersWithIV);
end;

procedure TTestStreamCipherReset.DoTestReset(const ACipher1,
  ACipher2: IStreamCipher; const ACipherParams: ICipherParameters);
var
  LPlaintext, LCiphertext: TBytes;
begin
  ACipher1.Init(true, ACipherParams);
  System.SetLength(LPlaintext, 1023);
  System.SetLength(LCiphertext, System.Length(LPlaintext));

  // Establish baseline answer
  ACipher1.ProcessBytes(LPlaintext, 0, System.Length(LPlaintext), LCiphertext, 0);

  // Test encryption resets
  DoCheckReset(ACipher1, ACipherParams, true, LPlaintext, LCiphertext);

  // Test decryption resets with fresh instance
  ACipher2.Init(false, ACipherParams);
  DoCheckReset(ACipher2, ACipherParams, false, LCiphertext, LPlaintext);
end;

procedure TTestStreamCipherReset.SetUp;
begin
  inherited;
  FSecureRandom := TCryptoServicesRegistrar.GetSecureRandom();
end;

procedure TTestStreamCipherReset.TearDown;
begin
  inherited;
end;

procedure TTestStreamCipherReset.TestReset;
begin
  DoTestReset(TCipherEngine.Salsa20Engine, 32, 8);
  DoTestReset(TCipherEngine.Salsa20Engine, 16, 8);
  DoTestReset(TCipherEngine.XSalsa20Engine, 32, 24);
  DoTestReset(TCipherEngine.ChaChaEngine, 32, 8);
  DoTestReset(TCipherEngine.ChaChaEngine, 16, 8);
end;

initialization

// Register any test cases with the test runner

{$IFDEF FPC}
  RegisterTest(TTestStreamCipherReset);
{$ELSE}
  RegisterTest(TTestStreamCipherReset.Suite);
{$ENDIF FPC}

end.
