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
  ClpISecureRandom,
  CryptoLibTestBase;

type

  TCryptoLibTestCase = class abstract(TTestCase)

  end;

type
{$SCOPEDENUMS ON}
  TCipherEngine = (Salsa20Engine, XSalsa20Engine, ChaChaEngine);
{$SCOPEDENUMS OFF}

type

  /// <summary>
  /// Test whether block ciphers implement reset contract on init,
  /// encrypt/decrypt and reset.
  /// </summary>
  TTestStreamCipherReset = class(TCryptoLibAlgorithmTestCase)
  private
  var
    FSecureRandom: ISecureRandom;

    procedure DoCheckReset(const cipher: IStreamCipher;
      const cipherParams: ICipherParameters; encrypt: Boolean;
      const pretext, posttext: TBytes);

    function DoMake(CipherEngine: TCipherEngine): IStreamCipher;

    function DoRandom(size: Int32): TBytes;
    procedure DoTestReset(CipherEngine: TCipherEngine;
      KeyLen, IVLen: Int32); overload;
    procedure DoTestReset(const cipher1, cipher2: IStreamCipher;
      const cipherParams: ICipherParameters); overload;

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published

    procedure TestReset;

  end;

implementation

{ TTestStreamCipherReset }

procedure TTestStreamCipherReset.DoCheckReset(const cipher: IStreamCipher;
  const cipherParams: ICipherParameters; encrypt: Boolean;
  const pretext, posttext: TBytes);
var
  output: TBytes;
begin
  // Do initial run
  System.SetLength(output, System.Length(posttext));
  cipher.ProcessBytes(pretext, 0, System.Length(pretext), output, 0);

  // Check encrypt resets cipher
  cipher.Init(encrypt, cipherParams);
  try
    cipher.ProcessBytes(pretext, 0, System.Length(pretext), output, 0);
  except
    on e: Exception do
    begin
      Fail(Format('%s init did not reset: %s', [cipher.AlgorithmName,
        e.Message]));
    end;

  end;

  if not(AreEqual(output, posttext)) then
  begin
    Fail(Format('%s init did not reset. Expected %s But Got %s',
      [cipher.AlgorithmName, EncodeHex(posttext), EncodeHex(output)]));
  end;

  // Check reset resets data
  cipher.Reset();

  try
    cipher.ProcessBytes(pretext, 0, System.Length(pretext), output, 0);
  except
    on e: Exception do
    begin
      Fail(Format('%s reset did not reset: ', [cipher.AlgorithmName,
        e.Message]));
    end;

  end;

  if not(AreEqual(output, posttext)) then
  begin
    Fail(Format('%s init did not reset.', [cipher.AlgorithmName]));
  end;

  //
  // try
  // {
  // cipher.ProcessBytes(pretext, 0, pretext.Length, output, 0);
  // }
  // catch (Exception e)
  // {
  // Fail(cipher.AlgorithmName + " reset did not reset: " + e.Message);
  // }
  // if (!Arrays.AreEqual(output, posttext))
  // {
  // Fail(cipher.AlgorithmName + " reset did not reset.");
  // }
end;

function TTestStreamCipherReset.DoMake(CipherEngine: TCipherEngine)
  : IStreamCipher;
begin
  case CipherEngine of
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

function TTestStreamCipherReset.DoRandom(size: Int32): TBytes;
begin
  Result := TSecureRandom.GetNextBytes(FSecureRandom, size);
end;

procedure TTestStreamCipherReset.DoTestReset(CipherEngine: TCipherEngine;
  KeyLen, IVLen: Int32);
begin
  DoTestReset(DoMake(CipherEngine), DoMake(CipherEngine),
    TParametersWithIV.Create(TKeyParameter.Create(DoRandom(KeyLen))
    as IKeyParameter, DoRandom(IVLen)) as IParametersWithIV);
end;

procedure TTestStreamCipherReset.DoTestReset(const cipher1,
  cipher2: IStreamCipher; const cipherParams: ICipherParameters);
var
  plaintext, ciphertext: TBytes;
begin
  cipher1.Init(true, cipherParams);
  System.SetLength(plaintext, 1023);
  System.SetLength(ciphertext, System.Length(plaintext));

  // Establish baseline answer
  cipher1.ProcessBytes(plaintext, 0, System.Length(plaintext), ciphertext, 0);

  // Test encryption resets
  DoCheckReset(cipher1, cipherParams, true, plaintext, ciphertext);

  // Test decryption resets with fresh instance
  cipher2.Init(false, cipherParams);
  DoCheckReset(cipher2, cipherParams, false, ciphertext, plaintext);
end;

procedure TTestStreamCipherReset.SetUp;
begin
  inherited;
  FSecureRandom := TSecureRandom.Create();
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
