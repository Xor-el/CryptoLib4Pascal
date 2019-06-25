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

unit CTSTests;

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
  ClpAesEngine,
  ClpIAesEngine,
  ClpIKeyParameter,
  ClpKeyParameter,
  ClpParametersWithIV,
  ClpIParametersWithIV,
  // ClpIBufferedCipher,
  ClpIBufferedBlockCipher,
  // ClpICipherKeyGenerator,
  ClpICipherParameters,
  // ClpGeneratorUtilities,
  // ClpParameterUtilities,
  // ClpCipherUtilities,
  // ClpNistObjectIdentifiers,
  ClpBlockCipherModes,
  ClpIBlockCipherModes,
  ClpIBlockCipher,
  // ClpBufferedBlockCipher,
  // ClpIBufferedBlockCipher,
  // ClpPaddedBufferedBlockCipher,
  // ClpIPaddedBufferedBlockCipher,
  // ClpPaddingModes,
  // ClpIPaddingModes,
  ClpCryptoLibTypes,
  CryptoLibTestBase;

type

  TTestCTS = class(TCryptoLibAlgorithmTestCase)
  private
  var
    Faes128, FaesIn1, FaesIn2, FaesIn3, FaesOut1, FaesOut2, FaesOut3,
      FZeroIV: TBytes;

    procedure DoCTSTest(id: Int32; const cipher: IBlockCipher;
      const params: ICipherParameters; const input, output: TBytes);

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published

    procedure TestCTS;
    procedure TestExceptions;

  end;

implementation

{ TTestCTS }

procedure TTestCTS.DoCTSTest(id: Int32; const cipher: IBlockCipher;
  const params: ICipherParameters; const input, output: TBytes);
var
  &out: TBytes;
  engine: IBufferedBlockCipher;
  len: Int32;
begin
  System.SetLength(&out, System.length(input));

  engine := TCTSBlockCipher.Create(cipher) as ICTSBlockCipher;

  engine.Init(true, params);

  len := engine.ProcessBytes(input, 0, System.length(input), &out, 0);

  engine.doFinal(&out, len);

  if not(AreEqual(output, &out)) then
  begin
    Fail(Format('Failed Encryption, ID %d Expected %s but got %s',
      [id, EncodeHex(output), EncodeHex(&out)]));
  end;

  engine.Init(false, params);

  len := engine.ProcessBytes(output, 0, System.length(output), &out, 0);

  engine.doFinal(&out, len);

  if not(AreEqual(input, &out)) then
  begin
    Fail(Format('Failed Decryption, ID %d Expected %s but got %s',
      [id, EncodeHex(input), EncodeHex(&out)]));
  end;
end;

procedure TTestCTS.SetUp;
begin
  inherited;
  //
  // test vectors from rfc3962
  //
  Faes128 := DecodeHex('636869636B656E207465726979616B69');
  FaesIn1 := DecodeHex('4920776F756C64206C696B652074686520');
  FaesOut1 := DecodeHex('C6353568F2BF8CB4D8A580362DA7FF7F97');
  FaesIn2 := DecodeHex
    ('4920776F756C64206C696B65207468652047656E6572616C20476175277320');
  FaesOut2 := DecodeHex
    ('FC00783E0EFDB2C1D445D4C8EFF7ED2297687268D6ECCCC0C07B25E25ECFE5');
  FaesIn3 := DecodeHex
    ('4920776F756C64206C696B65207468652047656E6572616C2047617527732043');
  FaesOut3 := DecodeHex
    ('39312523A78662D5BE7FCBCC98EBF5A897687268D6ECCCC0C07B25E25ECFE584');
  System.SetLength(FZeroIV, 16);
end;

procedure TTestCTS.TearDown;
begin
  inherited;

end;

procedure TTestCTS.TestCTS;
begin
  DoCTSTest(1, TCBCBlockCipher.Create(TAESEngine.Create() as IAESEngine)
    as ICBCBlockCipher, TParametersWithIV.Create(TKeyParameter.Create(Faes128)
    as IKeyParameter, FZeroIV) as IParametersWithIV, FaesIn1, FaesOut1);
  DoCTSTest(2, TCBCBlockCipher.Create(TAESEngine.Create() as IAESEngine)
    as ICBCBlockCipher, TParametersWithIV.Create(TKeyParameter.Create(Faes128)
    as IKeyParameter, FZeroIV) as IParametersWithIV, FaesIn2, FaesOut2);
  DoCTSTest(3, TCBCBlockCipher.Create(TAESEngine.Create() as IAESEngine)
    as ICBCBlockCipher, TParametersWithIV.Create(TKeyParameter.Create(Faes128)
    as IKeyParameter, FZeroIV) as IParametersWithIV, FaesIn3, FaesOut3);
end;

procedure TTestCTS.TestExceptions;
begin
  try
    TCTSBlockCipher.Create(TSICBlockCipher.Create(TAESEngine.Create()
      as IAESEngine) as ISICBlockCipher);
    Fail('Expected CTS construction error - only ECB/CBC supported.');
  except
    on e: EArgumentCryptoLibException do
    begin
      // expected
    end;
  end;
end;

initialization

// Register any test cases with the test runner

{$IFDEF FPC}
  RegisterTest(TTestCTS);
{$ELSE}
  RegisterTest(TTestCTS.Suite);
{$ENDIF FPC}

end.
