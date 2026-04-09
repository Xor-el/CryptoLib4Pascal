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
  ClpAesUtilities,
  ClpIKeyParameter,
  ClpKeyParameter,
  ClpParametersWithIV,
  ClpIParametersWithIV,
  ClpIBufferedBlockCipher,
  ClpICipherParameters,
  ClpCbcBlockCipher,
  ClpCtsBlockCipher,
  ClpSicBlockCipher,
  ClpICbcBlockCipher,
  ClpICtsBlockCipher,
  ClpISicBlockCipher,
  ClpIBlockCipher,
  ClpCryptoLibTypes,
  CryptoLibTestBase;

type

  TTestCTS = class(TCryptoLibAlgorithmTestCase)
  private
  var
    FAes128, FAesIn1, FAesIn2, FAesIn3, FAesOut1, FAesOut2, FAesOut3,
      FZeroIV: TBytes;

    procedure DoCTSTest(AId: Int32; const ACipher: IBlockCipher;
      const AParams: ICipherParameters; const AInput, AOutput: TBytes);

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published

    procedure TestCTS;
    procedure TestExceptions;

  end;

implementation

{ TTestCTS }

procedure TTestCTS.DoCTSTest(AId: Int32; const ACipher: IBlockCipher;
  const AParams: ICipherParameters; const AInput, AOutput: TBytes);
var
  LOut: TBytes;
  LEngine: IBufferedBlockCipher;
  LLen: Int32;
begin
  System.SetLength(LOut, System.Length(AInput));

  LEngine := TCTSBlockCipher.Create(ACipher) as ICTSBlockCipher;

  LEngine.Init(True, AParams);

  LLen := LEngine.ProcessBytes(AInput, 0, System.Length(AInput), LOut, 0);

  LEngine.DoFinal(LOut, LLen);

  if not(AreEqual(AOutput, LOut)) then
  begin
    Fail(Format('Failed Encryption, ID %d Expected %s but got %s',
      [AId, EncodeHex(AOutput), EncodeHex(LOut)]));
  end;

  LEngine.Init(False, AParams);

  LLen := LEngine.ProcessBytes(AOutput, 0, System.Length(AOutput), LOut, 0);

  LEngine.DoFinal(LOut, LLen);

  if not(AreEqual(AInput, LOut)) then
  begin
    Fail(Format('Failed Decryption, ID %d Expected %s but got %s',
      [AId, EncodeHex(AInput), EncodeHex(LOut)]));
  end;
end;

procedure TTestCTS.SetUp;
begin
  inherited;
  FAes128 := DecodeHex('636869636B656E207465726979616B69');
  FAesIn1 := DecodeHex('4920776F756C64206C696B652074686520');
  FAesOut1 := DecodeHex('C6353568F2BF8CB4D8A580362DA7FF7F97');
  FAesIn2 := DecodeHex
    ('4920776F756C64206C696B65207468652047656E6572616C20476175277320');
  FAesOut2 := DecodeHex
    ('FC00783E0EFDB2C1D445D4C8EFF7ED2297687268D6ECCCC0C07B25E25ECFE5');
  FAesIn3 := DecodeHex
    ('4920776F756C64206C696B65207468652047656E6572616C2047617527732043');
  FAesOut3 := DecodeHex
    ('39312523A78662D5BE7FCBCC98EBF5A897687268D6ECCCC0C07B25E25ECFE584');
  System.SetLength(FZeroIV, 16);
end;

procedure TTestCTS.TearDown;
begin
  inherited;
end;

procedure TTestCTS.TestCTS;
begin
  DoCTSTest(1, TCbcBlockCipher.Create(TAesUtilities.CreateEngine())
    as ICBCBlockCipher, TParametersWithIV.Create(TKeyParameter.Create(FAes128)
    as IKeyParameter, FZeroIV) as IParametersWithIV, FAesIn1, FAesOut1);
  DoCTSTest(2, TCbcBlockCipher.Create(TAesUtilities.CreateEngine())
    as ICBCBlockCipher, TParametersWithIV.Create(TKeyParameter.Create(FAes128)
    as IKeyParameter, FZeroIV) as IParametersWithIV, FAesIn2, FAesOut2);
  DoCTSTest(3, TCbcBlockCipher.Create(TAesUtilities.CreateEngine())
    as ICBCBlockCipher, TParametersWithIV.Create(TKeyParameter.Create(FAes128)
    as IKeyParameter, FZeroIV) as IParametersWithIV, FAesIn3, FAesOut3);
end;

procedure TTestCTS.TestExceptions;
begin
  try
    TCTSBlockCipher.Create(TSicBlockCipher.Create(TAesUtilities.CreateEngine()) as ISicBlockCipher);
    Fail('Expected CTS construction error - only ECB/CBC supported.');
  except
    on e: EArgumentCryptoLibException do
    begin
      // expected
    end;
  end;
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestCTS);
{$ELSE}
  RegisterTest(TTestCTS.Suite);
{$ENDIF FPC}

end.
