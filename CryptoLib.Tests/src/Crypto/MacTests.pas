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

unit MacTests;

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
  ClpIBlockCipher,
  ClpAesEngine,
  ClpIMac,
  ClpICipherParameters,
  ClpCbcBlockCipherMac,
  ClpCfbBlockCipherMac,
  ClpKeyParameter,
  ClpIKeyParameter,
  ClpParametersWithIV,
  ClpIParametersWithIV,
  ClpPkcs7Padding,
  ClpIPkcs7Padding,
  ClpCryptoLibTypes,
  ClpEncoders,
  CryptoLibTestBase;

type

  TTestMac = class(TCryptoLibAlgorithmTestCase)
  strict private
  class var
    FKeyBytes, FIVBytes, FInput1, FOutput1, FOutput2, FOutput3,
    FInput2, FOutput4, FOutput5, FOutput6: TBytes;

    class constructor CreateTestMac;

  private
    function CreateCipherEngine(): IBlockCipher;
    procedure CheckEqual(const AName: string; const AExpected, AActual: TBytes);

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  published
    procedure TestCbcMacZeroIv;
    procedure TestCbcMacWithIv;
    procedure TestCfbMacWithIv;
    procedure TestCfbMacWordAlignedZeroIv;
    procedure TestCbcMacWordAlignedZeroIvWithPadding;
    procedure TestCbcMacNonWordAlignedZeroIvWithPaddingReset;
    procedure TestCbcMacNonWordAlignedZeroIvWithPaddingReinit;

  end;

implementation

{ TTestMac }

function TTestMac.CreateCipherEngine: IBlockCipher;
begin
  Result := TAesEngine.Create();
end;

class constructor TTestMac.CreateTestMac;
begin
  FKeyBytes := THexEncoder.Decode('0123456789abcdef0123456789abcdef');
  FIVBytes := THexEncoder.Decode('0123456789abcdef0123456789abcdef');

  FInput1 := THexEncoder.Decode
    ('37363534333231204e6f77206973207468652074696d6520666f7220');
  FInput2 := THexEncoder.Decode('3736353433323120');

  FOutput1 := THexEncoder.Decode('87da3587b2649e3c');
  FOutput2 := THexEncoder.Decode('75c39f271779ecae');
  FOutput3 := THexEncoder.Decode('5e6d6068c932b7e2');
  FOutput4 := THexEncoder.Decode('36736dd41cfc49d4');
  FOutput5 := THexEncoder.Decode('0376f977de2166d1');
  FOutput6 := THexEncoder.Decode('f338ed02ba54413f');
end;

procedure TTestMac.CheckEqual(const AName: string; const AExpected,
  AActual: TBytes);
begin
  if not AreEqual(AExpected, AActual) then
  begin
    Fail(Format('%s Failed - expected %s got %s',
      [AName, EncodeHex(AExpected), EncodeHex(AActual)]));
  end;
end;

procedure TTestMac.SetUp;
begin
  inherited;
end;

procedure TTestMac.TearDown;
begin
  inherited;
end;

procedure TTestMac.TestCbcMacZeroIv;
var
  LKey: IKeyParameter;
  LCipher: IBlockCipher;
  LMac: IMac;
  LOutBytes: TBytes;
begin
  LKey := TKeyParameter.Create(FKeyBytes);
  LCipher := CreateCipherEngine();
  LMac := TCbcBlockCipherMac.Create(LCipher);

  LMac.Init(LKey);
  LMac.BlockUpdate(FInput1, 0, Length(FInput1));

  SetLength(LOutBytes, 8);
  LMac.DoFinal(LOutBytes, 0);

  CheckEqual('IMac-Cbc-ZeroIv', FOutput1, LOutBytes);
end;

procedure TTestMac.TestCbcMacWithIv;
var
  LKey: IKeyParameter;
  LCipher: IBlockCipher;
  LMac: IMac;
  LParam: IParametersWithIV;
  LOutBytes: TBytes;
begin
  LKey := TKeyParameter.Create(FKeyBytes);
  LCipher := CreateCipherEngine();
  LMac := TCbcBlockCipherMac.Create(LCipher);

  LParam := TParametersWithIV.Create(LKey, FIVBytes);
  LMac.Init(LParam as ICipherParameters);

  LMac.BlockUpdate(FInput1, 0, Length(FInput1));

  SetLength(LOutBytes, 8);
  LMac.DoFinal(LOutBytes, 0);

  CheckEqual('IMac-Cbc-WithIv', FOutput2, LOutBytes);
end;

procedure TTestMac.TestCfbMacWithIv;
var
  LKey: IKeyParameter;
  LCipher: IBlockCipher;
  LMac: IMac;
  LParam: IParametersWithIV;
  LOutBytes: TBytes;
begin
  LKey := TKeyParameter.Create(FKeyBytes);
  LCipher := CreateCipherEngine();
  LMac := TCfbBlockCipherMac.Create(LCipher);

  LParam := TParametersWithIV.Create(LKey, FIVBytes);
  LMac.Init(LParam as ICipherParameters);

  LMac.BlockUpdate(FInput1, 0, Length(FInput1));

  SetLength(LOutBytes, 8);
  LMac.DoFinal(LOutBytes, 0);

  CheckEqual('IMac-Cfb-WithIv', FOutput3, LOutBytes);
end;

procedure TTestMac.TestCfbMacWordAlignedZeroIv;
var
  LKey: IKeyParameter;
  LCipher: IBlockCipher;
  LMac: IMac;
  LOutBytes: TBytes;
begin
  LKey := TKeyParameter.Create(FKeyBytes);
  LCipher := CreateCipherEngine();
  LMac := TCfbBlockCipherMac.Create(LCipher);

  LMac.Init(LKey);
  LMac.BlockUpdate(FInput2, 0, Length(FInput2));

  SetLength(LOutBytes, 8);
  LMac.DoFinal(LOutBytes, 0);

  CheckEqual('IMac-Cfb-WordAligned-ZeroIv', FOutput4, LOutBytes);
end;

procedure TTestMac.TestCbcMacWordAlignedZeroIvWithPadding;
var
  LKey: IKeyParameter;
  LCipher: IBlockCipher;
  LPadding: IPkcs7Padding;
  LMac: IMac;
  LOutBytes: TBytes;
begin
  LKey := TKeyParameter.Create(FKeyBytes);
  LCipher := CreateCipherEngine();
  LPadding := TPkcs7Padding.Create();
  LMac := TCbcBlockCipherMac.Create(LCipher, LPadding);

  LMac.Init(LKey);
  LMac.BlockUpdate(FInput2, 0, Length(FInput2));

  SetLength(LOutBytes, 8);
  LMac.DoFinal(LOutBytes, 0);

  CheckEqual('IMac-Cbc-WordAligned-ZeroIv-Padding', FOutput5, LOutBytes);
end;

procedure TTestMac.TestCbcMacNonWordAlignedZeroIvWithPaddingReset;
var
  LKey: IKeyParameter;
  LCipher: IBlockCipher;
  LPadding: IPkcs7Padding;
  LMac: IMac;
  LOutBytes: TBytes;
begin
  LKey := TKeyParameter.Create(FKeyBytes);
  LCipher := CreateCipherEngine();
  LPadding := TPkcs7Padding.Create();
  LMac := TCbcBlockCipherMac.Create(LCipher, LPadding);

  LMac.Init(LKey);
  LMac.BlockUpdate(FInput2, 0, Length(FInput2));

  SetLength(LOutBytes, 8);
  LMac.DoFinal(LOutBytes, 0);
  CheckEqual('IMac-Cbc-WordAligned-ZeroIv-Padding-Reset-Base', FOutput5,
    LOutBytes);

  // now reset and feed non-word-aligned input1
  LMac.Reset;
  LMac.BlockUpdate(FInput1, 0, Length(FInput1));

  SetLength(LOutBytes, 8);
  LMac.DoFinal(LOutBytes, 0);

  CheckEqual('IMac-Cbc-NonWordAligned-ZeroIv-Padding-Reset', FOutput6, LOutBytes);
end;

procedure TTestMac.TestCbcMacNonWordAlignedZeroIvWithPaddingReinit;
var
  LKey: IKeyParameter;
  LCipher: IBlockCipher;
  LPadding: IPkcs7Padding;
  LMac: IMac;
  LOutBytes: TBytes;
begin
  LKey := TKeyParameter.Create(FKeyBytes);
  LCipher := CreateCipherEngine();
  LPadding := TPkcs7Padding.Create();
  LMac := TCbcBlockCipherMac.Create(LCipher, LPadding);

  LMac.Init(LKey);
  LMac.BlockUpdate(FInput1, 0, Length(FInput1));

  SetLength(LOutBytes, 8);
  LMac.DoFinal(LOutBytes, 0);

  CheckEqual('IMac-Cbc-NonWordAligned-ZeroIv-Padding-Reinit', FOutput6,
    LOutBytes);
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestMac);
{$ELSE}
  RegisterTest(TTestMac.Suite);
{$ENDIF FPC}

end.

