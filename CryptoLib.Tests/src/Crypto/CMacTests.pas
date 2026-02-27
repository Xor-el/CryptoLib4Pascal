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

unit CMacTests;

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
  ClpIMac,
  ClpICipherParameters,
  ClpAesEngine,
  ClpIAesEngine,
  ClpCMac,
  ClpICMac,
  ClpMacUtilities,
  ClpKeyParameter,
  ClpIKeyParameter,
  ClpParametersWithIV,
  ClpIParametersWithIV,
  ClpEncoders,
  ClpCryptoLibTypes,
  CryptoLibTestBase;

type

  TTestCMac = class(TCryptoLibAlgorithmTestCase)
  strict private
  class var
    FKeyBytes128, FKeyBytes192, FKeyBytes256: TBytes;
    FInput0, FInput16, FInput40, FInput64: TBytes;
    FOutput_k128_m0, FOutput_k128_m16, FOutput_k128_m40, FOutput_k128_m64: TBytes;
    FOutput_k192_m0, FOutput_k192_m16, FOutput_k192_m40, FOutput_k192_m64: TBytes;
    FOutput_k256_m0, FOutput_k256_m16, FOutput_k256_m40, FOutput_k256_m64: TBytes;
    FOutputDesEde: TBytes;

    class constructor CreateTestCMac;

  private
    procedure CheckEqual(const AName: string; const AExpected, AActual: TBytes);

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  published
    // AES CMAC tests (official vectors)
    procedure TestAesCmac128_Key128_Empty;
    procedure TestAesCmac128_Key128_M16;
    procedure TestAesCmac128_Key128_M40;
    procedure TestAesCmac128_Key128_M64;

    procedure TestAesCmac128_Key192_Empty;
    procedure TestAesCmac128_Key192_M16;
    procedure TestAesCmac128_Key192_M40;
    procedure TestAesCmac128_Key192_M64;

    procedure TestAesCmac128_Key256_Empty;
    procedure TestAesCmac128_Key256_M16;
    procedure TestAesCmac128_Key256_M40;
    procedure TestAesCmac128_Key256_M64;

    // DESede CMAC test from C# SimpleTest version (if available)
    procedure TestDesEdeCmac_Empty;

    // Exception behaviour: CMac must not accept IV parameters
    procedure TestCMacDoesNotAcceptIv;

  end;

implementation

{ TTestCMac }

class constructor TTestCMac.CreateTestCMac;
begin
  FKeyBytes128 := THexEncoder.Decode('2b7e151628aed2a6abf7158809cf4f3c');
  FKeyBytes192 := THexEncoder.Decode(
    '8e73b0f7da0e6452c810f32b809079e5' +
    '62f8ead2522c6b7b');
  FKeyBytes256 := THexEncoder.Decode(
    '603deb1015ca71be2b73aef0857d7781' +
    '1f352c073b6108d72d9810a30914dff4');

  FInput0 := THexEncoder.Decode('');
  FInput16 := THexEncoder.Decode('6bc1bee22e409f96e93d7e117393172a');
  FInput40 := THexEncoder.Decode(
    '6bc1bee22e409f96e93d7e117393172a' +
    'ae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411');
  FInput64 := THexEncoder.Decode(
    '6bc1bee22e409f96e93d7e117393172a' +
    'ae2d8a571e03ac9c9eb76fac45af8e51' +
    '30c81c46a35ce411e5fbc1191a0a52ef' +
    'f69f2445df4f9b17ad2b417be66c3710');

  FOutput_k128_m0 := THexEncoder.Decode('bb1d6929e95937287fa37d129b756746');
  FOutput_k128_m16 := THexEncoder.Decode('070a16b46b4d4144f79bdd9dd04a287c');
  FOutput_k128_m40 := THexEncoder.Decode('dfa66747de9ae63030ca32611497c827');
  FOutput_k128_m64 := THexEncoder.Decode('51f0bebf7e3b9d92fc49741779363cfe');

  FOutput_k192_m0 := THexEncoder.Decode('d17ddf46adaacde531cac483de7a9367');
  FOutput_k192_m16 := THexEncoder.Decode('9e99a7bf31e710900662f65e617c5184');
  FOutput_k192_m40 := THexEncoder.Decode('8a1de5be2eb31aad089a82e6ee908b0e');
  FOutput_k192_m64 := THexEncoder.Decode('a1d5df0eed790f794d77589659f39a11');

  FOutput_k256_m0 := THexEncoder.Decode('028962f61b7bf89efc6b551f4667d983');
  FOutput_k256_m16 := THexEncoder.Decode('28a7023f452e8f82bd4bf28d8c37c35c');
  FOutput_k256_m40 := THexEncoder.Decode('aaf3d8f1de5640c232f5b169b9c911e6');
  FOutput_k256_m64 := THexEncoder.Decode('e1992190549f6ed5696a2c056c315410');

  FOutputDesEde := THexEncoder.Decode('1ca670dea381d37c');
end;

procedure TTestCMac.CheckEqual(const AName: string; const AExpected,
  AActual: TBytes);
begin
  if not AreEqual(AExpected, AActual) then
  begin
    Fail(Format('%s Failed - expected %s got %s',
      [AName, EncodeHex(AExpected), EncodeHex(AActual)]));
  end;
end;

procedure TTestCMac.SetUp;
begin
  inherited;
end;

procedure TTestCMac.TearDown;
begin
  inherited;
end;

procedure TTestCMac.TestAesCmac128_Key128_Empty;
var
  LMac: IMac;
  LKey: IKeyParameter;
  LOut: TBytes;
begin
  LMac := TMacUtilities.GetMac('AESCMAC');
  LKey := TKeyParameter.Create(FKeyBytes128) as IKeyParameter;

  LMac.Init(LKey);
  LMac.BlockUpdate(FInput0, 0, Length(FInput0));

  SetLength(LOut, LMac.GetMacSize);
  LMac.DoFinal(LOut, 0);

  CheckEqual('CMac-AES-128-m0', FOutput_k128_m0, LOut);
end;

procedure TTestCMac.TestAesCmac128_Key128_M16;
var
  LMac: IMac;
  LKey: IKeyParameter;
  LOut: TBytes;
begin
  LMac := TMacUtilities.GetMac('AESCMAC');
  LKey := TKeyParameter.Create(FKeyBytes128) as IKeyParameter;

  LMac.Init(LKey);
  LMac.BlockUpdate(FInput16, 0, Length(FInput16));

  SetLength(LOut, LMac.GetMacSize);
  LMac.DoFinal(LOut, 0);

  CheckEqual('CMac-AES-128-m16', FOutput_k128_m16, LOut);
end;

procedure TTestCMac.TestAesCmac128_Key128_M40;
var
  LMac: IMac;
  LKey: IKeyParameter;
  LOut: TBytes;
begin
  LMac := TMacUtilities.GetMac('AESCMAC');
  LKey := TKeyParameter.Create(FKeyBytes128) as IKeyParameter;

  LMac.Init(LKey);
  LMac.BlockUpdate(FInput40, 0, Length(FInput40));

  SetLength(LOut, LMac.GetMacSize);
  LMac.DoFinal(LOut, 0);

  CheckEqual('CMac-AES-128-m40', FOutput_k128_m40, LOut);
end;

procedure TTestCMac.TestAesCmac128_Key128_M64;
var
  LMac: IMac;
  LKey: IKeyParameter;
  LOut: TBytes;
begin
  LMac := TMacUtilities.GetMac('AESCMAC');
  LKey := TKeyParameter.Create(FKeyBytes128) as IKeyParameter;

  LMac.Init(LKey);
  LMac.BlockUpdate(FInput64, 0, Length(FInput64));

  SetLength(LOut, LMac.GetMacSize);
  LMac.DoFinal(LOut, 0);

  CheckEqual('CMac-AES-128-m64', FOutput_k128_m64, LOut);
end;

procedure TTestCMac.TestAesCmac128_Key192_Empty;
var
  LMac: IMac;
  LKey: IKeyParameter;
  LOut: TBytes;
begin
  LMac := TMacUtilities.GetMac('AESCMAC');
  LKey := TKeyParameter.Create(FKeyBytes192) as IKeyParameter;

  LMac.Init(LKey);
  LMac.BlockUpdate(FInput0, 0, Length(FInput0));

  SetLength(LOut, LMac.GetMacSize);
  LMac.DoFinal(LOut, 0);

  CheckEqual('CMac-AES-192-m0', FOutput_k192_m0, LOut);
end;

procedure TTestCMac.TestAesCmac128_Key192_M16;
var
  LMac: IMac;
  LKey: IKeyParameter;
  LOut: TBytes;
begin
  LMac := TMacUtilities.GetMac('AESCMAC');
  LKey := TKeyParameter.Create(FKeyBytes192) as IKeyParameter;

  LMac.Init(LKey);
  LMac.BlockUpdate(FInput16, 0, Length(FInput16));

  SetLength(LOut, LMac.GetMacSize);
  LMac.DoFinal(LOut, 0);

  CheckEqual('CMac-AES-192-m16', FOutput_k192_m16, LOut);
end;

procedure TTestCMac.TestAesCmac128_Key192_M40;
var
  LMac: IMac;
  LKey: IKeyParameter;
  LOut: TBytes;
begin
  LMac := TMacUtilities.GetMac('AESCMAC');
  LKey := TKeyParameter.Create(FKeyBytes192) as IKeyParameter;

  LMac.Init(LKey);
  LMac.BlockUpdate(FInput40, 0, Length(FInput40));

  SetLength(LOut, LMac.GetMacSize);
  LMac.DoFinal(LOut, 0);

  CheckEqual('CMac-AES-192-m40', FOutput_k192_m40, LOut);
end;

procedure TTestCMac.TestAesCmac128_Key192_M64;
var
  LMac: IMac;
  LKey: IKeyParameter;
  LOut: TBytes;
begin
  LMac := TMacUtilities.GetMac('AESCMAC');
  LKey := TKeyParameter.Create(FKeyBytes192) as IKeyParameter;

  LMac.Init(LKey);
  LMac.BlockUpdate(FInput64, 0, Length(FInput64));

  SetLength(LOut, LMac.GetMacSize);
  LMac.DoFinal(LOut, 0);

  CheckEqual('CMac-AES-192-m64', FOutput_k192_m64, LOut);
end;

procedure TTestCMac.TestAesCmac128_Key256_Empty;
var
  LMac: IMac;
  LKey: IKeyParameter;
  LOut: TBytes;
begin
  LMac := TMacUtilities.GetMac('AESCMAC');
  LKey := TKeyParameter.Create(FKeyBytes256) as IKeyParameter;

  LMac.Init(LKey);
  LMac.BlockUpdate(FInput0, 0, Length(FInput0));

  SetLength(LOut, LMac.GetMacSize);
  LMac.DoFinal(LOut, 0);

  CheckEqual('CMac-AES-256-m0', FOutput_k256_m0, LOut);
end;

procedure TTestCMac.TestAesCmac128_Key256_M16;
var
  LMac: IMac;
  LKey: IKeyParameter;
  LOut: TBytes;
begin
  LMac := TMacUtilities.GetMac('AESCMAC');
  LKey := TKeyParameter.Create(FKeyBytes256) as IKeyParameter;

  LMac.Init(LKey);
  LMac.BlockUpdate(FInput16, 0, Length(FInput16));

  SetLength(LOut, LMac.GetMacSize);
  LMac.DoFinal(LOut, 0);

  CheckEqual('CMac-AES-256-m16', FOutput_k256_m16, LOut);
end;

procedure TTestCMac.TestAesCmac128_Key256_M40;
var
  LMac: IMac;
  LKey: IKeyParameter;
  LOut: TBytes;
begin
  LMac := TMacUtilities.GetMac('AESCMAC');
  LKey := TKeyParameter.Create(FKeyBytes256) as IKeyParameter;

  LMac.Init(LKey);
  LMac.BlockUpdate(FInput40, 0, Length(FInput40));

  SetLength(LOut, LMac.GetMacSize);
  LMac.DoFinal(LOut, 0);

  CheckEqual('CMac-AES-256-m40', FOutput_k256_m40, LOut);
end;

procedure TTestCMac.TestAesCmac128_Key256_M64;
var
  LMac: IMac;
  LKey: IKeyParameter;
  LOut: TBytes;
begin
  LMac := TMacUtilities.GetMac('AESCMAC');
  LKey := TKeyParameter.Create(FKeyBytes256) as IKeyParameter;

  LMac.Init(LKey);
  LMac.BlockUpdate(FInput64, 0, Length(FInput64));

  SetLength(LOut, LMac.GetMacSize);
  LMac.DoFinal(LOut, 0);

  CheckEqual('CMac-AES-256-m64', FOutput_k256_m64, LOut);
end;

procedure TTestCMac.TestDesEdeCmac_Empty;
var
  LMac: IMac;
  LKey: IKeyParameter;
  LOut: TBytes;
begin
  try
    LMac := TMacUtilities.GetMac('DESedeCMAC');
  except
    on E: ESecurityUtilityCryptoLibException do
    begin
      // Algorithm not available; this vector is effectively unported.
      Exit;
    end;
  end;

  LKey := TKeyParameter.Create(FKeyBytes128) as IKeyParameter;

  LMac.Init(LKey);
  LMac.BlockUpdate(FInput0, 0, Length(FInput0));

  SetLength(LOut, LMac.GetMacSize);
  LMac.DoFinal(LOut, 0);

  CheckEqual('CMac-DESede-m0', FOutputDesEde, LOut);
end;

procedure TTestCMac.TestCMacDoesNotAcceptIv;
var
  LEngine: IAesEngine;
  LMac: ICMac;
  LParamsWithIv: IParametersWithIV;
begin
  LEngine := TAesEngine.Create();
  LMac := TCMac.Create(LEngine) as ICMac;

  LParamsWithIv := TParametersWithIV.Create(TKeyParameter.Create
    (TBytes.Create(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)) as IKeyParameter,
    TBytes.Create(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0));

  try
    LMac.Init(LParamsWithIv as ICipherParameters);
    Fail('CMac does not accept IV');
  except
    on E: EArgumentCryptoLibException do
    begin
      // expected
    end;
  end;
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestCMac);
{$ELSE}
  RegisterTest(TTestCMac.Suite);
{$ENDIF FPC}

end.

