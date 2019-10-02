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

unit KMacTests;

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
  ClpKeyParameter,
  ClpIKeyParameter,
  ClpKMac,
  ClpIMac,
  ClpConverters,
  CryptoLibTestBase;

type

  /// <summary>
  /// KMAC tester
  /// </summary>
  TTestKMac = class(TCryptoLibAlgorithmTestCase)
  private
  var
    FData, FRawKeyInHex, FCustomizationMessage, FZeroToThreeInHex: String;

    procedure DoComputeKMAC128(const AKey, ACustomization, AData,
      AExpectedResult: String; AOutputSizeInBits: UInt64);

    procedure DoComputeKMAC256(const AKey, ACustomization, AData,
      AExpectedResult: String; AOutputSizeInBits: UInt64);

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published

    procedure TestKMac;

  end;

implementation

{ TTestKMac }

procedure TTestKMac.SetUp;
var
  LIdx: Int32;
  LTemp: TBytes;
begin
  inherited;
  System.SetLength(LTemp, 200);
  for LIdx := 0 to 199 do
  begin
    LTemp[LIdx] := LIdx;
  end;

  FData := TConverters.ConvertBytesToHexString(LTemp, False);
  FRawKeyInHex :=
    '404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F';
  FCustomizationMessage := 'My Tagged Application';
  FZeroToThreeInHex := '00010203';
end;

procedure TTestKMac.TearDown;
begin
  inherited;

end;

procedure TTestKMac.DoComputeKMAC128(const AKey, ACustomization, AData,
  AExpectedResult: String; AOutputSizeInBits: UInt64);
var
  LMac: IMac;
  LIdx: Int32;
  LActualResult, LKey, LCustomization, LData: TBytes;
begin
  LKey := TConverters.ConvertHexStringToBytes(AKey);
  LCustomization := TConverters.ConvertStringToBytes(ACustomization,
    TEncoding.UTF8);
  LData := TConverters.ConvertHexStringToBytes(AData);

  LMac := TKMAC128.Create(LCustomization, AOutputSizeInBits);

  LMac.Init(TKeyParameter.Create(LKey) as IKeyParameter);

  for LIdx := System.Low(LData) to System.High(LData) do
  begin
    // do incremental hashing
    LMac.BlockUpdate(TBytes.Create(LData[LIdx]), 0, 1);
  end;

  System.SetLength(LActualResult, LMac.GetMacSize());
  LMac.DoFinal(LActualResult, 0);

  CheckEquals(AExpectedResult, TConverters.ConvertBytesToHexString
    (LActualResult, False), Format('Expected %s But got %s',
    [AExpectedResult, TConverters.ConvertBytesToHexString(LActualResult,
    False)]));

end;

procedure TTestKMac.DoComputeKMAC256(const AKey, ACustomization, AData,
  AExpectedResult: String; AOutputSizeInBits: UInt64);
var
  LMac: IMac;
  LIdx: Int32;
  LActualResult, LKey, LCustomization, LData: TBytes;
begin
  LKey := TConverters.ConvertHexStringToBytes(AKey);
  LCustomization := TConverters.ConvertStringToBytes(ACustomization,
    TEncoding.UTF8);
  LData := TConverters.ConvertHexStringToBytes(AData);

  LMac := TKMAC256.Create(LCustomization, AOutputSizeInBits);

  LMac.Init(TKeyParameter.Create(LKey) as IKeyParameter);

  for LIdx := System.Low(LData) to System.High(LData) do
  begin
    // do incremental hashing
    LMac.BlockUpdate(TBytes.Create(LData[LIdx]), 0, 1);
  end;

  System.SetLength(LActualResult, LMac.GetMacSize());
  LMac.DoFinal(LActualResult, 0);

  CheckEquals(AExpectedResult, TConverters.ConvertBytesToHexString
    (LActualResult, False), Format('Expected %s But got %s',
    [AExpectedResult, TConverters.ConvertBytesToHexString(LActualResult,
    False)]));

end;

procedure TTestKMac.TestKMac;
begin
  DoComputeKMAC128(FRawKeyInHex, '', FZeroToThreeInHex,
    'E5780B0D3EA6F7D3A429C5706AA43A00FADBD7D49628839E3187243F456EE14E', 32 * 8);

  DoComputeKMAC128(FRawKeyInHex, FCustomizationMessage, FZeroToThreeInHex,
    '3B1FBA963CD8B0B59E8C1A6D71888B7143651AF8BA0A7070C0979E2811324AA5', 32 * 8);

  DoComputeKMAC128(FRawKeyInHex, FCustomizationMessage, FData,
    '1F5B4E6CCA02209E0DCB5CA635B89A15E271ECC760071DFD805FAA38F9729230', 32 * 8);

  DoComputeKMAC256(FRawKeyInHex, FCustomizationMessage, FZeroToThreeInHex,
    '20C570C31346F703C9AC36C61C03CB64C3970D0CFC787E9B79599D273A68D2F7F69D4CC3DE9D104A351689F27CF6F5951F0103F33F4F24871024D9C27773A8DD',
    64 * 8);

  DoComputeKMAC256(FRawKeyInHex, '', FData,
    '75358CF39E41494E949707927CEE0AF20A3FF553904C86B08F21CC414BCFD691589D27CF5E15369CBBFF8B9A4C2EB17800855D0235FF635DA82533EC6B759B69',
    64 * 8);

  DoComputeKMAC256(FRawKeyInHex, FCustomizationMessage, FData,
    'B58618F71F92E1D56C1B8C55DDD7CD188B97B4CA4D99831EB2699A837DA2E4D970FBACFDE50033AEA585F1A2708510C32D07880801BD182898FE476876FC8965',
    64 * 8);
end;

initialization

// Register any test cases with the test runner

{$IFDEF FPC}
  RegisterTest(TTestKMac);
{$ELSE}
  RegisterTest(TTestKMac.Suite);
{$ENDIF FPC}

end.
