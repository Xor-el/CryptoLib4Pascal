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

unit GMacTests;

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
  ClpGMac,
  ClpGcmBlockCipher,
  ClpIGcmBlockCipher,
  ClpAesUtilities,
  ClpKeyParameter,
  ClpIKeyParameter,
  ClpParametersWithIV,
  ClpICipherParameters,
  ClpCryptoLibTypes,
  CryptoLibTestBase;

type

  TTestGMac = class(TCryptoLibAlgorithmTestCase)
  strict private
    class var
      FTestVectors: TCryptoLibGenericArray<TCryptoLibStringArray>;

    class constructor CreateTestGMac;

  private
    procedure TestSingleByte(const AMac: IMac; const AName: string;
      const AAd, ATag: TBytes);
    procedure TestMultibyte(const AMac: IMac; const AName: string;
      const AAd, ATag: TBytes);
    procedure CheckMac(const AMac: IMac; const AName: string;
      const ATag: TBytes);
    procedure TestInvalidMacSize(ASize: Int32);

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  published
    procedure TestGMacVectors;
    procedure TestInvalidMacSizes;

  end;

implementation

{ TTestGMac }

class constructor TTestGMac.CreateTestGMac;
begin
  // Test vectors from NIST CAVP GCM test vectors (PTlen = 0)
  // Format: [name, key, iv, ad, tag]
  FTestVectors := TCryptoLibGenericArray<TCryptoLibStringArray>.Create(
    TCryptoLibStringArray.Create(
    '128/96/0/128',
    '11754cd72aec309bf52f7687212e8957',
    '3c819d9a9bed087615030b65',
    '',
    '250327c674aaf477aef2675748cf6971'),
    TCryptoLibStringArray.Create(
    '128/96/0/120',
    '272f16edb81a7abbea887357a58c1917',
    '794ec588176c703d3d2a7a07',
    '',
    'b6e6f197168f5049aeda32dafbdaeb'),
    TCryptoLibStringArray.Create(
    '128/96/0/112',
    '81b6844aab6a568c4556a2eb7eae752f',
    'ce600f59618315a6829bef4d',
    '',
    '89b43e9dbc1b4f597dbbc7655bb5'),
    TCryptoLibStringArray.Create(
    '128/96/0/104',
    'cde2f9a9b1a004165ef9dc981f18651b',
    '29512c29566c7322e1e33e8e',
    '',
    '2e58ce7dabd107c82759c66a75'),
    TCryptoLibStringArray.Create(
    '128/96/0/96',
    'b01e45cc3088aaba9fa43d81d481823f',
    '5a2c4a66468713456a4bd5e1',
    '',
    '014280f944f53c681164b2ff'),
    TCryptoLibStringArray.Create(
    '128/96/128/128',
    '77be63708971c4e240d1cb79e8d77feb',
    'e0e00f19fed7ba0136a797f3',
    '7a43ec1d9c0a5a78a0b16533a6213cab',
    '209fcc8d3675ed938e9c7166709dd946'),
    TCryptoLibStringArray.Create(
    '128/96/128/96',
    'bea48ae4980d27f357611014d4486625',
    '32bddb5c3aa998a08556454c',
    '8a50b0b8c7654bced884f7f3afda2ead',
    '8e0f6d8bf05ffebe6f500eb1'),
    TCryptoLibStringArray.Create(
    '128/96/384/128',
    '99e3e8793e686e571d8285c564f75e2b',
    'c2dd0ab868da6aa8ad9c0d23',
    'b668e42d4e444ca8b23cfdd95a9fedd5178aa521144890b093733cf5cf22526c' +
    '5917ee476541809ac6867a8c399309fc',
    '3f4fba100eaf1f34b0baadaae9995d85'),
    TCryptoLibStringArray.Create(
    '128/96/384/96',
    'c77acd1b0918e87053cb3e51651e7013',
    '39ff857a81745d10f718ac00',
    '407992f82ea23b56875d9a3cb843ceb83fd27cb954f7c5534d58539fe96fb534' +
    '502a1b38ea4fac134db0a42de4be1137',
    '2a5dc173285375dc82835876'),
    TCryptoLibStringArray.Create(
    '128/1024/0/128',
    'd0f1f4defa1e8c08b4b26d576392027c',
    '42b4f01eb9f5a1ea5b1eb73b0fb0baed54f387ecaa0393c7d7dffc6af50146ec' +
    'c021abf7eb9038d4303d91f8d741a11743166c0860208bcc02c6258fd9511a2f' +
    'a626f96d60b72fcff773af4e88e7a923506e4916ecbd814651e9f445adef4ad6' +
    'a6b6c7290cc13b956130eef5b837c939fcac0cbbcc9656cd75b13823ee5acdac',
    '',
    '7ab49b57ddf5f62c427950111c5c4f0d'),
    TCryptoLibStringArray.Create(
    '128/1024/384/96',
    '3cce72d37933394a8cac8a82deada8f0',
    'aa2f0d676d705d9733c434e481972d4888129cf7ea55c66511b9c0d25a92a174' +
    'b1e28aa072f27d4de82302828955aadcb817c4907361869bd657b45ff4a6f323' +
    '871987fcf9413b0702d46667380cd493ed24331a28b9ce5bbfa82d3a6e7679fc' +
    'ce81254ba64abcad14fd18b22c560a9d2c1cd1d3c42dac44c683edf92aced894',
    '5686b458e9c176f4de8428d9ebd8e12f569d1c7595cf49a4b0654ab194409f86' +
    'c0dd3fdb8eb18033bb4338c70f0b97d1',
    'a3a9444b21f330c3df64c8b6')
  );
end;

procedure TTestGMac.SetUp;
begin
  inherited;
end;

procedure TTestGMac.TearDown;
begin
  inherited;
end;

procedure TTestGMac.TestSingleByte(const AMac: IMac; const AName: string;
  const AAd, ATag: TBytes);
var
  LI: Int32;
begin
  for LI := 0 to System.Length(AAd) - 1 do
  begin
    AMac.Update(AAd[LI]);
  end;
  CheckMac(AMac, AName, ATag);
end;

procedure TTestGMac.TestMultibyte(const AMac: IMac; const AName: string;
  const AAd, ATag: TBytes);
begin
  AMac.BlockUpdate(AAd, 0, System.Length(AAd));
  CheckMac(AMac, AName, ATag);
end;

procedure TTestGMac.CheckMac(const AMac: IMac; const AName: string;
  const ATag: TBytes);
var
  LGeneratedMac: TBytes;
begin
  System.SetLength(LGeneratedMac, AMac.GetMacSize());
  AMac.DoFinal(LGeneratedMac, 0);
  if not AreEqual(ATag, LGeneratedMac) then
  begin
    Fail(Format('Failed %s - expected %s got %s',
      [AName, EncodeHex(ATag), EncodeHex(LGeneratedMac)]));
  end;
end;

procedure TTestGMac.TestInvalidMacSize(ASize: Int32);
var
  LMac: IMac;
begin
  try
    LMac := TGMac.Create(
      TGcmBlockCipher.Create(TAesUtilities.CreateEngine())
        as IGcmBlockCipher,
      ASize) as IMac;
    LMac.Init(
      TParametersWithIV.Create(
        TKeyParameter.Create(TBytes.Create(
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)) as IKeyParameter,
        TBytes.Create(
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0))
      as ICipherParameters);
    Fail(Format('Expected failure for illegal mac size %d', [ASize]));
  except
    on E: EArgumentCryptoLibException do
    begin
      // expected
    end;
  end;
end;

procedure TTestGMac.TestGMacVectors;
var
  LI: Int32;
  LName: string;
  LKey, LIv, LAd, LTag: TBytes;
  LMac: IMac;
  LKeyParam: IKeyParameter;
begin
  for LI := 0 to System.Length(FTestVectors) - 1 do
  begin
    LName := FTestVectors[LI][0];
    LKey := DecodeHex(FTestVectors[LI][1]);
    LIv := DecodeHex(FTestVectors[LI][2]);
    LAd := DecodeHex(FTestVectors[LI][3]);
    LTag := DecodeHex(FTestVectors[LI][4]);

    LKeyParam := TKeyParameter.Create(LKey) as IKeyParameter;

    LMac := TGMac.Create(
      TGcmBlockCipher.Create(TAesUtilities.CreateEngine())
        as IGcmBlockCipher,
      System.Length(LTag) * 8) as IMac;
    LMac.Init(TParametersWithIV.Create(LKeyParam, LIv) as ICipherParameters);
    TestSingleByte(LMac, LName, LAd, LTag);

    LMac := TGMac.Create(
      TGcmBlockCipher.Create(TAesUtilities.CreateEngine())
        as IGcmBlockCipher,
      System.Length(LTag) * 8) as IMac;
    LMac.Init(TParametersWithIV.Create(LKeyParam, LIv) as ICipherParameters);
    TestMultibyte(LMac, LName, LAd, LTag);
  end;
end;

procedure TTestGMac.TestInvalidMacSizes;
begin
  TestInvalidMacSize(97);
  TestInvalidMacSize(136);
  TestInvalidMacSize(24);
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestGMac);
{$ELSE}
  RegisterTest(TTestGMac.Suite);
{$ENDIF FPC}

end.
