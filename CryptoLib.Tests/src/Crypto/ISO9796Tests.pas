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

unit ISO9796Tests;

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
  ClpBigInteger,
  ClpEncoders,
  ClpRsaEngine,
  ClpIRsaEngine,
  ClpISO9796d1Encoding,
  ClpIISO9796d1Encoding,
  ClpRsaKeyParameters,
  ClpIRsaKeyParameters,
  ClpIAsymmetricBlockCipher,
  ClpCryptoLibTypes,
  CryptoLibTestBase;

type

  TTestISO9796 = class(TCryptoLibAlgorithmTestCase)
  private
  class var
    // Test 1 and 2 parameters
    FMod1, FPub1, FPri1: TBigInteger;
    FMsg1, FSig1, FMsg2, FSig2: TCryptoLibByteArray;
    
    // Test 3 parameters
    FMod2, FPub2, FPri2: TBigInteger;
    FMsg3, FSig3: TCryptoLibByteArray;

    class constructor Create;

  private
    function IsSameAs(const a: TCryptoLibByteArray; off: Int32;
      const b: TCryptoLibByteArray): Boolean;

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  published
    procedure TestISO9796d1_Test1;
    procedure TestISO9796d1_Test2;
    procedure TestISO9796d1_Test3;

  end;

implementation

{ TTestISO9796 }

class constructor TTestISO9796.Create;
begin
  // ISO 9796-1 Test 1 and 2 parameters
  FMod1 := TBigInteger.Create('0100000000000000000000000000000000bba2d15dbb303c8a21c5ebbcbae52b7125087920dd7cdf358ea119fd66fb064012ec8ce692f0a0b8e8321b041acd40b7', 16);
  FPub1 := TBigInteger.Create('03', 16);
  FPri1 := TBigInteger.Create('2aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaac9f0783a49dd5f6c5af651f4c9d0dc9281c96a3f16a85f9572d7cc3f2d0f25a9dbf1149e4cdc32273faadd3fda5dcda7', 16);

  FMsg1 := THex.Decode('0cbbaa99887766554433221100');
  // sig1 = mod1.Subtract(BigInteger("309f873d8ded8379490f6097eaafdabc137d3ebfd8f25ab5f138d56a719cdc526bdd022ea65dabab920a81013a85d092e04d3e421caab717c90d89ea45a8d23a", 16)).ToByteArray()
  FSig1 := FMod1.Subtract(TBigInteger.Create('309f873d8ded8379490f6097eaafdabc137d3ebfd8f25ab5f138d56a719cdc526bdd022ea65dabab920a81013a85d092e04d3e421caab717c90d89ea45a8d23a', 16)).ToByteArray();

  FMsg2 := THex.Decode('fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210');
  FSig2 := TBigInteger.Create('319bb9becb49f3ed1bca26d0fcf09b0b0a508e4d0bd43b350f959b72cd25b3af47d608fdcd248eada74fbe19990dbeb9bf0da4b4e1200243a14e5cab3f7e610c', 16).ToByteArray();

  // ISO 9796-1 Test 3 parameters
  FMod2 := TBigInteger.Create('ffffff7fa27087c35ebead78412d2bdffe0301edd494df13458974ea89b364708f7d0f5a00a50779ddf9f7d4cb80b8891324da251a860c4ec9ef288104b3858d', 16);
  FPub2 := TBigInteger.Create('03', 16);
  FPri2 := TBigInteger.Create('2aaaaa9545bd6bf5e51fc7940adcdca5550080524e18cfd88b96e8d1c19de6121b13fac0eb0495d47928e047724d91d1740f6968457ce53ec8e24c9362ce84b5', 16);

  FMsg3 := THex.Decode('0112233445566778899aabbccd');
  FSig3 := FMod2.Subtract(TBigInteger.Create('58e59ffb4b1fb1bcdbf8d1fe9afa3730c78a318a1134f5791b7313d480ff07ac319b068edf8f212945cb09cf33df30ace54f4a063fcca0b732f4b662dc4e2454', 16)).ToByteArray();
end;

procedure TTestISO9796.SetUp;
begin
  inherited;
end;

procedure TTestISO9796.TearDown;
begin
  inherited;
end;

function TTestISO9796.IsSameAs(const a: TCryptoLibByteArray; off: Int32;
  const b: TCryptoLibByteArray): Boolean;
var
  i: Int32;
begin
  if (System.Length(a) - off) <> System.Length(b) then
  begin
    Result := False;
    Exit;
  end;

  for i := 0 to System.Length(b) - 1 do
  begin
    if a[i + off] <> b[i] then
    begin
      Result := False;
      Exit;
    end;
  end;

  Result := True;
end;

procedure TTestISO9796.TestISO9796d1_Test1;
var
  pubParameters, privParameters: IRsaKeyParameters;
  rsa: IRsaEngine;
  eng: IISO9796d1Encoding;
  data: TCryptoLibByteArray;
begin
  pubParameters := TRsaKeyParameters.Create(False, FMod1, FPub1);
  privParameters := TRsaKeyParameters.Create(True, FMod1, FPri1);
  rsa := TRsaEngine.Create();

  // ISO 9796-1 - private sign, public verify
  eng := TISO9796d1Encoding.Create(rsa as IAsymmetricBlockCipher);

  eng.Init(True, privParameters);
  eng.SetPadBits(4);

  data := eng.ProcessBlock(FMsg1, 0, System.Length(FMsg1));

  eng.Init(False, pubParameters);

  CheckTrue(AreEqual(FSig1, data), 'failed ISO9796-1 generation Test 1');

  data := eng.ProcessBlock(data, 0, System.Length(data));

  CheckTrue(AreEqual(FMsg1, data), 'failed ISO9796-1 retrieve Test 1');
end;

procedure TTestISO9796.TestISO9796d1_Test2;
var
  pubParameters, privParameters: IRsaKeyParameters;
  rsa: IRsaEngine;
  eng: IISO9796d1Encoding;
  data: TCryptoLibByteArray;
begin
  pubParameters := TRsaKeyParameters.Create(False, FMod1, FPub1);
  privParameters := TRsaKeyParameters.Create(True, FMod1, FPri1);
  rsa := TRsaEngine.Create();

  // ISO 9796-1 - private sign, public verify
  eng := TISO9796d1Encoding.Create(rsa as IAsymmetricBlockCipher);

  eng.Init(True, privParameters);

  data := eng.ProcessBlock(FMsg2, 0, System.Length(FMsg2));

  eng.Init(False, pubParameters);

  CheckTrue(IsSameAs(data, 1, FSig2), 'failed ISO9796-1 generation Test 2');

  data := eng.ProcessBlock(data, 0, System.Length(data));

  CheckTrue(AreEqual(FMsg2, data), 'failed ISO9796-1 retrieve Test 2');
end;

procedure TTestISO9796.TestISO9796d1_Test3;
var
  pubParameters, privParameters: IRsaKeyParameters;
  rsa: IRsaEngine;
  eng: IISO9796d1Encoding;
  data: TCryptoLibByteArray;
begin
  pubParameters := TRsaKeyParameters.Create(False, FMod2, FPub2);
  privParameters := TRsaKeyParameters.Create(True, FMod2, FPri2);
  rsa := TRsaEngine.Create();

  // ISO 9796-1 - private sign, public verify
  eng := TISO9796d1Encoding.Create(rsa as IAsymmetricBlockCipher);

  eng.Init(True, privParameters);
  eng.SetPadBits(4);

  data := eng.ProcessBlock(FMsg3, 0, System.Length(FMsg3));

  eng.Init(False, pubParameters);

  CheckTrue(IsSameAs(FSig3, 1, data), 'failed ISO9796-1 generation Test 3');

  data := eng.ProcessBlock(data, 0, System.Length(data));

  CheckTrue(IsSameAs(FMsg3, 0, data), 'failed ISO9796-1 retrieve Test 3');
end;

initialization

// Register any test cases with the test runner

{$IFDEF FPC}
  RegisterTest(TTestISO9796);
{$ELSE}
  RegisterTest(TTestISO9796.Suite);
{$ENDIF FPC}

end.
