{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                           Author - Ugochukwu Mmaduekwe                          * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ *                                                                                 * }
{ *                              Acknowledgements:                                  * }
{ *                                                                                 * }
{ *      Thanks to Sphere 10 Software (http://www.sphere10.com/) for sponsoring     * }
{ *                         the development of this library                         * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit HMacTests;

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
  ClpIMac,
  ClpICipherKeyGenerator,
  ClpMacUtilities,
  ClpGeneratorUtilities,
  ClpPkcsObjectIdentifiers,
  ClpIanaObjectIdentifiers,
  ClpNistObjectIdentifiers,
  ClpRosstandartObjectIdentifiers,
  CryptoLibTestBase,
  HmacVectors;

type

  /// <summary>
  /// HMAC tester
  /// </summary>
  TTestHMac = class(TCryptoLibAlgorithmTestCase)
  private
  var
    FKeyBytes, FMessage: TBytes;

    function GetExpected(const AAlgorithm: string): TBytes;
    procedure DoTestHMac(const hmacName: String; const AAlgorithm: string);
      overload;
    procedure DoTestHMac(const hmacName: String; const AAlgorithm: string;
      defKeySize: Int32); overload;
    procedure DoTestExceptions();

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published

    procedure TestHMac;

  end;

implementation

{ TTestHMac }

function TTestHMac.GetExpected(const AAlgorithm: string): TBytes;
begin
  Result := DecodeHex(THmacVectors.GetCrossAlgorithmExpectedHex(AAlgorithm));
end;

procedure TTestHMac.DoTestExceptions;
var
  mac: IMac;
begin
  mac := TMacUtilities.GetMac('HmacSHA1');
  try
    mac.Init(Nil);
    Fail('bad argument Init test failed.');
  except
    on e: Exception do
    begin
      // pass
    end;
  end;
end;

procedure TTestHMac.DoTestHMac(const hmacName: String; const AAlgorithm: string);
var
  key: IKeyParameter;
  mac: IMac;
  outBytes: TBytes;
  kGen: ICipherKeyGenerator;
  expected: TBytes;
begin
  expected := GetExpected(AAlgorithm);
  key := TKeyParameter.Create(FKeyBytes);

  mac := TMacUtilities.GetMac(hmacName);
  mac.Init(key);
  mac.Reset();
  mac.BlockUpdate(FMessage, 0, System.Length(FMessage));
  outBytes := TMacUtilities.DoFinal(mac);

  if (not AreEqual(outBytes, expected)) then
  begin
    Fail('Failed - expected ' + EncodeHex(expected) + ' got ' +
      EncodeHex(outBytes));
  end;

  kGen := TGeneratorUtilities.GetKeyGenerator(hmacName);
  key := TKeyParameter.Create(kGen.GenerateKey());
  mac.Init(key);
  mac.BlockUpdate(FMessage, 0, System.Length(FMessage));
  outBytes := TMacUtilities.DoFinal(mac);
end;

procedure TTestHMac.DoTestHMac(const hmacName: String; const AAlgorithm: string;
  defKeySize: Int32);
var
  key: IKeyParameter;
  mac: IMac;
  outBytes: TBytes;
  kGen: ICipherKeyGenerator;
  expected: TBytes;
begin
  expected := GetExpected(AAlgorithm);
  key := TKeyParameter.Create(FKeyBytes);

  mac := TMacUtilities.GetMac(hmacName);
  mac.Init(key);
  mac.Reset();
  mac.BlockUpdate(FMessage, 0, System.Length(FMessage));
  outBytes := TMacUtilities.DoFinal(mac);

  if (not AreEqual(outBytes, expected)) then
  begin
    Fail('Failed - expected ' + EncodeHex(expected) + ' got ' +
      EncodeHex(outBytes));
  end;

  kGen := TGeneratorUtilities.GetKeyGenerator(hmacName);
  key := TKeyParameter.Create(kGen.GenerateKey());
  mac.Init(key);
  mac.BlockUpdate(FMessage, 0, System.Length(FMessage));
  outBytes := TMacUtilities.DoFinal(mac);

  CheckTrue(System.Length(key.GetKey()) = (defKeySize div 8),
    'default key wrong length');
end;

procedure TTestHMac.SetUp;
begin
  inherited;
  FKeyBytes := THmacVectors.GetCrossAlgorithmKeyBytes();
  FMessage := THmacVectors.GetCrossAlgorithmMessage();
end;

procedure TTestHMac.TearDown;
begin
  inherited;
end;

procedure TTestHMac.TestHMac;
begin
  DoTestHMac('HMac-SHA1', 'SHA1');
  DoTestHMac('HMac-MD5', 'MD5');
  DoTestHMac('HMac-MD4', 'MD4');
  DoTestHMac('HMac-MD2', 'MD2');
  DoTestHMac('HMac-SHA224', 'SHA224');
  DoTestHMac('HMac-SHA256', 'SHA256');
  DoTestHMac('HMac-SHA384', 'SHA384');
  DoTestHMac('HMac-SHA512', 'SHA512');
  DoTestHMac('HMac-SHA512/224', 'SHA512/224');
  DoTestHMac('HMac-SHA512/256', 'SHA512/256');

  DoTestHMac('HMac-RIPEMD128', 'RIPEMD128');
  DoTestHMac('HMac-RIPEMD160', 'RIPEMD160');

  DoTestHMac('HMac-TIGER', 'TIGER');

  DoTestHMac('HMac-KECCAK224', 'KECCAK224', 224);
  DoTestHMac('HMac-KECCAK256', 'KECCAK256', 256);
  DoTestHMac('HMac-KECCAK288', 'KECCAK288', 288);
  DoTestHMac('HMac-KECCAK384', 'KECCAK384', 384);
  DoTestHMac('HMac-KECCAK512', 'KECCAK512', 512);

  DoTestHMac('HMac-SHA3-224', 'SHA3-224', 224);
  DoTestHMac('HMac-SHA3-256', 'SHA3-256', 256);
  DoTestHMac('HMac-SHA3-384', 'SHA3-384', 384);
  DoTestHMac('HMac-SHA3-512', 'SHA3-512', 512);

  DoTestHMac('HMac-GOST3411-2012-256', 'GOST3411-2012-256', 256);
  DoTestHMac('HMac-GOST3411-2012-512', 'GOST3411-2012-512', 512);

  DoTestHMac('HMac/SHA1', 'SHA1');

  DoTestHMac('HMac/MD5', 'MD5');
  DoTestHMac('HMac/MD4', 'MD4');
  DoTestHMac('HMac/MD2', 'MD2');

  DoTestHMac('HMac/SHA224', 'SHA224');
  DoTestHMac('HMac/SHA256', 'SHA256');
  DoTestHMac('HMac/SHA384', 'SHA384');
  DoTestHMac('HMac/SHA512', 'SHA512');

  DoTestHMac('HMac/RIPEMD128', 'RIPEMD128');
  DoTestHMac('HMac/RIPEMD160', 'RIPEMD160');
  DoTestHMac('HMac/TIGER', 'TIGER');

  DoTestHMac('HMac/KECCAK224', 'KECCAK224', 224);
  DoTestHMac('HMac/KECCAK256', 'KECCAK256', 256);
  DoTestHMac('HMac/KECCAK288', 'KECCAK288', 288);
  DoTestHMac('HMac/KECCAK384', 'KECCAK384', 384);
  DoTestHMac('HMac/KECCAK512', 'KECCAK512', 512);

  DoTestHMac('HMac/SHA3-224', 'SHA3-224', 224);
  DoTestHMac('HMac/SHA3-256', 'SHA3-256', 256);
  DoTestHMac('HMac/SHA3-384', 'SHA3-384', 384);
  DoTestHMac('HMac/SHA3-512', 'SHA3-512', 512);

  DoTestHMac('HMac/GOST3411-2012-256', 'GOST3411-2012-256', 256);
  DoTestHMac('HMac/GOST3411-2012-512', 'GOST3411-2012-512', 512);

  DoTestHMac(TPkcsObjectIdentifiers.IdHmacWithSha1.Id, 'SHA1');
  DoTestHMac(TPkcsObjectIdentifiers.IdHmacWithSha224.Id, 'SHA224');
  DoTestHMac(TPkcsObjectIdentifiers.IdHmacWithSha256.Id, 'SHA256');
  DoTestHMac(TPkcsObjectIdentifiers.IdHmacWithSha384.Id, 'SHA384');
  DoTestHMac(TPkcsObjectIdentifiers.IdHmacWithSha512.Id, 'SHA512');
  DoTestHMac(TIanaObjectIdentifiers.HmacSha1.Id, 'SHA1');

  DoTestHMac(TIanaObjectIdentifiers.HmacMD5.Id, 'MD5');

  DoTestHMac(TIanaObjectIdentifiers.HmacRipeMD160.Id, 'RIPEMD160');

  DoTestHMac(TIanaObjectIdentifiers.HmacTiger.Id, 'TIGER');

  DoTestHMac(TNistObjectIdentifiers.IdHMacWithSha3_224.Id, 'SHA3-224', 224);
  DoTestHMac(TNistObjectIdentifiers.IdHMacWithSha3_256.Id, 'SHA3-256', 256);
  DoTestHMac(TNistObjectIdentifiers.IdHMacWithSha3_384.Id, 'SHA3-384', 384);
  DoTestHMac(TNistObjectIdentifiers.IdHMacWithSha3_512.Id, 'SHA3-512', 512);

  DoTestHMac(TRosstandartObjectIdentifiers.IdTc26HmacGost3411_12_256.ID,
    'GOST3411-2012-256', 256);
  DoTestHMac(TRosstandartObjectIdentifiers.IdTc26HmacGost3411_12_512.ID,
    'GOST3411-2012-512', 512);

  DoTestExceptions();
end;

initialization

// Register any test cases with the test runner

{$IFDEF FPC}
  RegisterTest(TTestHMac);
{$ELSE}
  RegisterTest(TTestHMac.Suite);
{$ENDIF FPC}

end.
