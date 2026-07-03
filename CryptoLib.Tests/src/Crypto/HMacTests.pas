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
  ClpHMac,
  ClpICipherKeyGenerator,
  ClpMacUtilities,
  ClpGeneratorUtilities,
  ClpDigestUtilities,
  ClpStringUtilities,
  ClpConverters,
  ClpPkcsObjectIdentifiers,
  ClpIanaObjectIdentifiers,
  ClpNistObjectIdentifiers,
  ClpRosstandartObjectIdentifiers,
  ClpCryptoLibTypes,
  CryptoLibTestBase,
  HmacVectors;

type

  /// <summary>
  /// Shared driver for the per-digest HMAC vector tests. Concrete subclasses
  /// supply the vector selector and digest name; each is registered as its own
  /// suite so a failure pinpoints the digest. Vectors come from RFC 2202
  /// (MD5, SHA-1), RFC 4231 (SHA-224/256/384/512) and RFC 2286
  /// (RIPEMD-128/160), all served via <c>THmacVectors</c>.
  /// </summary>
  TTestHMacVectorsBase = class abstract(TCryptoLibAlgorithmTestCase)
  protected
    /// <summary>Algorithm key used to select this digest's rows from the vector table.</summary>
    function GetVectorSelector: string; virtual; abstract;
    /// <summary>Digest name passed to <c>TDigestUtilities.GetDigest</c>.</summary>
    function GetDigestName: string; virtual; abstract;
  published
    procedure TestHMacVectors;
  end;

  /// <summary>MD5 HMac test, vectors from RFC 2202.</summary>
  TTestMD5HMac = class sealed(TTestHMacVectorsBase)
  protected
    function GetVectorSelector: string; override;
    function GetDigestName: string; override;
  end;

  /// <summary>SHA-1 HMac test, vectors from RFC 2202.</summary>
  TTestSHA1HMac = class sealed(TTestHMacVectorsBase)
  protected
    function GetVectorSelector: string; override;
    function GetDigestName: string; override;
  end;

  /// <summary>SHA-224 HMac test, vectors from RFC 4231.</summary>
  TTestSHA224HMac = class sealed(TTestHMacVectorsBase)
  protected
    function GetVectorSelector: string; override;
    function GetDigestName: string; override;
  end;

  /// <summary>SHA-256 HMac test, vectors from RFC 4231.</summary>
  TTestSHA256HMac = class sealed(TTestHMacVectorsBase)
  protected
    function GetVectorSelector: string; override;
    function GetDigestName: string; override;
  end;

  /// <summary>SHA-384 HMac test, vectors from RFC 4231.</summary>
  TTestSHA384HMac = class sealed(TTestHMacVectorsBase)
  protected
    function GetVectorSelector: string; override;
    function GetDigestName: string; override;
  end;

  /// <summary>SHA-512 HMac test, vectors from RFC 4231.</summary>
  TTestSHA512HMac = class sealed(TTestHMacVectorsBase)
  protected
    function GetVectorSelector: string; override;
    function GetDigestName: string; override;
  end;

  /// <summary>RIPEMD-128 HMac test, vectors from RFC 2286.</summary>
  TTestRIPEMD128HMac = class sealed(TTestHMacVectorsBase)
  protected
    function GetVectorSelector: string; override;
    function GetDigestName: string; override;
  end;

  /// <summary>RIPEMD-160 HMac test, vectors from RFC 2286.</summary>
  TTestRIPEMD160HMac = class sealed(TTestHMacVectorsBase)
  protected
    function GetVectorSelector: string; override;
    function GetDigestName: string; override;
  end;

  /// <summary>
  /// Cross-algorithm HMAC smoke test: exercises the MacUtilities / OID lookup
  /// surface and default key-generator sizes across the full algorithm set.
  /// </summary>
  TTestHMac = class(TCryptoLibAlgorithmTestCase)
  private
  var
    FKeyBytes, FMessage: TBytes;

    function GetExpected(const AAlgorithm: string): TBytes;
    procedure DoTestHMac(const AHmacName: String; const AAlgorithm: string);
      overload;
    procedure DoTestHMac(const AHmacName: String; const AAlgorithm: string;
      defKeySize: Int32); overload;
    procedure DoTestExceptions();

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published

    procedure TestHMac;

  end;

implementation

{ TTestHMacVectorsBase }

procedure TTestHMacVectorsBase.TestHMacVectors;
var
  LRows: TCryptoLibGenericArray<THmacRfc2202Row>;
  LRow: THmacRfc2202Row;
  LHmac: IMac;
  LResBuf, LM, LM2: TBytes;
  LI, LVector: Int32;
begin
  LRows := THmacVectors.GetRfc2202Rows(GetVectorSelector);
  LHmac := THMac.Create(TDigestUtilities.GetDigest(GetDigestName));
  SetLength(LResBuf, LHmac.GetMacSize());

  for LI := 0 to High(LRows) do
  begin
    LRow := LRows[LI];
    LM := TConverters.ConvertStringToBytes(LRow.Message, TEncoding.ASCII);
    if TStringUtilities.StartsWith(LRow.Message, '0x', True) then
      LM := DecodeHex(Copy(LRow.Message, 3, Length(LRow.Message) - 2));

    LHmac.Init(TKeyParameter.Create(DecodeHex(LRow.Key)) as IKeyParameter);
    LHmac.BlockUpdate(LM, 0, Length(LM));
    LHmac.DoFinal(LResBuf, 0);

    if not AreEqual(LResBuf, DecodeHex(LRow.ExpectedHex)) then
      Fail(Format('%s vector %d failed', [GetVectorSelector, LRow.CaseIndex]));
  end;

  LVector := 0;
  LRow := LRows[LVector];
  LM2 := TConverters.ConvertStringToBytes(LRow.Message, TEncoding.ASCII);
  if TStringUtilities.StartsWith(LRow.Message, '0x', True) then
    LM2 := DecodeHex(Copy(LRow.Message, 3, Length(LRow.Message) - 2));

  LHmac.Init(TKeyParameter.Create(DecodeHex(LRow.Key)) as IKeyParameter);
  LHmac.BlockUpdate(LM2, 0, Length(LM2));
  LHmac.DoFinal(LResBuf, 0);
  LHmac.Reset();
  LHmac.BlockUpdate(LM2, 0, Length(LM2));
  LHmac.DoFinal(LResBuf, 0);

  if not AreEqual(LResBuf, DecodeHex(LRow.ExpectedHex)) then
    Fail(Format('%s reset with vector %d failed', [GetVectorSelector, LVector]));
end;

{ TTestMD5HMac }

function TTestMD5HMac.GetVectorSelector: string;
begin
  Result := 'MD5';
end;

function TTestMD5HMac.GetDigestName: string;
begin
  Result := 'MD5';
end;

{ TTestSHA1HMac }

function TTestSHA1HMac.GetVectorSelector: string;
begin
  Result := 'SHA1';
end;

function TTestSHA1HMac.GetDigestName: string;
begin
  Result := 'SHA-1';
end;

{ TTestSHA224HMac }

function TTestSHA224HMac.GetVectorSelector: string;
begin
  Result := 'SHA224';
end;

function TTestSHA224HMac.GetDigestName: string;
begin
  Result := 'SHA-224';
end;

{ TTestSHA256HMac }

function TTestSHA256HMac.GetVectorSelector: string;
begin
  Result := 'SHA256';
end;

function TTestSHA256HMac.GetDigestName: string;
begin
  Result := 'SHA-256';
end;

{ TTestSHA384HMac }

function TTestSHA384HMac.GetVectorSelector: string;
begin
  Result := 'SHA384';
end;

function TTestSHA384HMac.GetDigestName: string;
begin
  Result := 'SHA-384';
end;

{ TTestSHA512HMac }

function TTestSHA512HMac.GetVectorSelector: string;
begin
  Result := 'SHA512';
end;

function TTestSHA512HMac.GetDigestName: string;
begin
  Result := 'SHA-512';
end;

{ TTestRIPEMD128HMac }

function TTestRIPEMD128HMac.GetVectorSelector: string;
begin
  Result := 'RIPEMD128';
end;

function TTestRIPEMD128HMac.GetDigestName: string;
begin
  Result := 'RIPEMD128';
end;

{ TTestRIPEMD160HMac }

function TTestRIPEMD160HMac.GetVectorSelector: string;
begin
  Result := 'RIPEMD160';
end;

function TTestRIPEMD160HMac.GetDigestName: string;
begin
  Result := 'RIPEMD160';
end;

{ TTestHMac }

function TTestHMac.GetExpected(const AAlgorithm: string): TBytes;
begin
  Result := DecodeHex(THmacVectors.GetCrossAlgorithmExpectedHex(AAlgorithm));
end;

procedure TTestHMac.DoTestExceptions;
var
  LMac: IMac;
begin
  LMac := TMacUtilities.GetMac('HmacSHA1');
  try
    LMac.Init(nil);
    Fail('bad argument Init test failed.');
  except
    on E: Exception do
    begin
      // pass
    end;
  end;
end;

procedure TTestHMac.DoTestHMac(const AHmacName: String; const AAlgorithm: string);
var
  LKey: IKeyParameter;
  LMac: IMac;
  LOutBytes: TBytes;
  LKGenerator: ICipherKeyGenerator;
  LExpected: TBytes;
begin
  LExpected := GetExpected(AAlgorithm);
  LKey := TKeyParameter.Create(FKeyBytes);

  LMac := TMacUtilities.GetMac(AHmacName);
  LMac.Init(LKey);
  LMac.Reset();
  LMac.BlockUpdate(FMessage, 0, System.Length(FMessage));
  LOutBytes := TMacUtilities.DoFinal(LMac);

  if (not AreEqual(LOutBytes, LExpected)) then
  begin
    Fail('Failed - expected ' + EncodeHex(LExpected) + ' got ' +
      EncodeHex(LOutBytes));
  end;

  LKGenerator := TGeneratorUtilities.GetKeyGenerator(AHmacName);
  LKey := TKeyParameter.Create(LKGenerator.GenerateKey());
  LMac.Init(LKey);
  LMac.BlockUpdate(FMessage, 0, System.Length(FMessage));
  LOutBytes := TMacUtilities.DoFinal(LMac);
end;

procedure TTestHMac.DoTestHMac(const AHmacName: String; const AAlgorithm: string;
  defKeySize: Int32);
var
  LKey: IKeyParameter;
  LMac: IMac;
  LOutBytes: TBytes;
  LKeyGenerator: ICipherKeyGenerator;
  LExpected: TBytes;
begin
  LExpected := GetExpected(AAlgorithm);
  LKey := TKeyParameter.Create(FKeyBytes);

  LMac := TMacUtilities.GetMac(AHmacName);
  LMac.Init(LKey);
  LMac.Reset();
  LMac.BlockUpdate(FMessage, 0, System.Length(FMessage));
  LOutBytes := TMacUtilities.DoFinal(LMac);

  if (not AreEqual(LOutBytes, LExpected)) then
  begin
    Fail('Failed - expected ' + EncodeHex(LExpected) + ' got ' +
      EncodeHex(LOutBytes));
  end;

  LKeyGenerator := TGeneratorUtilities.GetKeyGenerator(AHmacName);
  LKey := TKeyParameter.Create(LKeyGenerator.GenerateKey());
  LMac.Init(LKey);
  LMac.BlockUpdate(FMessage, 0, System.Length(FMessage));
  LOutBytes := TMacUtilities.DoFinal(LMac);

  CheckTrue(System.Length(LKey.GetKey()) = (defKeySize div 8),
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
  RegisterTest(TTestMD5HMac);
  RegisterTest(TTestSHA1HMac);
  RegisterTest(TTestSHA224HMac);
  RegisterTest(TTestSHA256HMac);
  RegisterTest(TTestSHA384HMac);
  RegisterTest(TTestSHA512HMac);
  RegisterTest(TTestRIPEMD128HMac);
  RegisterTest(TTestRIPEMD160HMac);
  RegisterTest(TTestHMac);
{$ELSE}
  RegisterTest(TTestMD5HMac.Suite);
  RegisterTest(TTestSHA1HMac.Suite);
  RegisterTest(TTestSHA224HMac.Suite);
  RegisterTest(TTestSHA256HMac.Suite);
  RegisterTest(TTestSHA384HMac.Suite);
  RegisterTest(TTestSHA512HMac.Suite);
  RegisterTest(TTestRIPEMD128HMac.Suite);
  RegisterTest(TTestRIPEMD160HMac.Suite);
  RegisterTest(TTestHMac.Suite);
{$ENDIF FPC}

end.
