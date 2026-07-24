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

unit AesBlockCipherTestBase;

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
  ClpIBulkBlockCipher,
  ClpIKeyParameter,
  ClpKeyParameter,
  ClpICipherParameters,
  ClpIBufferedBlockCipher,
  ClpBufferedBlockCipher,
  ClpSecureRandom,
  ClpISecureRandom,
  ClpCryptoLibTypes,
  CryptoLibTestBase,
  BlockCipherTestBase;

type
  TAesBlockCipherTestBase = class abstract(TBlockCipherTestBase)
  strict private
  class var
    FBlockCipherVectorKeys, FBlockCipherVectorInputs,
    FBlockCipherVectorOutputs, FBlockCipherMonteCarloIterations,
    FBlockCipherMonteCarloKeys, FBlockCipherMonteCarloInputs,
    FBlockCipherMonteCarloOutputs: TCryptoLibStringArray;

    class constructor CreateBlockCipherTestData;

    procedure DoBlockCipherMonteCarloTest(const AIteration: String;
      const AEngine: IBlockCipher; const AParam: ICipherParameters;
      const AInput, AOutput: String; const APreface: String = '');

  strict protected
    // engine hooks supplied by the concrete suite
    function GetEngineFactory: TBlockCipherFactory; virtual; abstract;
    function EngineLabel: String; virtual; abstract;
    // default: always run; hardware suites override with a real capability check
    function EngineSupported: Boolean; virtual;

    procedure RunBlockCipherMonteCarloTests(const ACreateEngine
      : TBlockCipherFactory; const AEngineLabel: String);
    // Single-block ProcessBlock with the output buffer aliasing the input.
    procedure DoInPlaceBlockTest(const ACreateEngine: TBlockCipherFactory;
      const AEngineLabel: String);
    // Bulk ProcessBlocks in place; skipped when the engine has no bulk path.
    procedure DoInPlaceBulkBlocksTest(const ACreateEngine: TBlockCipherFactory;
      const AEngineLabel: String);
  published
    procedure TestBlockCipherVector;
    procedure TestMonteCarloAES;
    procedure TestBadParameters;
    procedure TestInPlaceBlock;
    procedure TestInPlaceBulkBlocks;
  end;

implementation

{ TAesBlockCipherTestBase }

class constructor TAesBlockCipherTestBase.CreateBlockCipherTestData;
begin
  FBlockCipherVectorKeys := TCryptoLibStringArray.Create
    ('80000000000000000000000000000000',
    '00000000000000000000000000000080',
    '000000000000000000000000000000000000000000000000',
    '0000000000000000000000000000000000000000000000000000000000000000');

  FBlockCipherVectorInputs := TCryptoLibStringArray.Create
    ('00000000000000000000000000000000',
    '00000000000000000000000000000000',
    '80000000000000000000000000000000',
    '80000000000000000000000000000000');

  FBlockCipherVectorOutputs := TCryptoLibStringArray.Create
    ('0EDD33D3C621E546455BD8BA1418BEC8',
    '172AEAB3D507678ECAF455C12587ADB7',
    '6CD02513E8D4DC986B4AFE087A60BD0C',
    'DDC6BF790C15760D8D9AEB6F9A75FD4E');

  FBlockCipherMonteCarloIterations := TCryptoLibStringArray.Create
    ('10000', '10000', '10000', '10000',
    '10000', '10000', '10000', '10000',
    '10000', '10000', '10000', '10000');

  FBlockCipherMonteCarloKeys := TCryptoLibStringArray.Create(
    '00000000000000000000000000000000',
    '5F060D3716B345C253F6749ABAC10917',
    'AAFE47EE82411A2BF3F6752AE8D7831138F041560631B114',
    '28E79E2AFC5F7745FCCABE2F6257C2EF4C4EDFB37324814ED4137C288711A386',
    '00000000000000000000000000000000',
    '5F060D3716B345C253F6749ABAC10917',
    'AAFE47EE82411A2BF3F6752AE8D7831138F041560631B114',
    '28E79E2AFC5F7745FCCABE2F6257C2EF4C4EDFB37324814ED4137C288711A386',
    '00000000000000000000000000000000',
    '5F060D3716B345C253F6749ABAC10917',
    'AAFE47EE82411A2BF3F6752AE8D7831138F041560631B114',
    '28E79E2AFC5F7745FCCABE2F6257C2EF4C4EDFB37324814ED4137C288711A386');

  FBlockCipherMonteCarloInputs := TCryptoLibStringArray.Create(
    '00000000000000000000000000000000',
    '355F697E8B868B65B25A04E18D782AFA',
    'F3F6752AE8D7831138F041560631B114',
    'C737317FE0846F132B23C8C2A672CE22',
    '00000000000000000000000000000000',
    '355F697E8B868B65B25A04E18D782AFA',
    'F3F6752AE8D7831138F041560631B114',
    'C737317FE0846F132B23C8C2A672CE22',
    '00000000000000000000000000000000',
    '355F697E8B868B65B25A04E18D782AFA',
    'F3F6752AE8D7831138F041560631B114',
    'C737317FE0846F132B23C8C2A672CE22');

  FBlockCipherMonteCarloOutputs := TCryptoLibStringArray.Create(
    'C34C052CC0DA8D73451AFE5F03BE297F',
    'ACC863637868E3E068D2FD6E3508454A',
    '77BA00ED5412DFF27C8ED91F3C376172',
    'E58B82BFBA53C0040DC610C642121168',
    'C34C052CC0DA8D73451AFE5F03BE297F',
    'ACC863637868E3E068D2FD6E3508454A',
    '77BA00ED5412DFF27C8ED91F3C376172',
    'E58B82BFBA53C0040DC610C642121168',
    'C34C052CC0DA8D73451AFE5F03BE297F',
    'ACC863637868E3E068D2FD6E3508454A',
    '77BA00ED5412DFF27C8ED91F3C376172',
    'E58B82BFBA53C0040DC610C642121168');
end;

procedure TAesBlockCipherTestBase.DoBlockCipherMonteCarloTest(const AIteration: String;
  const AEngine: IBlockCipher; const AParam: ICipherParameters;
  const AInput, AOutput: String; const APreface: String);
var
  LCipher: IBufferedBlockCipher;
  LLen1, LLen2, LI, LIterations: Int32;
  LInput, LOutput, LOutBytes: TBytes;
  LPrefix: String;
begin
  LInput := DecodeHex(AInput);
  LOutput := DecodeHex(AOutput);
  LIterations := StrToInt(AIteration);

  if APreface <> '' then
    LPrefix := '[' + APreface + '] '
  else
    LPrefix := '';

  LCipher := TBufferedBlockCipher.Create(AEngine);

  LCipher.Init(True, AParam);

  System.SetLength(LOutBytes, System.Length(LInput));

  System.Move(LInput[0], LOutBytes[0], System.Length(LOutBytes) *
    System.SizeOf(Byte));

  LI := 0;
  while LI <> LIterations do
  begin
    LLen1 := LCipher.ProcessBytes(LOutBytes, 0, System.Length(LOutBytes),
      LOutBytes, 0);

    LCipher.DoFinal(LOutBytes, LLen1);
    System.Inc(LI);
  end;

  if (not AreEqual(LOutBytes, LOutput)) then
  begin
    Fail(LPrefix + Format('Encryption Failed - Expected %s but got %s',
      [EncodeHex(LOutput), EncodeHex(LOutBytes)]));
  end;

  LCipher.Init(False, AParam);

  LI := 0;
  while LI <> LIterations do
  begin
    LLen2 := LCipher.ProcessBytes(LOutBytes, 0, System.Length(LOutBytes),
      LOutBytes, 0);

    LCipher.DoFinal(LOutBytes, LLen2);
    System.Inc(LI);
  end;

  if (not AreEqual(LInput, LOutBytes)) then
  begin
    Fail(LPrefix + Format('Decryption Failed - Expected %s but got %s',
      [EncodeHex(LInput), EncodeHex(LOutBytes)]));
  end;
end;

function TAesBlockCipherTestBase.EngineSupported: Boolean;
begin
  Result := True;
end;

procedure TAesBlockCipherTestBase.TestBlockCipherVector;
begin
  if not EngineSupported then
    Exit;
  RunBlockCipherVectorTests(GetEngineFactory(), EngineLabel,
    FBlockCipherVectorKeys, FBlockCipherVectorInputs, FBlockCipherVectorOutputs);
end;

procedure TAesBlockCipherTestBase.TestMonteCarloAES;
begin
  if not EngineSupported then
    Exit;
  RunBlockCipherMonteCarloTests(GetEngineFactory(), EngineLabel);
end;

procedure TAesBlockCipherTestBase.TestBadParameters;
begin
  if not EngineSupported then
    Exit;
  AssertEngineRejectsBadParameters(GetEngineFactory(), EngineLabel);
end;

procedure TAesBlockCipherTestBase.RunBlockCipherMonteCarloTests(const ACreateEngine
  : TBlockCipherFactory; const AEngineLabel: String);
var
  LI: Int32;
  LPreface: String;
begin
  for LI := System.Low(FBlockCipherMonteCarloKeys)
    to System.High(FBlockCipherMonteCarloKeys) do
  begin
    LPreface := Format('%s Monte Carlo index %d', [AEngineLabel, LI]);
    DoBlockCipherMonteCarloTest(FBlockCipherMonteCarloIterations[LI],
      ACreateEngine(),
      TKeyParameter.Create(DecodeHex(FBlockCipherMonteCarloKeys[LI]))
      as IKeyParameter, FBlockCipherMonteCarloInputs[LI],
      FBlockCipherMonteCarloOutputs[LI], LPreface);
  end;
end;

procedure TAesBlockCipherTestBase.DoInPlaceBlockTest(
  const ACreateEngine: TBlockCipherFactory; const AEngineLabel: String);
var
  LEngine: IBlockCipher;
  LRnd: ISecureRandom;
  LKeyParam: IKeyParameter;
  LKey, LPlain, LRef, LBuf: TBytes;
  LBlockSize: Int32;
begin
  LEngine := ACreateEngine();
  LBlockSize := LEngine.GetBlockSize();

  LRnd := TSecureRandom.Create();
  LRnd.SetSeed(Int64(20260726));
  System.SetLength(LKey, 16);
  LRnd.NextBytes(LKey);
  System.SetLength(LPlain, LBlockSize);
  LRnd.NextBytes(LPlain);
  LKeyParam := TKeyParameter.Create(LKey) as IKeyParameter;

  // Reference ciphertext, produced out of place.
  LEngine.Init(True, LKeyParam as ICipherParameters);
  System.SetLength(LRef, LBlockSize);
  LEngine.ProcessBlock(LPlain, 0, LRef, 0);

  // In-place encrypt: the block is transformed over itself.
  LEngine.Init(True, LKeyParam as ICipherParameters);
  System.SetLength(LBuf, LBlockSize);
  System.Move(LPlain[0], LBuf[0], LBlockSize);
  LEngine.ProcessBlock(LBuf, 0, LBuf, 0);
  if not AreEqual(LBuf, LRef) then
    Fail(Format('[%s] in-place ProcessBlock encrypt mismatch', [AEngineLabel]));

  // In-place decrypt recovers the plaintext.
  LEngine.Init(False, LKeyParam as ICipherParameters);
  LEngine.ProcessBlock(LBuf, 0, LBuf, 0);
  if not AreEqual(LBuf, LPlain) then
    Fail(Format('[%s] in-place ProcessBlock decrypt mismatch', [AEngineLabel]));
end;

procedure TAesBlockCipherTestBase.DoInPlaceBulkBlocksTest(
  const ACreateEngine: TBlockCipherFactory; const AEngineLabel: String);
const
  CCount = 8;
var
  LEngine: IBlockCipher;
  LBulk: IBulkBlockCipher;
  LRnd: ISecureRandom;
  LKeyParam: IKeyParameter;
  LKey, LPlain, LRef, LBuf: TBytes;
  LBlockSize, LTotal, LI: Int32;
begin
  LEngine := ACreateEngine();
  // Engines with no bulk path are already covered by DoInPlaceBlockTest.
  if not Supports(LEngine, IBulkBlockCipher, LBulk) then
    Exit;

  LBlockSize := LEngine.GetBlockSize();
  LTotal := LBlockSize * CCount;

  LRnd := TSecureRandom.Create();
  LRnd.SetSeed(Int64(20260727));
  System.SetLength(LKey, 16);
  LRnd.NextBytes(LKey);
  System.SetLength(LPlain, LTotal);
  LRnd.NextBytes(LPlain);
  LKeyParam := TKeyParameter.Create(LKey) as IKeyParameter;

  // Reference: per-block ProcessBlock, out of place.
  LEngine.Init(True, LKeyParam as ICipherParameters);
  System.SetLength(LRef, LTotal);
  for LI := 0 to CCount - 1 do
    LEngine.ProcessBlock(LPlain, LI * LBlockSize, LRef, LI * LBlockSize);

  // In-place bulk encrypt must match the per-block reference.
  LBulk.Init(True, LKeyParam as ICipherParameters);
  System.SetLength(LBuf, LTotal);
  System.Move(LPlain[0], LBuf[0], LTotal);
  LBulk.ProcessBlocks(LBuf, 0, CCount, LBuf, 0);
  if not AreEqual(LBuf, LRef) then
    Fail(Format('[%s] in-place ProcessBlocks encrypt mismatch', [AEngineLabel]));

  // In-place bulk decrypt recovers the plaintext.
  LBulk.Init(False, LKeyParam as ICipherParameters);
  LBulk.ProcessBlocks(LBuf, 0, CCount, LBuf, 0);
  if not AreEqual(LBuf, LPlain) then
    Fail(Format('[%s] in-place ProcessBlocks decrypt mismatch', [AEngineLabel]));
end;

procedure TAesBlockCipherTestBase.TestInPlaceBlock;
begin
  if not EngineSupported then
    Exit;
  DoInPlaceBlockTest(GetEngineFactory(), EngineLabel);
end;

procedure TAesBlockCipherTestBase.TestInPlaceBulkBlocks;
begin
  if not EngineSupported then
    Exit;
  DoInPlaceBulkBlocksTest(GetEngineFactory(), EngineLabel);
end;

end.
