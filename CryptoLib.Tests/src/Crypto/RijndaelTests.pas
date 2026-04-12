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

unit RijndaelTests;

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
  ClpICipherParameters,
  ClpRijndaelEngine,
  ClpIRijndaelEngine,
  ClpKeyParameter,
  ClpIKeyParameter,
  ClpBufferedBlockCipher,
  ClpIBufferedBlockCipher,
  ClpCryptoLibTypes,
  CryptoLibTestBase;

type

  /// <summary>
  /// Test vectors from the NIST standard tests and Brian Gladman's vector set
  /// http://fp.gladman.plus.com/cryptography_technology/rijndael
  /// </summary>
  TTestRijndael = class(TCryptoLibAlgorithmTestCase)
  strict private
  class var

    FBlockCipherVectorBlockSizes, FBlockCipherVectorKeys,
    FBlockCipherVectorInputs, FBlockCipherVectorOutputs,
    FBlockCipherMonteCarloBlockSizes, FBlockCipherMonteCarloIterations,
    FBlockCipherMonteCarloKeys, FBlockCipherMonteCarloInputs,
    FBlockCipherMonteCarloOutputs: TCryptoLibStringArray;

    class constructor CreateTestVectors();

  private

    procedure DoBlockCipherVectorTest(const AEngine: IBlockCipher;
      const AParam: ICipherParameters; const AInput, AOutput: String);

    procedure DoBlockCipherMonteCarloTest(const AIteration: String;
      const AEngine: IBlockCipher; const AParam: ICipherParameters;
      const AInput, AOutput: String);

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published

    procedure TestBlockCipherVector;
    procedure TestMonteCarlo;

  end;

implementation

{ TTestRijndael }

class constructor TTestRijndael.CreateTestVectors;
begin
  FBlockCipherVectorBlockSizes := TCryptoLibStringArray.Create(
    '128', '128', '160', '160', '192', '192', '224', '224', '256', '256');

  FBlockCipherVectorKeys := TCryptoLibStringArray.Create
    ('80000000000000000000000000000000',
    '00000000000000000000000000000080',
    '2B7E151628AED2A6ABF7158809CF4F3C',
    '2B7E151628AED2A6ABF7158809CF4F3C762E7160',
    '2B7E151628AED2A6ABF7158809CF4F3C',
    '2B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA5',
    '2B7E151628AED2A6ABF7158809CF4F3C',
    '2B7E151628AED2A6ABF7158809CF4F3C762E7160',
    '2B7E151628AED2A6ABF7158809CF4F3C',
    '2B7E151628AED2A6ABF7158809CF4F3C762E7160');

  FBlockCipherVectorInputs := TCryptoLibStringArray.Create
    ('00000000000000000000000000000000',
    '00000000000000000000000000000000',
    '3243F6A8885A308D313198A2E03707344A409382',
    '3243F6A8885A308D313198A2E03707344A409382',
    '3243F6A8885A308D313198A2E03707344A4093822299F31D',
    '3243F6A8885A308D313198A2E03707344A4093822299F31D',
    '3243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA9',
    '3243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA9',
    '3243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C8',
    '3243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C8');

  FBlockCipherVectorOutputs := TCryptoLibStringArray.Create
    ('0EDD33D3C621E546455BD8BA1418BEC8',
    '172AEAB3D507678ECAF455C12587ADB7',
    '16E73AEC921314C29DF905432BC8968AB64B1F51',
    '0553EB691670DD8A5A5B5ADDF1AA7450F7A0E587',
    'B24D275489E82BB8F7375E0D5FCDB1F481757C538B65148A',
    '725AE43B5F3161DE806A7C93E0BCA93C967EC1AE1B71E1CF',
    'B0A8F78F6B3C66213F792FFD2A61631F79331407A5E5C8D3793ACEB1',
    '08B99944EDFCE33A2ACB131183AB0168446B2D15E958480010F545E3',
    '7D15479076B69A46FFB3B3BEAE97AD8313F622F67FEDB487DE9F06B9ED9C8F19',
    '514F93FB296B5AD16AA7DF8B577ABCBD484DECACCCC7FB1F18DC567309CEEFFD');

  FBlockCipherMonteCarloBlockSizes := TCryptoLibStringArray.Create(
    '128', '128', '128', '128');

  FBlockCipherMonteCarloIterations := TCryptoLibStringArray.Create(
    '10000', '10000', '10000', '10000');

  FBlockCipherMonteCarloKeys := TCryptoLibStringArray.Create
    ('00000000000000000000000000000000',
    '5F060D3716B345C253F6749ABAC10917',
    'AAFE47EE82411A2BF3F6752AE8D7831138F041560631B114',
    '28E79E2AFC5F7745FCCABE2F6257C2EF4C4EDFB37324814ED4137C288711A386');

  FBlockCipherMonteCarloInputs := TCryptoLibStringArray.Create
    ('00000000000000000000000000000000',
    '355F697E8B868B65B25A04E18D782AFA',
    'F3F6752AE8D7831138F041560631B114',
    'C737317FE0846F132B23C8C2A672CE22');

  FBlockCipherMonteCarloOutputs := TCryptoLibStringArray.Create
    ('C34C052CC0DA8D73451AFE5F03BE297F',
    'ACC863637868E3E068D2FD6E3508454A',
    '77BA00ED5412DFF27C8ED91F3C376172',
    'E58B82BFBA53C0040DC610C642121168');
end;

procedure TTestRijndael.DoBlockCipherVectorTest(const AEngine: IBlockCipher;
  const AParam: ICipherParameters; const AInput, AOutput: String);
var
  LCipher: IBufferedBlockCipher;
  LLen1, LLen2: Int32;
  LInput, LOutput, LOutBytes: TBytes;
begin
  LInput := DecodeHex(AInput);
  LOutput := DecodeHex(AOutput);

  LCipher := TBufferedBlockCipher.Create(AEngine);

  LCipher.Init(True, AParam);

  System.SetLength(LOutBytes, System.Length(LInput));

  LLen1 := LCipher.ProcessBytes(LInput, 0, System.Length(LInput), LOutBytes, 0);

  LCipher.DoFinal(LOutBytes, LLen1);

  if (not AreEqual(LOutBytes, LOutput)) then
  begin
    Fail(Format('Encryption Failed - Expected %s but got %s',
      [EncodeHex(LOutput), EncodeHex(LOutBytes)]));
  end;

  LCipher.Init(False, AParam);

  LLen2 := LCipher.ProcessBytes(LOutput, 0, System.Length(LOutput),
    LOutBytes, 0);

  LCipher.DoFinal(LOutBytes, LLen2);

  if (not AreEqual(LInput, LOutBytes)) then
  begin
    Fail(Format('Decryption Failed - Expected %s but got %s',
      [EncodeHex(LInput), EncodeHex(LOutBytes)]));
  end;
end;

procedure TTestRijndael.DoBlockCipherMonteCarloTest(const AIteration: String;
  const AEngine: IBlockCipher; const AParam: ICipherParameters;
  const AInput, AOutput: String);
var
  LCipher: IBufferedBlockCipher;
  LLen1, LLen2, LI, LIterations: Int32;
  LInput, LOutput, LOutBytes: TBytes;
begin
  LInput := DecodeHex(AInput);
  LOutput := DecodeHex(AOutput);
  LIterations := StrToInt(AIteration);

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
    Fail(Format('Encryption Failed - Expected %s but got %s',
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
    Fail(Format('Decryption Failed - Expected %s but got %s',
      [EncodeHex(LInput), EncodeHex(LOutBytes)]));
  end;
end;

procedure TTestRijndael.SetUp;
begin
  inherited;
end;

procedure TTestRijndael.TearDown;
begin
  inherited;
end;

procedure TTestRijndael.TestBlockCipherVector;
var
  LI: Int32;
begin
  for LI := System.Low(FBlockCipherVectorKeys)
    to System.High(FBlockCipherVectorKeys) do
  begin
    DoBlockCipherVectorTest
      (TRijndaelEngine.Create
      (StrToInt(FBlockCipherVectorBlockSizes[LI]))
      as IRijndaelEngine,
      TKeyParameter.Create(DecodeHex(FBlockCipherVectorKeys[LI]))
      as IKeyParameter, FBlockCipherVectorInputs[LI],
      FBlockCipherVectorOutputs[LI]);
  end;
end;

procedure TTestRijndael.TestMonteCarlo;
var
  LI: Int32;
begin
  for LI := System.Low(FBlockCipherMonteCarloKeys)
    to System.High(FBlockCipherMonteCarloKeys) do
  begin
    DoBlockCipherMonteCarloTest(FBlockCipherMonteCarloIterations[LI],
      TRijndaelEngine.Create
      (StrToInt(FBlockCipherMonteCarloBlockSizes[LI]))
      as IRijndaelEngine,
      TKeyParameter.Create(DecodeHex(FBlockCipherMonteCarloKeys[LI]))
      as IKeyParameter, FBlockCipherMonteCarloInputs[LI],
      FBlockCipherMonteCarloOutputs[LI]);
  end;
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestRijndael);
{$ELSE}
  RegisterTest(TTestRijndael.Suite);
{$ENDIF FPC}

end.
