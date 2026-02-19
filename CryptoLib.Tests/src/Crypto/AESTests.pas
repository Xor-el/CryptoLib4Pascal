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

unit AESTests;

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
  ClpAesEngine,
  ClpIAesEngine,
  ClpAesLightEngine,
  ClpIAesLightEngine,
  ClpIBlockCipher,
  ClpIKeyParameter,
  ClpKeyParameter,
  ClpParametersWithIV,
  ClpIParametersWithIV,
  ClpIBufferedCipher,
  ClpIBufferedBlockCipher,
  ClpBufferedBlockCipher,
  ClpICipherParameters,
  ClpICipherKeyGenerator,
  ClpGeneratorUtilities,
  ClpParameterUtilities,
  ClpCipherUtilities,
  ClpNistObjectIdentifiers,
  ClpCbcBlockCipher,
  ClpCfbBlockCipher,
  ClpOfbBlockCipher,
  ClpSicBlockCipher,
  ClpICbcBlockCipher,
  ClpICfbBlockCipher,
  ClpIOfbBlockCipher,
  ClpISicBlockCipher,
  ClpWrapperUtilities,
  ClpIWrapper,
  ClpFixedSecureRandom,
  ClpCryptoLibTypes,
  CryptoLibTestBase;

type

  TTestAES = class(TCryptoLibAlgorithmTestCase)
  strict private
  class var

    FBlockCipherVectorKeys, FBlockCipherVectorInputs,
    FBlockCipherVectorOutputs, FBlockCipherMonteCarloIterations,
    FBlockCipherMonteCarloKeys, FBlockCipherMonteCarloInputs,
    FBlockCipherMonteCarloOutputs, FOfficialVectorKeys_AES_CBC,
    FOfficialVectorIVs_AES_CBC, FOfficialVectorInputs_AES_CBC,
    FOfficialVectorOutputs_AES_CBC, FOfficialVectorKeys_AES_CFB,
    FOfficialVectorIVs_AES_CFB, FOfficialVectorInputs_AES_CFB,
    FOfficialVectorOutputs_AES_CFB, FOfficialVectorKeys_AES_CTR,
    FOfficialVectorIVs_AES_CTR, FOfficialVectorInputs_AES_CTR,
    FOfficialVectorOutputs_AES_CTR, FOfficialVectorKeys_AES_ECB,
    FOfficialVectorInputs_AES_ECB, FOfficialVectorOutputs_AES_ECB,
    FOfficialVectorKeys_AES_OFB, FOfficialVectorIVs_AES_OFB,
    FOfficialVectorInputs_AES_OFB, FOfficialVectorOutputs_AES_OFB,
    FCipherTestVectors: TCryptoLibStringArray;

    class constructor CreateTestVectors();

  private

    procedure DoBlockCipherVectorTest(const AEngine: IBlockCipher;
      const AParam: ICipherParameters; const AInput, AOutput: String);

    procedure DoBlockCipherMonteCarloTest(const AIteration: String;
      const AEngine: IBlockCipher; const AParam: ICipherParameters;
      const AInput, AOutput: String);

    procedure DoAESTest(const ACipher: IBufferedCipher;
      const AParam: ICipherParameters; const AInput, AOutput: String;
      AWithPadding: Boolean = False);

    procedure DoOidTest(const AOids, ANames: TCryptoLibStringArray;
      AGroupSize: Int32);

    procedure DoCipherTest(AStrength: Int32; const AKeyBytes,
      AInput, AOutput: TBytes);

    procedure DoWrapTest(AId: Int32; const AWrappingAlgorithm: String;
      const AKek, AInput, AOutput: TBytes); overload;

    procedure DoWrapTest(AId: Int32; const AWrappingAlgorithm: String;
      const AKek, AIV: TBytes; const ARandom: IFixedSecureRandom;
      const AInput, AOutput: TBytes); overload;

    procedure DoWrapOidTest(const AOids: TCryptoLibStringArray;
      const AName: String);

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published

    procedure TestBlockCipherVector;
    procedure TestBlockCipherVectorLight;
    procedure TestMonteCarloAES;
    procedure TestMonteCarloAESLight;
    procedure TestBadParameters;
    procedure TestOids;
    procedure TestCiphers;
    procedure TestAES_CBC_PKCS7PADDING_WITH_IV;
    procedure TestAES_CBC_NOPADDING_WITH_IV;
    procedure TestAES_CFB_NOPADDING_WITH_IV;
    procedure TestAES_OFB_NOPADDING_WITH_IV;
    procedure TestAES_CTR_NOPADDING_WITH_IV;
    procedure TestAES_ECB_NOPADDING_NO_IV;
    procedure TestWrap;
    procedure TestWrapRfc3211;
    procedure TestWrapRfc5649;
    procedure TestWrapOids;
    procedure TestWrapPadOids;
    procedure TestAesEax;
    procedure TestAesEaxBadPadding;
    procedure TestAesCcm;
    procedure TestAesCcmBadPadding;
    procedure TestAesOcb;
    procedure TestAesOcbBadPadding;

  end;

implementation

{ TTestAES }

class constructor TTestAES.CreateTestVectors;
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

  FBlockCipherMonteCarloKeys := TCryptoLibStringArray.Create
    ('00000000000000000000000000000000',
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

  FBlockCipherMonteCarloInputs := TCryptoLibStringArray.Create
    ('00000000000000000000000000000000',
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

  FBlockCipherMonteCarloOutputs := TCryptoLibStringArray.Create
    ('C34C052CC0DA8D73451AFE5F03BE297F',
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

  FOfficialVectorKeys_AES_CBC := TCryptoLibStringArray.Create(
    '2B7E151628AED2A6ABF7158809CF4F3C', '2B7E151628AED2A6ABF7158809CF4F3C',
    '2B7E151628AED2A6ABF7158809CF4F3C', '2B7E151628AED2A6ABF7158809CF4F3C',
    '8E73B0F7DA0E6452C810F32B809079E562F8EAD2522C6B7B',
    '8E73B0F7DA0E6452C810F32B809079E562F8EAD2522C6B7B',
    '8E73B0F7DA0E6452C810F32B809079E562F8EAD2522C6B7B',
    '8E73B0F7DA0E6452C810F32B809079E562F8EAD2522C6B7B',
    '603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4',
    '603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4',
    '603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4',
    '603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4');

  FOfficialVectorIVs_AES_CBC := TCryptoLibStringArray.Create(
    '000102030405060708090A0B0C0D0E0F', '7649ABAC8119B246CEE98E9B12E9197D',
    '5086CB9B507219EE95DB113A917678B2', '73BED6B8E3C1743B7116E69E22229516',
    '000102030405060708090A0B0C0D0E0F', '4F021DB243BC633D7178183A9FA071E8',
    'B4D9ADA9AD7DEDF4E5E738763F69145A', '571B242012FB7AE07FA9BAAC3DF102E0',
    '000102030405060708090A0B0C0D0E0F', 'F58C4C04D6E5F1BA779EABFB5F7BFBD6',
    '9CFC4E967EDB808D679F777BC6702C7D', '39F23369A9D9BACFA530E26304231461');

  FOfficialVectorInputs_AES_CBC := TCryptoLibStringArray.Create(
    '6BC1BEE22E409F96E93D7E117393172A', 'AE2D8A571E03AC9C9EB76FAC45AF8E51',
    '30C81C46A35CE411E5FBC1191A0A52EF', 'F69F2445DF4F9B17AD2B417BE66C3710',
    '6BC1BEE22E409F96E93D7E117393172A', 'AE2D8A571E03AC9C9EB76FAC45AF8E51',
    '30C81C46A35CE411E5FBC1191A0A52EF', 'F69F2445DF4F9B17AD2B417BE66C3710',
    '6BC1BEE22E409F96E93D7E117393172A', 'AE2D8A571E03AC9C9EB76FAC45AF8E51',
    '30C81C46A35CE411E5FBC1191A0A52EF', 'F69F2445DF4F9B17AD2B417BE66C3710');

  FOfficialVectorOutputs_AES_CBC := TCryptoLibStringArray.Create(
    '7649ABAC8119B246CEE98E9B12E9197D', '5086CB9B507219EE95DB113A917678B2',
    '73BED6B8E3C1743B7116E69E22229516', '3FF1CAA1681FAC09120ECA307586E1A7',
    '4F021DB243BC633D7178183A9FA071E8', 'B4D9ADA9AD7DEDF4E5E738763F69145A',
    '571B242012FB7AE07FA9BAAC3DF102E0', '08B0E27988598881D920A9E64F5615CD',
    'F58C4C04D6E5F1BA779EABFB5F7BFBD6', '9CFC4E967EDB808D679F777BC6702C7D',
    '39F23369A9D9BACFA530E26304231461', 'B2EB05E2C39BE9FCDA6C19078C6A9D1B');

  FOfficialVectorKeys_AES_CFB := TCryptoLibStringArray.Create(
    '2B7E151628AED2A6ABF7158809CF4F3C', '2B7E151628AED2A6ABF7158809CF4F3C',
    '2B7E151628AED2A6ABF7158809CF4F3C', '2B7E151628AED2A6ABF7158809CF4F3C',
    '8E73B0F7DA0E6452C810F32B809079E562F8EAD2522C6B7B',
    '8E73B0F7DA0E6452C810F32B809079E562F8EAD2522C6B7B',
    '8E73B0F7DA0E6452C810F32B809079E562F8EAD2522C6B7B',
    '8E73B0F7DA0E6452C810F32B809079E562F8EAD2522C6B7B',
    '603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4',
    '603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4',
    '603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4',
    '603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4');

  FOfficialVectorIVs_AES_CFB := TCryptoLibStringArray.Create(
    '000102030405060708090A0B0C0D0E0F', '3B3FD92EB72DAD20333449F8E83CFB4A',
    'C8A64537A0B3A93FCDE3CDAD9F1CE58B', '26751F67A3CBB140B1808CF187A4F4DF',
    '000102030405060708090A0B0C0D0E0F', 'CDC80D6FDDF18CAB34C25909C99A4174',
    '67CE7F7F81173621961A2B70171D3D7A', '2E1E8A1DD59B88B1C8E60FED1EFAC4C9',
    '000102030405060708090A0B0C0D0E0F', 'DC7E84BFDA79164B7ECD8486985D3860',
    '39FFED143B28B1C832113C6331E5407B', 'DF10132415E54B92A13ED0A8267AE2F9');

  FOfficialVectorInputs_AES_CFB := TCryptoLibStringArray.Create(
    '6BC1BEE22E409F96E93D7E117393172A', 'AE2D8A571E03AC9C9EB76FAC45AF8E51',
    '30C81C46A35CE411E5FBC1191A0A52EF', 'F69F2445DF4F9B17AD2B417BE66C3710',
    '6BC1BEE22E409F96E93D7E117393172A', 'AE2D8A571E03AC9C9EB76FAC45AF8E51',
    '30C81C46A35CE411E5FBC1191A0A52EF', 'F69F2445DF4F9B17AD2B417BE66C3710',
    '6BC1BEE22E409F96E93D7E117393172A', 'AE2D8A571E03AC9C9EB76FAC45AF8E51',
    '30C81C46A35CE411E5FBC1191A0A52EF', 'F69F2445DF4F9B17AD2B417BE66C3710');

  FOfficialVectorOutputs_AES_CFB := TCryptoLibStringArray.Create(
    '3B3FD92EB72DAD20333449F8E83CFB4A', 'C8A64537A0B3A93FCDE3CDAD9F1CE58B',
    '26751F67A3CBB140B1808CF187A4F4DF', 'C04B05357C5D1C0EEAC4C66F9FF7F2E6',
    'CDC80D6FDDF18CAB34C25909C99A4174', '67CE7F7F81173621961A2B70171D3D7A',
    '2E1E8A1DD59B88B1C8E60FED1EFAC4C9', 'C05F9F9CA9834FA042AE8FBA584B09FF',
    'DC7E84BFDA79164B7ECD8486985D3860', '39FFED143B28B1C832113C6331E5407B',
    'DF10132415E54B92A13ED0A8267AE2F9', '75A385741AB9CEF82031623D55B1E471');

  FOfficialVectorKeys_AES_CTR := TCryptoLibStringArray.Create(
    '2B7E151628AED2A6ABF7158809CF4F3C', '2B7E151628AED2A6ABF7158809CF4F3C',
    '2B7E151628AED2A6ABF7158809CF4F3C', '2B7E151628AED2A6ABF7158809CF4F3C',
    '8E73B0F7DA0E6452C810F32B809079E562F8EAD2522C6B7B',
    '8E73B0F7DA0E6452C810F32B809079E562F8EAD2522C6B7B',
    '8E73B0F7DA0E6452C810F32B809079E562F8EAD2522C6B7B',
    '8E73B0F7DA0E6452C810F32B809079E562F8EAD2522C6B7B',
    '603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4',
    '603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4',
    '603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4',
    '603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4');

  FOfficialVectorIVs_AES_CTR := TCryptoLibStringArray.Create(
    'F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF', 'F0F1F2F3F4F5F6F7F8F9FAFBFCFDFF00',
    'F0F1F2F3F4F5F6F7F8F9FAFBFCFDFF01', 'F0F1F2F3F4F5F6F7F8F9FAFBFCFDFF02',
    'F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF', 'F0F1F2F3F4F5F6F7F8F9FAFBFCFDFF00',
    'F0F1F2F3F4F5F6F7F8F9FAFBFCFDFF01', 'F0F1F2F3F4F5F6F7F8F9FAFBFCFDFF02',
    'F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF', 'F0F1F2F3F4F5F6F7F8F9FAFBFCFDFF00',
    'F0F1F2F3F4F5F6F7F8F9FAFBFCFDFF01', 'F0F1F2F3F4F5F6F7F8F9FAFBFCFDFF02');

  FOfficialVectorInputs_AES_CTR := TCryptoLibStringArray.Create(
    '6BC1BEE22E409F96E93D7E117393172A', 'AE2D8A571E03AC9C9EB76FAC45AF8E51',
    '30C81C46A35CE411E5FBC1191A0A52EF', 'F69F2445DF4F9B17AD2B417BE66C3710',
    '6BC1BEE22E409F96E93D7E117393172A', 'AE2D8A571E03AC9C9EB76FAC45AF8E51',
    '30C81C46A35CE411E5FBC1191A0A52EF', 'F69F2445DF4F9B17AD2B417BE66C3710',
    '6BC1BEE22E409F96E93D7E117393172A', 'AE2D8A571E03AC9C9EB76FAC45AF8E51',
    '30C81C46A35CE411E5FBC1191A0A52EF', 'F69F2445DF4F9B17AD2B417BE66C3710');

  FOfficialVectorOutputs_AES_CTR := TCryptoLibStringArray.Create(
    '874D6191B620E3261BEF6864990DB6CE', '9806F66B7970FDFF8617187BB9FFFDFF',
    '5AE4DF3EDBD5D35E5B4F09020DB03EAB', '1E031DDA2FBE03D1792170A0F3009CEE',
    '1ABC932417521CA24F2B0459FE7E6E0B', '090339EC0AA6FAEFD5CCC2C6F4CE8E94',
    '1E36B26BD1EBC670D1BD1D665620ABF7', '4F78A7F6D29809585A97DAEC58C6B050',
    '601EC313775789A5B7A7F504BBF3D228', 'F443E3CA4D62B59ACA84E990CACAF5C5',
    '2B0930DAA23DE94CE87017BA2D84988D', 'DFC9C58DB67AADA613C2DD08457941A6');

  FOfficialVectorKeys_AES_ECB := TCryptoLibStringArray.Create(
    '2B7E151628AED2A6ABF7158809CF4F3C', '2B7E151628AED2A6ABF7158809CF4F3C',
    '2B7E151628AED2A6ABF7158809CF4F3C', '2B7E151628AED2A6ABF7158809CF4F3C',
    '8E73B0F7DA0E6452C810F32B809079E562F8EAD2522C6B7B',
    '8E73B0F7DA0E6452C810F32B809079E562F8EAD2522C6B7B',
    '8E73B0F7DA0E6452C810F32B809079E562F8EAD2522C6B7B',
    '8E73B0F7DA0E6452C810F32B809079E562F8EAD2522C6B7B',
    '603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4',
    '603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4',
    '603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4',
    '603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4');

  FOfficialVectorInputs_AES_ECB := TCryptoLibStringArray.Create(
    '6BC1BEE22E409F96E93D7E117393172A', 'AE2D8A571E03AC9C9EB76FAC45AF8E51',
    '30C81C46A35CE411E5FBC1191A0A52EF', 'F69F2445DF4F9B17AD2B417BE66C3710',
    '6BC1BEE22E409F96E93D7E117393172A', 'AE2D8A571E03AC9C9EB76FAC45AF8E51',
    '30C81C46A35CE411E5FBC1191A0A52EF', 'F69F2445DF4F9B17AD2B417BE66C3710',
    '6BC1BEE22E409F96E93D7E117393172A', 'AE2D8A571E03AC9C9EB76FAC45AF8E51',
    '30C81C46A35CE411E5FBC1191A0A52EF', 'F69F2445DF4F9B17AD2B417BE66C3710');

  FOfficialVectorOutputs_AES_ECB := TCryptoLibStringArray.Create(
    '3AD77BB40D7A3660A89ECAF32466EF97', 'F5D3D58503B9699DE785895A96FDBAAF',
    '43B1CD7F598ECE23881B00E3ED030688', '7B0C785E27E8AD3F8223207104725DD4',
    'BD334F1D6E45F25FF712A214571FA5CC', '974104846D0AD3AD7734ECB3ECEE4EEF',
    'EF7AFD2270E2E60ADCE0BA2FACE6444E', '9A4B41BA738D6C72FB16691603C18E0E',
    'F3EED1BDB5D2A03C064B5A7E3DB181F8', '591CCB10D410ED26DC5BA74A31362870',
    'B6ED21B99CA6F4F9F153E7B1BEAFED1D', '23304B7A39F9F3FF067D8D8F9E24ECC7');

  FOfficialVectorKeys_AES_OFB := TCryptoLibStringArray.Create(
    '2B7E151628AED2A6ABF7158809CF4F3C', '2B7E151628AED2A6ABF7158809CF4F3C',
    '2B7E151628AED2A6ABF7158809CF4F3C', '2B7E151628AED2A6ABF7158809CF4F3C',
    '8E73B0F7DA0E6452C810F32B809079E562F8EAD2522C6B7B',
    '8E73B0F7DA0E6452C810F32B809079E562F8EAD2522C6B7B',
    '8E73B0F7DA0E6452C810F32B809079E562F8EAD2522C6B7B',
    '8E73B0F7DA0E6452C810F32B809079E562F8EAD2522C6B7B',
    '603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4',
    '603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4',
    '603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4',
    '603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4');

  FOfficialVectorIVs_AES_OFB := TCryptoLibStringArray.Create(
    '000102030405060708090A0B0C0D0E0F', '50FE67CC996D32B6DA0937E99BAFEC60',
    'D9A4DADA0892239F6B8B3D7680E15674', 'A78819583F0308E7A6BF36B1386ABF23',
    '000102030405060708090A0B0C0D0E0F', 'A609B38DF3B1133DDDFF2718BA09565E',
    '52EF01DA52602FE0975F78AC84BF8A50', 'BD5286AC63AABD7EB067AC54B553F71D',
    '000102030405060708090A0B0C0D0E0F', 'B7BF3A5DF43989DD97F0FA97EBCE2F4A',
    'E1C656305ED1A7A6563805746FE03EDC', '41635BE625B48AFC1666DD42A09D96E7');

  FOfficialVectorInputs_AES_OFB := TCryptoLibStringArray.Create(
    '6BC1BEE22E409F96E93D7E117393172A', 'AE2D8A571E03AC9C9EB76FAC45AF8E51',
    '30C81C46A35CE411E5FBC1191A0A52EF', 'F69F2445DF4F9B17AD2B417BE66C3710',
    '6BC1BEE22E409F96E93D7E117393172A', 'AE2D8A571E03AC9C9EB76FAC45AF8E51',
    '30C81C46A35CE411E5FBC1191A0A52EF', 'F69F2445DF4F9B17AD2B417BE66C3710',
    '6BC1BEE22E409F96E93D7E117393172A', 'AE2D8A571E03AC9C9EB76FAC45AF8E51',
    '30C81C46A35CE411E5FBC1191A0A52EF', 'F69F2445DF4F9B17AD2B417BE66C3710');

  FOfficialVectorOutputs_AES_OFB := TCryptoLibStringArray.Create(
    '3B3FD92EB72DAD20333449F8E83CFB4A', '7789508D16918F03F53C52DAC54ED825',
    '9740051E9C5FECF64344F7A82260EDCC', '304C6528F659C77866A510D9C1D6AE5E',
    'CDC80D6FDDF18CAB34C25909C99A4174', 'FCC28B8D4C63837C09E81700C1100401',
    '8D9A9AEAC0F6596F559C6D4DAF59A5F2', '6D9F200857CA6C3E9CAC524BD9ACC92A',
    'DC7E84BFDA79164B7ECD8486985D3860', '4FEBDC6740D20B3AC88F6AD82A4FB08D',
    '71AB47A086E86EEDF39D1C5BBA97C408', '0126141D67F37BE8538F5A8BE740E484');

  FCipherTestVectors := TCryptoLibStringArray.Create(
    '128',
    '000102030405060708090a0b0c0d0e0f',
    '00112233445566778899aabbccddeeff',
    '69c4e0d86a7b0430d8cdb78070b4c55a',
    '192',
    '000102030405060708090a0b0c0d0e0f1011121314151617',
    '00112233445566778899aabbccddeeff',
    'dda97ca4864cdfe06eaf70a0ec0d7191',
    '256',
    '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
    '00112233445566778899aabbccddeeff',
    '8ea2b7ca516745bfeafc49904b496089');
end;

procedure TTestAES.DoBlockCipherVectorTest(const AEngine: IBlockCipher;
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

procedure TTestAES.DoBlockCipherMonteCarloTest(const AIteration: String;
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

procedure TTestAES.DoAESTest(const ACipher: IBufferedCipher;
  const AParam: ICipherParameters; const AInput, AOutput: String;
  AWithPadding: Boolean);
var
  LInput, LOutput, LEncryptionResult, LDecryptionResult: TBytes;
begin
  LInput := DecodeHex(AInput);
  LOutput := DecodeHex(AOutput);

  ACipher.Init(True, AParam);

  LEncryptionResult := ACipher.DoFinal(LInput);

  if not AWithPadding then
  begin
    if (not AreEqual(LOutput, LEncryptionResult)) then
    begin
      Fail(Format('Encryption Failed - Expected %s but got %s',
        [EncodeHex(LOutput), EncodeHex(LEncryptionResult)]));
    end;
  end;

  ACipher.Init(False, AParam);

  LDecryptionResult := ACipher.DoFinal(LEncryptionResult);

  if (not AreEqual(LInput, LDecryptionResult)) then
  begin
    Fail(Format('Decryption Failed - Expected %s but got %s',
      [EncodeHex(LInput), EncodeHex(LDecryptionResult)]));
  end;
end;

procedure TTestAES.DoOidTest(const AOids, ANames: TCryptoLibStringArray;
  AGroupSize: Int32);
var
  LData, LResult, LIV: TBytes;
  LI: Int32;
  LC1, LC2: IBufferedCipher;
  LKg: ICipherKeyGenerator;
  LK: IKeyParameter;
  LCp: ICipherParameters;
begin
  LData := TBytes.Create(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
    15, 16);
  LI := 0;
  while LI <> System.Length(AOids) do
  begin
    LC1 := TCipherUtilities.GetCipher(AOids[LI]);
    LC2 := TCipherUtilities.GetCipher(ANames[LI]);
    LKg := TGeneratorUtilities.GetKeyGenerator(AOids[LI]);

    LK := TParameterUtilities.CreateKeyParameter(AOids[LI], LKg.GenerateKey());

    LCp := LK;

    if System.Pos('/ECB/', ANames[LI]) = 0 then
    begin
      System.SetLength(LIV, 16);
      LCp := TParametersWithIV.Create(LCp, LIV);
    end;

    LC1.Init(True, LCp);
    LC2.Init(False, LCp);

    LResult := LC2.DoFinal(LC1.DoFinal(LData));

    if (not AreEqual(LData, LResult)) then
    begin
      Fail('failed OID test');
    end;

    if (System.Length(LK.GetKey()) <> (16 + ((LI div AGroupSize) * 8))) then
    begin
      Fail('failed key length test');
    end;
    System.Inc(LI);
  end;
end;

procedure TTestAES.DoCipherTest(AStrength: Int32; const AKeyBytes,
  AInput, AOutput: TBytes);
var
  LKey: IKeyParameter;
  LInCipher, LOutCipher: IBufferedCipher;
  LEncBytes, LDecBytes: TBytes;
begin
  LKey := TParameterUtilities.CreateKeyParameter('AES', AKeyBytes);

  LOutCipher := TCipherUtilities.GetCipher('AES/ECB/NoPadding');
  LInCipher := TCipherUtilities.GetCipher('AES/ECB/NoPadding');

  LOutCipher.Init(True, LKey);
  LInCipher.Init(False, LKey);

  LEncBytes := LOutCipher.DoFinal(AInput);

  if (not AreEqual(LEncBytes, AOutput)) then
  begin
    Fail(Format('AES failed encryption - expected %s got %s',
      [EncodeHex(AOutput), EncodeHex(LEncBytes)]));
  end;

  LDecBytes := LInCipher.DoFinal(LEncBytes);

  if (not AreEqual(LDecBytes, AInput)) then
  begin
    Fail(Format('AES failed decryption - expected %s got %s',
      [EncodeHex(AInput), EncodeHex(LDecBytes)]));
  end;
end;

procedure TTestAES.DoWrapTest(AId: Int32; const AWrappingAlgorithm: String;
  const AKek, AInput, AOutput: TBytes);
begin
  DoWrapTest(AId, AWrappingAlgorithm, AKek, nil, nil, AInput, AOutput);
end;

procedure TTestAES.DoWrapTest(AId: Int32; const AWrappingAlgorithm: String;
  const AKek, AIV: TBytes; const ARandom: IFixedSecureRandom;
  const AInput, AOutput: TBytes);
var
  LWrapper: IWrapper;
  LCp, LUnwrapCp: ICipherParameters;
  LCText, LPText: TBytes;
begin
  LWrapper := TWrapperUtilities.GetWrapper(AWrappingAlgorithm);

  LCp := TParameterUtilities.CreateKeyParameter('AES', AKek);

  if AIV <> nil then
    LCp := TParametersWithIV.Create(LCp, AIV);

  LUnwrapCp := LCp;

  if ARandom <> nil then
    LCp := TParameterUtilities.WithRandom(LCp, ARandom);

  LWrapper.Init(True, LCp);

  LCText := LWrapper.Wrap(AInput, 0, System.Length(AInput));
  if (not AreEqual(LCText, AOutput)) then
  begin
    Fail(Format('failed wrap test %d expected %s got %s',
      [AId, EncodeHex(AOutput), EncodeHex(LCText)]));
  end;

  LWrapper.Init(False, LUnwrapCp);

  LPText := LWrapper.Unwrap(AOutput, 0, System.Length(AOutput));
  if (not AreEqual(LPText, AInput)) then
  begin
    Fail(Format('failed unwrap test %d expected %s got %s',
      [AId, EncodeHex(AInput), EncodeHex(LPText)]));
  end;
end;

procedure TTestAES.DoWrapOidTest(const AOids: TCryptoLibStringArray;
  const AName: String);
var
  LData: TBytes;
  LI: Int32;
  LC1, LC2: IWrapper;
  LKg: ICipherKeyGenerator;
  LK: IKeyParameter;
  LWrapped, LUnwrapped: TBytes;
begin
  LData := TBytes.Create(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
    15, 16);

  for LI := 0 to System.Length(AOids) - 1 do
  begin
    LC1 := TWrapperUtilities.GetWrapper(AOids[LI]);
    LC2 := TWrapperUtilities.GetWrapper(AName);
    LKg := TGeneratorUtilities.GetKeyGenerator(AOids[LI]);

    LK := TParameterUtilities.CreateKeyParameter(AOids[LI], LKg.GenerateKey());

    LC1.Init(True, LK);
    LC2.Init(False, LK);

    LWrapped := LC1.Wrap(LData, 0, System.Length(LData));
    LUnwrapped := LC2.Unwrap(LWrapped, 0, System.Length(LWrapped));

    if (not AreEqual(LData, LUnwrapped)) then
    begin
      Fail('failed wrap OID test');
    end;

    if (System.Length(LK.GetKey()) <> (16 + (LI * 8))) then
    begin
      Fail('failed key length test');
    end;
  end;
end;

procedure TTestAES.SetUp;
begin
  inherited;
end;

procedure TTestAES.TearDown;
begin
  inherited;
end;

procedure TTestAES.TestBlockCipherVector;
var
  LI: Int32;
begin
  for LI := System.Low(FBlockCipherVectorKeys)
    to System.High(FBlockCipherVectorKeys) do
  begin
    DoBlockCipherVectorTest(TAesEngine.Create() as IAesEngine,
      TKeyParameter.Create(DecodeHex(FBlockCipherVectorKeys[LI]))
      as IKeyParameter, FBlockCipherVectorInputs[LI],
      FBlockCipherVectorOutputs[LI]);
  end;
end;

procedure TTestAES.TestBlockCipherVectorLight;
var
  LI: Int32;
begin
  for LI := System.Low(FBlockCipherVectorKeys)
    to System.High(FBlockCipherVectorKeys) do
  begin
    DoBlockCipherVectorTest(TAesLightEngine.Create() as IAesLightEngine,
      TKeyParameter.Create(DecodeHex(FBlockCipherVectorKeys[LI]))
      as IKeyParameter, FBlockCipherVectorInputs[LI],
      FBlockCipherVectorOutputs[LI]);
  end;
end;

procedure TTestAES.TestMonteCarloAES;
var
  LI: Int32;
begin
  for LI := System.Low(FBlockCipherMonteCarloKeys)
    to System.High(FBlockCipherMonteCarloKeys) do
  begin
    DoBlockCipherMonteCarloTest(FBlockCipherMonteCarloIterations[LI],
      TAesEngine.Create() as IAesEngine,
      TKeyParameter.Create(DecodeHex(FBlockCipherMonteCarloKeys[LI]))
      as IKeyParameter, FBlockCipherMonteCarloInputs[LI],
      FBlockCipherMonteCarloOutputs[LI]);
  end;
end;

procedure TTestAES.TestMonteCarloAESLight;
var
  LI: Int32;
begin
  for LI := System.Low(FBlockCipherMonteCarloKeys)
    to System.High(FBlockCipherMonteCarloKeys) do
  begin
    DoBlockCipherMonteCarloTest(FBlockCipherMonteCarloIterations[LI],
      TAesLightEngine.Create() as IAesLightEngine,
      TKeyParameter.Create(DecodeHex(FBlockCipherMonteCarloKeys[LI]))
      as IKeyParameter, FBlockCipherMonteCarloInputs[LI],
      FBlockCipherMonteCarloOutputs[LI]);
  end;
end;

procedure TTestAES.TestBadParameters;
var
  LDudKey, LIV: TBytes;
  LEngine: IAesEngine;
  LEngine2: IAesLightEngine;
begin
  LEngine := TAesEngine.Create();

  try
    System.SetLength(LDudKey, 6);
    LEngine.Init(True, TKeyParameter.Create(LDudKey) as IKeyParameter);
    Fail('failed key length check');
  except
    on e: EArgumentCryptoLibException do
    begin
      // expected
    end;
  end;

  try
    System.SetLength(LIV, 16);
    LEngine.Init(True, TParametersWithIV.Create(nil, LIV) as IParametersWithIV);
    Fail('failed parameter check');
  except
    on e: EArgumentCryptoLibException do
    begin
      // expected
    end;
  end;

  LEngine2 := TAesLightEngine.Create();

  try
    System.SetLength(LDudKey, 6);
    LEngine2.Init(True, TKeyParameter.Create(LDudKey) as IKeyParameter);
    Fail('failed key length check');
  except
    on e: EArgumentCryptoLibException do
    begin
      // expected
    end;
  end;

  try
    System.SetLength(LIV, 16);
    LEngine2.Init(True, TParametersWithIV.Create(nil, LIV)
      as IParametersWithIV);
    Fail('failed parameter check');
  except
    on e: EArgumentCryptoLibException do
    begin
      // expected
    end;
  end;
end;

procedure TTestAES.TestCiphers;
var
  LI: Int32;
begin
  LI := 0;
  while LI <> System.Length(FCipherTestVectors) do
  begin
    DoCipherTest(StrToInt(FCipherTestVectors[LI]),
      DecodeHex(FCipherTestVectors[LI + 1]),
      DecodeHex(FCipherTestVectors[LI + 2]),
      DecodeHex(FCipherTestVectors[LI + 3]));
    System.Inc(LI, 4);
  end;
end;

procedure TTestAES.TestOids;
var
  LOids, LNames: TCryptoLibStringArray;
begin
  LOids := TCryptoLibStringArray.Create(
    TNistObjectIdentifiers.IdAes128Ecb.Id,
    TNistObjectIdentifiers.IdAes128Cbc.Id,
    TNistObjectIdentifiers.IdAes128Ofb.Id,
    TNistObjectIdentifiers.IdAes128Cfb.Id,
    TNistObjectIdentifiers.IdAes192Ecb.Id,
    TNistObjectIdentifiers.IdAes192Cbc.Id,
    TNistObjectIdentifiers.IdAes192Ofb.Id,
    TNistObjectIdentifiers.IdAes192Cfb.Id,
    TNistObjectIdentifiers.IdAes256Ecb.Id,
    TNistObjectIdentifiers.IdAes256Cbc.Id,
    TNistObjectIdentifiers.IdAes256Ofb.Id,
    TNistObjectIdentifiers.IdAes256Cfb.Id);

  LNames := TCryptoLibStringArray.Create(
    'AES/ECB/PKCS7Padding', 'AES/CBC/PKCS7Padding',
    'AES/OFB/NoPadding', 'AES/CFB/NoPadding',
    'AES/ECB/PKCS7Padding', 'AES/CBC/PKCS7Padding',
    'AES/OFB/NoPadding', 'AES/CFB/NoPadding',
    'AES/ECB/PKCS7Padding', 'AES/CBC/PKCS7Padding',
    'AES/OFB/NoPadding', 'AES/CFB/NoPadding');

  DoOidTest(LOids, LNames, 4);
end;

procedure TTestAES.TestAES_CBC_NOPADDING_WITH_IV;
var
  LKeyParametersWithIV: IParametersWithIV;
  LKeyBytes, LIVBytes: TBytes;
  LCipher: IBufferedCipher;
  LInput, LOutput: String;
  LI: Int32;
  LEngine: IAesEngine;
  LBlockCipher: ICbcBlockCipher;
begin
  LEngine := TAesEngine.Create();
  LBlockCipher := TCbcBlockCipher.Create(LEngine);
  LCipher := TBufferedBlockCipher.Create(LBlockCipher) as IBufferedBlockCipher;

  for LI := System.Low(FOfficialVectorKeys_AES_CBC)
    to System.High(FOfficialVectorKeys_AES_CBC) do
  begin
    LKeyBytes := DecodeHex(FOfficialVectorKeys_AES_CBC[LI]);
    LIVBytes := DecodeHex(FOfficialVectorIVs_AES_CBC[LI]);
    LInput := FOfficialVectorInputs_AES_CBC[LI];
    LOutput := FOfficialVectorOutputs_AES_CBC[LI];

    LKeyParametersWithIV := TParametersWithIV.Create
      (TParameterUtilities.CreateKeyParameter('AES', LKeyBytes), LIVBytes);

    DoAESTest(LCipher, LKeyParametersWithIV as ICipherParameters,
      LInput, LOutput);
  end;
end;

procedure TTestAES.TestAES_CBC_PKCS7PADDING_WITH_IV;
var
  LKeyParametersWithIV: IParametersWithIV;
  LKeyBytes, LIVBytes: TBytes;
  LCipher: IBufferedCipher;
  LInput, LOutput: String;
  LI: Int32;
begin
  LCipher := TCipherUtilities.GetCipher('AES/CBC/PKCS7PADDING');

  for LI := System.Low(FOfficialVectorKeys_AES_CBC)
    to System.High(FOfficialVectorKeys_AES_CBC) do
  begin
    LKeyBytes := DecodeHex(FOfficialVectorKeys_AES_CBC[LI]);
    LIVBytes := DecodeHex(FOfficialVectorIVs_AES_CBC[LI]);
    LInput := FOfficialVectorInputs_AES_CBC[LI];
    LOutput := FOfficialVectorOutputs_AES_CBC[LI];

    LKeyParametersWithIV := TParametersWithIV.Create
      (TParameterUtilities.CreateKeyParameter('AES', LKeyBytes), LIVBytes);

    DoAESTest(LCipher, LKeyParametersWithIV as ICipherParameters,
      LInput, LOutput, True);
  end;
end;

procedure TTestAES.TestAES_CFB_NOPADDING_WITH_IV;
var
  LKeyParametersWithIV: IParametersWithIV;
  LKeyBytes, LIVBytes: TBytes;
  LCipher: IBufferedCipher;
  LInput, LOutput: String;
  LI: Int32;
  LEngine: IAesEngine;
  LBlockCipher: ICfbBlockCipher;
begin
  LEngine := TAesEngine.Create();
  LBlockCipher := TCfbBlockCipher.Create(LEngine, LEngine.GetBlockSize * 8);
  LCipher := TBufferedBlockCipher.Create(LBlockCipher) as IBufferedBlockCipher;

  for LI := System.Low(FOfficialVectorKeys_AES_CFB)
    to System.High(FOfficialVectorKeys_AES_CFB) do
  begin
    LKeyBytes := DecodeHex(FOfficialVectorKeys_AES_CFB[LI]);
    LIVBytes := DecodeHex(FOfficialVectorIVs_AES_CFB[LI]);
    LInput := FOfficialVectorInputs_AES_CFB[LI];
    LOutput := FOfficialVectorOutputs_AES_CFB[LI];

    LKeyParametersWithIV := TParametersWithIV.Create
      (TParameterUtilities.CreateKeyParameter('AES', LKeyBytes), LIVBytes);

    DoAESTest(LCipher, LKeyParametersWithIV as ICipherParameters,
      LInput, LOutput);
  end;
end;

procedure TTestAES.TestAES_CTR_NOPADDING_WITH_IV;
var
  LKeyParametersWithIV: IParametersWithIV;
  LKeyBytes, LIVBytes: TBytes;
  LCipher: IBufferedCipher;
  LInput, LOutput: String;
  LI: Int32;
  LEngine: IAesEngine;
  LBlockCipher: ISicBlockCipher;
begin
  LEngine := TAesEngine.Create();
  LBlockCipher := TSicBlockCipher.Create(LEngine);
  LCipher := TBufferedBlockCipher.Create(LBlockCipher) as IBufferedBlockCipher;

  for LI := System.Low(FOfficialVectorKeys_AES_CTR)
    to System.High(FOfficialVectorKeys_AES_CTR) do
  begin
    LKeyBytes := DecodeHex(FOfficialVectorKeys_AES_CTR[LI]);
    LIVBytes := DecodeHex(FOfficialVectorIVs_AES_CTR[LI]);
    LInput := FOfficialVectorInputs_AES_CTR[LI];
    LOutput := FOfficialVectorOutputs_AES_CTR[LI];

    LKeyParametersWithIV := TParametersWithIV.Create
      (TParameterUtilities.CreateKeyParameter('AES', LKeyBytes), LIVBytes);

    DoAESTest(LCipher, LKeyParametersWithIV as ICipherParameters,
      LInput, LOutput);
  end;
end;

procedure TTestAES.TestAES_ECB_NOPADDING_NO_IV;
var
  LKeyParameter: IKeyParameter;
  LKeyBytes: TBytes;
  LCipher: IBufferedCipher;
  LInput, LOutput: String;
  LI: Int32;
  LEngine: IAesEngine;
  LBlockCipher: IBlockCipher;
begin
  LEngine := TAesEngine.Create();
  LBlockCipher := LEngine as IBlockCipher;
  LCipher := TBufferedBlockCipher.Create(LBlockCipher) as IBufferedBlockCipher;

  for LI := System.Low(FOfficialVectorKeys_AES_ECB)
    to System.High(FOfficialVectorKeys_AES_ECB) do
  begin
    LKeyBytes := DecodeHex(FOfficialVectorKeys_AES_ECB[LI]);
    LInput := FOfficialVectorInputs_AES_ECB[LI];
    LOutput := FOfficialVectorOutputs_AES_ECB[LI];

    LKeyParameter := TParameterUtilities.CreateKeyParameter('AES', LKeyBytes);

    DoAESTest(LCipher, LKeyParameter as ICipherParameters, LInput, LOutput);
  end;
end;

procedure TTestAES.TestAES_OFB_NOPADDING_WITH_IV;
var
  LKeyParametersWithIV: IParametersWithIV;
  LKeyBytes, LIVBytes: TBytes;
  LCipher: IBufferedCipher;
  LInput, LOutput: String;
  LI: Int32;
  LEngine: IAesEngine;
  LBlockCipher: IOfbBlockCipher;
begin
  LEngine := TAesEngine.Create();
  LBlockCipher := TOfbBlockCipher.Create(LEngine, LEngine.GetBlockSize * 8);
  LCipher := TBufferedBlockCipher.Create(LBlockCipher) as IBufferedBlockCipher;

  for LI := System.Low(FOfficialVectorKeys_AES_OFB)
    to System.High(FOfficialVectorKeys_AES_OFB) do
  begin
    LKeyBytes := DecodeHex(FOfficialVectorKeys_AES_OFB[LI]);
    LIVBytes := DecodeHex(FOfficialVectorIVs_AES_OFB[LI]);
    LInput := FOfficialVectorInputs_AES_OFB[LI];
    LOutput := FOfficialVectorOutputs_AES_OFB[LI];

    LKeyParametersWithIV := TParametersWithIV.Create
      (TParameterUtilities.CreateKeyParameter('AES', LKeyBytes), LIVBytes);

    DoAESTest(LCipher, LKeyParametersWithIV as ICipherParameters,
      LInput, LOutput);
  end;
end;

procedure TTestAES.TestWrap;
begin
  DoWrapTest(1, 'AESWrap',
    DecodeHex('000102030405060708090a0b0c0d0e0f'),
    DecodeHex('00112233445566778899aabbccddeeff'),
    DecodeHex('1fa68b0a8112b447aef34bd8fb5a7b829d3e862371d2cfe5'));
end;

procedure TTestAES.TestWrapRfc3211;
var
  LKek: TBytes;
begin
  LKek := DecodeHex('000102030405060708090a0b0c0d0e0f');
  DoWrapTest(2, 'AESRFC3211WRAP',
    LKek, LKek,
    TFixedSecureRandom.From(
      TCryptoLibMatrixByteArray.Create(
        DecodeHex('9688df2af1b7b1ac9688df2a'))),
    DecodeHex('00112233445566778899aabbccddeeff'),
    DecodeHex('7c8798dfc802553b3f00bb4315e3a087322725c92398b9c112c74d0925c63b61'));
end;

procedure TTestAES.TestWrapRfc5649;
begin
  DoWrapTest(3, 'AESWrapPad',
    DecodeHex('5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8'),
    DecodeHex('c37b7e6492584340bed12207808941155068f738'),
    DecodeHex('138bdeaa9b8fa7fc61f97742e72248ee5ae6ae5360d1ae6a5f54f373fa543b6a'));
end;

procedure TTestAES.TestWrapOids;
var
  LWrapOids: TCryptoLibStringArray;
begin
  LWrapOids := TCryptoLibStringArray.Create(
    TNistObjectIdentifiers.IdAes128Wrap.Id,
    TNistObjectIdentifiers.IdAes192Wrap.Id,
    TNistObjectIdentifiers.IdAes256Wrap.Id);

  DoWrapOidTest(LWrapOids, 'AESWrap');
end;

procedure TTestAES.TestWrapPadOids;
var
  LWrapPadOids: TCryptoLibStringArray;
begin
  LWrapPadOids := TCryptoLibStringArray.Create(
    TNistObjectIdentifiers.IdAes128WrapPad.Id,
    TNistObjectIdentifiers.IdAes192WrapPad.Id,
    TNistObjectIdentifiers.IdAes256WrapPad.Id);

  DoWrapOidTest(LWrapPadOids, 'AESWrapPad');
end;

procedure TTestAES.TestAesEax;
var
  LK, LN, LP, LC: TBytes;
  LKeyParam: IKeyParameter;
  LInCipher, LOutCipher: IBufferedCipher;
  LEnc, LDec: TBytes;
begin
  // AES/EAX single vector
  LK := DecodeHex('233952DEE4D5ED5F9B9C6D6FF80FF478');
  LN := DecodeHex('62EC67F9C3A4A407FCB2A8C49031A8B3');
  LP := DecodeHex('68656c6c6f20776f726c642121');
  LC := DecodeHex('2f9f76cb7659c70e4be11670a3e193ae1bc6b5762a');

  LKeyParam := TParameterUtilities.CreateKeyParameter('AES', LK);

  LInCipher := TCipherUtilities.GetCipher('AES/EAX/NoPadding');
  LOutCipher := TCipherUtilities.GetCipher('AES/EAX/NoPadding');

  LInCipher.Init(True, TParametersWithIV.Create(LKeyParam, LN) as ICipherParameters);
  LEnc := LInCipher.DoFinal(LP);
  if not AreEqual(LEnc, LC) then
  begin
    Fail('ciphertext does not match in AES/EAX');
  end;

  LOutCipher.Init(False, TParametersWithIV.Create(LKeyParam, LN) as ICipherParameters);
  LDec := LOutCipher.DoFinal(LC);
  if not AreEqual(LDec, LP) then
  begin
    Fail('plaintext does not match in AES/EAX');
  end;
end;

procedure TTestAES.TestAesEaxBadPadding;
var
  LK: TBytes;
  LKeyParam: IKeyParameter;
begin
  LK := DecodeHex('233952DEE4D5ED5F9B9C6D6FF80FF478');
  LKeyParam := TParameterUtilities.CreateKeyParameter('AES', LK);
  try
    TCipherUtilities.GetCipher('AES/EAX/PKCS5Padding');
    Fail('bad padding missed in AES/EAX');
  except
    on E: ESecurityUtilityCryptoLibException do
    begin
      // expected
    end;
  end;
end;

procedure TTestAES.TestAesCcm;
var
  LK, LN, LP, LC: TBytes;
  LKeyParam: IKeyParameter;
  LInCipher, LOutCipher: IBufferedCipher;
  LEnc, LDec: TBytes;
begin
  // AES/CCM single vector
  LK := DecodeHex('404142434445464748494A4B4C4D4E4F');
  LN := DecodeHex('10111213141516');
  LP := DecodeHex('68656c6c6f20776f726c642121');
  LC := DecodeHex('39264f148b54c456035de0a531c8344f46db12b388');

  LKeyParam := TParameterUtilities.CreateKeyParameter('AES', LK);

  LInCipher := TCipherUtilities.GetCipher('AES/CCM/NoPadding');
  LOutCipher := TCipherUtilities.GetCipher('AES/CCM/NoPadding');

  LInCipher.Init(True, TParametersWithIV.Create(LKeyParam, LN) as ICipherParameters);
  LEnc := LInCipher.DoFinal(LP);
  if not AreEqual(LEnc, LC) then
  begin
    Fail('ciphertext does not match in AES/CCM');
  end;

  LOutCipher.Init(False, TParametersWithIV.Create(LKeyParam, LN) as ICipherParameters);
  LDec := LOutCipher.DoFinal(LC);
  if not AreEqual(LDec, LP) then
  begin
    Fail('plaintext does not match in AES/CCM');
  end;
end;

procedure TTestAES.TestAesCcmBadPadding;
var
  LK: TBytes;
  LKeyParam: IKeyParameter;
begin
  LK := DecodeHex('404142434445464748494A4B4C4D4E4F');
  LKeyParam := TParameterUtilities.CreateKeyParameter('AES', LK);
  try
    TCipherUtilities.GetCipher('AES/CCM/PKCS5Padding');
    Fail('bad padding missed in AES/CCM');
  except
    on E: ESecurityUtilityCryptoLibException do
    begin
      // expected
    end;
  end;
end;

procedure TTestAES.TestAesOcb;
var
  LK, LN, LP, LC: TBytes;
  LKeyParam: IKeyParameter;
  LInCipher, LOutCipher: IBufferedCipher;
  LEnc, LDec: TBytes;
begin
  // AES/OCB single vector
  LK := DecodeHex('000102030405060708090A0B0C0D0E0F');
  LP := DecodeHex('000102030405060708090A0B0C0D0E0F');
  LN := DecodeHex('000102030405060708090A0B');
  LC := DecodeHex('BEA5E8798DBE7110031C144DA0B2612213CC8B747807121A4CBB3E4BD6B456AF');

  LKeyParam := TParameterUtilities.CreateKeyParameter('AES', LK);

  LInCipher := TCipherUtilities.GetCipher('AES/OCB/NoPadding');
  LOutCipher := TCipherUtilities.GetCipher('AES/OCB/NoPadding');

  LInCipher.Init(True, TParametersWithIV.Create(LKeyParam, LN) as ICipherParameters);
  LEnc := LInCipher.DoFinal(LP);
  if not AreEqual(LEnc, LC) then
  begin
    Fail('ciphertext does not match in AES/OCB');
  end;

  LOutCipher.Init(False, TParametersWithIV.Create(LKeyParam, LN) as ICipherParameters);
  LDec := LOutCipher.DoFinal(LC);
  if not AreEqual(LDec, LP) then
  begin
    Fail('plaintext does not match in AES/OCB');
  end;
end;

procedure TTestAES.TestAesOcbBadPadding;
var
  LK: TBytes;
  LKeyParam: IKeyParameter;
begin
  LK := DecodeHex('000102030405060708090A0B0C0D0E0F');
  LKeyParam := TParameterUtilities.CreateKeyParameter('AES', LK);
  try
    TCipherUtilities.GetCipher('AES/OCB/PKCS5Padding');
    Fail('bad padding missed in AES/OCB');
  except
    on E: ESecurityUtilityCryptoLibException do
    begin
      // expected
    end;
  end;
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestAES);
{$ELSE}
  RegisterTest(TTestAES.Suite);
{$ENDIF FPC}

end.
