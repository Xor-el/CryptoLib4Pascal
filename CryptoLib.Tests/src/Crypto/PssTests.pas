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

unit PssTests;

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
  ClpIRsaKeyParameters,
  ClpRsaKeyParameters,
  ClpIRsaPrivateCrtKeyParameters,
  ClpRsaPrivateCrtKeyParameters,
  ClpIRsaKeyGenerationParameters,
  ClpRsaKeyGenerationParameters,
  ClpParametersWithRandom,
  ClpIParametersWithRandom,
  ClpIRsaKeyPairGenerator,
  ClpRsaKeyPairGenerator,
  ClpRsaEngine,
  ClpRsaBlindedEngine,
  ClpPssSigner,
  ClpIPssSigner,
  ClpDigestUtilities,
  ClpIDigest,
  ClpIAsymmetricCipherKeyPair,
  ClpISigner,
  ClpSignerUtilities,
  ClpISecureRandom,
  ClpSecureRandom,
  ClpConverters,
  ClpArrayUtilities,
  ClpEncoders,
  ClpCryptoLibTypes,
  CryptoLibTestBase;

type
  /// <summary>
  /// A SecureRandom that returns a fixed, pre-supplied byte sequence.
  /// </summary>
  IFixedRandom = interface(ISecureRandom)
    ['{B0E9B1D4-7E9D-4E2B-9C9C-2E0E6B2C7F7D}']
    procedure NextBytes(const ABuf: TCryptoLibByteArray); overload;
    procedure NextBytes(const ABuf: TCryptoLibByteArray; AOff, ALen: Int32); overload;
  end;

  /// <summary>
  /// Returns deterministic bytes by copying from FVals into the output buffer.
  /// </summary>
  TFixedRandom = class(TSecureRandom, IFixedRandom)
  private
    FVals: TCryptoLibByteArray;
  public
    constructor Create(const AVals: TCryptoLibByteArray);

    procedure NextBytes(const ABuf: TCryptoLibByteArray); override;
    procedure NextBytes(const ABuf: TCryptoLibByteArray; AOff, ALen: Int32); override;
  end;

type

  TTestPss = class(TCryptoLibAlgorithmTestCase)
  private
  const
    NumLoopTests = 50;

  class var
    // Example 1: A 1024-bit RSA keypair
    FPub1: IRsaKeyParameters;
    FPrv1: IRsaPrivateCrtKeyParameters;
    FMsg1a, FSlt1a, FSig1a: TCryptoLibByteArray;
    FMsg1b, FSlt1b, FSig1b: TCryptoLibByteArray;

    // Example 2: A 1025-bit RSA keypair
    FPub2: IRsaKeyParameters;
    FPrv2: IRsaPrivateCrtKeyParameters;
    FMsg2a, FSlt2a, FSig2a: TCryptoLibByteArray;

    // Example 4: A 1027-bit RSA key pair
    FPub4: IRsaKeyParameters;
    FPrv4: IRsaPrivateCrtKeyParameters;
    FMsg4a, FSlt4a, FSig4a: TCryptoLibByteArray;

    // Example 8: A 1031-bit RSA key pair
    FPub8: IRsaKeyParameters;
    FPrv8: IRsaPrivateCrtKeyParameters;
    FMsg8a, FSlt8a, FSig8a: TCryptoLibByteArray;

    // Example 9: A 1536-bit RSA key pair
    FPub9: IRsaKeyParameters;
    FPrv9: IRsaPrivateCrtKeyParameters;
    FMsg9a, FSlt9a, FSig9a: TCryptoLibByteArray;
    FSecureRandom: ISecureRandom;

    class constructor CreateTestPss;

    procedure DoTestPssSignature(id: Integer; const pub, prv: IRsaKeyParameters;
      const salt, msg, sig: TCryptoLibByteArray);
    procedure DoTestLoopSha1;
    procedure DoTestLoopMixedDigest;
    procedure DoTestFixedSalt;
    procedure DoTestSha512ZeroSalt;
    procedure DoSignerUtilitiesSha1;
    procedure DoSignerUtilitiesSha256;
    procedure DoSignerUtilitiesSha384;
    procedure DoSignerUtilitiesSha512;
    procedure DoRawSignerTest;

  published
    procedure TestPssVectors;
    procedure TestLoopSha1;
    procedure TestLoopMixedDigest;
    procedure TestFixedSalt;
    procedure TestSha512ZeroSalt;
    procedure TestSignerUtilitiesSha1;
    procedure TestSignerUtilitiesSha256;
    procedure TestSignerUtilitiesSha384;
    procedure TestSignerUtilitiesSha512;
    procedure TestRawSigner;

  end;

implementation

{ TFixedRandom }

constructor TFixedRandom.Create(const AVals: TCryptoLibByteArray);
begin
  inherited Create;

  FVals := System.Copy(AVals);
end;

procedure TFixedRandom.NextBytes(const ABuf: TCryptoLibByteArray);
begin
  NextBytes(ABuf, 0, System.Length(ABuf));
end;

procedure TFixedRandom.NextBytes(const ABuf: TCryptoLibByteArray; AOff, ALen: Int32);
begin
  System.Move(FVals[0], ABuf[AOff], ALen);
end;

{ TTestPss }

class constructor TTestPss.CreateTestPss;
begin
  // Example 1: A 1024-bit RSA keypair
  FPub1 := TRsaKeyParameters.Create(False,
    TBigInteger.Create('a56e4a0e701017589a5187dc7ea841d156f2ec0e36ad52a44dfeb1e61f7ad991d8c51056ffedb162b4c0f283a12a88a394dff526ab7291cb' + 'b307ceabfce0b1dfd5cd9508096d5b2b8b6df5d671ef6377c0921cb23c270a70e2598e6ff89d19f105acc2d3f0cb35f29280e1386b6f64c4ef22e1e1f20d0ce8cffb2249bd9a2137', 16),
    TBigInteger.Create('010001', 16));

  FPrv1 := TRsaPrivateCrtKeyParameters.Create(
    TBigInteger.Create('a56e4a0e701017589a5187dc7ea841d156f2ec0e36ad52a44dfeb1e61f7ad991d8c51056ffedb162b4c0f283a12a88a394dff526ab7291cbb30' + '7ceabfce0b1dfd5cd9508096d5b2b8b6df5d671ef6377c0921cb23c270a70e2598e6ff89d19f105acc2d3f0cb35f29280e1386b6f64c4ef22e1e1f20d0ce8cffb2249bd9a2137', 16),
    TBigInteger.Create('010001', 16),
    TBigInteger.Create('33a5042a90b27d4f5451ca9bbbd0b44771a101af884340aef9885f2a4bbe92e894a724ac3c568c8f97853ad07c0266c8c6a3ca0929f1e8f112318' + '84429fc4d9ae55fee896a10ce707c3ed7e734e44727a39574501a532683109c2abacaba283c31b4bd2f53c3ee37e352cee34f9e503bd80c0622ad79c6dcee883547c6a3b325', 16),
    TBigInteger.Create('e7e8942720a877517273a356053ea2a1bc0c94aa72d55c6e86296b2dfc967948c0a72cbccca7eacb35706e09a1df55a1535bd9b3cc34160b3b6dcd3eda8e6443', 16),
    TBigInteger.Create('b69dca1cf7d4d7ec81e75b90fcca874abcde123fd2700180aa90479b6e48de8d67ed24f9f19d85ba275874f542cd20dc723e6963364a1f9425452b269a6799fd', 16),
    TBigInteger.Create('28fa13938655be1f8a159cbaca5a72ea190c30089e19cd274a556f36c4f6e19f554b34c077790427bbdd8dd3ede2448328f385d81b30e8e43b2fffa027861979', 16),
    TBigInteger.Create('1a8b38f398fa712049898d7fb79ee0a77668791299cdfa09efc0e507acb21ed74301ef5bfd48be455eaeb6e1678255827580a8e4e8e14151d1510a82a3f2e729', 16),
    TBigInteger.Create('27156aba4126d24a81f3a528cbfb27f56886f840a9f6e86e17a44b94fe9319584b8e22fdde1e5a2e3bd8aa5ba8d8584194eb2190acf832b847f13a3d24a79f4d', 16));

  // PSSExample1.1
  FMsg1a := THex.Decode('cdc87da223d786df3b45e0bbbc721326d1ee2af806cc315475cc6f0d9c66e1b62371d45ce2392e1ac92844c310102f156a0d8d52c1f4c40ba3aa65095' + '786cb769757a6563ba958fed0bcc984e8b517a3d5f515b23b8a41e74aa867693f90dfb061a6e86dfaaee64472c00e5f20945729cbebe77f06ce78e08f4098fba' + '41f9d6193c0317e8b60d4b6084acb42d29e3808a3bc372d85e331170fcbf7cc72d0b71c296648b3a4d10f416295d0807aa625cab2744fd9ea8fd223c42537029828bd16be02546f130fd2e33b936d2676e08aed1b73318b750a0167d0');
  FSlt1a := THex.Decode('dee959c7e06411361420ff80185ed57f3e6776af');
  FSig1a := THex.Decode('9074308fb598e9701b2294388e52f971faac2b60a5145af185df5287b5ed2887e57ce7fd44dc8634e407c8e0e4360bc226f3ec227f9d9e54638e8d31f5' + '051215df6ebb9c2f9579aa77598a38f914b5b9c1bd83c4e2f9f382a0d0aa3542ffee65984a601bc69eb28deb27dca12c82c2d4c3f66cd500f1ff2b994d8a4e30cbb33c');

  // PSSExample1.2
  FMsg1b := THex.Decode('851384cdfe819c22ed6c4ccb30daeb5cf059bc8e1166b7e3530c4c233e2b5f8f71a1cca582d43ecc72b1bca16dfc7013226b9e');
  FSlt1b := THex.Decode('ef2869fa40c346cb183dab3d7bffc98fd56df42d');
  FSig1b := THex.Decode('3ef7f46e831bf92b32274142a585ffcefbdca7b32ae90d10fb0f0c729984f04ef29a9df0780775ce43739b97838390db0a5505e63de927028d9d29b219ca2c' + '4517832558a55d694a6d25b9dab66003c4cccd907802193be5170d26147d37b93590241be51c25055f47ef62752cfbe21418fafe98c22c4d4d47724fdb5669e843');

  // Example 2: A 1025-bit RSA keypair
  FPub2 := TRsaKeyParameters.Create(False,
    TBigInteger.Create('01d40c1bcf97a68ae7cdbd8a7bf3e34fa19dcca4ef75a47454375f94514d88fed006fb829f8419ff87d6315da68a1ff3a0938e9abb3464011c303ad99199cf0c' + '7c7a8b477dce829e8844f625b115e5e9c4a59cf8f8113b6834336a2fd2689b472cbb5e5cabe674350c59b6c17e176874fb42f8fc3d176a017edc61fd326c4b33c9', 16),
    TBigInteger.Create('010001', 16));

  FPrv2 := TRsaPrivateCrtKeyParameters.Create(
    TBigInteger.Create('01d40c1bcf97a68ae7cdbd8a7bf3e34fa19dcca4ef75a47454375f94514d88fed006fb829f8419ff87d6315da68a1ff3a0938e9abb3464011c303ad99199cf0c' + '7c7a8b477dce829e8844f625b115e5e9c4a59cf8f8113b6834336a2fd2689b472cbb5e5cabe674350c59b6c17e176874fb42f8fc3d176a017edc61fd326c4b33c9', 16),
    TBigInteger.Create('010001', 16),
    TBigInteger.Create('027d147e4673057377fd1ea201565772176a7dc38358d376045685a2e787c23c15576bc16b9f444402d6bfc5d98a3e88ea13ef67c353eca0c0ddba9255bd7b8bb' + '50a644afdfd1dd51695b252d22e7318d1b6687a1c10ff75545f3db0fe602d5f2b7f294e3601eab7b9d1cecd767f64692e3e536ca2846cb0c2dd486a39fa75b1', 16),
    TBigInteger.Create('016601e926a0f8c9e26ecab769ea65a5e7c52cc9e080ef519457c644da6891c5a104d3ea7955929a22e7c68a7af9fcad777c3ccc2b9e3d3650bce404399b7e59d1', 16),
    TBigInteger.Create('014eafa1d4d0184da7e31f877d1281ddda625664869e8379e67ad3b75eae74a580e9827abd6eb7a002cb5411f5266797768fb8e95ae40e3e8a01f35ff89e56c079', 16),
    TBigInteger.Create('e247cce504939b8f0a36090de200938755e2444b29539a7da7a902f6056835c0db7b52559497cfe2c61a8086d0213c472c78851800b171f6401de2e9c2756f31', 16),
    TBigInteger.Create('b12fba757855e586e46f64c38a70c68b3f548d93d787b399999d4c8f0bbd2581c21e19ed0018a6d5d3df86424b3abcad40199d31495b61309f27c1bf55d487c1', 16),
    TBigInteger.Create('564b1e1fa003bda91e89090425aac05b91da9ee25061e7628d5f51304a84992fdc33762bd378a59f030a334d532bd0dae8f298ea9ed844636ad5fb8cbdc03cad', 16));

  // PSS Example 2.1
  FMsg2a := THex.Decode('daba032066263faedb659848115278a52c44faa3a76f37515ed336321072c40a9d9b53bc05014078adf520875146aae70ff060226dcb7b1f1fc27e9360');
  FSlt2a := THex.Decode('57bf160bcb02bb1dc7280cf0458530b7d2832ff7');
  FSig2a := THex.Decode('014c5ba5338328ccc6e7a90bf1c0ab3fd606ff4796d3c12e4b639ed9136a5fec6c16d8884bdd99cfdc521456b0742b736868cf90de099adb8d5ffd1deff39ba4007' + 'ab746cefdb22d7df0e225f54627dc65466131721b90af445363a8358b9f607642f78fab0ab0f43b7168d64bae70d8827848d8ef1e421c5754ddf42c2589b5b3');

  // Example 4: A 1027-bit RSA key pair
  FPub4 := TRsaKeyParameters.Create(False,
    TBigInteger.Create('054adb7886447efe6f57e0368f06cf52b0a3370760d161cef126b91be7f89c421b62a6ec1da3c311d75ed50e0ab5fff3fd338acc3aa8a4e77ee26369acb81ba900fa' + '83f5300cf9bb6c53ad1dc8a178b815db4235a9a9da0c06de4e615ea1277ce559e9c108de58c14a81aa77f5a6f8d1335494498848c8b95940740be7bf7c3705', 16),
    TBigInteger.Create('010001', 16));

  FPrv4 := TRsaPrivateCrtKeyParameters.Create(
    TBigInteger.Create('054adb7886447efe6f57e0368f06cf52b0a3370760d161cef126b91be7f89c421b62a6ec1da3c311d75ed50e0ab5fff3fd338acc3aa8a4e77ee26369acb81ba900fa83' + 'f5300cf9bb6c53ad1dc8a178b815db4235a9a9da0c06de4e615ea1277ce559e9c108de58c14a81aa77f5a6f8d1335494498848c8b95940740be7bf7c3705', 16),
    TBigInteger.Create('010001', 16),
    TBigInteger.Create('fa041f8cd9697ceed38ec8caa275523b4dd72b09a301d3541d72f5d31c05cbce2d6983b36183af10690bd46c46131e35789431a556771dd0049b57461bf060c1f68472e' + '8a67c25f357e5b6b4738fa541a730346b4a07649a2dfa806a69c975b6aba64678acc7f5913e89c622f2d8abb1e3e32554e39df94ba60c002e387d9011', 16),
    TBigInteger.Create('029232336d2838945dba9dd7723f4e624a05f7375b927a87abe6a893a1658fd49f47f6c7b0fa596c65fa68a23f0ab432962d18d4343bd6fd671a5ea8d148413995', 16),
    TBigInteger.Create('020ef5efe7c5394aed2272f7e81a74f4c02d145894cb1b3cab23a9a0710a2afc7e3329acbb743d01f680c4d02afb4c8fde7e20930811bb2b995788b5e872c20bb1', 16),
    TBigInteger.Create('026e7e28010ecf2412d9523ad704647fb4fe9b66b1a681581b0e15553a89b1542828898f27243ebab45ff5e1acb9d4df1b051fbc62824dbc6f6c93261a78b9a759', 16),
    TBigInteger.Create('012ddcc86ef655998c39ddae11718669e5e46cf1495b07e13b1014cd69b3af68304ad2a6b64321e78bf3bbca9bb494e91d451717e2d97564c6549465d0205cf421', 16),
    TBigInteger.Create('010600c4c21847459fe576703e2ebecae8a5094ee63f536bf4ac68d3c13e5e4f12ac5cc10ab6a2d05a199214d1824747d551909636b774c22cac0b837599abcc75', 16));

  // PSS Example 4.1
  FMsg4a := THex.Decode('9fb03b827c8217d9');
  FSlt4a := THex.Decode('ed7c98c95f30974fbe4fbddcf0f28d6021c0e91d');
  FSig4a := THex.Decode('0323d5b7bf20ba4539289ae452ae4297080feff4518423ff4811a817837e7d82f1836cdfab54514ff0887bddeebf40bf99b047abc3ecfa6a37a3ef00f4a0c4a88aae090' + '4b745c846c4107e8797723e8ac810d9e3d95dfa30ff4966f4d75d13768d20857f2b1406f264cfe75e27d7652f4b5ed3575f28a702f8c4ed9cf9b2d44948');

  // Example 8: A 1031-bit RSA key pair
  FPub8 := TRsaKeyParameters.Create(False,
    TBigInteger.Create('495370a1fb18543c16d3631e3163255df62be6eee890d5f25509e4f778a8ea6fbbbcdf85dff64e0d972003ab3681fbba6dd41fd541829b2e582de9f2a4a4e0a2d0900bef47' + '53db3cee0ee06c7dfae8b1d53b5953218f9cceea695b08668edeaadced9463b1d790d5ebf27e9115b46cad4d9a2b8efab0561b0810344739ada0733f', 16),
    TBigInteger.Create('010001', 16));

  FPrv8 := TRsaPrivateCrtKeyParameters.Create(
    TBigInteger.Create('495370a1fb18543c16d3631e3163255df62be6eee890d5f25509e4f778a8ea6fbbbcdf85dff64e0d972003ab3681fbba6dd41fd541829b2e582de9f2a4a4e0a2d0900bef475' + '3db3cee0ee06c7dfae8b1d53b5953218f9cceea695b08668edeaadced9463b1d790d5ebf27e9115b46cad4d9a2b8efab0561b0810344739ada0733f', 16),
    TBigInteger.Create('010001', 16),
    TBigInteger.Create('6c66ffe98980c38fcdeab5159898836165f4b4b817c4f6a8d486ee4ea9130fe9b9092bd136d184f95f504a607eac565846d2fdd6597a8967c7396ef95a6eeebb4578a643966d' + 'ca4d8ee3de842de63279c618159c1ab54a89437b6a6120e4930afb52a4ba6ced8a4947ac64b30a3497cbe701c2d6266d517219ad0ec6d347dbe9', 16),
    TBigInteger.Create('08dad7f11363faa623d5d6d5e8a319328d82190d7127d2846c439b0ab72619b0a43a95320e4ec34fc3a9cea876422305bd76c5ba7be9e2f410c8060645a1d29edb', 16),
    TBigInteger.Create('0847e732376fc7900f898ea82eb2b0fc418565fdae62f7d9ec4ce2217b97990dd272db157f99f63c0dcbb9fbacdbd4c4dadb6df67756358ca4174825b48f49706d', 16),
    TBigInteger.Create('05c2a83c124b3621a2aa57ea2c3efe035eff4560f33ddebb7adab81fce69a0c8c2edc16520dda83d59a23be867963ac65f2cc710bbcfb96ee103deb771d105fd85', 16),
    TBigInteger.Create('04cae8aa0d9faa165c87b682ec140b8ed3b50b24594b7a3b2c220b3669bb819f984f55310a1ae7823651d4a02e99447972595139363434e5e30a7e7d241551e1b9', 16),
    TBigInteger.Create('07d3e47bf686600b11ac283ce88dbb3f6051e8efd04680e44c171ef531b80b2b7c39fc766320e2cf15d8d99820e96ff30dc69691839c4b40d7b06e45307dc91f3f', 16));

  // PSS Example 8.1
  FMsg8a := THex.Decode('81332f4be62948415ea1d899792eeacf6c6e1db1da8be13b5cea41db2fed467092e1ff398914c714259775f595f8547f735692a575e6923af78f22c6997ddb90fb6f72d7bb0dd' + '5744a31decd3dc3685849836ed34aec596304ad11843c4f88489f209735f5fb7fdaf7cec8addc5818168f880acbf490d51005b7a8e84e43e54287977571dd99eea4b161eb2df1f5108f12a4142a83322edb05a75487a3435c9a78ce53ed93bc550857d7a9fb');
  FSlt8a := THex.Decode('1d65491d79c864b373009be6f6f2467bac4c78fa');
  FSig8a := THex.Decode('0262ac254bfa77f3c1aca22c5179f8f040422b3c5bafd40a8f21cf0fa5a667ccd5993d42dbafb409c520e25fce2b1ee1e716577f1efa17f3da28052f40f0419b23106d7845aaf0' + '1125b698e7a4dfe92d3967bb00c4d0d35ba3552ab9a8b3eef07c7fecdbc5424ac4db1e20cb37d0b2744769940ea907e17fbbca673b20522380c5');

  // Example 9: A 1536-bit RSA key pair
  FPub9 := TRsaKeyParameters.Create(False,
    TBigInteger.Create('e6bd692ac96645790403fdd0f5beb8b9bf92ed10007fc365046419dd06c05c5b5b2f48ecf989e4ce269109979cbb40b4a0ad24d22483d1ee315ad4ccb1534268352691c524f6dd8e' + '6c29d224cf246973aec86c5bf6b1401a850d1b9ad1bb8cbcec47b06f0f8c7f45d3fc8f319299c5433ddbc2b3053b47ded2ecd4a4caefd614833dc8bb622f317ed076b8057fe8de3f84480ad5e83e4a61904a4f248fb397027357e1d30e463139815c6fd4fd5ac5b8172a45230ecb6318a04f1455d84e5a8b', 16),
    TBigInteger.Create('010001', 16));

  FPrv9 := TRsaPrivateCrtKeyParameters.Create(
    TBigInteger.Create('e6bd692ac96645790403fdd0f5beb8b9bf92ed10007fc365046419dd06c05c5b5b2f48ecf989e4ce269109979cbb40b4a0ad24d22483d1ee315ad4ccb1534268352691c524f6dd8e6' + 'c29d224cf246973aec86c5bf6b1401a850d1b9ad1bb8cbcec47b06f0f8c7f45d3fc8f319299c5433ddbc2b3053b47ded2ecd4a4caefd614833dc8bb622f317ed076b8057fe8de3f84480ad5e83e4a61904a4f248fb397027357e1d30e463139815c6fd4fd5ac5b8172a45230ecb6318a04f1455d84e5a8b', 16),
    TBigInteger.Create('010001', 16),
    TBigInteger.Create('6a7fd84fb85fad073b34406db74f8d61a6abc12196a961dd79565e9da6e5187bce2d980250f7359575359270d91590bb0e427c71460b55d51410b191bcf309fea131a92c8e702738fa' + '719f1e0041f52e40e91f229f4d96a1e6f172e15596b4510a6daec26105f2bebc53316b87bdf21311666070e8dfee69d52c71a976caae79c72b68d28580dc686d9f5129d225f82b3d615513a882b3db91416b48ce08888213e37eeb9af800d81cab328ce420689903c00c7b5fd31b75503a6d419684d629', 16),
    TBigInteger.Create('f8eb97e98df12664eefdb761596a69ddcd0e76daece6ed4bf5a1b50ac086f7928a4d2f8726a77e515b74da41988f220b1cc87aa1fc810ce99a82f2d1ce821edced794c6941f42c7a1a0b8c4d28c75ec60b652279f6154a762aed165d47dee367', 16),
    TBigInteger.Create('ed4d71d0a6e24b93c2e5f6b4bbe05f5fb0afa042d204fe3378d365c2f288b6a8dad7efe45d153eef40cacc7b81ff934002d108994b94a5e4728cd9c963375ae49965bda55cbf0efed8d6553b4027f2d86208a6e6b489c176128092d629e49d3d', 16),
    TBigInteger.Create('2bb68bddfb0c4f56c8558bffaf892d8043037841e7fa81cfa61a38c5e39b901c8ee71122a5da2227bd6cdeeb481452c12ad3d61d5e4f776a0ab556591befe3e59e5a7fddb8345e1f2f35b9f4cee57c32414c086aec993e9353e480d9eec6289f', 16),
    TBigInteger.Create('4ff897709fad079746494578e70fd8546130eeab5627c49b080f05ee4ad9f3e4b7cba9d6a5dff113a41c3409336833f190816d8a6bc42e9bec56b7567d0f3c9c696db619b245d901dd856db7c8092e77e9a1cccd56ee4dba42c5fdb61aec2669', 16),
    TBigInteger.Create('77b9d1137b50404a982729316efafc7dfe66d34e5a182600d5f30a0a8512051c560d081d4d0a1835ec3d25a60f4e4d6aa948b2bf3dbb5b124cbbc3489255a3a948372f6978496745f943e1db4f18382ceaa505dfc65757bb3f857a58dce52156', 16));

  // PSS Example 9.1
  FMsg9a := THex.Decode('a88e265855e9d7ca36c68795f0b31b591cd6587c71d060a0b3f7f3eaef43795922028bc2b6ad467cfc2d7f659c5385aa70ba3672cdde4cfe4970cc7904601b278872bf51321c4a972f3c9' + '5570f3445d4f57980e0f20df54846e6a52c668f1288c03f95006ea32f562d40d52af9feb32f0fa06db65b588a237b34e592d55cf979f903a642ef64d2ed542aa8c77dc1dd762f45a59303ed75e541ca271e2b60ca709e44fa0661131e8d5d4163fd8d398566ce26de8730e' + '72f9cca737641c244159420637028df0a18079d6208ea8b4711a2c750f5');
  FSlt9a := THex.Decode('c0a425313df8d7564bd2434d311523d5257eed80');
  FSig9a := THex.Decode('586107226c3ce013a7c8f04d1a6a2959bb4b8e205ba43a27b50f124111bc35ef589b039f5932187cb696d7d9a32c0c38300a5cdda4834b62d2eb240af33f79d13dfbf095bf599e0d968694' + '8c1964747b67e89c9aba5cd85016236f566cc5802cb13ead51bc7ca6bef3b94dcbdbb1d570469771df0e00b1a8a06777472d2316279edae86474668d4e1efff95f1de61c6020da32ae92bbf16520fef3cf4d88f61121f24bbd9fe91b59caf1235b2a93ff81fc403addf4ebdea84934a9cdaf8e1a9e');

  FSecureRandom := TSecureRandom.Create();
end;

procedure TTestPss.DoTestPssSignature(id: Integer; const pub, prv: IRsaKeyParameters;
  const salt, msg, sig: TCryptoLibByteArray);
var
  eng: IPssSigner;
  s: TCryptoLibByteArray;
begin
  eng := TPssSigner.Create(TRsaEngine.Create(), TDigestUtilities.GetDigest('SHA-1'), 20);

  eng.Init(True, TParametersWithRandom.Create(prv, TFixedRandom.Create(salt) as IFixedRandom) as IParametersWithRandom);
  eng.BlockUpdate(msg, 0, System.Length(msg));
  s := eng.GenerateSignature();

  CheckTrue(TArrayUtilities.AreEqual<Byte>(s, sig),
    Format('Test %d: PSS signature generation failed', [id]));

  eng.Init(False, pub);
  eng.BlockUpdate(msg, 0, System.Length(msg));
  CheckTrue(eng.VerifySignature(sig),
    Format('Test %d: PSS signature verification failed', [id]));
end;

procedure TTestPss.DoTestLoopSha1;
var
  eng: IPssSigner;
  data, s: TCryptoLibByteArray;
  failed, j: Integer;
begin
  eng := TPssSigner.Create(TRsaEngine.Create(), TDigestUtilities.GetDigest('SHA-1'), 20);
  failed := 0;
  SetLength(data, 1000);

  FSecureRandom.NextBytes(data);

  for j := 0 to NumLoopTests - 1 do
  begin
    eng.Init(True, TParametersWithRandom.Create(FPrv8, FSecureRandom) as IParametersWithRandom);
    eng.BlockUpdate(data, 0, System.Length(data));
    s := eng.GenerateSignature();

    eng.Init(False, FPub8);
    eng.BlockUpdate(data, 0, System.Length(data));

    if not eng.VerifySignature(s) then
      Inc(failed);
  end;

  CheckEquals(0, failed, Format('Loop test failed - failures: %d', [failed]));
end;

procedure TTestPss.DoTestLoopMixedDigest;
var
  eng: IPssSigner;
  data, s: TCryptoLibByteArray;
  failed, j: Integer;
begin
  // SHA-256 for content, SHA-1 for MGF
  eng := TPssSigner.Create(TRsaEngine.Create(),
    TDigestUtilities.GetDigest('SHA-256'),
    TDigestUtilities.GetDigest('SHA-1'), 20);
  failed := 0;
  SetLength(data, 1000);

  FSecureRandom.NextBytes(data);

  for j := 0 to NumLoopTests - 1 do
  begin
    eng.Init(True, TParametersWithRandom.Create(FPrv8, FSecureRandom) as IParametersWithRandom);
    eng.BlockUpdate(data, 0, System.Length(data));
    s := eng.GenerateSignature();

    eng.Init(False, FPub8);
    eng.BlockUpdate(data, 0, System.Length(data));

    if not eng.VerifySignature(s) then
      Inc(failed);
  end;

  CheckEquals(0, failed, Format('Mixed digest loop test failed - failures: %d', [failed]));
end;

procedure TTestPss.DoTestFixedSalt;
var
  eng: IPssSigner;
  data, fixedSalt, wrongSalt, s: TCryptoLibByteArray;
begin
  data := THex.Decode('010203040506070809101112131415');
  fixedSalt := THex.Decode('deadbeef');
  wrongSalt := THex.Decode('beefbeef');

  // Create signer with fixed salt
  eng := TPssSigner.Create(TRsaBlindedEngine.Create(),
    TDigestUtilities.GetDigest('SHA-256'),
    TDigestUtilities.GetDigest('SHA-1'),
    fixedSalt);

  eng.Init(True, FPrv8);
  eng.BlockUpdate(data, 0, System.Length(data));
  s := eng.GenerateSignature();

  eng.Init(False, FPub8);
  eng.BlockUpdate(data, 0, System.Length(data));
  CheckTrue(eng.VerifySignature(s), 'Fixed salt verification failed');

  // Test failure with wrong salt
  eng := TPssSigner.Create(TRsaBlindedEngine.Create(),
    TDigestUtilities.GetDigest('SHA-256'),
    TDigestUtilities.GetDigest('SHA-1'),
    wrongSalt);

  eng.Init(False, FPub8);
  eng.BlockUpdate(data, 0, System.Length(data));
  CheckFalse(eng.VerifySignature(s), 'Wrong salt should fail verification');
end;

procedure TTestPss.DoTestSha512ZeroSalt;
var
  eng: IPssSigner;
  s: TCryptoLibByteArray;
begin
  // SHA-512 with zero salt length
  eng := TPssSigner.Create(TRsaEngine.Create(),
    TDigestUtilities.GetDigest('SHA-512'), 0, TPssSigner.TrailerImplicit);

  eng.Init(True, FPrv1);
  eng.BlockUpdate(FMsg1a, 0, System.Length(FMsg1a));
  s := eng.GenerateSignature();

  eng.Init(False, FPub1);
  eng.BlockUpdate(FMsg1a, 0, System.Length(FMsg1a));
  CheckTrue(eng.VerifySignature(s), 'SHA-512 zero salt verification failed');
end;

procedure TTestPss.DoSignerUtilitiesSha1;
var
  kpGen: IRsaKeyPairGenerator;
  kpParams: IRsaKeyGenerationParameters;
  keyPair: IAsymmetricCipherKeyPair;
  signer: ISigner;
  message, signature: TCryptoLibByteArray;
  verified: Boolean;
begin
  kpGen := TRsaKeyPairGenerator.Create();
  kpParams := TRsaKeyGenerationParameters.Create(
    TBigInteger.ValueOf(65537), TSecureRandom.Create(), 2048, 100);
  kpGen.Init(kpParams);
  keyPair := kpGen.GenerateKeyPair();

  message := TConverters.ConvertStringToBytes('Test PSS signature SHA-1',
    TEncoding.UTF8);

  signer := TSignerUtilities.GetSigner('SHA-1withRSAandMGF1');
  signer.Init(True, keyPair.Private);
  signer.BlockUpdate(message, 0, System.Length(message));
  signature := signer.GenerateSignature();

  CheckTrue(System.Length(signature) > 0, 'PSS SHA-1 signature is empty');

  signer.Init(False, keyPair.Public);
  signer.BlockUpdate(message, 0, System.Length(message));
  verified := signer.VerifySignature(signature);

  CheckTrue(verified, 'PSS SHA-1 signature verification failed');
end;

procedure TTestPss.DoSignerUtilitiesSha256;
var
  kpGen: IRsaKeyPairGenerator;
  kpParams: IRsaKeyGenerationParameters;
  keyPair: IAsymmetricCipherKeyPair;
  signer: ISigner;
  &message, signature: TCryptoLibByteArray;
  verified: Boolean;
begin
  kpGen := TRsaKeyPairGenerator.Create();
  kpParams := TRsaKeyGenerationParameters.Create(
    TBigInteger.ValueOf(65537), TSecureRandom.Create(), 2048, 100);
  kpGen.Init(kpParams);
  keyPair := kpGen.GenerateKeyPair();

  &message := TConverters.ConvertStringToBytes('Test PSS signature SHA-256',
    TEncoding.UTF8);

  signer := TSignerUtilities.GetSigner('SHA-256withRSAandMGF1');
  signer.Init(True, keyPair.Private);
  signer.BlockUpdate(&message, 0, System.Length(&message));
  signature := signer.GenerateSignature();

  CheckTrue(System.Length(signature) > 0, 'PSS SHA-256 signature is empty');

  signer.Init(False, keyPair.Public);
  signer.BlockUpdate(&message, 0, System.Length(&message));
  verified := signer.VerifySignature(signature);

  CheckTrue(verified, 'PSS SHA-256 signature verification failed');

  // Test with modified message (should fail)
  &message[0] := &message[0] xor $FF;
  signer.Init(False, keyPair.Public);
  signer.BlockUpdate(&message, 0, System.Length(&message));
  verified := signer.VerifySignature(signature);

  CheckFalse(verified, 'PSS modified message should fail verification');
end;

procedure TTestPss.DoSignerUtilitiesSha384;
var
  kpGen: IRsaKeyPairGenerator;
  kpParams: IRsaKeyGenerationParameters;
  keyPair: IAsymmetricCipherKeyPair;
  signer: ISigner;
  &message, signature: TCryptoLibByteArray;
  verified: Boolean;
begin
  kpGen := TRsaKeyPairGenerator.Create();
  kpParams := TRsaKeyGenerationParameters.Create(
    TBigInteger.ValueOf(65537), TSecureRandom.Create(), 2048, 100);
  kpGen.Init(kpParams);
  keyPair := kpGen.GenerateKeyPair();

  &message := TConverters.ConvertStringToBytes('Test PSS signature SHA-384',
    TEncoding.UTF8);

  signer := TSignerUtilities.GetSigner('SHA-384withRSAandMGF1');
  signer.Init(True, keyPair.Private);
  signer.BlockUpdate(&message, 0, System.Length(&message));
  signature := signer.GenerateSignature();

  CheckTrue(System.Length(signature) > 0, 'PSS SHA-384 signature is empty');

  signer.Init(False, keyPair.Public);
  signer.BlockUpdate(&message, 0, System.Length(&message));
  verified := signer.VerifySignature(signature);

  CheckTrue(verified, 'PSS SHA-384 signature verification failed');
end;

procedure TTestPss.DoSignerUtilitiesSha512;
var
  kpGen: IRsaKeyPairGenerator;
  kpParams: IRsaKeyGenerationParameters;
  keyPair: IAsymmetricCipherKeyPair;
  signer: ISigner;
  &message, signature: TCryptoLibByteArray;
  verified: Boolean;
begin
  kpGen := TRsaKeyPairGenerator.Create();
  kpParams := TRsaKeyGenerationParameters.Create(
    TBigInteger.ValueOf(65537), TSecureRandom.Create(), 2048, 100);
  kpGen.Init(kpParams);
  keyPair := kpGen.GenerateKeyPair();

  &message := TConverters.ConvertStringToBytes('Test PSS signature SHA-512',
    TEncoding.UTF8);

  signer := TSignerUtilities.GetSigner('SHA-512withRSAandMGF1');
  signer.Init(True, keyPair.Private);
  signer.BlockUpdate(&message, 0, System.Length(&message));
  signature := signer.GenerateSignature();

  CheckTrue(System.Length(signature) > 0, 'PSS SHA-512 signature is empty');

  signer.Init(False, keyPair.Public);
  signer.BlockUpdate(&message, 0, System.Length(&message));
  verified := signer.VerifySignature(signature);

  CheckTrue(verified, 'PSS SHA-512 signature verification failed');
end;

procedure TTestPss.DoRawSignerTest;
var
  kpGen: IRsaKeyPairGenerator;
  kpParams: IRsaKeyGenerationParameters;
  keyPair: IAsymmetricCipherKeyPair;
  signer: IPssSigner;
  digest: IDigest;
  hash, signature: TCryptoLibByteArray;
  verified: Boolean;
begin
  kpGen := TRsaKeyPairGenerator.Create();
  kpParams := TRsaKeyGenerationParameters.Create(
    TBigInteger.ValueOf(17), TSecureRandom.Create(), 1024, 100);
  kpGen.Init(kpParams);
  keyPair := kpGen.GenerateKeyPair();

  digest := TDigestUtilities.GetDigest('SHA-256');

  // Generate random hash
  hash := TSecureRandom.GetNextBytes(FSecureRandom, digest.GetDigestSize());

  // Sign with raw signer
  signer := TPssSigner.CreateRawSigner(TRsaBlindedEngine.Create(), digest);
  signer.Init(True, keyPair.Private);
  signer.BlockUpdate(hash, 0, System.Length(hash));
  signature := signer.GenerateSignature();

  // Verify
  signer.Init(False, keyPair.Public);
  signer.BlockUpdate(hash, 0, System.Length(hash));
  verified := signer.VerifySignature(signature);

  CheckTrue(verified, 'Raw signer verification failed');
end;

procedure TTestPss.TestPssVectors;
begin
  DoTestPssSignature(1, FPub1, FPrv1, FSlt1a, FMsg1a, FSig1a);
  DoTestPssSignature(2, FPub1, FPrv1, FSlt1b, FMsg1b, FSig1b);
  DoTestPssSignature(3, FPub2, FPrv2, FSlt2a, FMsg2a, FSig2a);
  DoTestPssSignature(5, FPub4, FPrv4, FSlt4a, FMsg4a, FSig4a);
  DoTestPssSignature(7, FPub8, FPrv8, FSlt8a, FMsg8a, FSig8a);
  DoTestPssSignature(9, FPub9, FPrv9, FSlt9a, FMsg9a, FSig9a);
end;

procedure TTestPss.TestLoopSha1;
begin
  DoTestLoopSha1;
end;

procedure TTestPss.TestLoopMixedDigest;
begin
  DoTestLoopMixedDigest;
end;

procedure TTestPss.TestFixedSalt;
begin
  DoTestFixedSalt;
end;

procedure TTestPss.TestSha512ZeroSalt;
begin
  DoTestSha512ZeroSalt;
end;

procedure TTestPss.TestSignerUtilitiesSha1;
begin
  DoSignerUtilitiesSha1;
end;

procedure TTestPss.TestSignerUtilitiesSha256;
begin
  DoSignerUtilitiesSha256;
end;

procedure TTestPss.TestSignerUtilitiesSha384;
begin
  DoSignerUtilitiesSha384;
end;

procedure TTestPss.TestSignerUtilitiesSha512;
begin
  DoSignerUtilitiesSha512;
end;

procedure TTestPss.TestRawSigner;
begin
  DoRawSignerTest;
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestPss);
{$ELSE}
  RegisterTest(TTestPss.Suite);
{$ENDIF FPC}

end.
