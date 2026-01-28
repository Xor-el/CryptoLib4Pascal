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

unit X931SignerTests;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses

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
  ClpRsaEngine,
  ClpIRsaEngine,
  ClpX931Signer,
  ClpDigestUtilities,
  ClpISigner,
  ClpEncoders,
  ClpArrayUtilities,
  ClpCryptoLibTypes,
  CryptoLibTestBase;

type

  TTestX931Signer = class(TCryptoLibAlgorithmTestCase)
  private
    procedure ShouldPassSignatureTest1;
    procedure ShouldPassSignatureTest2;
    procedure ShouldPassSignatureTest3;

  published
    procedure TestX931Signer;

  end;

implementation

{ TTestX931Signer }

procedure TTestX931Signer.TestX931Signer;
var
  LRsaPubMod, LRsaPubExp, LRsaPrivMod, LRsaPrivDP, LRsaPrivDQ, LRsaPrivExp,
    LRsaPrivP, LRsaPrivQ, LRsaPrivQinv: TBigInteger;
  LRsaPublic: IRsaKeyParameters;
  LRsaPrivate: IRsaPrivateCrtKeyParameters;
  LMsg, LSig: TCryptoLibByteArray;
  LSigner: IX931Signer;
begin
  LRsaPubMod := TBigInteger.Create(TBase64.Decode('AIASoe2PQb1IP7bTyC9usjHP7FvnUMVpKW49iuFtrw/dMpYlsMMoIU2jupfifDpdFxIktSB4P+6Ymg5WjvHKTIrvQ7SR4zV4jaPTu56Ys0pZ9EDA6gb3HLjtU+8Bb1mfWM+yjKxcPDuFjwEtjGlPHg1Vq+CA9HNcMSKNn2+tW6qt'));
  LRsaPubExp := TBigInteger.Create(TBase64.Decode('EQ=='));
  LRsaPrivMod := TBigInteger.Create(TBase64.Decode('AIASoe2PQb1IP7bTyC9usjHP7FvnUMVpKW49iuFtrw/dMpYlsMMoIU2jupfifDpdFxIktSB4P+6Ymg5WjvHKTIrvQ7SR4zV4jaPTu56Ys0pZ9EDA6gb3HLjtU+8Bb1mfWM+yjKxcPDuFjwEtjGlPHg1Vq+CA9HNcMSKNn2+tW6qt'));
  LRsaPrivDP := TBigInteger.Create(TBase64.Decode('JXzfzG5v+HtLJIZqYMUefJfFLu8DPuJGaLD6lI3cZ0babWZ/oPGoJa5iHpX4Ul/7l3s1PFsuy1GhzCdOdlfRcQ=='));
  LRsaPrivDQ := TBigInteger.Create(TBase64.Decode('YNdJhw3cn0gBoVmMIFRZzflPDNthBiWy/dUMSRfJCxoZjSnr1gysZHK01HteV1YYNGcwPdr3j4FbOfri5c6DUQ=='));
  LRsaPrivExp := TBigInteger.Create(TBase64.Decode('DxFAOhDajr00rBjqX+7nyZ/9sHWRCCp9WEN5wCsFiWVRPtdB+NeLcou7mWXwf1Y+8xNgmmh//fPV45G2dsyBeZbXeJwB7bzx9NMEAfedchyOwjR8PYdjK3NpTLKtZlEJ6Jkh4QihrXpZMO4fKZWUm9bid3+lmiq43FwW+Hof8/E='));
  LRsaPrivP := TBigInteger.Create(TBase64.Decode('AJ9StyTVW+AL/1s7RBtFwZGFBgd3zctBqzzwKPda6LbtIFDznmwDCqAlIQH9X14X7UPLokCDhuAa76OnDXb1OiE='));
  LRsaPrivQ := TBigInteger.Create(TBase64.Decode('AM3JfD79dNJ5A3beScSzPtWxx/tSLi0QHFtkuhtSizeXdkv5FSba7lVzwEOGKHmW829bRoNxThDy4ds1IihW1w0='));
  LRsaPrivQinv := TBigInteger.Create(TBase64.Decode('Lt0g7wrsNsQxuDdB8q/rH8fSFeBXMGLtCIqfOec1j7FEIuYA/ACiRDgXkHa0WgN7nLXSjHoy630wC5Toq8vvUg=='));

  LRsaPublic := TRsaKeyParameters.Create(False, LRsaPubMod, LRsaPubExp);
  LRsaPrivate := TRsaPrivateCrtKeyParameters.Create(LRsaPrivMod, LRsaPubExp,
    LRsaPrivExp, LRsaPrivP, LRsaPrivQ, LRsaPrivDP, LRsaPrivDQ, LRsaPrivQinv);

  LMsg := TCryptoLibByteArray.Create(1, 6, 3, 32, 7, 43, 2, 5, 7, 78, 4, 23);

  LSigner := TX931Signer.Create(TRsaEngine.Create() as IRsaEngine,
    TDigestUtilities.GetDigest('SHA-1'));
  LSigner.Init(True, LRsaPrivate);
  LSigner.BlockUpdate(LMsg, 0, System.Length(LMsg));
  LSig := LSigner.GenerateSignature();

  LSigner := TX931Signer.Create(TRsaEngine.Create() as IRsaEngine,
    TDigestUtilities.GetDigest('SHA-1'));
  LSigner.Init(False, LRsaPublic);
  LSigner.BlockUpdate(LMsg, 0, System.Length(LMsg));
  CheckTrue(LSigner.VerifySignature(LSig), 'X9.31 Signer failed.');

  ShouldPassSignatureTest1();
  ShouldPassSignatureTest2();
  ShouldPassSignatureTest3();
end;

procedure TTestX931Signer.ShouldPassSignatureTest1;
var
  LN, LE: TBigInteger;
  LMsg, LSig: TCryptoLibByteArray;
  LRsaPublic: IRsaKeyParameters;
  LSigner: IX931Signer;
begin
  LN := TBigInteger.Create(
  'c9be1b28f8caccca65d86cc3c9bbcc13eccc059df3b80bd2292b811eff3aa0dd75e1e85c333b8e3fa9bed53bb20f5359ff4e' +
  '6900c5e9a388e3a4772a583a79e2299c76582c2b27694b65e9ba22e66bfb817f8b70b22206d7d8ae488c86dbb7137c26d5ef' +
  'f9b33c90e6cee640630313b7a715802e15142fef498c404a8de19674974785f0f852e2d470fe85a2e54ffca9f5851f672b71' +
  'df691785a5cdabe8f14aa628942147de7593b2cf962414a5b59c632c4e14f1768c0ab2e9250824beea60a3529f11bf5e070c' +
  'e90a47686eb0be1086fb21f0827f55295b4a48307db0b048c05a4aec3f488c576ca6f1879d354224c7e84cbcd8e76dd217a3' +
  'de54dba73c35', 16);

  LE := TBigInteger.Create('e75b1b', 16);

  LMsg := THex.Decode(
  '5bb0d1c0ef9b5c7af2477fe08d45523d3842a4b2db943f7033126c2a7829bacb3d2cfc6497ec91688189e81b7f8742488224' +
  'ba320ce983ce9480722f2cc5bc42611f00bb6311884f660ccc244788378673532edb05284fd92e83f6f6dab406209032e6af' +
  '9a33c998677933e32d6fb95fd27408940d7728f9c9c40267ca1d20ce');

  LSig := THex.Decode(
  '0fe8bb8e3109a1eb7489ef35bf4c1a0780071da789c8bd226a4170538eafefdd30b732d628f0e87a0b9450051feae9754d4f' +
  'b61f57862d10f0bacc4f660d13281d0cd1141c006ade5186ff7d961a4c6cd0a4b352fc1295c5afd088f80ac1f8e192ef116a' +
  '010a442655fe8ff5eeacea15807906fb0f0dfa86e680d4c005872357f7ece9aa4e20b15d5f709b30f08648ecaa34f2fbf54e' +
  'b6b414fa2ff6f87561f70163235e69ccb4ac82a2e46d3be214cc2ef5263b569b2d8fd839b21a9e102665105ea762bda25bb4' +
  '46cfd831487a6b846100dee113ae95ae64f4af22c428c87bab809541c962bb3a56d4c86588e0af4ebc7fcc66dadced311051' +
  '356d3ea745f7');

  LRsaPublic := TRsaKeyParameters.Create(False, LN, LE);
  LSigner := TX931Signer.Create(TRsaEngine.Create() as IRsaEngine,
    TDigestUtilities.GetDigest('SHA-1'));

  LSigner.Init(False, LRsaPublic);

  LSigner.BlockUpdate(LMsg, 0, System.Length(LMsg));

  CheckTrue(LSigner.VerifySignature(LSig), 'RSA X931 verify test 1 failed.');
end;

procedure TTestX931Signer.ShouldPassSignatureTest2;
var
  LN, LE: TBigInteger;
  LMsg, LSig: TCryptoLibByteArray;
  LRsaPublic: IRsaKeyParameters;
  LSigner: IX931Signer;
begin
  LN := TBigInteger.Create(
  'b746ba6c3c0be64bbe33aa55b2929b0af4e86d773d44bfe5914db9287788c4663984b61a418d2eecca30d752ff6b620a07ec' +
  '72eeb2b422d2429da352407b99982800b9dd7697be6a7b1baa98ca5f4fc2fe33400f20b9dba337ac25c987804165d4a6e0ee' +
  '4d18eabd6de5abdfe578cae6713ff91d16c80a5bb20217fe614d9509e75a43e1825327b9da8f0a9f6eeaa1c04b69fb4bacc0' +
  '73569fff4ab491becbe6d0441d437fc3fa823239c4a0f75321666b68dd3f66e2dd394089a15bcc288a68a4eb0a48e17d6397' +
  '43b9dea0a91cc35820544732aff253f8ca9967c609dc01c2f8cd0313a7a91cfa94ff74289a1d2b6f19d1811f4b9a65f4cce9' +
  'e5759b4cc64f', 16);

  LE := TBigInteger.Create('dcbbdb', 16);
  LMsg := THex.Decode('a5d3c8a060f897bbbc20ae0955052f37fbc70986b6e11c65075c9f457142bfa93856897c69020aa81a91b5e4f39e05cdeecc' +
  '63395ab849c8262ca8bc5c96870aecb8edb0aba0024a9bdb71e06de6100344e5c318bc979ef32b8a49a8278ba99d4861bce4' +
  '2ebbc5c8c666aaa6cac39aff8779f2cae367620f9edd4cb1d80b6c8c');

  LSig := THex.Decode(
  '39fbbd1804c689a533b0043f84da0f06081038c0fbf31e443e46a05e58f50de5198bbca40522afefaba3aed7082a6cb93b1d' +
  'a39f1f5a42246bf64930781948d300549bef0f8d554ecfca60a1b1ecba95a7014ee4545ad4f0c4e3a31942c6738b4ccd6244' +
  'b6a21267dadf0826a5f713f13b1f5a9ab8501d957a26d4948278ac67851071a315674bdab173bfef2c2690c8373da6bf3d69' +
  'f30c0e5da8883de872f59521b40793854085641adf98d13db991c5d0a8aaa0222934fa33332e90ef0b954e195cb267d6ffb3' +
  '6c96e14d1ec7b915a87598b4461a3146566354dc2ae748c84ee0cd46543b53ebff8cdf47725b280a1f799fb6ebb4a31ad2bd' +
  'd5178250f83a');

  LRsaPublic := TRsaKeyParameters.Create(False, LN, LE);
  LSigner := TX931Signer.Create(TRsaEngine.Create() as IRsaEngine,
    TDigestUtilities.GetDigest('SHA-224'));

  LSigner.Init(False, LRsaPublic);

  LSigner.BlockUpdate(LMsg, 0, System.Length(LMsg));

  CheckTrue(LSigner.VerifySignature(LSig), 'RSA X931 verify test 2 failed.');
end;

procedure TTestX931Signer.ShouldPassSignatureTest3;
var
  LN, LE, LD: TBigInteger;
  LMsg, LSig, LS: TCryptoLibByteArray;
  LRsaPublic: IRsaKeyParameters;
  LRsaPrivate: IRsaKeyParameters;
  LSigner: IX931Signer;
begin
  LN := TBigInteger.Create(
  'dcb5686a3d2063a3f9cf7b9b32d2d3765b4c449b09b4960245a9111cd3b0cbd3260496885b8e1fa5db33b03efcc759d9c1af' +
  'e29d93c6faebc7e0efada334b5b9a29655e2da2c8f11103d8203be311feab7ae88e9f1b2ec7d8fc655d77202b1681dd9717e' +
  'c0f525b35584987e19539635a1ed23ca482a00149c609a23dc1645fd', 16);

  LE := TBigInteger.Create(
  '0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000' +
  '0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000' +
  '000000000000000000000000000000000000000000000000000dc9f7', 16);

  LD := TBigInteger.Create('189d6345099098992e0c9ca5f281e1338092342fa0acc85cc2a111f30f9bd2fb4753cd1a48ef0ddca9bf1af33ec76fb2e23a' +
  '9fb4896c26f2235b516f7c05ef7ae81e70f4b491a5fedba9b935e9c76d761a813ce7776ff8a1e5efe1166ff2eca26aa900da' +
  '88c908d51af9de26977fe39719cc781df32216fa41b838f0c63803c3'
  , 16);

  LMsg := THex.Decode('911475c6e210ef4ac65b6fe8d2bfe5e01b959771b137c4ef69b88716e0d2ff9ebc1fad0f358c1dd7d50cc99a7b893ac9a620' +
  '7076f08d8467d9e48c69c683bfe64a44dabaa3f7c243880f6ab7229bf7bb587822314fc5de5131983bfb2eef8b4bc1eac36f' +
  '353724b567cd1ae8cddd64ddb7057549d5c81ad5fa3b5e751f00abf5');

  LSig := THex.Decode(
  '02c50ec0ac8a7f38ef5630c396964d6a6daaa7e3083ab5b57fa2a2632f3b70e2e85c8456cd774d45d7e44fcb063f0f04fff9' +
  'f1e3adfda11272535a92cb59320b190b5ee4261f23d6ceaa925df3a7bfa42e26bf61ea9645d9d64b3c90a820802768a6e209' +
  'c9f83705375a3867afccc037e8242a98fa4c3db6b2d9877754d47289');

  LRsaPublic := TRsaKeyParameters.Create(False, LN, LE);
  LSigner := TX931Signer.Create(TRsaEngine.Create() as IRsaEngine,
    TDigestUtilities.GetDigest('SHA-1'));

  LRsaPrivate := TRsaKeyParameters.Create(True, LN, LD);

  LSigner.Init(True, LRsaPrivate);

  LSigner.BlockUpdate(LMsg, 0, System.Length(LMsg));

  LS := LSigner.GenerateSignature();

  CheckTrue(TArrayUtilities.AreEqual<Byte>(LSig, LS), 'RSA X931 sig test 3 failed.');

  LSigner.Init(False, LRsaPublic);

  LSigner.BlockUpdate(LMsg, 0, System.Length(LMsg));

  CheckTrue(LSigner.VerifySignature(LSig), 'RSA X931 verify test 3 failed.');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestX931Signer);
{$ELSE}
  RegisterTest(TTestX931Signer.Suite);
{$ENDIF FPC}

end.
