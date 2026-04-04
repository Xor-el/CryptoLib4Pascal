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

unit DigestTests;

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
  ClpMiscObjectIdentifiers,
  ClpNistObjectIdentifiers,
  ClpRosstandartObjectIdentifiers,
  ClpTeleTrusTObjectIdentifiers,
  ClpIDigest,
  ClpDigestUtilities,
  ClpConverters,
  CryptoLibTestBase,
  ClpCryptoLibTypes;

type

  TTestDigest = class(TCryptoLibAlgorithmTestCase)
  private
  var
    FAbcVectors: TCryptoLibMatrixGenericArray<String>;

    procedure DoTest(const AAlgorithm: String);
    procedure DoAbcTest(const AAlgorithm, AHash: String);

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestDigests();

  end;

implementation

{ TTestDigest }

procedure TTestDigest.SetUp;
begin
  inherited;
  FAbcVectors := TCryptoLibMatrixGenericArray<String>.Create
    (
    TCryptoLibStringArray.Create('MD2',
    'da853b0d3f88d99b30283a69e6ded6bb'),
    TCryptoLibStringArray.Create('MD4',
    'a448017aaf21d8525fc10ae87aa6729d'),
    TCryptoLibStringArray.Create('MD5',
    '900150983cd24fb0d6963f7d28e17f72'),
    TCryptoLibStringArray.Create('SHA1',
    'a9993e364706816aba3e25717850c26c9cd0d89d'),
    TCryptoLibStringArray.Create('SHA-1',
    'a9993e364706816aba3e25717850c26c9cd0d89d'),
    TCryptoLibStringArray.Create('SHA224',
    '23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7'),
    TCryptoLibStringArray.Create('SHA-224',
    '23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7'),
    TCryptoLibStringArray.Create('SHA256',
    'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'),
    TCryptoLibStringArray.Create('SHA-256',
    'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'),
    TCryptoLibStringArray.Create('SHA384',
    'cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7'),
    TCryptoLibStringArray.Create('SHA-384',
    'cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7'),
    TCryptoLibStringArray.Create('SHA512',
    'ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f'),
    TCryptoLibStringArray.Create('SHA-512',
    'ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f'),
    TCryptoLibStringArray.Create('SHA512/224',
    '4634270F707B6A54DAAE7530460842E20E37ED265CEEE9A43E8924AA'),
    TCryptoLibStringArray.Create('SHA512(224)',
    '4634270F707B6A54DAAE7530460842E20E37ED265CEEE9A43E8924AA'),
    TCryptoLibStringArray.Create('SHA-512/224',
    '4634270F707B6A54DAAE7530460842E20E37ED265CEEE9A43E8924AA'),
    TCryptoLibStringArray.Create('SHA-512(224)',
    '4634270F707B6A54DAAE7530460842E20E37ED265CEEE9A43E8924AA'),
    TCryptoLibStringArray.Create('SHA512/256',
    '53048E2681941EF99B2E29B76B4C7DABE4C2D0C634FC6D46E0E2F13107E7AF23'),
    TCryptoLibStringArray.Create('SHA512(256)',
    '53048E2681941EF99B2E29B76B4C7DABE4C2D0C634FC6D46E0E2F13107E7AF23'),
    TCryptoLibStringArray.Create('SHA-512/256',
    '53048E2681941EF99B2E29B76B4C7DABE4C2D0C634FC6D46E0E2F13107E7AF23'),
    TCryptoLibStringArray.Create('SHA-512(256)',
    '53048E2681941EF99B2E29B76B4C7DABE4C2D0C634FC6D46E0E2F13107E7AF23'),
    TCryptoLibStringArray.Create('RIPEMD128',
    'c14a12199c66e4ba84636b0f69144c77'),
    TCryptoLibStringArray.Create(TTeleTrusTObjectIdentifiers.RipeMD128.ID,
    'c14a12199c66e4ba84636b0f69144c77'),
    TCryptoLibStringArray.Create('RIPEMD160',
    '8eb208f7e05d987a9b044a8e98c6b087f15a0bfc'),
    TCryptoLibStringArray.Create(TTeleTrusTObjectIdentifiers.RipeMD160.ID,
    '8eb208f7e05d987a9b044a8e98c6b087f15a0bfc'),
    TCryptoLibStringArray.Create('RIPEMD256',
    'afbd6e228b9d8cbbcef5ca2d03e6dba10ac0bc7dcbe4680e1e42d2e975459b65'),
    TCryptoLibStringArray.Create(TTeleTrusTObjectIdentifiers.RipeMD256.ID,
    'afbd6e228b9d8cbbcef5ca2d03e6dba10ac0bc7dcbe4680e1e42d2e975459b65'),
    TCryptoLibStringArray.Create('RIPEMD320',
    'de4c01b3054f8930a79d09ae738e92301e5a17085beffdc1b8d116713e74f82fa942d64cdbc4682d'),
    TCryptoLibStringArray.Create('Tiger',
    '2AAB1484E8C158F2BFB8C5FF41B57A525129131C957B5F93'),
    TCryptoLibStringArray.Create('GOST3411',
    'b285056dbf18d7392d7677369524dd14747459ed8143997e163b2986f92fd42c'),
    TCryptoLibStringArray.Create('WHIRLPOOL',
    '4E2448A4C6F486BB16B6562C73B4020BF3043E3A731BCE721AE1B303D97E6D4C7181EEBDB6C57E277D0E34957114CBD6C797FC9D95D8B582D225292076D4EEF5'),
    TCryptoLibStringArray.Create('SHA3-224',
    'e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf'),
    TCryptoLibStringArray.Create(TNistObjectIdentifiers.IdSha3_224.ID,
    'e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf'),
    TCryptoLibStringArray.Create('SHA3-256',
    '3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532'),
    TCryptoLibStringArray.Create(TNistObjectIdentifiers.IdSha3_256.ID,
    '3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532'),
    TCryptoLibStringArray.Create('SHA3-384',
    'ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25'),
    TCryptoLibStringArray.Create(TNistObjectIdentifiers.IdSha3_384.ID,
    'ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25'),
    TCryptoLibStringArray.Create('SHA3-512',
    'b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0'),
    TCryptoLibStringArray.Create(TNistObjectIdentifiers.IdSha3_512.ID,
    'b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0'),
    TCryptoLibStringArray.Create('SHAKE128',
    '5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc8'),
    TCryptoLibStringArray.Create('SHAKE128-256',
    '5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc8'),
    TCryptoLibStringArray.Create(TNistObjectIdentifiers.IdShake128.ID,
    '5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc8'),
    TCryptoLibStringArray.Create('SHAKE256',
    '483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739d5a15bef186a5386c75744c0527e1faa9f8726e462a12a4feb06bd8801e751e4'),
    TCryptoLibStringArray.Create('SHAKE256-512',
    '483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739d5a15bef186a5386c75744c0527e1faa9f8726e462a12a4feb06bd8801e751e4'),
    TCryptoLibStringArray.Create(TNistObjectIdentifiers.IdShake256.ID,
    '483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739d5a15bef186a5386c75744c0527e1faa9f8726e462a12a4feb06bd8801e751e4'),
    TCryptoLibStringArray.Create('KECCAK224',
    'c30411768506ebe1c2871b1ee2e87d38df342317300a9b97a95ec6a8'),
    TCryptoLibStringArray.Create('KECCAK-224',
    'c30411768506ebe1c2871b1ee2e87d38df342317300a9b97a95ec6a8'),
    TCryptoLibStringArray.Create('KECCAK256',
    '4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45'),
    TCryptoLibStringArray.Create('KECCAK-256',
    '4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45'),
    TCryptoLibStringArray.Create('KECCAK288',
    '20ff13d217d5789fa7fc9e0e9a2ee627363ec28171d0b6c52bbd2f240554dbc94289f4d6'),
    TCryptoLibStringArray.Create('KECCAK-288',
    '20ff13d217d5789fa7fc9e0e9a2ee627363ec28171d0b6c52bbd2f240554dbc94289f4d6'),
    TCryptoLibStringArray.Create('KECCAK384',
    'f7df1165f033337be098e7d288ad6a2f74409d7a60b49c36642218de161b1f99f8c681e4afaf31a34db29fb763e3c28e'),
    TCryptoLibStringArray.Create('KECCAK-384',
    'f7df1165f033337be098e7d288ad6a2f74409d7a60b49c36642218de161b1f99f8c681e4afaf31a34db29fb763e3c28e'),
    TCryptoLibStringArray.Create('KECCAK512',
    '18587dc2ea106b9a1563e32b3312421ca164c7f1f07bc922a9c83d77cea3a1e5d0c69910739025372dc14ac9642629379540c17e2a65b19d77aa511a9d00bb96'),
    TCryptoLibStringArray.Create('KECCAK-512',
    '18587dc2ea106b9a1563e32b3312421ca164c7f1f07bc922a9c83d77cea3a1e5d0c69910739025372dc14ac9642629379540c17e2a65b19d77aa511a9d00bb96'),
    TCryptoLibStringArray.Create('BLAKE2B-160',
    '384264f676f39536840523f284921cdc68b6846b'),
    TCryptoLibStringArray.Create('BLAKE2B-256',
    'bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319'),
    TCryptoLibStringArray.Create('BLAKE2B-384',
    '6f56a82c8e7ef526dfe182eb5212f7db9df1317e57815dbda46083fc30f54ee6c66ba83be64b302d7cba6ce15bb556f4'),
    TCryptoLibStringArray.Create('BLAKE2B-512',
    'ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923'),
    TCryptoLibStringArray.Create(TMiscObjectIdentifiers.IdBlake2b160.ID,
    '384264f676f39536840523f284921cdc68b6846b'),
    TCryptoLibStringArray.Create(TMiscObjectIdentifiers.IdBlake2b256.ID,
    'bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319'),
    TCryptoLibStringArray.Create(TMiscObjectIdentifiers.IdBlake2b384.ID,
    '6f56a82c8e7ef526dfe182eb5212f7db9df1317e57815dbda46083fc30f54ee6c66ba83be64b302d7cba6ce15bb556f4'),
    TCryptoLibStringArray.Create(TMiscObjectIdentifiers.IdBlake2b512.ID,
    'ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923'),
    TCryptoLibStringArray.Create('BLAKE2S-128',
    'aa4938119b1dc7b87cbad0ffd200d0ae'),
    TCryptoLibStringArray.Create('BLAKE2S-160',
    '5ae3b99be29b01834c3b508521ede60438f8de17'),
    TCryptoLibStringArray.Create('BLAKE2S-224',
    '0b033fc226df7abde29f67a05d3dc62cf271ef3dfea4d387407fbd55'),
    TCryptoLibStringArray.Create('BLAKE2S-256',
    '508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982'),
    TCryptoLibStringArray.Create(TMiscObjectIdentifiers.IdBlake2s128.ID,
    'aa4938119b1dc7b87cbad0ffd200d0ae'),
    TCryptoLibStringArray.Create(TMiscObjectIdentifiers.IdBlake2s160.ID,
    '5ae3b99be29b01834c3b508521ede60438f8de17'),
    TCryptoLibStringArray.Create(TMiscObjectIdentifiers.IdBlake2s224.ID,
    '0b033fc226df7abde29f67a05d3dc62cf271ef3dfea4d387407fbd55'),
    TCryptoLibStringArray.Create(TMiscObjectIdentifiers.IdBlake2s256.ID,
    '508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982'),
    TCryptoLibStringArray.Create('GOST3411-2012-256',
    '4e2919cf137ed41ec4fb6270c61826cc4fffb660341e0af3688cd0626d23b481'),
    TCryptoLibStringArray.Create(TRosstandartObjectIdentifiers.IdTc26Gost3411_12_256.ID,
    '4e2919cf137ed41ec4fb6270c61826cc4fffb660341e0af3688cd0626d23b481'),
    TCryptoLibStringArray.Create('GOST3411-2012-512',
    '28156e28317da7c98f4fe2bed6b542d0dab85bb224445fcedaf75d46e26d7eb8d5997f3e0915dd6b7f0aab08d9c8beb0d8c64bae2ab8b3c8c6bc53b3bf0db728'),
    TCryptoLibStringArray.Create(TRosstandartObjectIdentifiers.IdTc26Gost3411_12_512.ID,
    '28156e28317da7c98f4fe2bed6b542d0dab85bb224445fcedaf75d46e26d7eb8d5997f3e0915dd6b7f0aab08d9c8beb0d8c64bae2ab8b3c8c6bc53b3bf0db728'),
    TCryptoLibStringArray.Create('BLAKE3-256',
    '6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85'),
    TCryptoLibStringArray.Create(TMiscObjectIdentifiers.Blake3_256.ID,
    '6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85'));
end;

procedure TTestDigest.TearDown;
begin
  FAbcVectors := nil;
  inherited;
end;

procedure TTestDigest.DoAbcTest(const AAlgorithm, AHash: String);
var
  LAbc, LResult: TBytes;
  LDigest: IDigest;
begin
  LAbc := TBytes.Create($61, $62, $63);

  LDigest := TDigestUtilities.GetDigest(AAlgorithm);

  LDigest.BlockUpdate(LAbc, 0, System.Length(LAbc));
  LResult := TDigestUtilities.DoFinal(LDigest);

  if (not AreEqual(LResult, DecodeHex(AHash))) then
  begin
    Fail(Format('abc result not equal for %s, expected %s actual %s', [AAlgorithm, AHash, EncodeHex(LResult)]));
  end;
end;

procedure TTestDigest.DoTest(const AAlgorithm: String);
var
  LMessage, LResult, LResult2: TBytes;
  LDigest, LD: IDigest;
  LI: Int32;
begin
  LMessage := TConverters.ConvertStringToBytes('hello world', TEncoding.ASCII);

  LDigest := TDigestUtilities.GetDigest(AAlgorithm);

  LDigest.BlockUpdate(LMessage, 0, System.Length(LMessage));
  LResult := TDigestUtilities.DoFinal(LDigest);

  LDigest.BlockUpdate(LMessage, 0, System.Length(LMessage));
  LResult2 := TDigestUtilities.DoFinal(LDigest);

  if (not AreEqual(LResult, LResult2)) then
  begin
    Fail('Result object 1 not equal');
  end;

  for LI := 0 to System.Pred(System.Length(LMessage)) do
  begin
    LDigest.Update(LMessage[LI]);
  end;

  LResult2 := TDigestUtilities.DoFinal(LDigest);

  if (not AreEqual(LResult, LResult2)) then
  begin
    Fail('Result object 2 not equal');
  end;

  LDigest.BlockUpdate(LMessage, 0, System.Length(LMessage) div 2);
  LDigest.BlockUpdate(LMessage, System.Length(LMessage) div 2,
    System.Length(LMessage) - (System.Length(LMessage) div 2));

  LResult2 := TDigestUtilities.DoFinal(LDigest);

  if (not AreEqual(LResult, LResult2)) then
  begin
    Fail('Result object 3 not equal');
  end;

  LDigest.BlockUpdate(LMessage, 0, System.Length(LMessage) div 2);
  LD := LDigest.Clone();
  LDigest.BlockUpdate(LMessage, System.Length(LMessage) div 2,
    System.Length(LMessage) - (System.Length(LMessage) div 2));

  LResult2 := TDigestUtilities.DoFinal(LDigest);

  if (not AreEqual(LResult, LResult2)) then
  begin
    Fail('Result object 4(a) not equal');
  end;

  LD.BlockUpdate(LMessage, System.Length(LMessage) div 2,
    System.Length(LMessage) - (System.Length(LMessage) div 2));

  LResult2 := TDigestUtilities.DoFinal(LD);

  if (not AreEqual(LResult, LResult2)) then
  begin
    Fail('Result object 4(b) not equal');
  end;

  LDigest.BlockUpdate(LMessage, 0, System.Length(LMessage) div 2);
  LDigest.Reset();
  LDigest.BlockUpdate(LMessage, 0, System.Length(LMessage) div 2);
  LDigest.BlockUpdate(LMessage, System.Length(LMessage) div 2,
    System.Length(LMessage) - (System.Length(LMessage) div 2));

  LResult2 := TDigestUtilities.DoFinal(LDigest);

  if (not AreEqual(LResult, LResult2)) then
  begin
    Fail('Result object 5 not equal');
  end;

end;

procedure TTestDigest.TestDigests;
var
  LI: Int32;
begin
  for LI := 0 to System.Pred(System.Length(FAbcVectors)) do
  begin
    DoTest(FAbcVectors[LI][0]);

    DoAbcTest(FAbcVectors[LI][0], FAbcVectors[LI][1]);
  end;
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestDigest);
{$ELSE}
  RegisterTest(TTestDigest.Suite);
{$ENDIF FPC}

end.
