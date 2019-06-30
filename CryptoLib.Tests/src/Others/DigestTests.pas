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
  ClpRosstandartObjectIdentifiers,
  ClpIDigest,
  ClpDigestUtilities,
  ClpConverters,
  CryptoLibTestBase,
  ClpCryptoLibTypes;

type

  TTestDigest = class(TCryptoLibAlgorithmTestCase)
  private
  var
    FabcVectors: TCryptoLibMatrixGenericArray<String>;

    procedure DoTest(const algorithm: String);
    procedure DoAbcTest(const algorithm, hash: String);

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
  FabcVectors := TCryptoLibMatrixGenericArray<String>.Create
    (TCryptoLibStringArray.Create('MD2', 'da853b0d3f88d99b30283a69e6ded6bb'),
    TCryptoLibStringArray.Create('MD4', 'a448017aaf21d8525fc10ae87aa6729d'),
    TCryptoLibStringArray.Create('MD5', '900150983cd24fb0d6963f7d28e17f72'),
    TCryptoLibStringArray.Create('SHA-1',
    'a9993e364706816aba3e25717850c26c9cd0d89d'),
    TCryptoLibStringArray.Create('SHA-224',
    '23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7'),
    TCryptoLibStringArray.Create('SHA-256',
    'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'),
    TCryptoLibStringArray.Create('SHA-384',
    'cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7'),
    TCryptoLibStringArray.Create('SHA-512',
    'ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f'),
    TCryptoLibStringArray.Create('SHA-512/224',
    '4634270F707B6A54DAAE7530460842E20E37ED265CEEE9A43E8924AA'),
    TCryptoLibStringArray.Create('SHA-512/256',
    '53048E2681941EF99B2E29B76B4C7DABE4C2D0C634FC6D46E0E2F13107E7AF23'),
    TCryptoLibStringArray.Create('RIPEMD128',
    'c14a12199c66e4ba84636b0f69144c77'),
    TCryptoLibStringArray.Create('RIPEMD160',
    '8eb208f7e05d987a9b044a8e98c6b087f15a0bfc'),
    TCryptoLibStringArray.Create('RIPEMD256',
    'afbd6e228b9d8cbbcef5ca2d03e6dba10ac0bc7dcbe4680e1e42d2e975459b65'),
    TCryptoLibStringArray.Create('RIPEMD320',
    'de4c01b3054f8930a79d09ae738e92301e5a17085beffdc1b8d116713e74f82fa942d64cdbc4682d'),
    TCryptoLibStringArray.Create('Tiger',
    '2AAB1484E8C158F2BFB8C5FF41B57A525129131C957B5F93'),
    TCryptoLibStringArray.Create('GOST3411',
    'b285056dbf18d7392d7677369524dd14747459ed8143997e163b2986f92fd42c'),
    TCryptoLibStringArray.Create('WHIRLPOOL',
    '4E2448A4C6F486BB16B6562C73B4020BF3043E3A731BCE721AE1B303D97E6D4C7181EEBDB6C57E277D0E34957114CBD6C797FC9D95D8B582D225292076D4EEF5'),
    TCryptoLibStringArray.Create('SM3',
    '66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0'),
    TCryptoLibStringArray.Create('SHA3-224',
    'e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf'),
    TCryptoLibStringArray.Create('SHA3-256',
    '3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532'),
    TCryptoLibStringArray.Create('SHA3-384',
    'ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25'),
    TCryptoLibStringArray.Create('SHA3-512',
    'b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0'),
    TCryptoLibStringArray.Create('KECCAK-224',
    'c30411768506ebe1c2871b1ee2e87d38df342317300a9b97a95ec6a8'),
    TCryptoLibStringArray.Create('KECCAK-256',
    '4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45'),
    TCryptoLibStringArray.Create('KECCAK-288',
    '20ff13d217d5789fa7fc9e0e9a2ee627363ec28171d0b6c52bbd2f240554dbc94289f4d6'),
    TCryptoLibStringArray.Create('KECCAK-384',
    'f7df1165f033337be098e7d288ad6a2f74409d7a60b49c36642218de161b1f99f8c681e4afaf31a34db29fb763e3c28e'),
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
    TCryptoLibStringArray.Create(TMiscObjectIdentifiers.id_blake2b160.Id,
    '384264f676f39536840523f284921cdc68b6846b'),
    TCryptoLibStringArray.Create(TMiscObjectIdentifiers.id_blake2b256.Id,
    'bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319'),
    TCryptoLibStringArray.Create(TMiscObjectIdentifiers.id_blake2b384.Id,
    '6f56a82c8e7ef526dfe182eb5212f7db9df1317e57815dbda46083fc30f54ee6c66ba83be64b302d7cba6ce15bb556f4'),
    TCryptoLibStringArray.Create(TMiscObjectIdentifiers.id_blake2b512.Id,
    'ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923'),
    TCryptoLibStringArray.Create('BLAKE2S-128',
    'aa4938119b1dc7b87cbad0ffd200d0ae'),
    TCryptoLibStringArray.Create('BLAKE2S-160',
    '5ae3b99be29b01834c3b508521ede60438f8de17'),
    TCryptoLibStringArray.Create('BLAKE2S-224',
    '0b033fc226df7abde29f67a05d3dc62cf271ef3dfea4d387407fbd55'),
    TCryptoLibStringArray.Create('BLAKE2S-256',
    '508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982'),
    TCryptoLibStringArray.Create(TMiscObjectIdentifiers.id_blake2s128.Id,
    'aa4938119b1dc7b87cbad0ffd200d0ae'),
    TCryptoLibStringArray.Create(TMiscObjectIdentifiers.id_blake2s160.Id,
    '5ae3b99be29b01834c3b508521ede60438f8de17'),
    TCryptoLibStringArray.Create(TMiscObjectIdentifiers.id_blake2s224.Id,
    '0b033fc226df7abde29f67a05d3dc62cf271ef3dfea4d387407fbd55'),
    TCryptoLibStringArray.Create(TMiscObjectIdentifiers.id_blake2s256.Id,
    '508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982'),
    TCryptoLibStringArray.Create('GOST3411-2012-256',
    '4e2919cf137ed41ec4fb6270c61826cc4fffb660341e0af3688cd0626d23b481'),
    TCryptoLibStringArray.Create(TRosstandartObjectIdentifiers.
    id_tc26_gost_3411_12_256.Id,
    '4e2919cf137ed41ec4fb6270c61826cc4fffb660341e0af3688cd0626d23b481'),
    TCryptoLibStringArray.Create('GOST3411-2012-512',
    '28156e28317da7c98f4fe2bed6b542d0dab85bb224445fcedaf75d46e26d7eb8d5997f3e0915dd6b7f0aab08d9c8beb0d8c64bae2ab8b3c8c6bc53b3bf0db728'),
    TCryptoLibStringArray.Create(TRosstandartObjectIdentifiers.
    id_tc26_gost_3411_12_512.Id,
    '28156e28317da7c98f4fe2bed6b542d0dab85bb224445fcedaf75d46e26d7eb8d5997f3e0915dd6b7f0aab08d9c8beb0d8c64bae2ab8b3c8c6bc53b3bf0db728'),
    TCryptoLibStringArray.Create('DSTU7564-256',
    '0bd1b36109f1318411a0517315aa46b8839df06622a278676f5487996c9cfc04'));
end;

procedure TTestDigest.TearDown;
begin
  FabcVectors := Nil;
  inherited;
end;

procedure TTestDigest.DoAbcTest(const algorithm, hash: String);
var
  abc, result: TBytes;
  digest: IDigest;
begin
  abc := TBytes.Create($61, $62, $63);

  digest := TDigestUtilities.GetDigest(algorithm);

  digest.BlockUpdate(abc, 0, System.Length(abc));
  result := TDigestUtilities.DoFinal(digest);

  if (not AreEqual(result, DecodeHex(hash))) then
  begin
    Fail(Format('abc result not equal for %s', [algorithm]));
  end;
end;

procedure TTestDigest.DoTest(const algorithm: String);
var
  &message, result, result2: TBytes;
  digest, d: IDigest;
  i: Int32;
begin
  &message := TConverters.ConvertStringToBytes('hello world', TEncoding.ASCII);

  digest := TDigestUtilities.GetDigest(algorithm);

  digest.BlockUpdate(&message, 0, System.Length(&message));
  result := TDigestUtilities.DoFinal(digest);

  digest.BlockUpdate(&message, 0, System.Length(&message));
  result2 := TDigestUtilities.DoFinal(digest);

  // test one digest the same message with the same instance
  if (not AreEqual(result, result2)) then
  begin
    Fail('Result object 1 not equal');
  end;

  // test two, single byte updates
  for i := 0 to System.Pred(System.Length(&message)) do
  begin
    digest.Update(&message[i]);
  end;

  result2 := TDigestUtilities.DoFinal(digest);

  if (not AreEqual(result, result2)) then
  begin
    Fail('Result object 2 not equal');
  end;

  // test three, two half updates
  digest.BlockUpdate(&message, 0, System.Length(&message) div 2);
  digest.BlockUpdate(&message, System.Length(&message) div 2,
    System.Length(&message) - (System.Length(&message) div 2));

  result2 := TDigestUtilities.DoFinal(digest);

  if (not AreEqual(result, result2)) then
  begin
    Fail('Result object 3 not equal');
  end;

  // test four, clone test
  digest.BlockUpdate(&message, 0, System.Length(&message) div 2);
  d := digest.Clone();
  digest.BlockUpdate(&message, System.Length(&message) div 2,
    System.Length(&message) - (System.Length(&message) div 2));

  result2 := TDigestUtilities.DoFinal(digest);

  if (not AreEqual(result, result2)) then
  begin
    Fail('Result object 4(a) not equal');
  end;

  d.BlockUpdate(&message, System.Length(&message) div 2, System.Length(&message)
    - (System.Length(&message) div 2));

  result2 := TDigestUtilities.DoFinal(d);

  if (not AreEqual(result, result2)) then
  begin
    Fail('Result object 4(b) not equal');
  end;

  // test five, check reset() method
  digest.BlockUpdate(&message, 0, System.Length(&message) div 2);
  digest.Reset();
  digest.BlockUpdate(&message, 0, System.Length(&message) div 2);
  digest.BlockUpdate(&message, System.Length(&message) div 2,
    System.Length(&message) - (System.Length(&message) div 2));

  result2 := TDigestUtilities.DoFinal(digest);

  if (not AreEqual(result, result2)) then
  begin
    Fail('Result object 5 not equal');
  end;

end;

procedure TTestDigest.TestDigests;
var
  i: Int32;
begin
  for i := 0 to System.Pred(System.Length(FabcVectors[0])) do
  begin
    DoTest(FabcVectors[i][0]);

    DoAbcTest(FabcVectors[i][0], FabcVectors[i][1]);
  end;
end;

initialization

// Register any test cases with the test runner

{$IFDEF FPC}
  RegisterTest(TTestDigest);
{$ELSE}
  RegisterTest(TTestDigest.Suite);
{$ENDIF FPC}

end.
