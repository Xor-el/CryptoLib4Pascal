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

unit GcmSivTests;

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
  ClpGcmSivBlockCipher,
  ClpIGcmSivBlockCipher,
  ClpAeadParameters,
  ClpIAeadParameters,
  ClpKeyParameter,
  ClpIKeyParameter,
  ClpICipherParameters,
  ClpConverters,
  ClpSecureRandom,
  ClpISecureRandom,
  ClpCryptoLibTypes,
  ClpFusedKernelToggle,
  CryptoLibTestBase;

type

  TTestGcmSiv = class(TCryptoLibAlgorithmTestCase)
  private
    procedure TestSivCipher(const AKey, ANonce, AAEAD, AData,
      AExpected: string);

    function NextInt32(const ARandom: ISecureRandom; AN: Int32): Int32;
    procedure RandomisedRoundTrip(const ARandom: ISecureRandom);

  protected
    procedure SetUp; override;
    procedure TearDown; override;

    // Workers run twice via RunWithFusedToggle (fused on / off).
    procedure DoTestAesGcmSiv128Set1;
    procedure DoTestAesGcmSiv128Set2;
    procedure DoTestAesGcmSiv128Set3;
    procedure DoTestAesGcmSiv256Set1;
    procedure DoTestAesGcmSiv256Set2;
    procedure DoTestAesGcmSiv256Set3;
    procedure DoTestAesGcmSiv256Set4;
    procedure DoTestRandomised;

  published
    procedure TestAesGcmSiv128Set1;
    procedure TestAesGcmSiv128Set2;
    procedure TestAesGcmSiv128Set3;
    procedure TestAesGcmSiv256Set1;
    procedure TestAesGcmSiv256Set2;
    procedure TestAesGcmSiv256Set3;
    procedure TestAesGcmSiv256Set4;
    procedure TestRandomised;

  end;

implementation

{ TTestGcmSiv }

procedure TTestGcmSiv.SetUp;
begin
  inherited;
end;

procedure TTestGcmSiv.TearDown;
begin
  inherited;
end;

procedure TTestGcmSiv.TestSivCipher(const AKey, ANonce, AAEAD, AData,
  AExpected: string);
var
  LCipher: IGcmSivBlockCipher;
  LKey: IKeyParameter;
  LNonce, LAead, LData, LOutput, LFinal, LExpected: TBytes;
  LParams: IAeadParameters;
  LI: Int32;
begin
  try
    LKey := TKeyParameter.Create(DecodeHex(AKey)) as IKeyParameter;
    LNonce := DecodeHex(ANonce);
    LAead := DecodeHex(AAEAD);
    LData := DecodeHex(AData);

    LParams := TAeadParameters.Create(LKey, 128, LNonce, LAead);

    LCipher := TGcmSivBlockCipher.Create() as IGcmSivBlockCipher;
    LCipher.Init(True, LParams as ICipherParameters);

    System.SetLength(LOutput, LCipher.GetOutputSize(System.Length(LData)));
    System.SetLength(LFinal, System.Length(LData));

    LCipher.ProcessBytes(LData, 0, System.Length(LData), nil, 0);
    LCipher.DoFinal(LOutput, 0);

    LExpected := DecodeHex(AExpected);
    if not AreEqual(LExpected, LOutput) then
    begin
      Fail('Encryption mismatch');
    end;

    // Repeat processing byte at a time
    for LI := 0 to System.Length(LData) - 1 do
    begin
      LCipher.ProcessByte(LData[LI], nil, 0);
    end;
    LCipher.DoFinal(LOutput, 0);
    if not AreEqual(LExpected, LOutput) then
    begin
      Fail('Encryption mismatch (byte-at-a-time)');
    end;

    if System.Length(LData) >= 2 then
    begin
      // Repeat processing checking processBytes with non-empty internal buffer
      LCipher.ProcessByte(LData[0], nil, 0);
      LCipher.ProcessBytes(LData, 1, System.Length(LData) - 1, nil, 0);
      LCipher.DoFinal(LOutput, 0);
      if not AreEqual(LExpected, LOutput) then
      begin
        Fail('Encryption mismatch (mixed processing)');
      end;
    end;

    // Decryption
    LCipher.Init(False, LParams as ICipherParameters);
    LCipher.ProcessBytes(LOutput, 0, System.Length(LOutput), nil, 0);
    LCipher.DoFinal(LFinal, 0);
    if not AreEqual(LData, LFinal) then
    begin
      Fail('Decryption mismatch');
    end;
  except
    on E: EInvalidCipherTextCryptoLibException do
    begin
      Fail('Bad Text: ' + E.Message);
    end;
  end;
end;

// AES-GCM-SIV-128 Set 1
procedure TTestGcmSiv.DoTestAesGcmSiv128Set1;
const
  CKey1 = '01000000000000000000000000000000';
  CNonce1 = '030000000000000000000000';
  CEmpty = '';
  CData8 = '0100000000000000';
  CData12 = '010000000000000000000000';
  CData16 = '01000000000000000000000000000000';
  CData32 = '01000000000000000000000000000000' +
    '02000000000000000000000000000000';
  CData48 = '01000000000000000000000000000000' +
    '02000000000000000000000000000000' +
    '03000000000000000000000000000000';
  CData64 = '01000000000000000000000000000000' +
    '02000000000000000000000000000000' +
    '03000000000000000000000000000000' +
    '04000000000000000000000000000000';
  CExpected1 = 'dc20e2d83f25705bb49e439eca56de25';
  CExpected2 = 'b5d839330ac7b786578782fff6013b81' +
    '5b287c22493a364c';
  CExpected3 = '7323ea61d05932260047d942a4978db3' +
    '57391a0bc4fdec8b0d106639';
  CExpected4 = '743f7c8077ab25f8624e2e948579cf77' +
    '303aaf90f6fe21199c6068577437a0c4';
  CExpected5 = '84e07e62ba83a6585417245d7ec413a9' +
    'fe427d6315c09b57ce45f2e3936a9445' +
    '1a8e45dcd4578c667cd86847bf6155ff';
  CExpected6 = '3fd24ce1f5a67b75bf2351f181a475c7' +
    'b800a5b4d3dcf70106b1eea82fa1d64d' +
    'f42bf7226122fa92e17a40eeaac1201b' +
    '5e6e311dbf395d35b0fe39c2714388f8';
  CExpected7 = '2433668f1058190f6d43e360f4f35cd8' +
    'e475127cfca7028ea8ab5c20f7ab2af0' +
    '2516a2bdcbc08d521be37ff28c152bba' +
    '36697f25b4cd169c6590d1dd39566d3f' +
    '8a263dd317aa88d56bdf3936dba75bb8';
begin
  TestSivCipher(CKey1, CNonce1, CEmpty, CEmpty, CExpected1);
  TestSivCipher(CKey1, CNonce1, CEmpty, CData8, CExpected2);
  TestSivCipher(CKey1, CNonce1, CEmpty, CData12, CExpected3);
  TestSivCipher(CKey1, CNonce1, CEmpty, CData16, CExpected4);
  TestSivCipher(CKey1, CNonce1, CEmpty, CData32, CExpected5);
  TestSivCipher(CKey1, CNonce1, CEmpty, CData48, CExpected6);
  TestSivCipher(CKey1, CNonce1, CEmpty, CData64, CExpected7);
end;

// AES-GCM-SIV-128 Set 2
procedure TTestGcmSiv.DoTestAesGcmSiv128Set2;
const
  CKey1 = '01000000000000000000000000000000';
  CNonce1 = '030000000000000000000000';
  CAead1 = '01';
  CAead12 = '010000000000000000000000';
  CAead18 = '01000000000000000000000000000000' + '0200';
  CAead20 = '01000000000000000000000000000000' + '02000000';
  CData4 = '02000000';
  CData8 = '0200000000000000';
  CData12 = '020000000000000000000000';
  CData16 = '02000000000000000000000000000000';
  CData18 = '03000000000000000000000000000000' + '0400';
  CData20 = '03000000000000000000000000000000' + '04000000';
  CData32 = '02000000000000000000000000000000' +
    '03000000000000000000000000000000';
  CData48 = '02000000000000000000000000000000' +
    '03000000000000000000000000000000' +
    '04000000000000000000000000000000';
  CData64 = '02000000000000000000000000000000' +
    '03000000000000000000000000000000' +
    '04000000000000000000000000000000' +
    '05000000000000000000000000000000';
  CExpected1 = '1e6daba35669f4273b0a1a2560969cdf' +
    '790d99759abd1508';
  CExpected2 = '296c7889fd99f41917f4462008299c51' +
    '02745aaa3a0c469fad9e075a';
  CExpected3 = 'e2b0c5da79a901c1745f700525cb335b' +
    '8f8936ec039e4e4bb97ebd8c4457441f';
  CExpected4 = '620048ef3c1e73e57e02bb8562c416a3' +
    '19e73e4caac8e96a1ecb2933145a1d71' +
    'e6af6a7f87287da059a71684ed3498e1';
  CExpected5 = '50c8303ea93925d64090d07bd109dfd9' +
    '515a5a33431019c17d93465999a8b005' +
    '3201d723120a8562b838cdff25bf9d1e' +
    '6a8cc3865f76897c2e4b245cf31c51f2';
  CExpected6 = '2f5c64059db55ee0fb847ed513003746' +
    'aca4e61c711b5de2e7a77ffd02da42fe' +
    'ec601910d3467bb8b36ebbaebce5fba3' +
    '0d36c95f48a3e7980f0e7ac299332a80' +
    'cdc46ae475563de037001ef84ae21744';
  CExpected7 = 'a8fe3e8707eb1f84fb28f8cb73de8e99' +
    'e2f48a14';
  CExpected8 = '6bb0fecf5ded9b77f902c7d5da236a43' +
    '91dd029724afc9805e976f451e6d87f6' +
    'fe106514';
  CExpected9 = '44d0aaf6fb2f1f34add5e8064e83e12a' +
    '2adabff9b2ef00fb47920cc72a0c0f13' +
    'b9fd';
begin
  TestSivCipher(CKey1, CNonce1, CAead1, CData8, CExpected1);
  TestSivCipher(CKey1, CNonce1, CAead1, CData12, CExpected2);
  TestSivCipher(CKey1, CNonce1, CAead1, CData16, CExpected3);
  TestSivCipher(CKey1, CNonce1, CAead1, CData32, CExpected4);
  TestSivCipher(CKey1, CNonce1, CAead1, CData48, CExpected5);
  TestSivCipher(CKey1, CNonce1, CAead1, CData64, CExpected6);
  TestSivCipher(CKey1, CNonce1, CAead12, CData4, CExpected7);
  TestSivCipher(CKey1, CNonce1, CAead18, CData20, CExpected8);
  TestSivCipher(CKey1, CNonce1, CAead20, CData18, CExpected9);
end;

// AES-GCM-SIV-128 Set 3
procedure TTestGcmSiv.DoTestAesGcmSiv128Set3;
const
  CEmpty = '';
  CKey1 = 'e66021d5eb8e4f4066d4adb9c33560e4';
  CKey2 = '36864200e0eaf5284d884a0e77d31646';
  CKey3 = 'aedb64a6c590bc84d1a5e269e4b47801';
  CKey4 = 'd5cc1fd161320b6920ce07787f86743b';
  CKey5 = 'b3fed1473c528b8426a582995929a149';
  CKey6 = '2d4ed87da44102952ef94b02b805249b';
  CKey7 = 'bde3b2f204d1e9f8b06bc47f9745b3d1';
  CKey8 = 'f901cfe8a69615a93fdf7a98cad48179';
  CNonce1 = 'f46e44bb3da0015c94f70887';
  CNonce2 = 'bae8e37fc83441b16034566b';
  CNonce3 = 'afc0577e34699b9e671fdd4f';
  CNonce4 = '275d1ab32f6d1f0434d8848c';
  CNonce5 = '9e9ad8780c8d63d0ab4149c0';
  CNonce6 = 'ac80e6f61455bfac8308a2d4';
  CNonce7 = 'ae06556fb6aa7890bebc18fe';
  CNonce8 = '6245709fb18853f68d833640';
  CAead2 = '46bb91c3c5';
  CAead3 = 'fc880c94a95198874296';
  CAead4 = '046787f3ea22c127aaf195d1894728';
  CAead5 = 'c9882e5386fd9f92ec489c8fde2be2cf' + '97e74e93';
  CAead6 = '2950a70d5a1db2316fd568378da107b5' + '2b0da55210cc1c1b0a';
  CAead7 = '1860f762ebfbd08284e421702de0de18' + 'baa9c9596291b08466f37de21c7f';
  CAead8 = '7576f7028ec6eb5ea7e298342a94d4b2' +
    '02b370ef9768ec6561c4fe6b7e7296fa' + '859c21';
  CData2 = '7a806c';
  CData3 = 'bdc66f146545';
  CData4 = '1177441f195495860f';
  CData5 = '9f572c614b4745914474e7c7';
  CData6 = '0d8c8451178082355c9e940fea2f58';
  CData7 = '6b3db4da3d57aa94842b9803a96e07fb' + '6de7';
  CData8 = 'e42a3c02c25b64869e146d7b233987bd' + 'dfc240871d';
  CExpected1 = 'a4194b79071b01a87d65f706e3949578';
  CExpected2 = 'af60eb711bd85bc1e4d3e0a462e074ee' + 'a428a8';
  CExpected3 = 'bb93a3e34d3cd6a9c45545cfc11f03ad' + '743dba20f966';
  CExpected4 = '4f37281f7ad12949d01d02fd0cd174c8' + '4fc5dae2f60f52fd2b';
  CExpected5 = 'f54673c5ddf710c745641c8bc1dc2f87' + '1fb7561da1286e655e24b7b0';
  CExpected6 = 'c9ff545e07b88a015f05b274540aa183' +
    'b3449b9f39552de99dc214a1190b0b';
  CExpected7 = '6298b296e24e8cc35dce0bed484b7f30' +
    'd5803e377094f04709f64d7b985310a4' + 'db84';
  CExpected8 = '391cc328d484a4f46406181bcd62efd9' +
    'b3ee197d052d15506c84a9edd65e13e9' + 'd24a2a6e70';
begin
  TestSivCipher(CKey1, CNonce1, CEmpty, CEmpty, CExpected1);
  TestSivCipher(CKey2, CNonce2, CAead2, CData2, CExpected2);
  TestSivCipher(CKey3, CNonce3, CAead3, CData3, CExpected3);
  TestSivCipher(CKey4, CNonce4, CAead4, CData4, CExpected4);
  TestSivCipher(CKey5, CNonce5, CAead5, CData5, CExpected5);
  TestSivCipher(CKey6, CNonce6, CAead6, CData6, CExpected6);
  TestSivCipher(CKey7, CNonce7, CAead7, CData7, CExpected7);
  TestSivCipher(CKey8, CNonce8, CAead8, CData8, CExpected8);
end;

// AES-GCM-SIV-256 Set 1
procedure TTestGcmSiv.DoTestAesGcmSiv256Set1;
const
  CEmpty = '';
  CKey1 = '01000000000000000000000000000000' +
    '00000000000000000000000000000000';
  CNonce1 = '030000000000000000000000';
  CData8 = '0100000000000000';
  CData12 = '010000000000000000000000';
  CData16 = '01000000000000000000000000000000';
  CData32 = '01000000000000000000000000000000' +
    '02000000000000000000000000000000';
  CData48 = '01000000000000000000000000000000' +
    '02000000000000000000000000000000' +
    '03000000000000000000000000000000';
  CData64 = '01000000000000000000000000000000' +
    '02000000000000000000000000000000' +
    '03000000000000000000000000000000' +
    '04000000000000000000000000000000';
  CExpected1 = '07f5f4169bbf55a8400cd47ea6fd400f';
  CExpected2 = 'c2ef328e5c71c83b843122130f7364b7' +
    '61e0b97427e3df28';
  CExpected3 = '9aab2aeb3faa0a34aea8e2b18ca50da9' +
    'ae6559e48fd10f6e5c9ca17e';
  CExpected4 = '85a01b63025ba19b7fd3ddfc033b3e76' +
    'c9eac6fa700942702e90862383c6c366';
  CExpected5 = '4a6a9db4c8c6549201b9edb53006cba8' +
    '21ec9cf850948a7c86c68ac7539d027f' +
    'e819e63abcd020b006a976397632eb5d';
  CExpected6 = 'c00d121893a9fa603f48ccc1ca3c57ce' +
    '7499245ea0046db16c53c7c66fe717e3' +
    '9cf6c748837b61f6ee3adcee17534ed5' +
    '790bc96880a99ba804bd12c0e6a22cc4';
  CExpected7 = 'c2d5160a1f8683834910acdafc41fbb1' +
    '632d4a353e8b905ec9a5499ac34f96c7' +
    'e1049eb080883891a4db8caaa1f99dd0' +
    '04d80487540735234e3744512c6f90ce' +
    '112864c269fc0d9d88c61fa47e39aa08';
begin
  TestSivCipher(CKey1, CNonce1, CEmpty, CEmpty, CExpected1);
  TestSivCipher(CKey1, CNonce1, CEmpty, CData8, CExpected2);
  TestSivCipher(CKey1, CNonce1, CEmpty, CData12, CExpected3);
  TestSivCipher(CKey1, CNonce1, CEmpty, CData16, CExpected4);
  TestSivCipher(CKey1, CNonce1, CEmpty, CData32, CExpected5);
  TestSivCipher(CKey1, CNonce1, CEmpty, CData48, CExpected6);
  TestSivCipher(CKey1, CNonce1, CEmpty, CData64, CExpected7);
end;

// AES-GCM-SIV-256 Set 2
procedure TTestGcmSiv.DoTestAesGcmSiv256Set2;
const
  CKey1 = '01000000000000000000000000000000' +
    '00000000000000000000000000000000';
  CNonce1 = '030000000000000000000000';
  CAead1 = '01';
  CAead12 = '010000000000000000000000';
  CAead18 = '01000000000000000000000000000000' + '0200';
  CAead20 = '01000000000000000000000000000000' + '02000000';
  CData4 = '02000000';
  CData8 = '0200000000000000';
  CData12 = '020000000000000000000000';
  CData16 = '02000000000000000000000000000000';
  CData18 = '03000000000000000000000000000000' + '0400';
  CData20 = '03000000000000000000000000000000' + '04000000';
  CData32 = '02000000000000000000000000000000' +
    '03000000000000000000000000000000';
  CData48 = '02000000000000000000000000000000' +
    '03000000000000000000000000000000' +
    '04000000000000000000000000000000';
  CData64 = '02000000000000000000000000000000' +
    '03000000000000000000000000000000' +
    '04000000000000000000000000000000' +
    '05000000000000000000000000000000';
  CExpected1 = '1de22967237a813291213f267e3b452f' + '02d01ae33e4ec854';
  CExpected2 = '163d6f9cc1b346cd453a2e4cc1a4a19a' +
    'e800941ccdc57cc8413c277f';
  CExpected3 = 'c91545823cc24f17dbb0e9e807d5ec17' +
    'b292d28ff61189e8e49f3875ef91aff7';
  CExpected4 = '07dad364bfc2b9da89116d7bef6daaaf' +
    '6f255510aa654f920ac81b94e8bad365' +
    'aea1bad12702e1965604374aab96dbbc';
  CExpected5 = 'c67a1f0f567a5198aa1fcc8e3f213143' +
    '36f7f51ca8b1af61feac35a86416fa47' +
    'fbca3b5f749cdf564527f2314f42fe25' +
    '03332742b228c647173616cfd44c54eb';
  CExpected6 = '67fd45e126bfb9a79930c43aad2d3696' +
    '7d3f0e4d217c1e551f59727870beefc9' +
    '8cb933a8fce9de887b1e40799988db1f' +
    'c3f91880ed405b2dd298318858467c89' +
    '5bde0285037c5de81e5b570a049b62a0';
  CExpected7 = '22b3f4cd1835e517741dfddccfa07fa4' + '661b74cf';
  CExpected8 = '43dd0163cdb48f9fe3212bf61b201976' +
    '067f342bb879ad976d8242acc188ab59' + 'cabfe307';
  CExpected9 = '462401724b5ce6588d5a54aae5375513' +
    'a075cfcdf5042112aa29685c912fc205' + '6543';
begin
  TestSivCipher(CKey1, CNonce1, CAead1, CData8, CExpected1);
  TestSivCipher(CKey1, CNonce1, CAead1, CData12, CExpected2);
  TestSivCipher(CKey1, CNonce1, CAead1, CData16, CExpected3);
  TestSivCipher(CKey1, CNonce1, CAead1, CData32, CExpected4);
  TestSivCipher(CKey1, CNonce1, CAead1, CData48, CExpected5);
  TestSivCipher(CKey1, CNonce1, CAead1, CData64, CExpected6);
  TestSivCipher(CKey1, CNonce1, CAead12, CData4, CExpected7);
  TestSivCipher(CKey1, CNonce1, CAead18, CData20, CExpected8);
  TestSivCipher(CKey1, CNonce1, CAead20, CData18, CExpected9);
end;

// AES-GCM-SIV-256 Set 3
procedure TTestGcmSiv.DoTestAesGcmSiv256Set3;
const
  CEmpty = '';
  CKey1 = 'e66021d5eb8e4f4066d4adb9c33560e4' +
    'f46e44bb3da0015c94f7088736864200';
  CKey2 = 'bae8e37fc83441b16034566b7a806c46' +
    'bb91c3c5aedb64a6c590bc84d1a5e269';
  CKey3 = '6545fc880c94a95198874296d5cc1fd1' +
    '61320b6920ce07787f86743b275d1ab3';
  CKey4 = 'd1894728b3fed1473c528b8426a58299' +
    '5929a1499e9ad8780c8d63d0ab4149c0';
  CKey5 = 'a44102952ef94b02b805249bac80e6f6' +
    '1455bfac8308a2d40d8c845117808235';
  CKey6 = '9745b3d1ae06556fb6aa7890bebc18fe' +
    '6b3db4da3d57aa94842b9803a96e07fb';
  CKey7 = 'b18853f68d833640e42a3c02c25b6486' +
    '9e146d7b233987bddfc240871d7576f7';
  CKey8 = '3c535de192eaed3822a2fbbe2ca9dfc8' +
    '8255e14a661b8aa82cc54236093bbc23';
  CNonce1 = 'e0eaf5284d884a0e77d31646';
  CNonce2 = 'e4b47801afc0577e34699b9e';
  CNonce3 = '2f6d1f0434d8848c1177441f';
  CNonce4 = '9f572c614b4745914474e7c7';
  CNonce5 = '5c9e940fea2f582950a70d5a';
  CNonce6 = '6de71860f762ebfbd08284e4';
  CNonce7 = '028ec6eb5ea7e298342a94d4';
  CNonce8 = '688089e55540db1872504e1c';
  CAead2 = '4fbdc66f14';
  CAead3 = '6787f3ea22c127aaf195';
  CAead4 = '489c8fde2be2cf97e74e932d4ed87d';
  CAead5 = '0da55210cc1c1b0abde3b2f204d1e9f8' + 'b06bc47f';
  CAead6 = 'f37de21c7ff901cfe8a69615a93fdf7a' + '98cad481796245709f';
  CAead7 = '9c2159058b1f0fe91433a5bdc20e214e' + 'ab7fecef4454a10ef0657df21ac7';
  CAead8 = '734320ccc9d9bbbb19cb81b2af4ecbc3' +
    'e72834321f7aa0f70b7282b4f33df23f' + '167541';
  CData2 = '671fdd';
  CData3 = '195495860f04';
  CData4 = 'c9882e5386fd9f92ec';
  CData5 = '1db2316fd568378da107b52b';
  CData6 = '21702de0de18baa9c9596291b08466';
  CData7 = 'b202b370ef9768ec6561c4fe6b7e7296' + 'fa85';
  CData8 = 'ced532ce4159b035277d4dfbb7db6296' + '8b13cd4eec';
  CExpected1 = '169fbb2fbf389a995f6390af22228a62';
  CExpected2 = '0eaccb93da9bb81333aee0c785b240d3' + '19719d';
  CExpected3 = 'a254dad4f3f96b62b84dc40c84636a5e' + 'c12020ec8c2c';
  CExpected4 = '0df9e308678244c44bc0fd3dc6628dfe' + '55ebb0b9fb2295c8c2';
  CExpected5 = '8dbeb9f7255bf5769dd56692404099c2' +
    '587f64979f21826706d497d5';
  CExpected6 = '793576dfa5c0f88729a7ed3c2f1bffb3' +
    '080d28f6ebb5d3648ce97bd5ba67fd';
  CExpected7 = '857e16a64915a787637687db4a951963' +
    '5cdd454fc2a154fea91f8363a39fec7d' + '0a49';
  CExpected8 = '626660c26ea6612fb17ad91e8e767639' +
    'edd6c9faee9d6c7029675b89eaf4ba1d' + 'ed1a286594';
begin
  TestSivCipher(CKey1, CNonce1, CEmpty, CEmpty, CExpected1);
  TestSivCipher(CKey2, CNonce2, CAead2, CData2, CExpected2);
  TestSivCipher(CKey3, CNonce3, CAead3, CData3, CExpected3);
  TestSivCipher(CKey4, CNonce4, CAead4, CData4, CExpected4);
  TestSivCipher(CKey5, CNonce5, CAead5, CData5, CExpected5);
  TestSivCipher(CKey6, CNonce6, CAead6, CData6, CExpected6);
  TestSivCipher(CKey7, CNonce7, CAead7, CData7, CExpected7);
  TestSivCipher(CKey8, CNonce8, CAead8, CData8, CExpected8);
end;

// AES-GCM-SIV-256 Set 4
procedure TTestGcmSiv.DoTestAesGcmSiv256Set4;
const
  CEmpty = '';
  CKey1 = '00000000000000000000000000000000' +
    '00000000000000000000000000000000';
  CNonce1 = '000000000000000000000000';
  CData1 = '00000000000000000000000000000000' +
    '4db923dc793ee6497c76dcc03a98e108';
  CData2 = 'eb3640277c7ffd1303c7a542d02d3e4c' +
    '0000000000000000';
  CExpected1 = 'f3f80f2cf0cb2dd9c5984fcda908456c' +
    'c537703b5ba70324a6793a7bf218d3ea' +
    'ffffffff000000000000000000000000';
  CExpected2 = '18ce4f0b8cb4d0cac65fea8f79257b20' +
    '888e53e72299e56dffffffff00000000' +
    '0000000000000000';
begin
  TestSivCipher(CKey1, CNonce1, CEmpty, CData1, CExpected1);
  TestSivCipher(CKey1, CNonce1, CEmpty, CData2, CExpected2);
end;

function TTestGcmSiv.NextInt32(const ARandom: ISecureRandom; AN: Int32): Int32;
begin
  if AN <= 0 then
  begin
    Result := 0;
    Exit;
  end;
  Result := Int32(UInt32(ARandom.NextInt32) and $7FFFFFFF) mod AN;
end;

procedure TTestGcmSiv.RandomisedRoundTrip(const ARandom: ISecureRandom);
var
  LKey, LNonce, LAad, LPlain, LEnc, LDec, LTmp: TBytes;
  LKeyBits, LKeyBytes, LAadLen, LPlainLen, LIdx, LLen: Int32;
  LCipher: IGcmSivBlockCipher;
  LParams: IAeadParameters;
begin
  // Sweep key sizes and plaintext lengths covering both the fused
  // POLYVAL kernel (>=128 bytes) and the 16-byte scalar tail fold.
  for LIdx := 0 to 31 do
  begin
    if (LIdx and 1) = 0 then
      LKeyBits := 128
    else
      LKeyBits := 256;
    LKeyBytes := LKeyBits div 8;
    SetLength(LKey, LKeyBytes);
    ARandom.NextBytes(LKey);

    SetLength(LNonce, 12);
    ARandom.NextBytes(LNonce);

    LAadLen := NextInt32(ARandom, 4097);
    SetLength(LAad, LAadLen);
    if LAadLen > 0 then
      ARandom.NextBytes(LAad);

    LPlainLen := NextInt32(ARandom, 4097);
    SetLength(LPlain, LPlainLen);
    if LPlainLen > 0 then
      ARandom.NextBytes(LPlain);

    LParams := TAeadParameters.Create(TKeyParameter.Create(LKey)
      as IKeyParameter, 128, LNonce, LAad);

    LCipher := TGcmSivBlockCipher.Create() as IGcmSivBlockCipher;
    LCipher.Init(True, LParams as ICipherParameters);
    SetLength(LEnc, LCipher.GetOutputSize(LPlainLen));
    LLen := LCipher.ProcessBytes(LPlain, 0, LPlainLen, nil, 0);
    LLen := LLen + LCipher.DoFinal(LEnc, 0);
    if LLen <> Length(LEnc) then
      Fail(Format('encrypt output length mismatch at iter %d (got %d, want %d)',
        [LIdx, LLen, Length(LEnc)]));

    LCipher.Init(False, LParams as ICipherParameters);
    SetLength(LTmp, LCipher.GetOutputSize(Length(LEnc)));
    LLen := LCipher.ProcessBytes(LEnc, 0, Length(LEnc), nil, 0);
    LLen := LLen + LCipher.DoFinal(LTmp, 0);
    SetLength(LDec, LLen);
    if LLen > 0 then
      System.Move(LTmp[0], LDec[0], LLen);

    if not AreEqual(LPlain, LDec) then
      Fail(Format('round-trip plaintext mismatch at iter %d ' +
        '(keybits=%d aad=%d plain=%d)',
        [LIdx, LKeyBits, LAadLen, LPlainLen]));
  end;
end;

procedure TTestGcmSiv.DoTestRandomised;
var
  LRandom: ISecureRandom;
begin
  LRandom := TSecureRandom.GetInstance('SHA256PRNG');
  LRandom.SetSeed(TConverters.ConvertStringToBytes('GcmSivDualModeRandomSeed-v1',
    TEncoding.ASCII));
  RandomisedRoundTrip(LRandom);
end;

procedure TTestGcmSiv.TestAesGcmSiv128Set1;
begin
  RunWithFusedToggle(DoTestAesGcmSiv128Set1);
end;

procedure TTestGcmSiv.TestAesGcmSiv128Set2;
begin
  RunWithFusedToggle(DoTestAesGcmSiv128Set2);
end;

procedure TTestGcmSiv.TestAesGcmSiv128Set3;
begin
  RunWithFusedToggle(DoTestAesGcmSiv128Set3);
end;

procedure TTestGcmSiv.TestAesGcmSiv256Set1;
begin
  RunWithFusedToggle(DoTestAesGcmSiv256Set1);
end;

procedure TTestGcmSiv.TestAesGcmSiv256Set2;
begin
  RunWithFusedToggle(DoTestAesGcmSiv256Set2);
end;

procedure TTestGcmSiv.TestAesGcmSiv256Set3;
begin
  RunWithFusedToggle(DoTestAesGcmSiv256Set3);
end;

procedure TTestGcmSiv.TestAesGcmSiv256Set4;
begin
  RunWithFusedToggle(DoTestAesGcmSiv256Set4);
end;

procedure TTestGcmSiv.TestRandomised;
begin
  RunWithFusedToggle(DoTestRandomised);
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestGcmSiv);
{$ELSE}
  RegisterTest(TTestGcmSiv.Suite);
{$ENDIF FPC}

end.
