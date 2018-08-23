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
  ClpDigestUtilities,
  ClpMacUtilities,
  ClpGeneratorUtilities,
  ClpPkcsObjectIdentifiers,
  ClpIanaObjectIdentifiers,
  ClpNistObjectIdentifiers,
  ClpRosstandartObjectIdentifiers,
  ClpHex,
  ClpArrayUtils,
  ClpConverters,
  ClpCryptoLibTypes;

type

  TCryptoLibTestCase = class abstract(TTestCase)

  end;

type

  /// <summary>
  /// HMAC tester
  /// </summary>
  TTestHMac = class(TCryptoLibTestCase)
  private
  var
    FkeyBytes, Fmessage, Foutput1, FoutputMD5, FoutputMD2, FoutputMD4,
      Foutput224, Foutput256, Foutput384, Foutput512, Foutput512_224,
      Foutput512_256, FoutputRipeMD128, FoutputRipeMD160, FoutputTiger,
      FoutputSha3_224, FoutputSha3_256, FoutputSha3_384, FoutputSha3_512,
      FoutputGost2012_256, FoutputGost2012_512: TBytes;

    procedure DoTestHMac(const hmacName: String; const output: TBytes);
      overload;
    procedure DoTestHMac(const hmacName: String; defKeySize: Int32;
      const output: TBytes); overload;
    procedure DoTestExceptions();

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published

    procedure TestHMac;

  end;

implementation

{ TTestHMac }

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

procedure TTestHMac.DoTestHMac(const hmacName: String; const output: TBytes);
var
  key: IKeyParameter;
  mac: IMac;
  outBytes: TBytes;
  kGen: ICipherKeyGenerator;
begin
  key := TKeyParameter.Create(FkeyBytes);

  mac := TMacUtilities.GetMac(hmacName);
  mac.Init(key);
  mac.Reset();
  mac.BlockUpdate(Fmessage, 0, System.Length(Fmessage));
  outBytes := TMacUtilities.DoFinal(mac);

  if (not TArrayUtils.AreEqual(outBytes, output)) then
  begin
    Fail('Failed - expected ' + THex.Encode(output) + ' got ' +
      THex.Encode(outBytes));
  end;

  kGen := TGeneratorUtilities.GetKeyGenerator(hmacName);
  key := TKeyParameter.Create(kGen.GenerateKey());
  mac.Init(key); // hmacName
  mac.BlockUpdate(Fmessage, 0, System.Length(Fmessage));
  outBytes := TMacUtilities.DoFinal(mac);
end;

procedure TTestHMac.DoTestHMac(const hmacName: String; defKeySize: Int32;
  const output: TBytes);
var
  key: IKeyParameter;
  mac: IMac;
  outBytes: TBytes;
  kGen: ICipherKeyGenerator;
begin
  key := TKeyParameter.Create(FkeyBytes);

  mac := TMacUtilities.GetMac(hmacName);
  mac.Init(key);
  mac.Reset();
  mac.BlockUpdate(Fmessage, 0, System.Length(Fmessage));
  outBytes := TMacUtilities.DoFinal(mac);

  if (not TArrayUtils.AreEqual(outBytes, output)) then
  begin
    Fail('Failed - expected ' + THex.Encode(output) + ' got ' +
      THex.Encode(outBytes));
  end;

  kGen := TGeneratorUtilities.GetKeyGenerator(hmacName);
  key := TKeyParameter.Create(kGen.GenerateKey());
  mac.Init(key); // hmacName
  mac.BlockUpdate(Fmessage, 0, System.Length(Fmessage));
  outBytes := TMacUtilities.DoFinal(mac);

  CheckTrue(System.Length(key.GetKey()) = (defKeySize div 8),
    'default key wrong length');
end;

procedure TTestHMac.SetUp;
begin
  inherited;
  FkeyBytes := THex.Decode('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b');
  Fmessage := TConverters.ConvertStringToBytes('Hi There', TEncoding.ASCII);
  Foutput1 := THex.Decode('b617318655057264e28bc0b6fb378c8ef146be00');
  FoutputMD5 := THex.Decode('5ccec34ea9656392457fa1ac27f08fbc');
  FoutputMD2 := THex.Decode('dc1923ef5f161d35bef839ca8c807808');
  FoutputMD4 := THex.Decode('5570ce964ba8c11756cdc3970278ff5a');
  Foutput224 := THex.Decode
    ('896fb1128abbdf196832107cd49df33f47b4b1169912ba4f53684b22');
  Foutput256 := THex.Decode
    ('b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7');
  Foutput384 := THex.Decode
    ('afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6');
  Foutput512 := THex.Decode
    ('87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854');
  Foutput512_224 := THex.Decode
    ('b244ba01307c0e7a8ccaad13b1067a4cf6b961fe0c6a20bda3d92039');
  Foutput512_256 := THex.Decode
    ('9f9126c3d9c3c330d760425ca8a217e31feae31bfe70196ff81642b868402eab');
  FoutputRipeMD128 := THex.Decode('fda5717fb7e20cf05d30bb286a44b05d');
  FoutputRipeMD160 := THex.Decode('24cb4bd67d20fc1a5d2ed7732dcc39377f0a5668');
  FoutputTiger := THex.Decode
    ('1d7a658c75f8f004916e7b07e2a2e10aec7de2ae124d3647');

  FoutputSha3_224 := THex.Decode
    ('3b16546bbc7be2706a031dcafd56373d9884367641d8c59af3c860f7');
  FoutputSha3_256 := THex.Decode
    ('ba85192310dffa96e2a3a40e69774351140bb7185e1202cdcc917589f95e16bb');
  FoutputSha3_384 := THex.Decode
    ('68d2dcf7fd4ddd0a2240c8a437305f61fb7334cfb5d0226e1bc27dc10a2e723a20d370b47743130e26ac7e3d532886bd');
  FoutputSha3_512 := THex.Decode
    ('eb3fbd4b2eaab8f5c504bd3a41465aacec15770a7cabac531e482f860b5ec7ba47ccb2c6f2afce8f88d22b6dc61380f23a668fd3888bb80537c0a0b86407689e');

  FoutputGost2012_256 :=
    THex.Decode
    ('f03422dfa37a507ca126ce01b8eba6b7fdda8f8a60dd8f2703e3a372120b8294');
  FoutputGost2012_512 :=
    THex.Decode
    ('86b6a06bfa9f1974aff6ccd7fa3f835f0bd850395d6084efc47b9dda861a2cdf0dcaf959160733d5269f6567966dd7a9f932a77cd6f080012cd476f1c2cc31bb');

end;

procedure TTestHMac.TearDown;
begin
  inherited;

end;

procedure TTestHMac.TestHMac;
begin
  DoTestHMac('HMac-SHA1', Foutput1);
  DoTestHMac('HMac-MD5', FoutputMD5);
  DoTestHMac('HMac-MD4', FoutputMD4);
  DoTestHMac('HMac-MD2', FoutputMD2);
  DoTestHMac('HMac-SHA224', Foutput224);
  DoTestHMac('HMac-SHA256', Foutput256);
  DoTestHMac('HMac-SHA384', Foutput384);
  DoTestHMac('HMac-SHA512', Foutput512);
  DoTestHMac('HMac-SHA512/224', Foutput512_224);
  DoTestHMac('HMac-SHA512/256', Foutput512_256);

  DoTestHMac('HMac-RIPEMD128', FoutputRipeMD128);
  DoTestHMac('HMac-RIPEMD160', FoutputRipeMD160);

  DoTestHMac('HMac-TIGER', FoutputTiger);

  DoTestHMac('HMac-SHA3-224', 224, FoutputSha3_224);
  DoTestHMac('HMac-SHA3-256', 256, FoutputSha3_256);
  DoTestHMac('HMac-SHA3-384', 384, FoutputSha3_384);
  DoTestHMac('HMac-SHA3-512', 512, FoutputSha3_512);

  DoTestHMac('HMac-GOST3411-2012-256', 256, FoutputGost2012_256);
  DoTestHMac('HMac-GOST3411-2012-512', 512, FoutputGost2012_512);

  DoTestHMac('HMac/SHA1', Foutput1);

  DoTestHMac('HMac/MD5', FoutputMD5);
  DoTestHMac('HMac/MD4', FoutputMD4);
  DoTestHMac('HMac/MD2', FoutputMD2);

  DoTestHMac('HMac/SHA224', Foutput224);
  DoTestHMac('HMac/SHA256', Foutput256);
  DoTestHMac('HMac/SHA384', Foutput384);
  DoTestHMac('HMac/SHA512', Foutput512);

  DoTestHMac('HMac/RIPEMD128', FoutputRipeMD128);
  DoTestHMac('HMac/RIPEMD160', FoutputRipeMD160);
  DoTestHMac('HMac/TIGER', FoutputTiger);

  DoTestHMac('HMac/SHA3-224', 224, FoutputSha3_224);
  DoTestHMac('HMac/SHA3-256', 256, FoutputSha3_256);
  DoTestHMac('HMac/SHA3-384', 384, FoutputSha3_384);
  DoTestHMac('HMac/SHA3-512', 512, FoutputSha3_512);

  DoTestHMac('HMac/GOST3411-2012-256', 256, FoutputGost2012_256);
  DoTestHMac('HMac/GOST3411-2012-512', 512, FoutputGost2012_512);

  DoTestHMac(TPkcsObjectIdentifiers.IdHmacWithSha1.Id, Foutput1);
  DoTestHMac(TPkcsObjectIdentifiers.IdHmacWithSha224.Id, Foutput224);
  DoTestHMac(TPkcsObjectIdentifiers.IdHmacWithSha256.Id, Foutput256);
  DoTestHMac(TPkcsObjectIdentifiers.IdHmacWithSha384.Id, Foutput384);
  DoTestHMac(TPkcsObjectIdentifiers.IdHmacWithSha512.Id, Foutput512);
  DoTestHMac(TIanaObjectIdentifiers.HmacSha1.Id, Foutput1);

  DoTestHMac(TIanaObjectIdentifiers.HmacMD5.Id, FoutputMD5);

  DoTestHMac(TIanaObjectIdentifiers.HmacRipeMD160.Id, FoutputRipeMD160);

  DoTestHMac(TIanaObjectIdentifiers.HmacTiger.Id, FoutputTiger);

  DoTestHMac(TNistObjectIdentifiers.IdHMacWithSha3_224.Id, 224,
    FoutputSha3_224);
  DoTestHMac(TNistObjectIdentifiers.IdHMacWithSha3_256.Id, 256,
    FoutputSha3_256);
  DoTestHMac(TNistObjectIdentifiers.IdHMacWithSha3_384.Id, 384,
    FoutputSha3_384);
  DoTestHMac(TNistObjectIdentifiers.IdHMacWithSha3_512.Id, 512,
    FoutputSha3_512);

  DoTestHMac(TRosstandartObjectIdentifiers.id_tc26_hmac_gost_3411_12_256.Id,
    256, FoutputGost2012_256);
  DoTestHMac(TRosstandartObjectIdentifiers.id_tc26_hmac_gost_3411_12_512.Id,
    512, FoutputGost2012_512);

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
