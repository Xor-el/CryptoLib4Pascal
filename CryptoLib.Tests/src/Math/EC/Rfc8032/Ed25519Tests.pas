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

unit Ed25519Tests;

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
  ClpIDigest,
  ClpEd25519,
  ClpSecureRandom,
  ClpISecureRandom,
  ClpConverters,
  CryptoLibTestBase;

type

  TTestEd25519 = class(TCryptoLibAlgorithmTestCase)
  private
  var
    FRandom: ISecureRandom;
    FEd25519: TEd25519;

    procedure CheckEd25519Vector(const ASK, APK, AM, ASig, AText: String);
    procedure CheckEd25519ctxVector(const ASK, APK, AM, ACTX, ASig, AText: String);
    procedure CheckEd25519phVector(const ASK, APK, AM, ACTX, ASig, AText: String);
    procedure ImplTamingVector(ANumber: Int32; AExpected: Boolean; const AMsgHex, APubHex, ASigHex: String); overload;
    function ImplTamingVector(const AMsgHex, APubHex, ASigHex: String): Boolean; overload;
  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestEd25519Consistency();
    procedure TestEd25519ctxConsistency();
    procedure TestEd25519phConsistency();
    procedure TestEd25519Vector1();
    procedure TestEd25519Vector2();
    procedure TestEd25519Vector3();
    procedure TestEd25519Vector1023();

    procedure TestEd25519VectorSHAabc();
    procedure TestEd25519ctxVector1();
    procedure TestEd25519ctxVector2();
    procedure TestEd25519ctxVector3();
    procedure TestEd25519ctxVector4();
    procedure TestEd25519phVector1();

    procedure TestPublicKeyValidationFull();
    procedure TestPublicKeyValidationPartial();
    procedure TamingNonRepudiation();
    procedure TamingVector_00();
    procedure TamingVector_01();
    procedure TamingVector_02();
    procedure TamingVector_03();
    procedure TamingVector_04();
    procedure TamingVector_05();
    procedure TamingVector_06();
    procedure TamingVector_07();
    procedure TamingVector_08();
    procedure TamingVector_09();
    procedure TamingVector_10();
    procedure TamingVector_11();
  end;

implementation

{ TTestEd25519 }

procedure TTestEd25519.CheckEd25519Vector(const ASK, APK, AM, ASig, AText: String);
var
  LSk, LPk, LM, LSig, LPkGen, LBadSig, LSigGen: TBytes;
  LShouldVerify, LShouldNotVerify: Boolean;
begin
  LSk := DecodeHex(ASK);
  LPk := DecodeHex(APK);

  System.SetLength(LPkGen, TEd25519.PublicKeySize);
  FEd25519.GeneratePublicKey(LSk, 0, LPkGen, 0);
  CheckTrue(AreEqual(LPk, LPkGen), AText);

  LM := DecodeHex(AM);
  LSig := DecodeHex(ASig);

  LBadSig := System.Copy(LSig);
  LBadSig[TEd25519.SignatureSize - 1] := Byte(LBadSig[TEd25519.SignatureSize - 1]
    xor $80);

  System.SetLength(LSigGen, TEd25519.SignatureSize);
  FEd25519.Sign(LSk, 0, LM, 0, System.Length(LM), LSigGen, 0);
  CheckTrue(AreEqual(LSig, LSigGen), AText);

  FEd25519.Sign(LSk, 0, LPk, 0, LM, 0, System.Length(LM), LSigGen, 0);
  CheckTrue(AreEqual(LSig, LSigGen), AText);

  LShouldVerify := FEd25519.Verify(LSig, 0, LPk, 0, LM, 0, System.Length(LM));
  CheckTrue(LShouldVerify, AText);

  LShouldNotVerify := FEd25519.Verify(LBadSig, 0, LPk, 0, LM, 0, System.Length(LM));
  CheckFalse(LShouldNotVerify, AText);
end;

procedure TTestEd25519.CheckEd25519ctxVector(const ASK, APK, AM, ACTX, ASig,
  AText: String);
var
  LSk, LPk, LM, LCtx, LSig, LPkGen, LBadSig, LSigGen: TBytes;
  LShouldVerify, LShouldNotVerify: Boolean;
begin
  LSk := DecodeHex(ASK);
  LPk := DecodeHex(APK);

  System.SetLength(LPkGen, TEd25519.PublicKeySize);
  FEd25519.GeneratePublicKey(LSk, 0, LPkGen, 0);
  CheckTrue(AreEqual(LPk, LPkGen), AText);

  LM := DecodeHex(AM);
  LCtx := DecodeHex(ACTX);
  LSig := DecodeHex(ASig);

  LBadSig := System.Copy(LSig);
  LBadSig[TEd25519.SignatureSize - 1] := Byte(LBadSig[TEd25519.SignatureSize - 1]
    xor $80);

  System.SetLength(LSigGen, TEd25519.SignatureSize);
  FEd25519.Sign(LSk, 0, LCtx, LM, 0, System.Length(LM), LSigGen, 0);
  CheckTrue(AreEqual(LSig, LSigGen), AText);

  FEd25519.Sign(LSk, 0, LPk, 0, LCtx, LM, 0, System.Length(LM), LSigGen, 0);
  CheckTrue(AreEqual(LSig, LSigGen), AText);

  LShouldVerify := FEd25519.Verify(LSig, 0, LPk, 0, LCtx, LM, 0, System.Length(LM));
  CheckTrue(LShouldVerify, AText);

  LShouldNotVerify := FEd25519.Verify(LBadSig, 0, LPk, 0, LCtx, LM, 0,
    System.Length(LM));
  CheckFalse(LShouldNotVerify, AText);
end;

procedure TTestEd25519.CheckEd25519phVector(const ASK, APK, AM, ACTX, ASig,
  AText: String);
var
  LSk, LPk, LM, LCtx, LPh, LSig, LPkGen, LBadSig, LSigGen: TBytes;
  LPrehash: IDigest;
  LShouldVerify, LShouldNotVerify: Boolean;
begin
  LSk := DecodeHex(ASK);
  LPk := DecodeHex(APK);

  System.SetLength(LPkGen, TEd25519.PublicKeySize);
  FEd25519.GeneratePublicKey(LSk, 0, LPkGen, 0);
  CheckTrue(AreEqual(LPk, LPkGen), AText);

  LM := DecodeHex(AM);
  LCtx := DecodeHex(ACTX);
  LSig := DecodeHex(ASig);

  LBadSig := System.Copy(LSig);
  LBadSig[TEd25519.SignatureSize - 1] := Byte(LBadSig[TEd25519.SignatureSize - 1]
    xor $80);

  System.SetLength(LSigGen, TEd25519.SignatureSize);

  LPrehash := TEd25519.CreatePreHash();
  LPrehash.BlockUpdate(LM, 0, System.Length(LM));
  System.SetLength(LPh, TEd25519.PrehashSize);
  LPrehash.DoFinal(LPh, 0);

  FEd25519.SignPreHash(LSk, 0, LCtx, LPh, 0, LSigGen, 0);
  CheckTrue(AreEqual(LSig, LSigGen), AText);

  FEd25519.SignPreHash(LSk, 0, LPk, 0, LCtx, LPh, 0, LSigGen, 0);
  CheckTrue(AreEqual(LSig, LSigGen), AText);

  LShouldVerify := FEd25519.VerifyPreHash(LSig, 0, LPk, 0, LCtx, LPh, 0);
  CheckTrue(LShouldVerify, AText);

  LShouldNotVerify := FEd25519.VerifyPreHash(LBadSig, 0, LPk, 0, LCtx, LPh, 0);
  CheckFalse(LShouldNotVerify, AText);

  LPrehash := TEd25519.CreatePreHash();
  LPrehash.BlockUpdate(LM, 0, System.Length(LM));
  FEd25519.SignPreHash(LSk, 0, LCtx, LPrehash, LSigGen, 0);
  CheckTrue(AreEqual(LSig, LSigGen), AText);

  LPrehash := TEd25519.CreatePreHash();
  LPrehash.BlockUpdate(LM, 0, System.Length(LM));
  FEd25519.SignPreHash(LSk, 0, LPk, 0, LCtx, LPrehash, LSigGen, 0);
  CheckTrue(AreEqual(LSig, LSigGen), AText);

  LPrehash := TEd25519.CreatePreHash();
  LPrehash.BlockUpdate(LM, 0, System.Length(LM));
  LShouldVerify := FEd25519.VerifyPreHash(LSig, 0, LPk, 0, LCtx, LPrehash);
  CheckTrue(LShouldVerify, AText);

  LPrehash := TEd25519.CreatePreHash();
  LPrehash.BlockUpdate(LM, 0, System.Length(LM));
  LShouldNotVerify := FEd25519.VerifyPreHash(LBadSig, 0, LPk, 0, LCtx, LPrehash);
  CheckFalse(LShouldNotVerify, AText);
end;

procedure TTestEd25519.ImplTamingVector(ANumber: Int32; AExpected: Boolean;
  const AMsgHex, APubHex, ASigHex: String);
var
  LActual: Boolean;
begin
  LActual := ImplTamingVector(AMsgHex, APubHex, ASigHex);
  CheckEquals(AExpected, LActual, Format('Failed Taming EdDSA Vector #%d', [ANumber]));
end;

function TTestEd25519.ImplTamingVector(const AMsgHex, APubHex,
  ASigHex: String): Boolean;
var
  LMsg, LPub, LSig: TBytes;
begin
  if System.Length(ASigHex) <> TEd25519.SignatureSize * 2 then
  begin
    Result := False;
    Exit;
  end;

  LMsg := DecodeHex(AMsgHex);
  LPub := DecodeHex(APubHex);
  LSig := DecodeHex(ASigHex);

  try
    Result := FEd25519.Verify(LSig, 0, LPub, 0, LMsg, 0, System.Length(LMsg));
  except
    Result := False;
  end;
end;

procedure TTestEd25519.SetUp;
begin
  inherited;
  TEd25519.Precompute();
  FRandom := TSecureRandom.Create();
  FEd25519 := TEd25519.Create();
end;

procedure TTestEd25519.TearDown;
begin
  FEd25519.Free;
  FEd25519 := nil;
  inherited;
end;

procedure TTestEd25519.TestEd25519Consistency;
var
  LSk, LPk, LPk2, LM, LSig1, LSig2: TBytes;
  LPublicPoint: TEd25519.IPublicPoint;
  I, LMLen: Int32;
  LShouldVerify, LShouldNotVerify: Boolean;
begin
  System.SetLength(LSk, TEd25519.SecretKeySize);
  System.SetLength(LPk, TEd25519.PublicKeySize);
  System.SetLength(LPk2, TEd25519.PublicKeySize);
  System.SetLength(LM, 255);
  System.SetLength(LSig1, TEd25519.SignatureSize);
  System.SetLength(LSig2, TEd25519.SignatureSize);

  FRandom.NextBytes(LM);

  for I := 0 to 9 do
  begin
    FEd25519.GeneratePrivateKey(FRandom, LSk);
    LPublicPoint := TEd25519.GeneratePublicKey(LSk, 0);
    TEd25519.EncodePublicPoint(LPublicPoint, LPk, 0);

    FEd25519.GeneratePublicKey(LSk, 0, LPk2, 0);
    CheckTrue(AreEqual(LPk, LPk2), Format('Ed25519 consistent generation #%d', [I]));

    LMLen := FRandom.NextInt32() and 255;

    FEd25519.Sign(LSk, 0, LM, 0, LMLen, LSig1, 0);
    FEd25519.Sign(LSk, 0, LPk, 0, LM, 0, LMLen, LSig2, 0);

    CheckTrue(AreEqual(LSig1, LSig2), Format('Ed25519 consistent signatures #%d', [I]));

    LShouldVerify := FEd25519.Verify(LSig1, 0, LPk, 0, LM, 0, LMLen);
    CheckTrue(LShouldVerify, Format('Ed25519 consistent sign/verify #%d', [I]));

    LShouldVerify := FEd25519.Verify(LSig1, 0, LPublicPoint, LM, 0, LMLen);
    CheckTrue(LShouldVerify, Format('Ed25519 consistent sign/verify #%d', [I]));

    LSig1[TEd25519.PublicKeySize - 1] := Byte(LSig1[TEd25519.PublicKeySize - 1]
      xor $80);

    LShouldNotVerify := FEd25519.Verify(LSig1, 0, LPk, 0, LM, 0, LMLen);
    CheckFalse(LShouldNotVerify,
      Format('Ed25519 consistent verification failure #%d', [I]));

    LShouldNotVerify := FEd25519.Verify(LSig1, 0, LPublicPoint, LM, 0, LMLen);
    CheckFalse(LShouldNotVerify,
      Format('Ed25519 consistent verification failure #%d', [I]));
  end;
end;

procedure TTestEd25519.TestEd25519ctxConsistency;
var
  LSk, LPk, LPk2, LCtx, LM, LSig1, LSig2: TBytes;
  LPublicPoint: TEd25519.IPublicPoint;
  I, LMLen: Int32;
  LShouldVerify, LShouldNotVerify: Boolean;
begin
  System.SetLength(LSk, TEd25519.SecretKeySize);
  System.SetLength(LPk, TEd25519.PublicKeySize);
  System.SetLength(LPk2, TEd25519.PublicKeySize);
  System.SetLength(LCtx, FRandom.NextInt32() and 7);
  System.SetLength(LM, 255);
  System.SetLength(LSig1, TEd25519.SignatureSize);
  System.SetLength(LSig2, TEd25519.SignatureSize);

  FRandom.NextBytes(LCtx);
  FRandom.NextBytes(LM);

  for I := 0 to 9 do
  begin
    FEd25519.GeneratePrivateKey(FRandom, LSk);
    LPublicPoint := TEd25519.GeneratePublicKey(LSk, 0);
    TEd25519.EncodePublicPoint(LPublicPoint, LPk, 0);

    FEd25519.GeneratePublicKey(LSk, 0, LPk2, 0);
    CheckTrue(AreEqual(LPk, LPk2), Format('Ed25519 consistent generation #%d', [I]));

    LMLen := FRandom.NextInt32() and 255;

    FEd25519.Sign(LSk, 0, LCtx, LM, 0, LMLen, LSig1, 0);
    FEd25519.Sign(LSk, 0, LPk, 0, LCtx, LM, 0, LMLen, LSig2, 0);

    CheckTrue(AreEqual(LSig1, LSig2),
      Format('Ed25519ctx consistent signatures #%d', [I]));

    LShouldVerify := FEd25519.Verify(LSig1, 0, LPk, 0, LCtx, LM, 0, LMLen);
    CheckTrue(LShouldVerify, Format('Ed25519ctx consistent sign/verify #%d', [I]));

    LShouldVerify := FEd25519.Verify(LSig1, 0, LPublicPoint, LCtx, LM, 0, LMLen);
    CheckTrue(LShouldVerify, Format('Ed25519ctx consistent sign/verify #%d', [I]));

    LSig1[TEd25519.PublicKeySize - 1] := Byte(LSig1[TEd25519.PublicKeySize - 1]
      xor $80);

    LShouldNotVerify := FEd25519.Verify(LSig1, 0, LPk, 0, LCtx, LM, 0, LMLen);
    CheckFalse(LShouldNotVerify,
      Format('Ed25519ctx consistent verification failure #%d', [I]));

    LShouldNotVerify := FEd25519.Verify(LSig1, 0, LPublicPoint, LCtx, LM, 0, LMLen);
    CheckFalse(LShouldNotVerify,
      Format('Ed25519ctx consistent verification failure #%d', [I]));
  end;
end;

procedure TTestEd25519.TestEd25519phConsistency;
var
  LSk, LPk, LPk2, LCtx, LM, LPh, LSig1, LSig2: TBytes;
  LPublicPoint: TEd25519.IPublicPoint;
  LPrehash: IDigest;
  I, LMLen: Int32;
  LShouldVerify, LShouldNotVerify: Boolean;
begin
  System.SetLength(LSk, TEd25519.SecretKeySize);
  System.SetLength(LPk, TEd25519.PublicKeySize);
  System.SetLength(LPk2, TEd25519.PublicKeySize);
  System.SetLength(LCtx, FRandom.NextInt32() and 7);
  System.SetLength(LM, 255);
  System.SetLength(LPh, TEd25519.PrehashSize);
  System.SetLength(LSig1, TEd25519.SignatureSize);
  System.SetLength(LSig2, TEd25519.SignatureSize);

  FRandom.NextBytes(LCtx);
  FRandom.NextBytes(LM);

  for I := 0 to 9 do
  begin
    FEd25519.GeneratePrivateKey(FRandom, LSk);
    LPublicPoint := TEd25519.GeneratePublicKey(LSk, 0);
    TEd25519.EncodePublicPoint(LPublicPoint, LPk, 0);

    FEd25519.GeneratePublicKey(LSk, 0, LPk2, 0);
    CheckTrue(AreEqual(LPk, LPk2), Format('Ed25519 consistent generation #%d', [I]));

    LMLen := FRandom.NextInt32() and 255;

    LPrehash := TEd25519.CreatePreHash();
    LPrehash.BlockUpdate(LM, 0, LMLen);
    LPrehash.DoFinal(LPh, 0);

    FEd25519.SignPreHash(LSk, 0, LCtx, LPh, 0, LSig1, 0);
    FEd25519.SignPreHash(LSk, 0, LPk, 0, LCtx, LPh, 0, LSig2, 0);

    CheckTrue(AreEqual(LSig1, LSig2),
      Format('Ed25519ph consistent signatures #%d', [I]));

    LShouldVerify := FEd25519.VerifyPreHash(LSig1, 0, LPk, 0, LCtx, LPh, 0);
    CheckTrue(LShouldVerify, Format('Ed25519ph consistent sign/verify #%d', [I]));

    LShouldVerify := FEd25519.VerifyPreHash(LSig1, 0, LPublicPoint, LCtx, LPh, 0);
    CheckTrue(LShouldVerify, Format('Ed25519ph consistent sign/verify #%d', [I]));

    LSig1[TEd25519.PublicKeySize - 1] := Byte(LSig1[TEd25519.PublicKeySize - 1]
      xor $80);

    LShouldNotVerify := FEd25519.VerifyPreHash(LSig1, 0, LPk, 0, LCtx, LPh, 0);
    CheckFalse(LShouldNotVerify,
      Format('Ed25519ph consistent verification failure #%d', [I]));

    LShouldNotVerify := FEd25519.VerifyPreHash(LSig1, 0, LPublicPoint, LCtx, LPh, 0);
    CheckFalse(LShouldNotVerify,
      Format('Ed25519ph consistent verification failure #%d', [I]));
  end;
end;

procedure TTestEd25519.TestEd25519Vector1;
begin
  CheckEd25519Vector(
    '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60',
    'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a',
    '',
    'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b',
    'Ed25519 Vector #1');
end;

procedure TTestEd25519.TestEd25519Vector2;
begin
  CheckEd25519Vector(
    '4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb',
    '3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c',
    '72',
    '92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00',
    'Ed25519 Vector #2');
end;

procedure TTestEd25519.TestEd25519Vector3;
begin
  CheckEd25519Vector(
    'c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7',
    'fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025',
    'af82',
    '6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a',
    'Ed25519 Vector #3');
end;

procedure TTestEd25519.TestEd25519Vector1023;
var
  LM: String;
begin
  LM := '08b8b2b733424243760fe426a4b54908632110a66c2f6591eabd3345e3e4eb98fa6e264bf09efe12ee50f8f54e9f77b1e355' +
        'f6c50544e23fb1433ddf73be84d879de7c0046dc4996d9e773f4bc9efe5738829adb26c81b37c93a1b270b20329d658675fc' +
        '6ea534e0810a4432826bf58c941efb65d57a338bbd2e26640f89ffbc1a858efcb8550ee3a5e1998bd177e93a7363c344fe6b' +
        '199ee5d02e82d522c4feba15452f80288a821a579116ec6dad2b3b310da903401aa62100ab5d1a36553e06203b33890cc9b8' +
        '32f79ef80560ccb9a39ce767967ed628c6ad573cb116dbefefd75499da96bd68a8a97b928a8bbc103b6621fcde2beca1231d' +
        '206be6cd9ec7aff6f6c94fcd7204ed3455c68c83f4a41da4af2b74ef5c53f1d8ac70bdcb7ed185ce81bd84359d44254d9562' +
        '9e9855a94a7c1958d1f8ada5d0532ed8a5aa3fb2d17ba70eb6248e594e1a2297acbbb39d502f1a8c6eb6f1ce22b3de1a1f40' +
        'cc24554119a831a9aad6079cad88425de6bde1a9187ebb6092cf67bf2b13fd65f27088d78b7e883c8759d2c4f5c65adb7553' +
        '878ad575f9fad878e80a0c9ba63bcbcc2732e69485bbc9c90bfbd62481d9089beccf80cfe2df16a2cf65bd92dd597b0707e0' +
        '917af48bbb75fed413d238f5555a7a569d80c3414a8d0859dc65a46128bab27af87a71314f318c782b23ebfe808b82b0ce26' +
        '401d2e22f04d83d1255dc51addd3b75a2b1ae0784504df543af8969be3ea7082ff7fc9888c144da2af58429ec96031dbcad3' +
        'dad9af0dcbaaaf268cb8fcffead94f3c7ca495e056a9b47acdb751fb73e666c6c655ade8297297d07ad1ba5e43f1bca32301' +
        '651339e22904cc8c42f58c30c04aafdb038dda0847dd988dcda6f3bfd15c4b4c4525004aa06eeff8ca61783aacec57fb3d1f' +
        '92b0fe2fd1a85f6724517b65e614ad6808d6f6ee34dff7310fdc82aebfd904b01e1dc54b2927094b2db68d6f903b68401ade' +
        'bf5a7e08d78ff4ef5d63653a65040cf9bfd4aca7984a74d37145986780fc0b16ac451649de6188a7dbdf191f64b5fc5e2ab4' +
        '7b57f7f7276cd419c17a3ca8e1b939ae49e488acba6b965610b5480109c8b17b80e1b7b750dfc7598d5d5011fd2dcc5600a3' +
        '2ef5b52a1ecc820e308aa342721aac0943bf6686b64b2579376504ccc493d97e6aed3fb0f9cd71a43dd497f01f17c0e2cb37' +
        '97aa2a2f256656168e6c496afc5fb93246f6b1116398a346f1a641f3b041e989f7914f90cc2c7fff357876e506b50d334ba7' +
        '7c225bc307ba537152f3f1610e4eafe595f6d9d90d11faa933a15ef1369546868a7f3a45a96768d40fd9d03412c091c6315c' +
        'f4fde7cb68606937380db2eaaa707b4c4185c32eddcdd306705e4dc1ffc872eeee475a64dfac86aba41c0618983f8741c5ef' +
        '68d3a101e8a3b8cac60c905c15fc910840b94c00a0b9d0';

  CheckEd25519Vector(
    'f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5',
    '278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e',
    LM,
    '0aab4c900501b3e24d7cdf4663326a3a87df5e4843b2cbdb67cbf6e460fec350aa5371b1508f9f4528ecea23c436d94b5e8fcd4f681e30a6ac00a9704a188a03',
    'Ed25519 Vector #1023');
end;

procedure TTestEd25519.TestEd25519VectorSHAabc;
begin
  CheckEd25519Vector(
    '833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42',
    'ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf',
    'ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f',
    'dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b58909351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704',
    'Ed25519 Vector SHA(abc)');
end;

procedure TTestEd25519.TestEd25519ctxVector1;
begin
  CheckEd25519ctxVector(
    '0305334e381af78f141cb666f6199f57bc3495335a256a95bd2a55bf546663f6',
    'dfc9425e4f968f7f0c29f0259cf5f9aed6851c2bb4ad8bfb860cfee0ab248292',
    'f726936d19c800494e3fdaff20b276a8',
    '666f6f',
    '55a4cc2f70a54e04288c5f4cd1e45a7bb520b36292911876cada7323198dd87a8b36950b95130022907a7fb7c4e9b2d5f6cca685a587b4b21f4b888e4e7edb0d',
    'Ed25519ctx Vector #1');
end;

procedure TTestEd25519.TestEd25519ctxVector2;
begin
  CheckEd25519ctxVector(
    '0305334e381af78f141cb666f6199f57bc3495335a256a95bd2a55bf546663f6',
    'dfc9425e4f968f7f0c29f0259cf5f9aed6851c2bb4ad8bfb860cfee0ab248292',
    'f726936d19c800494e3fdaff20b276a8',
    '626172',
    'fc60d5872fc46b3aa69f8b5b4351d5808f92bcc044606db097abab6dbcb1aee3216c48e8b3b66431b5b186d1d28f8ee15a5ca2df6668346291c2043d4eb3e90d',
    'Ed25519ctx Vector #2');
end;

procedure TTestEd25519.TestEd25519ctxVector3;
begin
  CheckEd25519ctxVector(
    '0305334e381af78f141cb666f6199f57bc3495335a256a95bd2a55bf546663f6',
    'dfc9425e4f968f7f0c29f0259cf5f9aed6851c2bb4ad8bfb860cfee0ab248292',
    '508e9e6882b979fea900f62adceaca35',
    '666f6f',
    '8b70c1cc8310e1de20ac53ce28ae6e7207f33c3295e03bb5c0732a1d20dc64908922a8b052cf99b7c4fe107a5abb5b2c4085ae75890d02df26269d8945f84b0b',
    'Ed25519ctx Vector #3');
end;

procedure TTestEd25519.TestEd25519ctxVector4;
begin
  CheckEd25519ctxVector(
    'ab9c2853ce297ddab85c993b3ae14bcad39b2c682beabc27d6d4eb20711d6560',
    '0f1d1274943b91415889152e893d80e93275a1fc0b65fd71b4b0dda10ad7d772',
    'f726936d19c800494e3fdaff20b276a8',
    '666f6f',
    '21655b5f1aa965996b3f97b3c849eafba922a0a62992f73b3d1b73106a84ad85e9b86a7b6005ea868337ff2d20a7f5fbd4cd10b0be49a68da2b2e0dc0ad8960f',
    'Ed25519ctx Vector #4');
end;

procedure TTestEd25519.TestEd25519phVector1;
begin
  CheckEd25519phVector(
    '833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42',
    'ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf',
    '616263',
    '',
    '98a70222f0b8121aa9d30f813d683f809e462b469c7ff87639499bb94e6dae4131f85042463c2a355a2003d062adf5aaa10b8c61e636062aaad11c2a26083406',
    'Ed25519ph Vector #1');
end;

procedure TTestEd25519.TestPublicKeyValidationFull;
var
  LSk, LPk: TBytes;
  I: Int32;
begin
  System.SetLength(LSk, TEd25519.SecretKeySize);
  System.SetLength(LPk, TEd25519.PublicKeySize);

  for I := 0 to 9 do
  begin
    FEd25519.GeneratePrivateKey(FRandom, LSk);
    FEd25519.GeneratePublicKey(LSk, 0, LPk, 0);
    CheckTrue(TEd25519.ValidatePublicKeyFull(LPk, 0));
  end;

  // Small order points (canonical encodings)
  CheckFalse(TEd25519.ValidatePublicKeyFull(DecodeHex('0000000000000000000000000000000000000000000000000000000000000000'), 0));
  CheckFalse(TEd25519.ValidatePublicKeyFull(DecodeHex('0000000000000000000000000000000000000000000000000000000000000080'), 0));
  CheckFalse(TEd25519.ValidatePublicKeyFull(DecodeHex('0100000000000000000000000000000000000000000000000000000000000000'), 0));
  CheckFalse(TEd25519.ValidatePublicKeyFull(DecodeHex('ECFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7F'), 0));
  CheckFalse(TEd25519.ValidatePublicKeyFull(DecodeHex('C7176A703D4DD84FBA3C0B760D10670F2A2053FA2C39CCC64EC7FD7792AC037A'), 0));
  CheckFalse(TEd25519.ValidatePublicKeyFull(DecodeHex('C7176A703D4DD84FBA3C0B760D10670F2A2053FA2C39CCC64EC7FD7792AC03FA'), 0));
  CheckFalse(TEd25519.ValidatePublicKeyFull(DecodeHex('26E8958FC2B227B045C3F489F2EF98F0D5DFAC05D3C63339B13802886D53FC05'), 0));
  CheckFalse(TEd25519.ValidatePublicKeyFull(DecodeHex('26E8958FC2B227B045C3F489F2EF98F0D5DFAC05D3C63339B13802886D53FC85'), 0));

  // Small order points (non-canonical encodings)
  CheckFalse(TEd25519.ValidatePublicKeyFull(DecodeHex('0100000000000000000000000000000000000000000000000000000000000080'), 0));
  CheckFalse(TEd25519.ValidatePublicKeyFull(DecodeHex('ECFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF'), 0));

  // Non-canonical encodings
  CheckFalse(TEd25519.ValidatePublicKeyFull(DecodeHex('EDFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7F'), 0));
  CheckFalse(TEd25519.ValidatePublicKeyFull(DecodeHex('EDFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF'), 0));
  CheckFalse(TEd25519.ValidatePublicKeyFull(DecodeHex('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7F'), 0));
  CheckFalse(TEd25519.ValidatePublicKeyFull(DecodeHex('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF'), 0));

  CheckFalse(TEd25519.ValidatePublicKeyFull(DecodeHex('D73D6044821BD0DF4068AE1792F0851170F53062150AA70A87E2A58A05A26115'), 0));
  CheckFalse(TEd25519.ValidatePublicKeyFull(DecodeHex('F9D557BE0F3C700571CD8AD9CFDE0A2C67F88EE71830073C7756A0599311AD94'), 0));
  CheckFalse(TEd25519.ValidatePublicKeyFull(DecodeHex('7A772BBC08D53BF381B150D8411B9AF134BBF24B90A038EFD8DA4A17B32606A1'), 0));
  CheckFalse(TEd25519.ValidatePublicKeyFull(DecodeHex('DC6EF81316C08B91209A73FE8E208DD319F56C6A47956A03AF7D6D826A88AC87'), 0));
  CheckFalse(TEd25519.ValidatePublicKeyFull(DecodeHex('6EEDF105177868C9AD48DAF2C36EE3B169D892A02A3BF83101B1D50D86BFB19E'), 0));
  CheckFalse(TEd25519.ValidatePublicKeyFull(DecodeHex('4BAAB5711F22FF7479E6D9BD2C5BC4DCD3CFC9F36921971496907B1F2B62C6BA'), 0));
  CheckFalse(TEd25519.ValidatePublicKeyFull(DecodeHex('D96A46432581A80085F978F7FC0977E228C5A3FD2E64D588BB5F5E5A84E4ABAE'), 0));
  CheckFalse(TEd25519.ValidatePublicKeyFull(DecodeHex('10C326AE15FA5BA89EDDAB89C860797385298F4C7750BAEB94A5AAC9A876B538'), 0));
  CheckFalse(TEd25519.ValidatePublicKeyFull(DecodeHex('7808F3F6EB858E9BBD2570F20A9F7502175F312FA2DBE4C96EB5C683B384AA60'), 0));
  CheckFalse(TEd25519.ValidatePublicKeyFull(DecodeHex('0DE943C51E91AA3ED9FFA82D39A9813D94F59246452F6A7780D067BC61342FE1'), 0));

  CheckFalse(TEd25519.ValidatePublicKeyFull(DecodeHex('10026DBFB4C55628716BB0EF979A10DD5AC7AA970C229B5E68DD993E2C20E7D5'), 0));
  CheckFalse(TEd25519.ValidatePublicKeyFull(DecodeHex('68EC52D16C1DB4483AA8679277C34E0DC56EB7D064D302B9749F0D31A901D484'), 0));
  CheckFalse(TEd25519.ValidatePublicKeyFull(DecodeHex('6E54C8F00669422D5697E09C0575AE1E699841ACF1690A5DFAA25E3160F3A2EF'), 0));
  CheckFalse(TEd25519.ValidatePublicKeyFull(DecodeHex('CA66B62D361F790AA9658161BA0FFDC3CE60624151258C7301926DFE0C67EE64'), 0));
  CheckFalse(TEd25519.ValidatePublicKeyFull(DecodeHex('88D912C322AE3D0907B38ED08727FBF06D51C5D1DE622B5BC24DAB30078AE9FF'), 0));
  CheckFalse(TEd25519.ValidatePublicKeyFull(DecodeHex('F24683E044CE3F14BCA24F1356AE7767509E17EFA2606438BA275860819E14B8'), 0));
  CheckFalse(TEd25519.ValidatePublicKeyFull(DecodeHex('B2865F02E6D19A94CE6147B574095733B3628A2FBE2C84022262D88F7D6C4F7D'), 0));
  CheckFalse(TEd25519.ValidatePublicKeyFull(DecodeHex('FA4DA03321816C1C9066BD250982DDD1B4349C43C5E124D2B39F8DDA4E5364F8'), 0));
  CheckFalse(TEd25519.ValidatePublicKeyFull(DecodeHex('FCADF40DE51A943F3B7847DBEBA0627B33D020D81DFFABF2B3701BD9B746952A'), 0));
  CheckFalse(TEd25519.ValidatePublicKeyFull(DecodeHex('379B071E6F7E2479D5A8588AB708137808D63F689127D4A228E2C1681873C55E'), 0));
end;

procedure TTestEd25519.TestPublicKeyValidationPartial;
var
  LSk, LPk: TBytes;
  I: Int32;
begin
  System.SetLength(LSk, TEd25519.SecretKeySize);
  System.SetLength(LPk, TEd25519.PublicKeySize);

  for I := 0 to 9 do
  begin
    FEd25519.GeneratePrivateKey(FRandom, LSk);
    FEd25519.GeneratePublicKey(LSk, 0, LPk, 0);
    CheckTrue(TEd25519.ValidatePublicKeyPartial(LPk, 0));
  end;

  CheckFalse(TEd25519.ValidatePublicKeyPartial(DecodeHex(
    '0000000000000000000000000000000000000000000000000000000000000000'), 0));
  CheckFalse(TEd25519.ValidatePublicKeyPartial(DecodeHex(
    '0000000000000000000000000000000000000000000000000000000000000080'), 0));
  CheckFalse(TEd25519.ValidatePublicKeyPartial(DecodeHex(
    '0100000000000000000000000000000000000000000000000000000000000000'), 0));
  CheckFalse(TEd25519.ValidatePublicKeyPartial(DecodeHex(
    'ECFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7F'), 0));
  CheckFalse(TEd25519.ValidatePublicKeyPartial(DecodeHex(
    'C7176A703D4DD84FBA3C0B760D10670F2A2053FA2C39CCC64EC7FD7792AC037A'), 0));
  CheckFalse(TEd25519.ValidatePublicKeyPartial(DecodeHex(
    'C7176A703D4DD84FBA3C0B760D10670F2A2053FA2C39CCC64EC7FD7792AC03FA'), 0));
  CheckFalse(TEd25519.ValidatePublicKeyPartial(DecodeHex(
    '26E8958FC2B227B045C3F489F2EF98F0D5DFAC05D3C63339B13802886D53FC05'), 0));
  CheckFalse(TEd25519.ValidatePublicKeyPartial(DecodeHex(
    '26E8958FC2B227B045C3F489F2EF98F0D5DFAC05D3C63339B13802886D53FC85'), 0));

  CheckFalse(TEd25519.ValidatePublicKeyPartial(DecodeHex(
    '0100000000000000000000000000000000000000000000000000000000000080'), 0));
  CheckFalse(TEd25519.ValidatePublicKeyPartial(DecodeHex(
    'ECFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF'), 0));

  CheckFalse(TEd25519.ValidatePublicKeyPartial(DecodeHex(
    'EDFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7F'), 0));
  CheckFalse(TEd25519.ValidatePublicKeyPartial(DecodeHex(
    'EDFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF'), 0));
  CheckFalse(TEd25519.ValidatePublicKeyPartial(DecodeHex(
    'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7F'), 0));
  CheckFalse(TEd25519.ValidatePublicKeyPartial(DecodeHex(
    'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF'), 0));

  CheckFalse(TEd25519.ValidatePublicKeyPartial(DecodeHex(
    'D73D6044821BD0DF4068AE1792F0851170F53062150AA70A87E2A58A05A26115'), 0));
  CheckFalse(TEd25519.ValidatePublicKeyPartial(DecodeHex(
    'F9D557BE0F3C700571CD8AD9CFDE0A2C67F88EE71830073C7756A0599311AD94'), 0));
  CheckFalse(TEd25519.ValidatePublicKeyPartial(DecodeHex(
    '7A772BBC08D53BF381B150D8411B9AF134BBF24B90A038EFD8DA4A17B32606A1'), 0));
  CheckFalse(TEd25519.ValidatePublicKeyPartial(DecodeHex(
    'DC6EF81316C08B91209A73FE8E208DD319F56C6A47956A03AF7D6D826A88AC87'), 0));
  CheckFalse(TEd25519.ValidatePublicKeyPartial(DecodeHex(
    '6EEDF105177868C9AD48DAF2C36EE3B169D892A02A3BF83101B1D50D86BFB19E'), 0));
  CheckFalse(TEd25519.ValidatePublicKeyPartial(DecodeHex(
    '4BAAB5711F22FF7479E6D9BD2C5BC4DCD3CFC9F36921971496907B1F2B62C6BA'), 0));
  CheckFalse(TEd25519.ValidatePublicKeyPartial(DecodeHex(
    'D96A46432581A80085F978F7FC0977E228C5A3FD2E64D588BB5F5E5A84E4ABAE'), 0));
  CheckFalse(TEd25519.ValidatePublicKeyPartial(DecodeHex(
    '10C326AE15FA5BA89EDDAB89C860797385298F4C7750BAEB94A5AAC9A876B538'), 0));
  CheckFalse(TEd25519.ValidatePublicKeyPartial(DecodeHex(
    '7808F3F6EB858E9BBD2570F20A9F7502175F312FA2DBE4C96EB5C683B384AA60'), 0));
  CheckFalse(TEd25519.ValidatePublicKeyPartial(DecodeHex(
    '0DE943C51E91AA3ED9FFA82D39A9813D94F59246452F6A7780D067BC61342FE1'), 0));

  CheckTrue(TEd25519.ValidatePublicKeyPartial(DecodeHex(
    '10026DBFB4C55628716BB0EF979A10DD5AC7AA970C229B5E68DD993E2C20E7D5'), 0));
  CheckTrue(TEd25519.ValidatePublicKeyPartial(DecodeHex(
    '68EC52D16C1DB4483AA8679277C34E0DC56EB7D064D302B9749F0D31A901D484'), 0));
  CheckTrue(TEd25519.ValidatePublicKeyPartial(DecodeHex(
    '6E54C8F00669422D5697E09C0575AE1E699841ACF1690A5DFAA25E3160F3A2EF'), 0));
  CheckTrue(TEd25519.ValidatePublicKeyPartial(DecodeHex(
    'CA66B62D361F790AA9658161BA0FFDC3CE60624151258C7301926DFE0C67EE64'), 0));
  CheckTrue(TEd25519.ValidatePublicKeyPartial(DecodeHex(
    '88D912C322AE3D0907B38ED08727FBF06D51C5D1DE622B5BC24DAB30078AE9FF'), 0));
  CheckTrue(TEd25519.ValidatePublicKeyPartial(DecodeHex(
    'F24683E044CE3F14BCA24F1356AE7767509E17EFA2606438BA275860819E14B8'), 0));
  CheckTrue(TEd25519.ValidatePublicKeyPartial(DecodeHex(
    'B2865F02E6D19A94CE6147B574095733B3628A2FBE2C84022262D88F7D6C4F7D'), 0));
  CheckTrue(TEd25519.ValidatePublicKeyPartial(DecodeHex(
    'FA4DA03321816C1C9066BD250982DDD1B4349C43C5E124D2B39F8DDA4E5364F8'), 0));
  CheckTrue(TEd25519.ValidatePublicKeyPartial(DecodeHex(
    'FCADF40DE51A943F3B7847DBEBA0627B33D020D81DFFABF2B3701BD9B746952A'), 0));
  CheckTrue(TEd25519.ValidatePublicKeyPartial(DecodeHex(
    '379B071E6F7E2479D5A8588AB708137808D63F689127D4A228E2C1681873C55E'), 0));
end;

procedure TTestEd25519.TamingNonRepudiation;
var
  LMsg1, LMsg2, LPub, LSig: TBytes;
begin
  LMsg1 := TConverters.ConvertStringToBytes('Send 100 USD to Alice',
    TEncoding.UTF8);
  LMsg2 := TConverters.ConvertStringToBytes('Send 100000 USD to Alice',
    TEncoding.UTF8);
  LPub := DecodeHex(
    'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f');
  LSig := DecodeHex(
    'a9d55260f765261eb9b84e106f665e00b867287a761990d7135963ee0a7d59dc' +
    'a5bb704786be79fc476f91d3f3f89b03984d8068dcf1bb7dfc6637b45450ac04');

  CheckFalse(FEd25519.Verify(LSig, 0, LPub, 0, LMsg1, 0, System.Length(LMsg1)));
  CheckFalse(FEd25519.Verify(LSig, 0, LPub, 0, LMsg2, 0, System.Length(LMsg2)));
end;

procedure TTestEd25519.TamingVector_00;
begin
  ImplTamingVector(0, False,
    '8c93255d71dcab10e8f379c26200f3c7bd5f09d9bc3068d3ef4edeb4853022b6',
    'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa',
    'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a' +
    '0000000000000000000000000000000000000000000000000000000000000000');
end;

procedure TTestEd25519.TamingVector_01;
begin
  ImplTamingVector(1, False,
    '9bd9f44f4dcc75bd531b56b2cd280b0bb38fc1cd6d1230e14861d861de092e79',
    'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa',
    'f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43' +
    'a5bb704786be79fc476f91d3f3f89b03984d8068dcf1bb7dfc6637b45450ac04');
end;

procedure TTestEd25519.TamingVector_02;
begin
  ImplTamingVector(2, True,
    'aebf3f2601a0c8c5d39cc7d8911642f740b78168218da8471772b35f9d35b9ab',
    'f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43',
    'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa' +
    '8c4bd45aecaca5b24fb97bc10ac27ac8751a7dfe1baff8b953ec9f5833ca260e');
end;

procedure TTestEd25519.TamingVector_03;
begin
  ImplTamingVector(3, True,
    '9bd9f44f4dcc75bd531b56b2cd280b0bb38fc1cd6d1230e14861d861de092e79',
    'cdb267ce40c5cd45306fa5d2f29731459387dbf9eb933b7bd5aed9a765b88d4d',
    '9046a64750444938de19f227bb80485e92b83fdb4b6506c160484c016cc1852f' +
    '87909e14428a7a1d62e9f22f3d3ad7802db02eb2e688b6c52fcd6648a98bd009');
end;

procedure TTestEd25519.TamingVector_04;
begin
  ImplTamingVector(4, True,
    'e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec4011eaccd55b53f56c',
    'cdb267ce40c5cd45306fa5d2f29731459387dbf9eb933b7bd5aed9a765b88d4d',
    '160a1cb0dc9c0258cd0a7d23e94d8fa878bcb1925f2c64246b2dee1796bed512' +
    '5ec6bc982a269b723e0668e540911a9a6a58921d6925e434ab10aa7940551a09');
end;

procedure TTestEd25519.TamingVector_05;
begin
  ImplTamingVector(5, True,
    'e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec4011eaccd55b53f56c',
    'cdb267ce40c5cd45306fa5d2f29731459387dbf9eb933b7bd5aed9a765b88d4d',
    '21122a84e0b5fca4052f5b1235c80a537878b38f3142356b2c2384ebad4668b7' +
    'e40bc836dac0f71076f9abe3a53f9c03c1ceeeddb658d0030494ace586687405');
end;

procedure TTestEd25519.TamingVector_06;
begin
  ImplTamingVector(6, False,
    '85e241a07d148b41e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec40',
    '442aad9f089ad9e14647b1ef9099a1ff4798d78589e66f28eca69c11f582a623',
    'e96f66be976d82e60150baecff9906684aebb1ef181f67a7189ac78ea23b6c0e' +
    '547f7690a0e2ddcd04d87dbc3490dc19b3b3052f7ff0538cb68afb369ba3a514');
end;

procedure TTestEd25519.TamingVector_07;
begin
  ImplTamingVector(7, False,
    '85e241a07d148b41e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec40',
    '442aad9f089ad9e14647b1ef9099a1ff4798d78589e66f28eca69c11f582a623',
    '8ce5b96c8f26d0ab6c47958c9e68b937104cd36e13c33566acd2fe8d38aa1942' +
    '7e71f98a4734e74f2f13f06f97c20d58cc3f54b8bd0d272f42b695dd7e89a8c22');
end;

procedure TTestEd25519.TamingVector_08;
begin
  ImplTamingVector(8, False,
    '9bedc267423725d473888631ebf45988bad3db83851ee85c85e241a07d148b41',
    'f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43',
    'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff' +
    '03be9678ac102edcd92b0210bb34d7428d12ffc5df5f37e359941266a4e35f0f');
end;

procedure TTestEd25519.TamingVector_09;
begin
  ImplTamingVector(9, False,
    '9bedc267423725d473888631ebf45988bad3db83851ee85c85e241a07d148b41',
    'f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43',
    'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff' +
    'ca8c5b64cd208982aa38d4936621a4775aa233aa0505711d8fdcfdaa943d4908');
end;

procedure TTestEd25519.TamingVector_10;
begin
  ImplTamingVector(10, False,
    'e96b7021eb39c1a163b6da4e3093dcd3f21387da4cc4572be588fafae23c155b',
    'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
    'a9d55260f765261eb9b84e106f665e00b867287a761990d7135963ee0a7d59dc' +
    'a5bb704786be79fc476f91d3f3f89b03984d8068dcf1bb7dfc6637b45450ac04');
end;

procedure TTestEd25519.TamingVector_11;
begin
  ImplTamingVector(11, False,
    '39a591f5321bbe07fd5a23dc2f39d025d74526615746727ceefd6e82ae65c06f',
    'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
    'a9d55260f765261eb9b84e106f665e00b867287a761990d7135963ee0a7d59dc' +
    'a5bb704786be79fc476f91d3f3f89b03984d8068dcf1bb7dfc6637b45450ac04');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestEd25519);
{$ELSE}
  RegisterTest(TTestEd25519.Suite);
{$ENDIF FPC}

end.
