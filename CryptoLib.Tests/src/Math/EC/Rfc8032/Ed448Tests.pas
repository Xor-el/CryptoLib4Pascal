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

unit Ed448Tests;

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
  ClpIXof,
  ClpDigestUtilities,
  ClpEd448,
  ClpSecureRandom,
  ClpISecureRandom,
  CryptoLibTestBase;

type

  TTestEd448 = class(TCryptoLibAlgorithmTestCase)
  private
  var
    FRandom: ISecureRandom;
    FEd448: TEd448;
    FEd448Xof: TEd448;

    procedure CheckEd448Vector(const ASK, APK, AM, ACTX, ASig, AText: String);
    procedure CheckEd448phVector(const ASK, APK, AM, ACTX, ASig, AText: String);
  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestEd448Consistency();
    procedure TestEd448ConsistencyDefaultMatchesXof();
    procedure TestEd448phConsistency();
    procedure TestEd448Vector1();
    procedure TestEd448Vector2();
    procedure TestEd448Vector3();
    procedure TestEd448Vector4();
    procedure TestEd448Vector5();
    procedure TestEd448Vector6();
    procedure TestEd448Vector64();
    procedure TestEd448Vector256();
    procedure TestEd448Vector1023();
    procedure TestEd448phVector1();
    procedure TestEd448phVector2();
    procedure TestPublicKeyValidationFull();
    procedure TestPublicKeyValidationPartial();
  end;

implementation

type
  TEd448Shake256 = class(TEd448)
  strict protected
    function CreateXof(): IXof; override;
  end;

function TEd448Shake256.CreateXof(): IXof;
begin
  Result := TDigestUtilities.GetDigest('SHAKE256-512') as IXof;
end;

{ TTestEd448 }

procedure TTestEd448.CheckEd448Vector(const ASK, APK, AM, ACTX, ASig, AText: String);
var
  LSk, LPk, LM, LCtx, LSig, LPkGen, LBadSig, LSigGen: TBytes;
  LShouldVerify, LShouldNotVerify: Boolean;
begin
  LSk := DecodeHex(ASK);
  LPk := DecodeHex(APK);

  System.SetLength(LPkGen, TEd448.PublicKeySize);
  FEd448.GeneratePublicKey(LSk, 0, LPkGen, 0);
  CheckTrue(AreEqual(LPk, LPkGen), AText);

  LM := DecodeHex(AM);
  LCtx := DecodeHex(ACTX);
  LSig := DecodeHex(ASig);

  LBadSig := System.Copy(LSig);
  LBadSig[TEd448.SignatureSize - 1] := Byte(LBadSig[TEd448.SignatureSize - 1] xor $80);

  System.SetLength(LSigGen, TEd448.SignatureSize);
  FEd448.Sign(LSk, 0, LCtx, LM, 0, System.Length(LM), LSigGen, 0);
  CheckTrue(AreEqual(LSig, LSigGen), AText);

  FEd448.Sign(LSk, 0, LPk, 0, LCtx, LM, 0, System.Length(LM), LSigGen, 0);
  CheckTrue(AreEqual(LSig, LSigGen), AText);

  LShouldVerify := FEd448.Verify(LSig, 0, LPk, 0, LCtx, LM, 0, System.Length(LM));
  CheckTrue(LShouldVerify, AText);

  LShouldNotVerify := FEd448.Verify(LBadSig, 0, LPk, 0, LCtx, LM, 0, System.Length(LM));
  CheckFalse(LShouldNotVerify, AText);
end;

procedure TTestEd448.CheckEd448phVector(const ASK, APK, AM, ACTX, ASig, AText: String);
var
  LSk, LPk, LM, LCtx, LPh, LSig, LPkGen, LBadSig, LSigGen: TBytes;
  LPrehash: IXof;
  LShouldVerify, LShouldNotVerify: Boolean;
begin
  LSk := DecodeHex(ASK);
  LPk := DecodeHex(APK);

  System.SetLength(LPkGen, TEd448.PublicKeySize);
  FEd448.GeneratePublicKey(LSk, 0, LPkGen, 0);
  CheckTrue(AreEqual(LPk, LPkGen), AText);

  LM := DecodeHex(AM);
  LCtx := DecodeHex(ACTX);
  LSig := DecodeHex(ASig);

  LBadSig := System.Copy(LSig);
  LBadSig[TEd448.SignatureSize - 1] := Byte(LBadSig[TEd448.SignatureSize - 1] xor $80);

  System.SetLength(LSigGen, TEd448.SignatureSize);

  LPrehash := FEd448.CreatePrehash();
  LPrehash.BlockUpdate(LM, 0, System.Length(LM));
  System.SetLength(LPh, TEd448.PrehashSize);
  LPrehash.OutputFinal(LPh, 0, System.Length(LPh));

  FEd448.SignPrehash(LSk, 0, LCtx, LPh, 0, LSigGen, 0);
  CheckTrue(AreEqual(LSig, LSigGen), AText);

  FEd448.SignPrehash(LSk, 0, LPk, 0, LCtx, LPh, 0, LSigGen, 0);
  CheckTrue(AreEqual(LSig, LSigGen), AText);

  LShouldVerify := FEd448.VerifyPrehash(LSig, 0, LPk, 0, LCtx, LPh, 0);
  CheckTrue(LShouldVerify, AText);

  LShouldNotVerify := FEd448.VerifyPrehash(LBadSig, 0, LPk, 0, LCtx, LPh, 0);
  CheckFalse(LShouldNotVerify, AText);

  LPrehash := FEd448.CreatePrehash();
  LPrehash.BlockUpdate(LM, 0, System.Length(LM));
  FEd448.SignPrehash(LSk, 0, LCtx, LPrehash, LSigGen, 0);
  CheckTrue(AreEqual(LSig, LSigGen), AText);

  LPrehash := FEd448.CreatePrehash();
  LPrehash.BlockUpdate(LM, 0, System.Length(LM));
  FEd448.SignPrehash(LSk, 0, LPk, 0, LCtx, LPrehash, LSigGen, 0);
  CheckTrue(AreEqual(LSig, LSigGen), AText);

  LPrehash := FEd448.CreatePrehash();
  LPrehash.BlockUpdate(LM, 0, System.Length(LM));
  LShouldVerify := FEd448.VerifyPrehash(LSig, 0, LPk, 0, LCtx, LPrehash);
  CheckTrue(LShouldVerify, AText);

  LPrehash := FEd448.CreatePrehash();
  LPrehash.BlockUpdate(LM, 0, System.Length(LM));
  LShouldNotVerify := FEd448.VerifyPrehash(LBadSig, 0, LPk, 0, LCtx, LPrehash);
  CheckFalse(LShouldNotVerify, AText);
end;

procedure TTestEd448.SetUp;
begin
  inherited;
  TEd448.Precompute();
  FRandom := TSecureRandom.Create();
  FEd448 := TEd448.Create();
  FEd448Xof := TEd448Shake256.Create();
end;

procedure TTestEd448.TearDown;
begin
  FEd448Xof.Free;
  FEd448.Free;
  inherited;
end;

procedure TTestEd448.TestEd448Consistency;
var
  LSk, LPk, LPk2, LCtx, LM, LSig1, LSig2: TBytes;
  LPublicPoint: TEd448.IPublicPoint;
  I, LMLen: Int32;
  LShouldVerify, LShouldNotVerify: Boolean;
begin
  System.SetLength(LSk, TEd448.SecretKeySize);
  System.SetLength(LPk, TEd448.PublicKeySize);
  System.SetLength(LPk2, TEd448.PublicKeySize);
  System.SetLength(LCtx, FRandom.NextInt32() and 7);
  System.SetLength(LM, 255);
  System.SetLength(LSig1, TEd448.SignatureSize);
  System.SetLength(LSig2, TEd448.SignatureSize);

  FRandom.NextBytes(LCtx);
  FRandom.NextBytes(LM);

  for I := 0 to 9 do
  begin
    FEd448.GeneratePrivateKey(FRandom, LSk);
    LPublicPoint := FEd448.GeneratePublicKey(LSk, 0);
    TEd448.EncodePublicPoint(LPublicPoint, LPk, 0);

    FEd448.GeneratePublicKey(LSk, 0, LPk2, 0);
    CheckTrue(AreEqual(LPk, LPk2), Format('Ed448 consistent generation #%d', [I]));

    LMLen := FRandom.NextInt32() and 255;

    FEd448.Sign(LSk, 0, LCtx, LM, 0, LMLen, LSig1, 0);
    FEd448.Sign(LSk, 0, LPk, 0, LCtx, LM, 0, LMLen, LSig2, 0);

    CheckTrue(AreEqual(LSig1, LSig2), Format('Ed448 consistent signatures #%d', [I]));

    LShouldVerify := FEd448.Verify(LSig1, 0, LPk, 0, LCtx, LM, 0, LMLen);
    CheckTrue(LShouldVerify, Format('Ed448 consistent sign/verify #%d', [I]));

    LShouldVerify := FEd448.Verify(LSig1, 0, LPublicPoint, LCtx, LM, 0, LMLen);
    CheckTrue(LShouldVerify, Format('Ed448 consistent sign/verify #%d', [I]));

    LSig1[TEd448.PublicKeySize - 1] := Byte(LSig1[TEd448.PublicKeySize - 1] xor $80);

    LShouldNotVerify := FEd448.Verify(LSig1, 0, LPk, 0, LCtx, LM, 0, LMLen);
    CheckFalse(LShouldNotVerify, Format('Ed448 consistent verification failure #%d', [I]));

    LShouldNotVerify := FEd448.Verify(LSig1, 0, LPublicPoint, LCtx, LM, 0, LMLen);
    CheckFalse(LShouldNotVerify, Format('Ed448 consistent verification failure #%d', [I]));
  end;
end;

procedure TTestEd448.TestEd448ConsistencyDefaultMatchesXof;
var
  LSk, LPk, LPkDefault, LPkXof, LCtx, LM, LPh, LSig1, LSig2: TBytes;
  LPublicPoint: TEd448.IPublicPoint;
  I, LMLen: Int32;
  LPrehash: IXof;
begin
  System.SetLength(LSk, TEd448.SecretKeySize);
  System.SetLength(LPk, TEd448.PublicKeySize);
  System.SetLength(LPkDefault, TEd448.PublicKeySize);
  System.SetLength(LPkXof, TEd448.PublicKeySize);
  System.SetLength(LCtx, FRandom.NextInt32() and 7);
  System.SetLength(LM, 255);
  System.SetLength(LPh, TEd448.PrehashSize);
  System.SetLength(LSig1, TEd448.SignatureSize);
  System.SetLength(LSig2, TEd448.SignatureSize);

  FRandom.NextBytes(LCtx);
  FRandom.NextBytes(LM);

  for I := 0 to 9 do
  begin
    FEd448.GeneratePrivateKey(FRandom, LSk);

    FEd448.GeneratePublicKey(LSk, 0, LPkDefault, 0);
    FEd448Xof.GeneratePublicKey(LSk, 0, LPkXof, 0);
    CheckTrue(AreEqual(LPkDefault, LPkXof), Format('Default vs XOF key gen #%d', [I]));
    LPk := LPkDefault;
    LPublicPoint := FEd448.GeneratePublicKey(LSk, 0);

    LMLen := FRandom.NextInt32() and 255;

    FEd448.Sign(LSk, 0, LCtx, LM, 0, LMLen, LSig1, 0);
    FEd448Xof.Sign(LSk, 0, LCtx, LM, 0, LMLen, LSig2, 0);
    CheckTrue(AreEqual(LSig1, LSig2), Format('Default vs XOF Sign #%d', [I]));

    FEd448.Sign(LSk, 0, LPk, 0, LCtx, LM, 0, LMLen, LSig1, 0);
    FEd448Xof.Sign(LSk, 0, LPk, 0, LCtx, LM, 0, LMLen, LSig2, 0);
    CheckTrue(AreEqual(LSig1, LSig2), Format('Default vs XOF Sign with Pk #%d', [I]));

    CheckTrue(FEd448.Verify(LSig1, 0, LPk, 0, LCtx, LM, 0, LMLen), Format('Default verify own sig #%d', [I]));
    CheckTrue(FEd448Xof.Verify(LSig2, 0, LPk, 0, LCtx, LM, 0, LMLen), Format('XOF verify own sig #%d', [I]));
    CheckTrue(FEd448Xof.Verify(LSig1, 0, LPk, 0, LCtx, LM, 0, LMLen), Format('Default sig with XOF pubkey Verify #%d', [I]));
    CheckTrue(FEd448.Verify(LSig2, 0, LPk, 0, LCtx, LM, 0, LMLen), Format('XOF sig with default pubkey Verify #%d', [I]));

    CheckTrue(FEd448.Verify(LSig1, 0, LPublicPoint, LCtx, LM, 0, LMLen), Format('Default verify PublicPoint own sig #%d', [I]));
    CheckTrue(FEd448Xof.Verify(LSig2, 0, LPublicPoint, LCtx, LM, 0, LMLen), Format('XOF verify PublicPoint own sig #%d', [I]));
    CheckTrue(FEd448Xof.Verify(LSig1, 0, LPublicPoint, LCtx, LM, 0, LMLen), Format('Default sig with XOF pubkey Verify PublicPoint #%d', [I]));
    CheckTrue(FEd448.Verify(LSig2, 0, LPublicPoint, LCtx, LM, 0, LMLen), Format('XOF sig with default pubkey Verify PublicPoint #%d', [I]));

    LPrehash := FEd448.CreatePrehash();
    LPrehash.BlockUpdate(LM, 0, LMLen);
    LPrehash.OutputFinal(LPh, 0, System.Length(LPh));

    FEd448.SignPrehash(LSk, 0, LCtx, LPh, 0, LSig1, 0);
    FEd448Xof.SignPrehash(LSk, 0, LCtx, LPh, 0, LSig2, 0);
    CheckTrue(AreEqual(LSig1, LSig2), Format('Default vs XOF SignPrehash #%d', [I]));

    FEd448.SignPrehash(LSk, 0, LPk, 0, LCtx, LPh, 0, LSig1, 0);
    FEd448Xof.SignPrehash(LSk, 0, LPk, 0, LCtx, LPh, 0, LSig2, 0);
    CheckTrue(AreEqual(LSig1, LSig2), Format('Default vs XOF SignPrehash with Pk #%d', [I]));

    CheckTrue(FEd448.VerifyPrehash(LSig1, 0, LPk, 0, LCtx, LPh, 0), Format('Default VerifyPrehash own sig #%d', [I]));
    CheckTrue(FEd448Xof.VerifyPrehash(LSig2, 0, LPk, 0, LCtx, LPh, 0), Format('XOF VerifyPrehash own sig #%d', [I]));
    CheckTrue(FEd448Xof.VerifyPrehash(LSig1, 0, LPk, 0, LCtx, LPh, 0), Format('Default sig with XOF pubkey VerifyPrehash #%d', [I]));
    CheckTrue(FEd448.VerifyPrehash(LSig2, 0, LPk, 0, LCtx, LPh, 0), Format('XOF sig with default pubkey VerifyPrehash #%d', [I]));

    CheckTrue(FEd448.VerifyPrehash(LSig1, 0, LPublicPoint, LCtx, LPh, 0), Format('Default VerifyPrehash PublicPoint own sig #%d', [I]));
    CheckTrue(FEd448Xof.VerifyPrehash(LSig2, 0, LPublicPoint, LCtx, LPh, 0), Format('XOF VerifyPrehash PublicPoint own sig #%d', [I]));
    CheckTrue(FEd448Xof.VerifyPrehash(LSig1, 0, LPublicPoint, LCtx, LPh, 0), Format('Default sig with XOF pubkey VerifyPrehash PublicPoint #%d', [I]));
    CheckTrue(FEd448.VerifyPrehash(LSig2, 0, LPublicPoint, LCtx, LPh, 0), Format('XOF sig with default pubkey VerifyPrehash PublicPoint #%d', [I]));
  end;
end;

procedure TTestEd448.TestEd448phConsistency;
var
  LSk, LPk, LPk2, LCtx, LM, LPh, LSig1, LSig2: TBytes;
  LPublicPoint: TEd448.IPublicPoint;
  LPrehash: IXof;
  I, LMLen: Int32;
  LShouldVerify, LShouldNotVerify: Boolean;
begin
  System.SetLength(LSk, TEd448.SecretKeySize);
  System.SetLength(LPk, TEd448.PublicKeySize);
  System.SetLength(LPk2, TEd448.PublicKeySize);
  System.SetLength(LCtx, FRandom.NextInt32() and 7);
  System.SetLength(LM, 255);
  System.SetLength(LPh, TEd448.PrehashSize);
  System.SetLength(LSig1, TEd448.SignatureSize);
  System.SetLength(LSig2, TEd448.SignatureSize);

  FRandom.NextBytes(LCtx);
  FRandom.NextBytes(LM);

  for I := 0 to 9 do
  begin
    FEd448.GeneratePrivateKey(FRandom, LSk);
    LPublicPoint := FEd448.GeneratePublicKey(LSk, 0);
    TEd448.EncodePublicPoint(LPublicPoint, LPk, 0);

    FEd448.GeneratePublicKey(LSk, 0, LPk2, 0);
    CheckTrue(AreEqual(LPk, LPk2), Format('Ed448 consistent generation #%d', [I]));

    LMLen := FRandom.NextInt32() and 255;

    LPrehash := FEd448.CreatePrehash();
    LPrehash.BlockUpdate(LM, 0, LMLen);
    LPrehash.OutputFinal(LPh, 0, System.Length(LPh));

    FEd448.SignPrehash(LSk, 0, LCtx, LPh, 0, LSig1, 0);
    FEd448.SignPrehash(LSk, 0, LPk, 0, LCtx, LPh, 0, LSig2, 0);

    CheckTrue(AreEqual(LSig1, LSig2), Format('Ed448ph consistent signatures #%d', [I]));

    LShouldVerify := FEd448.VerifyPrehash(LSig1, 0, LPk, 0, LCtx, LPh, 0);
    CheckTrue(LShouldVerify, Format('Ed448ph consistent sign/verify #%d', [I]));

    LShouldVerify := FEd448.VerifyPrehash(LSig1, 0, LPublicPoint, LCtx, LPh, 0);
    CheckTrue(LShouldVerify, Format('Ed448ph consistent sign/verify #%d', [I]));

    LSig1[TEd448.PublicKeySize - 1] := Byte(LSig1[TEd448.PublicKeySize - 1] xor $80);

    LShouldNotVerify := FEd448.VerifyPrehash(LSig1, 0, LPk, 0, LCtx, LPh, 0);
    CheckFalse(LShouldNotVerify, Format('Ed448ph consistent verification failure #%d', [I]));

    LShouldNotVerify := FEd448.VerifyPrehash(LSig1, 0, LPublicPoint, LCtx, LPh, 0);
    CheckFalse(LShouldNotVerify, Format('Ed448ph consistent verification failure #%d', [I]));
  end;
end;

procedure TTestEd448.TestEd448Vector1;
begin
  CheckEd448Vector(
    '6c82a562cb808d10d632be89c8513ebf6c929f34ddfa8c9f63c9960ef6e348a3528c8a3fcc2f044e39a3fc5b94492f8f032e7549a20098f95b',
    '5fd7449b59b461fd2ce787ec616ad46a1da1342485a70e1f8a0ea75d80e96778edf124769b46c7061bd6783df1e50f6cd1fa1abeafe8256180',
    '',
    '',
    '533a37f6bbe457251f023c0d88f976ae2dfb504a843e34d2074fd823d41a591f2b233f034f628281f2fd7a22ddd47d7828c59bd0a21bfd3980ff0d2028d4b18a9df63e006c5d1c2d345b925d8dc00b4104852db99ac5c7cdda8530a113a0f4dbb61149f05a7363268c71d95808ff2e652600',
    'Ed448 Vector #1');
end;

procedure TTestEd448.TestEd448Vector2;
begin
  CheckEd448Vector(
    'c4eab05d357007c632f3dbb48489924d552b08fe0c353a0d4a1f00acda2c463afbea67c5e8d2877c5e3bc397a659949ef8021e954e0a12274e',
    '43ba28f430cdff456ae531545f7ecd0ac834a55d9358c0372bfa0c6c6798c0866aea01eb00742802b8438ea4cb82169c235160627b4c3a9480',
    '03',
    '',
    '26b8f91727bd62897af15e41eb43c377efb9c610d48f2335cb0bd0087810f4352541b143c4b981b7e18f62de8ccdf633fc1bf037ab7cd779805e0dbcc0aae1cbcee1afb2e027df36bc04dcecbf154336c19f0af7e0a6472905e799f1953d2a0ff3348ab21aa4adafd1d234441cf807c03a00',
    'Ed448 Vector #2');
end;

procedure TTestEd448.TestEd448Vector3;
begin
  CheckEd448Vector(
    'c4eab05d357007c632f3dbb48489924d552b08fe0c353a0d4a1f00acda2c463afbea67c5e8d2877c5e3bc397a659949ef8021e954e0a12274e',
    '43ba28f430cdff456ae531545f7ecd0ac834a55d9358c0372bfa0c6c6798c0866aea01eb00742802b8438ea4cb82169c235160627b4c3a9480',
    '03',
    '666f6f',
    'd4f8f6131770dd46f40867d6fd5d5055de43541f8c5e35abbcd001b32a89f7d2151f7647f11d8ca2ae279fb842d607217fce6e042f6815ea000c85741de5c8da1144a6a1aba7f96de42505d7a7298524fda538fccbbb754f578c1cad10d54d0d5428407e85dcbc98a49155c13764e66c3c00',
    'Ed448 Vector #3');
end;

procedure TTestEd448.TestEd448Vector4;
begin
  CheckEd448Vector(
    'cd23d24f714274e744343237b93290f511f6425f98e64459ff203e8985083ffdf60500553abc0e05cd02184bdb89c4ccd67e187951267eb328',
    'dcea9e78f35a1bf3499a831b10b86c90aac01cd84b67a0109b55a36e9328b1e365fce161d71ce7131a543ea4cb5f7e9f1d8b00696447001400',
    '0c3e544074ec63b0265e0c',
    '',
    '1f0a8888ce25e8d458a21130879b840a9089d999aaba039eaf3e3afa090a09d389dba82c4ff2ae8ac5cdfb7c55e94d5d961a29fe0109941e00b8dbdeea6d3b051068df7254c0cdc129cbe62db2dc957dbb47b51fd3f213fb8698f064774250a5028961c9bf8ffd973fe5d5c206492b140e00',
    'Ed448 Vector #4');
end;

procedure TTestEd448.TestEd448Vector5;
begin
  CheckEd448Vector(
    '258cdd4ada32ed9c9ff54e63756ae582fb8fab2ac721f2c8e676a72768513d939f63dddb55609133f29adf86ec9929dccb52c1c5fd2ff7e21b',
    '3ba16da0c6f2cc1f30187740756f5e798d6bc5fc015d7c63cc9510ee3fd44adc24d8e968b6e46e6f94d19b945361726bd75e149ef09817f580',
    '64a65f3cdedcdd66811e2915',
    '',
    '7eeeab7c4e50fb799b418ee5e3197ff6bf15d43a14c34389b59dd1a7b1b85b4ae90438aca634bea45e3a2695f1270f07fdcdf7c62b8efeaf00b45c2c96ba457eb1a8bf075a3db28e5c24f6b923ed4ad747c3c9e03c7079efb87cb110d3a99861e72003cbae6d6b8b827e4e6c143064ff3c00',
    'Ed448 Vector #5');
end;

procedure TTestEd448.TestEd448Vector6;
begin
  CheckEd448Vector(
    '7ef4e84544236752fbb56b8f31a23a10e42814f5f55ca037cdcc11c64c9a3b2949c1bb60700314611732a6c2fea98eebc0266a11a93970100e',
    'b3da079b0aa493a5772029f0467baebee5a8112d9d3a22532361da294f7bb3815c5dc59e176b4d9f381ca0938e13c6c07b174be65dfa578e80',
    '64a65f3cdedcdd66811e2915e7',
    '',
    '6a12066f55331b6c22acd5d5bfc5d71228fbda80ae8dec26bdd306743c5027cb4890810c162c027468675ecf645a83176c0d7323a2ccde2d80efe5a1268e8aca1d6fbc194d3f77c44986eb4ab4177919ad8bec33eb47bbb5fc6e28196fd1caf56b4e7e0ba5519234d047155ac727a1053100',
    'Ed448 Vector #6');
end;

procedure TTestEd448.TestEd448Vector64;
begin
  CheckEd448Vector(
    'd65df341ad13e008567688baedda8e9dcdc17dc024974ea5b4227b6530e339bff21f99e68ca6968f3cca6dfe0fb9f4fab4fa135d5542ea3f01',
    'df9705f58edbab802c7f8363cfe5560ab1c6132c20a9f1dd163483a26f8ac53a39d6808bf4a1dfbd261b099bb03b3fb50906cb28bd8a081f00',
    'bd0f6a3747cd561bdddf4640a332461a4a30a12a434cd0bf40d766d9c6d458e5512204a30c17d1f50b5079631f64eb3112182da3005835461113718d1a5ef944',
    '',
    '554bc2480860b49eab8532d2a533b7d578ef473eeb58c98bb2d0e1ce488a98b18dfde9b9b90775e67f47d4a1c3482058efc9f40d2ca033a0801b63d45b3b722ef552bad3b4ccb667da350192b61c508cf7b6b5adadc2c8d9a446ef003fb05cba5f30e88e36ec2703b349ca229c2670833900',
    'Ed448 Vector #64');
end;

procedure TTestEd448.TestEd448Vector256;
begin
  CheckEd448Vector(
    '2ec5fe3c17045abdb136a5e6a913e32ab75ae68b53d2fc149b77e504132d37569b7e766ba74a19bd6162343a21c8590aa9cebca9014c636df5',
    '79756f014dcfe2079f5dd9e718be4171e2ef2486a08f25186f6bff43a9936b9bfe12402b08ae65798a3d81e22e9ec80e7690862ef3d4ed3a00',
    '15777532b0bdd0d1389f636c5f6b9ba734c90af572877e2d272dd078aa1e567cfa80e12928bb542330e8409f31745041' +
    '07ecd5efac61ae7504dabe2a602ede89e5cca6257a7c77e27a702b3ae39fc769fc54f2395ae6a1178cab4738e543072f' +
    'c1c177fe71e92e25bf03e4ecb72f47b64d0465aaea4c7fad372536c8ba516a6039c3c2a39f0e4d832be432dfa9a706a6' +
    'e5c7e19f397964ca4258002f7c0541b590316dbc5622b6b2a6fe7a4abffd9610' +
    '5eca76ea7b98816af0748c10df048ce012d901015a51f189f3888145c03650aa23ce894c3bd889e030d565071c59f409a9981b51878fd6fc110624dcbcde0bf7a69ccce38fabdf86f3bef6044819de11',
    '',
    'c650ddbb0601c19ca11439e1640dd931f43c518ea5bea70d3dcde5f4191fe53f00cf966546b72bcc7d58be2b9badef2874' +
    '3954e3a44a23f880e8d4f1cfce2d7a61452d26da05896f0a50da66a239a8a188b6d825b3305ad77b73fbac0836ecc60987fd08527c1a8e80d5823e65cafe2a3d00',
    'Ed448 Vector #256');
end;

procedure TTestEd448.TestEd448Vector1023;
begin
  CheckEd448Vector(
    '872d093780f5d3730df7c212664b37b8a0f24f56810daa8382cd4fa3f77634ec44dc54f1c2ed9bea86fafb7632d8be199ea165f5ad55dd9ce8',
    'a81b2e8a70a5ac94ffdbcc9badfc3feb0801f258578bb114ad44ece1ec0e799da08effb81c5d685c0c56f64eecaef8cdf11cc38737838cf400',
    '6ddf802e1aae4986935f7f981ba3f0351d6273c0a0c22c9c0e8339168e675412a3debfaf435ed651558007db4384b650fcc07e3b586a27a4f7a00ac8a6fec2cd' +
    '86ae4bf1570c41e6a40c931db27b2faa15a8cedd52cff7362c4e6e23daec0fbc3a79b6806e316efcc7b68119bf46bc76a26067a53f296dafdbdc11c77f7777e9' +
    '72660cf4b6a9b369a6665f02e0cc9b6edfad136b4fabe723d2813db3136cfde9b6d044322fee2947952e031b73ab5c603349b307bdc27bc6cb8b8bbd7bd32321' +
    '9b8033a581b59eadebb09b3c4f3d2277d4f0343624acc817804728b25ab797172b4c5c21a22f9c7839d64300232eb66e53f31c723fa37fe387c7d3e50bdf9813' +
    'a30e5bb12cf4cd930c40cfb4e1fc622592a49588794494d56d24ea4b40c89fc0596cc9ebb961c8cb10adde976a5d602b1c3f85b9b9a001ed3c6a4d3b1437f520' +
    '96cd1956d042a597d561a596ecd3d1735a8d570ea0ec27225a2c4aaff26306d1526c1af3ca6d9cf5a2c98f47e1c46db9a33234cfd4d81f2c98538a09ebe76998' +
    'd0d8fd25997c7d255c6d66ece6fa56f11144950f027795e653008f4bd7ca2dee85d8e90f3dc315130ce2a00375a318c7c3d97be2c8ce5b6db41a6254ff264fa6' +
    '155baee3b0773c0f497c573f19bb4f4240281f0b1f4f7be857a4e59d416c06b4c50fa09e1810ddc6b1467baeac5a3668d11b6ecaa901440016f389f80acc4db9' +
    '77025e7f5924388c7e340a732e554440e76570f8dd71b7d640b3450d1fd5f0410a18f9a3494f707c717b79b4bf75c98400b096b21653b5d217cf3565c9597456' +
    'f70703497a078763829bc01bb1cbc8fa04eadc9a6e3f6699587a9e75c94e5bab0036e0b2e711392cff0047d0d6b05bd2a588bc109718954259f1d86678a579a3' +
    '120f19cfb2963f177aeb70f2d4844826262e51b80271272068ef5b3856fa8535aa2a88b2d41f2a0e2fda7624c2850272ac4a2f561f8f2f7a318bfd5caf969614' +
    '9e4ac824ad3460538fdc25421beec2cc6818162d06bbed0c40a387192349db67a118bada6cd5ab0140ee273204f628aad1c135f770279a651e24d8c14d75a605' +
    '9d76b96a6fd857def5e0b354b27ab937a5815d16b5fae407ff18222c6d1ed263be68c95f32d908bd895cd76207ae726487567f9a67dad79abec316f683b17f2d' +
    '02bf07e0ac8b5bc6162cf94697b3c27cd1fea49b27f23ba2901871962506520c392da8b6ad0d99f7013fbc06c2c17a569500c8a7696481c1cd33e9b14e40b82e' +
    '79a5f5db82571ba97bae3ad3e0479515bb0e2b0f3bfcd1fd33034efc6245eddd7ee2086ddae2600d8ca73e214e8c2b0bdb2b047c6a464a562ed77b73d2d841c4' +
    'b34973551257713b753632efba348169abc90a68f42611a40126d7cb21b58695568186f7e569d2ff0f9e745d0487dd2eb997cafc5abf9dd102e62ff66cba87',
    '',
    'e301345a41a39a4d72fff8df69c98075a0cc082b802fc9b2b6bc503f926b65bddf7f4c8f1cb49f6396afc8a70abe6d8aef0db478d4c6b2970076c6a0484fe76d' +
    '76b3a97625d79f1ce240e7c576750d295528286f719b413de9ada3e8eb78ed573603ce30d8bb761785dc30dbc320869e1a00',
    'Ed448 Vector #1023');
end;

procedure TTestEd448.TestEd448phVector1;
begin
  CheckEd448phVector(
    '833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42ef7822e0d5104127dc05d6dbefde69e3ab2cec7c867c6e2c49',
    '259b71c19f83ef77a7abd26524cbdb3161b590a48f7d17de3ee0ba9c52beb743c09428a131d6b1b57303d90d8132c276d5ed3d5d01c0f53880',
    '616263',
    '',
    '822f6901f7480f3d5f562c592994d9693602875614483256505600bbc281ae381f54d6bce2ea911574932f52a4e6cadd78769375ec3ffd1b801a0d9b3f4030cd' +
    '433964b6457ea39476511214f97469b57dd32dbc560a9a94d00bff07620464a3ad203df7dc7ce360c3cd3696d9d9fab90f00',
    'Ed448ph Vector #1');
end;

procedure TTestEd448.TestEd448phVector2;
begin
  CheckEd448phVector(
    '833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42ef7822e0d5104127dc05d6dbefde69e3ab2cec7c867c6e2c49',
    '259b71c19f83ef77a7abd26524cbdb3161b590a48f7d17de3ee0ba9c52beb743c09428a131d6b1b57303d90d8132c276d5ed3d5d01c0f53880',
    '616263',
    '666f6f',
    'c32299d46ec8ff02b54540982814dce9a05812f81962b649d528095916a2aa481065b1580423ef927ecf0af5888f90da0f6a9a85ad5dc3f280d91224ba9911a3' +
    '653d00e484e2ce232521481c8658df304bb7745a73514cdb9bf3e15784ab71284f8d0704a608c54a6b62d97beb511d132100',
    'Ed448ph Vector #2');
end;

procedure TTestEd448.TestPublicKeyValidationFull;
var
  LSk, LPk: TBytes;
  I: Int32;
begin
  System.SetLength(LSk, TEd448.SecretKeySize);
  System.SetLength(LPk, TEd448.PublicKeySize);

  for I := 0 to 9 do
  begin
    FEd448.GeneratePrivateKey(FRandom, LSk);
    FEd448.GeneratePublicKey(LSk, 0, LPk, 0);
    CheckTrue(TEd448.ValidatePublicKeyFull(LPk, 0));
  end;

  CheckFalse(TEd448.ValidatePublicKeyFull(DecodeHex('000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'), 0));
  CheckFalse(TEd448.ValidatePublicKeyFull(DecodeHex('000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000080'), 0));
  CheckFalse(TEd448.ValidatePublicKeyFull(DecodeHex('010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'), 0));
  CheckFalse(TEd448.ValidatePublicKeyFull(DecodeHex('FEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00'), 0));
  CheckFalse(TEd448.ValidatePublicKeyFull(DecodeHex('010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000080'), 0));
  CheckFalse(TEd448.ValidatePublicKeyFull(DecodeHex('FEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF80'), 0));
  CheckFalse(TEd448.ValidatePublicKeyFull(DecodeHex('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00'), 0));
  CheckFalse(TEd448.ValidatePublicKeyFull(DecodeHex('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF80'), 0));
  CheckFalse(TEd448.ValidatePublicKeyFull(DecodeHex('00000000000000000000000000000000000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00'), 0));
  CheckFalse(TEd448.ValidatePublicKeyFull(DecodeHex('00000000000000000000000000000000000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF80'), 0));
  CheckFalse(TEd448.ValidatePublicKeyFull(DecodeHex('000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001'), 0));
  CheckFalse(TEd448.ValidatePublicKeyFull(DecodeHex('000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000081'), 0));

  CheckFalse(TEd448.ValidatePublicKeyFull(DecodeHex('C784B7238BDDDB84C44FB80936FB103FCF39C1F74EE83163A57DB4AD3946FDC81BF0504D6EC1DBABABDB750997BCA465D5FCD3A45F8E183D00'), 0));
  CheckFalse(TEd448.ValidatePublicKeyFull(DecodeHex('149578BCA53F7D199B472D6D367D22A35942BBCA2051F833122D4DC12FE758A16D672A54D5F8C390C44C2F8B32F21121DA69E9DE8FF9675780'), 0));
  CheckFalse(TEd448.ValidatePublicKeyFull(DecodeHex('9E9F6E7A8576E8D7C286C493FE76559419012B164589DF764E735CFFDE21BFCAF4D7553F9B37178A2F20C77473E4195E3E1E327F3174C14500'), 0));
  CheckFalse(TEd448.ValidatePublicKeyFull(DecodeHex('1979BDCBE0CEC16602B87257114059029605C720D5AFD2A90EF4B06655B34B561EBA6C1034452C3D8D1DA41C57340B0C9A95297E712CA75C00'), 0));
  CheckFalse(TEd448.ValidatePublicKeyFull(DecodeHex('E2B8507036D478F262A7009734CDD383734002CE32397FEA22BFEDEE0CEBB0064D176FB45A05AF19F8B18B07EE20D6E2320D075E95DAF15200'), 0));
  CheckFalse(TEd448.ValidatePublicKeyFull(DecodeHex('3C2FFFFCF504A0EBD8051B3962546C39410464A9C44DC3E82FA9437F2450F0F93C892F28E2ABDF7EA84B051E5536CCA6B44762D0941C5D0700'), 0));
  CheckFalse(TEd448.ValidatePublicKeyFull(DecodeHex('997FE46037CF6207B27B6D0BB9D7D97A038D5BFCF898D07EE6ED07953F0889CC4745D1E018EB7A894EFE88871004452E99C6A344362DA6E080'), 0));
  CheckFalse(TEd448.ValidatePublicKeyFull(DecodeHex('F67C319B8EDCE2E85D450BE46E1671183EB499CE8ABE56BCF666C13A99C5ECBC89FCE9B3B578E2A5D061D3590506BC27614DB6B0C682971B80'), 0));
  CheckFalse(TEd448.ValidatePublicKeyFull(DecodeHex('A7776DDD0BD52EC4D017478E38700395F9F4C45A3BEFFE4EA9994EA1A9E92D8D1CC56539BF57FF88401BBDC764904BC0E3635AEE1721FD3380'), 0));
  CheckFalse(TEd448.ValidatePublicKeyFull(DecodeHex('9F914CD9920D2B75ADBF34F758DA39BB35D1C81B5C480571A7A8B2CAAD7BA0F32D13AF9C69B0BECE5775B324DC49C063354EA2F6F231A23800'), 0));

  CheckFalse(TEd448.ValidatePublicKeyFull(DecodeHex('2E0ACAB5953BC2F22C557C75E6B86225BE9CB3E82E78FC886EB57B628229C0C9548CD82630483C03D0E5DC02B2C3B1BD0E5DEE0B8DE4A88000'), 0));
  CheckFalse(TEd448.ValidatePublicKeyFull(DecodeHex('0F89D2E413A36A33031329169EFAAE88D8F84E90E741C3DFBB01C32544D995FF6EB354B6C5C29E62ACC124E806540C46CB0C0ED71931B39D00'), 0));
  CheckFalse(TEd448.ValidatePublicKeyFull(DecodeHex('AB553809FE1B027328EC7DBE71929C1F3A435B74CC0C06BEA831BC5E287EF2ACF4E831EC8E0C964A80BF85B966D32CADAE8E17E12EAFD3AF80'), 0));
  CheckFalse(TEd448.ValidatePublicKeyFull(DecodeHex('3043631378826937A822BDB8878DC33B9174BEC3530B2A8A4048F6B06B378DBC450E34ED623E47B1449E7636DAFB72F584605EF3BE01647F00'), 0));
  CheckFalse(TEd448.ValidatePublicKeyFull(DecodeHex('8A03959C8BD20BA7B1DA92A4C5591BC846F4CD8BE07387B325E179BB12245E17BDDE1AC82E9F7CAB2A79DDDBE68F8BA8DB7F03F91156C24A00'), 0));
  CheckFalse(TEd448.ValidatePublicKeyFull(DecodeHex('46299C8D31BAFEBBCF1719A851123CC4722E5BE9D93D8F98C215D34082AF658C570B4CFD44079993CBC19B0EAD3BFD0DFB2B67EBABB119B780'), 0));
  CheckFalse(TEd448.ValidatePublicKeyFull(DecodeHex('81A58C03708DD60BD68237622EC9934E8DE27FE7997F74A501B06C60C8F9D68856E7D12B88F1507E29EB0C30531B5AA353F154F2551AF5E580'), 0));
  CheckFalse(TEd448.ValidatePublicKeyFull(DecodeHex('DC5028F5AA0B9217B40C7FE00E10503C37B6611BA87CDD70F01536E87AD659711BA1265E679F94EC8D5ED87476CE031D14B2C7E46268F11A80'), 0));
  CheckFalse(TEd448.ValidatePublicKeyFull(DecodeHex('910DDFE36AAB6DCB7D5B72E6F2DF0769AD86665262232C487F722FEA85429DE247D1EBBC5C579A01D04672894E2B0F3FBDF22B43EA191DF700'), 0));
  CheckFalse(TEd448.ValidatePublicKeyFull(DecodeHex('43482D0750D4830AAAF578346288050EAE8ADF96DF66F243E73252114E432B448730517FD8726871508CAD7ECECFDB33120CA5558788B6C800'), 0));
end;

procedure TTestEd448.TestPublicKeyValidationPartial;
var
  LSk, LPk: TBytes;
  I: Int32;
begin
  System.SetLength(LSk, TEd448.SecretKeySize);
  System.SetLength(LPk, TEd448.PublicKeySize);

  for I := 0 to 9 do
  begin
    FEd448.GeneratePrivateKey(FRandom, LSk);
    FEd448.GeneratePublicKey(LSk, 0, LPk, 0);
    CheckTrue(TEd448.ValidatePublicKeyPartial(LPk, 0));
  end;

  CheckFalse(TEd448.ValidatePublicKeyPartial(DecodeHex('000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'), 0));
  CheckFalse(TEd448.ValidatePublicKeyPartial(DecodeHex('000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000080'), 0));
  CheckFalse(TEd448.ValidatePublicKeyPartial(DecodeHex('010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'), 0));
  CheckFalse(TEd448.ValidatePublicKeyPartial(DecodeHex('FEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00'), 0));
  CheckFalse(TEd448.ValidatePublicKeyPartial(DecodeHex('010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000080'), 0));
  CheckFalse(TEd448.ValidatePublicKeyPartial(DecodeHex('FEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF80'), 0));
  CheckFalse(TEd448.ValidatePublicKeyPartial(DecodeHex('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00'), 0));
  CheckFalse(TEd448.ValidatePublicKeyPartial(DecodeHex('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF80'), 0));
  CheckFalse(TEd448.ValidatePublicKeyPartial(DecodeHex('00000000000000000000000000000000000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00'), 0));
  CheckFalse(TEd448.ValidatePublicKeyPartial(DecodeHex('00000000000000000000000000000000000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF80'), 0));
  CheckFalse(TEd448.ValidatePublicKeyPartial(DecodeHex('000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001'), 0));
  CheckFalse(TEd448.ValidatePublicKeyPartial(DecodeHex('000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000081'), 0));

  CheckFalse(TEd448.ValidatePublicKeyPartial(DecodeHex('C784B7238BDDDB84C44FB80936FB103FCF39C1F74EE83163A57DB4AD3946FDC81BF0504D6EC1DBABABDB750997BCA465D5FCD3A45F8E183D00'), 0));
  CheckFalse(TEd448.ValidatePublicKeyPartial(DecodeHex('149578BCA53F7D199B472D6D367D22A35942BBCA2051F833122D4DC12FE758A16D672A54D5F8C390C44C2F8B32F21121DA69E9DE8FF9675780'), 0));
  CheckFalse(TEd448.ValidatePublicKeyPartial(DecodeHex('9E9F6E7A8576E8D7C286C493FE76559419012B164589DF764E735CFFDE21BFCAF4D7553F9B37178A2F20C77473E4195E3E1E327F3174C14500'), 0));
  CheckFalse(TEd448.ValidatePublicKeyPartial(DecodeHex('1979BDCBE0CEC16602B87257114059029605C720D5AFD2A90EF4B06655B34B561EBA6C1034452C3D8D1DA41C57340B0C9A95297E712CA75C00'), 0));
  CheckFalse(TEd448.ValidatePublicKeyPartial(DecodeHex('E2B8507036D478F262A7009734CDD383734002CE32397FEA22BFEDEE0CEBB0064D176FB45A05AF19F8B18B07EE20D6E2320D075E95DAF15200'), 0));
  CheckFalse(TEd448.ValidatePublicKeyPartial(DecodeHex('3C2FFFFCF504A0EBD8051B3962546C39410464A9C44DC3E82FA9437F2450F0F93C892F28E2ABDF7EA84B051E5536CCA6B44762D0941C5D0700'), 0));
  CheckFalse(TEd448.ValidatePublicKeyPartial(DecodeHex('997FE46037CF6207B27B6D0BB9D7D97A038D5BFCF898D07EE6ED07953F0889CC4745D1E018EB7A894EFE88871004452E99C6A344362DA6E080'), 0));
  CheckFalse(TEd448.ValidatePublicKeyPartial(DecodeHex('F67C319B8EDCE2E85D450BE46E1671183EB499CE8ABE56BCF666C13A99C5ECBC89FCE9B3B578E2A5D061D3590506BC27614DB6B0C682971B80'), 0));
  CheckFalse(TEd448.ValidatePublicKeyPartial(DecodeHex('A7776DDD0BD52EC4D017478E38700395F9F4C45A3BEFFE4EA9994EA1A9E92D8D1CC56539BF57FF88401BBDC764904BC0E3635AEE1721FD3380'), 0));
  CheckFalse(TEd448.ValidatePublicKeyPartial(DecodeHex('9F914CD9920D2B75ADBF34F758DA39BB35D1C81B5C480571A7A8B2CAAD7BA0F32D13AF9C69B0BECE5775B324DC49C063354EA2F6F231A23800'), 0));

  CheckTrue(TEd448.ValidatePublicKeyPartial(DecodeHex('2E0ACAB5953BC2F22C557C75E6B86225BE9CB3E82E78FC886EB57B628229C0C9548CD82630483C03D0E5DC02B2C3B1BD0E5DEE0B8DE4A88000'), 0));
  CheckTrue(TEd448.ValidatePublicKeyPartial(DecodeHex('0F89D2E413A36A33031329169EFAAE88D8F84E90E741C3DFBB01C32544D995FF6EB354B6C5C29E62ACC124E806540C46CB0C0ED71931B39D00'), 0));
  CheckTrue(TEd448.ValidatePublicKeyPartial(DecodeHex('AB553809FE1B027328EC7DBE71929C1F3A435B74CC0C06BEA831BC5E287EF2ACF4E831EC8E0C964A80BF85B966D32CADAE8E17E12EAFD3AF80'), 0));
  CheckTrue(TEd448.ValidatePublicKeyPartial(DecodeHex('3043631378826937A822BDB8878DC33B9174BEC3530B2A8A4048F6B06B378DBC450E34ED623E47B1449E7636DAFB72F584605EF3BE01647F00'), 0));
  CheckTrue(TEd448.ValidatePublicKeyPartial(DecodeHex('8A03959C8BD20BA7B1DA92A4C5591BC846F4CD8BE07387B325E179BB12245E17BDDE1AC82E9F7CAB2A79DDDBE68F8BA8DB7F03F91156C24A00'), 0));
  CheckTrue(TEd448.ValidatePublicKeyPartial(DecodeHex('46299C8D31BAFEBBCF1719A851123CC4722E5BE9D93D8F98C215D34082AF658C570B4CFD44079993CBC19B0EAD3BFD0DFB2B67EBABB119B780'), 0));
  CheckTrue(TEd448.ValidatePublicKeyPartial(DecodeHex('81A58C03708DD60BD68237622EC9934E8DE27FE7997F74A501B06C60C8F9D68856E7D12B88F1507E29EB0C30531B5AA353F154F2551AF5E580'), 0));
  CheckTrue(TEd448.ValidatePublicKeyPartial(DecodeHex('DC5028F5AA0B9217B40C7FE00E10503C37B6611BA87CDD70F01536E87AD659711BA1265E679F94EC8D5ED87476CE031D14B2C7E46268F11A80'), 0));
  CheckTrue(TEd448.ValidatePublicKeyPartial(DecodeHex('910DDFE36AAB6DCB7D5B72E6F2DF0769AD86665262232C487F722FEA85429DE247D1EBBC5C579A01D04672894E2B0F3FBDF22B43EA191DF700'), 0));
  CheckTrue(TEd448.ValidatePublicKeyPartial(DecodeHex('43482D0750D4830AAAF578346288050EAE8ADF96DF66F243E73252114E432B448730517FD8726871508CAD7ECECFDB33120CA5558788B6C800'), 0));
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestEd448);
{$ELSE}
  RegisterTest(TTestEd448.Suite);
{$ENDIF FPC}

end.
