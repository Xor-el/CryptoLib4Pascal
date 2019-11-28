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

unit Ed25519HigherLevelTests;

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
  TypInfo,
  ClpSecureRandom,
  ClpISecureRandom,
  ClpISigner,
  ClpEd25519,
  ClpIEd25519,
  ClpEd25519Signer,
  ClpIEd25519Signer,
  ClpEd25519CtxSigner,
  ClpIEd25519CtxSigner,
  ClpEd25519PhSigner,
  ClpIEd25519PhSigner,
  ClpIEd25519PrivateKeyParameters,
  ClpIEd25519PublicKeyParameters,
  ClpEd25519PrivateKeyParameters,
  ClpEd25519PublicKeyParameters,
  ClpIAsymmetricCipherKeyPair,
  ClpAsymmetricCipherKeyPair,
  ClpEd25519KeyPairGenerator,
  ClpIEd25519KeyPairGenerator,
  ClpEd25519KeyGenerationParameters,
  ClpIEd25519KeyGenerationParameters,
  ClpSignerUtilities,
  ClpCryptoLibTypes,
  CryptoLibTestBase;

type

  /// <summary>
  /// test vectors gotten from <see href="https://github.com/warner/python-ed25519" />
  /// and <see href="https://github.com/Matoking/python-ed25519-blake2b" />
  /// </summary>
  TTestEd25519HigherLevel = class(TCryptoLibAlgorithmTestCase)
  private
  var
    FRandom: ISecureRandom;

  type
{$SCOPEDENUMS ON}
    TEd25519SignerAlgorithm = (Ed25519, Ed25519Blake2B);
{$SCOPEDENUMS OFF}
  function CreateSigner(algorithm: TEd25519.TEd25519Algorithm;
    const context: TBytes): ISigner;

  function CreateCustomSigner(const algorithm: TEd25519SignerAlgorithm)
    : ISigner;

  function ReconstructEd25519KeyPair(algorithm: TEd25519SignerAlgorithm;
    const sk, pk: TBytes): IAsymmetricCipherKeyPair;

  function RandomContext(length: Int32): TBytes;

  procedure DoTestConsistency(algorithm: TEd25519.TEd25519Algorithm;
    const context: TBytes);

  procedure DoEd25519Test(id: Int32; algorithm: TEd25519SignerAlgorithm;
    const sk, pk, msg, sig: String);
  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestConsistency();
    procedure TestEd25519();

  end;

implementation

{ TTestEd25519HigherLevel }

function TTestEd25519HigherLevel.CreateCustomSigner(const algorithm
  : TEd25519SignerAlgorithm): ISigner;
var
  algorithmName: String;
begin
  algorithmName := GetEnumName(TypeInfo(TEd25519SignerAlgorithm),
    Ord(algorithm));
  Result := TSignerUtilities.GetSigner(algorithmName);
end;

function TTestEd25519HigherLevel.CreateSigner
  (algorithm: TEd25519.TEd25519Algorithm; const context: TBytes): ISigner;
begin
  case algorithm of
    TEd25519.TEd25519Algorithm.Ed25519:
      Result := TEd25519Signer.Create(TEd25519.Create() as IEd25519)
        as IEd25519Signer;
    TEd25519.TEd25519Algorithm.Ed25519ctx:
      Result := TEd25519CtxSigner.Create(TEd25519.Create() as IEd25519, context)
        as IEd25519CtxSigner;
    TEd25519.TEd25519Algorithm.Ed25519ph:
      Result := TEd25519PhSigner.Create(TEd25519.Create() as IEd25519, context)
        as IEd25519PhSigner;
  else
    begin
      raise EArgumentCryptoLibException.Create('algorithm');
    end;
  end;
end;

procedure TTestEd25519HigherLevel.DoEd25519Test(id: Int32;
  algorithm: TEd25519SignerAlgorithm; const sk, pk, msg, sig: String);
var
  LSk, LPk, LMsg, LSig, LResultSig, LKey: TBytes;
  LKeyPair: IAsymmetricCipherKeyPair;
  LIsVerified: Boolean;
  LSigner: ISigner;
begin
  LSk := DecodeHex(sk);
  LPk := DecodeHex(pk);
  LMsg := DecodeHex(msg);
  LSig := DecodeHex(sig);
  LKeyPair := ReconstructEd25519KeyPair(algorithm, LSk, LPk);
  LSigner := CreateCustomSigner(algorithm);

  case algorithm of
    TTestEd25519HigherLevel.TEd25519SignerAlgorithm.Ed25519:
      begin
        LKey := (LKeyPair.Private as IEd25519PrivateKeyParameters).GetEncoded();
        if not AreEqual(LKey, System.Copy(LSk, 0, 32)) then
        begin
          Fail(Format
            ('Test with Id %d Failed on PrivateKey Reconstruction Comparison, Expected "%s" but got "%s"',
            [id, EncodeHex(LSk), EncodeHex(LKey)]));
        end;

        LKey := (LKeyPair.Public as IEd25519PublicKeyParameters).GetEncoded();
        if not AreEqual(LKey, System.Copy(LPk, 0, 64)) then
        begin
          Fail(Format
            ('Test with Id %d Failed on PublicKey Reconstruction Comparison, Expected "%s" but got "%s"',
            [id, EncodeHex(LPk), EncodeHex(LKey)]));
        end;
      end;
    TTestEd25519HigherLevel.TEd25519SignerAlgorithm.Ed25519Blake2B:
      begin
        LKey := (LKeyPair.Private as IEd25519PrivateKeyParameters).GetEncoded();
        if not AreEqual(LKey, System.Copy(LSk, 0, 32)) then
        begin
          Fail(Format
            ('Test with Id %d Failed on PrivateKey Reconstruction Comparison, Expected "%s" but got "%s"',
            [id, EncodeHex(LSk), EncodeHex(LKey)]));
        end;

        LKey := (LKeyPair.Public as IEd25519PublicKeyParameters).GetEncoded();
        if not AreEqual(LKey, System.Copy(LPk, 0, 64)) then
        begin
          Fail(Format
            ('Test with Id %d Failed on PublicKey Reconstruction Comparison, Expected "%s" but got "%s"',
            [id, EncodeHex(LPk), EncodeHex(LKey)]));
        end;
      end
  else
    begin
      raise EArgumentCryptoLibException.Create('algorithm');
    end;

  end;

  LSigner.Init(True, LKeyPair.Private);
  LSigner.BlockUpdate(LMsg, 0, System.length(LMsg));
  LResultSig := LSigner.GenerateSignature();

  if not AreEqual(LResultSig, System.Copy(LSig, 0, 64)) then
  begin
    Fail(Format
      ('Test with Id %d Failed on Signature Comparison, Expected "%s" but got "%s"',
      [id, EncodeHex(LSig), EncodeHex(LResultSig)]));
  end;

  LSigner.Init(False, LKeyPair.Public);
  LSigner.BlockUpdate(LMsg, 0, System.length(LMsg));
  LIsVerified := LSigner.VerifySignature(LResultSig);

  if not LIsVerified then
  begin
    Fail(Format('Test with Id %d Failed on Verifying "%s" Signature',
      [id, EncodeHex(LResultSig)]));
  end;
end;

procedure TTestEd25519HigherLevel.DoTestConsistency
  (algorithm: TEd25519.TEd25519Algorithm; const context: TBytes);
var
  kpg: IEd25519KeyPairGenerator;
  kp: IAsymmetricCipherKeyPair;
  privateKey: IEd25519PrivateKeyParameters;
  publicKey: IEd25519PublicKeyParameters;
  msg, signature, wrongLengthSignature: TBytes;
  Signer, verifier: ISigner;
  shouldVerify, shouldNotVerify: Boolean;
  algorithmName: String;
  tempRand: Int32;
begin
  kpg := TEd25519KeyPairGenerator.Create(TEd25519.Create() as IEd25519);
  kpg.Init(TEd25519KeyGenerationParameters.Create(FRandom)
    as IEd25519KeyGenerationParameters);

  kp := kpg.GenerateKeyPair();
  privateKey := kp.Private as IEd25519PrivateKeyParameters;
  publicKey := kp.Public as IEd25519PublicKeyParameters;

  System.SetLength(msg, FRandom.NextInt32 and 255);
  FRandom.NextBytes(msg);

  Signer := CreateSigner(algorithm, context);
  Signer.Init(True, privateKey);
  Signer.BlockUpdate(msg, 0, System.length(msg));
  signature := Signer.GenerateSignature();

  verifier := CreateSigner(algorithm, context);
  verifier.Init(False, publicKey);
  verifier.BlockUpdate(msg, 0, System.length(msg));
  shouldVerify := verifier.VerifySignature(signature);

  algorithmName := GetEnumName(TypeInfo(TEd25519.TEd25519Algorithm),
    Ord(algorithm));

  if (not shouldVerify) then
  begin
    Fail(Format('Ed25519 (%s) signature failed to verify', [algorithmName]));
  end;

  wrongLengthSignature := Prepend(signature, Byte($00));

  verifier.Init(False, publicKey);
  verifier.BlockUpdate(msg, 0, System.length(msg));
  shouldNotVerify := verifier.VerifySignature(wrongLengthSignature);

  if (shouldNotVerify) then
  begin
    Fail(Format('Ed25519 (%s) wrong length signature incorrectly verified',
      [algorithmName]));
  end;

  tempRand := FRandom.Next();
  signature[tempRand mod System.length(signature)] :=
    signature[tempRand mod System.length(signature)
    ] xor Byte(1 shl (FRandom.NextInt32 and 7));

  verifier.Init(False, publicKey);
  verifier.BlockUpdate(msg, 0, System.length(msg));
  shouldNotVerify := verifier.VerifySignature(signature);

  if (shouldNotVerify) then
  begin
    Fail(Format('Ed25519 (%s) bad signature incorrectly verified',
      [algorithmName]));
  end;
end;

function TTestEd25519HigherLevel.RandomContext(length: Int32): TBytes;
begin
  System.SetLength(Result, length);
  FRandom.NextBytes(Result);
end;

function TTestEd25519HigherLevel.ReconstructEd25519KeyPair
  (algorithm: TEd25519SignerAlgorithm; const sk, pk: TBytes)
  : IAsymmetricCipherKeyPair;
begin
  case algorithm of
    TTestEd25519HigherLevel.TEd25519SignerAlgorithm.Ed25519:
      begin
        Result := TAsymmetricCipherKeyPair.Create
          (TEd25519PublicKeyParameters.Create(pk, 0)
          as IEd25519PublicKeyParameters,
          TEd25519PrivateKeyParameters.Create(TEd25519.Create() as IEd25519, sk,
          0) as IEd25519PrivateKeyParameters);
      end;
    TTestEd25519HigherLevel.TEd25519SignerAlgorithm.Ed25519Blake2B:
      begin
        Result := TAsymmetricCipherKeyPair.Create
          (TEd25519PublicKeyParameters.Create(pk, 0)
          as IEd25519PublicKeyParameters,
          TEd25519PrivateKeyParameters.Create(TEd25519Blake2B.Create()
          as IEd25519Blake2B, sk, 0) as IEd25519PrivateKeyParameters);
      end
  else
    begin
      raise EArgumentCryptoLibException.Create('algorithm');
    end;
  end;
end;

procedure TTestEd25519HigherLevel.SetUp;
begin
  inherited;
  FRandom := TSecureRandom.Create();
end;

procedure TTestEd25519HigherLevel.TearDown;
begin
  inherited;

end;

procedure TTestEd25519HigherLevel.TestConsistency;
var
  i: Int32;
  context: TBytes;
begin
  i := 0;
  while i < 10 do
  begin
    DoTestConsistency(TEd25519.TEd25519Algorithm.Ed25519, Nil);

    context := RandomContext(FRandom.NextInt32 and 255);
    DoTestConsistency(TEd25519.TEd25519Algorithm.Ed25519ctx, context);
    DoTestConsistency(TEd25519.TEd25519Algorithm.Ed25519ph, context);
    System.Inc(i);
  end;
end;

procedure TTestEd25519HigherLevel.TestEd25519;
begin

  // TEd25519SignerAlgorithm.Ed25519

  DoEd25519Test(1, TEd25519SignerAlgorithm.Ed25519,
    '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a',
    'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a', '',
    'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b');

  DoEd25519Test(2, TEd25519SignerAlgorithm.Ed25519,
    '4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c',
    '3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c', '72',
    '92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c0072');

  DoEd25519Test(3, TEd25519SignerAlgorithm.Ed25519,
    'c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025',
    'fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025', 'af82',
    '6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40aaf82');

  DoEd25519Test(4, TEd25519SignerAlgorithm.Ed25519,
    '0d4a05b07352a5436e180356da0ae6efa0345ff7fb1572575772e8005ed978e9e61a185bcef2613a6c7cb79763ce945d3b245d76114dd440bcf5f2dc1aa57057',
    'e61a185bcef2613a6c7cb79763ce945d3b245d76114dd440bcf5f2dc1aa57057',
    'cbc77b', 'd9868d52c2bebce5f3fa5a79891970f309cb6591e3e1702a70276fa97c24b3a8e58606c38c9758529da50ee31b8219cba45271c689afa60b0ea26c99db19b00ccbc77b');

  DoEd25519Test(5, TEd25519SignerAlgorithm.Ed25519,
    '6df9340c138cc188b5fe4464ebaa3f7fc206a2d55c3434707e74c9fc04e20ebbc0dac102c4533186e25dc43128472353eaabdb878b152aeb8e001f92d90233a7',
    'c0dac102c4533186e25dc43128472353eaabdb878b152aeb8e001f92d90233a7',
    '5f4c8989',
    '124f6fc6b0d100842769e71bd530664d888df8507df6c56dedfdb509aeb93416e26b918d38aa06305df3095697c18b2aa832eaa52edc0ae49fbae5a85e150c075f4c8989');

  // TEd25519SignerAlgorithm.Ed25519Blake2B

  DoEd25519Test(6, TEd25519SignerAlgorithm.Ed25519Blake2B,
    '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60',
    '78e65bf30f893d32fc57ef051c341bdede242544fc2a2112f0fa2c7afdebc02f', '',
    '99a523bd4616c8161144d6a99d3c32400cb4a326f4d79e307340f6afa11750a0085d7d84626bc9e4b153fc0e396d15ce44c39bae4533804db1fe5b52f2b1b805');

  DoEd25519Test(7, TEd25519SignerAlgorithm.Ed25519Blake2B,
    '4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb',
    '5e71392d91e6a58fedeb0850364f56cd158a60447557d7890389c9b3d4576d4d', '72',
    '6da75e15b5707f4de5a153c48a5d839fb85074c38aeb6285977f03a13977597f976069fdb903f183474aaa5ed0cfe878ba8ef868c5e47ca3f96ccfb3a89b2a0672');

  DoEd25519Test(8, TEd25519SignerAlgorithm.Ed25519Blake2B,
    'c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7',
    '8d53ca70f0eab23b9178345785fcdb69ed6723f8148f7e339e88653700b718da', 'af82',
    '7cc3c13852bd12abf3ce4ca8ca2836cbf86da96c4634c50df3fb80dc809e29db0e109c361353407c1236a904f636868aa33977a99d3f844598db1538b4295203af82');

  DoEd25519Test(9, TEd25519SignerAlgorithm.Ed25519Blake2B,
    '0d4a05b07352a5436e180356da0ae6efa0345ff7fb1572575772e8005ed978e9',
    '0c6989f1abebe219db9d1e2cb8b0c602b191828ef7238f8e6dbff8a506802c09',
    'cbc77b', '7fb2c11db736d16ebd07a653463dc8739d3315f89f61a66715e41528cb32b7689393f5af8a66c9c7336e209e6b187259fe266f7941a435fecb8cd7a7fc759400cbc77b');

  DoEd25519Test(10, TEd25519SignerAlgorithm.Ed25519Blake2B,
    '6df9340c138cc188b5fe4464ebaa3f7fc206a2d55c3434707e74c9fc04e20ebb',
    'ce99a0d41b2c1bdf593cfe41b0bf38f40ab77a804a71138188cc879b59869d90',
    '5f4c8989',
    'e09625735d184975409020659f3c0b07f036a19a7e7aa2100964cef577806e26125d1437577d2d3286c29df871797cac3fc0cdecbbeca616030cfcc6711db6065f4c8989');
end;

initialization

// Register any test cases with the test runner

{$IFDEF FPC}
  RegisterTest(TTestEd25519HigherLevel);
{$ELSE}
  RegisterTest(TTestEd25519HigherLevel.Suite);
{$ENDIF FPC}

end.
