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

unit RSADigestSignerTests;

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
  ClpIDigest,
  ClpISigner,
  ClpRsaDigestSigner,
  ClpIRsaDigestSigner,
  ClpIRsaParameters,
  ClpIAsn1Objects,
  ClpAsn1Objects,
  ClpX509Asn1Objects,
  ClpIX509Asn1Objects,
  ClpDigestUtilities,
  ClpX509ObjectIdentifiers,
  ClpNistObjectIdentifiers,
  ClpPkcsObjectIdentifiers,
  ClpTeleTrusTObjectIdentifiers,
  ClpCryptoLibTypes,
  CryptoTestKeys;

type

  TTestRSADigestSigner = class(TTestCase)
  strict private
    class var
      FRsaPublic: IRsaKeyParameters;
      FRsaPrivate: IRsaPrivateCrtKeyParameters;

    class procedure SetUpKeys;
    procedure CheckDigest(const digest: IDigest;
      const digOid: IDerObjectIdentifier);
    procedure CheckNullDigest(const digest: IDigest;
      const digOid: IDerObjectIdentifier);
    class function CreatePrehashSigner: IRsaDigestSigner;

  protected
    procedure SetUp; override;
  published
    procedure TestRipeMD128;
    procedure TestRipeMD160;
    procedure TestRipeMD256;
    procedure TestSha1;
    procedure TestSha224;
    procedure TestSha256;
    procedure TestSha384;
    procedure TestSha512;
    procedure TestSha512_224;
    procedure TestSha512_256;
    procedure TestSha3_224;
    procedure TestSha3_256;
    procedure TestSha3_384;
    procedure TestSha3_512;
    procedure TestMD2;
    procedure TestMD4;
    procedure TestMD5;
    procedure TestNullDigestSha1;
    procedure TestNullDigestSha256;
    procedure TestNullFormatError;
    procedure TestNoNullDigestInfoTailBytesChecked;
  end;

implementation

{ TTestRSADigestSigner }

class procedure TTestRSADigestSigner.SetUpKeys;
begin
  FRsaPublic := TCryptoTestKeys.GetRsaDigestSignerPublic;
  FRsaPrivate := TCryptoTestKeys.GetRsaDigestSignerPrivate;
end;

procedure TTestRSADigestSigner.SetUp;
begin
  inherited;
  if FRsaPublic = nil then
    SetUpKeys;
end;

procedure TTestRSADigestSigner.CheckDigest(const digest: IDigest;
  const digOid: IDerObjectIdentifier);
var
  msg, sig: TCryptoLibByteArray;
  signer: ISigner;
begin
  msg := TCryptoLibByteArray.Create(1, 6, 3, 32, 7, 43, 2, 5, 7, 78, 4, 23);

  signer := TRsaDigestSigner.Create(digest);
  signer.Init(True, FRsaPrivate);
  signer.BlockUpdate(msg, 0, Length(msg));
  sig := signer.GenerateSignature();

  signer := TRsaDigestSigner.Create(digest, digOid);
  signer.Init(False, FRsaPublic);
  signer.BlockUpdate(msg, 0, Length(msg));
  CheckTrue(signer.VerifySignature(sig), 'RSA Digest Signer failed for ' + digest.AlgorithmName);
end;

procedure TTestRSADigestSigner.CheckNullDigest(const digest: IDigest;
  const digOid: IDerObjectIdentifier);
var
  msg, hash, infoEnc, sig: TCryptoLibByteArray;
  digInfo: IDigestInfo;
  signer: ISigner;
begin
  msg := TCryptoLibByteArray.Create(1, 6, 3, 32, 7, 43, 2, 5, 7, 78, 4, 23);
  hash := TDigestUtilities.DoFinal(digest, msg);

  digInfo := TDigestInfo.Create(TAlgorithmIdentifier.Create(digOid, TDerNull.Instance), hash);
  infoEnc := digInfo.GetDerEncoded();

  // Sign with prehash signer
  signer := CreatePrehashSigner();
  signer.Init(True, FRsaPrivate);
  signer.BlockUpdate(infoEnc, 0, Length(infoEnc));
  sig := signer.GenerateSignature();

  // Verify with regular signer
  signer := TRsaDigestSigner.Create(digest, digOid);
  signer.Init(False, FRsaPublic);
  signer.BlockUpdate(msg, 0, Length(msg));
  CheckTrue(signer.VerifySignature(sig), 'NONE - RSA Digest Signer failed (1)');

  // Verify with prehash signer
  signer := CreatePrehashSigner();
  signer.Init(False, FRsaPublic);
  signer.BlockUpdate(infoEnc, 0, Length(infoEnc));
  CheckTrue(signer.VerifySignature(sig), 'NONE - RSA Digest Signer failed (2)');
end;

class function TTestRSADigestSigner.CreatePrehashSigner: IRsaDigestSigner;
var
  nullOid: IDerObjectIdentifier;
begin
  nullOid := nil;
  Result := TRsaDigestSigner.Create(TDigestUtilities.GetDigest('None'), nullOid);
end;

procedure TTestRSADigestSigner.TestRipeMD128;
begin
  CheckDigest(TDigestUtilities.GetDigest('RIPEMD128'), TTeleTrusTObjectIdentifiers.RipeMD128);
end;

procedure TTestRSADigestSigner.TestRipeMD160;
begin
  CheckDigest(TDigestUtilities.GetDigest('RIPEMD160'), TTeleTrusTObjectIdentifiers.RipeMD160);
end;

procedure TTestRSADigestSigner.TestRipeMD256;
begin
  CheckDigest(TDigestUtilities.GetDigest('RIPEMD256'), TTeleTrusTObjectIdentifiers.RipeMD256);
end;

procedure TTestRSADigestSigner.TestSha1;
begin
  CheckDigest(TDigestUtilities.GetDigest('SHA-1'), TX509ObjectIdentifiers.IdSha1);
end;

procedure TTestRSADigestSigner.TestSha224;
begin
  CheckDigest(TDigestUtilities.GetDigest('SHA-224'), TNistObjectIdentifiers.IdSha224);
end;

procedure TTestRSADigestSigner.TestSha256;
begin
  CheckDigest(TDigestUtilities.GetDigest('SHA-256'), TNistObjectIdentifiers.IdSha256);
end;

procedure TTestRSADigestSigner.TestSha384;
begin
  CheckDigest(TDigestUtilities.GetDigest('SHA-384'), TNistObjectIdentifiers.IdSha384);
end;

procedure TTestRSADigestSigner.TestSha512;
begin
  CheckDigest(TDigestUtilities.GetDigest('SHA-512'), TNistObjectIdentifiers.IdSha512);
end;

procedure TTestRSADigestSigner.TestSha512_224;
begin
  CheckDigest(TDigestUtilities.GetDigest('SHA-512/224'), TNistObjectIdentifiers.IdSha512_224);
end;

procedure TTestRSADigestSigner.TestSha512_256;
begin
  CheckDigest(TDigestUtilities.GetDigest('SHA-512/256'), TNistObjectIdentifiers.IdSha512_256);
end;

procedure TTestRSADigestSigner.TestSha3_224;
begin
  CheckDigest(TDigestUtilities.GetDigest('SHA3-224'), TNistObjectIdentifiers.IdSha3_224);
end;

procedure TTestRSADigestSigner.TestSha3_256;
begin
  CheckDigest(TDigestUtilities.GetDigest('SHA3-256'), TNistObjectIdentifiers.IdSha3_256);
end;

procedure TTestRSADigestSigner.TestSha3_384;
begin
  CheckDigest(TDigestUtilities.GetDigest('SHA3-384'), TNistObjectIdentifiers.IdSha3_384);
end;

procedure TTestRSADigestSigner.TestSha3_512;
begin
  CheckDigest(TDigestUtilities.GetDigest('SHA3-512'), TNistObjectIdentifiers.IdSha3_512);
end;

procedure TTestRSADigestSigner.TestMD2;
begin
  CheckDigest(TDigestUtilities.GetDigest('MD2'), TPkcsObjectIdentifiers.MD2);
end;

procedure TTestRSADigestSigner.TestMD4;
begin
  CheckDigest(TDigestUtilities.GetDigest('MD4'), TPkcsObjectIdentifiers.MD4);
end;

procedure TTestRSADigestSigner.TestMD5;
begin
  CheckDigest(TDigestUtilities.GetDigest('MD5'), TPkcsObjectIdentifiers.MD5);
end;

procedure TTestRSADigestSigner.TestNullDigestSha1;
begin
  CheckNullDigest(TDigestUtilities.GetDigest('SHA-1'), TX509ObjectIdentifiers.IdSha1);
end;

procedure TTestRSADigestSigner.TestNullDigestSha256;
begin
  CheckNullDigest(TDigestUtilities.GetDigest('SHA-256'), TNistObjectIdentifiers.IdSha256);
end;

procedure TTestRSADigestSigner.TestNullFormatError;
var
  LSigner: ISigner;
  LExceptionRaised: Boolean;
begin
  LSigner := CreatePrehashSigner();
  LSigner.Init(True, FRsaPrivate);
  LSigner.BlockUpdate(TCryptoLibByteArray.Create(0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0), 0, 20);

  LExceptionRaised := False;
  try
    LSigner.GenerateSignature();
  except
    on E: Exception do
    begin
      LExceptionRaised := True;
      CheckTrue(Pos('unable to encode signature', E.Message) > 0,
        'Wrong exception message: ' + E.Message);
    end;
  end;

  CheckTrue(LExceptionRaised, 'Expected exception not raised');
end;

procedure TTestRSADigestSigner.TestNoNullDigestInfoTailBytesChecked;
var
  LMsg, LHash, LTampered, LLooseEnc, LForgedSig: TCryptoLibByteArray;
  LDigest: IDigest;
  LLoose: IDigestInfo;
  LLooseSigner, LVerifier: ISigner;
begin
  LMsg := TCryptoLibByteArray.Create(1, 6, 3, 32, 7, 43, 2, 5, 7, 78, 4, 23);

  LDigest := TDigestUtilities.GetDigest('SHA-256');
  LHash := TDigestUtilities.DoFinal(LDigest, LMsg);

  LTampered := System.Copy(LHash);
  LTampered[System.Length(LTampered) - 1] := LTampered[System.Length(LTampered) - 1] xor $01;
  LTampered[System.Length(LTampered) - 2] := LTampered[System.Length(LTampered) - 2] xor $80;

  LLoose := TDigestInfo.Create(
    TAlgorithmIdentifier.Create(TNistObjectIdentifiers.IdSha256, nil) as IAlgorithmIdentifier, LTampered);
  LLooseEnc := LLoose.GetDerEncoded();

  LLooseSigner := CreatePrehashSigner();
  LLooseSigner.Init(True, FRsaPrivate);
  LLooseSigner.BlockUpdate(LLooseEnc, 0, System.Length(LLooseEnc));
  LForgedSig := LLooseSigner.GenerateSignature();

  LVerifier := TRsaDigestSigner.Create(LDigest, TNistObjectIdentifiers.IdSha256);
  LVerifier.Init(False, FRsaPublic);
  LVerifier.BlockUpdate(LMsg, 0, System.Length(LMsg));
  CheckFalse(LVerifier.VerifySignature(LForgedSig),
    'no-NULL DigestInfo with wrong final hash bytes must be rejected');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestRSADigestSigner);
{$ELSE}
  RegisterTest(TTestRSADigestSigner.Suite);
{$ENDIF FPC}

end.
