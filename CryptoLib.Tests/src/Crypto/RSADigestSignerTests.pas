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

unit RSADigestSignerTests;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  SysUtils,
  Classes,
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
  ClpRsaKeyParameters,
  ClpIRsaKeyParameters,
  ClpRsaPrivateCrtKeyParameters,
  ClpIRsaPrivateCrtKeyParameters,
  ClpIAsn1Objects,
  ClpAlgorithmIdentifier,
  ClpIDigestInfo,
  ClpDigestInfo,
  ClpAsn1Objects,
  ClpDigestUtilities,
  ClpX509ObjectIdentifiers,
  ClpNistObjectIdentifiers,
  ClpPkcsObjectIdentifiers,
  ClpTeleTrusTObjectIdentifiers,
  ClpEncoders,
  ClpCryptoLibTypes;

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
  end;

implementation

{ TTestRSADigestSigner }

class procedure TTestRSADigestSigner.SetUpKeys;
var
  rsaPubMod, rsaPubExp, rsaPrivMod, rsaPrivExp: TBigInteger;
  rsaPrivP, rsaPrivQ, rsaPrivDP, rsaPrivDQ, rsaPrivQinv: TBigInteger;
begin
  rsaPubMod := TBigInteger.Create(1, TBase64.Decode(
    'AIASoe2PQb1IP7bTyC9usjHP7FvnUMVpKW49iuFtrw/dMpYlsMMoIU2jupfifDpdFxIktSB4P+6Ymg5WjvHKTIrvQ7SR4zV4jaPTu56Ys0pZ9EDA6gb3HLjtU+8Bb1mfWM+yjKxcPDuFjwEtjGlPHg1Vq+CA9HNcMSKNn2+tW6qt'));
  rsaPubExp := TBigInteger.Create(1, TBase64.Decode('EQ=='));

  rsaPrivMod := TBigInteger.Create(1, TBase64.Decode(
    'AIASoe2PQb1IP7bTyC9usjHP7FvnUMVpKW49iuFtrw/dMpYlsMMoIU2jupfifDpdFxIktSB4P+6Ymg5WjvHKTIrvQ7SR4zV4jaPTu56Ys0pZ9EDA6gb3HLjtU+8Bb1mfWM+yjKxcPDuFjwEtjGlPHg1Vq+CA9HNcMSKNn2+tW6qt'));
  rsaPrivExp := TBigInteger.Create(1, TBase64.Decode(
    'DxFAOhDajr00rBjqX+7nyZ/9sHWRCCp9WEN5wCsFiWVRPtdB+NeLcou7mWXwf1Y+8xNgmmh//fPV45G2dsyBeZbXeJwB7bzx9NMEAfedchyOwjR8PYdjK3NpTLKtZlEJ6Jkh4QihrXpZMO4fKZWUm9bid3+lmiq43FwW+Hof8/E='));

  rsaPrivP := TBigInteger.Create(1, TBase64.Decode(
    'AJ9StyTVW+AL/1s7RBtFwZGFBgd3zctBqzzwKPda6LbtIFDznmwDCqAlIQH9X14X7UPLokCDhuAa76OnDXb1OiE='));
  rsaPrivQ := TBigInteger.Create(1, TBase64.Decode(
    'AM3JfD79dNJ5A3beScSzPtWxx/tSLi0QHFtkuhtSizeXdkv5FSba7lVzwEOGKHmW829bRoNxThDy4ds1IihW1w0='));
  rsaPrivDP := TBigInteger.Create(1, TBase64.Decode(
    'JXzfzG5v+HtLJIZqYMUefJfFLu8DPuJGaLD6lI3cZ0babWZ/oPGoJa5iHpX4Ul/7l3s1PFsuy1GhzCdOdlfRcQ=='));
  rsaPrivDQ := TBigInteger.Create(1, TBase64.Decode(
    'YNdJhw3cn0gBoVmMIFRZzflPDNthBiWy/dUMSRfJCxoZjSnr1gysZHK01HteV1YYNGcwPdr3j4FbOfri5c6DUQ=='));
  rsaPrivQinv := TBigInteger.Create(1, TBase64.Decode(
    'Lt0g7wrsNsQxuDdB8q/rH8fSFeBXMGLtCIqfOec1j7FEIuYA/ACiRDgXkHa0WgN7nLXSjHoy630wC5Toq8vvUg=='));

  FRsaPublic := TRsaKeyParameters.Create(False, rsaPubMod, rsaPubExp);
  FRsaPrivate := TRsaPrivateCrtKeyParameters.Create(rsaPrivMod, rsaPubExp,
    rsaPrivExp, rsaPrivP, rsaPrivQ, rsaPrivDP, rsaPrivDQ, rsaPrivQinv);
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
  signer: ISigner;
  exceptionRaised: Boolean;
begin
  signer := CreatePrehashSigner();
  signer.Init(True, FRsaPrivate);
  signer.BlockUpdate(TCryptoLibByteArray.Create(0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0), 0, 20);

  exceptionRaised := False;
  try
    signer.GenerateSignature();
  except
    on E: Exception do
    begin
      exceptionRaised := True;
      CheckTrue(Pos('unable to encode signature', E.Message) > 0,
        'Wrong exception message: ' + E.Message);
    end;
  end;

  CheckTrue(exceptionRaised, 'Expected exception not raised');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestRSADigestSigner);
{$ELSE}
  RegisterTest(TTestRSADigestSigner.Suite);
{$ENDIF FPC}

end.
