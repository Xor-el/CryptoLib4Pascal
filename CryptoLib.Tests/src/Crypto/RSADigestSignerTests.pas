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
  ClpIDigest,
  ClpISigner,
  ClpRsaDigestSigner,
  ClpIRsaDigestSigner,
  ClpIRsaParameters,
  ClpIAsn1Core,
  ClpIAsn1Objects,
  ClpAsn1Objects,
  ClpX509Asn1Objects,
  ClpIX509Asn1Objects,
  ClpDigestUtilities,
  ClpX509ObjectIdentifiers,
  ClpNistObjectIdentifiers,
  ClpPkcsObjectIdentifiers,
  ClpTeleTrusTObjectIdentifiers,
  ClpCryptoLibConfig,
  ClpSignerUtilities,
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
    function SignSha256DigestInfo(const AParameters: IAsn1Encodable): TCryptoLibByteArray;
    function VerifySha256(const ASignature: TCryptoLibByteArray; AStrict: Boolean): Boolean;
    function CounterMessage(ACounter: Int32): TCryptoLibByteArray;
    function Sha256DigestInfo(const AMsg: TCryptoLibByteArray): TCryptoLibByteArray;
    procedure FindLeadingZeroSignature(const AAlgorithm: String; AWrapDigestInfo: Boolean;
      out AMsg, ASig: TCryptoLibByteArray);
    function VerifyWith(const AVerifier: ISigner; const AMsg, ASig: TCryptoLibByteArray): Boolean;

  protected
    procedure SetUp; override;
    procedure TearDown; override;
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
    procedure TestStrictDigestInfoRejectsAbsentParameters;
    procedure TestStrictDigestInfoAcceptsCanonical;
    procedure TestStrictDigestInfoIsOnByDefaultAndResets;
    procedure TestStrictDigestInfoReachesTheSignerFactory;
    procedure TestStrictLengthIsOnByDefaultAndResets;
    procedure TestSignatureShorterThanModulusRejected;
    procedure TestSignatureLongerThanModulusRejected;
    procedure TestEmptySignatureRejected;
    procedure TestSignerReusableAfterRejectedLength;
    procedure TestShortSignatureRejectedThroughSignerFactory;
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

procedure TTestRSADigestSigner.TearDown;
begin
  // the strict mode is process-wide: leave it as the later tests expect it
  TCryptoLibConfig.ResetToDefaults();
  inherited;
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
  // only the lenient fallback reads the tail bytes of a no-NULL DigestInfo
  TCryptoLibConfig.Pkcs1.StrictDigestInfo := False;
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

function TTestRSADigestSigner.SignSha256DigestInfo(
  const AParameters: IAsn1Encodable): TCryptoLibByteArray;
var
  LMsg, LHash, LEnc: TCryptoLibByteArray;
  LDigestInfo: IDigestInfo;
  LSigner: ISigner;
begin
  LMsg := TCryptoLibByteArray.Create(1, 6, 3, 32, 7, 43, 2, 5, 7, 78, 4, 23);
  LHash := TDigestUtilities.DoFinal(TDigestUtilities.GetDigest('SHA-256'), LMsg);
  LDigestInfo := TDigestInfo.Create(
    TAlgorithmIdentifier.Create(TNistObjectIdentifiers.IdSha256, AParameters) as IAlgorithmIdentifier,
    LHash);
  LEnc := LDigestInfo.GetDerEncoded();
  LSigner := CreatePrehashSigner();
  LSigner.Init(True, FRsaPrivate);
  LSigner.BlockUpdate(LEnc, 0, System.Length(LEnc));
  Result := LSigner.GenerateSignature();
end;

function TTestRSADigestSigner.VerifySha256(const ASignature: TCryptoLibByteArray;
  AStrict: Boolean): Boolean;
var
  LMsg: TCryptoLibByteArray;
  LVerifier: IRsaDigestSigner;
begin
  LMsg := TCryptoLibByteArray.Create(1, 6, 3, 32, 7, 43, 2, 5, 7, 78, 4, 23);
  LVerifier := TRsaDigestSigner.Create(TDigestUtilities.GetDigest('SHA-256'),
    TNistObjectIdentifiers.IdSha256) as IRsaDigestSigner;
  TCryptoLibConfig.Pkcs1.StrictDigestInfo := AStrict;
  LVerifier.Init(False, FRsaPublic);
  LVerifier.BlockUpdate(LMsg, 0, System.Length(LMsg));
  Result := LVerifier.VerifySignature(ASignature);
end;

procedure TTestRSADigestSigner.TestStrictDigestInfoRejectsAbsentParameters;
var
  LSig: TCryptoLibByteArray;
begin
  LSig := SignSha256DigestInfo(nil);
  CheckTrue(VerifySha256(LSig, False), 'the lenient verifier still accepts absent parameters');
  CheckFalse(VerifySha256(LSig, True), 'the strict verifier rejects absent parameters');
end;

procedure TTestRSADigestSigner.TestStrictDigestInfoAcceptsCanonical;
var
  LSig: TCryptoLibByteArray;
begin
  LSig := SignSha256DigestInfo(TDerNull.Instance);
  CheckTrue(VerifySha256(LSig, True), 'the strict verifier accepts the NULL-parameters encoding');
  CheckTrue(VerifySha256(LSig, False), 'the lenient verifier accepts it too');
end;

procedure TTestRSADigestSigner.TestStrictDigestInfoIsOnByDefaultAndResets;
begin
  CheckTrue(TCryptoLibConfig.Pkcs1.StrictDigestInfo, 'the default is strict');
  TCryptoLibConfig.Pkcs1.StrictDigestInfo := False;
  CheckFalse(TCryptoLibConfig.Pkcs1.StrictDigestInfo, 'it can be relaxed');
  TCryptoLibConfig.Pkcs1.ResetToDefaults();
  CheckTrue(TCryptoLibConfig.Pkcs1.StrictDigestInfo, 'the area reset returns to strict');
  TCryptoLibConfig.Pkcs1.StrictDigestInfo := False;
  TCryptoLibConfig.ResetToDefaults();
  CheckTrue(TCryptoLibConfig.Pkcs1.StrictDigestInfo, 'the global reset returns to strict');
end;

procedure TTestRSADigestSigner.TestStrictLengthIsOnByDefaultAndResets;
begin
  CheckTrue(TCryptoLibConfig.Pkcs1.StrictLength, 'the default is strict');
  TCryptoLibConfig.Pkcs1.StrictLength := False;
  CheckFalse(TCryptoLibConfig.Pkcs1.StrictLength, 'it can be relaxed');
  TCryptoLibConfig.Pkcs1.ResetToDefaults();
  CheckTrue(TCryptoLibConfig.Pkcs1.StrictLength, 'the area reset returns to strict');
  TCryptoLibConfig.Pkcs1.StrictLength := False;
  TCryptoLibConfig.ResetToDefaults();
  CheckTrue(TCryptoLibConfig.Pkcs1.StrictLength, 'the global reset returns to strict');
end;

procedure TTestRSADigestSigner.TestStrictDigestInfoReachesTheSignerFactory;
var
  LSig, LMsg: TCryptoLibByteArray;
  LVerifier: ISigner;
begin
  // certificates, CRLs, OCSP and CMS verify through the signer factory, not a held IRsaDigestSigner
  LSig := SignSha256DigestInfo(nil);
  LMsg := TCryptoLibByteArray.Create(1, 6, 3, 32, 7, 43, 2, 5, 7, 78, 4, 23);
  LVerifier := TSignerUtilities.GetSigner('SHA-256withRSA');
  LVerifier.Init(False, FRsaPublic);
  LVerifier.BlockUpdate(LMsg, 0, System.Length(LMsg));
  CheckFalse(LVerifier.VerifySignature(LSig), 'the default rejects a DigestInfo without NULL');
  TCryptoLibConfig.Pkcs1.StrictDigestInfo := False;
  LVerifier := TSignerUtilities.GetSigner('SHA-256withRSA');
  LVerifier.Init(False, FRsaPublic);
  LVerifier.BlockUpdate(LMsg, 0, System.Length(LMsg));
  CheckTrue(LVerifier.VerifySignature(LSig), 'relaxing it accepts the form through the factory too');
end;

function TTestRSADigestSigner.CounterMessage(ACounter: Int32): TCryptoLibByteArray;
begin
  Result := TCryptoLibByteArray.Create(Byte(ACounter), Byte(ACounter shr 8), 1, 2, 3);
end;

function TTestRSADigestSigner.Sha256DigestInfo(const AMsg: TCryptoLibByteArray): TCryptoLibByteArray;
var
  LHash: TCryptoLibByteArray;
  LDigestInfo: IDigestInfo;
begin
  LHash := TDigestUtilities.DoFinal(TDigestUtilities.GetDigest('SHA-256'), AMsg);
  LDigestInfo := TDigestInfo.Create(
    TAlgorithmIdentifier.Create(TNistObjectIdentifiers.IdSha256, TDerNull.Instance) as IAlgorithmIdentifier,
    LHash);
  Result := LDigestInfo.GetDerEncoded();
end;

// signing is deterministic, so the first message whose signature starts with 0x00 is stable
procedure TTestRSADigestSigner.FindLeadingZeroSignature(const AAlgorithm: String;
  AWrapDigestInfo: Boolean; out AMsg, ASig: TCryptoLibByteArray);
var
  LI: Int32;
  LSigner: ISigner;
  LInput: TCryptoLibByteArray;
  LFound: Boolean;
begin
  LFound := False;
  LI := 0;
  while (not LFound) and (LI < 4096) do
  begin
    AMsg := CounterMessage(LI);
    if AWrapDigestInfo then
      LInput := Sha256DigestInfo(AMsg)
    else
      LInput := AMsg;
    LSigner := TSignerUtilities.GetSigner(AAlgorithm);
    LSigner.Init(True, FRsaPrivate);
    LSigner.BlockUpdate(LInput, 0, System.Length(LInput));
    ASig := LSigner.GenerateSignature();
    LFound := ASig[0] = 0;
    System.Inc(LI);
  end;
  CheckTrue(LFound, 'no leading-zero signature found');
end;

function TTestRSADigestSigner.VerifyWith(const AVerifier: ISigner;
  const AMsg, ASig: TCryptoLibByteArray): Boolean;
begin
  AVerifier.BlockUpdate(AMsg, 0, System.Length(AMsg));
  Result := AVerifier.VerifySignature(ASig);
end;

procedure TTestRSADigestSigner.TestSignatureShorterThanModulusRejected;
var
  LMsg, LSig, LShort: TCryptoLibByteArray;
  LVerifier: IRsaDigestSigner;
begin
  FindLeadingZeroSignature('SHA-256withRSA', False, LMsg, LSig);
  LShort := System.Copy(LSig, 1, System.Length(LSig) - 1);
  LVerifier := TRsaDigestSigner.Create(TDigestUtilities.GetDigest('SHA-256')) as IRsaDigestSigner;
  LVerifier.Init(False, FRsaPublic);
  CheckTrue(VerifyWith(LVerifier, LMsg, LSig), 'the full signature verifies');
  LVerifier := TRsaDigestSigner.Create(TDigestUtilities.GetDigest('SHA-256')) as IRsaDigestSigner;
  LVerifier.Init(False, FRsaPublic);
  CheckFalse(VerifyWith(LVerifier, LMsg, LShort), 'the signature without its leading zero is rejected');
end;

procedure TTestRSADigestSigner.TestSignatureLongerThanModulusRejected;
var
  LMsg, LSig, LLong: TCryptoLibByteArray;
  LVerifier: ISigner;
begin
  FindLeadingZeroSignature('SHA-256withRSA', False, LMsg, LSig);
  System.SetLength(LLong, System.Length(LSig) + 1);
  System.Move(LSig[0], LLong[1], System.Length(LSig));
  LLong[0] := 0;
  LVerifier := TSignerUtilities.GetSigner('SHA-256withRSA');
  LVerifier.Init(False, FRsaPublic);
  CheckFalse(VerifyWith(LVerifier, LMsg, LLong), 'a signature with an extra leading zero is rejected');
end;

procedure TTestRSADigestSigner.TestEmptySignatureRejected;
var
  LMsg, LEmpty: TCryptoLibByteArray;
  LVerifier: ISigner;
begin
  LMsg := CounterMessage(0);
  LVerifier := TSignerUtilities.GetSigner('SHA-256withRSA');
  LVerifier.Init(False, FRsaPublic);
  CheckFalse(VerifyWith(LVerifier, LMsg, nil), 'a nil signature is rejected');
  LVerifier := TSignerUtilities.GetSigner('SHA-256withRSA');
  LVerifier.Init(False, FRsaPublic);
  LEmpty := nil;
  CheckFalse(VerifyWith(LVerifier, LMsg, LEmpty), 'an empty signature is rejected');
end;

procedure TTestRSADigestSigner.TestSignerReusableAfterRejectedLength;
var
  LMsg, LSig, LShort: TCryptoLibByteArray;
  LVerifier: ISigner;
begin
  FindLeadingZeroSignature('SHA-256withRSA', False, LMsg, LSig);
  LShort := System.Copy(LSig, 1, System.Length(LSig) - 1);
  LVerifier := TSignerUtilities.GetSigner('SHA-256withRSA');
  LVerifier.Init(False, FRsaPublic);
  CheckFalse(VerifyWith(LVerifier, LMsg, LShort), 'the short signature is rejected');
  CheckTrue(VerifyWith(LVerifier, LMsg, LSig), 'the same instance verifies the next message');
end;

procedure TTestRSADigestSigner.TestShortSignatureRejectedThroughSignerFactory;
var
  LMsg, LSig, LShort, LInput: TCryptoLibByteArray;
  LVerifier: ISigner;
begin
  FindLeadingZeroSignature('SHA-256withRSA', False, LMsg, LSig);
  LShort := System.Copy(LSig, 1, System.Length(LSig) - 1);
  LVerifier := TSignerUtilities.GetSigner('SHA-256withRSA');
  LVerifier.Init(False, FRsaPublic);
  CheckFalse(VerifyWith(LVerifier, LMsg, LShort), 'the digest signer rejects the short signature');

  FindLeadingZeroSignature('RSA', True, LMsg, LSig);
  LShort := System.Copy(LSig, 1, System.Length(LSig) - 1);
  LInput := Sha256DigestInfo(LMsg);
  LVerifier := TSignerUtilities.GetSigner('RSA');
  LVerifier.Init(False, FRsaPublic);
  CheckTrue(VerifyWith(LVerifier, LInput, LSig), 'the raw signer accepts the full signature');
  LVerifier := TSignerUtilities.GetSigner('RSA');
  LVerifier.Init(False, FRsaPublic);
  CheckFalse(VerifyWith(LVerifier, LInput, LShort), 'the raw signer rejects the short signature');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestRSADigestSigner);
{$ELSE}
  RegisterTest(TTestRSADigestSigner.Suite);
{$ENDIF FPC}

end.
