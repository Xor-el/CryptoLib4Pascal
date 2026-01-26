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

unit ClpRsaDigestSigner;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  Generics.Collections,
  ClpCryptoLibComparers,
  ClpICipherParameters,
  ClpIAsymmetricKeyParameter,
  ClpIParametersWithRandom,
  ClpParameterUtilities,
  ClpIDigest,
  ClpIRsa,
  ClpIAsymmetricBlockCipher,
  ClpISigner,
  ClpIRsaDigestSigner,
  ClpIRsaCoreEngine,
  ClpRsaCoreEngine,
  ClpIRsaBlindedEngine,
  ClpRsaBlindedEngine,
  ClpIPkcs1Encoding,
  ClpPkcs1Encoding,
  ClpIX509Asn1Objects,
  ClpX509Asn1Objects,
  ClpIAsn1Objects,
  ClpAsn1Objects,
  ClpX509ObjectIdentifiers,
  ClpNistObjectIdentifiers,
  ClpPkcsObjectIdentifiers,
  ClpTeleTrusTObjectIdentifiers,
  ClpArrayUtils,
  ClpCryptoLibTypes;

resourcestring
  SSigningRequiresPrivateKey = 'Signing requires private key.';
  SVerificationRequiresPublicKey = 'Verification requires public key.';
  SNotInitForSignature = 'RsaDigestSigner not initialised for signature generation.';
  SNotInitForVerification = 'RsaDigestSigner not initialised for verification';
  SUnableToEncode = 'unable to encode signature: ';

type
  /// <summary>
  /// RSA signer that uses a digest algorithm and PKCS#1 v1.5 padding.
  /// </summary>
  TRsaDigestSigner = class(TInterfacedObject, ISigner, IRsaDigestSigner)

  strict private
  class var
    FOidMap: TDictionary<String, IDerObjectIdentifier>;

  var
    FEngine: IAsymmetricBlockCipher;
    FDigestAlgID: IAlgorithmIdentifier;
    FDigest: IDigest;
    FForSigning: Boolean;

    class constructor CreateRsaDigestSigner();
    class destructor DestroyRsaDigestSigner();

    class function CheckDerEncoded(const AHash: TCryptoLibByteArray): TCryptoLibByteArray; static;
    function DerEncode(const ADigestAlgID: IAlgorithmIdentifier;
      const AHash: TCryptoLibByteArray): TCryptoLibByteArray;
    class function TryGetAltAlgID(const AAlgID: IAlgorithmIdentifier;
      out AAltAlgID: IAlgorithmIdentifier): Boolean; static;

  strict protected
    function GetAlgorithmName: String;

  public
    constructor Create(const digest: IDigest); overload;
    constructor Create(const digest: IDigest;
      const digestOid: IDerObjectIdentifier); overload;
    constructor Create(const digest: IDigest;
      const algId: IAlgorithmIdentifier); overload;
    constructor Create(const rsa: IRsa; const digest: IDigest;
      const digestOid: IDerObjectIdentifier); overload;
    constructor Create(const rsa: IRsa; const digest: IDigest;
      const algId: IAlgorithmIdentifier); overload;
    constructor Create(const rsaEngine: IAsymmetricBlockCipher;
      const digest: IDigest;
      const algId: IAlgorithmIdentifier); overload;

    procedure Init(AForSigning: Boolean; const AParameters: ICipherParameters);
    procedure Update(AInput: Byte);
    procedure BlockUpdate(const AInput: TCryptoLibByteArray; AInOff, ALength: Int32);
    function GetMaxSignatureSize: Int32;
    function GenerateSignature(): TCryptoLibByteArray;
    function VerifySignature(const ASignature: TCryptoLibByteArray): Boolean;
    procedure Reset();

    property AlgorithmName: String read GetAlgorithmName;

  end;

implementation

{ TRsaDigestSigner }

class constructor TRsaDigestSigner.CreateRsaDigestSigner;
begin
  FOidMap := TDictionary<String, IDerObjectIdentifier>.Create(
    TCryptoLibComparers.OrdinalIgnoreCaseEqualityComparer);

  FOidMap.Add('RIPEMD128', TTeleTrusTObjectIdentifiers.RipeMD128);
  FOidMap.Add('RIPEMD160', TTeleTrusTObjectIdentifiers.RipeMD160);
  FOidMap.Add('RIPEMD256', TTeleTrusTObjectIdentifiers.RipeMD256);

  FOidMap.Add('SHA-1', TX509ObjectIdentifiers.IdSha1);
  FOidMap.Add('SHA-224', TNistObjectIdentifiers.IdSha224);
  FOidMap.Add('SHA-256', TNistObjectIdentifiers.IdSha256);
  FOidMap.Add('SHA-384', TNistObjectIdentifiers.IdSha384);
  FOidMap.Add('SHA-512', TNistObjectIdentifiers.IdSha512);
  FOidMap.Add('SHA-512/224', TNistObjectIdentifiers.IdSha512_224);
  FOidMap.Add('SHA-512/256', TNistObjectIdentifiers.IdSha512_256);
  FOidMap.Add('SHA3-224', TNistObjectIdentifiers.IdSha3_224);
  FOidMap.Add('SHA3-256', TNistObjectIdentifiers.IdSha3_256);
  FOidMap.Add('SHA3-384', TNistObjectIdentifiers.IdSha3_384);
  FOidMap.Add('SHA3-512', TNistObjectIdentifiers.IdSha3_512);

  FOidMap.Add('MD2', TPkcsObjectIdentifiers.MD2);
  FOidMap.Add('MD4', TPkcsObjectIdentifiers.MD4);
  FOidMap.Add('MD5', TPkcsObjectIdentifiers.MD5);
end;

class destructor TRsaDigestSigner.DestroyRsaDigestSigner;
begin
  FOidMap.Free;
end;

constructor TRsaDigestSigner.Create(const digest: IDigest);
var
  oid: IDerObjectIdentifier;
begin
  if FOidMap.TryGetValue(digest.AlgorithmName, oid) then
    Create(digest, oid)
  else
  begin
    oid := nil;
    Create(digest, oid);
  end;
end;

constructor TRsaDigestSigner.Create(const digest: IDigest;
  const digestOid: IDerObjectIdentifier);
var
  algId: IAlgorithmIdentifier;
begin
  if digestOid <> nil then
    algId := TAlgorithmIdentifier.Create(digestOid, TDerNull.Instance)
  else
    algId := nil;

  Create(digest, algId);
end;

constructor TRsaDigestSigner.Create(const digest: IDigest;
  const algId: IAlgorithmIdentifier);
begin
  Create(TRsaCoreEngine.Create() as IRsa, digest, algId);
end;

constructor TRsaDigestSigner.Create(const rsa: IRsa; const digest: IDigest;
  const digestOid: IDerObjectIdentifier);
var
  algId: IAlgorithmIdentifier;
begin
  if digestOid <> nil then
    algId := TAlgorithmIdentifier.Create(digestOid, TDerNull.Instance)
  else
    algId := nil;

  Create(rsa, digest, algId);
end;

constructor TRsaDigestSigner.Create(const rsa: IRsa; const digest: IDigest;
  const algId: IAlgorithmIdentifier);
begin
  Create(TRsaBlindedEngine.Create(rsa) as IAsymmetricBlockCipher, digest, algId);
end;

constructor TRsaDigestSigner.Create(const rsaEngine: IAsymmetricBlockCipher;
  const digest: IDigest; const algId: IAlgorithmIdentifier);
begin
  inherited Create();
  FEngine := TPkcs1Encoding.Create(rsaEngine) as IAsymmetricBlockCipher;
  FDigest := digest;
  FDigestAlgID := algId;
end;

function TRsaDigestSigner.GetAlgorithmName: String;
begin
  Result := FDigest.AlgorithmName + 'withRSA';
end;

procedure TRsaDigestSigner.Init(AForSigning: Boolean;
  const AParameters: ICipherParameters);
var
  LKey: IAsymmetricKeyParameter;
begin
  FForSigning := AForSigning;

  LKey := TParameterUtilities.IgnoreRandom(AParameters) as IAsymmetricKeyParameter;

  if AForSigning and (not LKey.IsPrivate) then
  begin
    raise EInvalidKeyCryptoLibException.CreateRes(@SSigningRequiresPrivateKey);
  end;

  if (not AForSigning) and LKey.IsPrivate then
  begin
    raise EInvalidKeyCryptoLibException.CreateRes(@SVerificationRequiresPublicKey);
  end;

  Reset();
  FEngine.Init(AForSigning, AParameters);
end;

procedure TRsaDigestSigner.Update(AInput: Byte);
begin
  FDigest.Update(AInput);
end;

procedure TRsaDigestSigner.BlockUpdate(const AInput: TCryptoLibByteArray;
  AInOff, ALength: Int32);
begin
  FDigest.BlockUpdate(AInput, AInOff, ALength);
end;

function TRsaDigestSigner.GetMaxSignatureSize: Int32;
begin
  Result := FEngine.OutputBlockSize;
end;

class function TRsaDigestSigner.CheckDerEncoded(
  const AHash: TCryptoLibByteArray): TCryptoLibByteArray;
var
  LDigestInfo: IDigestInfo;
begin
  // Validate that hash is a valid DER-encoded DigestInfo
  LDigestInfo := TDigestInfo.GetInstance(AHash);
  Result := AHash;
end;

function TRsaDigestSigner.GenerateSignature: TCryptoLibByteArray;
var
  hash, data: TCryptoLibByteArray;
begin
  if not FForSigning then
    raise EInvalidOperationCryptoLibException.CreateRes(@SNotInitForSignature);

  hash := FDigest.DoFinal();

  try
    if FDigestAlgID = nil then
      data := CheckDerEncoded(hash)
    else
      data := DerEncode(FDigestAlgID, hash);

    Result := FEngine.ProcessBlock(data, 0, System.Length(data));
  except
    on E: EIOCryptoLibException do
    begin
      // IO errors should be reported as encoding failures
      raise ECryptoLibException.Create(SUnableToEncode + E.Message);
    end;

    on E: ECryptoLibException do
    begin
      raise ECryptoLibException.Create(SUnableToEncode + E.Message);
    end;

    on E: Exception do
    begin
      // Non-crypto exceptions get wrapped
      raise ECryptoLibException.Create(SUnableToEncode + E.Message);
    end;
  end;
end;

function TRsaDigestSigner.VerifySignature(
  const ASignature: TCryptoLibByteArray): Boolean;
var
  LSig, LHash, LExpected: TCryptoLibByteArray;
  LAltAlgID: IAlgorithmIdentifier;
begin
  if FForSigning then
  begin
    raise EInvalidOperationCryptoLibException.CreateRes(@SNotInitForVerification);
  end;

  try
    LSig := FEngine.ProcessBlock(ASignature, 0, System.Length(ASignature));
  except
    Result := False;
    Exit;
  end;

  SetLength(LHash, FDigest.GetDigestSize);
  FDigest.DoFinal(LHash, 0);

  if FDigestAlgID = nil then
  begin
    Result := TArrayUtils.ConstantTimeAreEqual(LSig, CheckDerEncoded(LHash));
    Exit;
  end;

  LExpected := DerEncode(FDigestAlgID, LHash);
  if TArrayUtils.ConstantTimeAreEqual(LSig, LExpected) then
  begin
    Result := True;
    Exit;
  end;

  // Try alternate algorithm identifier encoding (with/without DerNull)
  if TryGetAltAlgID(FDigestAlgID, LAltAlgID) then
  begin
    LExpected := DerEncode(LAltAlgID, LHash);
    if TArrayUtils.ConstantTimeAreEqual(LSig, LExpected) then
    begin
      Result := True;
      Exit;
    end;
  end;

  Result := False;
end;

procedure TRsaDigestSigner.Reset;
begin
  FDigest.Reset();
end;

function TRsaDigestSigner.DerEncode(const ADigestAlgID: IAlgorithmIdentifier;
  const AHash: TCryptoLibByteArray): TCryptoLibByteArray;
var
  LDigestInfo: IDigestInfo;
begin
  LDigestInfo := TDigestInfo.Create(ADigestAlgID, TDerOctetString.WithContents(AHash) as IAsn1OctetString);
  Result := LDigestInfo.GetDerEncoded();
end;

class function TRsaDigestSigner.TryGetAltAlgID(const AAlgID: IAlgorithmIdentifier;
  out AAltAlgID: IAlgorithmIdentifier): Boolean;
begin
  if AAlgID.Parameters = nil then
  begin
    AAltAlgID := TAlgorithmIdentifier.Create(AAlgID.Algorithm, TDerNull.Instance);
    Result := True;
  end
  else if TDerNull.Instance.Equals(AAlgID.Parameters) then
  begin
    AAltAlgID := TAlgorithmIdentifier.Create(AAlgID.Algorithm, nil);
    Result := True;
  end
  else
  begin
    AAltAlgID := nil;
    Result := False;
  end;
end;

end.
