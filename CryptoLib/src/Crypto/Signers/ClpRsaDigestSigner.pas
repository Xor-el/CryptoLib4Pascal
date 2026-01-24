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

    class function CheckDerEncoded(const hash: TCryptoLibByteArray): TCryptoLibByteArray; static;
    function DerEncode(const digestAlgID: IAlgorithmIdentifier;
      const hash: TCryptoLibByteArray): TCryptoLibByteArray;
    class function TryGetAltAlgID(const algID: IAlgorithmIdentifier;
      out altAlgID: IAlgorithmIdentifier): Boolean; static;

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

    procedure Init(forSigning: Boolean; const parameters: ICipherParameters);
    procedure Update(input: Byte);
    procedure BlockUpdate(const input: TCryptoLibByteArray; inOff, len: Int32);
    function GetMaxSignatureSize: Int32;
    function GenerateSignature(): TCryptoLibByteArray;
    function VerifySignature(const signature: TCryptoLibByteArray): Boolean;
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

procedure TRsaDigestSigner.Init(forSigning: Boolean;
  const parameters: ICipherParameters);
var
  key: IAsymmetricKeyParameter;
begin
  FForSigning := forSigning;

  key := TParameterUtilities.IgnoreRandom(parameters) as IAsymmetricKeyParameter;

  if forSigning and (not key.IsPrivate) then
  begin
    raise EInvalidKeyCryptoLibException.CreateRes(@SSigningRequiresPrivateKey);
  end;

  if (not forSigning) and key.IsPrivate then
  begin
    raise EInvalidKeyCryptoLibException.CreateRes(@SVerificationRequiresPublicKey);
  end;

  Reset();
  FEngine.Init(forSigning, parameters);
end;

procedure TRsaDigestSigner.Update(input: Byte);
begin
  FDigest.Update(input);
end;

procedure TRsaDigestSigner.BlockUpdate(const input: TCryptoLibByteArray;
  inOff, len: Int32);
begin
  FDigest.BlockUpdate(input, inOff, len);
end;

function TRsaDigestSigner.GetMaxSignatureSize: Int32;
begin
  Result := FEngine.OutputBlockSize;
end;

class function TRsaDigestSigner.CheckDerEncoded(
  const hash: TCryptoLibByteArray): TCryptoLibByteArray;
var
  LDigestInfo: IDigestInfo;
begin
  // Validate that hash is a valid DER-encoded DigestInfo
  LDigestInfo := TDigestInfo.GetInstance(hash);
  Result := hash;
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
  const signature: TCryptoLibByteArray): Boolean;
var
  sig, hash, expected: TCryptoLibByteArray;
  altAlgID: IAlgorithmIdentifier;
begin
  if FForSigning then
  begin
    raise EInvalidOperationCryptoLibException.CreateRes(@SNotInitForVerification);
  end;

  try
    sig := FEngine.ProcessBlock(signature, 0, System.Length(signature));
  except
    Result := False;
    Exit;
  end;

  SetLength(hash, FDigest.GetDigestSize);
  FDigest.DoFinal(hash, 0);

  if FDigestAlgID = nil then
  begin
    Result := TArrayUtils.ConstantTimeAreEqual(sig, CheckDerEncoded(hash));
    Exit;
  end;

  expected := DerEncode(FDigestAlgID, hash);
  if TArrayUtils.ConstantTimeAreEqual(sig, expected) then
  begin
    Result := True;
    Exit;
  end;

  // Try alternate algorithm identifier encoding (with/without DerNull)
  if TryGetAltAlgID(FDigestAlgID, altAlgID) then
  begin
    expected := DerEncode(altAlgID, hash);
    if TArrayUtils.ConstantTimeAreEqual(sig, expected) then
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

function TRsaDigestSigner.DerEncode(const digestAlgID: IAlgorithmIdentifier;
  const hash: TCryptoLibByteArray): TCryptoLibByteArray;
var
  digestInfo: IDigestInfo;
begin
  digestInfo := TDigestInfo.Create(digestAlgID, TDerOctetString.WithContents(hash) as IAsn1OctetString);
  Result := digestInfo.GetDerEncoded();
end;

class function TRsaDigestSigner.TryGetAltAlgID(const algID: IAlgorithmIdentifier;
  out altAlgID: IAlgorithmIdentifier): Boolean;
begin
  if algID.Parameters = nil then
  begin
    altAlgID := TAlgorithmIdentifier.Create(algID.Algorithm, TDerNull.Instance);
    Result := True;
  end
  else if TDerNull.Instance.Equals(algID.Parameters) then
  begin
    altAlgID := TAlgorithmIdentifier.Create(algID.Algorithm, nil);
    Result := True;
  end
  else
  begin
    altAlgID := nil;
    Result := False;
  end;
end;

end.
