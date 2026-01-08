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

unit ClpSubjectPublicKeyInfo;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpAsn1Objects,
  ClpIAsn1Objects,
  ClpAlgorithmIdentifier,
  ClpIAlgorithmIdentifier,
  ClpISubjectPublicKeyInfo,
  ClpIAsymmetricKeyParameter,
  ClpIECPublicKeyParameters,
  ClpIECDomainParameters,
  ClpX9ObjectIdentifiers,
  ClpX9ECParameters,
  ClpIX9ECParameters,
  ClpECNamedCurveTable,
  ClpIEd25519PublicKeyParameters,
  ClpEdECObjectIdentifiers,
  ClpCryptoLibTypes;

resourcestring
  SInvalidSubjectPublicKeyInfo = 'Invalid SubjectPublicKeyInfo: %s';
  SBadSequenceSize = 'Bad Sequence Size: %d';
  SUnsupportedPublicKeyType = 'Unsupported public key type';

type
  /// <summary>
  /// SubjectPublicKeyInfo ::= SEQUENCE {
  ///   algorithm AlgorithmIdentifier,
  ///   subjectPublicKey BIT STRING
  /// }
  /// </summary>
  TSubjectPublicKeyInfo = class(TAsn1Encodable, ISubjectPublicKeyInfo)

  strict private
  var
    FAlgorithm: IAlgorithmIdentifier;
    FPublicKeyData: IDerBitString;

    function GetAlgorithm: IAlgorithmIdentifier;
    function GetPublicKeyData: IDerBitString;

    constructor Create(const seq: IAsn1Sequence); overload;

  public
    constructor Create(const algorithm: IAlgorithmIdentifier;
      const publicKey: IDerBitString); overload;

    function ToAsn1Object(): IAsn1Object; override;

    property Algorithm: IAlgorithmIdentifier read GetAlgorithm;
    property PublicKeyData: IDerBitString read GetPublicKeyData;

    class function GetInstance(obj: TObject): ISubjectPublicKeyInfo; overload;
      static;
    class function GetInstance(const obj: IAsn1TaggedObject;
      explicitly: Boolean): ISubjectPublicKeyInfo; overload; static;

    /// <summary>
    /// Creates SubjectPublicKeyInfo from a public key.
    /// Supports ECDSA (IECPublicKeyParameters) and EdDSA (Ed25519).
    /// For ECDSA, automatically detects named curves and uses compact OID.
    /// </summary>
    class function CreateFromPublicKey(
      const publicKey: IAsymmetricKeyParameter): ISubjectPublicKeyInfo; static;

  strict private
    /// <summary>
    /// Finds the named curve OID for the given domain parameters.
    /// Returns nil if no matching named curve is found.
    /// </summary>
    class function FindCurveOid(
      const domain: IECDomainParameters): IDerObjectIdentifier; static;
  end;

implementation

{ TSubjectPublicKeyInfo }

constructor TSubjectPublicKeyInfo.Create(const algorithm: IAlgorithmIdentifier;
  const publicKey: IDerBitString);
begin
  inherited Create();
  FAlgorithm := algorithm;
  FPublicKeyData := publicKey;
end;

constructor TSubjectPublicKeyInfo.Create(const seq: IAsn1Sequence);
begin
  inherited Create();
  if seq.Count <> 2 then
  begin
    raise EArgumentCryptoLibException.CreateResFmt(@SBadSequenceSize,
      [seq.Count]);
  end;

  FAlgorithm := TAlgorithmIdentifier.GetInstance(seq[0] as TObject);
  FPublicKeyData := TDerBitString.GetInstance(seq[1] as TAsn1Encodable);
end;

function TSubjectPublicKeyInfo.GetAlgorithm: IAlgorithmIdentifier;
begin
  Result := FAlgorithm;
end;

function TSubjectPublicKeyInfo.GetPublicKeyData: IDerBitString;
begin
  Result := FPublicKeyData;
end;

class function TSubjectPublicKeyInfo.GetInstance(obj: TObject): ISubjectPublicKeyInfo;
begin
  if (obj = nil) or (obj is TSubjectPublicKeyInfo) then
  begin
    Result := obj as TSubjectPublicKeyInfo;
    Exit;
  end;

  if obj is TAsn1Sequence then
  begin
    Result := TSubjectPublicKeyInfo.Create(obj as TAsn1Sequence);
    Exit;
  end;

  raise EArgumentCryptoLibException.CreateResFmt(@SInvalidSubjectPublicKeyInfo,
    [obj.ToString]);
end;

class function TSubjectPublicKeyInfo.GetInstance(const obj: IAsn1TaggedObject;
  explicitly: Boolean): ISubjectPublicKeyInfo;
begin
  Result := GetInstance(TAsn1Sequence.GetInstance(obj, explicitly) as TAsn1Sequence);
end;

function TSubjectPublicKeyInfo.ToAsn1Object: IAsn1Object;
var
  v: IAsn1EncodableVector;
  algAsn1: IAsn1Object;
begin
  algAsn1 := FAlgorithm.ToAsn1Object;

  v := TAsn1EncodableVector.Create();
  v.Add(algAsn1);
  v.Add(FPublicKeyData);

  Result := TDerSequence.FromVector(v);
end;

class function TSubjectPublicKeyInfo.FindCurveOid(
  const domain: IECDomainParameters): IDerObjectIdentifier;
var
  names: TCryptoLibStringArray;
  name: string;
  curveParams: IX9ECParameters;
begin
  Result := nil;
  names := TECNamedCurveTable.Names;

  for name in names do
  begin
    curveParams := TECNamedCurveTable.GetByName(name);
    // Compare N (unique per curve, fast BigInteger comparison)
    if (curveParams <> nil) and domain.N.Equals(curveParams.N) then
    begin
      Result := TECNamedCurveTable.GetOid(name);
      Exit;
    end;
  end;
end;

class function TSubjectPublicKeyInfo.CreateFromPublicKey(
  const publicKey: IAsymmetricKeyParameter): ISubjectPublicKeyInfo;
var
  domain: IECDomainParameters;
  encodedPoint: TCryptoLibByteArray;
  ecParams: IX9ECParameters;
  algId: IAlgorithmIdentifier;
  pubKeyBits: IDerBitString;
  ecPublicKey: IECPublicKeyParameters;
  ed25519Key: IEd25519PublicKeyParameters;
  encodedKey: TCryptoLibByteArray;
  curveOid: IDerObjectIdentifier;
begin
  // ECDSA keys
  if Supports(publicKey, IECPublicKeyParameters) then
  begin
    ecPublicKey := publicKey as IECPublicKeyParameters;
    domain := ecPublicKey.Parameters;

    // Try to find named curve OID first (compact representation)
    curveOid := FindCurveOid(domain);

    if curveOid <> nil then
    begin
      // Use named curve OID as parameter
      algId := TAlgorithmIdentifier.Create(TX9ObjectIdentifiers.IdECPublicKey, curveOid);
    end
    else
    begin
      // Fall back to explicit parameters for custom/unknown curves
      ecParams := TX9ECParameters.Create(domain.Curve, domain.G, domain.N,
        domain.H, domain.GetSeed);
      algId := TAlgorithmIdentifier.Create(TX9ObjectIdentifiers.IdECPublicKey,
        ecParams.ToAsn1Object);
    end;

    // Encode the public key point (uncompressed encoding)
    encodedPoint := ecPublicKey.Q.GetEncoded(False);

    pubKeyBits := TDerBitString.Create(encodedPoint);

    Result := TSubjectPublicKeyInfo.Create(algId, pubKeyBits);
  end
  // Ed25519 keys
  else if Supports(publicKey, IEd25519PublicKeyParameters) then
  begin
    ed25519Key := publicKey as IEd25519PublicKeyParameters;

    // Per RFC 8410: Ed25519 uses id-Ed25519 (1.3.101.112) with no parameters
    algId := TAlgorithmIdentifier.Create(TEdECObjectIdentifiers.id_Ed25519);

    // Get the raw 32-byte public key encoding
    encodedKey := ed25519Key.GetEncoded();

    pubKeyBits := TDerBitString.Create(encodedKey);

    Result := TSubjectPublicKeyInfo.Create(algId, pubKeyBits);
  end
  else
    raise EArgumentCryptoLibException.Create(SUnsupportedPublicKeyType);
end;

end.
