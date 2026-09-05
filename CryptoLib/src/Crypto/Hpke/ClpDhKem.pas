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

unit ClpDhKem;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpBigInteger,
  ClpBigIntegerUtilities,
  ClpPack,
  ClpConverters,
  ClpArrayUtilities,
  ClpWNafUtilities,
  ClpISecureRandom,
  ClpSecureRandom,
  ClpICipherParameters,
  ClpIAsymmetricKeyParameter,
  ClpIAsymmetricCipherKeyPair,
  ClpAsymmetricCipherKeyPair,
  ClpIRawAgreement,
  ClpECDHRawAgreement,
  ClpX25519Agreement,
  ClpX448Agreement,
  ClpIECCommon,
  ClpIECParameters,
  ClpECParameters,
  ClpIECGenerators,
  ClpECGenerators,
  ClpIX25519Parameters,
  ClpX25519Parameters,
  ClpIX448Parameters,
  ClpX448Parameters,
  ClpX25519,
  ClpX448,
  ClpHpkeTypes,
  ClpIHpkeKdf,
  ClpHpkeKdf,
  ClpIHpkeKem,
  ClpCryptoLibTypes,
  ClpCryptoLibExceptions;

resourcestring
  SInvalidKemId = 'invalid kem id';
  SPkEncodedNil = '''pkEncoded'' cannot be nil';
  SPkEncodedInvalidLength = '''pkEncoded'' has invalid length';
  SPkEncodedInvalidFormat = '''pkEncoded'' has invalid format';
  SSkEncodedNil = '''skEncoded'' cannot be nil';
  SSkEncodedInvalidLength = '''skEncoded'' has invalid length';
  SDeriveKeyPairError = 'DeriveKeyPairError';

type
  /// <summary>
  /// The Diffie-Hellman based KEMs of RFC 9180 sec. 7.1: DHKEM(P-256, SHA-256),
  /// DHKEM(P-384, SHA-384), DHKEM(P-521, SHA-512), DHKEM(X25519, SHA-256) and
  /// DHKEM(X448, SHA-512).
  /// </summary>
  TDhKem = class sealed(TInterfacedObject, IHpkeKem)

  strict private
  var
    FKemId: THpkeKemId;
    FKdf: IHpkeKdf;
    FRawAgreement: IRawAgreement;
    FDomainParams: IECDomainParameters;
    FRandom: ISecureRandom;
    FSuiteId: TCryptoLibByteArray;
    FBitmask: Byte;
    FNsk, FNsecret, FNenc: Int32;

    function IsEc(): Boolean; inline;
    function ValidateSk(const AD: TBigInteger): Boolean;
    function ExtractAndExpand(const ADh, AKemContext: TCryptoLibByteArray)
      : TCryptoLibByteArray;
    function CalculateRawAgreement(const APrivateKey: IAsymmetricKeyParameter;
      const APublicKey: IAsymmetricKeyParameter): TCryptoLibByteArray;

    function GetEncryptionSize(): Int32;

  public
    constructor Create(AKemId: THpkeKemId);

    function GeneratePrivateKey(): IAsymmetricCipherKeyPair;
    function DeriveKeyPair(const AIkm: TCryptoLibByteArray)
      : IAsymmetricCipherKeyPair;

    procedure Encap(const APkR: IAsymmetricKeyParameter;
      out ASharedSecret, AEnc: TCryptoLibByteArray); overload;
    procedure Encap(const APkR: IAsymmetricKeyParameter;
      const AKpE: IAsymmetricCipherKeyPair;
      out ASharedSecret, AEnc: TCryptoLibByteArray); overload;
    procedure AuthEncap(const APkR: IAsymmetricKeyParameter;
      const AKpS: IAsymmetricCipherKeyPair;
      out ASharedSecret, AEnc: TCryptoLibByteArray);

    function Decap(const AEnc: TCryptoLibByteArray;
      const AKpR: IAsymmetricCipherKeyPair): TCryptoLibByteArray;
    function AuthDecap(const AEnc: TCryptoLibByteArray;
      const AKpR: IAsymmetricCipherKeyPair; const APkS: IAsymmetricKeyParameter)
      : TCryptoLibByteArray;

    function SerializePublicKey(const AKey: IAsymmetricKeyParameter)
      : TCryptoLibByteArray;
    function SerializePrivateKey(const AKey: IAsymmetricKeyParameter)
      : TCryptoLibByteArray;
    function DeserializePublicKey(const APkEncoded: TCryptoLibByteArray)
      : IAsymmetricKeyParameter;
    function DeserializePrivateKey(const ASkEncoded,
      APkEncoded: TCryptoLibByteArray): IAsymmetricCipherKeyPair;

    property EncryptionSize: Int32 read GetEncryptionSize;
  end;

implementation

{ TDhKem }

constructor TDhKem.Create(AKemId: THpkeKemId);
begin
  inherited Create();
  FKemId := AKemId;
  FRandom := TSecureRandom.Create() as ISecureRandom;

  case AKemId of
    THpkeKemId.P256_SHA256:
      begin
        FKdf := THpkeKdf.Create(THpkeKdfId.HkdfSha256);
        FDomainParams := TECDomainParameters.LookupName('P-256');
        FRawAgreement := TECDHRawAgreement.Create() as IRawAgreement;
        FBitmask := $FF;
        FNsk := 32;
        FNsecret := 32;
        FNenc := 65;
      end;
    THpkeKemId.P384_SHA384:
      begin
        FKdf := THpkeKdf.Create(THpkeKdfId.HkdfSha384);
        FDomainParams := TECDomainParameters.LookupName('P-384');
        FRawAgreement := TECDHRawAgreement.Create() as IRawAgreement;
        FBitmask := $FF;
        FNsk := 48;
        FNsecret := 48;
        FNenc := 97;
      end;
    THpkeKemId.P521_SHA512:
      begin
        FKdf := THpkeKdf.Create(THpkeKdfId.HkdfSha512);
        FDomainParams := TECDomainParameters.LookupName('P-521');
        FRawAgreement := TECDHRawAgreement.Create() as IRawAgreement;
        FBitmask := $01;
        FNsk := 66;
        FNsecret := 64;
        FNenc := 133;
      end;
    THpkeKemId.X25519_SHA256:
      begin
        FKdf := THpkeKdf.Create(THpkeKdfId.HkdfSha256);
        FRawAgreement := TX25519Agreement.Create() as IRawAgreement;
        FNsk := 32;
        FNsecret := 32;
        FNenc := 32;
      end;
    THpkeKemId.X448_SHA512:
      begin
        FKdf := THpkeKdf.Create(THpkeKdfId.HkdfSha512);
        FRawAgreement := TX448Agreement.Create() as IRawAgreement;
        FNsk := 56;
        FNsecret := 64;
        FNenc := 56;
      end;
  else
    raise EArgumentCryptoLibException.CreateRes(@SInvalidKemId);
  end;

  FSuiteId := TArrayUtilities.Concatenate<Byte>
    ([TConverters.ConvertStringToBytes('KEM', TEncoding.ASCII),
    TPack.UInt16_To_BE(UInt16(Ord(FKemId)))]);
end;

function TDhKem.IsEc: Boolean;
begin
  Result := FKemId in [THpkeKemId.P256_SHA256, THpkeKemId.P384_SHA384,
    THpkeKemId.P521_SHA512];
end;

function TDhKem.GetEncryptionSize: Int32;
begin
  Result := FNenc;
end;

function TDhKem.ValidateSk(const AD: TBigInteger): Boolean;
var
  LN: TBigInteger;
  LMinWeight: Int32;
begin
  LN := FDomainParams.N;
  LMinWeight := LN.BitLength shr 2;

  if (AD.CompareTo(TBigInteger.One) < 0) or (AD.CompareTo(LN) >= 0) then
  begin
    Result := False;
    Exit;
  end;

  if TWNafUtilities.GetNafWeight(AD) < LMinWeight then
  begin
    Result := False;
    Exit;
  end;

  Result := True;
end;

function TDhKem.CalculateRawAgreement(const APrivateKey,
  APublicKey: IAsymmetricKeyParameter): TCryptoLibByteArray;
begin
  FRawAgreement.Init(APrivateKey as ICipherParameters);
  System.SetLength(Result, FRawAgreement.AgreementSize);
  FRawAgreement.CalculateAgreement(APublicKey as ICipherParameters, Result, 0);
end;

function TDhKem.ExtractAndExpand(const ADh, AKemContext: TCryptoLibByteArray)
  : TCryptoLibByteArray;
var
  LEaePrk: TCryptoLibByteArray;
begin
  LEaePrk := FKdf.LabeledExtract(nil, FSuiteId, 'eae_prk', ADh);
  Result := FKdf.LabeledExpand(LEaePrk, FSuiteId, 'shared_secret',
    AKemContext, FNsecret);
  // wipe the raw DH output and the extracted PRK
  TArrayUtilities.Fill(LEaePrk, 0, System.Length(LEaePrk), Byte(0));
  TArrayUtilities.Fill(ADh, 0, System.Length(ADh), Byte(0));
end;

function TDhKem.SerializePublicKey(const AKey: IAsymmetricKeyParameter)
  : TCryptoLibByteArray;
var
  LEcPub: IECPublicKeyParameters;
  LX25519Pub: IX25519PublicKeyParameters;
  LX448Pub: IX448PublicKeyParameters;
begin
  case FKemId of
    THpkeKemId.P256_SHA256, THpkeKemId.P384_SHA384, THpkeKemId.P521_SHA512:
      begin
        LEcPub := AKey as IECPublicKeyParameters;
        Result := LEcPub.Q.GetEncoded(False);
      end;
    THpkeKemId.X25519_SHA256:
      begin
        LX25519Pub := AKey as IX25519PublicKeyParameters;
        Result := LX25519Pub.GetEncoded();
      end;
    THpkeKemId.X448_SHA512:
      begin
        LX448Pub := AKey as IX448PublicKeyParameters;
        Result := LX448Pub.GetEncoded();
      end;
  else
    raise EInvalidOperationCryptoLibException.CreateRes(@SInvalidKemId);
  end;
end;

function TDhKem.SerializePrivateKey(const AKey: IAsymmetricKeyParameter)
  : TCryptoLibByteArray;
var
  LEcPriv: IECPrivateKeyParameters;
  LX25519Priv: IX25519PrivateKeyParameters;
  LX448Priv: IX448PrivateKeyParameters;
begin
  case FKemId of
    THpkeKemId.P256_SHA256, THpkeKemId.P384_SHA384, THpkeKemId.P521_SHA512:
      begin
        LEcPriv := AKey as IECPrivateKeyParameters;
        Result := TBigIntegerUtilities.AsUnsignedByteArray(FNsk, LEcPriv.D);
      end;
    THpkeKemId.X25519_SHA256:
      begin
        LX25519Priv := AKey as IX25519PrivateKeyParameters;
        Result := LX25519Priv.GetEncoded();
        // RFC 9180 sec. 7.1.2: SerializePrivateKey MUST clamp its output.
        TX25519.ClampPrivateKey(Result);
      end;
    THpkeKemId.X448_SHA512:
      begin
        LX448Priv := AKey as IX448PrivateKeyParameters;
        Result := LX448Priv.GetEncoded();
        TX448.ClampPrivateKey(Result);
      end;
  else
    raise EInvalidOperationCryptoLibException.CreateRes(@SInvalidKemId);
  end;
end;

function TDhKem.DeserializePublicKey(const APkEncoded: TCryptoLibByteArray)
  : IAsymmetricKeyParameter;
var
  LPoint: IECPoint;
begin
  if APkEncoded = nil then
  begin
    raise EArgumentNilCryptoLibException.CreateRes(@SPkEncodedNil);
  end;
  if System.Length(APkEncoded) <> FNenc then
  begin
    raise EArgumentCryptoLibException.CreateRes(@SPkEncodedInvalidLength);
  end;

  case FKemId of
    THpkeKemId.P256_SHA256, THpkeKemId.P384_SHA384, THpkeKemId.P521_SHA512:
      begin
        // 0x04 marks the uncompressed encoding.
        if APkEncoded[0] <> $04 then
        begin
          raise EArgumentCryptoLibException.CreateRes(@SPkEncodedInvalidFormat);
        end;
        LPoint := FDomainParams.Curve.DecodePoint(APkEncoded);
        Result := TECPublicKeyParameters.Create(LPoint, FDomainParams);
      end;
    THpkeKemId.X25519_SHA256:
      Result := TX25519PublicKeyParameters.Create(APkEncoded);
    THpkeKemId.X448_SHA512:
      Result := TX448PublicKeyParameters.Create(APkEncoded);
  else
    raise EInvalidOperationCryptoLibException.CreateRes(@SInvalidKemId);
  end;
end;

function TDhKem.DeserializePrivateKey(const ASkEncoded,
  APkEncoded: TCryptoLibByteArray): IAsymmetricCipherKeyPair;
var
  LPub: IAsymmetricKeyParameter;
  LD: TBigInteger;
  LEcPriv: IECPrivateKeyParameters;
  LX25519Priv: IX25519PrivateKeyParameters;
  LX448Priv: IX448PrivateKeyParameters;
begin
  if ASkEncoded = nil then
  begin
    raise EArgumentNilCryptoLibException.CreateRes(@SSkEncodedNil);
  end;
  if System.Length(ASkEncoded) <> FNsk then
  begin
    raise EArgumentCryptoLibException.CreateRes(@SSkEncodedInvalidLength);
  end;

  LPub := nil;
  if APkEncoded <> nil then
  begin
    LPub := DeserializePublicKey(APkEncoded);
  end;

  case FKemId of
    THpkeKemId.P256_SHA256, THpkeKemId.P384_SHA384, THpkeKemId.P521_SHA512:
      begin
        LD := TBigInteger.Create(1, ASkEncoded);
        LEcPriv := TECPrivateKeyParameters.Create(LD, FDomainParams);
        if LPub = nil then
        begin
          LPub := TECKeyPairGenerator.GetCorrespondingPublicKey(LEcPriv);
        end;
        Result := TAsymmetricCipherKeyPair.Create(LPub,
          LEcPriv as IAsymmetricKeyParameter);
      end;
    THpkeKemId.X25519_SHA256:
      begin
        LX25519Priv := TX25519PrivateKeyParameters.Create(ASkEncoded);
        if LPub = nil then
        begin
          LPub := LX25519Priv.GeneratePublicKey();
        end;
        Result := TAsymmetricCipherKeyPair.Create(LPub,
          LX25519Priv as IAsymmetricKeyParameter);
      end;
    THpkeKemId.X448_SHA512:
      begin
        LX448Priv := TX448PrivateKeyParameters.Create(ASkEncoded);
        if LPub = nil then
        begin
          LPub := LX448Priv.GeneratePublicKey();
        end;
        Result := TAsymmetricCipherKeyPair.Create(LPub,
          LX448Priv as IAsymmetricKeyParameter);
      end;
  else
    raise EInvalidOperationCryptoLibException.CreateRes(@SInvalidKemId);
  end;
end;

function TDhKem.GeneratePrivateKey(): IAsymmetricCipherKeyPair;
var
  LGen: IECKeyPairGenerator;
  LX25519Priv: IX25519PrivateKeyParameters;
  LX448Priv: IX448PrivateKeyParameters;
begin
  case FKemId of
    THpkeKemId.P256_SHA256, THpkeKemId.P384_SHA384, THpkeKemId.P521_SHA512:
      begin
        LGen := TECKeyPairGenerator.Create();
        LGen.Init(TECKeyGenerationParameters.Create(FDomainParams, FRandom)
          as IECKeyGenerationParameters);
        Result := LGen.GenerateKeyPair();
      end;
    THpkeKemId.X25519_SHA256:
      begin
        LX25519Priv := TX25519PrivateKeyParameters.Create(FRandom);
        Result := TAsymmetricCipherKeyPair.Create(LX25519Priv.GeneratePublicKey(),
          LX25519Priv as IAsymmetricKeyParameter);
      end;
    THpkeKemId.X448_SHA512:
      begin
        LX448Priv := TX448PrivateKeyParameters.Create(FRandom);
        Result := TAsymmetricCipherKeyPair.Create(LX448Priv.GeneratePublicKey(),
          LX448Priv as IAsymmetricKeyParameter);
      end;
  else
    raise EInvalidOperationCryptoLibException.CreateRes(@SInvalidKemId);
  end;
end;

function TDhKem.DeriveKeyPair(const AIkm: TCryptoLibByteArray)
  : IAsymmetricCipherKeyPair;
var
  LDkpPrk, LBytes, LCounterArray, LSkBytes: TCryptoLibByteArray;
  LCounter: Int32;
  LD: TBigInteger;
  LEcPriv: IECPrivateKeyParameters;
  LPub: IAsymmetricKeyParameter;
  LX25519Priv: IX25519PrivateKeyParameters;
  LX448Priv: IX448PrivateKeyParameters;
begin
  LDkpPrk := FKdf.LabeledExtract(nil, FSuiteId, 'dkp_prk', AIkm);

  if IsEc() then
  begin
    System.SetLength(LCounterArray, 1);
    for LCounter := 0 to 255 do
    begin
      LCounterArray[0] := Byte(LCounter);
      LBytes := FKdf.LabeledExpand(LDkpPrk, FSuiteId, 'candidate',
        LCounterArray, FNsk);
      LBytes[0] := LBytes[0] and FBitmask;

      LD := TBigInteger.Create(1, LBytes);
      // LD holds its own copy; wipe every candidate (accepted or rejected)
      TArrayUtilities.Fill(LBytes, 0, System.Length(LBytes), Byte(0));
      if ValidateSk(LD) then
      begin
        LEcPriv := TECPrivateKeyParameters.Create(LD, FDomainParams);
        LPub := TECKeyPairGenerator.GetCorrespondingPublicKey(LEcPriv);
        Result := TAsymmetricCipherKeyPair.Create(LPub,
          LEcPriv as IAsymmetricKeyParameter);
        TArrayUtilities.Fill(LDkpPrk, 0, System.Length(LDkpPrk), Byte(0));
        Exit;
      end;
    end;
    TArrayUtilities.Fill(LDkpPrk, 0, System.Length(LDkpPrk), Byte(0));
    raise EInvalidOperationCryptoLibException.CreateRes(@SDeriveKeyPairError);
  end;

  LSkBytes := FKdf.LabeledExpand(LDkpPrk, FSuiteId, 'sk', nil, FNsk);
  case FKemId of
    THpkeKemId.X25519_SHA256:
      begin
        LX25519Priv := TX25519PrivateKeyParameters.Create(LSkBytes);
        Result := TAsymmetricCipherKeyPair.Create(LX25519Priv.GeneratePublicKey(),
          LX25519Priv as IAsymmetricKeyParameter);
      end;
    THpkeKemId.X448_SHA512:
      begin
        LX448Priv := TX448PrivateKeyParameters.Create(LSkBytes);
        Result := TAsymmetricCipherKeyPair.Create(LX448Priv.GeneratePublicKey(),
          LX448Priv as IAsymmetricKeyParameter);
      end;
  else
    raise EInvalidOperationCryptoLibException.CreateRes(@SInvalidKemId);
  end;
  // the key params copied the scalar; wipe the derived scalar and PRK
  TArrayUtilities.Fill(LSkBytes, 0, System.Length(LSkBytes), Byte(0));
  TArrayUtilities.Fill(LDkpPrk, 0, System.Length(LDkpPrk), Byte(0));
end;

procedure TDhKem.Encap(const APkR: IAsymmetricKeyParameter;
  out ASharedSecret, AEnc: TCryptoLibByteArray);
begin
  Encap(APkR, GeneratePrivateKey(), ASharedSecret, AEnc);
end;

procedure TDhKem.Encap(const APkR: IAsymmetricKeyParameter;
  const AKpE: IAsymmetricCipherKeyPair;
  out ASharedSecret, AEnc: TCryptoLibByteArray);
var
  LSecret, LPkRm, LKemContext: TCryptoLibByteArray;
begin
  LSecret := CalculateRawAgreement(AKpE.Private, APkR);

  AEnc := SerializePublicKey(AKpE.Public);
  LPkRm := SerializePublicKey(APkR);
  LKemContext := TArrayUtilities.Concatenate<Byte>([AEnc, LPkRm]);

  ASharedSecret := ExtractAndExpand(LSecret, LKemContext);
end;

function TDhKem.Decap(const AEnc: TCryptoLibByteArray;
  const AKpR: IAsymmetricCipherKeyPair): TCryptoLibByteArray;
var
  LPkE: IAsymmetricKeyParameter;
  LSecret, LPkRm, LKemContext: TCryptoLibByteArray;
begin
  LPkE := DeserializePublicKey(AEnc);
  LSecret := CalculateRawAgreement(AKpR.Private, LPkE);

  LPkRm := SerializePublicKey(AKpR.Public);
  LKemContext := TArrayUtilities.Concatenate<Byte>([AEnc, LPkRm]);

  Result := ExtractAndExpand(LSecret, LKemContext);
end;

procedure TDhKem.AuthEncap(const APkR: IAsymmetricKeyParameter;
  const AKpS: IAsymmetricCipherKeyPair;
  out ASharedSecret, AEnc: TCryptoLibByteArray);
var
  LKpE: IAsymmetricCipherKeyPair;
  LAgreementSize: Int32;
  LSecret, LPkRm, LPkSm, LKemContext: TCryptoLibByteArray;
begin
  LKpE := GeneratePrivateKey();

  FRawAgreement.Init(LKpE.Private as ICipherParameters);
  LAgreementSize := FRawAgreement.AgreementSize;

  System.SetLength(LSecret, LAgreementSize * 2);
  // DH(skE, pkR)
  FRawAgreement.CalculateAgreement(APkR as ICipherParameters, LSecret, 0);
  // DH(skS, pkR)
  FRawAgreement.Init(AKpS.Private as ICipherParameters);
  FRawAgreement.CalculateAgreement(APkR as ICipherParameters, LSecret,
    LAgreementSize);

  AEnc := SerializePublicKey(LKpE.Public);
  LPkRm := SerializePublicKey(APkR);
  LPkSm := SerializePublicKey(AKpS.Public);
  LKemContext := TArrayUtilities.Concatenate<Byte>([AEnc, LPkRm, LPkSm]);

  ASharedSecret := ExtractAndExpand(LSecret, LKemContext);
end;

function TDhKem.AuthDecap(const AEnc: TCryptoLibByteArray;
  const AKpR: IAsymmetricCipherKeyPair; const APkS: IAsymmetricKeyParameter)
  : TCryptoLibByteArray;
var
  LPkE: IAsymmetricKeyParameter;
  LAgreementSize: Int32;
  LSecret, LPkRm, LPkSm, LKemContext: TCryptoLibByteArray;
begin
  LPkE := DeserializePublicKey(AEnc);

  FRawAgreement.Init(AKpR.Private as ICipherParameters);
  LAgreementSize := FRawAgreement.AgreementSize;

  System.SetLength(LSecret, LAgreementSize * 2);
  // DH(skR, pkE)
  FRawAgreement.CalculateAgreement(LPkE as ICipherParameters, LSecret, 0);
  // DH(skR, pkS)
  FRawAgreement.CalculateAgreement(APkS as ICipherParameters, LSecret,
    LAgreementSize);

  LPkRm := SerializePublicKey(AKpR.Public);
  LPkSm := SerializePublicKey(APkS);
  LKemContext := TArrayUtilities.Concatenate<Byte>([AEnc, LPkRm, LPkSm]);

  Result := ExtractAndExpand(LSecret, LKemContext);
end;

end.
