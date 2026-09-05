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

unit ClpHpke;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpPack,
  ClpConverters,
  ClpArrayUtilities,
  ClpIAsymmetricKeyParameter,
  ClpIAsymmetricCipherKeyPair,
  ClpHpkeTypes,
  ClpIHpkeKdf,
  ClpHpkeKdf,
  ClpIHpkeKem,
  ClpDhKem,
  ClpIHpkeAead,
  ClpHpkeAead,
  ClpIHpkeContext,
  ClpHpkeContext,
  ClpIHpke,
  ClpCryptoLibTypes,
  ClpCryptoLibExceptions;

resourcestring
  SInconsistentPskInputs = 'Inconsistent PSK inputs';
  SPskNotNeeded = 'PSK input provided when not needed';
  SPskRequired = 'Missing required PSK input';

type
  /// <summary>
  /// Hybrid Public Key Encryption facade (RFC 9180). Pins a
  /// (mode, KEM, KDF, AEAD) suite via the constructor.
  /// </summary>
  THpke = class sealed(TInterfacedObject, IHpke)

  strict private
  const
    NonceSize = Int32(12);

  var
    FMode: THpkeMode;
    FAeadId: THpkeAeadId;
    FKem: IHpkeKem;
    FKdf: IHpkeKdf;
    FSuiteId: TCryptoLibByteArray;
    FNk, FEncSize: Int32;

    function GetEncSize(): Int32;
    function GetAeadId(): THpkeAeadId;
    procedure VerifyPskInputs(AMode: THpkeMode;
      const APsk, APskId: TCryptoLibByteArray);
    procedure KeySchedule(AMode: THpkeMode;
      const ASharedSecret, AInfo, APsk, APskId: TCryptoLibByteArray;
      out AAead: IHpkeAead; out AExporterSecret: TCryptoLibByteArray);

  public
    constructor Create(AMode: THpkeMode; AKemId: THpkeKemId;
      AKdfId: THpkeKdfId; AAeadId: THpkeAeadId);

    function GeneratePrivateKey(): IAsymmetricCipherKeyPair;
    function DeriveKeyPair(const AIkm: TCryptoLibByteArray)
      : IAsymmetricCipherKeyPair;

    function SerializePublicKey(const APk: IAsymmetricKeyParameter)
      : TCryptoLibByteArray;
    function SerializePrivateKey(const ASk: IAsymmetricKeyParameter)
      : TCryptoLibByteArray;
    function DeserializePublicKey(const APkEncoded: TCryptoLibByteArray)
      : IAsymmetricKeyParameter;
    function DeserializePrivateKey(const ASkEncoded,
      APkEncoded: TCryptoLibByteArray): IAsymmetricCipherKeyPair;

    function SetupBaseS(const APkR: IAsymmetricKeyParameter;
      const AInfo: TCryptoLibByteArray): IHpkeContextWithEncapsulation;
    function SetupBaseR(const AEnc: TCryptoLibByteArray;
      const ASkR: IAsymmetricCipherKeyPair; const AInfo: TCryptoLibByteArray)
      : IHpkeContext;

    function SetupPskS(const APkR: IAsymmetricKeyParameter;
      const AInfo, APsk, APskId: TCryptoLibByteArray)
      : IHpkeContextWithEncapsulation;
    function SetupPskR(const AEnc: TCryptoLibByteArray;
      const ASkR: IAsymmetricCipherKeyPair;
      const AInfo, APsk, APskId: TCryptoLibByteArray): IHpkeContext;

    function SetupAuthS(const APkR: IAsymmetricKeyParameter;
      const AInfo: TCryptoLibByteArray; const ASkS: IAsymmetricCipherKeyPair)
      : IHpkeContextWithEncapsulation;
    function SetupAuthR(const AEnc: TCryptoLibByteArray;
      const ASkR: IAsymmetricCipherKeyPair; const AInfo: TCryptoLibByteArray;
      const APkS: IAsymmetricKeyParameter): IHpkeContext;

    function SetupAuthPskS(const APkR: IAsymmetricKeyParameter;
      const AInfo, APsk, APskId: TCryptoLibByteArray;
      const ASkS: IAsymmetricCipherKeyPair): IHpkeContextWithEncapsulation;
    function SetupAuthPskR(const AEnc: TCryptoLibByteArray;
      const ASkR: IAsymmetricCipherKeyPair;
      const AInfo, APsk, APskId: TCryptoLibByteArray;
      const APkS: IAsymmetricKeyParameter): IHpkeContext;

    procedure Seal(const APkR: IAsymmetricKeyParameter;
      const AInfo, AAad, APt, APsk, APskId: TCryptoLibByteArray;
      const ASkS: IAsymmetricCipherKeyPair;
      out ACt, AEnc: TCryptoLibByteArray);

    function Open(const AEnc: TCryptoLibByteArray;
      const ASkR: IAsymmetricCipherKeyPair;
      const AInfo, AAad, ACt, APsk, APskId: TCryptoLibByteArray;
      const APkS: IAsymmetricKeyParameter): TCryptoLibByteArray;

    procedure SendExport(const APkR: IAsymmetricKeyParameter;
      const AInfo, AExporterContext: TCryptoLibByteArray; AL: Int32;
      const APsk, APskId: TCryptoLibByteArray;
      const ASkS: IAsymmetricCipherKeyPair;
      out AEnc, AExported: TCryptoLibByteArray);

    function ReceiveExport(const AEnc: TCryptoLibByteArray;
      const ASkR: IAsymmetricCipherKeyPair;
      const AInfo, AExporterContext: TCryptoLibByteArray; AL: Int32;
      const APsk, APskId: TCryptoLibByteArray;
      const APkS: IAsymmetricKeyParameter): TCryptoLibByteArray;

    property EncSize: Int32 read GetEncSize;
    property AeadId: THpkeAeadId read GetAeadId;
  end;

implementation

{ THpke }

constructor THpke.Create(AMode: THpkeMode; AKemId: THpkeKemId;
  AKdfId: THpkeKdfId; AAeadId: THpkeAeadId);
begin
  inherited Create();
  FMode := AMode;
  FAeadId := AAeadId;
  FKdf := THpkeKdf.Create(AKdfId);
  FKem := TDhKem.Create(AKemId);

  if AAeadId = THpkeAeadId.AesGcm128 then
  begin
    FNk := 16;
  end
  else
  begin
    FNk := 32;
  end;

  FEncSize := FKem.EncryptionSize;

  FSuiteId := TArrayUtilities.Concatenate<Byte>
    ([TConverters.ConvertStringToBytes('HPKE', TEncoding.ASCII),
    TPack.UInt16_To_BE(UInt16(Ord(AKemId))),
    TPack.UInt16_To_BE(UInt16(Ord(AKdfId))),
    TPack.UInt16_To_BE(UInt16(Ord(AAeadId)))]);
end;

function THpke.GetEncSize: Int32;
begin
  Result := FEncSize;
end;

function THpke.GetAeadId: THpkeAeadId;
begin
  Result := FAeadId;
end;

procedure THpke.VerifyPskInputs(AMode: THpkeMode;
  const APsk, APskId: TCryptoLibByteArray);
var
  LGotPsk, LGotPskId: Boolean;
begin
  LGotPsk := APsk <> nil;
  LGotPskId := APskId <> nil;

  if LGotPsk <> LGotPskId then
  begin
    raise EArgumentCryptoLibException.CreateRes(@SInconsistentPskInputs);
  end;

  if LGotPsk and ((Ord(AMode) mod 2) = 0) then
  begin
    raise EArgumentCryptoLibException.CreateRes(@SPskNotNeeded);
  end;
  if (not LGotPsk) and ((Ord(AMode) mod 2) = 1) then
  begin
    raise EArgumentCryptoLibException.CreateRes(@SPskRequired);
  end;
end;

procedure THpke.KeySchedule(AMode: THpkeMode;
  const ASharedSecret, AInfo, APsk, APskId: TCryptoLibByteArray;
  out AAead: IHpkeAead; out AExporterSecret: TCryptoLibByteArray);
var
  LPskIdHash, LInfoHash, LModeArray, LKsContext, LSecret, LKey,
    LBaseNonce: TCryptoLibByteArray;
begin
  VerifyPskInputs(AMode, APsk, APskId);

  LPskIdHash := FKdf.LabeledExtract(nil, FSuiteId, 'psk_id_hash', APskId);
  LInfoHash := FKdf.LabeledExtract(nil, FSuiteId, 'info_hash', AInfo);

  System.SetLength(LModeArray, 1);
  LModeArray[0] := Byte(Ord(AMode));
  LKsContext := TArrayUtilities.Concatenate<Byte>([LModeArray, LPskIdHash,
    LInfoHash]);

  LSecret := FKdf.LabeledExtract(ASharedSecret, FSuiteId, 'secret', APsk);

  LKey := FKdf.LabeledExpand(LSecret, FSuiteId, 'key', LKsContext, FNk);
  LBaseNonce := FKdf.LabeledExpand(LSecret, FSuiteId, 'base_nonce', LKsContext,
    NonceSize);
  AExporterSecret := FKdf.LabeledExpand(LSecret, FSuiteId, 'exp', LKsContext,
    FKdf.HashSize);

  AAead := THpkeAead.Create(FAeadId, LKey, LBaseNonce) as IHpkeAead;

  TArrayUtilities.Fill(LKey, 0, System.Length(LKey), Byte(0));
  TArrayUtilities.Fill(LBaseNonce, 0, System.Length(LBaseNonce), Byte(0));
  TArrayUtilities.Fill(LSecret, 0, System.Length(LSecret), Byte(0));
  TArrayUtilities.Fill(ASharedSecret, 0, System.Length(ASharedSecret), Byte(0));
end;

function THpke.GeneratePrivateKey: IAsymmetricCipherKeyPair;
begin
  Result := FKem.GeneratePrivateKey();
end;

function THpke.DeriveKeyPair(const AIkm: TCryptoLibByteArray)
  : IAsymmetricCipherKeyPair;
begin
  Result := FKem.DeriveKeyPair(AIkm);
end;

function THpke.SerializePublicKey(const APk: IAsymmetricKeyParameter)
  : TCryptoLibByteArray;
begin
  Result := FKem.SerializePublicKey(APk);
end;

function THpke.SerializePrivateKey(const ASk: IAsymmetricKeyParameter)
  : TCryptoLibByteArray;
begin
  Result := FKem.SerializePrivateKey(ASk);
end;

function THpke.DeserializePublicKey(const APkEncoded: TCryptoLibByteArray)
  : IAsymmetricKeyParameter;
begin
  Result := FKem.DeserializePublicKey(APkEncoded);
end;

function THpke.DeserializePrivateKey(const ASkEncoded,
  APkEncoded: TCryptoLibByteArray): IAsymmetricCipherKeyPair;
begin
  Result := FKem.DeserializePrivateKey(ASkEncoded, APkEncoded);
end;

function THpke.SetupBaseS(const APkR: IAsymmetricKeyParameter;
  const AInfo: TCryptoLibByteArray): IHpkeContextWithEncapsulation;
var
  LSharedSecret, LEnc, LExporterSecret: TCryptoLibByteArray;
  LAead: IHpkeAead;
begin
  FKem.Encap(APkR, LSharedSecret, LEnc);
  KeySchedule(THpkeMode.Base, LSharedSecret, AInfo, nil, nil, LAead,
    LExporterSecret);
  Result := THpkeContextWithEncapsulation.Create(LAead, FKdf, LExporterSecret,
    FSuiteId, LEnc);
end;

function THpke.SetupBaseR(const AEnc: TCryptoLibByteArray;
  const ASkR: IAsymmetricCipherKeyPair; const AInfo: TCryptoLibByteArray)
  : IHpkeContext;
var
  LSharedSecret, LExporterSecret: TCryptoLibByteArray;
  LAead: IHpkeAead;
begin
  LSharedSecret := FKem.Decap(AEnc, ASkR);
  KeySchedule(THpkeMode.Base, LSharedSecret, AInfo, nil, nil, LAead,
    LExporterSecret);
  Result := THpkeContext.Create(LAead, FKdf, LExporterSecret, FSuiteId);
end;

function THpke.SetupPskS(const APkR: IAsymmetricKeyParameter;
  const AInfo, APsk, APskId: TCryptoLibByteArray)
  : IHpkeContextWithEncapsulation;
var
  LSharedSecret, LEnc, LExporterSecret: TCryptoLibByteArray;
  LAead: IHpkeAead;
begin
  FKem.Encap(APkR, LSharedSecret, LEnc);
  KeySchedule(THpkeMode.Psk, LSharedSecret, AInfo, APsk, APskId, LAead,
    LExporterSecret);
  Result := THpkeContextWithEncapsulation.Create(LAead, FKdf, LExporterSecret,
    FSuiteId, LEnc);
end;

function THpke.SetupPskR(const AEnc: TCryptoLibByteArray;
  const ASkR: IAsymmetricCipherKeyPair;
  const AInfo, APsk, APskId: TCryptoLibByteArray): IHpkeContext;
var
  LSharedSecret, LExporterSecret: TCryptoLibByteArray;
  LAead: IHpkeAead;
begin
  LSharedSecret := FKem.Decap(AEnc, ASkR);
  KeySchedule(THpkeMode.Psk, LSharedSecret, AInfo, APsk, APskId, LAead,
    LExporterSecret);
  Result := THpkeContext.Create(LAead, FKdf, LExporterSecret, FSuiteId);
end;

function THpke.SetupAuthS(const APkR: IAsymmetricKeyParameter;
  const AInfo: TCryptoLibByteArray; const ASkS: IAsymmetricCipherKeyPair)
  : IHpkeContextWithEncapsulation;
var
  LSharedSecret, LEnc, LExporterSecret: TCryptoLibByteArray;
  LAead: IHpkeAead;
begin
  FKem.AuthEncap(APkR, ASkS, LSharedSecret, LEnc);
  KeySchedule(THpkeMode.Auth, LSharedSecret, AInfo, nil, nil, LAead,
    LExporterSecret);
  Result := THpkeContextWithEncapsulation.Create(LAead, FKdf, LExporterSecret,
    FSuiteId, LEnc);
end;

function THpke.SetupAuthR(const AEnc: TCryptoLibByteArray;
  const ASkR: IAsymmetricCipherKeyPair; const AInfo: TCryptoLibByteArray;
  const APkS: IAsymmetricKeyParameter): IHpkeContext;
var
  LSharedSecret, LExporterSecret: TCryptoLibByteArray;
  LAead: IHpkeAead;
begin
  LSharedSecret := FKem.AuthDecap(AEnc, ASkR, APkS);
  KeySchedule(THpkeMode.Auth, LSharedSecret, AInfo, nil, nil, LAead,
    LExporterSecret);
  Result := THpkeContext.Create(LAead, FKdf, LExporterSecret, FSuiteId);
end;

function THpke.SetupAuthPskS(const APkR: IAsymmetricKeyParameter;
  const AInfo, APsk, APskId: TCryptoLibByteArray;
  const ASkS: IAsymmetricCipherKeyPair): IHpkeContextWithEncapsulation;
var
  LSharedSecret, LEnc, LExporterSecret: TCryptoLibByteArray;
  LAead: IHpkeAead;
begin
  FKem.AuthEncap(APkR, ASkS, LSharedSecret, LEnc);
  KeySchedule(THpkeMode.AuthPsk, LSharedSecret, AInfo, APsk, APskId, LAead,
    LExporterSecret);
  Result := THpkeContextWithEncapsulation.Create(LAead, FKdf, LExporterSecret,
    FSuiteId, LEnc);
end;

function THpke.SetupAuthPskR(const AEnc: TCryptoLibByteArray;
  const ASkR: IAsymmetricCipherKeyPair;
  const AInfo, APsk, APskId: TCryptoLibByteArray;
  const APkS: IAsymmetricKeyParameter): IHpkeContext;
var
  LSharedSecret, LExporterSecret: TCryptoLibByteArray;
  LAead: IHpkeAead;
begin
  LSharedSecret := FKem.AuthDecap(AEnc, ASkR, APkS);
  KeySchedule(THpkeMode.AuthPsk, LSharedSecret, AInfo, APsk, APskId, LAead,
    LExporterSecret);
  Result := THpkeContext.Create(LAead, FKdf, LExporterSecret, FSuiteId);
end;

procedure THpke.Seal(const APkR: IAsymmetricKeyParameter;
  const AInfo, AAad, APt, APsk, APskId: TCryptoLibByteArray;
  const ASkS: IAsymmetricCipherKeyPair; out ACt, AEnc: TCryptoLibByteArray);
var
  LCtx: IHpkeContextWithEncapsulation;
begin
  case FMode of
    THpkeMode.Base:
      LCtx := SetupBaseS(APkR, AInfo);
    THpkeMode.Auth:
      LCtx := SetupAuthS(APkR, AInfo, ASkS);
    THpkeMode.Psk:
      LCtx := SetupPskS(APkR, AInfo, APsk, APskId);
    THpkeMode.AuthPsk:
      LCtx := SetupAuthPskS(APkR, AInfo, APsk, APskId, ASkS);
  end;
  ACt := LCtx.Seal(AAad, APt);
  AEnc := LCtx.GetEncapsulation();
end;

function THpke.Open(const AEnc: TCryptoLibByteArray;
  const ASkR: IAsymmetricCipherKeyPair;
  const AInfo, AAad, ACt, APsk, APskId: TCryptoLibByteArray;
  const APkS: IAsymmetricKeyParameter): TCryptoLibByteArray;
var
  LCtx: IHpkeContext;
begin
  case FMode of
    THpkeMode.Base:
      LCtx := SetupBaseR(AEnc, ASkR, AInfo);
    THpkeMode.Auth:
      LCtx := SetupAuthR(AEnc, ASkR, AInfo, APkS);
    THpkeMode.Psk:
      LCtx := SetupPskR(AEnc, ASkR, AInfo, APsk, APskId);
    THpkeMode.AuthPsk:
      LCtx := SetupAuthPskR(AEnc, ASkR, AInfo, APsk, APskId, APkS);
  end;
  Result := LCtx.Open(AAad, ACt);
end;

procedure THpke.SendExport(const APkR: IAsymmetricKeyParameter;
  const AInfo, AExporterContext: TCryptoLibByteArray; AL: Int32;
  const APsk, APskId: TCryptoLibByteArray;
  const ASkS: IAsymmetricCipherKeyPair; out AEnc, AExported: TCryptoLibByteArray);
var
  LCtx: IHpkeContextWithEncapsulation;
begin
  case FMode of
    THpkeMode.Base:
      LCtx := SetupBaseS(APkR, AInfo);
    THpkeMode.Auth:
      LCtx := SetupAuthS(APkR, AInfo, ASkS);
    THpkeMode.Psk:
      LCtx := SetupPskS(APkR, AInfo, APsk, APskId);
    THpkeMode.AuthPsk:
      LCtx := SetupAuthPskS(APkR, AInfo, APsk, APskId, ASkS);
  end;
  AEnc := LCtx.GetEncapsulation();
  AExported := LCtx.Export(AExporterContext, AL);
end;

function THpke.ReceiveExport(const AEnc: TCryptoLibByteArray;
  const ASkR: IAsymmetricCipherKeyPair;
  const AInfo, AExporterContext: TCryptoLibByteArray; AL: Int32;
  const APsk, APskId: TCryptoLibByteArray;
  const APkS: IAsymmetricKeyParameter): TCryptoLibByteArray;
var
  LCtx: IHpkeContext;
begin
  case FMode of
    THpkeMode.Base:
      LCtx := SetupBaseR(AEnc, ASkR, AInfo);
    THpkeMode.Auth:
      LCtx := SetupAuthR(AEnc, ASkR, AInfo, APkS);
    THpkeMode.Psk:
      LCtx := SetupPskR(AEnc, ASkR, AInfo, APsk, APskId);
    THpkeMode.AuthPsk:
      LCtx := SetupAuthPskR(AEnc, ASkR, AInfo, APsk, APskId, APkS);
  end;
  Result := LCtx.Export(AExporterContext, AL);
end;

end.
