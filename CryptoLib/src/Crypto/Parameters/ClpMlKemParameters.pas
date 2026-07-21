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

unit ClpMlKemParameters;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  Generics.Collections,
  ClpAsymmetricKeyParameter,
  ClpIMlKemParameters,
  ClpIMlKemEngine,
  ClpISecureRandom,
  ClpMlKemEngine,
  ClpMlKemCore,
  ClpNistObjectIdentifiers,
  ClpIAsn1Objects,
  ClpAsn1Comparers,
  ClpCryptoLibComparers,
  ClpKeyGenerationParameters,
  ClpCryptoLibTypes,
  ClpCryptoLibExceptions;

resourcestring
  SInvalidMlKemLength = 'invalid length';
  SModulusCheckFailed = 'modulus check failed';
  SHashCheckFailed = 'hash check failed';
  SNoSeedAvailable = 'no seed available';
  SInvalidMlKemFormat = 'invalid format';
  SUnrecognisedMlKemOid = 'unrecognised ML-KEM parameters OID';
  SParametersNil = 'parameters cannot be nil';
  SRandomNil = 'random cannot be nil';

type
  TMlKemParameterSet = class sealed(TInterfacedObject, IMlKemParameterSet)
  strict private
  class var
    FMlKem512: IMlKemParameterSet;
    FMlKem768: IMlKemParameterSet;
    FMlKem1024: IMlKemParameterSet;
  var
    FName: String;
    FEngine: IMlKemEngine;
  public
    class constructor Create;
    class destructor Destroy;
    class function FromName(const AName: String): IMlKemParameterSet; static;
    constructor Create(const AName: String; AK: Int32); overload;
    function GetName: String;
    function GetEncapsulationLength: Int32;
    function GetSecretLength: Int32;
    function GetEngine: IMlKemEngine;

    class property MlKem512: IMlKemParameterSet read FMlKem512;
    class property MlKem768: IMlKemParameterSet read FMlKem768;
    class property MlKem1024: IMlKemParameterSet read FMlKem1024;
  end;

  TMlKemParameters = class sealed(TObject)
  strict private
  class var
    FByName: TDictionary<string, IMlKemParameters>;
    FByOid: TDictionary<IDerObjectIdentifier, IMlKemParameters>;
    FMlKem512: IMlKemParameters;
    FMlKem768: IMlKemParameters;
    FMlKem1024: IMlKemParameters;
  var
    FName: String;
    FParameterSet: IMlKemParameterSet;
    FOid: IDerObjectIdentifier;
  public
    class constructor Create;
    class destructor Destroy;
    class function ByName: TDictionary<string, IMlKemParameters>; static;
    class function ByOid: TDictionary<IDerObjectIdentifier, IMlKemParameters>; static;
    class function GetByName(const AName: String): IMlKemParameters; static;
    class function GetByOid(const AOid: IDerObjectIdentifier): IMlKemParameters; static;
    constructor Create(const AName: String; const AParameterSet: IMlKemParameterSet;
      const AOid: IDerObjectIdentifier); overload;
    function GetName: String;
    function GetParameterSet: IMlKemParameterSet;
    function GetOid: IDerObjectIdentifier;

    class property MlKem512: IMlKemParameters read FMlKem512;
    class property MlKem768: IMlKemParameters read FMlKem768;
    class property MlKem1024: IMlKemParameters read FMlKem1024;
  end;

  TMlKemParametersImpl = class sealed(TInterfacedObject, IMlKemParameters)
  strict private
  var
    FName: String;
    FParameterSet: IMlKemParameterSet;
    FOid: IDerObjectIdentifier;
  public
    constructor Create(const AName: String; const AParameterSet: IMlKemParameterSet;
      const AOid: IDerObjectIdentifier);
    function GetName: String;
    function GetParameterSet: IMlKemParameterSet;
    function GetOid: IDerObjectIdentifier;
  end;

  TMlKemKeyParameters = class abstract(TAsymmetricKeyParameter, IMlKemKeyParameters)
  strict private
  var
    FParameters: IMlKemParameters;
  strict protected
    constructor Create(APrivateKey: Boolean; const AParameters: IMlKemParameters);
  public
    function GetParameters: IMlKemParameters;
    property Parameters: IMlKemParameters read GetParameters;
  end;

  TMlKemPublicKeyParameters = class sealed(TMlKemKeyParameters, IMlKemPublicKeyParameters)
  strict private
  var
    FEncoding: TCryptoLibByteArray;
    procedure InternalEncapsulate(const ARandBytes: TCryptoLibByteArray;
      const AEnc, ASec: TCryptoLibByteArray; AEncOff, ASecOff: Int32);
  public
    class function FromEncoding(const AParameters: IMlKemParameters;
      const AEncoding: TCryptoLibByteArray): IMlKemPublicKeyParameters; static;
    constructor Create(const AParameters: IMlKemParameters; const AEncoding: TCryptoLibByteArray);
    function GetEncoded(): TCryptoLibByteArray;
    function GetEncoding: TCryptoLibByteArray;
  end;

  TMlKemPrivateKeyParameters = class sealed(TMlKemKeyParameters, IMlKemPrivateKeyParameters)
  strict private
  var
    FSeed: TCryptoLibByteArray;
    FEncoding: TCryptoLibByteArray;
    FPreferredFormat: TMlKemPrivateKeyFormat;
    class function CheckFormat(AFormat: TMlKemPrivateKeyFormat;
      const ASeed: TCryptoLibByteArray): TMlKemPrivateKeyFormat; static;
  public
    class function FromEncoding(const AParameters: IMlKemParameters;
      const AEncoding: TCryptoLibByteArray): IMlKemPrivateKeyParameters; static;
    class function FromSeed(const AParameters: IMlKemParameters;
      const ASeed: TCryptoLibByteArray): IMlKemPrivateKeyParameters; overload; static;
    class function FromSeed(const AParameters: IMlKemParameters;
      const ASeed: TCryptoLibByteArray; APreferredFormat: TMlKemPrivateKeyFormat): IMlKemPrivateKeyParameters; overload; static;
    constructor Create(const AParameters: IMlKemParameters; const ASeed, AEncoding: TCryptoLibByteArray;
      APreferredFormat: TMlKemPrivateKeyFormat);
    function GetEncoded(): TCryptoLibByteArray;
    function GetSeed(): TCryptoLibByteArray;
    function GetPublicKey(): IMlKemPublicKeyParameters;
    function GetPublicKeyEncoded(): TCryptoLibByteArray;
    function GetPreferredFormat: TMlKemPrivateKeyFormat;
    function WithPreferredFormat(AFormat: TMlKemPrivateKeyFormat): IMlKemPrivateKeyParameters;
    function GetEncoding: TCryptoLibByteArray;
  end;

  TMlKemKeyGenerationParameters = class sealed(TKeyGenerationParameters,
    IMlKemKeyGenerationParameters)
  strict private
  var
    FParameters: IMlKemParameters;
  public
    constructor Create(const ARandom: ISecureRandom; const AParameters: IMlKemParameters); overload;
    constructor Create(const ARandom: ISecureRandom; const AParametersOid: IDerObjectIdentifier); overload;
    function GetParameters: IMlKemParameters;
  end;

implementation

{ TMlKemParameterSet }

class constructor TMlKemParameterSet.Create;
begin
  FMlKem512 := TMlKemParameterSet.Create('ML-KEM-512', 2);
  FMlKem768 := TMlKemParameterSet.Create('ML-KEM-768', 3);
  FMlKem1024 := TMlKemParameterSet.Create('ML-KEM-1024', 4);
end;

class destructor TMlKemParameterSet.Destroy;
begin
  FMlKem512 := nil;
  FMlKem768 := nil;
  FMlKem1024 := nil;
end;

constructor TMlKemParameterSet.Create(const AName: String; AK: Int32);
begin
  inherited Create;
  FName := AName;
  FEngine := TMlKemEngine.Create(AK);
end;

class function TMlKemParameterSet.FromName(const AName: String): IMlKemParameterSet;
begin
  if SameText(AName, 'ML-KEM-512') then
    Result := MlKem512
  else if SameText(AName, 'ML-KEM-768') then
    Result := MlKem768
  else if SameText(AName, 'ML-KEM-1024') then
    Result := MlKem1024
  else
    Result := nil;
end;

function TMlKemParameterSet.GetEncapsulationLength: Int32;
begin
  Result := FEngine.CipherTextBytes;
end;

function TMlKemParameterSet.GetEngine: IMlKemEngine;
begin
  Result := FEngine;
end;

function TMlKemParameterSet.GetName: String;
begin
  Result := FName;
end;

function TMlKemParameterSet.GetSecretLength: Int32;
begin
  Result := TMlKemEngine.SharedSecretBytes;
end;

{ TMlKemParameters }

class constructor TMlKemParameters.Create;
begin
  FMlKem512 := TMlKemParametersImpl.Create('ML-KEM-512', TMlKemParameterSet.MlKem512,
    TNistObjectIdentifiers.IdAlgMlKem512);
  FMlKem768 := TMlKemParametersImpl.Create('ML-KEM-768', TMlKemParameterSet.MlKem768,
    TNistObjectIdentifiers.IdAlgMlKem768);
  FMlKem1024 := TMlKemParametersImpl.Create('ML-KEM-1024', TMlKemParameterSet.MlKem1024,
    TNistObjectIdentifiers.IdAlgMlKem1024);
  FByName := TDictionary<string, IMlKemParameters>.Create(
    TCryptoLibComparers.OrdinalIgnoreCaseEqualityComparer);
  FByName.Add('ML-KEM-512', MlKem512);
  FByName.Add('ML-KEM-768', MlKem768);
  FByName.Add('ML-KEM-1024', MlKem1024);
  FByOid := TDictionary<IDerObjectIdentifier, IMlKemParameters>.Create(
    TAsn1Comparers.OidEqualityComparer);
  FByOid.Add(MlKem512.Oid, MlKem512);
  FByOid.Add(MlKem768.Oid, MlKem768);
  FByOid.Add(MlKem1024.Oid, MlKem1024);
end;

class destructor TMlKemParameters.Destroy;
begin
  FByOid.Free;
  FByName.Free;
  FMlKem512 := nil;
  FMlKem768 := nil;
  FMlKem1024 := nil;
end;

class function TMlKemParameters.ByName: TDictionary<string, IMlKemParameters>;
begin
  Result := FByName;
end;

class function TMlKemParameters.ByOid: TDictionary<IDerObjectIdentifier, IMlKemParameters>;
begin
  Result := FByOid;
end;

class function TMlKemParameters.GetByName(const AName: String): IMlKemParameters;
begin
  if not FByName.TryGetValue(AName, Result) then
    Result := nil;
end;

class function TMlKemParameters.GetByOid(const AOid: IDerObjectIdentifier): IMlKemParameters;
begin
  if not FByOid.TryGetValue(AOid, Result) then
    Result := nil;
end;

constructor TMlKemParameters.Create(const AName: String;
  const AParameterSet: IMlKemParameterSet; const AOid: IDerObjectIdentifier);
begin
  inherited Create;
  FName := AName;
  FParameterSet := AParameterSet;
  FOid := AOid;
end;

function TMlKemParameters.GetName: String;
begin
  Result := FName;
end;

function TMlKemParameters.GetOid: IDerObjectIdentifier;
begin
  Result := FOid;
end;

function TMlKemParameters.GetParameterSet: IMlKemParameterSet;
begin
  Result := FParameterSet;
end;

{ TMlKemParametersImpl }

constructor TMlKemParametersImpl.Create(const AName: String;
  const AParameterSet: IMlKemParameterSet; const AOid: IDerObjectIdentifier);
begin
  inherited Create;
  FName := AName;
  FParameterSet := AParameterSet;
  FOid := AOid;
end;

function TMlKemParametersImpl.GetName: String;
begin
  Result := FName;
end;

function TMlKemParametersImpl.GetOid: IDerObjectIdentifier;
begin
  Result := FOid;
end;

function TMlKemParametersImpl.GetParameterSet: IMlKemParameterSet;
begin
  Result := FParameterSet;
end;

{ TMlKemKeyParameters }

constructor TMlKemKeyParameters.Create(APrivateKey: Boolean;
  const AParameters: IMlKemParameters);
begin
  inherited Create(APrivateKey);
  FParameters := AParameters;
end;

function TMlKemKeyParameters.GetParameters: IMlKemParameters;
begin
  Result := FParameters;
end;

{ TMlKemPublicKeyParameters }

class function TMlKemPublicKeyParameters.FromEncoding(const AParameters: IMlKemParameters;
  const AEncoding: TCryptoLibByteArray): IMlKemPublicKeyParameters;
var
  LEngine: IMlKemEngine;
  LCopy: TCryptoLibByteArray;
begin
  if AParameters = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SParametersNil);
  if AEncoding = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SParametersNil);
  LEngine := AParameters.ParameterSet.Engine;
  if System.Length(AEncoding) <> LEngine.PublicKeyBytes then
    raise EArgumentCryptoLibException.CreateRes(@SInvalidMlKemLength);
  LCopy := System.Copy(AEncoding);
  if not LEngine.CheckEncapKeyModulus(LCopy) then
    raise EArgumentCryptoLibException.CreateRes(@SModulusCheckFailed);
  Result := TMlKemPublicKeyParameters.Create(AParameters, LCopy);
end;

constructor TMlKemPublicKeyParameters.Create(const AParameters: IMlKemParameters;
  const AEncoding: TCryptoLibByteArray);
begin
  inherited Create(False, AParameters);
  FEncoding := AEncoding;
end;

function TMlKemPublicKeyParameters.GetEncoded: TCryptoLibByteArray;
begin
  Result := System.Copy(FEncoding);
end;

function TMlKemPublicKeyParameters.GetEncoding: TCryptoLibByteArray;
begin
  Result := FEncoding;
end;

procedure TMlKemPublicKeyParameters.InternalEncapsulate(const ARandBytes: TCryptoLibByteArray;
  const AEnc, ASec: TCryptoLibByteArray; AEncOff, ASecOff: Int32);
begin
  if System.Length(ARandBytes) <> MlKemSymBytes then
    raise EArgumentCryptoLibException.CreateRes(@SInvalidMlKemLength);
  Parameters.ParameterSet.Engine.KemEncrypt(FEncoding, ARandBytes, AEnc, AEncOff, ASec, ASecOff);
end;

{ TMlKemPrivateKeyParameters }

class function TMlKemPrivateKeyParameters.CheckFormat(AFormat: TMlKemPrivateKeyFormat;
  const ASeed: TCryptoLibByteArray): TMlKemPrivateKeyFormat;
begin
  case AFormat of
    TMlKemPrivateKeyFormat.EncodingOnly:
      ;
    TMlKemPrivateKeyFormat.SeedAndEncoding, TMlKemPrivateKeyFormat.SeedOnly:
      if ASeed = nil then
        raise EInvalidOperationCryptoLibException.CreateRes(@SNoSeedAvailable);
  else
    raise EArgumentCryptoLibException.CreateRes(@SInvalidMlKemFormat);
  end;
  Result := AFormat;
end;

class function TMlKemPrivateKeyParameters.FromEncoding(const AParameters: IMlKemParameters;
  const AEncoding: TCryptoLibByteArray): IMlKemPrivateKeyParameters;
var
  LEngine: IMlKemEngine;
  LCopy: TCryptoLibByteArray;
begin
  if AParameters = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SParametersNil);
  if AEncoding = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SParametersNil);
  LEngine := AParameters.ParameterSet.Engine;
  if System.Length(AEncoding) <> LEngine.SecretKeyBytes then
    raise EArgumentCryptoLibException.CreateRes(@SInvalidMlKemLength);
  LCopy := System.Copy(AEncoding);
  if not LEngine.CheckDecapKeyHash(LCopy) then
    raise EArgumentCryptoLibException.CreateRes(@SHashCheckFailed);
  Result := TMlKemPrivateKeyParameters.Create(AParameters, nil, LCopy, TMlKemPrivateKeyFormat.EncodingOnly);
end;

class function TMlKemPrivateKeyParameters.FromSeed(const AParameters: IMlKemParameters;
  const ASeed: TCryptoLibByteArray): IMlKemPrivateKeyParameters;
begin
  Result := FromSeed(AParameters, ASeed, TMlKemPrivateKeyFormat.SeedOnly);
end;

class function TMlKemPrivateKeyParameters.FromSeed(const AParameters: IMlKemParameters;
  const ASeed: TCryptoLibByteArray; APreferredFormat: TMlKemPrivateKeyFormat): IMlKemPrivateKeyParameters;
var
  LSeedCopy, LEncoding: TCryptoLibByteArray;
  LEngineConcrete: TMlKemEngine;
begin
  if AParameters = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SParametersNil);
  if ASeed = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SParametersNil);
  if System.Length(ASeed) <> TMlKemEngine.SeedBytes then
    raise EArgumentCryptoLibException.CreateRes(@SInvalidMlKemLength);
  APreferredFormat := CheckFormat(APreferredFormat, ASeed);
  LSeedCopy := System.Copy(ASeed);
  LEngineConcrete := AParameters.ParameterSet.Engine as TMlKemEngine;
  LEngineConcrete.GenerateKemKeyPairFromSeed(LSeedCopy, LEncoding);
  Result := TMlKemPrivateKeyParameters.Create(AParameters, LSeedCopy, LEncoding, APreferredFormat);
end;

constructor TMlKemPrivateKeyParameters.Create(const AParameters: IMlKemParameters;
  const ASeed, AEncoding: TCryptoLibByteArray; APreferredFormat: TMlKemPrivateKeyFormat);
begin
  inherited Create(True, AParameters);
  FSeed := ASeed;
  FEncoding := AEncoding;
  FPreferredFormat := APreferredFormat;
end;

function TMlKemPrivateKeyParameters.GetEncoded: TCryptoLibByteArray;
begin
  Result := System.Copy(FEncoding);
end;

function TMlKemPrivateKeyParameters.GetEncoding: TCryptoLibByteArray;
begin
  Result := FEncoding;
end;

function TMlKemPrivateKeyParameters.GetPreferredFormat: TMlKemPrivateKeyFormat;
begin
  Result := FPreferredFormat;
end;

function TMlKemPrivateKeyParameters.GetPublicKey: IMlKemPublicKeyParameters;
begin
  Result := TMlKemPublicKeyParameters.Create(Parameters,
    System.Copy(GetPublicKeyEncoded));
end;

function TMlKemPrivateKeyParameters.GetPublicKeyEncoded: TCryptoLibByteArray;
begin
  Result := Parameters.ParameterSet.Engine.CopyEncapKey(FEncoding);
end;

function TMlKemPrivateKeyParameters.GetSeed: TCryptoLibByteArray;
begin
  Result := System.Copy(FSeed);
end;

function TMlKemPrivateKeyParameters.WithPreferredFormat(AFormat: TMlKemPrivateKeyFormat): IMlKemPrivateKeyParameters;
begin
  if FPreferredFormat = AFormat then
    Result := Self as IMlKemPrivateKeyParameters
  else
    Result := TMlKemPrivateKeyParameters.Create(Parameters, FSeed, FEncoding,
      CheckFormat(AFormat, FSeed));
end;

{ TMlKemKeyGenerationParameters }

constructor TMlKemKeyGenerationParameters.Create(const ARandom: ISecureRandom;
  const AParameters: IMlKemParameters);
begin
  inherited Create(ARandom, 256);
  if AParameters = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SParametersNil);
  FParameters := AParameters;
end;

constructor TMlKemKeyGenerationParameters.Create(const ARandom: ISecureRandom;
  const AParametersOid: IDerObjectIdentifier);
begin
  inherited Create(ARandom, 256);
  if AParametersOid = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SParametersNil);
  FParameters := TMlKemParameters.GetByOid(AParametersOid);
  if FParameters = nil then
    raise EArgumentCryptoLibException.CreateRes(@SUnrecognisedMlKemOid);
end;

function TMlKemKeyGenerationParameters.GetParameters: IMlKemParameters;
begin
  Result := FParameters;
end;

end.
