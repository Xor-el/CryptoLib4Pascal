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

unit ClpMlDsaParameters;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  Generics.Collections,
  ClpAsymmetricKeyParameter,
  ClpIMlDsaParameters,
  ClpIMlDsaEngine,
  ClpISecureRandom,
  ClpMlDsaEngine,
  ClpNistObjectIdentifiers,
  ClpIAsn1Objects,
  ClpAsn1Comparers,
  ClpCryptoLibComparers,
  ClpKeyGenerationParameters,
  ClpCryptoLibTypes;

resourcestring
  SInvalidMlDsaLength = 'invalid length';
  SInvalidMlDsaFormat = 'invalid format';
  SNoSeedAvailable = 'no seed available';
  SUnrecognisedMlDsaOid = 'unrecognised ML-DSA parameters OID';
  SParametersNil = 'parameters cannot be nil';
  SRandomNil = 'random cannot be nil';

type
  TMlDsaParameterSet = class sealed(TInterfacedObject, IMlDsaParameterSet)
  strict private
  class var
    FMlDsa44: IMlDsaParameterSet;
    FMlDsa65: IMlDsaParameterSet;
    FMlDsa87: IMlDsaParameterSet;
  var
    FName: String;
    FMode: Int32;
  public
    class constructor Create;
    class destructor Destroy;
    class function FromName(const AName: String): IMlDsaParameterSet; static;
    constructor Create(const AName: String; AMode: Int32); overload;
    function GetName: String;
    function GetPrivateKeyLength: Int32;
    function GetPublicKeyLength: Int32;
    function GetSeedLength: Int32;
    function GetEngine(const ARandom: ISecureRandom): IMlDsaEngine;

    class property MlDsa44: IMlDsaParameterSet read FMlDsa44;
    class property MlDsa65: IMlDsaParameterSet read FMlDsa65;
    class property MlDsa87: IMlDsaParameterSet read FMlDsa87;
  end;
  TMlDsaParametersImpl = class sealed(TInterfacedObject, IMlDsaParameters)
  strict private
  var
    FName: String;
    FParameterSet: IMlDsaParameterSet;
    FOid: IDerObjectIdentifier;
    FPreHashOid: IDerObjectIdentifier;
  public
    constructor Create(const AName: String; const AParameterSet: IMlDsaParameterSet;
      const AOid: IDerObjectIdentifier; const APreHashOid: IDerObjectIdentifier);
    function GetName: String;
    function GetParameterSet: IMlDsaParameterSet;
    function GetOid: IDerObjectIdentifier;
    function GetPreHashOid: IDerObjectIdentifier;
    function GetIsPreHash: Boolean;
  end;
  TMlDsaParameters = class sealed(TObject)
  strict private
  class var
    FByName: TDictionary<string, IMlDsaParameters>;
    FByOid: TDictionary<IDerObjectIdentifier, IMlDsaParameters>;
    FMlDsa44: IMlDsaParameters;
    FMlDsa65: IMlDsaParameters;
    FMlDsa87: IMlDsaParameters;
    FMlDsa44WithSha512: IMlDsaParameters;
    FMlDsa65WithSha512: IMlDsaParameters;
    FMlDsa87WithSha512: IMlDsaParameters;
  public
    class constructor Create;
    class destructor Destroy;
    class function ByName: TDictionary<string, IMlDsaParameters>; static;
    class function ByOid: TDictionary<IDerObjectIdentifier, IMlDsaParameters>; static;
    class function GetByName(const AName: String): IMlDsaParameters; static;
    class function GetByOid(const AOid: IDerObjectIdentifier): IMlDsaParameters; static;

    class property MlDsa44: IMlDsaParameters read FMlDsa44;
    class property MlDsa65: IMlDsaParameters read FMlDsa65;
    class property MlDsa87: IMlDsaParameters read FMlDsa87;
    class property MlDsa44WithSha512: IMlDsaParameters read FMlDsa44WithSha512;
    class property MlDsa65WithSha512: IMlDsaParameters read FMlDsa65WithSha512;
    class property MlDsa87WithSha512: IMlDsaParameters read FMlDsa87WithSha512;
  end;
  TMlDsaKeyParameters = class abstract(TAsymmetricKeyParameter, IMlDsaKeyParameters)
  strict private
  var
    FParameters: IMlDsaParameters;
  strict protected
    constructor Create(APrivateKey: Boolean; const AParameters: IMlDsaParameters);
  public
    function GetParameters: IMlDsaParameters;
    property Parameters: IMlDsaParameters read GetParameters;
  end;
  TMlDsaPublicKeyParameters = class sealed(TMlDsaKeyParameters, IMlDsaPublicKeyParameters)
  strict private
  var
    FRho: TCryptoLibByteArray;
    FT1: TCryptoLibByteArray;
    FCachedPublicKeyHash: TCryptoLibByteArray;
    function EnsurePublicKeyHash: TCryptoLibByteArray;
  public
    class function FromEncoding(const AParameters: IMlDsaParameters;
      const AEncoding: TCryptoLibByteArray): IMlDsaPublicKeyParameters; static;
    constructor Create(const AParameters: IMlDsaParameters; const ARho, AT1: TCryptoLibByteArray);
    function GetEncoded(): TCryptoLibByteArray;
    function GetRho: TCryptoLibByteArray;
    function GetT1: TCryptoLibByteArray;
    function GetPublicKeyHash: TCryptoLibByteArray;
    function VerifyInternal(const AMsg: TCryptoLibByteArray; AMsgOff, AMsgLen: Int32;
      const ASig: TCryptoLibByteArray): Boolean;
  end;
  TMlDsaPrivateKeyParameters = class sealed(TMlDsaKeyParameters, IMlDsaPrivateKeyParameters)
  strict private
  var
    FRho, FK, FTr, FS1, FS2, FT0, FT1, FSeed: TCryptoLibByteArray;
    FPreferredFormat: TMlDsaPrivateKeyFormat;
    class function CheckFormat(AFormat: TMlDsaPrivateKeyFormat;
      const ASeed: TCryptoLibByteArray): TMlDsaPrivateKeyFormat; static;
  public
    class function FromEncoding(const AParameters: IMlDsaParameters;
      const AEncoding: TCryptoLibByteArray): IMlDsaPrivateKeyParameters; static;
    class function FromSeed(const AParameters: IMlDsaParameters;
      const ASeed: TCryptoLibByteArray): IMlDsaPrivateKeyParameters; overload; static;
    class function FromSeed(const AParameters: IMlDsaParameters;
      const ASeed: TCryptoLibByteArray; APreferredFormat: TMlDsaPrivateKeyFormat): IMlDsaPrivateKeyParameters; overload; static;
    constructor Create(const AParameters: IMlDsaParameters; const ARho, AK, ATr, AS1, AS2, AT0, AT1,
      ASeed: TCryptoLibByteArray; APreferredFormat: TMlDsaPrivateKeyFormat);
    function GetEncoded(): TCryptoLibByteArray;
    function GetSeed(): TCryptoLibByteArray;
    function GetPublicKey(): IMlDsaPublicKeyParameters;
    function GetPublicKeyEncoded(): TCryptoLibByteArray;
    function GetPreferredFormat: TMlDsaPrivateKeyFormat;
    function WithPreferredFormat(AFormat: TMlDsaPrivateKeyFormat): IMlDsaPrivateKeyParameters;
    function GetRho: TCryptoLibByteArray;
    function GetK: TCryptoLibByteArray;
    function GetTr: TCryptoLibByteArray;
    function GetS1: TCryptoLibByteArray;
    function GetS2: TCryptoLibByteArray;
    function GetT0: TCryptoLibByteArray;
    function SignInternal(const ARnd, AMsg: TCryptoLibByteArray; AMsgOff, AMsgLen: Int32): TCryptoLibByteArray;
  end;
  TMlDsaKeyGenerationParameters = class sealed(TKeyGenerationParameters,
    IMlDsaKeyGenerationParameters)
  strict private
  var
    FParameters: IMlDsaParameters;
  public
    constructor Create(const ARandom: ISecureRandom; const AParameters: IMlDsaParameters); overload;
    constructor Create(const ARandom: ISecureRandom; const AParametersOid: IDerObjectIdentifier); overload;
    function GetParameters: IMlDsaParameters;
  end;

implementation

{ TMlDsaParameterSet }

class constructor TMlDsaParameterSet.Create;
begin
  FMlDsa44 := TMlDsaParameterSet.Create('ML-DSA-44', 2);
  FMlDsa65 := TMlDsaParameterSet.Create('ML-DSA-65', 3);
  FMlDsa87 := TMlDsaParameterSet.Create('ML-DSA-87', 5);
end;

class destructor TMlDsaParameterSet.Destroy;
begin
  FMlDsa44 := nil;
  FMlDsa65 := nil;
  FMlDsa87 := nil;
end;

constructor TMlDsaParameterSet.Create(const AName: String; AMode: Int32);
begin
  inherited Create;
  FName := AName;
  FMode := AMode;
end;

class function TMlDsaParameterSet.FromName(const AName: String): IMlDsaParameterSet;
begin
  if SameText(AName, 'ML-DSA-44') then
    Result := MlDsa44
  else if SameText(AName, 'ML-DSA-65') then
    Result := MlDsa65
  else if SameText(AName, 'ML-DSA-87') then
    Result := MlDsa87
  else
    Result := nil;
end;

function TMlDsaParameterSet.GetEngine(const ARandom: ISecureRandom): IMlDsaEngine;
begin
  Result := TMlDsaEngine.Create(FMode, ARandom);
end;

function TMlDsaParameterSet.GetName: String;
begin
  Result := FName;
end;

function TMlDsaParameterSet.GetPrivateKeyLength: Int32;
begin
  case FMode of
    2: Result := 2560;
    3: Result := 4032;
    5: Result := 4896;
  else
    raise EInvalidOperationCryptoLibException.CreateRes(@SInvalidMlDsaLength);
  end;
end;

function TMlDsaParameterSet.GetPublicKeyLength: Int32;
begin
  case FMode of
    2: Result := 1312;
    3: Result := 1952;
    5: Result := 2592;
  else
    raise EInvalidOperationCryptoLibException.CreateRes(@SInvalidMlDsaLength);
  end;
end;

function TMlDsaParameterSet.GetSeedLength: Int32;
begin
  Result := TMlDsaEngine.SeedBytes;
end;

{ TMlDsaParametersImpl }

constructor TMlDsaParametersImpl.Create(const AName: String;
  const AParameterSet: IMlDsaParameterSet; const AOid: IDerObjectIdentifier;
  const APreHashOid: IDerObjectIdentifier);
begin
  inherited Create;
  FName := AName;
  FParameterSet := AParameterSet;
  FOid := AOid;
  FPreHashOid := APreHashOid;
end;

function TMlDsaParametersImpl.GetIsPreHash: Boolean;
begin
  Result := FPreHashOid <> nil;
end;

function TMlDsaParametersImpl.GetName: String;
begin
  Result := FName;
end;

function TMlDsaParametersImpl.GetOid: IDerObjectIdentifier;
begin
  Result := FOid;
end;

function TMlDsaParametersImpl.GetParameterSet: IMlDsaParameterSet;
begin
  Result := FParameterSet;
end;

function TMlDsaParametersImpl.GetPreHashOid: IDerObjectIdentifier;
begin
  Result := FPreHashOid;
end;

{ TMlDsaParameters }

class constructor TMlDsaParameters.Create;
begin
  FMlDsa44 := TMlDsaParametersImpl.Create('ML-DSA-44', TMlDsaParameterSet.MlDsa44,
    TNistObjectIdentifiers.IdMlDsa44, nil);
  FMlDsa65 := TMlDsaParametersImpl.Create('ML-DSA-65', TMlDsaParameterSet.MlDsa65,
    TNistObjectIdentifiers.IdMlDsa65, nil);
  FMlDsa87 := TMlDsaParametersImpl.Create('ML-DSA-87', TMlDsaParameterSet.MlDsa87,
    TNistObjectIdentifiers.IdMlDsa87, nil);
  FMlDsa44WithSha512 := TMlDsaParametersImpl.Create('ML-DSA-44-WITH-SHA512',
    TMlDsaParameterSet.MlDsa44, TNistObjectIdentifiers.IdHashMlDsa44WithSha512,
    TNistObjectIdentifiers.IdSha512);
  FMlDsa65WithSha512 := TMlDsaParametersImpl.Create('ML-DSA-65-WITH-SHA512',
    TMlDsaParameterSet.MlDsa65, TNistObjectIdentifiers.IdHashMlDsa65WithSha512,
    TNistObjectIdentifiers.IdSha512);
  FMlDsa87WithSha512 := TMlDsaParametersImpl.Create('ML-DSA-87-WITH-SHA512',
    TMlDsaParameterSet.MlDsa87, TNistObjectIdentifiers.IdHashMlDsa87WithSha512,
    TNistObjectIdentifiers.IdSha512);
  FByName := TDictionary<string, IMlDsaParameters>.Create(
    TCryptoLibComparers.OrdinalIgnoreCaseEqualityComparer);
  FByName.Add('ML-DSA-44', MlDsa44);
  FByName.Add('ML-DSA-44-WITH-SHA512', MlDsa44WithSha512);
  FByName.Add('ML-DSA-65', MlDsa65);
  FByName.Add('ML-DSA-65-WITH-SHA512', MlDsa65WithSha512);
  FByName.Add('ML-DSA-87', MlDsa87);
  FByName.Add('ML-DSA-87-WITH-SHA512', MlDsa87WithSha512);
  FByOid := TDictionary<IDerObjectIdentifier, IMlDsaParameters>.Create(
    TAsn1Comparers.OidEqualityComparer);
  FByOid.Add(MlDsa44.Oid, MlDsa44);
  FByOid.Add(MlDsa44WithSha512.Oid, MlDsa44WithSha512);
  FByOid.Add(MlDsa65.Oid, MlDsa65);
  FByOid.Add(MlDsa65WithSha512.Oid, MlDsa65WithSha512);
  FByOid.Add(MlDsa87.Oid, MlDsa87);
  FByOid.Add(MlDsa87WithSha512.Oid, MlDsa87WithSha512);
end;

class destructor TMlDsaParameters.Destroy;
begin
  FByOid.Free;
  FByName.Free;
  FMlDsa44 := nil;
  FMlDsa65 := nil;
  FMlDsa87 := nil;
  FMlDsa44WithSha512 := nil;
  FMlDsa65WithSha512 := nil;
  FMlDsa87WithSha512 := nil;
end;

class function TMlDsaParameters.ByName: TDictionary<string, IMlDsaParameters>;
begin
  Result := FByName;
end;

class function TMlDsaParameters.ByOid: TDictionary<IDerObjectIdentifier, IMlDsaParameters>;
begin
  Result := FByOid;
end;

class function TMlDsaParameters.GetByName(const AName: String): IMlDsaParameters;
begin
  if not FByName.TryGetValue(AName, Result) then
    Result := nil;
end;

class function TMlDsaParameters.GetByOid(const AOid: IDerObjectIdentifier): IMlDsaParameters;
begin
  if not FByOid.TryGetValue(AOid, Result) then
    Result := nil;
end;

{ TMlDsaKeyParameters }

constructor TMlDsaKeyParameters.Create(APrivateKey: Boolean;
  const AParameters: IMlDsaParameters);
begin
  inherited Create(APrivateKey);
  FParameters := AParameters;
end;

function TMlDsaKeyParameters.GetParameters: IMlDsaParameters;
begin
  Result := FParameters;
end;

{ TMlDsaPublicKeyParameters }

class function TMlDsaPublicKeyParameters.FromEncoding(const AParameters: IMlDsaParameters;
  const AEncoding: TCryptoLibByteArray): IMlDsaPublicKeyParameters;
var
  LRho, LT1: TCryptoLibByteArray;
begin
  if AParameters = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SParametersNil);
  if AEncoding = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SParametersNil);
  if System.Length(AEncoding) <> AParameters.ParameterSet.PublicKeyLength then
    raise EArgumentCryptoLibException.CreateRes(@SInvalidMlDsaLength);
  System.SetLength(LRho, TMlDsaEngine.SeedBytes);
  System.SetLength(LT1, System.Length(AEncoding) - TMlDsaEngine.SeedBytes);
  System.Move(AEncoding[0], LRho[0], TMlDsaEngine.SeedBytes);
  System.Move(AEncoding[TMlDsaEngine.SeedBytes], LT1[0], System.Length(LT1));
  Result := TMlDsaPublicKeyParameters.Create(AParameters, LRho, LT1);
end;

constructor TMlDsaPublicKeyParameters.Create(const AParameters: IMlDsaParameters;
  const ARho, AT1: TCryptoLibByteArray);
begin
  inherited Create(False, AParameters);
  FRho := ARho;
  FT1 := AT1;
end;

function TMlDsaPublicKeyParameters.EnsurePublicKeyHash: TCryptoLibByteArray;
begin
  if FCachedPublicKeyHash = nil then
    FCachedPublicKeyHash := TMlDsaEngine.CalculatePublicKeyHash(FRho, FT1);
  Result := FCachedPublicKeyHash;
end;

function TMlDsaPublicKeyParameters.GetEncoded: TCryptoLibByteArray;
begin
  System.SetLength(Result, System.Length(FRho) + System.Length(FT1));
  System.Move(FRho[0], Result[0], System.Length(FRho));
  System.Move(FT1[0], Result[System.Length(FRho)], System.Length(FT1));
end;

function TMlDsaPublicKeyParameters.GetPublicKeyHash: TCryptoLibByteArray;
begin
  Result := EnsurePublicKeyHash;
end;

function TMlDsaPublicKeyParameters.GetRho: TCryptoLibByteArray;
begin
  Result := FRho;
end;

function TMlDsaPublicKeyParameters.GetT1: TCryptoLibByteArray;
begin
  Result := FT1;
end;

function TMlDsaPublicKeyParameters.VerifyInternal(const AMsg: TCryptoLibByteArray;
  AMsgOff, AMsgLen: Int32; const ASig: TCryptoLibByteArray): Boolean;
var
  LEngine: IMlDsaEngine;
  LEngineConcrete: TMlDsaEngine;
begin
  LEngine := Parameters.ParameterSet.GetEngine(nil);
  LEngineConcrete := LEngine as TMlDsaEngine;
  Result := LEngineConcrete.VerifyInternal(ASig, System.Length(ASig), AMsg, AMsgOff, AMsgLen, FRho, FT1,
    EnsurePublicKeyHash);
end;

{ TMlDsaPrivateKeyParameters }

class function TMlDsaPrivateKeyParameters.CheckFormat(AFormat: TMlDsaPrivateKeyFormat;
  const ASeed: TCryptoLibByteArray): TMlDsaPrivateKeyFormat;
begin
  case AFormat of
    TMlDsaPrivateKeyFormat.EncodingOnly:
      ;
    TMlDsaPrivateKeyFormat.SeedAndEncoding, TMlDsaPrivateKeyFormat.SeedOnly:
      if ASeed = nil then
        raise EInvalidOperationCryptoLibException.CreateRes(@SNoSeedAvailable);
  else
    raise EArgumentCryptoLibException.CreateRes(@SInvalidMlDsaFormat);
  end;
  Result := AFormat;
end;

class function TMlDsaPrivateKeyParameters.FromEncoding(const AParameters: IMlDsaParameters;
  const AEncoding: TCryptoLibByteArray): IMlDsaPrivateKeyParameters;
var
  LEngine: IMlDsaEngine;
  LIndex, LDelta: Int32;
  LRho, LK, LTr, LS1, LS2, LT0, LT1: TCryptoLibByteArray;
begin
  if AParameters = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SParametersNil);
  if AEncoding = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SParametersNil);
  if System.Length(AEncoding) <> AParameters.ParameterSet.PrivateKeyLength then
    raise EArgumentCryptoLibException.CreateRes(@SInvalidMlDsaLength);
  LEngine := AParameters.ParameterSet.GetEngine(nil);
  LIndex := 0;
  System.SetLength(LRho, TMlDsaEngine.SeedBytes);
  System.Move(AEncoding[LIndex], LRho[0], TMlDsaEngine.SeedBytes);
  Inc(LIndex, TMlDsaEngine.SeedBytes);
  System.SetLength(LK, TMlDsaEngine.SeedBytes);
  System.Move(AEncoding[LIndex], LK[0], TMlDsaEngine.SeedBytes);
  Inc(LIndex, TMlDsaEngine.SeedBytes);
  System.SetLength(LTr, TMlDsaEngine.TrBytes);
  System.Move(AEncoding[LIndex], LTr[0], TMlDsaEngine.TrBytes);
  Inc(LIndex, TMlDsaEngine.TrBytes);
  LDelta := LEngine.L * LEngine.PolyEtaPackedBytes;
  System.SetLength(LS1, LDelta);
  System.Move(AEncoding[LIndex], LS1[0], LDelta);
  Inc(LIndex, LDelta);
  LDelta := LEngine.K * LEngine.PolyEtaPackedBytes;
  System.SetLength(LS2, LDelta);
  System.Move(AEncoding[LIndex], LS2[0], LDelta);
  Inc(LIndex, LDelta);
  LDelta := LEngine.K * TMlDsaEngine.PolyT0PackedBytes;
  System.SetLength(LT0, LDelta);
  System.Move(AEncoding[LIndex], LT0[0], LDelta);
  LT1 := LEngine.DeriveT1(LRho, LS1, LS2, LT0);
  Result := TMlDsaPrivateKeyParameters.Create(AParameters, LRho, LK, LTr, LS1, LS2, LT0, LT1, nil,
    TMlDsaPrivateKeyFormat.EncodingOnly);
end;

class function TMlDsaPrivateKeyParameters.FromSeed(const AParameters: IMlDsaParameters;
  const ASeed: TCryptoLibByteArray): IMlDsaPrivateKeyParameters;
begin
  Result := FromSeed(AParameters, ASeed, TMlDsaPrivateKeyFormat.SeedOnly);
end;

class function TMlDsaPrivateKeyParameters.FromSeed(const AParameters: IMlDsaParameters;
  const ASeed: TCryptoLibByteArray; APreferredFormat: TMlDsaPrivateKeyFormat): IMlDsaPrivateKeyParameters;
var
  LEngine: IMlDsaEngine;
  LEngineConcrete: TMlDsaEngine;
  LRho, LK, LTr, LS1, LS2, LT0, LT1: TCryptoLibByteArray;
  LSeedCopy: TCryptoLibByteArray;
begin
  if AParameters = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SParametersNil);
  if ASeed = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SParametersNil);
  if System.Length(ASeed) <> AParameters.ParameterSet.SeedLength then
    raise EArgumentCryptoLibException.CreateRes(@SInvalidMlDsaLength);
  APreferredFormat := CheckFormat(APreferredFormat, ASeed);
  LSeedCopy := System.Copy(ASeed);
  LEngine := AParameters.ParameterSet.GetEngine(nil);
  LEngineConcrete := LEngine as TMlDsaEngine;
  LEngineConcrete.GenerateKeyPairInternal(LSeedCopy, LRho, LK, LTr, LS1, LS2, LT0, LT1);
  Result := TMlDsaPrivateKeyParameters.Create(AParameters, LRho, LK, LTr, LS1, LS2, LT0, LT1,
    LSeedCopy, APreferredFormat);
end;

constructor TMlDsaPrivateKeyParameters.Create(const AParameters: IMlDsaParameters;
  const ARho, AK, ATr, AS1, AS2, AT0, AT1, ASeed: TCryptoLibByteArray;
  APreferredFormat: TMlDsaPrivateKeyFormat);
begin
  inherited Create(True, AParameters);
  FRho := ARho;
  FK := AK;
  FTr := ATr;
  FS1 := AS1;
  FS2 := AS2;
  FT0 := AT0;
  FT1 := AT1;
  FSeed := ASeed;
  FPreferredFormat := APreferredFormat;
end;

function TMlDsaPrivateKeyParameters.GetEncoded: TCryptoLibByteArray;
var
  LOff: Int32;
begin
  System.SetLength(Result, System.Length(FRho) + System.Length(FK) + System.Length(FTr) +
    System.Length(FS1) + System.Length(FS2) + System.Length(FT0));
  LOff := 0;
  System.Move(FRho[0], Result[LOff], System.Length(FRho));
  Inc(LOff, System.Length(FRho));
  System.Move(FK[0], Result[LOff], System.Length(FK));
  Inc(LOff, System.Length(FK));
  System.Move(FTr[0], Result[LOff], System.Length(FTr));
  Inc(LOff, System.Length(FTr));
  System.Move(FS1[0], Result[LOff], System.Length(FS1));
  Inc(LOff, System.Length(FS1));
  System.Move(FS2[0], Result[LOff], System.Length(FS2));
  Inc(LOff, System.Length(FS2));
  System.Move(FT0[0], Result[LOff], System.Length(FT0));
end;

function TMlDsaPrivateKeyParameters.GetK: TCryptoLibByteArray;
begin
  Result := FK;
end;

function TMlDsaPrivateKeyParameters.GetPreferredFormat: TMlDsaPrivateKeyFormat;
begin
  Result := FPreferredFormat;
end;

function TMlDsaPrivateKeyParameters.GetPublicKey: IMlDsaPublicKeyParameters;
begin
  Result := TMlDsaPublicKeyParameters.Create(Parameters, FRho, FT1);
end;

function TMlDsaPrivateKeyParameters.GetPublicKeyEncoded: TCryptoLibByteArray;
begin
  Result := GetPublicKey.GetEncoded();
end;

function TMlDsaPrivateKeyParameters.GetRho: TCryptoLibByteArray;
begin
  Result := FRho;
end;

function TMlDsaPrivateKeyParameters.GetS1: TCryptoLibByteArray;
begin
  Result := FS1;
end;

function TMlDsaPrivateKeyParameters.GetS2: TCryptoLibByteArray;
begin
  Result := FS2;
end;

function TMlDsaPrivateKeyParameters.GetSeed: TCryptoLibByteArray;
begin
  Result := System.Copy(FSeed);
end;

function TMlDsaPrivateKeyParameters.GetT0: TCryptoLibByteArray;
begin
  Result := FT0;
end;

function TMlDsaPrivateKeyParameters.GetTr: TCryptoLibByteArray;
begin
  Result := FTr;
end;

function TMlDsaPrivateKeyParameters.SignInternal(const ARnd, AMsg: TCryptoLibByteArray;
  AMsgOff, AMsgLen: Int32): TCryptoLibByteArray;
var
  LEngine: IMlDsaEngine;
  LEngineConcrete: TMlDsaEngine;
begin
  LEngine := Parameters.ParameterSet.GetEngine(nil);
  System.SetLength(Result, LEngine.CryptoBytes);
  LEngineConcrete := LEngine as TMlDsaEngine;
  LEngineConcrete.SignInternal(Result, System.Length(Result), AMsg, AMsgOff, AMsgLen, FRho, FK, FTr, FT0, FS1, FS2,
    ARnd);
end;

function TMlDsaPrivateKeyParameters.WithPreferredFormat(AFormat: TMlDsaPrivateKeyFormat): IMlDsaPrivateKeyParameters;
begin
  if FPreferredFormat = AFormat then
    Result := Self as IMlDsaPrivateKeyParameters
  else
    Result := TMlDsaPrivateKeyParameters.Create(Parameters, FRho, FK, FTr, FS1, FS2, FT0, FT1, FSeed,
      CheckFormat(AFormat, FSeed));
end;

{ TMlDsaKeyGenerationParameters }

constructor TMlDsaKeyGenerationParameters.Create(const ARandom: ISecureRandom;
  const AParameters: IMlDsaParameters);
begin
  inherited Create(ARandom, 256);
  if AParameters = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SParametersNil);
  FParameters := AParameters;
end;

constructor TMlDsaKeyGenerationParameters.Create(const ARandom: ISecureRandom;
  const AParametersOid: IDerObjectIdentifier);
begin
  inherited Create(ARandom, 256);
  if AParametersOid = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SParametersNil);
  FParameters := TMlDsaParameters.GetByOid(AParametersOid);
  if FParameters = nil then
    raise EArgumentCryptoLibException.CreateRes(@SUnrecognisedMlDsaOid);
end;

function TMlDsaKeyGenerationParameters.GetParameters: IMlDsaParameters;
begin
  Result := FParameters;
end;
end.
