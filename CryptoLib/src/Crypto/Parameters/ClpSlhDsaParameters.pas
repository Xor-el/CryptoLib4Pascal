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

unit ClpSlhDsaParameters;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  Generics.Collections,
  ClpAsymmetricKeyParameter,
  ClpISlhDsaParameters,
  ClpISlhDsaEngine,
  ClpISlhDsaCore,
  ClpISecureRandom,
  ClpSlhDsaCore,
  ClpSlhDsaEngine,
  ClpNistObjectIdentifiers,
  ClpIAsn1Objects,
  ClpAsn1Comparers,
  ClpCryptoLibComparers,
  ClpKeyGenerationParameters,
  ClpArrayUtilities,
  ClpCryptoLibTypes;

resourcestring
  SInvalidSlhDsaLength = 'invalid encoding';
  SUnrecognisedSlhDsaOid = 'unrecognised SLH-DSA parameters OID';
  SParametersNil = 'parameters cannot be nil';
  SRandomNil = 'random cannot be nil';
  SInvalidOptRandLength = 'invalid optRand length';

type
  TSlhDsaParameterSet = class sealed(TInterfacedObject, ISlhDsaParameterSet)
  strict private
  class var
    FSlhDsaSha2_128s, FSlhDsaShake_128s, FSlhDsaSha2_128f, FSlhDsaShake_128f,
    FSlhDsaSha2_192s, FSlhDsaShake_192s, FSlhDsaSha2_192f, FSlhDsaShake_192f,
    FSlhDsaSha2_256s, FSlhDsaShake_256s, FSlhDsaSha2_256f, FSlhDsaShake_256f: ISlhDsaParameterSet;
  var
    FName: String;
    FN, FW, FD, FA, FK, FH: Int32;
    FUseShake: Boolean;
    function CreateEngine: ISlhDsaEngine;
  public
    class constructor Create;
    class destructor Destroy;
    class function FromName(const AName: String): ISlhDsaParameterSet; static;
    constructor Create(const AName: String; AN, AW, AD, AA, AK, AH: Int32; AUseShake: Boolean); overload;
    function GetName: String;
    function GetPrivateKeyLength: Int32;
    function GetPublicKeyLength: Int32;
    function GetN: Int32;
    function GetEngine: ISlhDsaEngine;

    class property SlhDsaSha2_128s: ISlhDsaParameterSet read FSlhDsaSha2_128s;
    class property SlhDsaShake_128s: ISlhDsaParameterSet read FSlhDsaShake_128s;
    class property SlhDsaSha2_128f: ISlhDsaParameterSet read FSlhDsaSha2_128f;
    class property SlhDsaShake_128f: ISlhDsaParameterSet read FSlhDsaShake_128f;
    class property SlhDsaSha2_192s: ISlhDsaParameterSet read FSlhDsaSha2_192s;
    class property SlhDsaShake_192s: ISlhDsaParameterSet read FSlhDsaShake_192s;
    class property SlhDsaSha2_192f: ISlhDsaParameterSet read FSlhDsaSha2_192f;
    class property SlhDsaShake_192f: ISlhDsaParameterSet read FSlhDsaShake_192f;
    class property SlhDsaSha2_256s: ISlhDsaParameterSet read FSlhDsaSha2_256s;
    class property SlhDsaShake_256s: ISlhDsaParameterSet read FSlhDsaShake_256s;
    class property SlhDsaSha2_256f: ISlhDsaParameterSet read FSlhDsaSha2_256f;
    class property SlhDsaShake_256f: ISlhDsaParameterSet read FSlhDsaShake_256f;
  end;

  TSlhDsaParametersImpl = class sealed(TInterfacedObject, ISlhDsaParameters)
  strict private
  var
    FName: String;
    FParameterSet: ISlhDsaParameterSet;
    FOid: IDerObjectIdentifier;
    FPreHashOid: IDerObjectIdentifier;
  public
    constructor Create(const AName: String; const AParameterSet: ISlhDsaParameterSet;
      const AOid: IDerObjectIdentifier; const APreHashOid: IDerObjectIdentifier);
    function GetName: String;
    function GetParameterSet: ISlhDsaParameterSet;
    function GetOid: IDerObjectIdentifier;
    function GetPreHashOid: IDerObjectIdentifier;
    function GetIsPreHash: Boolean;
  end;

  TSlhDsaParameters = class sealed(TObject)
  strict private
  class var
    FByName: TDictionary<string, ISlhDsaParameters>;
    FByOid: TDictionary<IDerObjectIdentifier, ISlhDsaParameters>;
    FSlhDsaSha2_128s, FSlhDsaShake_128s, FSlhDsaSha2_128f, FSlhDsaShake_128f,
    FSlhDsaSha2_192s, FSlhDsaShake_192s, FSlhDsaSha2_192f, FSlhDsaShake_192f,
    FSlhDsaSha2_256s, FSlhDsaShake_256s, FSlhDsaSha2_256f, FSlhDsaShake_256f,
    FSlhDsaSha2_128sWithSha256, FSlhDsaShake_128sWithShake128,
    FSlhDsaSha2_128fWithSha256, FSlhDsaShake_128fWithShake128,
    FSlhDsaSha2_192sWithSha512, FSlhDsaShake_192sWithShake256,
    FSlhDsaSha2_192fWithSha512, FSlhDsaShake_192fWithShake256,
    FSlhDsaSha2_256sWithSha512, FSlhDsaShake_256sWithShake256,
    FSlhDsaSha2_256fWithSha512, FSlhDsaShake_256fWithShake256: ISlhDsaParameters;
    class procedure AddEntries(const AParams: ISlhDsaParameters); static;
  public
    class constructor Create;
    class destructor Destroy;
    class function ByName: TDictionary<string, ISlhDsaParameters>; static;
    class function ByOid: TDictionary<IDerObjectIdentifier, ISlhDsaParameters>; static;
    class function GetByName(const AName: String): ISlhDsaParameters; static;
    class function GetByOid(const AOid: IDerObjectIdentifier): ISlhDsaParameters; static;

    class property SlhDsaSha2_128s: ISlhDsaParameters read FSlhDsaSha2_128s;
    class property SlhDsaShake_128s: ISlhDsaParameters read FSlhDsaShake_128s;
    class property SlhDsaSha2_128f: ISlhDsaParameters read FSlhDsaSha2_128f;
    class property SlhDsaShake_128f: ISlhDsaParameters read FSlhDsaShake_128f;
    class property SlhDsaSha2_192s: ISlhDsaParameters read FSlhDsaSha2_192s;
    class property SlhDsaShake_192s: ISlhDsaParameters read FSlhDsaShake_192s;
    class property SlhDsaSha2_192f: ISlhDsaParameters read FSlhDsaSha2_192f;
    class property SlhDsaShake_192f: ISlhDsaParameters read FSlhDsaShake_192f;
    class property SlhDsaSha2_256s: ISlhDsaParameters read FSlhDsaSha2_256s;
    class property SlhDsaShake_256s: ISlhDsaParameters read FSlhDsaShake_256s;
    class property SlhDsaSha2_256f: ISlhDsaParameters read FSlhDsaSha2_256f;
    class property SlhDsaShake_256f: ISlhDsaParameters read FSlhDsaShake_256f;
    class property SlhDsaSha2_128sWithSha256: ISlhDsaParameters read FSlhDsaSha2_128sWithSha256;
    class property SlhDsaShake_128sWithShake128: ISlhDsaParameters read FSlhDsaShake_128sWithShake128;
    class property SlhDsaSha2_128fWithSha256: ISlhDsaParameters read FSlhDsaSha2_128fWithSha256;
    class property SlhDsaShake_128fWithShake128: ISlhDsaParameters read FSlhDsaShake_128fWithShake128;
    class property SlhDsaSha2_192sWithSha512: ISlhDsaParameters read FSlhDsaSha2_192sWithSha512;
    class property SlhDsaShake_192sWithShake256: ISlhDsaParameters read FSlhDsaShake_192sWithShake256;
    class property SlhDsaSha2_192fWithSha512: ISlhDsaParameters read FSlhDsaSha2_192fWithSha512;
    class property SlhDsaShake_192fWithShake256: ISlhDsaParameters read FSlhDsaShake_192fWithShake256;
    class property SlhDsaSha2_256sWithSha512: ISlhDsaParameters read FSlhDsaSha2_256sWithSha512;
    class property SlhDsaShake_256sWithShake256: ISlhDsaParameters read FSlhDsaShake_256sWithShake256;
    class property SlhDsaSha2_256fWithSha512: ISlhDsaParameters read FSlhDsaSha2_256fWithSha512;
    class property SlhDsaShake_256fWithShake256: ISlhDsaParameters read FSlhDsaShake_256fWithShake256;
  end;

  TSlhDsaKeyParameters = class abstract(TAsymmetricKeyParameter, ISlhDsaKeyParameters)
  strict private
  var
    FParameters: ISlhDsaParameters;
  strict protected
    constructor Create(APrivateKey: Boolean; const AParameters: ISlhDsaParameters);
  public
    function GetParameters: ISlhDsaParameters;
    property Parameters: ISlhDsaParameters read GetParameters;
  end;

  TSlhDsaPublicKeyParameters = class sealed(TSlhDsaKeyParameters, ISlhDsaPublicKeyParameters)
  strict private
  var
    FPk: TSlhDsaPK;
  public
    class function FromEncoding(const AParameters: ISlhDsaParameters;
      const AEncoding: TCryptoLibByteArray): ISlhDsaPublicKeyParameters; static;
    constructor Create(const AParameters: ISlhDsaParameters; const APk: TSlhDsaPK); overload;
    constructor Create(const AParameters: ISlhDsaParameters; const ASeed, ARoot: TCryptoLibByteArray); overload;
    function GetEncoded: TCryptoLibByteArray;
    function GetPk: TSlhDsaPK;
    function VerifyRaw(const AMsg: TCryptoLibByteArray; AMsgOff, AMsgLen: Int32;
      const ASignature: TCryptoLibByteArray): Boolean;
  end;

  TSlhDsaPrivateKeyParameters = class sealed(TSlhDsaKeyParameters, ISlhDsaPrivateKeyParameters)
  strict private
  var
    FSk: TSlhDsaSK;
    FPk: TSlhDsaPK;
  public
    class function FromEncoding(const AParameters: ISlhDsaParameters;
      const AEncoding: TCryptoLibByteArray): ISlhDsaPrivateKeyParameters; static;
    constructor Create(const AParameters: ISlhDsaParameters; const ASk: TSlhDsaSK; const APk: TSlhDsaPK);
    function GetEncoded: TCryptoLibByteArray;
    function GetPublicKey: ISlhDsaPublicKeyParameters;
    function GetPublicKeyEncoded: TCryptoLibByteArray;
    function GetSk: TSlhDsaSK;
    function GetPk: TSlhDsaPK;
    function SignRaw(const AOptRand: TCryptoLibByteArray; const AMsg: TCryptoLibByteArray;
      AMsgOff, AMsgLen: Int32): TCryptoLibByteArray;
  end;

  TSlhDsaKeyGenerationParameters = class sealed(TKeyGenerationParameters,
    ISlhDsaKeyGenerationParameters)
  strict private
  var
    FParameters: ISlhDsaParameters;
  public
    constructor Create(const ARandom: ISecureRandom; const AParameters: ISlhDsaParameters); overload;
    constructor Create(const ARandom: ISecureRandom; const AParametersOid: IDerObjectIdentifier); overload;
    function GetParameters: ISlhDsaParameters;
  end;

implementation

{ TSlhDsaParameterSet }

class constructor TSlhDsaParameterSet.Create;
begin
  FSlhDsaSha2_128s := TSlhDsaParameterSet.Create('SLH-DSA-SHA2-128s', 16, 16, 7, 12, 14, 63, False);
  FSlhDsaShake_128s := TSlhDsaParameterSet.Create('SLH-DSA-SHAKE-128s', 16, 16, 7, 12, 14, 63, True);
  FSlhDsaSha2_128f := TSlhDsaParameterSet.Create('SLH-DSA-SHA2-128f', 16, 16, 22, 6, 33, 66, False);
  FSlhDsaShake_128f := TSlhDsaParameterSet.Create('SLH-DSA-SHAKE-128f', 16, 16, 22, 6, 33, 66, True);
  FSlhDsaSha2_192s := TSlhDsaParameterSet.Create('SLH-DSA-SHA2-192s', 24, 16, 7, 14, 17, 63, False);
  FSlhDsaShake_192s := TSlhDsaParameterSet.Create('SLH-DSA-SHAKE-192s', 24, 16, 7, 14, 17, 63, True);
  FSlhDsaSha2_192f := TSlhDsaParameterSet.Create('SLH-DSA-SHA2-192f', 24, 16, 22, 8, 33, 66, False);
  FSlhDsaShake_192f := TSlhDsaParameterSet.Create('SLH-DSA-SHAKE-192f', 24, 16, 22, 8, 33, 66, True);
  FSlhDsaSha2_256s := TSlhDsaParameterSet.Create('SLH-DSA-SHA2-256s', 32, 16, 8, 14, 22, 64, False);
  FSlhDsaShake_256s := TSlhDsaParameterSet.Create('SLH-DSA-SHAKE-256s', 32, 16, 8, 14, 22, 64, True);
  FSlhDsaSha2_256f := TSlhDsaParameterSet.Create('SLH-DSA-SHA2-256f', 32, 16, 17, 9, 35, 68, False);
  FSlhDsaShake_256f := TSlhDsaParameterSet.Create('SLH-DSA-SHAKE-256f', 32, 16, 17, 9, 35, 68, True);
end;

class destructor TSlhDsaParameterSet.Destroy;
begin
  FSlhDsaSha2_128s := nil;
  FSlhDsaShake_128s := nil;
  FSlhDsaSha2_128f := nil;
  FSlhDsaShake_128f := nil;
  FSlhDsaSha2_192s := nil;
  FSlhDsaShake_192s := nil;
  FSlhDsaSha2_192f := nil;
  FSlhDsaShake_192f := nil;
  FSlhDsaSha2_256s := nil;
  FSlhDsaShake_256s := nil;
  FSlhDsaSha2_256f := nil;
  FSlhDsaShake_256f := nil;
end;

constructor TSlhDsaParameterSet.Create(const AName: String; AN, AW, AD, AA, AK, AH: Int32;
  AUseShake: Boolean);
begin
  inherited Create;
  FName := AName;
  FN := AN;
  FW := AW;
  FD := AD;
  FA := AA;
  FK := AK;
  FH := AH;
  FUseShake := AUseShake;
end;

function TSlhDsaParameterSet.CreateEngine: ISlhDsaEngine;
begin
  if FUseShake then
    Result := TSlhDsaShake256Engine.Create(FN, FW, FD, FA, FK, FH)
  else
    Result := TSlhDsaSha2Engine.Create(FN, FW, FD, FA, FK, FH);
end;

class function TSlhDsaParameterSet.FromName(const AName: String): ISlhDsaParameterSet;
begin
  if SameText(AName, 'SLH-DSA-SHA2-128f') then Result := SlhDsaSha2_128f
  else if SameText(AName, 'SLH-DSA-SHA2-128s') then Result := SlhDsaSha2_128s
  else if SameText(AName, 'SLH-DSA-SHA2-192f') then Result := SlhDsaSha2_192f
  else if SameText(AName, 'SLH-DSA-SHA2-192s') then Result := SlhDsaSha2_192s
  else if SameText(AName, 'SLH-DSA-SHA2-256f') then Result := SlhDsaSha2_256f
  else if SameText(AName, 'SLH-DSA-SHA2-256s') then Result := SlhDsaSha2_256s
  else if SameText(AName, 'SLH-DSA-SHAKE-128f') then Result := SlhDsaShake_128f
  else if SameText(AName, 'SLH-DSA-SHAKE-128s') then Result := SlhDsaShake_128s
  else if SameText(AName, 'SLH-DSA-SHAKE-192f') then Result := SlhDsaShake_192f
  else if SameText(AName, 'SLH-DSA-SHAKE-192s') then Result := SlhDsaShake_192s
  else if SameText(AName, 'SLH-DSA-SHAKE-256f') then Result := SlhDsaShake_256f
  else if SameText(AName, 'SLH-DSA-SHAKE-256s') then Result := SlhDsaShake_256s
  else
    Result := nil;
end;

function TSlhDsaParameterSet.GetEngine: ISlhDsaEngine;
begin
  Result := CreateEngine;
end;

function TSlhDsaParameterSet.GetN: Int32;
begin
  Result := FN;
end;

function TSlhDsaParameterSet.GetName: String;
begin
  Result := FName;
end;

function TSlhDsaParameterSet.GetPrivateKeyLength: Int32;
begin
  Result := 4 * FN;
end;

function TSlhDsaParameterSet.GetPublicKeyLength: Int32;
begin
  Result := 2 * FN;
end;

{ TSlhDsaParametersImpl }

constructor TSlhDsaParametersImpl.Create(const AName: String; const AParameterSet: ISlhDsaParameterSet;
  const AOid: IDerObjectIdentifier; const APreHashOid: IDerObjectIdentifier);
begin
  inherited Create;
  FName := AName;
  FParameterSet := AParameterSet;
  FOid := AOid;
  FPreHashOid := APreHashOid;
end;

function TSlhDsaParametersImpl.GetIsPreHash: Boolean;
begin
  Result := FPreHashOid <> nil;
end;

function TSlhDsaParametersImpl.GetName: String;
begin
  Result := FName;
end;

function TSlhDsaParametersImpl.GetOid: IDerObjectIdentifier;
begin
  Result := FOid;
end;

function TSlhDsaParametersImpl.GetParameterSet: ISlhDsaParameterSet;
begin
  Result := FParameterSet;
end;

function TSlhDsaParametersImpl.GetPreHashOid: IDerObjectIdentifier;
begin
  Result := FPreHashOid;
end;

{ TSlhDsaParameters }

class procedure TSlhDsaParameters.AddEntries(const AParams: ISlhDsaParameters);
begin
  FByName.Add(AParams.Name, AParams);
  FByOid.Add(AParams.Oid, AParams);
end;

class constructor TSlhDsaParameters.Create;
begin
  FByName := TDictionary<string, ISlhDsaParameters>.Create(
    TCryptoLibComparers.OrdinalIgnoreCaseEqualityComparer);
  FByOid := TDictionary<IDerObjectIdentifier, ISlhDsaParameters>.Create(
    TAsn1Comparers.OidEqualityComparer);

  FSlhDsaSha2_128s := TSlhDsaParametersImpl.Create('SLH-DSA-SHA2-128S',
    TSlhDsaParameterSet.SlhDsaSha2_128s, TNistObjectIdentifiers.IdSlhDsaSha2_128s, nil);
  FSlhDsaShake_128s := TSlhDsaParametersImpl.Create('SLH-DSA-SHAKE-128S',
    TSlhDsaParameterSet.SlhDsaShake_128s, TNistObjectIdentifiers.IdSlhDsaShake_128s, nil);
  FSlhDsaSha2_128f := TSlhDsaParametersImpl.Create('SLH-DSA-SHA2-128F',
    TSlhDsaParameterSet.SlhDsaSha2_128f, TNistObjectIdentifiers.IdSlhDsaSha2_128f, nil);
  FSlhDsaShake_128f := TSlhDsaParametersImpl.Create('SLH-DSA-SHAKE-128F',
    TSlhDsaParameterSet.SlhDsaShake_128f, TNistObjectIdentifiers.IdSlhDsaShake_128f, nil);
  FSlhDsaSha2_192s := TSlhDsaParametersImpl.Create('SLH-DSA-SHA2-192S',
    TSlhDsaParameterSet.SlhDsaSha2_192s, TNistObjectIdentifiers.IdSlhDsaSha2_192s, nil);
  FSlhDsaShake_192s := TSlhDsaParametersImpl.Create('SLH-DSA-SHAKE-192S',
    TSlhDsaParameterSet.SlhDsaShake_192s, TNistObjectIdentifiers.IdSlhDsaShake_192s, nil);
  FSlhDsaSha2_192f := TSlhDsaParametersImpl.Create('SLH-DSA-SHA2-192F',
    TSlhDsaParameterSet.SlhDsaSha2_192f, TNistObjectIdentifiers.IdSlhDsaSha2_192f, nil);
  FSlhDsaShake_192f := TSlhDsaParametersImpl.Create('SLH-DSA-SHAKE-192F',
    TSlhDsaParameterSet.SlhDsaShake_192f, TNistObjectIdentifiers.IdSlhDsaShake_192f, nil);
  FSlhDsaSha2_256s := TSlhDsaParametersImpl.Create('SLH-DSA-SHA2-256S',
    TSlhDsaParameterSet.SlhDsaSha2_256s, TNistObjectIdentifiers.IdSlhDsaSha2_256s, nil);
  FSlhDsaShake_256s := TSlhDsaParametersImpl.Create('SLH-DSA-SHAKE-256S',
    TSlhDsaParameterSet.SlhDsaShake_256s, TNistObjectIdentifiers.IdSlhDsaShake_256s, nil);
  FSlhDsaSha2_256f := TSlhDsaParametersImpl.Create('SLH-DSA-SHA2-256F',
    TSlhDsaParameterSet.SlhDsaSha2_256f, TNistObjectIdentifiers.IdSlhDsaSha2_256f, nil);
  FSlhDsaShake_256f := TSlhDsaParametersImpl.Create('SLH-DSA-SHAKE-256F',
    TSlhDsaParameterSet.SlhDsaShake_256f, TNistObjectIdentifiers.IdSlhDsaShake_256f, nil);

  FSlhDsaSha2_128sWithSha256 := TSlhDsaParametersImpl.Create('SLH-DSA-SHA2-128S-WITH-SHA256',
    TSlhDsaParameterSet.SlhDsaSha2_128s, TNistObjectIdentifiers.IdHashSlhDsaSha2_128sWithSha256,
    TNistObjectIdentifiers.IdSha256);
  FSlhDsaShake_128sWithShake128 := TSlhDsaParametersImpl.Create('SLH-DSA-SHAKE-128S-WITH-SHAKE128',
    TSlhDsaParameterSet.SlhDsaShake_128s, TNistObjectIdentifiers.IdHashSlhDsaShake_128sWithShake128,
    TNistObjectIdentifiers.IdShake128);
  FSlhDsaSha2_128fWithSha256 := TSlhDsaParametersImpl.Create('SLH-DSA-SHA2-128F-WITH-SHA256',
    TSlhDsaParameterSet.SlhDsaSha2_128f, TNistObjectIdentifiers.IdHashSlhDsaSha2_128fWithSha256,
    TNistObjectIdentifiers.IdSha256);
  FSlhDsaShake_128fWithShake128 := TSlhDsaParametersImpl.Create('SLH-DSA-SHAKE-128F-WITH-SHAKE128',
    TSlhDsaParameterSet.SlhDsaShake_128f, TNistObjectIdentifiers.IdHashSlhDsaShake_128fWithShake128,
    TNistObjectIdentifiers.IdShake128);
  FSlhDsaSha2_192sWithSha512 := TSlhDsaParametersImpl.Create('SLH-DSA-SHA2-192S-WITH-SHA512',
    TSlhDsaParameterSet.SlhDsaSha2_192s, TNistObjectIdentifiers.IdHashSlhDsaSha2_192sWithSha512,
    TNistObjectIdentifiers.IdSha512);
  FSlhDsaShake_192sWithShake256 := TSlhDsaParametersImpl.Create('SLH-DSA-SHAKE-192S-WITH-SHAKE256',
    TSlhDsaParameterSet.SlhDsaShake_192s, TNistObjectIdentifiers.IdHashSlhDsaShake_192sWithShake256,
    TNistObjectIdentifiers.IdShake256);
  FSlhDsaSha2_192fWithSha512 := TSlhDsaParametersImpl.Create('SLH-DSA-SHA2-192F-WITH-SHA512',
    TSlhDsaParameterSet.SlhDsaSha2_192f, TNistObjectIdentifiers.IdHashSlhDsaSha2_192fWithSha512,
    TNistObjectIdentifiers.IdSha512);
  FSlhDsaShake_192fWithShake256 := TSlhDsaParametersImpl.Create('SLH-DSA-SHAKE-192F-WITH-SHAKE256',
    TSlhDsaParameterSet.SlhDsaShake_192f, TNistObjectIdentifiers.IdHashSlhDsaShake_192fWithShake256,
    TNistObjectIdentifiers.IdShake256);
  FSlhDsaSha2_256sWithSha512 := TSlhDsaParametersImpl.Create('SLH-DSA-SHA2-256S-WITH-SHA512',
    TSlhDsaParameterSet.SlhDsaSha2_256s, TNistObjectIdentifiers.IdHashSlhDsaSha2_256sWithSha512,
    TNistObjectIdentifiers.IdSha512);
  FSlhDsaShake_256sWithShake256 := TSlhDsaParametersImpl.Create('SLH-DSA-SHAKE-256S-WITH-SHAKE256',
    TSlhDsaParameterSet.SlhDsaShake_256s, TNistObjectIdentifiers.IdHashSlhDsaShake_256sWithShake256,
    TNistObjectIdentifiers.IdShake256);
  FSlhDsaSha2_256fWithSha512 := TSlhDsaParametersImpl.Create('SLH-DSA-SHA2-256F-WITH-SHA512',
    TSlhDsaParameterSet.SlhDsaSha2_256f, TNistObjectIdentifiers.IdHashSlhDsaSha2_256fWithSha512,
    TNistObjectIdentifiers.IdSha512);
  FSlhDsaShake_256fWithShake256 := TSlhDsaParametersImpl.Create('SLH-DSA-SHAKE-256F-WITH-SHAKE256',
    TSlhDsaParameterSet.SlhDsaShake_256f, TNistObjectIdentifiers.IdHashSlhDsaShake_256fWithShake256,
    TNistObjectIdentifiers.IdShake256);

  AddEntries(SlhDsaSha2_128f);
  AddEntries(SlhDsaSha2_128fWithSha256);
  AddEntries(SlhDsaSha2_128s);
  AddEntries(SlhDsaSha2_128sWithSha256);
  AddEntries(SlhDsaSha2_192f);
  AddEntries(SlhDsaSha2_192fWithSha512);
  AddEntries(SlhDsaSha2_192s);
  AddEntries(SlhDsaSha2_192sWithSha512);
  AddEntries(SlhDsaSha2_256f);
  AddEntries(SlhDsaSha2_256fWithSha512);
  AddEntries(SlhDsaSha2_256s);
  AddEntries(SlhDsaSha2_256sWithSha512);
  AddEntries(SlhDsaShake_128f);
  AddEntries(SlhDsaShake_128fWithShake128);
  AddEntries(SlhDsaShake_128s);
  AddEntries(SlhDsaShake_128sWithShake128);
  AddEntries(SlhDsaShake_192f);
  AddEntries(SlhDsaShake_192fWithShake256);
  AddEntries(SlhDsaShake_192s);
  AddEntries(SlhDsaShake_192sWithShake256);
  AddEntries(SlhDsaShake_256f);
  AddEntries(SlhDsaShake_256fWithShake256);
  AddEntries(SlhDsaShake_256s);
  AddEntries(SlhDsaShake_256sWithShake256);
end;

class destructor TSlhDsaParameters.Destroy;
begin
  FByOid.Free;
  FByName.Free;
  FSlhDsaSha2_128s := nil;
  FSlhDsaShake_128s := nil;
  FSlhDsaSha2_128f := nil;
  FSlhDsaShake_128f := nil;
  FSlhDsaSha2_192s := nil;
  FSlhDsaShake_192s := nil;
  FSlhDsaSha2_192f := nil;
  FSlhDsaShake_192f := nil;
  FSlhDsaSha2_256s := nil;
  FSlhDsaShake_256s := nil;
  FSlhDsaSha2_256f := nil;
  FSlhDsaShake_256f := nil;
  FSlhDsaSha2_128sWithSha256 := nil;
  FSlhDsaShake_128sWithShake128 := nil;
  FSlhDsaSha2_128fWithSha256 := nil;
  FSlhDsaShake_128fWithShake128 := nil;
  FSlhDsaSha2_192sWithSha512 := nil;
  FSlhDsaShake_192sWithShake256 := nil;
  FSlhDsaSha2_192fWithSha512 := nil;
  FSlhDsaShake_192fWithShake256 := nil;
  FSlhDsaSha2_256sWithSha512 := nil;
  FSlhDsaShake_256sWithShake256 := nil;
  FSlhDsaSha2_256fWithSha512 := nil;
  FSlhDsaShake_256fWithShake256 := nil;
end;

class function TSlhDsaParameters.ByName: TDictionary<string, ISlhDsaParameters>;
begin
  Result := FByName;
end;

class function TSlhDsaParameters.ByOid: TDictionary<IDerObjectIdentifier, ISlhDsaParameters>;
begin
  Result := FByOid;
end;

class function TSlhDsaParameters.GetByName(const AName: String): ISlhDsaParameters;
begin
  if not FByName.TryGetValue(AName, Result) then
    Result := nil;
end;

class function TSlhDsaParameters.GetByOid(const AOid: IDerObjectIdentifier): ISlhDsaParameters;
begin
  if not FByOid.TryGetValue(AOid, Result) then
    Result := nil;
end;

{ TSlhDsaKeyParameters }

constructor TSlhDsaKeyParameters.Create(APrivateKey: Boolean; const AParameters: ISlhDsaParameters);
begin
  inherited Create(APrivateKey);
  FParameters := AParameters;
end;

function TSlhDsaKeyParameters.GetParameters: ISlhDsaParameters;
begin
  Result := FParameters;
end;

{ TSlhDsaPublicKeyParameters }

class function TSlhDsaPublicKeyParameters.FromEncoding(const AParameters: ISlhDsaParameters;
  const AEncoding: TCryptoLibByteArray): ISlhDsaPublicKeyParameters;
var
  LN: Int32;
  LPk: TSlhDsaPK;
begin
  if AParameters = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SParametersNil);
  if AEncoding = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SParametersNil);
  if System.Length(AEncoding) <> AParameters.ParameterSet.PublicKeyLength then
    raise EArgumentCryptoLibException.CreateRes(@SInvalidSlhDsaLength);
  LN := AParameters.ParameterSet.N;
  LPk.Seed := TArrayUtilities.CopyOfRange<Byte>(AEncoding, 0, LN);
  LPk.Root := TArrayUtilities.CopyOfRange<Byte>(AEncoding, LN, 2 * LN);
  Result := TSlhDsaPublicKeyParameters.Create(AParameters, LPk);
end;

constructor TSlhDsaPublicKeyParameters.Create(const AParameters: ISlhDsaParameters; const APk: TSlhDsaPK);
begin
  inherited Create(False, AParameters);
  FPk := APk;
end;

constructor TSlhDsaPublicKeyParameters.Create(const AParameters: ISlhDsaParameters;
  const ASeed, ARoot: TCryptoLibByteArray);
begin
  inherited Create(False, AParameters);
  FPk.Seed := ASeed;
  FPk.Root := ARoot;
end;

function TSlhDsaPublicKeyParameters.GetEncoded: TCryptoLibByteArray;
begin
  System.SetLength(Result, System.Length(FPk.Seed) + System.Length(FPk.Root));
  System.Move(FPk.Seed[0], Result[0], System.Length(FPk.Seed));
  System.Move(FPk.Root[0], Result[System.Length(FPk.Seed)], System.Length(FPk.Root));
end;

function TSlhDsaPublicKeyParameters.GetPk: TSlhDsaPK;
begin
  Result := FPk;
end;

function TSlhDsaPublicKeyParameters.VerifyRaw(const AMsg: TCryptoLibByteArray; AMsgOff, AMsgLen: Int32;
  const ASignature: TCryptoLibByteArray): Boolean;
var
  LEngine: ISlhDsaEngine;
  LIdxDigest: ISlhDsaIndexedDigest;
  LAdrs: ISlhDsaAdrs;
  LPkFors, LDigest: TCryptoLibByteArray;
  LIdxTree: UInt64;
  LIdxLeaf: UInt32;
  LHt: TSlhDsaHT;
begin
  LEngine := Parameters.ParameterSet.GetEngine;
  if LEngine.SignatureLength <> System.Length(ASignature) then
    Exit(False);

  LEngine.Init(FPk.Seed);
  LIdxDigest := LEngine.HMsg(ASignature, 0, FPk.Seed, FPk.Root, AMsg, AMsgOff, AMsgLen);
  LDigest := LIdxDigest.Digest;
  LIdxTree := LIdxDigest.IdxTree;
  LIdxLeaf := LIdxDigest.IdxLeaf;

  LAdrs := TSlhDsaAdrs.Create(SlhDsaAdrsForsTree);
  LAdrs.SetLayerAddress(0);
  LAdrs.SetTreeAddress(LIdxTree);
  LAdrs.SetKeyPairAddress(LIdxLeaf);

  System.SetLength(LPkFors, LEngine.N);
  TSlhDsaFors.PKFromSig(LEngine, ASignature, LDigest, LAdrs, LPkFors, 0);

  LAdrs.SetTypeAndClear(SlhDsaAdrsTree);
  LAdrs.SetLayerAddress(0);
  LAdrs.SetTreeAddress(LIdxTree);
  LAdrs.SetKeyPairAddress(LIdxLeaf);

  LHt := TSlhDsaHT.Create(LEngine, nil, FPk.Seed);
  try
    Result := LHt.Verify(LPkFors, ASignature, FPk.Seed, LIdxTree, LIdxLeaf, FPk.Root);
  finally
    LHt.Free;
  end;
end;

{ TSlhDsaPrivateKeyParameters }

class function TSlhDsaPrivateKeyParameters.FromEncoding(const AParameters: ISlhDsaParameters;
  const AEncoding: TCryptoLibByteArray): ISlhDsaPrivateKeyParameters;
var
  LN: Int32;
  LSk: TSlhDsaSK;
  LPk: TSlhDsaPK;
begin
  if AParameters = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SParametersNil);
  if AEncoding = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SParametersNil);
  if System.Length(AEncoding) <> AParameters.ParameterSet.PrivateKeyLength then
    raise EArgumentCryptoLibException.CreateRes(@SInvalidSlhDsaLength);
  LN := AParameters.ParameterSet.N;
  LSk.Seed := TArrayUtilities.CopyOfRange<Byte>(AEncoding, 0, LN);
  LSk.Prf := TArrayUtilities.CopyOfRange<Byte>(AEncoding, LN, 2 * LN);
  LPk.Seed := TArrayUtilities.CopyOfRange<Byte>(AEncoding, 2 * LN, 3 * LN);
  LPk.Root := TArrayUtilities.CopyOfRange<Byte>(AEncoding, 3 * LN, 4 * LN);
  Result := TSlhDsaPrivateKeyParameters.Create(AParameters, LSk, LPk);
end;

constructor TSlhDsaPrivateKeyParameters.Create(const AParameters: ISlhDsaParameters;
  const ASk: TSlhDsaSK; const APk: TSlhDsaPK);
begin
  inherited Create(True, AParameters);
  FSk := ASk;
  FPk := APk;
end;

function TSlhDsaPrivateKeyParameters.GetEncoded: TCryptoLibByteArray;
var
  LN: Int32;
begin
  LN := Parameters.ParameterSet.N;
  System.SetLength(Result, 4 * LN);
  System.Move(FSk.Seed[0], Result[0], LN);
  System.Move(FSk.Prf[0], Result[LN], LN);
  System.Move(FPk.Seed[0], Result[2 * LN], LN);
  System.Move(FPk.Root[0], Result[3 * LN], LN);
end;

function TSlhDsaPrivateKeyParameters.GetPk: TSlhDsaPK;
begin
  Result := FPk;
end;

function TSlhDsaPrivateKeyParameters.GetPublicKey: ISlhDsaPublicKeyParameters;
begin
  Result := TSlhDsaPublicKeyParameters.Create(Parameters, FPk);
end;

function TSlhDsaPrivateKeyParameters.GetPublicKeyEncoded: TCryptoLibByteArray;
begin
  Result := GetPublicKey.GetEncoded;
end;

function TSlhDsaPrivateKeyParameters.GetSk: TSlhDsaSK;
begin
  Result := FSk;
end;

function TSlhDsaPrivateKeyParameters.SignRaw(const AOptRand: TCryptoLibByteArray;
  const AMsg: TCryptoLibByteArray; AMsgOff, AMsgLen: Int32): TCryptoLibByteArray;
var
  LEngine: ISlhDsaEngine;
  LOptRand: TCryptoLibByteArray;
  LIdxDigest: ISlhDsaIndexedDigest;
  LAdrs: ISlhDsaAdrs;
  LDigest: TCryptoLibByteArray;
  LIdxTree: UInt64;
  LIdxLeaf: UInt32;
  LPkFors: TCryptoLibByteArray;
  LHt: TSlhDsaHT;
begin
  LEngine := Parameters.ParameterSet.GetEngine;

  if AOptRand = nil then
    LOptRand := TArrayUtilities.CopyOfRange<Byte>(FPk.Seed, 0, LEngine.N)
  else if System.Length(AOptRand) <> LEngine.N then
    raise EArgumentOutOfRangeCryptoLibException.CreateRes(@SInvalidOptRandLength)
  else
    LOptRand := AOptRand;

  LEngine.Init(FPk.Seed);
  System.SetLength(Result, LEngine.SignatureLength);
  LEngine.PrfMsg(FSk.Prf, LOptRand, AMsg, AMsgOff, AMsgLen, Result, 0);

  LIdxDigest := LEngine.HMsg(Result, 0, FPk.Seed, FPk.Root, AMsg, AMsgOff, AMsgLen);
  LDigest := LIdxDigest.Digest;
  LIdxTree := LIdxDigest.IdxTree;
  LIdxLeaf := LIdxDigest.IdxLeaf;

  LAdrs := TSlhDsaAdrs.Create(SlhDsaAdrsForsTree);
  LAdrs.SetTreeAddress(LIdxTree);
  LAdrs.SetKeyPairAddress(LIdxLeaf);
  TSlhDsaFors.Sign(LEngine, LDigest, FSk.Seed, LAdrs, Result);

  LAdrs := TSlhDsaAdrs.Create(SlhDsaAdrsForsTree);
  LAdrs.SetTreeAddress(LIdxTree);
  LAdrs.SetKeyPairAddress(LIdxLeaf);
  System.SetLength(LPkFors, LEngine.N);
  TSlhDsaFors.PKFromSig(LEngine, Result, LDigest, LAdrs, LPkFors, 0);

  LHt := TSlhDsaHT.Create(LEngine, FSk.Seed, FPk.Seed);
  try
    LHt.Sign(LPkFors, LIdxTree, LIdxLeaf, Result);
  finally
    LHt.Free;
  end;
end;

{ TSlhDsaKeyGenerationParameters }

constructor TSlhDsaKeyGenerationParameters.Create(const ARandom: ISecureRandom;
  const AParameters: ISlhDsaParameters);
begin
  if ARandom = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SRandomNil);
  if AParameters = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SParametersNil);
  inherited Create(ARandom, 256);
  FParameters := AParameters;
end;

constructor TSlhDsaKeyGenerationParameters.Create(const ARandom: ISecureRandom;
  const AParametersOid: IDerObjectIdentifier);
var
  LParams: ISlhDsaParameters;
begin
  LParams := TSlhDsaParameters.GetByOid(AParametersOid);
  if LParams = nil then
    raise EArgumentCryptoLibException.CreateRes(@SUnrecognisedSlhDsaOid);
  Create(ARandom, LParams);
end;

function TSlhDsaKeyGenerationParameters.GetParameters: ISlhDsaParameters;
begin
  Result := FParameters;
end;

end.
