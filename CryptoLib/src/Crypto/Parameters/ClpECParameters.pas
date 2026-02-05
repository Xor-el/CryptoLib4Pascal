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

unit ClpECParameters;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SyncObjs,
  SysUtils,
  ClpBigInteger,
  ClpECAlgorithms,
  ClpIECC,
  ClpIECParameters,
  ClpIAsn1Objects,
  ClpIX9ECAsn1Objects,
  ClpX9ECAsn1Objects,
  ClpAsymmetricKeyParameter,
  ClpKeyGenerationParameters,
  ClpISecureRandom,
  ClpECUtilities,
  ClpCryptoLibTypes;

resourcestring
  SCurveNil = 'Curve Cannot be Nil';
  SScalarNil = 'Scalar Cannot be Nil';
  SGNil = 'G Cannot be Nil';
  SBigIntegerNotInitialized = 'BigInteger Not Initialized "%s"';
  SQNil = 'Q Cannot be Nil';
  SQInfinity = 'Point at Infinity "Q"';
  SQPointNotOnCurve = 'Point Not on Curve "Q"';
  SScalarInvalidRange = 'Scalar is not in the Interval [1, n - 1]';
  SImplicitlyCANotImplemented = 'implicitlyCA';
  SOidNil = 'OID Cannot be Nil';
  SOidNotValid = 'OID is not a valid public key parameter set';
  SAlgorithmNil = 'Algorithm Cannot be Empty';
  SParameterNil = 'Parameter Cannot be Nil';
  SUnRecognizedAlgorithm = 'Unrecognised Algorithm: " %s, "Algorithm';

type
  TECDomainParameters = class(TInterfacedObject, IECDomainParameters)

  strict private

  var
    FLock: TCriticalSection;
    FCurve: IECCurve;
    FSeed: TCryptoLibByteArray;
    FG: IECPoint;
    Fn, FH, FHInv: TBigInteger;

    function GetCurve: IECCurve; inline;
    function GetG: IECPoint; inline;
    function GetH: TBigInteger; inline;
    function GetN: TBigInteger; inline;
    function GetHInv: TBigInteger; inline;
    function GetSeed: TCryptoLibByteArray; inline;

  public

    class function ValidatePublicPoint(const ACurve: IECCurve; const AQ: IECPoint)
      : IECPoint; overload; static;

    class function FromX9ECParameters(const AX9ECParameters: IX9ECParameters): IECDomainParameters; static;
    class function FromX962Parameters(const AX962Parameters: IX962Parameters): IECDomainParameters; static;

    constructor Create(const ACurve: IECCurve; const AG: IECPoint;
      const AN: TBigInteger); overload;
    constructor Create(const ACurve: IECCurve; const AG: IECPoint;
      const AN, AH: TBigInteger); overload;
    constructor Create(const ACurve: IECCurve; const AG: IECPoint;
      const AN, AH: TBigInteger; const ASeed: TCryptoLibByteArray); overload;

    function ValidatePrivateScalar(const AD: TBigInteger): TBigInteger;
    function ValidatePublicPoint(const AQ: IECPoint): IECPoint; overload;

    destructor Destroy; override;

    property Curve: IECCurve read GetCurve;
    property G: IECPoint read GetG;
    property N: TBigInteger read GetN;
    property H: TBigInteger read GetH;
    property HInv: TBigInteger read GetHInv;
    property Seed: TCryptoLibByteArray read GetSeed;
    function Equals(const AOther: IECDomainParameters): Boolean; reintroduce;
    function GetHashCode(): {$IFDEF DELPHI}Int32; {$ELSE}PtrInt;
{$ENDIF DELPHI}override;
    function ToX962Parameters: IX962Parameters;
    function ToX9ECParameters: IX9ECParameters;

  end;

  TECNamedDomainParameters = class sealed(TECDomainParameters, IECNamedDomainParameters)

  strict private
  var
    FName: IDerObjectIdentifier;

    function GetName: IDerObjectIdentifier; inline;

  public
    class function LookupOid(const AOid: IDerObjectIdentifier): IECNamedDomainParameters; static;

    constructor Create(const AName: IDerObjectIdentifier; const ADp: IECDomainParameters); overload;
    constructor Create(const AName: IDerObjectIdentifier; const AX9: IX9ECParameters); overload;
    constructor Create(const AName: IDerObjectIdentifier; const ACurve: IECCurve; const AG: IECPoint; const AN: TBigInteger); overload;
    constructor Create(const AName: IDerObjectIdentifier; const ACurve: IECCurve; const AG: IECPoint; const AN, AH: TBigInteger); overload;
    constructor Create(const AName: IDerObjectIdentifier; const ACurve: IECCurve; const AG: IECPoint; const AN, AH: TBigInteger; const ASeed: TCryptoLibByteArray); overload;

    function ToX962Parameters: IX962Parameters; reintroduce;

    property Name: IDerObjectIdentifier read GetName;

  end;

  TECKeyParameters = class abstract(TAsymmetricKeyParameter, IECKeyParameters)

  strict private

  const

    FAlgorithms: array [0 .. 5] of String = ('EC', 'ECDSA', 'ECDH', 'ECDHC', 'ECGOST3410', 'ECMQV');

  var
    FAlgorithm: String;
    FParameters: IECDomainParameters;

  strict protected

    constructor Create(const AAlgorithm: String; AIsPrivate: Boolean;
      const AParameters: IECDomainParameters);

    function CreateKeyGenerationParameters(const ARandom: ISecureRandom)
      : IECKeyGenerationParameters; inline;

    function GetAlgorithmName: String; inline;
    function GetParameters: IECDomainParameters; inline;

    function Equals(const AOther: IECKeyParameters): Boolean;
      reintroduce; overload;

  public
    class function VerifyAlgorithmName(const AAlgorithm: String): String; static;
    property AlgorithmName: String read GetAlgorithmName;
    property Parameters: IECDomainParameters read GetParameters;
    function GetHashCode(): {$IFDEF DELPHI}Int32; {$ELSE}PtrInt;
{$ENDIF DELPHI}override;

  end;

  TECPublicKeyParameters = class sealed(TECKeyParameters,
    IECPublicKeyParameters)

  strict private
  var
    FQ: IECPoint;

    function GetQ: IECPoint; inline;

  public
    constructor Create(const AQ: IECPoint;
      const AParameters: IECDomainParameters); overload;

    constructor Create(const AAlgorithm: String; const AQ: IECPoint;
      const AParameters: IECDomainParameters); overload;

    property Q: IECPoint read GetQ;

    function Equals(const AOther: IECPublicKeyParameters): Boolean;
      reintroduce; overload;
    function GetHashCode(): {$IFDEF DELPHI}Int32; {$ELSE}PtrInt;
{$ENDIF DELPHI}override;

  end;

  TECPrivateKeyParameters = class sealed(TECKeyParameters,
    IECPrivateKeyParameters)

  strict private
  var
    FD: TBigInteger;

    function GetD: TBigInteger; inline;

  public
    constructor Create(const AD: TBigInteger;
      const AParameters: IECDomainParameters); overload;

    constructor Create(const AAlgorithm: String; const AD: TBigInteger;
      const AParameters: IECDomainParameters); overload;

    property D: TBigInteger read GetD;

    function Equals(const AOther: IECPrivateKeyParameters): Boolean;
      reintroduce; overload;
    function GetHashCode(): {$IFDEF DELPHI}Int32; {$ELSE}PtrInt;
{$ENDIF DELPHI}override;

  end;

  TECKeyGenerationParameters = class sealed(TKeyGenerationParameters,
    IECKeyGenerationParameters)

  strict private
  var
    FDomainParams: IECDomainParameters;

    function GetDomainParameters: IECDomainParameters;

  public
    constructor Create(const ADomainParameters: IECDomainParameters;
      const ARandom: ISecureRandom);
    property DomainParameters: IECDomainParameters read GetDomainParameters;
  end;

implementation

{ TECDomainParameters }

class function TECDomainParameters.ValidatePublicPoint(const ACurve: IECCurve;
  const AQ: IECPoint): IECPoint;
begin
  if (AQ = nil) then
    raise EArgumentNilCryptoLibException.CreateRes(@SQNil);

  Result := TECAlgorithms.ImportPoint(ACurve, AQ).Normalize();

  if (Result.IsInfinity) then
    raise EArgumentCryptoLibException.CreateRes(@SQInfinity);

  if (not(Result.IsValid())) then
    raise EArgumentCryptoLibException.CreateRes(@SQPointNotOnCurve);

end;

class function TECDomainParameters.FromX9ECParameters(const AX9ECParameters: IX9ECParameters): IECDomainParameters;
begin
  Result := TECDomainParameters.Create(AX9ECParameters.Curve, AX9ECParameters.G, AX9ECParameters.N, AX9ECParameters.H, AX9ECParameters.GetSeed());
end;

class function TECDomainParameters.FromX962Parameters(const AX962Parameters: IX962Parameters): IECDomainParameters;
var
  LNamedCurve: IDerObjectIdentifier;
  LX9: IX9ECParameters;
begin
  if AX962Parameters.IsImplicitlyCA then
    raise ENotSupportedCryptoLibException.Create(SImplicitlyCANotImplemented);

  LNamedCurve := AX962Parameters.GetNamedCurve;
  if LNamedCurve <> nil then
  begin
    Result := TECNamedDomainParameters.LookupOid(LNamedCurve);
    Exit;
  end;

  LX9 := TX9ECParameters.GetInstance(AX962Parameters.GetParameters);
  Result := FromX9ECParameters(LX9);
end;

function TECDomainParameters.GetCurve: IECCurve;
begin
  Result := FCurve;
end;

function TECDomainParameters.GetG: IECPoint;
begin
  Result := FG;
end;

function TECDomainParameters.GetH: TBigInteger;
begin
  Result := FH;
end;

function TECDomainParameters.GetN: TBigInteger;
begin
  Result := Fn;
end;

function TECDomainParameters.GetHInv: TBigInteger;
begin
  FLock.Acquire;
  try
    if (not(FHInv.IsInitialized)) then
    begin
      FHInv := H.ModInverse(N);
    end;
    Result := FHInv;
  finally
    FLock.Release;
  end;
end;

function TECDomainParameters.GetSeed: TCryptoLibByteArray;
begin
  Result := System.Copy(FSeed);
end;

constructor TECDomainParameters.Create(const ACurve: IECCurve; const AG: IECPoint;
  const AN: TBigInteger);
begin
  Create(ACurve, AG, AN, TBigInteger.One, nil);
end;

constructor TECDomainParameters.Create(const ACurve: IECCurve; const AG: IECPoint;
  const AN, AH: TBigInteger);
begin
  Create(ACurve, AG, AN, AH, nil);
end;

constructor TECDomainParameters.Create(const ACurve: IECCurve; const AG: IECPoint;
  const AN, AH: TBigInteger; const ASeed: TCryptoLibByteArray);
begin
  if (ACurve = nil) then
    raise EArgumentNilCryptoLibException.CreateRes(@SCurveNil);
  if (AG = nil) then
    raise EArgumentNilCryptoLibException.CreateRes(@SGNil);

  if (not AN.IsInitialized) then
    raise EArgumentNilCryptoLibException.CreateResFmt
      (@SBigIntegerNotInitialized, ['n']);

  FLock := TCriticalSection.Create;

  FCurve := ACurve;
  FG := ValidatePublicPoint(ACurve, AG);
  Fn := AN;
  FH := AH;
  FHInv := TBigInteger.GetDefault;

  FSeed := System.Copy(ASeed);

end;

destructor TECDomainParameters.Destroy;
begin
  FLock.Free;
  inherited Destroy;
end;

function TECDomainParameters.ValidatePublicPoint(const AQ: IECPoint): IECPoint;
begin
  Result := ValidatePublicPoint(Curve, AQ);
end;

function TECDomainParameters.ValidatePrivateScalar(const AD: TBigInteger)
  : TBigInteger;
begin
  if (not(AD.IsInitialized)) then
  begin
    raise EArgumentNilCryptoLibException.CreateRes(@SScalarNil);
  end;

  if ((AD.CompareTo(TBigInteger.One) < 0) or (AD.CompareTo(N) >= 0)) then
  begin
    raise EArgumentCryptoLibException.CreateRes(@SScalarInvalidRange);
  end;
  Result := AD;
end;

function TECDomainParameters.Equals(const AOther: IECDomainParameters): Boolean;
begin

  if (AOther = Self as IECDomainParameters) then
  begin
    Result := True;
    Exit;
  end;

  if (AOther = nil) then
  begin
    Result := False;
    Exit;
  end;

  Result := Curve.Equals(AOther.Curve) and G.Equals(AOther.G) and
    N.Equals(AOther.N);

  if H.IsInitialized then
  begin
    Result := Result and H.Equals(AOther.H);
  end;
end;

function TECDomainParameters.GetHashCode: {$IFDEF DELPHI}Int32; {$ELSE}PtrInt;
{$ENDIF DELPHI}
begin
  Result := 4;
  Result := Result * 257;
  Result := Result xor FCurve.GetHashCode();
  Result := Result * 257;
  Result := Result xor FG.GetHashCode();
  Result := Result * 257;
  Result := Result xor Fn.GetHashCode();

  if H.IsInitialized then
  begin
    Result := Result * 257;
    Result := Result xor FH.GetHashCode();
  end;
end;

function TECDomainParameters.ToX962Parameters: IX962Parameters;
begin
  Result := TX962Parameters.Create(ToX9ECParameters());
end;

function TECDomainParameters.ToX9ECParameters: IX9ECParameters;
var
  LG: IX9ECPoint;
begin
  LG := TX9ECPoint.Create(G, False);
  Result := TX9ECParameters.Create(Curve, LG, N, H, Seed);
end;

{ TECNamedDomainParameters }

class function TECNamedDomainParameters.LookupOid(const AOid: IDerObjectIdentifier): IECNamedDomainParameters;
var
  LX9: IX9ECParameters;
begin
  if AOid = nil then
    raise EArgumentNilCryptoLibException.Create(SOidNil);

  LX9 := TECUtilities.FindECCurveByOid(AOid);

  if LX9 = nil then
    raise EArgumentCryptoLibException.Create(SOidNotValid);

  Result := TECNamedDomainParameters.Create(AOid, LX9);
end;

function TECNamedDomainParameters.GetName: IDerObjectIdentifier;
begin
  Result := FName;
end;

constructor TECNamedDomainParameters.Create(const AName: IDerObjectIdentifier; const ADp: IECDomainParameters);
begin
  inherited Create(ADp.Curve, ADp.G, ADp.N, ADp.H, ADp.Seed);
  FName := AName;
end;

constructor TECNamedDomainParameters.Create(const AName: IDerObjectIdentifier; const AX9: IX9ECParameters);
begin
  inherited Create(AX9.Curve, AX9.G, AX9.N, AX9.H, AX9.GetSeed());
  FName := AName;
end;

constructor TECNamedDomainParameters.Create(const AName: IDerObjectIdentifier; const ACurve: IECCurve; const AG: IECPoint; const AN: TBigInteger);
begin
  inherited Create(ACurve, AG, AN);
  FName := AName;
end;

constructor TECNamedDomainParameters.Create(const AName: IDerObjectIdentifier; const ACurve: IECCurve; const AG: IECPoint; const AN, AH: TBigInteger);
begin
  inherited Create(ACurve, AG, AN, AH);
  FName := AName;
end;

constructor TECNamedDomainParameters.Create(const AName: IDerObjectIdentifier; const ACurve: IECCurve; const AG: IECPoint; const AN, AH: TBigInteger; const ASeed: TCryptoLibByteArray);
begin
  inherited Create(ACurve, AG, AN, AH, ASeed);
  FName := AName;
end;

function TECNamedDomainParameters.ToX962Parameters: IX962Parameters;
begin
  Result := TX962Parameters.Create(FName);
end;

{ TECKeyParameters }

function TECKeyParameters.GetParameters: IECDomainParameters;
begin
  Result := FParameters;
end;

class function TECKeyParameters.VerifyAlgorithmName(const AAlgorithm
  : String): String;
var
  LUpper: String;
  LI: Int32;
  LFound: Boolean;
begin
  LUpper := UpperCase(AAlgorithm);
  LFound := False;
  for LI := System.Low(FAlgorithms) to System.High(FAlgorithms) do
  begin
    if (FAlgorithms[LI] = AAlgorithm) then
    begin
      LFound := True;
      break;
    end;
  end;

  if (not LFound) then
  begin
    raise EArgumentCryptoLibException.CreateResFmt(@SUnRecognizedAlgorithm,
      [AAlgorithm]);
  end;
  Result := LUpper;
end;

constructor TECKeyParameters.Create(const AAlgorithm: String; AIsPrivate: Boolean;
  const AParameters: IECDomainParameters);
begin
  inherited Create(AIsPrivate);
  if (AAlgorithm = '') then
    raise EArgumentNilCryptoLibException.CreateRes(@SAlgorithmNil);

  if (AParameters = nil) then
    raise EArgumentNilCryptoLibException.CreateRes(@SParameterNil);

  FAlgorithm := VerifyAlgorithmName(AAlgorithm);
  FParameters := AParameters;
end;

function TECKeyParameters.CreateKeyGenerationParameters
  (const ARandom: ISecureRandom): IECKeyGenerationParameters;
begin
  Result := TECKeyGenerationParameters.Create(Parameters, ARandom);
end;

function TECKeyParameters.Equals(const AOther: IECKeyParameters): Boolean;
begin
  if (AOther = Self as IECKeyParameters) then
  begin
    Result := True;
    Exit;
  end;

  if (AOther = nil) then
  begin
    Result := False;
    Exit;
  end;
  Result := FParameters.Equals(AOther.Parameters) and (inherited Equals(AOther));
end;

function TECKeyParameters.GetAlgorithmName: String;
begin
  Result := FAlgorithm;
end;

function TECKeyParameters.GetHashCode: {$IFDEF DELPHI}Int32; {$ELSE}PtrInt;
{$ENDIF DELPHI}
begin
  Result := FParameters.GetHashCode() xor (inherited GetHashCode());
end;

{ TECPublicKeyParameters }

function TECPublicKeyParameters.GetQ: IECPoint;
begin
  Result := FQ;
end;

constructor TECPublicKeyParameters.Create(const AAlgorithm: String;
  const AQ: IECPoint; const AParameters: IECDomainParameters);
begin
  inherited Create(AAlgorithm, False, AParameters);

  if (AQ = nil) then
  begin
    raise EArgumentNilCryptoLibException.CreateRes(@SQNil);
  end;

  FQ := AParameters.ValidatePublicPoint(AQ);
end;

constructor TECPublicKeyParameters.Create(const AQ: IECPoint;
  const AParameters: IECDomainParameters);
begin
  Create('EC', AQ, AParameters);
end;

function TECPublicKeyParameters.Equals(const AOther
  : IECPublicKeyParameters): Boolean;
begin
  if (AOther = Self as IECPublicKeyParameters) then
  begin
    Result := True;
    Exit;
  end;

  if (AOther = nil) then
  begin
    Result := False;
    Exit;
  end;
  Result := Q.Equals(AOther.Q) and (inherited Equals(AOther));
end;

function TECPublicKeyParameters.GetHashCode: {$IFDEF DELPHI}Int32; {$ELSE}PtrInt;
{$ENDIF DELPHI}
begin
  Result := Q.GetHashCode() xor (inherited GetHashCode());
end;

{ TECPrivateKeyParameters }

function TECPrivateKeyParameters.GetD: TBigInteger;
begin
  Result := FD;
end;

constructor TECPrivateKeyParameters.Create(const AD: TBigInteger;
  const AParameters: IECDomainParameters);
begin
  Create('EC', AD, AParameters);
end;

constructor TECPrivateKeyParameters.Create(const AAlgorithm: String;
  const AD: TBigInteger; const AParameters: IECDomainParameters);
begin
  inherited Create(AAlgorithm, True, AParameters);
  if (not(AD.IsInitialized)) then
    raise EArgumentNilCryptoLibException.CreateResFmt
      (@SBigIntegerNotInitialized, ['d']);
  FD := AParameters.ValidatePrivateScalar(AD);
end;

function TECPrivateKeyParameters.Equals(const AOther
  : IECPrivateKeyParameters): Boolean;
begin
  if (AOther = Self as IECPrivateKeyParameters) then
  begin
    Result := True;
    Exit;
  end;

  if (AOther = nil) then
  begin
    Result := False;
    Exit;
  end;
  Result := D.Equals(AOther.D) and (inherited Equals(AOther));
end;

function TECPrivateKeyParameters.GetHashCode: {$IFDEF DELPHI}Int32; {$ELSE}PtrInt;
{$ENDIF DELPHI}
begin
  Result := D.GetHashCode() xor (inherited GetHashCode());
end;

{ TECKeyGenerationParameters }

constructor TECKeyGenerationParameters.Create(const ADomainParameters
  : IECDomainParameters; const ARandom: ISecureRandom);
begin
  inherited Create(ARandom, ADomainParameters.N.BitLength);
  FDomainParams := ADomainParameters;
end;

function TECKeyGenerationParameters.GetDomainParameters: IECDomainParameters;
begin
  Result := FDomainParams;
end;

end.
