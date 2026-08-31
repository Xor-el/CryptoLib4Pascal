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

unit ClpRsaParameters;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SyncObjs,
  SysUtils,
  ClpBigInteger,
  ClpBigIntegerUtilities,
  ClpRsaBlinding,
  ClpIRsaBlinding,
  ClpPrimes,
  ClpCryptoServicesRegistrar,
  ClpIRsaParameters,
  ClpAsymmetricKeyParameter,
  ClpKeyGenerationParameters,
  ClpISecureRandom,
  ClpCryptoLibConfig,
  ClpCryptoLibTypes,
  ClpCryptoLibExceptions;

resourcestring
  SModulusNil = 'modulus cannot be nil';
  SExponentNil = 'exponent cannot be nil';
  SRsaModulusIsEven = 'RSA modulus is even';
  SRsaModulusOutOfRange = 'RSA modulus out of range';
  SRsaModulusHasSmallPrimeFactor = 'RSA modulus has a small prime factor';
  SRsaModulusIsNotComposite = 'RSA modulus is not composite';
  SRsaPublicExponentIsEven = 'RSA publicExponent is even';
  SPublicExponentNil = 'public exponent cannot be nil';
  SPublicExponentNotOdd = 'public exponent must be an odd number';
  SPublicKeyRequired = 'RSA parameters should be for a public key';
  SNotAValidRsa = 'not a valid RSA %s';

type
  TRsaKeyParameters = class(TAsymmetricKeyParameter, IRsaKeyParameters)

  strict private
  type
    // a bounded set of moduli that already passed validation: a ring buffer that overwrites
    // the oldest entry when full, so the memory footprint stays fixed. Not self-locking - the
    // owner serialises access (the Miller-Rabin runs unlocked, only the ring ops are guarded).
    TValidatedModulusRing = record
    strict private
    const
      // upper bound on remembered moduli; a ring buffer overwrites the oldest entry when
      // full, so the memory footprint stays fixed under many distinct peers
      ValidatedModuliCacheSize = 32;
    var
      FEntries: TCryptoLibGenericArray<TBigInteger>;
      FCount: Int32;
      FNext: Int32;
    public
      class function Init: TValidatedModulusRing; static;
      function Contains(const AModulus: TBigInteger): Boolean;
      procedure Remember(const AModulus: TBigInteger);
    end;

  strict private
    class var
      FValidated: TValidatedModulusRing;
      FValidatedLock: TCriticalSection;
    var
    FModulus: TBigInteger;
    FExponent: TBigInteger;

    class constructor Create;
    class destructor Destroy;
    class function IsModulusValidated(const AModulus: TBigInteger): Boolean; static;
    class procedure MarkModulusValidated(const AModulus: TBigInteger); static;
    class function Validate(const AModulus: TBigInteger; AIsInternal: Boolean): TBigInteger; static;
    class function GetEffectiveMaxMRTests(ABits: Int32): Int32; static;
    class function GetMRIterations(ABits: Int32): Int32; static;

  strict protected
    function GetModulus: TBigInteger;
    function GetExponent: TBigInteger;

  public

    class function ValidateModulus(const AModulus: TBigInteger): TBigInteger; static;

    constructor Create(AIsPrivate: Boolean;
      const AModulus, AExponent: TBigInteger); overload;
    constructor Create(AIsPrivate: Boolean;
      const AModulus, AExponent: TBigInteger; AIsInternal: Boolean); overload;

    function Equals(const AOther: IRsaKeyParameters): Boolean;
      reintroduce; overload;
    function GetHashCode(): {$IFDEF DELPHI}Int32; {$ELSE}PtrInt;
{$ENDIF DELPHI}override;

    property Modulus: TBigInteger read GetModulus;
    property Exponent: TBigInteger read GetExponent;

  end;

  TRsaPrivateCrtKeyParameters = class(TRsaKeyParameters, IRsaPrivateCrtKeyParameters)

  strict private
  var
    FE: TBigInteger;  // publicExponent
    FP: TBigInteger;
    FQ: TBigInteger;
    FDP: TBigInteger;
    FDQ: TBigInteger;
    FQInv: TBigInteger;
    // lazily-created per-key blinding cache.
    FBlinding: IRsaBlinding;
    FBlindingLock: TCriticalSection;

    class procedure ValidateValue(const AX: TBigInteger;
      const AParamName, ADesc: String); static;

  strict protected
    function GetPublicExponent: TBigInteger;
    function GetP: TBigInteger;
    function GetQ: TBigInteger;
    function GetDP: TBigInteger;
    function GetDQ: TBigInteger;
    function GetQInv: TBigInteger;
    function GetBlinding(const ARandom: ISecureRandom): IRsaBlinding;

  public
    constructor Create(const AModulus, APublicExponent, APrivateExponent,
      AP, AQ, ADP, ADQ, AQInv: TBigInteger); overload;
    constructor Create(const AModulus, APublicExponent, APrivateExponent,
      AP, AQ, ADP, ADQ, AQInv: TBigInteger; AIsInternal: Boolean); overload;
    destructor Destroy; override;

    function Equals(const AOther: IRsaPrivateCrtKeyParameters): Boolean;
      reintroduce; overload;
    function GetHashCode(): {$IFDEF DELPHI}Int32; {$ELSE}PtrInt;
{$ENDIF DELPHI}override;

    property PublicExponent: TBigInteger read GetPublicExponent;
    property P: TBigInteger read GetP;
    property Q: TBigInteger read GetQ;
    property DP: TBigInteger read GetDP;
    property DQ: TBigInteger read GetDQ;
    property QInv: TBigInteger read GetQInv;

  end;

  /// <summary>
  /// RSA key generation parameters.
  /// </summary>
  TRsaKeyGenerationParameters = class(TKeyGenerationParameters,
    IRsaKeyGenerationParameters)

  strict private
  const
    DefaultTests = 100;

  var
    FPublicExponent: TBigInteger;
    FCertainty: Int32;

  strict protected
    function GetPublicExponent: TBigInteger;
    function GetCertainty: Int32;

  public
    constructor Create(const APublicExponent: TBigInteger;
      const ARandom: ISecureRandom; AStrength, ACertainty: Int32);

    function Equals(const AOther: IRsaKeyGenerationParameters): Boolean;
      reintroduce; overload;
    function GetHashCode: {$IFDEF DELPHI}Int32;{$ELSE}PtrInt;{$ENDIF DELPHI} override;

    property PublicExponent: TBigInteger read GetPublicExponent;
    property Certainty: Int32 read GetCertainty;

  end;

  /// <summary>
  /// Parameters for RSA blinding operations.
  /// </summary>
  TRsaBlindingParameters = class(TInterfacedObject, IRsaBlindingParameters)

  strict private
  var
    FPublicKey: IRsaKeyParameters;
    FBlindingFactor: TBigInteger;

  strict protected
    function GetPublicKey: IRsaKeyParameters;
    function GetBlindingFactor: TBigInteger;

  public
    constructor Create(const APublicKey: IRsaKeyParameters;
      const ABlindingFactor: TBigInteger);

    property PublicKey: IRsaKeyParameters read GetPublicKey;
    property BlindingFactor: TBigInteger read GetBlindingFactor;

  end;

implementation

{ TRsaKeyParameters.TValidatedModulusRing }

class function TRsaKeyParameters.TValidatedModulusRing.Init: TValidatedModulusRing;
begin
  System.SetLength(Result.FEntries, ValidatedModuliCacheSize);
  Result.FCount := 0;
  Result.FNext := 0;
end;

function TRsaKeyParameters.TValidatedModulusRing.Contains(
  const AModulus: TBigInteger): Boolean;
var
  LI: Int32;
begin
  Result := False;
  for LI := 0 to FCount - 1 do
    if FEntries[LI].Equals(AModulus) then
      Exit(True);
end;

procedure TRsaKeyParameters.TValidatedModulusRing.Remember(
  const AModulus: TBigInteger);
var
  LI: Int32;
begin
  // another thread may have remembered the same modulus between the caller's check and now
  for LI := 0 to FCount - 1 do
    if FEntries[LI].Equals(AModulus) then
      Exit;
  FEntries[FNext] := AModulus;
  FNext := (FNext + 1) mod System.Length(FEntries);
  if FCount < System.Length(FEntries) then
    Inc(FCount);
end;

{ TRsaKeyParameters }

class constructor TRsaKeyParameters.Create;
begin
  FValidated := TValidatedModulusRing.Init;
  FValidatedLock := TCriticalSection.Create;
end;

class destructor TRsaKeyParameters.Destroy;
begin
  FValidatedLock.Free;
end;

class function TRsaKeyParameters.IsModulusValidated(
  const AModulus: TBigInteger): Boolean;
begin
  FValidatedLock.Enter;
  try
    Result := FValidated.Contains(AModulus);
  finally
    FValidatedLock.Leave;
  end;
end;

class procedure TRsaKeyParameters.MarkModulusValidated(
  const AModulus: TBigInteger);
begin
  FValidatedLock.Enter;
  try
    FValidated.Remember(AModulus);
  finally
    FValidatedLock.Leave;
  end;
end;

class function TRsaKeyParameters.GetEffectiveMaxMRTests(ABits: Int32): Int32;
begin
  if TCryptoLibConfig.Rsa.MaxMRTests.HasValue then
    Result := TCryptoLibConfig.Rsa.MaxMRTests.Value
  else
    Result := GetMRIterations(ABits);
end;

class function TRsaKeyParameters.GetMRIterations(ABits: Int32): Int32;
begin
  if ABits >= 1536 then
    Result := 3
  else if ABits >= 1024 then
    Result := 4
  else if ABits >= 512 then
    Result := 7
  else
    Result := 50;
end;

class function TRsaKeyParameters.ValidateModulus(
  const AModulus: TBigInteger): TBigInteger;
begin
  Result := Validate(AModulus, False);
end;

class function TRsaKeyParameters.Validate(const AModulus: TBigInteger;
  AIsInternal: Boolean): TBigInteger;
var
  LIterations: Int32;
  LMR: TPrimes.IMROutput;
begin
  Result := AModulus;
  if AIsInternal then
    Exit;

  // the cheap invariants always run: they are microseconds and depend on live config (MaxSize),
  // so a modulus is still rejected when the limits change even after it was seen before
  if not AModulus.TestBit(0) then
    raise EArgumentCryptoLibException.CreateRes(@SRsaModulusIsEven);
  if AModulus.BitLength > TCryptoLibConfig.Rsa.MaxSize then
    raise EArgumentCryptoLibException.CreateRes(@SRsaModulusOutOfRange);
  if TBigIntegerUtilities.HasAnySmallFactors(AModulus) then
    raise EArgumentCryptoLibException.CreateRes(@SRsaModulusHasSmallPrimeFactor);

  // only the expensive Miller-Rabin is memoized: a modulus that already passed it does not need
  // it again - the server's own key across signs, a peer/root certificate across handshakes
  if IsModulusValidated(AModulus) then
    Exit;

  LIterations := GetEffectiveMaxMRTests(AModulus.BitLength div 2);
  if LIterations > 0 then
  begin
    LMR := TPrimes.EnhancedMRProbablePrimeTest(AModulus,
      TCryptoServicesRegistrar.GetSecureRandom(), LIterations);
    if not LMR.IsProvablyComposite then
      raise EArgumentCryptoLibException.CreateRes(@SRsaModulusIsNotComposite);
    MarkModulusValidated(AModulus);
  end;
end;

constructor TRsaKeyParameters.Create(AIsPrivate: Boolean;
  const AModulus, AExponent: TBigInteger);
begin
  Create(AIsPrivate, AModulus, AExponent, False);
end;

constructor TRsaKeyParameters.Create(AIsPrivate: Boolean;
  const AModulus, AExponent: TBigInteger; AIsInternal: Boolean);
begin
  inherited Create(AIsPrivate);
  if not AModulus.IsInitialized then
    raise EArgumentNilCryptoLibException.CreateRes(@SModulusNil);
  if not AExponent.IsInitialized then
    raise EArgumentNilCryptoLibException.CreateRes(@SExponentNil);
  if AModulus.SignValue <= 0 then
    raise EArgumentCryptoLibException.CreateResFmt(@SNotAValidRsa, ['modulus']);
  if AExponent.SignValue <= 0 then
    raise EArgumentCryptoLibException.CreateResFmt(@SNotAValidRsa, ['exponent']);
  if (not AIsPrivate) and (AExponent.IsEven) then
    raise EArgumentCryptoLibException.CreateRes(@SRsaPublicExponentIsEven);
  FModulus := Validate(AModulus, AIsInternal);
  FExponent := AExponent;
end;

function TRsaKeyParameters.Equals(const AOther: IRsaKeyParameters): Boolean;
begin
  if AOther = nil then
  begin
    Result := False;
    Exit;
  end;
  if ((Self as IRsaKeyParameters) = AOther) then
  begin
    Result := True;
    Exit;
  end;
  Result := (IsPrivate = AOther.IsPrivate) and
    FModulus.Equals(AOther.Modulus) and FExponent.Equals(AOther.Exponent);
end;

function TRsaKeyParameters.GetExponent: TBigInteger;
begin
  Result := FExponent;
end;

function TRsaKeyParameters.GetHashCode: {$IFDEF DELPHI}Int32; {$ELSE}PtrInt;{$ENDIF DELPHI}
begin
  Result := FModulus.GetHashCode() xor FExponent.GetHashCode() xor Ord(IsPrivate);
end;

function TRsaKeyParameters.GetModulus: TBigInteger;
begin
  Result := FModulus;
end;

{ TRsaPrivateCrtKeyParameters }

class procedure TRsaPrivateCrtKeyParameters.ValidateValue(const AX: TBigInteger;
  const AParamName, ADesc: String);
begin
  if not AX.IsInitialized then
    raise EArgumentNilCryptoLibException.Create(AParamName);
  if AX.SignValue <= 0 then
    raise EArgumentCryptoLibException.CreateResFmt(@SNotAValidRsa, [ADesc]);
end;

constructor TRsaPrivateCrtKeyParameters.Create(const AModulus, APublicExponent,
  APrivateExponent, AP, AQ, ADP, ADQ, AQInv: TBigInteger);
begin
  Create(AModulus, APublicExponent, APrivateExponent, AP, AQ, ADP, ADQ, AQInv, False);
end;

constructor TRsaPrivateCrtKeyParameters.Create(const AModulus, APublicExponent,
  APrivateExponent, AP, AQ, ADP, ADQ, AQInv: TBigInteger; AIsInternal: Boolean);
begin
  inherited Create(True, AModulus, APrivateExponent, AIsInternal);
  ValidateValue(APublicExponent, 'publicExponent', 'exponent');
  ValidateValue(AP, 'p', 'P value');
  ValidateValue(AQ, 'q', 'Q value');
  ValidateValue(ADP, 'dP', 'DP value');
  ValidateValue(ADQ, 'dQ', 'DQ value');
  ValidateValue(AQInv, 'qInv', 'InverseQ value');
  FE := APublicExponent;
  FP := AP;
  FQ := AQ;
  FDP := ADP;
  FDQ := ADQ;
  FQInv := AQInv;
  FBlindingLock := TCriticalSection.Create;
end;

destructor TRsaPrivateCrtKeyParameters.Destroy;
begin
  FBlindingLock.Free;
  inherited Destroy;
end;

function TRsaPrivateCrtKeyParameters.GetBlinding(
  const ARandom: ISecureRandom): IRsaBlinding;
begin
  // guarded lazy init: the cache is created once and shared by every signature,
  // so the read is always taken under the lock (no unpublished-object window).
  FBlindingLock.Acquire;
  try
    if FBlinding = nil then
      FBlinding := TRsaBlindingBase.NewBlinding(Modulus, FE, ARandom);
    Result := FBlinding;
  finally
    FBlindingLock.Release;
  end;
end;

function TRsaPrivateCrtKeyParameters.Equals(
  const AOther: IRsaPrivateCrtKeyParameters): Boolean;
begin
  if AOther = nil then
  begin
    Result := False;
    Exit;
  end;
  if ((Self as IRsaPrivateCrtKeyParameters) = AOther) then
  begin
    Result := True;
    Exit;
  end;
  Result := FDP.Equals(AOther.DP) and FDQ.Equals(AOther.DQ) and
    Exponent.Equals(AOther.Exponent) and Modulus.Equals(AOther.Modulus) and
    FP.Equals(AOther.P) and FQ.Equals(AOther.Q) and
    FE.Equals(AOther.PublicExponent) and FQInv.Equals(AOther.QInv);
end;

function TRsaPrivateCrtKeyParameters.GetDP: TBigInteger;
begin
  Result := FDP;
end;

function TRsaPrivateCrtKeyParameters.GetDQ: TBigInteger;
begin
  Result := FDQ;
end;

function TRsaPrivateCrtKeyParameters.GetHashCode: {$IFDEF DELPHI}Int32; {$ELSE}PtrInt;{$ENDIF DELPHI}
begin
  Result := FDP.GetHashCode() xor FDQ.GetHashCode() xor Exponent.GetHashCode() xor
    Modulus.GetHashCode() xor FP.GetHashCode() xor FQ.GetHashCode() xor
    FE.GetHashCode() xor FQInv.GetHashCode();
end;

function TRsaPrivateCrtKeyParameters.GetP: TBigInteger;
begin
  Result := FP;
end;

function TRsaPrivateCrtKeyParameters.GetPublicExponent: TBigInteger;
begin
  Result := FE;
end;

function TRsaPrivateCrtKeyParameters.GetQ: TBigInteger;
begin
  Result := FQ;
end;

function TRsaPrivateCrtKeyParameters.GetQInv: TBigInteger;
begin
  Result := FQInv;
end;

{ TRsaKeyGenerationParameters }

constructor TRsaKeyGenerationParameters.Create(const APublicExponent: TBigInteger;
  const ARandom: ISecureRandom; AStrength, ACertainty: Int32);
begin
  inherited Create(ARandom, AStrength);
  if not APublicExponent.IsInitialized then
    raise EArgumentNilCryptoLibException.CreateRes(@SPublicExponentNil);
  if not APublicExponent.TestBit(0) then
    raise EArgumentCryptoLibException.CreateRes(@SPublicExponentNotOdd);
  FPublicExponent := APublicExponent;
  FCertainty := ACertainty;
end;

function TRsaKeyGenerationParameters.GetCertainty: Int32;
begin
  Result := FCertainty;
end;

function TRsaKeyGenerationParameters.GetPublicExponent: TBigInteger;
begin
  Result := FPublicExponent;
end;

function TRsaKeyGenerationParameters.Equals(const AOther: IRsaKeyGenerationParameters): Boolean;
begin
  if AOther = nil then
  begin
    Result := False;
    Exit;
  end;
  if (Self as IRsaKeyGenerationParameters) = AOther then
  begin
    Result := True;
    Exit;
  end;
  Result := (FCertainty = AOther.Certainty) and FPublicExponent.Equals(AOther.PublicExponent);
end;

function TRsaKeyGenerationParameters.GetHashCode: {$IFDEF DELPHI}Int32;{$ELSE}PtrInt;{$ENDIF DELPHI}
begin
  Result := FCertainty xor FPublicExponent.GetHashCode();
end;

{ TRsaBlindingParameters }

constructor TRsaBlindingParameters.Create(const APublicKey: IRsaKeyParameters;
  const ABlindingFactor: TBigInteger);
begin
  inherited Create();
  if APublicKey.IsPrivate then
    raise EArgumentCryptoLibException.CreateRes(@SPublicKeyRequired);
  FPublicKey := APublicKey;
  FBlindingFactor := ABlindingFactor;
end;

function TRsaBlindingParameters.GetBlindingFactor: TBigInteger;
begin
  Result := FBlindingFactor;
end;

function TRsaBlindingParameters.GetPublicKey: IRsaKeyParameters;
begin
  Result := FPublicKey;
end;

end.
