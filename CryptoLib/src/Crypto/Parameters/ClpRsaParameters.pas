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
  SysUtils,
  ClpBigInteger,
  ClpBigIntegerUtilities,
  ClpPrimes,
  ClpCryptoServicesRegistrar,
  ClpIRsaParameters,
  ClpAsymmetricKeyParameter,
  ClpKeyGenerationParameters,
  ClpISecureRandom,
  ClpCryptoLibTypes;

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
    /// <summary>
    /// Default maximum RSA modulus bit length when <see cref="MaxSize"/> is unset (<c>-1</c>).
    /// </summary>
    const
      DefaultMaxBitLength = 16384;
    class var
      FMaxSize: Int32;
      FMaxMRTests: Int32;
    var
    FModulus: TBigInteger;
    FExponent: TBigInteger;

    class constructor Create;

    class function Validate(const AModulus: TBigInteger; AIsInternal: Boolean): TBigInteger; static;
    class function GetEffectiveMaxSize: Int32; static;
    class function GetEffectiveMaxMRTests(ABits: Int32): Int32; static;
    class function GetMRIterations(ABits: Int32): Int32; static;

  strict protected
    function GetModulus: TBigInteger;
    function GetExponent: TBigInteger;

  public

    class function ValidateModulus(const AModulus: TBigInteger): TBigInteger; static;

    /// <summary>
    /// Maximum allowed RSA modulus bit length for externally supplied keys.
    /// Unset (<c>-1</c>) or any negative value selects <see cref="DefaultMaxBitLength"/>.
    /// </summary>
    class property MaxSize: Int32 read FMaxSize write FMaxSize;

    /// <summary>
    /// Enhanced Miller-Rabin iteration count for externally supplied moduli.
    /// Unset (<c>-1</c>) or any negative value selects a bit-length-dependent default;
    /// <c>0</c> disables composite testing.
    /// </summary>
    class property MaxMRTests: Int32 read FMaxMRTests write FMaxMRTests;

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

    class procedure ValidateValue(const AX: TBigInteger;
      const AParamName, ADesc: String); static;

  strict protected
    function GetPublicExponent: TBigInteger;
    function GetP: TBigInteger;
    function GetQ: TBigInteger;
    function GetDP: TBigInteger;
    function GetDQ: TBigInteger;
    function GetQInv: TBigInteger;

  public
    constructor Create(const AModulus, APublicExponent, APrivateExponent,
      AP, AQ, ADP, ADQ, AQInv: TBigInteger); overload;
    constructor Create(const AModulus, APublicExponent, APrivateExponent,
      AP, AQ, ADP, ADQ, AQInv: TBigInteger; AIsInternal: Boolean); overload;

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

{ TRsaKeyParameters }

class constructor TRsaKeyParameters.Create;
begin
  FMaxSize := -1;
  FMaxMRTests := -1;
end;

class function TRsaKeyParameters.GetEffectiveMaxSize: Int32;
begin
  if FMaxSize < 0 then
    Result := DefaultMaxBitLength
  else
    Result := FMaxSize;
end;

class function TRsaKeyParameters.GetEffectiveMaxMRTests(ABits: Int32): Int32;
begin
  if FMaxMRTests < 0 then
    Result := GetMRIterations(ABits)
  else
    Result := FMaxMRTests;
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
  if not AIsInternal then
  begin
    if not AModulus.TestBit(0) then
      raise EArgumentCryptoLibException.CreateRes(@SRsaModulusIsEven);
    if AModulus.BitLength > GetEffectiveMaxSize then
      raise EArgumentCryptoLibException.CreateRes(@SRsaModulusOutOfRange);
    if TBigIntegerUtilities.HasAnySmallFactors(AModulus) then
      raise EArgumentCryptoLibException.CreateRes(@SRsaModulusHasSmallPrimeFactor);

    LIterations := GetEffectiveMaxMRTests(AModulus.BitLength div 2);
    if LIterations > 0 then
    begin
      LMR := TPrimes.EnhancedMRProbablePrimeTest(AModulus,
        TCryptoServicesRegistrar.GetSecureRandom(), LIterations);
      if not LMR.IsProvablyComposite then
        raise EArgumentCryptoLibException.CreateRes(@SRsaModulusIsNotComposite);
    end;
  end;
  Result := AModulus;
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
