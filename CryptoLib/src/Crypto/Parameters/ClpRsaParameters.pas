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

unit ClpRsaParameters;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpBigInteger,
  ClpBigIntegerUtilities,
  ClpIRsaParameters,
  ClpAsymmetricKeyParameter,
  ClpKeyGenerationParameters,
  ClpISecureRandom,
  ClpCryptoLibTypes;

resourcestring
  SModulusNil = 'modulus';
  SExponentNil = 'exponent';
  SNotValidRsaModulus = 'Not a valid RSA modulus';
  SNotValidRsaExponent = 'Not a valid RSA exponent';
  SRsaModulusIsEven = 'RSA modulus is even';
  SRsaModulusOutOfRange = 'RSA modulus out of range';
  SRsaModulusHasSmallPrimeFactor = 'RSA modulus has a small prime factor';
  SRsaPublicExponentIsEven = 'RSA publicExponent is even';
  SNotValidRsaPValue = 'Not a valid RSA P value';
  SNotValidRsaQValue = 'Not a valid RSA Q value';
  SNotValidRsaDPValue = 'Not a valid RSA DP value';
  SNotValidRsaDQValue = 'Not a valid RSA DQ value';
  SNotValidRsaInverseQValue = 'Not a valid RSA InverseQ value';
  SPublicExponentNil = 'publicExponent';
  SPublicExponentNotOdd = 'Public exponent must be an odd number';
  SPublicKeyRequired = 'RSA parameters should be for a public key';

type
  TRsaKeyParameters = class(TAsymmetricKeyParameter, IRsaKeyParameters)

  strict private
  class var
    FSmallPrimesProduct: TBigInteger;

    class constructor CreateRsaKeyParameters();

    class function HasAnySmallFactors(const AModulus: TBigInteger): Boolean; static;
    class function Validate(const AModulus: TBigInteger): TBigInteger; static;

  strict private
  var
    FModulus: TBigInteger;
    FExponent: TBigInteger;

  strict protected
    function GetModulus: TBigInteger;
    function GetExponent: TBigInteger;

  public
    constructor Create(AIsPrivate: Boolean;
      const AModulus, AExponent: TBigInteger);

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
      AP, AQ, ADP, ADQ, AQInv: TBigInteger);

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

const
  SmallPrimesProductHex =
    '8138e8a0fcf3a4e84a771d40fd305d7f4aa59306d7251de54d98af8fe95729a1f' +
    '73d893fa424cd2edc8636a6c3285e022b0e3866a565ae8108eed8591cd4fe8d2' +
    'ce86165a978d719ebf647f362d33fca29cd179fb42401cbaf3df0c614056f9c8' +
    'f3cfd51e474afb6bc6974f78db8aba8e9e517fded658591ab7502bd41849462f';
  DefaultMaxBitLength = 16384;

{ TRsaKeyParameters }

class constructor TRsaKeyParameters.CreateRsaKeyParameters;
begin
  FSmallPrimesProduct := TBigInteger.Create(SmallPrimesProductHex, 16);
end;

class function TRsaKeyParameters.HasAnySmallFactors(
  const AModulus: TBigInteger): Boolean;
var
  LM, LX: TBigInteger;
begin
  if AModulus.BitLength < FSmallPrimesProduct.BitLength then
  begin
    LM := FSmallPrimesProduct;
    LX := AModulus;
  end
  else
  begin
    LM := AModulus;
    LX := FSmallPrimesProduct;
  end;
  Result := not TBigIntegerUtilities.ModOddIsCoprimeVar(LM, LX);
end;

class function TRsaKeyParameters.Validate(
  const AModulus: TBigInteger): TBigInteger;
begin
  if (AModulus.IsEven) then
    raise EArgumentCryptoLibException.CreateRes(@SRsaModulusIsEven);
  if (AModulus.BitLength > DefaultMaxBitLength) then
    raise EArgumentCryptoLibException.CreateRes(@SRsaModulusOutOfRange);
  if HasAnySmallFactors(AModulus) then
    raise EArgumentCryptoLibException.CreateRes(@SRsaModulusHasSmallPrimeFactor);
  Result := AModulus;
end;

constructor TRsaKeyParameters.Create(AIsPrivate: Boolean;
  const AModulus, AExponent: TBigInteger);
begin
  inherited Create(AIsPrivate);
  if not AModulus.IsInitialized then
    raise EArgumentNilCryptoLibException.CreateRes(@SModulusNil);
  if not AExponent.IsInitialized then
    raise EArgumentNilCryptoLibException.CreateRes(@SExponentNil);
  if AModulus.SignValue <= 0 then
    raise EArgumentCryptoLibException.CreateRes(@SNotValidRsaModulus);
  if AExponent.SignValue <= 0 then
    raise EArgumentCryptoLibException.CreateRes(@SNotValidRsaExponent);
  if (not AIsPrivate) and (AExponent.IsEven) then
    raise EArgumentCryptoLibException.CreateRes(@SRsaPublicExponentIsEven);
  FModulus := Validate(AModulus);
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
    raise EArgumentCryptoLibException.Create('Not a valid RSA ' + ADesc);
end;

constructor TRsaPrivateCrtKeyParameters.Create(const AModulus, APublicExponent,
  APrivateExponent, AP, AQ, ADP, ADQ, AQInv: TBigInteger);
begin
  inherited Create(True, AModulus, APrivateExponent);
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
