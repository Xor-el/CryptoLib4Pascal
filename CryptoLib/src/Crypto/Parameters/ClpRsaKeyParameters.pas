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

unit ClpRsaKeyParameters;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpBigInteger,
  ClpBigIntegers,
  ClpIRsaKeyParameters,
  ClpAsymmetricKeyParameter,
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

type
  TRsaKeyParameters = class(TAsymmetricKeyParameter, IRsaKeyParameters)

  strict private
  class var
    FSmallPrimesProduct: TBigInteger;

    class constructor CreateRsaKeyParameters();

    class function HasAnySmallFactors(const modulus: TBigInteger): Boolean; static;
    class function Validate(const modulus: TBigInteger): TBigInteger; static;

  strict private
  var
    FModulus: TBigInteger;
    FExponent: TBigInteger;

  strict protected
    function GetModulus: TBigInteger;
    function GetExponent: TBigInteger;

  public
    constructor Create(isPrivate: Boolean;
      const modulus, exponent: TBigInteger);

    function Equals(const other: IRsaKeyParameters): Boolean;
      reintroduce; overload;
    function GetHashCode(): {$IFDEF DELPHI}Int32; {$ELSE}PtrInt;
{$ENDIF DELPHI}override;

    property Modulus: TBigInteger read GetModulus;
    property Exponent: TBigInteger read GetExponent;

  end;

implementation

const
  // Hexadecimal value of the product of the 131 smallest odd primes from 3 to 743
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
  const modulus: TBigInteger): Boolean;
var
  M, X: TBigInteger;
begin
  // Check if modulus shares any factors with the product of small primes
  if modulus.BitLength < FSmallPrimesProduct.BitLength then
  begin
    M := FSmallPrimesProduct;
    X := modulus;
  end
  else
  begin
    M := modulus;
    X := FSmallPrimesProduct;
  end;

  Result := not TBigIntegers.ModOddIsCoprimeVar(M, X);
end;

class function TRsaKeyParameters.Validate(
  const modulus: TBigInteger): TBigInteger;
begin
  if (modulus.IsEven) then
  begin
    raise EArgumentCryptoLibException.CreateRes(@SRsaModulusIsEven);
  end;

  if (modulus.BitLength > DefaultMaxBitLength) then
  begin
    raise EArgumentCryptoLibException.CreateRes(@SRsaModulusOutOfRange);
  end;

  if HasAnySmallFactors(modulus) then
  begin
    raise EArgumentCryptoLibException.CreateRes(@SRsaModulusHasSmallPrimeFactor);
  end;

  Result := modulus;
end;

constructor TRsaKeyParameters.Create(isPrivate: Boolean;
  const modulus, exponent: TBigInteger);
begin
  inherited Create(isPrivate);

  if not modulus.IsInitialized then
  begin
    raise EArgumentNilCryptoLibException.CreateRes(@SModulusNil);
  end;

  if not exponent.IsInitialized then
  begin
    raise EArgumentNilCryptoLibException.CreateRes(@SExponentNil);
  end;

  if modulus.SignValue <= 0 then
  begin
    raise EArgumentCryptoLibException.CreateRes(@SNotValidRsaModulus);
  end;

  if exponent.SignValue <= 0 then
  begin
    raise EArgumentCryptoLibException.CreateRes(@SNotValidRsaExponent);
  end;

  if (not isPrivate) and (exponent.IsEven) then
  begin
    raise EArgumentCryptoLibException.CreateRes(@SRsaPublicExponentIsEven);
  end;

  FModulus := Validate(modulus);
  FExponent := exponent;
end;

function TRsaKeyParameters.Equals(const other: IRsaKeyParameters): Boolean;
begin
  if other = nil then
  begin
    Result := False;
    Exit;
  end;

  if ((Self as IRsaKeyParameters) = other) then
  begin
    Result := True;
    Exit;
  end;

  Result := (IsPrivate = other.IsPrivate) and
    FModulus.Equals(other.Modulus) and
    FExponent.Equals(other.Exponent);
end;

function TRsaKeyParameters.GetExponent: TBigInteger;
begin
  Result := FExponent;
end;

function TRsaKeyParameters.GetHashCode: {$IFDEF DELPHI}Int32; {$ELSE}PtrInt;
{$ENDIF DELPHI}
begin
  Result := FModulus.GetHashCode() xor FExponent.GetHashCode() xor
    Ord(IsPrivate);
end;

function TRsaKeyParameters.GetModulus: TBigInteger;
begin
  Result := FModulus;
end;

end.
