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

unit ClpFiniteFields;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpBigInteger,
  ClpCryptoLibTypes,
  ClpIFiniteField,
  ClpIPolynomial,
  ClpIPolynomialExtensionField,
  ClpPrimeField,
  ClpGF2Polynomial,
  ClpGenericPolynomialExtensionField;

resourcestring
  SIrreduciblePolynomialsConstantTerm = 'Irreducible polynomials in GF(2) must have constant term';
  SPolynomialExponentsMonotonic = 'Polynomial exponents must be monotonically increasing';
  SCharacteristicMustBeAtLeast2 = 'Must be >= 2';

type
  TFiniteFields = class sealed(TObject)
  strict private
    class var
      FGF_2, FGF_3: IFiniteField;
    class constructor Create;
  public
    class function GetBinaryExtensionField(const AExponents: TCryptoLibInt32Array)
      : IPolynomialExtensionField; static;
    class function GetPrimeField(const ACharacteristic: TBigInteger)
      : IFiniteField; static;
    class property GF_2: IFiniteField read FGF_2;
    class property GF_3: IFiniteField read FGF_3;
  end;

implementation

{ TFiniteFields }

class constructor TFiniteFields.Create;
begin
  FGF_2 := TPrimeField.Create(TBigInteger.Two);
  FGF_3 := TPrimeField.Create(TBigInteger.Three);
end;

class function TFiniteFields.GetBinaryExtensionField
  (const AExponents: TCryptoLibInt32Array): IPolynomialExtensionField;
var
  LExponents: TCryptoLibInt32Array;
  I: Int32;
begin
  if System.Length(AExponents) = 0 then
    raise EArgumentCryptoLibException.CreateRes(@SIrreduciblePolynomialsConstantTerm);
  if AExponents[0] <> 0 then
    raise EArgumentCryptoLibException.CreateRes(@SIrreduciblePolynomialsConstantTerm);
  for I := 1 to System.High(AExponents) do
  begin
    if AExponents[I] <= AExponents[I - 1] then
      raise EArgumentCryptoLibException.CreateRes(@SPolynomialExponentsMonotonic);
  end;
  Result := TGenericPolynomialExtensionField.Create(FGF_2,
    TGF2Polynomial.Create(AExponents) as IPolynomial);
end;

class function TFiniteFields.GetPrimeField(const ACharacteristic: TBigInteger)
  : IFiniteField;
var
  LBitLength: Int32;
begin
  LBitLength := ACharacteristic.BitLength;
  if (ACharacteristic.SignValue <= 0) or (LBitLength < 2) then
    raise EArgumentCryptoLibException.CreateRes(@SCharacteristicMustBeAtLeast2);
  if LBitLength < 3 then
  begin
    case ACharacteristic.Int32Value of
      2:
        Exit(FGF_2);
      3:
        Exit(FGF_3);
    end;
  end;
  Result := TPrimeField.Create(ACharacteristic);
end;

end.
