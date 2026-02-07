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

unit ClpGenericPolynomialExtensionField;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpBigInteger,
  ClpCryptoLibTypes,
  ClpBitOperations,
  ClpIFiniteField,
  ClpIPolynomial,
  ClpIExtensionField,
  ClpIPolynomialExtensionField,
  ClpIGenericPolynomialExtensionField;

type
  TGenericPolynomialExtensionField = class sealed(TInterfacedObject,
    IFiniteField, IExtensionField, IPolynomialExtensionField,
    IGenericPolynomialExtensionField)
  strict private
    FSubfield: IFiniteField;
    FMinimalPolynomial: IPolynomial;

    function GetCharacteristic: TBigInteger;
    function GetDimension: Int32;
    function GetSubfield: IFiniteField;
    function GetDegree: Int32;
    function GetMinimalPolynomial: IPolynomial;
  public
    constructor Create(const ASubfield: IFiniteField;
      const APolynomial: IPolynomial);
    function Equals(const AOther: IFiniteField): Boolean; reintroduce;
    function GetHashCode: {$IFDEF DELPHI}Int32; {$ELSE}PtrInt; {$ENDIF DELPHI} override;

    property Characteristic: TBigInteger read GetCharacteristic;
    property Dimension: Int32 read GetDimension;
    property Subfield: IFiniteField read GetSubfield;
    property Degree: Int32 read GetDegree;
    property MinimalPolynomial: IPolynomial read GetMinimalPolynomial;
  end;

implementation

{ TGenericPolynomialExtensionField }

constructor TGenericPolynomialExtensionField.Create(const ASubfield: IFiniteField;
  const APolynomial: IPolynomial);
begin
  Inherited Create();
  FSubfield := ASubfield;
  FMinimalPolynomial := APolynomial;
end;

function TGenericPolynomialExtensionField.GetCharacteristic: TBigInteger;
begin
  Result := FSubfield.Characteristic;
end;

function TGenericPolynomialExtensionField.GetDimension: Int32;
begin
  Result := FSubfield.Dimension * FMinimalPolynomial.Degree;
end;

function TGenericPolynomialExtensionField.GetSubfield: IFiniteField;
begin
  Result := FSubfield;
end;

function TGenericPolynomialExtensionField.GetDegree: Int32;
begin
  Result := FMinimalPolynomial.Degree;
end;

function TGenericPolynomialExtensionField.GetMinimalPolynomial: IPolynomial;
begin
  Result := FMinimalPolynomial;
end;

function TGenericPolynomialExtensionField.Equals(const AOther: IFiniteField): Boolean;
var
  LOther: IGenericPolynomialExtensionField;
  LExt: IExtensionField;
begin
  if AOther = nil then
    Exit(False);
  if not Supports(AOther, IGenericPolynomialExtensionField, LOther) then
    Exit(False);
  LExt := AOther as IExtensionField;
  Result := FSubfield.Equals(LExt.Subfield) and
    FMinimalPolynomial.Equals(LOther.MinimalPolynomial);
end;

function TGenericPolynomialExtensionField.GetHashCode: {$IFDEF DELPHI}Int32 {$ELSE}PtrInt {$ENDIF DELPHI};
begin
  Result := Int32(UInt32(FSubfield.GetHashCode) xor
    TBitOperations.RotateLeft32(UInt32(FMinimalPolynomial.GetHashCode), 16));
end;

end.
