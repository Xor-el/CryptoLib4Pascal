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

unit ClpPrimeField;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpBigInteger,
  ClpCryptoLibTypes,
  ClpIFiniteField,
  ClpIPrimeField;

type
  TPrimeField = class sealed(TInterfacedObject, IFiniteField, IPrimeField)
  strict private
    FCharacteristic: TBigInteger;

    function GetCharacteristic: TBigInteger;
    function GetDimension: Int32;
  public
    constructor Create(const ACharacteristic: TBigInteger);
    function Equals(const AOther: IFiniteField): Boolean; reintroduce;
    function GetHashCode: {$IFDEF DELPHI}Int32; {$ELSE}PtrInt; {$ENDIF DELPHI} override;

    property Characteristic: TBigInteger read GetCharacteristic;
    property Dimension: Int32 read GetDimension;
  end;

implementation

{ TPrimeField }

constructor TPrimeField.Create(const ACharacteristic: TBigInteger);
begin
  Inherited Create();
  FCharacteristic := ACharacteristic;
end;

function TPrimeField.GetCharacteristic: TBigInteger;
begin
  Result := FCharacteristic;
end;

function TPrimeField.GetDimension: Int32;
begin
  Result := 1;
end;

function TPrimeField.Equals(const AOther: IFiniteField): Boolean;
begin
  if AOther = nil then
    Exit(False);
  if (Self as IFiniteField) = AOther then
    Exit(True);
  Result := FCharacteristic.Equals(AOther.Characteristic);
end;

function TPrimeField.GetHashCode: {$IFDEF DELPHI}Int32{$ELSE}PtrInt{$ENDIF};
begin
  Result := FCharacteristic.GetHashCode();
end;

end.
