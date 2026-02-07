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

unit ClpGF2Polynomial;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpCryptoLibTypes,
  ClpArrayUtilities,
  ClpIPolynomial,
  ClpIGF2Polynomial;

type
  TGF2Polynomial = class sealed(TInterfacedObject, IPolynomial, IGF2Polynomial)
  strict private
    FExponents: TCryptoLibInt32Array;

    function GetDegree: Int32;
    function GetExponentsPresent: TCryptoLibInt32Array;
  public
    constructor Create(const AExponents: TCryptoLibInt32Array);
    function Equals(const AOther: IPolynomial): Boolean; reintroduce;
    function GetHashCode: {$IFDEF DELPHI}Int32; {$ELSE}PtrInt; {$ENDIF DELPHI} override;

    property Degree: Int32 read GetDegree;
    property ExponentsPresent: TCryptoLibInt32Array read GetExponentsPresent;
  end;

implementation

{ TGF2Polynomial }

constructor TGF2Polynomial.Create(const AExponents: TCryptoLibInt32Array);
begin
  Inherited Create();
  FExponents := TArrayUtilities.CopyOf(AExponents, System.Length(AExponents));
end;

function TGF2Polynomial.GetDegree: Int32;
begin
  Result := FExponents[System.High(FExponents)];
end;

function TGF2Polynomial.GetExponentsPresent: TCryptoLibInt32Array;
begin
  Result := TArrayUtilities.CopyOf(FExponents, System.Length(FExponents));
end;

function TGF2Polynomial.Equals(const AOther: IPolynomial): Boolean;
begin
  if AOther = nil then
    Exit(False);
  Result := (Degree = AOther.Degree) and
    TArrayUtilities.AreEqual<Int32>(FExponents, AOther.ExponentsPresent);
end;

function TGF2Polynomial.GetHashCode: {$IFDEF DELPHI}Int32; {$ELSE}PtrInt; {$ENDIF DELPHI};
begin
  Result := TArrayUtilities.GetArrayHashCode(FExponents);
end;

end.
