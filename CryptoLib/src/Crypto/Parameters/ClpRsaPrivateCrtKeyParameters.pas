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

unit ClpRsaPrivateCrtKeyParameters;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpBigInteger,
  ClpIRsaKeyParameters,
  ClpIRsaPrivateCrtKeyParameters,
  ClpRsaKeyParameters,
  ClpCryptoLibTypes;

resourcestring
  SNotValidRsaExponent = 'Not a valid RSA exponent';
  SNotValidRsaPValue = 'Not a valid RSA P value';
  SNotValidRsaQValue = 'Not a valid RSA Q value';
  SNotValidRsaDPValue = 'Not a valid RSA DP value';
  SNotValidRsaDQValue = 'Not a valid RSA DQ value';
  SNotValidRsaInverseQValue = 'Not a valid RSA InverseQ value';

type
  TRsaPrivateCrtKeyParameters = class(TRsaKeyParameters, IRsaPrivateCrtKeyParameters)

  strict private
  var
    Fe: TBigInteger;  // publicExponent
    Fp: TBigInteger;
    Fq: TBigInteger;
    FdP: TBigInteger;
    FdQ: TBigInteger;
    FqInv: TBigInteger;

    class procedure ValidateValue(const x: TBigInteger;
      const paramName, desc: String); static;

  strict protected
    function GetPublicExponent: TBigInteger;
    function GetP: TBigInteger;
    function GetQ: TBigInteger;
    function GetDP: TBigInteger;
    function GetDQ: TBigInteger;
    function GetQInv: TBigInteger;

  public
    constructor Create(const modulus, publicExponent, privateExponent,
      p, q, dP, dQ, qInv: TBigInteger);

    function Equals(const other: IRsaPrivateCrtKeyParameters): Boolean;
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

implementation

{ TRsaPrivateCrtKeyParameters }

class procedure TRsaPrivateCrtKeyParameters.ValidateValue(const x: TBigInteger;
  const paramName, desc: String);
begin
  if not x.IsInitialized then
  begin
    raise EArgumentNilCryptoLibException.Create(paramName);
  end;

  if x.SignValue <= 0 then
  begin
    raise EArgumentCryptoLibException.Create('Not a valid RSA ' + desc);
  end;
end;

constructor TRsaPrivateCrtKeyParameters.Create(const modulus, publicExponent,
  privateExponent, p, q, dP, dQ, qInv: TBigInteger);
begin
  inherited Create(True, modulus, privateExponent);

  ValidateValue(publicExponent, 'publicExponent', 'exponent');
  ValidateValue(p, 'p', 'P value');
  ValidateValue(q, 'q', 'Q value');
  ValidateValue(dP, 'dP', 'DP value');
  ValidateValue(dQ, 'dQ', 'DQ value');
  ValidateValue(qInv, 'qInv', 'InverseQ value');

  Fe := publicExponent;
  Fp := p;
  Fq := q;
  FdP := dP;
  FdQ := dQ;
  FqInv := qInv;
end;

function TRsaPrivateCrtKeyParameters.Equals(
  const other: IRsaPrivateCrtKeyParameters): Boolean;
begin
  if other = nil then
  begin
    Result := False;
    Exit;
  end;

  if ((Self as IRsaPrivateCrtKeyParameters) = other) then
  begin
    Result := True;
    Exit;
  end;

  Result := FdP.Equals(other.DP) and
    FdQ.Equals(other.DQ) and
    Exponent.Equals(other.Exponent) and
    Modulus.Equals(other.Modulus) and
    Fp.Equals(other.P) and
    Fq.Equals(other.Q) and
    Fe.Equals(other.PublicExponent) and
    FqInv.Equals(other.QInv);
end;

function TRsaPrivateCrtKeyParameters.GetDP: TBigInteger;
begin
  Result := FdP;
end;

function TRsaPrivateCrtKeyParameters.GetDQ: TBigInteger;
begin
  Result := FdQ;
end;

function TRsaPrivateCrtKeyParameters.GetHashCode: {$IFDEF DELPHI}Int32; {$ELSE}PtrInt;
{$ENDIF DELPHI}
begin
  Result := FdP.GetHashCode() xor FdQ.GetHashCode() xor
    Exponent.GetHashCode() xor Modulus.GetHashCode() xor
    Fp.GetHashCode() xor Fq.GetHashCode() xor
    Fe.GetHashCode() xor FqInv.GetHashCode();
end;

function TRsaPrivateCrtKeyParameters.GetP: TBigInteger;
begin
  Result := Fp;
end;

function TRsaPrivateCrtKeyParameters.GetPublicExponent: TBigInteger;
begin
  Result := Fe;
end;

function TRsaPrivateCrtKeyParameters.GetQ: TBigInteger;
begin
  Result := Fq;
end;

function TRsaPrivateCrtKeyParameters.GetQInv: TBigInteger;
begin
  Result := FqInv;
end;

end.
