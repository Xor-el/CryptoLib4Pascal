{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                    Copyright (c) 2018 Ugochukwu Mmaduekwe                       * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }

{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }

{ *                              Acknowledgements:                                  * }
{ *                                                                                 * }
{ *        Thanks to Sphere 10 Software (http://sphere10.com) for sponsoring        * }
{ *                        the development of this library                          * }

{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit ClpECPublicKeyParameters;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpCryptoLibTypes,
  ClpBigInteger,
  ClpIECInterface,
  ClpIECPublicKeyParameters,
  ClpIDerObjectIdentifier,
  ClpIECDomainParameters,
  ClpECKeyParameters;

resourcestring
  SQNil = 'Q Cannot be Nil';
  SQInfinity = 'Point at Infinity "Q"';
  SQPointNotOnCurve = 'Point Not on Curve "Q"';

type
  TECPublicKeyParameters = class sealed(TECKeyParameters,
    IECPublicKeyParameters)

  strict private
  var
    Fq: IECPoint;

    function GetQ: IECPoint; inline;
    class function Validate(q: IECPoint): IECPoint; static; inline;

  public
    constructor Create(q: IECPoint; parameters: IECDomainParameters); overload;

    constructor Create(const algorithm: String; q: IECPoint;
      parameters: IECDomainParameters); overload;

    constructor Create(const algorithm: String; q: IECPoint;
      publicKeyParamSet: IDerObjectIdentifier); overload;

    property q: IECPoint read GetQ;

    function Equals(other: IECPublicKeyParameters): Boolean; reintroduce;
    function GetHashCode(): {$IFDEF DELPHI}Int32; {$ELSE}PtrInt;
{$ENDIF DELPHI}override;

  end;

implementation

{ TECPublicKeyParameters }

class function TECPublicKeyParameters.Validate(q: IECPoint): IECPoint;
begin
  if (q = Nil) then
    raise EArgumentNilCryptoLibException.CreateRes(@SQNil);

  if (q.IsInfinity) then
    raise EArgumentCryptoLibException.CreateRes(@SQInfinity);

  q := q.Normalize();

  if (not(q.IsValid())) then
    raise EArgumentCryptoLibException.CreateRes(@SQPointNotOnCurve);

  result := q;
end;

constructor TECPublicKeyParameters.Create(const algorithm: String; q: IECPoint;
  parameters: IECDomainParameters);
begin
  Inherited Create(algorithm, false, parameters);
  if (q = Nil) then
    raise EArgumentNilCryptoLibException.CreateRes(@SQNil);

  Fq := Validate(q);
end;

constructor TECPublicKeyParameters.Create(q: IECPoint;
  parameters: IECDomainParameters);
begin
  Create('EC', q, parameters);
end;

constructor TECPublicKeyParameters.Create(const algorithm: String; q: IECPoint;
  publicKeyParamSet: IDerObjectIdentifier);
begin
  Inherited Create(algorithm, false, publicKeyParamSet);
  if (q = Nil) then
    raise EArgumentNilCryptoLibException.CreateRes(@SQNil);

  Fq := Validate(q);
end;

function TECPublicKeyParameters.Equals(other: IECPublicKeyParameters): Boolean;
begin
  if (other = Self as IECPublicKeyParameters) then
  begin
    result := true;
    Exit;
  end;

  if (other = Nil) then
  begin
    result := false;
    Exit;
  end;
  result := q.Equals(other.q) and (inherited Equals(other));
end;

function TECPublicKeyParameters.GetHashCode: {$IFDEF DELPHI}Int32; {$ELSE}PtrInt;
{$ENDIF DELPHI}
begin
  result := q.GetHashCode() xor (inherited GetHashCode());
end;

function TECPublicKeyParameters.GetQ: IECPoint;
begin
  result := Fq;
end;

end.
