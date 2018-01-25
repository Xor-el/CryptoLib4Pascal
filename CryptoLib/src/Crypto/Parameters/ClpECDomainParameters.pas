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

unit ClpECDomainParameters;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpBigInteger,
  ClpIECInterface,
  ClpCryptoLibTypes,
  ClpIECDomainParameters;

resourcestring
  SCurveNil = 'Curve Cannot be Nil';
  SGNil = 'G Cannot be Nil';
  SBigIntegerNotInitialized = 'BigInteger Not Initialized "%s"';

type

  TECDomainParameters = class sealed(TInterfacedObject, IECDomainParameters)

  strict private
  var
    Fcurve: IECCurve;
    Fseed: TCryptoLibByteArray;
    Fg: IECPoint;
    Fn, Fh: TBigInteger;

    function GetCurve: IECCurve; inline;
    function GetG: IECPoint; inline;
    function GetH: TBigInteger; inline;
    function GetN: TBigInteger; inline;
    function GetSeed: TCryptoLibByteArray; inline;

  public

    constructor Create(const curve: IECCurve; const g: IECPoint;
      const n: TBigInteger); overload;
    constructor Create(const curve: IECCurve; const g: IECPoint;
      const n, h: TBigInteger); overload;
    constructor Create(const curve: IECCurve; const g: IECPoint;
      const n, h: TBigInteger; seed: TCryptoLibByteArray); overload;

    property curve: IECCurve read GetCurve;
    property g: IECPoint read GetG;
    property n: TBigInteger read GetN;
    property h: TBigInteger read GetH;
    property seed: TCryptoLibByteArray read GetSeed;
    function Equals(const other: IECDomainParameters): Boolean; reintroduce;
    function GetHashCode(): {$IFDEF DELPHI}Int32; {$ELSE}PtrInt;
{$ENDIF DELPHI}override;

  end;

implementation

{ TECDomainParameters }

constructor TECDomainParameters.Create(const curve: IECCurve; const g: IECPoint;
  const n: TBigInteger);
begin
  Create(curve, g, n, TBigInteger.One)
end;

constructor TECDomainParameters.Create(const curve: IECCurve; const g: IECPoint;
  const n, h: TBigInteger);
begin
  Create(curve, g, n, h, Nil);
end;

constructor TECDomainParameters.Create(const curve: IECCurve; const g: IECPoint;
  const n, h: TBigInteger; seed: TCryptoLibByteArray);
begin
  if (curve = Nil) then
    raise EArgumentNilCryptoLibException.CreateRes(@SCurveNil);
  if (g = Nil) then
    raise EArgumentNilCryptoLibException.CreateRes(@SGNil);

  if (not n.IsInitialized) then
    raise EArgumentNilCryptoLibException.CreateResFmt
      (@SBigIntegerNotInitialized, ['n']);

  if (not h.IsInitialized) then
    raise EArgumentNilCryptoLibException.CreateResFmt
      (@SBigIntegerNotInitialized, ['h']);

  Fcurve := curve;
  Fg := g.Normalize();
  Fn := n;
  Fh := h;

  Fseed := System.Copy(seed);

end;

function TECDomainParameters.Equals(const other: IECDomainParameters): Boolean;
begin

  if (other = Self as IECDomainParameters) then
  begin
    Result := true;
    Exit;
  end;

  if (other = Nil) then
  begin
    Result := false;
    Exit;
  end;

  Result := curve.Equals(other.curve) and g.Equals(other.g) and
    n.Equals(other.n) and h.Equals(other.h);

end;

function TECDomainParameters.GetCurve: IECCurve;
begin
  Result := Fcurve;
end;

function TECDomainParameters.GetG: IECPoint;
begin
  Result := Fg;
end;

function TECDomainParameters.GetH: TBigInteger;
begin
  Result := Fh;
end;

function TECDomainParameters.GetHashCode: {$IFDEF DELPHI}Int32; {$ELSE}PtrInt;
{$ENDIF DELPHI}
begin
  Result := curve.GetHashCode();
  Result := Result * 37;
  Result := Result xor g.GetHashCode();
  Result := Result * 37;
  Result := Result xor n.GetHashCode();
  Result := Result * 37;
  Result := Result xor h.GetHashCode();
end;

function TECDomainParameters.GetN: TBigInteger;
begin
  Result := Fn;
end;

function TECDomainParameters.GetSeed: TCryptoLibByteArray;
begin
  Result := Fseed;
end;

end.
