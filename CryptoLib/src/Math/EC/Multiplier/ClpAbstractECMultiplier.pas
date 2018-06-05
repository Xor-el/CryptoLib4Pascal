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

unit ClpAbstractECMultiplier;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpBigInteger,
  ClpIECInterface,
  ClpIAbstractECMultiplier,
  ClpECAlgorithms,
  SysUtils;

type
  TAbstractECMultiplier = class abstract(TInterfacedObject,
    IAbstractECMultiplier, IECMultiplier)

  strict protected
    function MultiplyPositive(const p: IECPoint; const k: TBigInteger)
      : IECPoint; virtual; abstract;

  public

    constructor Create();
    destructor Destroy; override;
    function Multiply(const p: IECPoint; const k: TBigInteger)
      : IECPoint; virtual;

  end;

implementation

{ TAbstractECMultiplier }

constructor TAbstractECMultiplier.Create;
begin
  Inherited Create();
end;

destructor TAbstractECMultiplier.Destroy;
begin
  inherited Destroy;
end;

function TAbstractECMultiplier.Multiply(const p: IECPoint; const k: TBigInteger)
  : IECPoint;
var
  positive: IECPoint;
  sign: Int32;
begin

  sign := k.SignValue;
  if ((sign = 0) or (p.IsInfinity)) then
  begin
    Result := p.Curve.Infinity;
    Exit;
  end;

  positive := MultiplyPositive(p, k.Abs());

  raise Exception.Create(p.ToString + ' DABA ' + k.Abs().ToString + ' DABA ' +
    positive.ToString);

  if sign > 0 then
  begin
    Result := positive
  end
  else
  begin
    Result := positive.Negate();
  end;

  // /*
  // * Although the various multipliers ought not to produce invalid output under normal
  // * circumstances, a final check here is advised to guard against fault attacks.
  // */
  Result := TECAlgorithms.ValidatePoint(Result);

end;

end.
