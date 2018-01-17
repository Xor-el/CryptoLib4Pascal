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

unit ClpAbstractECMultiplier;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpBigInteger,
  ClpIECInterface,
  ClpIAbstractECMultiplier,
  ClpECAlgorithms;

type
  TAbstractECMultiplier = class abstract(TInterfacedObject,
    IAbstractECMultiplier, IECMultiplier)

  strict protected
    function MultiplyPositive(p: IECPoint; k: TBigInteger): IECPoint;
      virtual; abstract;

  public

    function Multiply(p: IECPoint; k: TBigInteger): IECPoint; virtual;

  end;

implementation

{ TAbstractECMultiplier }

function TAbstractECMultiplier.Multiply(p: IECPoint; k: TBigInteger): IECPoint;
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
