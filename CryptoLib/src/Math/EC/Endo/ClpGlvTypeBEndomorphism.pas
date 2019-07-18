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

unit ClpGlvTypeBEndomorphism;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpCryptoLibTypes,
  ClpBigInteger,
  ClpScaleXPointMap,
  ClpIGlvTypeBEndomorphism,
  ClpIECC,
  ClpIGlvTypeBParameters,
  ClpIGlvEndomorphism;

type
  TGlvTypeBEndomorphism = class(TInterfacedObject, IECEndomorphism,
    IGlvEndomorphism, IGlvTypeBEndomorphism)

  strict private
    function GetHasEfficientPointMap: Boolean; virtual;
    function GetPointMap: IECPointMap; virtual;

  strict protected
  var
    FParameters: IGlvTypeBParameters;
    FPointMap: IECPointMap;

    function CalculateB(const k, g: TBigInteger; t: Int32)
      : TBigInteger; virtual;

  public
    constructor Create(const curve: IECCurve;
      const parameters: IGlvTypeBParameters);
    destructor Destroy; override;
    function DecomposeScalar(const k: TBigInteger)
      : TCryptoLibGenericArray<TBigInteger>; virtual;

    property PointMap: IECPointMap read GetPointMap;
    property HasEfficientPointMap: Boolean read GetHasEfficientPointMap;
  end;

implementation

{ TGlvTypeBEndomorphism }

function TGlvTypeBEndomorphism.CalculateB(const k, g: TBigInteger; t: Int32)
  : TBigInteger;
var
  negative, extra: Boolean;
  b: TBigInteger;
begin
  negative := (g.SignValue < 0);
  b := k.Multiply(g.Abs());
  extra := b.TestBit(t - 1);
  b := b.ShiftRight(t);
  if (extra) then
  begin
    b := b.Add(TBigInteger.One);
  end;

  if negative then
  begin
    Result := b.Negate();
  end
  else
  begin
    Result := b;
  end;
end;

constructor TGlvTypeBEndomorphism.Create(const curve: IECCurve;
  const parameters: IGlvTypeBParameters);
begin
  Inherited Create();
  (*
    * NOTE: 'curve' MUST only be used to create a suitable ECFieldElement. Due to the way
    * ECCurve configuration works, 'curve' will not be the actual instance of ECCurve that the
    * endomorphism is being used with.
  *)
  FParameters := parameters;
  FPointMap := TScaleXPointMap.Create(curve.FromBigInteger(parameters.Beta));
end;

function TGlvTypeBEndomorphism.DecomposeScalar(const k: TBigInteger)
  : TCryptoLibGenericArray<TBigInteger>;
var
  bits: Int32;
  b1, b2, a, b: TBigInteger;
  p: IGlvTypeBParameters;
begin
  bits := FParameters.bits;
  b1 := CalculateB(k, FParameters.G1, bits);
  b2 := CalculateB(k, FParameters.G2, bits);

  p := FParameters;
  a := k.subtract((b1.Multiply(p.V1A)).Add(b2.Multiply(p.V2A)));
  b := (b1.Multiply(p.V1B)).Add(b2.Multiply(p.V2B)).Negate();

  Result := TCryptoLibGenericArray<TBigInteger>.Create(a, b);
end;

destructor TGlvTypeBEndomorphism.Destroy;
begin
  inherited Destroy;
end;

function TGlvTypeBEndomorphism.GetHasEfficientPointMap: Boolean;
begin
  Result := true;
end;

function TGlvTypeBEndomorphism.GetPointMap: IECPointMap;
begin
  Result := FPointMap;
end;

end.
