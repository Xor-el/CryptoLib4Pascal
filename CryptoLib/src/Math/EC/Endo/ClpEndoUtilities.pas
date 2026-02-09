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

unit ClpEndoUtilities;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpBigInteger,
  ClpIECCommon,
  ClpIPreCompCallback,
  ClpIPreCompInfo,
  ClpIEndoPreCompInfo,
  ClpIScalarSplitParameters,
  ClpEndoPreCompInfo,
  ClpCryptoLibTypes;

type
  TEndoUtilities = class sealed(TObject)
  strict private
    type
      TMapPointCallback = class sealed(TInterfacedObject, IPreCompCallback)
      strict private
        FEndomorphism: IECEndomorphism;
        FPoint: IECPoint;
        function CheckExisting(const AExistingEndo: IEndoPreCompInfo;
          const AEndomorphism: IECEndomorphism): Boolean;
      public
        constructor Create(const AEndomorphism: IECEndomorphism; const APoint: IECPoint);
        function Precompute(const AExisting: IPreCompInfo): IPreCompInfo;
      end;
  public
    const PRECOMP_NAME = 'bc_endo';
    class function DecomposeScalar(const AP: IScalarSplitParameters;
      const AK: TBigInteger): TCryptoLibGenericArray<TBigInteger>; static;
    class function MapPoint(const AEndomorphism: IECEndomorphism;
      const AP: IECPoint): IECPoint; static;
  private
    class function CalculateB(const AK, AG: TBigInteger;
      AT: Int32): TBigInteger; static;
  end;

implementation

constructor TEndoUtilities.TMapPointCallback.Create(const AEndomorphism: IECEndomorphism;
  const APoint: IECPoint);
begin
  inherited Create;
  FEndomorphism := AEndomorphism;
  FPoint := APoint;
end;

function TEndoUtilities.TMapPointCallback.CheckExisting(const AExistingEndo: IEndoPreCompInfo;
  const AEndomorphism: IECEndomorphism): Boolean;
begin
  Result := (AExistingEndo <> nil) and (AExistingEndo.Endomorphism = AEndomorphism) and
    (AExistingEndo.MappedPoint <> nil);
end;

function TEndoUtilities.TMapPointCallback.Precompute(const AExisting: IPreCompInfo): IPreCompInfo;
var
  LExistingEndo: IEndoPreCompInfo;
  LResult: IEndoPreCompInfo;
begin
  if Supports(AExisting, IEndoPreCompInfo, LExistingEndo) and
    CheckExisting(LExistingEndo, FEndomorphism) then
    Exit(LExistingEndo);

  LResult := TEndoPreCompInfo.Create;
  LResult.Endomorphism := FEndomorphism;
  LResult.MappedPoint := FEndomorphism.PointMap.Map(FPoint);
  Result := LResult;
end;

class function TEndoUtilities.CalculateB(const AK, AG: TBigInteger;
  AT: Int32): TBigInteger;
var
  LNegative: Boolean;
  LB: TBigInteger;
  LExtra: Boolean;
begin
  LNegative := AG.SignValue < 0;
  LB := AK.Multiply(AG.Abs());
  LExtra := LB.TestBit(AT - 1);
  LB := LB.ShiftRight(AT);
  if LExtra then
    LB := LB.Add(TBigInteger.One);
  if LNegative then
    Result := LB.Negate()
  else
    Result := LB;
end;

class function TEndoUtilities.DecomposeScalar(const AP: IScalarSplitParameters;
  const AK: TBigInteger): TCryptoLibGenericArray<TBigInteger>;
var
  LBits: Int32;
  LB1, LB2, LA, LB: TBigInteger;
begin
  LBits := AP.Bits;
  LB1 := CalculateB(AK, AP.G1, LBits);
  LB2 := CalculateB(AK, AP.G2, LBits);
  LA := AK.Subtract((LB1.Multiply(AP.V1A)).Add(LB2.Multiply(AP.V2A)));
  LB := (LB1.Multiply(AP.V1B)).Add(LB2.Multiply(AP.V2B)).Negate();
  Result := TCryptoLibGenericArray<TBigInteger>.Create(LA, LB);
end;

class function TEndoUtilities.MapPoint(const AEndomorphism: IECEndomorphism;
  const AP: IECPoint): IECPoint;
var
  LPrecomp: IPreCompInfo;
  LEndo: IEndoPreCompInfo;
  LPreCompCallback: IPreCompCallback;
begin
  LPreCompCallback := TEndoUtilities.TMapPointCallback.Create(AEndomorphism, AP);
  LPrecomp := AP.Curve.Precompute(AP, PRECOMP_NAME, LPreCompCallback);
  if not Supports(LPrecomp, IEndoPreCompInfo, LEndo) then
    raise EInvalidCastCryptoLibException.Create('Expected EndoPreCompInfo');
  Result := LEndo.MappedPoint;
end;

end.
