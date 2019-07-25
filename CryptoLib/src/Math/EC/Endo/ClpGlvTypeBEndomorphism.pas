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
  ClpIGlvEndomorphism,
  ClpECCompUtilities;

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

  public
    constructor Create(const curve: IECCurve;
      const parameters: IGlvTypeBParameters);

    function DecomposeScalar(const k: TBigInteger)
      : TCryptoLibGenericArray<TBigInteger>; virtual;

    property PointMap: IECPointMap read GetPointMap;
    property HasEfficientPointMap: Boolean read GetHasEfficientPointMap;
  end;

implementation

{ TGlvTypeBEndomorphism }

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
begin
  Result := TEndoUtilities.DecomposeScalar(FParameters.SplitParams, k);
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
