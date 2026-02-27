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
  ClpBigInteger,
  ClpIECCommon,
  ClpIGlvTypeBParameters,
  ClpIGlvTypeBEndomorphism,
  ClpEndoUtilities,
  ClpECPointMaps,
  ClpCryptoLibTypes;

type
  TGlvTypeBEndomorphism = class(TInterfacedObject, IECEndomorphism, IGlvEndomorphism, IGlvTypeBEndomorphism)
  strict private
    FParameters: IGlvTypeBParameters;
    FPointMap: IECPointMap;
  public
    constructor Create(const ACurve: IECCurve; const AParameters: IGlvTypeBParameters);
    function DecomposeScalar(const AK: TBigInteger): TCryptoLibGenericArray<TBigInteger>;
    function GetPointMap: IECPointMap;
    function GetHasEfficientPointMap: Boolean;
    property PointMap: IECPointMap read GetPointMap;
    property HasEfficientPointMap: Boolean read GetHasEfficientPointMap;
  end;

implementation

{ TGlvTypeBEndomorphism }

constructor TGlvTypeBEndomorphism.Create(const ACurve: IECCurve;
  const AParameters: IGlvTypeBParameters);
begin
  inherited Create;
  {
    NOTE: 'curve' MUST only be used to create a suitable ECFieldElement. Due to the way
    ECCurve configuration works, 'curve' will not be the actual instance of ECCurve that the
    endomorphism is being used with.
  }
  FParameters := AParameters;
  FPointMap := TScaleXPointMap.Create(ACurve.FromBigInteger(AParameters.Beta));
end;

function TGlvTypeBEndomorphism.DecomposeScalar(const AK: TBigInteger): TCryptoLibGenericArray<TBigInteger>;
begin
  Result := TEndoUtilities.DecomposeScalar(FParameters.SplitParams, AK);
end;

function TGlvTypeBEndomorphism.GetPointMap: IECPointMap;
begin
  Result := FPointMap;
end;

function TGlvTypeBEndomorphism.GetHasEfficientPointMap: Boolean;
begin
  Result := True;
end;

end.
