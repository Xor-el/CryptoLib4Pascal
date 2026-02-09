{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                Copyright (c) 2018 - 20XX Ugochukwu Mmaduekwe                    * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }

{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }

{ * ******************************************************************************* * }

unit ClpECPointMaps;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpIECCommon,
  ClpIECFieldElement;

type
  TScaleXPointMap = class(TInterfacedObject, IECPointMap)
  strict protected
    FScale: IECFieldElement;
  public
    constructor Create(const AScale: IECFieldElement);
    function Map(const AP: IECPoint): IECPoint; virtual;
  end;

type
  TScaleYPointMap = class(TInterfacedObject, IECPointMap)
  strict protected
    FScale: IECFieldElement;
  public
    constructor Create(const AScale: IECFieldElement);
    function Map(const AP: IECPoint): IECPoint; virtual;
  end;

type
  TScaleXNegateYPointMap = class(TInterfacedObject, IECPointMap)
  strict protected
    FScale: IECFieldElement;
  public
    constructor Create(const AScale: IECFieldElement);
    function Map(const AP: IECPoint): IECPoint; virtual;
  end;

type
  TScaleYNegateXPointMap = class(TInterfacedObject, IECPointMap)
  strict protected
    FScale: IECFieldElement;
  public
    constructor Create(const AScale: IECFieldElement);
    function Map(const AP: IECPoint): IECPoint; virtual;
  end;

implementation

{ TScaleXPointMap }

constructor TScaleXPointMap.Create(const AScale: IECFieldElement);
begin
  Inherited Create;
  FScale := AScale;
end;

function TScaleXPointMap.Map(const AP: IECPoint): IECPoint;
begin
  Result := AP.ScaleX(FScale);
end;

{ TScaleYPointMap }

constructor TScaleYPointMap.Create(const AScale: IECFieldElement);
begin
  Inherited Create;
  FScale := AScale;
end;

function TScaleYPointMap.Map(const AP: IECPoint): IECPoint;
begin
  Result := AP.ScaleY(FScale);
end;

{ TScaleXNegateYPointMap }

constructor TScaleXNegateYPointMap.Create(const AScale: IECFieldElement);
begin
  Inherited Create;
  FScale := AScale;
end;

function TScaleXNegateYPointMap.Map(const AP: IECPoint): IECPoint;
begin
  Result := AP.ScaleXNegateY(FScale);
end;

{ TScaleYNegateXPointMap }

constructor TScaleYNegateXPointMap.Create(const AScale: IECFieldElement);
begin
  Inherited Create;
  FScale := AScale;
end;

function TScaleYNegateXPointMap.Map(const AP: IECPoint): IECPoint;
begin
  Result := AP.ScaleYNegateX(FScale);
end;

end.
