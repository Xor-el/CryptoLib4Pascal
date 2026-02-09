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

unit ClpWNafPreCompInfo;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpIECCommon,
  ClpIPreCompInfo,
  ClpIWNafPreCompInfo,
  ClpCryptoLibTypes;

type
  TWNafPreCompInfo = class sealed(TInterfacedObject, IPreCompInfo, IWNafPreCompInfo)
  strict private
    FPromotionCountdown: Int32;
    FConfWidth: Int32;
    FPreComp: TCryptoLibGenericArray<IECPoint>;
    FPreCompNeg: TCryptoLibGenericArray<IECPoint>;
    FTwice: IECPoint;
    FWidth: Int32;
  public
    const
      PRECOMP_NAME = 'bc_wnaf';

    constructor Create;

    function DecrementPromotionCountdown: Int32;
    function GetConfWidth: Int32;
    function GetPreComp: TCryptoLibGenericArray<IECPoint>;
    function GetPreCompNeg: TCryptoLibGenericArray<IECPoint>;
    function GetTwice: IECPoint;
    function GetWidth: Int32;
    function GetIsPromoted: Boolean;

    procedure SetConfWidth(AValue: Int32);
    procedure SetPreComp(const AValue: TCryptoLibGenericArray<IECPoint>);
    procedure SetPreCompNeg(const AValue: TCryptoLibGenericArray<IECPoint>);
    procedure SetTwice(const AValue: IECPoint);
    procedure SetWidth(AValue: Int32);
    procedure SetPromotionCountdown(AValue: Int32);

    property ConfWidth: Int32 read GetConfWidth write SetConfWidth;
    property PreComp: TCryptoLibGenericArray<IECPoint> read GetPreComp write SetPreComp;
    property PreCompNeg: TCryptoLibGenericArray<IECPoint> read GetPreCompNeg write SetPreCompNeg;
    property Twice: IECPoint read GetTwice write SetTwice;
    property Width: Int32 read GetWidth write SetWidth;
    function GetPromotionCountdown: Int32;

    property IsPromoted: Boolean read GetIsPromoted;
    property PromotionCountdown: Int32 read GetPromotionCountdown write SetPromotionCountdown;
  end;

implementation

{ TWNafPreCompInfo }

constructor TWNafPreCompInfo.Create;
begin
  inherited Create;
  FPromotionCountdown := 4;
  FConfWidth := -1;
  FWidth := -1;
end;

function TWNafPreCompInfo.DecrementPromotionCountdown: Int32;
begin
  Result := FPromotionCountdown;
  if Result > 0 then
  begin
    Dec(FPromotionCountdown);
    Result := FPromotionCountdown;
  end;
end;

function TWNafPreCompInfo.GetConfWidth: Int32;
begin
  Result := FConfWidth;
end;

function TWNafPreCompInfo.GetPreComp: TCryptoLibGenericArray<IECPoint>;
begin
  Result := FPreComp;
end;

function TWNafPreCompInfo.GetPreCompNeg: TCryptoLibGenericArray<IECPoint>;
begin
  Result := FPreCompNeg;
end;

function TWNafPreCompInfo.GetTwice: IECPoint;
begin
  Result := FTwice;
end;

function TWNafPreCompInfo.GetWidth: Int32;
begin
  Result := FWidth;
end;

function TWNafPreCompInfo.GetIsPromoted: Boolean;
begin
  Result := FPromotionCountdown <= 0;
end;

function TWNafPreCompInfo.GetPromotionCountdown: Int32;
begin
  Result := FPromotionCountdown;
end;

procedure TWNafPreCompInfo.SetConfWidth(AValue: Int32);
begin
  FConfWidth := AValue;
end;

procedure TWNafPreCompInfo.SetPreComp(const AValue: TCryptoLibGenericArray<IECPoint>);
begin
  FPreComp := AValue;
end;

procedure TWNafPreCompInfo.SetPreCompNeg(const AValue: TCryptoLibGenericArray<IECPoint>);
begin
  FPreCompNeg := AValue;
end;

procedure TWNafPreCompInfo.SetTwice(const AValue: IECPoint);
begin
  FTwice := AValue;
end;

procedure TWNafPreCompInfo.SetWidth(AValue: Int32);
begin
  FWidth := AValue;
end;

procedure TWNafPreCompInfo.SetPromotionCountdown(AValue: Int32);
begin
  FPromotionCountdown := AValue;
end;

end.
