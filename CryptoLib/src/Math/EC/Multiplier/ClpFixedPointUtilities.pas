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

unit ClpFixedPointUtilities;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpBigInteger,
  ClpIECCommon,
  ClpIPreCompCallback,
  ClpIPreCompInfo,
  ClpIFixedPointPreCompInfo,
  ClpFixedPointPreCompInfo,
  ClpCryptoLibTypes;

type
  TFixedPointUtilities = class sealed(TObject)
  strict private
    type
      TFixedPointCallback = class sealed(TInterfacedObject, IPreCompCallback)
      strict private
        FP: IECPoint;
        function CheckExisting(const AExistingFP: IFixedPointPreCompInfo; AN: Int32): Boolean;
        function CheckTable(const ATable: IECLookupTable; AN: Int32): Boolean;
      public
        constructor Create(const AP: IECPoint);
        function Precompute(const AExisting: IPreCompInfo): IPreCompInfo;
      end;
  public
    const PRECOMP_NAME = 'bc_fixed_point';
    class function GetCombSize(const AC: IECCurve): Int32; static;
    class function GetFixedPointPreCompInfo(const APreCompInfo: IPreCompInfo): IFixedPointPreCompInfo; static;
    class function Precompute(const AP: IECPoint): IFixedPointPreCompInfo; static;
  end;

implementation

{ TFixedPointUtilities.TFixedPointCallback }

constructor TFixedPointUtilities.TFixedPointCallback.Create(const AP: IECPoint);
begin
  Inherited Create;
  FP := AP;
end;

function TFixedPointUtilities.TFixedPointCallback.CheckTable(const ATable: IECLookupTable; AN: Int32): Boolean;
begin
  Result := (ATable <> nil) and (ATable.Size >= AN);
end;

function TFixedPointUtilities.TFixedPointCallback.CheckExisting(const AExistingFP: IFixedPointPreCompInfo; AN: Int32): Boolean;
begin
  Result := (AExistingFP <> nil) and CheckTable(AExistingFP.LookupTable, AN);
end;

function TFixedPointUtilities.TFixedPointCallback.Precompute(const AExisting: IPreCompInfo): IPreCompInfo;
var
  LExistingFP: IFixedPointPreCompInfo;
  LC: IECCurve;
  LBits, LMinWidth, LN, LD, LBit, LStep, LI: Int32;
  LPow2Table, LLookupTable: TCryptoLibGenericArray<IECPoint>;
  LPow2: IECPoint;
  LResult: IFixedPointPreCompInfo;
begin
  if not Supports(AExisting, IFixedPointPreCompInfo, LExistingFP) then
    LExistingFP := nil;

  LC := FP.Curve;
  LBits := TFixedPointUtilities.GetCombSize(LC);
  if LBits > 250 then
    LMinWidth := 6
  else
    LMinWidth := 5;
  LN := 1 shl LMinWidth;

  if CheckExisting(LExistingFP, LN) then
    Exit(LExistingFP);

  LD := (LBits + LMinWidth - 1) div LMinWidth;

  System.SetLength(LPow2Table, LMinWidth + 1);
  LPow2Table[0] := FP;
  for LI := 1 to LMinWidth - 1 do
    LPow2Table[LI] := LPow2Table[LI - 1].TimesPow2(LD);
  LPow2Table[LMinWidth] := LPow2Table[0].Subtract(LPow2Table[1]);

  LC.NormalizeAll(LPow2Table);

  System.SetLength(LLookupTable, LN);
  LLookupTable[0] := LPow2Table[0];

  for LBit := LMinWidth - 1 downto 0 do
  begin
    LPow2 := LPow2Table[LBit];
    LStep := 1 shl LBit;
    LI := LStep;
    while LI < LN do
    begin
      LLookupTable[LI] := LLookupTable[LI - LStep].Add(LPow2);
      LI := LI + (LStep shl 1);
    end;
  end;

  LC.NormalizeAll(LLookupTable);

  LResult := TFixedPointPreCompInfo.Create;
  LResult.LookupTable := LC.CreateCacheSafeLookupTable(LLookupTable, 0, System.Length(LLookupTable));
  LResult.Offset := LPow2Table[LMinWidth];
  LResult.Width := LMinWidth;
  Result := LResult;
end;

{ TFixedPointUtilities }

class function TFixedPointUtilities.GetCombSize(const AC: IECCurve): Int32;
var
  LOrder: TBigInteger;
begin
  LOrder := AC.Order;
  if not LOrder.IsInitialized then
    Result := AC.FieldSize + 1
  else
    Result := LOrder.BitLength;
end;

class function TFixedPointUtilities.GetFixedPointPreCompInfo(const APreCompInfo: IPreCompInfo): IFixedPointPreCompInfo;
var
  LFP: IFixedPointPreCompInfo;
begin
  if Supports(APreCompInfo, IFixedPointPreCompInfo, LFP) then
    Result := LFP
  else
    Result := nil;
end;

class function TFixedPointUtilities.Precompute(const AP: IECPoint): IFixedPointPreCompInfo;
var
  LPrecomp: IPreCompInfo;
  LFP: IFixedPointPreCompInfo;
  LPrecompCallback: IPreCompCallback;
begin
  LPrecompCallback := TFixedPointUtilities.TFixedPointCallback.Create(AP);
  LPrecomp := AP.Curve.Precompute(AP, PRECOMP_NAME, LPrecompCallback);
  if Supports(LPrecomp, IFixedPointPreCompInfo, LFP) then
    Result := LFP
  else
    Result := nil;
end;

end.
