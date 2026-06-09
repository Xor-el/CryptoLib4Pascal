{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                           Author - Ugochukwu Mmaduekwe                          * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ *                                                                                 * }
{ *                              Acknowledgements:                                  * }
{ *                                                                                 * }
{ *      Thanks to Sphere 10 Software (http://www.sphere10.com/) for sponsoring     * }
{ *                         the development of this library                         * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit ClpF2mFieldData;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpCryptoLibTypes,
  ClpArrayUtilities,
  ClpIBinPolyMul,
  ClpIF2mFieldData;

type
  /// <summary>
  /// Field metadata and binary-polynomial arithmetic primitives for GF(2^m).
  /// </summary>
  TF2mFieldData = class sealed(TInterfacedObject, IF2mFieldData)
  strict private
    FM: Int32;
    FKs: TCryptoLibInt32Array;
    FMul: IBinPolyMul;
    FInv: IBinPolyInv;
    function GetM: Int32;
    function GetKs: TCryptoLibInt32Array;
    function GetMul: IBinPolyMul;
    function GetInv: IBinPolyInv;
  public
    constructor Create(AM: Int32; const AKs: TCryptoLibInt32Array; const AMul: IBinPolyMul;
      const AInv: IBinPolyInv);
    class function From(AM, AK1, AK2, AK3: Int32): IF2mFieldData; overload; static;
    class function From(AM: Int32; const AKs: TCryptoLibInt32Array): IF2mFieldData; overload; static;
    function GetK1: Int32;
    function GetK2: Int32;
    function GetK3: Int32;
    class function Equals(const A, B: IF2mFieldData): Boolean; static;
    class function GetHashCode(const AData: IF2mFieldData): Int32; static;
  end;

implementation

uses
  ClpBinPolys;

{ TF2mFieldData }

constructor TF2mFieldData.Create(AM: Int32; const AKs: TCryptoLibInt32Array; const AMul: IBinPolyMul;
  const AInv: IBinPolyInv);
begin
  inherited Create;
  FM := AM;
  FKs := AKs;
  FMul := AMul;
  FInv := AInv;
end;

function TF2mFieldData.GetM: Int32;
begin
  Result := FM;
end;

function TF2mFieldData.GetKs: TCryptoLibInt32Array;
begin
  Result := FKs;
end;

function TF2mFieldData.GetMul: IBinPolyMul;
begin
  Result := FMul;
end;

function TF2mFieldData.GetInv: IBinPolyInv;
begin
  Result := FInv;
end;

class function TF2mFieldData.From(AM, AK1, AK2, AK3: Int32): IF2mFieldData;
begin
  if AK2 = 0 then
    Result := From(AM, TCryptoLibInt32Array.Create(AK1))
  else
    Result := From(AM, TCryptoLibInt32Array.Create(AK1, AK2, AK3));
end;

class function TF2mFieldData.From(AM: Int32; const AKs: TCryptoLibInt32Array): IF2mFieldData;
var
  LMul: IBinPolyMul;
  LInv: IBinPolyInv;
begin
  if System.Length(AKs) = 1 then
    LMul := TBinPolys.TBinPolysMul.Trinomial(AM, AKs[0])
  else
    LMul := TBinPolys.TBinPolysMul.Pentanomial(AM, AKs[0], AKs[1], AKs[2]);
  LInv := TBinPolys.TBinPolysInv.ItohTsujii(LMul);
  Result := TF2mFieldData.Create(AM, AKs, LMul, LInv);
end;

function TF2mFieldData.GetK1: Int32;
begin
  Result := FKs[0];
end;

function TF2mFieldData.GetK2: Int32;
begin
  if System.Length(FKs) >= 2 then
    Result := FKs[1]
  else
    Result := 0;
end;

function TF2mFieldData.GetK3: Int32;
begin
  if System.Length(FKs) >= 3 then
    Result := FKs[2]
  else
    Result := 0;
end;

class function TF2mFieldData.Equals(const A, B: IF2mFieldData): Boolean;
begin
  if A = B then
    Exit(True);
  if (A = nil) or (B = nil) then
    Exit(False);
  Result := (A.M = B.M) and TArrayUtilities.AreEqual(A.Ks, B.Ks);
end;

class function TF2mFieldData.GetHashCode(const AData: IF2mFieldData): Int32;
begin
  if AData = nil then
    Exit(0);
  Result := AData.M xor TArrayUtilities.GetArrayHashCode(AData.Ks);
end;

end.
