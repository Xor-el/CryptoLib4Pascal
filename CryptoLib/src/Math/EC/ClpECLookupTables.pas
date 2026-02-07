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

unit ClpECLookupTables;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpIECCore,
  ClpCryptoLibTypes;

resourcestring
  SConstantTimeLookupNotSupported = 'Constant-time lookup not supported';

type
  TAbstractECLookupTable = class abstract(TInterfacedObject, IECLookupTable)
  public
    function Lookup(AIndex: Int32): IECPoint; virtual; abstract;
    function GetSize: Int32; virtual; abstract;
    function LookupVar(AIndex: Int32): IECPoint; virtual;
    property Size: Int32 read GetSize;
  end;

type
  TSimpleLookupTable = class(TAbstractECLookupTable, IECLookupTable)
  strict private
    FPoints: TCryptoLibGenericArray<IECPoint>;

    class function CopyPoints(const APoints: TCryptoLibGenericArray<IECPoint>; AOff, ALen: Int32)
      : TCryptoLibGenericArray<IECPoint>; static;
  public
    constructor Create(const APoints: TCryptoLibGenericArray<IECPoint>; AOff, ALen: Int32);
    function GetSize: Int32; override;
    function Lookup(AIndex: Int32): IECPoint; override;
    function LookupVar(AIndex: Int32): IECPoint; override;
  end;

implementation

{ TAbstractECLookupTable }

function TAbstractECLookupTable.LookupVar(AIndex: Int32): IECPoint;
begin
  Result := Lookup(AIndex);
end;

{ TSimpleLookupTable }

class function TSimpleLookupTable.CopyPoints(const APoints: TCryptoLibGenericArray<IECPoint>;
  AOff, ALen: Int32): TCryptoLibGenericArray<IECPoint>;
var
  LI: Int32;
begin
  System.SetLength(Result, ALen);
  for LI := 0 to ALen - 1 do
    Result[LI] := APoints[AOff + LI];
end;

constructor TSimpleLookupTable.Create(const APoints: TCryptoLibGenericArray<IECPoint>;
  AOff, ALen: Int32);
begin
  Inherited Create();
  FPoints := CopyPoints(APoints, AOff, ALen);
end;

function TSimpleLookupTable.GetSize: Int32;
begin
  Result := System.Length(FPoints);
end;

function TSimpleLookupTable.Lookup(AIndex: Int32): IECPoint;
begin
  raise ENotSupportedCryptoLibException.Create(SConstantTimeLookupNotSupported);
end;

function TSimpleLookupTable.LookupVar(AIndex: Int32): IECPoint;
begin
  Result := FPoints[AIndex];
end;

end.
