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

unit ClpSecT283K1Curve;

{$I ..\..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpHex,
  ClpBits,
  ClpNat320,
  ClpECCurve,
  ClpIECInterface,
  ClpSecT283FieldElement,
  ClpISecT283FieldElement,
  ClpSecT283K1Point,
  ClpISecT283K1Curve,
  ClpISecT283K1Point,
  ClpIECFieldElement,
  ClpWTauNafMultiplier,
  ClpBigInteger,
  ClpCryptoLibTypes;

type
  TSecT283K1Curve = class sealed(TAbstractF2mCurve, ISecT283K1Curve)

  strict private

  type
    TSecT283K1LookupTable = class sealed(TInterfacedObject,
      ISecT283K1LookupTable, IECLookupTable)

    strict private
    var
      Fm_outer: ISecT283K1Curve;
      Fm_table: TCryptoLibUInt64Array;
      Fm_size: Int32;

      function GetSize: Int32; virtual;

    public

      constructor Create(const outer: ISecT283K1Curve;
        const table: TCryptoLibUInt64Array; size: Int32);

      function Lookup(index: Int32): IECPoint; virtual;

      property size: Int32 read GetSize;

    end;

  const
    SECT283K1_DEFAULT_COORDS = Int32(TECCurve.COORD_LAMBDA_PROJECTIVE);
    SECT283K1_FE_LONGS = Int32(5);

    function GetM: Int32; inline;
    function GetK1: Int32; inline;
    function GetK2: Int32; inline;
    function GetK3: Int32; inline;
    function GetIsTrinomial: Boolean; inline;

  strict protected
  var
    Fm_infinity: ISecT283K1Point;

    function GetFieldSize: Int32; override;
    function GetInfinity: IECPoint; override;
    function GetIsKoblitz: Boolean; override;

    function CloneCurve(): IECCurve; override;

    function CreateDefaultMultiplier(): IECMultiplier; override;

    function CreateRawPoint(const x, y: IECFieldElement;
      withCompression: Boolean): IECPoint; overload; override;

    function CreateRawPoint(const x, y: IECFieldElement;
      const zs: TCryptoLibGenericArray<IECFieldElement>;
      withCompression: Boolean): IECPoint; overload; override;

  public
    constructor Create();
    function FromBigInteger(const x: TBigInteger): IECFieldElement; override;

    function SupportsCoordinateSystem(coord: Int32): Boolean; override;

    function CreateCacheSafeLookupTable(const points
      : TCryptoLibGenericArray<IECPoint>; off, len: Int32)
      : IECLookupTable; override;

    property Infinity: IECPoint read GetInfinity;
    property FieldSize: Int32 read GetFieldSize;
    property IsKoblitz: Boolean read GetIsKoblitz;

    property M: Int32 read GetM;
    property K1: Int32 read GetK1;
    property K2: Int32 read GetK2;
    property K3: Int32 read GetK3;
    property IsTrinomial: Boolean read GetIsTrinomial;

  end;

implementation

{ TSecT283K1Curve }

constructor TSecT283K1Curve.Create;
begin
  Inherited Create(283, 5, 7, 12);
  Fm_infinity := TSecT283K1Point.Create(Self as IECCurve, Nil, Nil);

  Fm_a := FromBigInteger(TBigInteger.Zero);
  Fm_b := FromBigInteger(TBigInteger.One);
  Fm_order := TBigInteger.Create(1,
    THex.Decode
    ('01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE9AE2ED07577265DFF7F94451E061E163C61')
    );
  Fm_cofactor := TBigInteger.ValueOf(4);

  Fm_coord := SECT283K1_DEFAULT_COORDS;
end;

function TSecT283K1Curve.CloneCurve: IECCurve;
begin
  result := TSecT283K1Curve.Create() as ISecT283K1Curve;
end;

function TSecT283K1Curve.CreateCacheSafeLookupTable(const points
  : TCryptoLibGenericArray<IECPoint>; off, len: Int32): IECLookupTable;
var
  table: TCryptoLibUInt64Array;
  pos, i: Int32;
  p: IECPoint;
begin
  System.SetLength(table, len * SECT283K1_FE_LONGS * 2);

  pos := 0;
  for i := 0 to System.Pred(len) do
  begin
    p := points[off + i];
    TNat320.Copy64((p.RawXCoord as ISecT283FieldElement).x, 0, table, pos);
    pos := pos + SECT283K1_FE_LONGS;
    TNat320.Copy64((p.RawYCoord as ISecT283FieldElement).x, 0, table, pos);
    pos := pos + SECT283K1_FE_LONGS;
  end;

  result := TSecT283K1LookupTable.Create(Self as ISecT283K1Curve, table, len);
end;

function TSecT283K1Curve.CreateRawPoint(const x, y: IECFieldElement;
  withCompression: Boolean): IECPoint;
begin
  result := TSecT283K1Point.Create(Self as IECCurve, x, y, withCompression);
end;

function TSecT283K1Curve.CreateRawPoint(const x, y: IECFieldElement;
  const zs: TCryptoLibGenericArray<IECFieldElement>; withCompression: Boolean)
  : IECPoint;
begin
  result := TSecT283K1Point.Create(Self as IECCurve, x, y, zs, withCompression);
end;

function TSecT283K1Curve.FromBigInteger(const x: TBigInteger): IECFieldElement;
begin
  result := TSecT283FieldElement.Create(x);
end;

function TSecT283K1Curve.GetFieldSize: Int32;
begin
  result := 283;
end;

function TSecT283K1Curve.GetInfinity: IECPoint;
begin
  result := Fm_infinity;
end;

function TSecT283K1Curve.GetIsKoblitz: Boolean;
begin
  result := True;
end;

function TSecT283K1Curve.GetIsTrinomial: Boolean;
begin
  result := False;
end;

function TSecT283K1Curve.GetK1: Int32;
begin
  result := 5;
end;

function TSecT283K1Curve.GetK2: Int32;
begin
  result := 7;
end;

function TSecT283K1Curve.GetK3: Int32;
begin
  result := 12;
end;

function TSecT283K1Curve.GetM: Int32;
begin
  result := 283;
end;

function TSecT283K1Curve.SupportsCoordinateSystem(coord: Int32): Boolean;
begin
  case coord of
    COORD_LAMBDA_PROJECTIVE:
      result := True
  else
    result := False;
  end;
end;

function TSecT283K1Curve.CreateDefaultMultiplier(): IECMultiplier;
begin
  result := TWTauNafMultiplier.Create() as IECMultiplier;
end;

{ TSecT283K1Curve.TSecT283K1LookupTable }

constructor TSecT283K1Curve.TSecT283K1LookupTable.Create
  (const outer: ISecT283K1Curve; const table: TCryptoLibUInt64Array;
  size: Int32);
begin
  Inherited Create();
  Fm_outer := outer;
  Fm_table := table;
  Fm_size := size;
end;

function TSecT283K1Curve.TSecT283K1LookupTable.GetSize: Int32;
begin
  result := Fm_size;
end;

function TSecT283K1Curve.TSecT283K1LookupTable.Lookup(index: Int32): IECPoint;
var
  x, y: TCryptoLibUInt64Array;
  pos, i, J: Int32;
  MASK: UInt64;
begin
  x := TNat320.Create64();
  y := TNat320.Create64();
  pos := 0;

  for i := 0 to System.Pred(Fm_size) do
  begin
    MASK := UInt64(Int64(TBits.Asr32((i xor index) - 1, 31)));

    for J := 0 to System.Pred(SECT283K1_FE_LONGS) do
    begin
      x[J] := x[J] xor (Fm_table[pos + J] and MASK);
      y[J] := y[J] xor (Fm_table[pos + SECT283K1_FE_LONGS + J] and MASK);
    end;

    pos := pos + (SECT283K1_FE_LONGS * 2);
  end;

  result := Fm_outer.CreateRawPoint(TSecT283FieldElement.Create(x)
    as ISecT283FieldElement, TSecT283FieldElement.Create(y)
    as ISecT283FieldElement, False);
end;

end.
