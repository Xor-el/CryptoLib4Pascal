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

unit ClpSecP521R1Curve;

{$I ..\..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpHex,
  ClpBits,
  ClpNat,
  ClpECCurve,
  ClpIECInterface,
  ClpISecP521R1FieldElement,
  ClpSecP521R1Point,
  ClpISecP521R1Curve,
  ClpISecP521R1Point,
  ClpIECFieldElement,
  ClpBigInteger,
  ClpCryptoLibTypes;

type
  TSecP521R1Curve = class sealed(TAbstractFpCurve, ISecP521R1Curve)

  strict private

  type
    TSecP521R1LookupTable = class sealed(TInterfacedObject,
      ISecP521R1LookupTable, IECLookupTable)

    strict private
    var
      Fm_outer: ISecP521R1Curve;
      Fm_table: TCryptoLibUInt32Array;
      Fm_size: Int32;

      function GetSize: Int32; virtual;

    public

      constructor Create(const outer: ISecP521R1Curve;
        const table: TCryptoLibUInt32Array; size: Int32);

      function Lookup(index: Int32): IECPoint; virtual;

      property size: Int32 read GetSize;

    end;

  const
    SECP521R1_DEFAULT_COORDS = Int32(TECCurve.COORD_JACOBIAN);
    SECP521R1_FE_INTS = Int32(17);

    class var

      Fq: TBigInteger;

    class function GetSecP521R1Curve_Q: TBigInteger; static; inline;
    class constructor SecP521R1Curve();

  strict protected
  var
    Fm_infinity: ISecP521R1Point;

    function GetQ: TBigInteger; virtual;
    function GetFieldSize: Int32; override;
    function GetInfinity: IECPoint; override;

    function CloneCurve(): IECCurve; override;

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

    property Q: TBigInteger read GetQ;
    property Infinity: IECPoint read GetInfinity;
    property FieldSize: Int32 read GetFieldSize;

    class property SecP521R1Curve_Q: TBigInteger read GetSecP521R1Curve_Q;

  end;

implementation

uses
  // included here to avoid circular dependency :)
  ClpSecP521R1FieldElement;

{ TSecP521R1Curve }

class function TSecP521R1Curve.GetSecP521R1Curve_Q: TBigInteger;
begin
  result := Fq;
end;

class constructor TSecP521R1Curve.SecP521R1Curve;
begin
  Fq := TBigInteger.Create(1,
    THex.Decode
    ('01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF')
    );
end;

constructor TSecP521R1Curve.Create;
begin
  Inherited Create(Fq);
  Fm_infinity := TSecP521R1Point.Create(Self as IECCurve, Nil, Nil);
  Fm_a := FromBigInteger(TBigInteger.Create(1,
    THex.Decode
    ('01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC'))
    );
  Fm_b := FromBigInteger(TBigInteger.Create(1,
    THex.Decode
    ('0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00'))
    );
  Fm_order := TBigInteger.Create(1,
    THex.Decode
    ('01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409')
    );
  Fm_cofactor := TBigInteger.One;
  Fm_coord := SECP521R1_DEFAULT_COORDS;
end;

function TSecP521R1Curve.CloneCurve: IECCurve;
begin
  result := TSecP521R1Curve.Create();
end;

function TSecP521R1Curve.CreateCacheSafeLookupTable(const points
  : TCryptoLibGenericArray<IECPoint>; off, len: Int32): IECLookupTable;
var
  table: TCryptoLibUInt32Array;
  pos, i: Int32;
  p: IECPoint;
begin
  System.SetLength(table, len * SECP521R1_FE_INTS * 2);

  pos := 0;
  for i := 0 to System.Pred(len) do
  begin
    p := points[off + i];
    TNat.Copy(SECP521R1_FE_INTS, (p.RawXCoord as ISecP521R1FieldElement).x, 0,
      table, pos);
    pos := pos + SECP521R1_FE_INTS;
    TNat.Copy(SECP521R1_FE_INTS, (p.RawYCoord as ISecP521R1FieldElement).x, 0,
      table, pos);
    pos := pos + SECP521R1_FE_INTS;
  end;

  result := TSecP521R1LookupTable.Create(Self as ISecP521R1Curve, table, len);
end;

function TSecP521R1Curve.CreateRawPoint(const x, y: IECFieldElement;
  withCompression: Boolean): IECPoint;
begin
  result := TSecP521R1Point.Create(Self as IECCurve, x, y, withCompression);
end;

function TSecP521R1Curve.CreateRawPoint(const x, y: IECFieldElement;
  const zs: TCryptoLibGenericArray<IECFieldElement>; withCompression: Boolean)
  : IECPoint;
begin
  result := TSecP521R1Point.Create(Self as IECCurve, x, y, zs, withCompression);
end;

function TSecP521R1Curve.FromBigInteger(const x: TBigInteger): IECFieldElement;
begin
  result := TSecP521R1FieldElement.Create(x);
end;

function TSecP521R1Curve.GetFieldSize: Int32;
begin
  result := Fq.BitLength;
end;

function TSecP521R1Curve.GetInfinity: IECPoint;
begin
  result := Fm_infinity;
end;

function TSecP521R1Curve.GetQ: TBigInteger;
begin
  result := Fq;
end;

function TSecP521R1Curve.SupportsCoordinateSystem(coord: Int32): Boolean;
begin
  case coord of
    COORD_JACOBIAN:
      result := True
  else
    result := False;
  end;
end;

{ TSecP521R1Curve.TSecP521R1LookupTable }

constructor TSecP521R1Curve.TSecP521R1LookupTable.Create
  (const outer: ISecP521R1Curve; const table: TCryptoLibUInt32Array;
  size: Int32);
begin
  Inherited Create();
  Fm_outer := outer;
  Fm_table := table;
  Fm_size := size;
end;

function TSecP521R1Curve.TSecP521R1LookupTable.GetSize: Int32;
begin
  result := Fm_size;
end;

function TSecP521R1Curve.TSecP521R1LookupTable.Lookup(index: Int32): IECPoint;
var
  x, y: TCryptoLibUInt32Array;
  pos, i, J: Int32;
  MASK: UInt32;
begin
  x := TNat.Create(SECP521R1_FE_INTS);
  y := TNat.Create(SECP521R1_FE_INTS);
  pos := 0;

  for i := 0 to System.Pred(Fm_size) do
  begin
    MASK := UInt32(TBits.Asr32((i xor index) - 1, 31));

    for J := 0 to System.Pred(SECP521R1_FE_INTS) do
    begin
      x[J] := x[J] xor (Fm_table[pos + J] and MASK);
      y[J] := y[J] xor (Fm_table[pos + SECP521R1_FE_INTS + J] and MASK);
    end;

    pos := pos + (SECP521R1_FE_INTS * 2);
  end;

  result := Fm_outer.CreateRawPoint(TSecP521R1FieldElement.Create(x)
    as ISecP521R1FieldElement, TSecP521R1FieldElement.Create(y)
    as ISecP521R1FieldElement, False);
end;

end.
