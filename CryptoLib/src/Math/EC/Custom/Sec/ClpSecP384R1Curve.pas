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

unit ClpSecP384R1Curve;

{$I ..\..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpHex,
  ClpBits,
  ClpNat,
  ClpECCurve,
  ClpIECInterface,
  ClpISecP384R1FieldElement,
  ClpSecP384R1Point,
  ClpISecP384R1Curve,
  ClpISecP384R1Point,
  ClpIECFieldElement,
  ClpBigInteger,
  ClpCryptoLibTypes;

type
  TSecP384R1Curve = class sealed(TAbstractFpCurve, ISecP384R1Curve)

  strict private

  type
    TSecP384R1LookupTable = class sealed(TInterfacedObject,
      ISecP384R1LookupTable, IECLookupTable)

    strict private
    var
      Fm_outer: ISecP384R1Curve;
      Fm_table: TCryptoLibUInt32Array;
      Fm_size: Int32;

      function GetSize: Int32; virtual;

    public

      constructor Create(const outer: ISecP384R1Curve;
        const table: TCryptoLibUInt32Array; size: Int32);

      function Lookup(index: Int32): IECPoint; virtual;

      property size: Int32 read GetSize;

    end;

  const
    SECP384R1_DEFAULT_COORDS = Int32(TECCurve.COORD_JACOBIAN);
    SECP384R1_FE_INTS = Int32(12);

    class var

      Fq: TBigInteger;

    class function GetSecP384R1Curve_Q: TBigInteger; static; inline;
    class constructor SecP384R1Curve();

  strict protected
  var
    Fm_infinity: ISecP384R1Point;

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

    class property SecP384R1Curve_Q: TBigInteger read GetSecP384R1Curve_Q;

  end;

implementation

uses
  // included here to avoid circular dependency :)
  ClpSecP384R1FieldElement;

{ TSecP384R1Curve }

class function TSecP384R1Curve.GetSecP384R1Curve_Q: TBigInteger;
begin
  result := Fq;
end;

class constructor TSecP384R1Curve.SecP384R1Curve;
begin
  Fq := TBigInteger.Create(1,
    THex.Decode
    ('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF')
    );
end;

constructor TSecP384R1Curve.Create;
begin
  Inherited Create(Fq);
  Fm_infinity := TSecP384R1Point.Create(Self as IECCurve, Nil, Nil);
  Fm_a := FromBigInteger(TBigInteger.Create(1,
    THex.Decode
    ('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC'))
    );
  Fm_b := FromBigInteger(TBigInteger.Create(1,
    THex.Decode
    ('B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF'))
    );
  Fm_order := TBigInteger.Create(1,
    THex.Decode
    ('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973')
    );
  Fm_cofactor := TBigInteger.One;
  Fm_coord := SECP384R1_DEFAULT_COORDS;
end;

function TSecP384R1Curve.CloneCurve: IECCurve;
begin
  result := TSecP384R1Curve.Create();
end;

function TSecP384R1Curve.CreateCacheSafeLookupTable(const points
  : TCryptoLibGenericArray<IECPoint>; off, len: Int32): IECLookupTable;
var
  table: TCryptoLibUInt32Array;
  pos, i: Int32;
  p: IECPoint;
begin
  System.SetLength(table, len * SECP384R1_FE_INTS * 2);

  pos := 0;
  for i := 0 to System.Pred(len) do
  begin
    p := points[off + i];
    TNat.Copy(SECP384R1_FE_INTS, (p.RawXCoord as ISecP384R1FieldElement).x, 0,
      table, pos);
    pos := pos + SECP384R1_FE_INTS;
    TNat.Copy(SECP384R1_FE_INTS, (p.RawYCoord as ISecP384R1FieldElement).x, 0,
      table, pos);
    pos := pos + SECP384R1_FE_INTS;
  end;

  result := TSecP384R1LookupTable.Create(Self as ISecP384R1Curve, table, len);
end;

function TSecP384R1Curve.CreateRawPoint(const x, y: IECFieldElement;
  withCompression: Boolean): IECPoint;
begin
  result := TSecP384R1Point.Create(Self as IECCurve, x, y, withCompression);
end;

function TSecP384R1Curve.CreateRawPoint(const x, y: IECFieldElement;
  const zs: TCryptoLibGenericArray<IECFieldElement>; withCompression: Boolean)
  : IECPoint;
begin
  result := TSecP384R1Point.Create(Self as IECCurve, x, y, zs, withCompression);
end;

function TSecP384R1Curve.FromBigInteger(const x: TBigInteger): IECFieldElement;
begin
  result := TSecP384R1FieldElement.Create(x);
end;

function TSecP384R1Curve.GetFieldSize: Int32;
begin
  result := Fq.BitLength;
end;

function TSecP384R1Curve.GetInfinity: IECPoint;
begin
  result := Fm_infinity;
end;

function TSecP384R1Curve.GetQ: TBigInteger;
begin
  result := Fq;
end;

function TSecP384R1Curve.SupportsCoordinateSystem(coord: Int32): Boolean;
begin
  case coord of
    COORD_JACOBIAN:
      result := True
  else
    result := False;
  end;
end;

{ TSecP384R1Curve.TSecP384R1LookupTable }

constructor TSecP384R1Curve.TSecP384R1LookupTable.Create
  (const outer: ISecP384R1Curve; const table: TCryptoLibUInt32Array;
  size: Int32);
begin
  Inherited Create();
  Fm_outer := outer;
  Fm_table := table;
  Fm_size := size;
end;

function TSecP384R1Curve.TSecP384R1LookupTable.GetSize: Int32;
begin
  result := Fm_size;
end;

function TSecP384R1Curve.TSecP384R1LookupTable.Lookup(index: Int32): IECPoint;
var
  x, y: TCryptoLibUInt32Array;
  pos, i, J: Int32;
  MASK: UInt32;
begin
  x := TNat.Create(SECP384R1_FE_INTS);
  y := TNat.Create(SECP384R1_FE_INTS);
  pos := 0;

  for i := 0 to System.Pred(Fm_size) do
  begin
    MASK := UInt32(TBits.Asr32((i xor index) - 1, 31));

    for J := 0 to System.Pred(SECP384R1_FE_INTS) do
    begin
      x[J] := x[J] xor (Fm_table[pos + J] and MASK);
      y[J] := y[J] xor (Fm_table[pos + SECP384R1_FE_INTS + J] and MASK);
    end;

    pos := pos + (SECP384R1_FE_INTS * 2);
  end;

  result := Fm_outer.CreateRawPoint(TSecP384R1FieldElement.Create(x)
    as ISecP384R1FieldElement, TSecP384R1FieldElement.Create(y)
    as ISecP384R1FieldElement, False);
end;

end.
