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

unit ClpSecP256R1Curve;

{$I ..\..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpHex,
  ClpBits,
  ClpNat256,
  ClpECCurve,
  ClpIECInterface,
  ClpISecP256R1FieldElement,
  ClpSecP256R1Point,
  ClpISecP256R1Curve,
  ClpISecP256R1Point,
  ClpIECFieldElement,
  ClpBigInteger,
  ClpCryptoLibTypes;

type
  TSecP256R1Curve = class sealed(TAbstractFpCurve, ISecP256R1Curve)

  strict private

  type
    TSecP256R1LookupTable = class sealed(TInterfacedObject,
      ISecP256R1LookupTable, IECLookupTable)

    strict private
    var
      Fm_outer: ISecP256R1Curve;
      Fm_table: TCryptoLibUInt32Array;
      Fm_size: Int32;

      function GetSize: Int32; virtual;

    public

      constructor Create(const outer: ISecP256R1Curve;
        const table: TCryptoLibUInt32Array; size: Int32);

      function Lookup(index: Int32): IECPoint; virtual;

      property size: Int32 read GetSize;

    end;

  const
    SECP256R1_DEFAULT_COORDS = Int32(TECCurve.COORD_JACOBIAN);
    SECP256R1_FE_INTS = Int32(8);

    class var

      Fq: TBigInteger;

    class function GetSecP256R1Curve_Q: TBigInteger; static; inline;
    class constructor SecP256R1Curve();

  strict protected
  var
    Fm_infinity: ISecP256R1Point;

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

    class property SecP256R1Curve_Q: TBigInteger read GetSecP256R1Curve_Q;

  end;

implementation

uses
  // included here to avoid circular dependency :)
  ClpSecP256R1FieldElement;

{ TSecP256R1Curve }

class function TSecP256R1Curve.GetSecP256R1Curve_Q: TBigInteger;
begin
  result := Fq;
end;

class constructor TSecP256R1Curve.SecP256R1Curve;
begin
  Fq := TBigInteger.Create(1,
    THex.Decode
    ('FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF'));
end;

constructor TSecP256R1Curve.Create;
begin
  Inherited Create(Fq);
  Fm_infinity := TSecP256R1Point.Create(Self as IECCurve, Nil, Nil);
  Fm_a := FromBigInteger(TBigInteger.Create(1,
    THex.Decode
    ('FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC')));
  Fm_b := FromBigInteger(TBigInteger.Create(1,
    THex.Decode
    ('5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B')));
  Fm_order := TBigInteger.Create(1,
    THex.Decode
    ('FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551'));
  Fm_cofactor := TBigInteger.One;
  Fm_coord := SECP256R1_DEFAULT_COORDS;
end;

function TSecP256R1Curve.CloneCurve: IECCurve;
begin
  result := TSecP256R1Curve.Create();
end;

function TSecP256R1Curve.CreateCacheSafeLookupTable(const points
  : TCryptoLibGenericArray<IECPoint>; off, len: Int32): IECLookupTable;
var
  table: TCryptoLibUInt32Array;
  pos, i: Int32;
  p: IECPoint;
begin
  System.SetLength(table, len * SECP256R1_FE_INTS * 2);

  pos := 0;
  for i := 0 to System.Pred(len) do
  begin
    p := points[off + i];
    TNat256.Copy((p.RawXCoord as ISecP256R1FieldElement).x, 0, table, pos);
    pos := pos + SECP256R1_FE_INTS;
    TNat256.Copy((p.RawYCoord as ISecP256R1FieldElement).x, 0, table, pos);
    pos := pos + SECP256R1_FE_INTS;
  end;

  result := TSecP256R1LookupTable.Create(Self as ISecP256R1Curve, table, len);
end;

function TSecP256R1Curve.CreateRawPoint(const x, y: IECFieldElement;
  withCompression: Boolean): IECPoint;
begin
  result := TSecP256R1Point.Create(Self as IECCurve, x, y, withCompression);
end;

function TSecP256R1Curve.CreateRawPoint(const x, y: IECFieldElement;
  const zs: TCryptoLibGenericArray<IECFieldElement>; withCompression: Boolean)
  : IECPoint;
begin
  result := TSecP256R1Point.Create(Self as IECCurve, x, y, zs, withCompression);
end;

function TSecP256R1Curve.FromBigInteger(const x: TBigInteger): IECFieldElement;
begin
  result := TSecP256R1FieldElement.Create(x);
end;

function TSecP256R1Curve.GetFieldSize: Int32;
begin
  result := Fq.BitLength;
end;

function TSecP256R1Curve.GetInfinity: IECPoint;
begin
  result := Fm_infinity;
end;

function TSecP256R1Curve.GetQ: TBigInteger;
begin
  result := Fq;
end;

function TSecP256R1Curve.SupportsCoordinateSystem(coord: Int32): Boolean;
begin
  case coord of
    COORD_JACOBIAN:
      result := True
  else
    result := False;
  end;
end;

{ TSecP256R1Curve.TSecP256R1LookupTable }

constructor TSecP256R1Curve.TSecP256R1LookupTable.Create
  (const outer: ISecP256R1Curve; const table: TCryptoLibUInt32Array;
  size: Int32);
begin
  Inherited Create();
  Fm_outer := outer;
  Fm_table := table;
  Fm_size := size;
end;

function TSecP256R1Curve.TSecP256R1LookupTable.GetSize: Int32;
begin
  result := Fm_size;
end;

function TSecP256R1Curve.TSecP256R1LookupTable.Lookup(index: Int32): IECPoint;
var
  x, y: TCryptoLibUInt32Array;
  pos, i, J: Int32;
  MASK: UInt32;
begin
  x := TNat256.Create();
  y := TNat256.Create();
  pos := 0;

  for i := 0 to System.Pred(Fm_size) do
  begin
    MASK := UInt32(TBits.Asr32((i xor index) - 1, 31));

    for J := 0 to System.Pred(SECP256R1_FE_INTS) do
    begin
      x[J] := x[J] xor (Fm_table[pos + J] and MASK);
      y[J] := y[J] xor (Fm_table[pos + SECP256R1_FE_INTS + J] and MASK);
    end;

    pos := pos + (SECP256R1_FE_INTS * 2);
  end;

  result := Fm_outer.CreateRawPoint(TSecP256R1FieldElement.Create(x)
    as ISecP256R1FieldElement, TSecP256R1FieldElement.Create(y)
    as ISecP256R1FieldElement, False);
end;

end.
