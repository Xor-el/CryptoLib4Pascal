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

unit ClpSecP256K1Curve;

{$I ..\..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpHex,
  ClpBits,
  ClpNat256,
  ClpECCurve,
  ClpIECInterface,
  ClpISecP256K1FieldElement,
  ClpSecP256K1Point,
  ClpISecP256K1Curve,
  ClpISecP256K1Point,
  ClpIECFieldElement,
  ClpBigInteger,
  ClpCryptoLibTypes;

type
  TSecP256K1Curve = class sealed(TAbstractFpCurve, ISecP256K1Curve)

  strict private

  type
    TSecP256K1LookupTable = class sealed(TInterfacedObject,
      ISecP256K1LookupTable, IECLookupTable)

    strict private
    var
      Fm_outer: ISecP256K1Curve;
      Fm_table: TCryptoLibUInt32Array;
      Fm_size: Int32;

      function GetSize: Int32; virtual;

    public

      constructor Create(const outer: ISecP256K1Curve;
        const table: TCryptoLibUInt32Array; size: Int32);

      function Lookup(index: Int32): IECPoint; virtual;

      property size: Int32 read GetSize;

    end;

  const
    SECP256K1_DEFAULT_COORDS = Int32(TECCurve.COORD_JACOBIAN);
    SECP256K1_FE_INTS = Int32(8);

    class var

      Fq: TBigInteger;

    class function GetSecP256K1Curve_Q: TBigInteger; static; inline;
    class constructor SecP256K1Curve();

  strict protected
  var
    Fm_infinity: ISecP256K1Point;

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

    class property SecP256K1Curve_Q: TBigInteger read GetSecP256K1Curve_Q;

  end;

implementation

uses
  // included here to avoid circular dependency :)
  ClpSecP256K1FieldElement;

{ TSecP256K1Curve }

class function TSecP256K1Curve.GetSecP256K1Curve_Q: TBigInteger;
begin
  result := Fq;
end;

class constructor TSecP256K1Curve.SecP256K1Curve;
begin
  Fq := TBigInteger.Create(1,
    THex.Decode
    ('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F'));
end;

constructor TSecP256K1Curve.Create;
begin
  Inherited Create(Fq);
  Fm_infinity := TSecP256K1Point.Create(Self as IECCurve, Nil, Nil);
  Fm_a := FromBigInteger(TBigInteger.Zero);
  Fm_b := FromBigInteger(TBigInteger.ValueOf(7));
  Fm_order := TBigInteger.Create(1,
    THex.Decode
    ('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141'));
  Fm_cofactor := TBigInteger.One;
  Fm_coord := SECP256K1_DEFAULT_COORDS;
end;

function TSecP256K1Curve.CloneCurve: IECCurve;
begin
  result := TSecP256K1Curve.Create();
end;

function TSecP256K1Curve.CreateCacheSafeLookupTable(const points
  : TCryptoLibGenericArray<IECPoint>; off, len: Int32): IECLookupTable;
var
  table: TCryptoLibUInt32Array;
  pos, i: Int32;
  p: IECPoint;
begin
  System.SetLength(table, len * SECP256K1_FE_INTS * 2);

  pos := 0;
  for i := 0 to System.Pred(len) do
  begin
    p := points[off + i];
    TNat256.Copy((p.RawXCoord as ISecP256K1FieldElement).x, 0, table, pos);
    pos := pos + SECP256K1_FE_INTS;
    TNat256.Copy((p.RawYCoord as ISecP256K1FieldElement).x, 0, table, pos);
    pos := pos + SECP256K1_FE_INTS;
  end;

  result := TSecP256K1LookupTable.Create(Self as ISecP256K1Curve, table, len);
end;

function TSecP256K1Curve.CreateRawPoint(const x, y: IECFieldElement;
  withCompression: Boolean): IECPoint;
begin
  result := TSecP256K1Point.Create(Self as IECCurve, x, y, withCompression);
end;

function TSecP256K1Curve.CreateRawPoint(const x, y: IECFieldElement;
  const zs: TCryptoLibGenericArray<IECFieldElement>; withCompression: Boolean)
  : IECPoint;
begin
  result := TSecP256K1Point.Create(Self as IECCurve, x, y, zs, withCompression);
end;

function TSecP256K1Curve.FromBigInteger(const x: TBigInteger): IECFieldElement;
begin
  result := TSecP256K1FieldElement.Create(x);
end;

function TSecP256K1Curve.GetFieldSize: Int32;
begin
  result := Fq.BitLength;
end;

function TSecP256K1Curve.GetInfinity: IECPoint;
begin
  result := Fm_infinity;
end;

function TSecP256K1Curve.GetQ: TBigInteger;
begin
  result := Fq;
end;

function TSecP256K1Curve.SupportsCoordinateSystem(coord: Int32): Boolean;
begin
  case coord of
    COORD_JACOBIAN:
      result := True
  else
    result := False;
  end;
end;

{ TSecP256K1Curve.TSecP256K1LookupTable }

constructor TSecP256K1Curve.TSecP256K1LookupTable.Create
  (const outer: ISecP256K1Curve; const table: TCryptoLibUInt32Array;
  size: Int32);
begin
  Inherited Create();
  Fm_outer := outer;
  Fm_table := table;
  Fm_size := size;
end;

function TSecP256K1Curve.TSecP256K1LookupTable.GetSize: Int32;
begin
  result := Fm_size;
end;

function TSecP256K1Curve.TSecP256K1LookupTable.Lookup(index: Int32): IECPoint;
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

    for J := 0 to System.Pred(SECP256K1_FE_INTS) do
    begin
      x[J] := x[J] xor (Fm_table[pos + J] and MASK);
      y[J] := y[J] xor (Fm_table[pos + SECP256K1_FE_INTS + J] and MASK);
    end;

    pos := pos + (SECP256K1_FE_INTS * 2);
  end;

  result := Fm_outer.CreateRawPoint(TSecP256K1FieldElement.Create(x)
    as ISecP256K1FieldElement, TSecP256K1FieldElement.Create(y)
    as ISecP256K1FieldElement, False);
end;

end.
