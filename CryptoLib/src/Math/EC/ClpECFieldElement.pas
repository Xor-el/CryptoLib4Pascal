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

unit ClpECFieldElement;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpBits,
  ClpBigInteger,
  ClpBigIntegers,
  ClpNat,
  ClpMod,
  ClpArrayUtils,
  ClpLongArray,
  ClpCryptoLibTypes,
  ClpIECFieldElement;

resourcestring
  SInvalidValue = 'Value Invalid in Fp Field Element, " x "';
  SInvalidValue2 = 'Value Invalid in F2m Field Element, "x"';
  SInvalidK2Value = 'k2 must be smaller than k3';
  SInvalidK2Value2 = 'k2 must be larger than 0';
  SInvalidFieldElement =
    'Field elements are not both instances of F2mFieldElement';
  SInvalidFieldElements =
    'Field elements are not elements of the same field F2m';
  SIncorrectRepresentation =
    'One of the F2m field elements has incorrect representation';
  SEvenValue = 'Even Value of Q';
  STraceInternalErrorCalculation = 'Internal Error in Trace Calculation';
  SHalfTraceUndefinedForM = 'Half-Trace Only Defined For Odd M';

type
  TECFieldElement = class abstract(TInterfacedObject, IECFieldElement)

  strict protected

    function GetBitLength: Int32; virtual;
    function GetIsOne: Boolean; virtual;
    function GetIsZero: Boolean; virtual;

    function GetFieldName: String; virtual; abstract;
    function GetFieldSize: Int32; virtual; abstract;

  public

    constructor Create();
    destructor Destroy; override;

    function ToBigInteger(): TBigInteger; virtual; abstract;
    function Add(const b: IECFieldElement): IECFieldElement; virtual; abstract;
    function AddOne(): IECFieldElement; virtual; abstract;
    function Subtract(const b: IECFieldElement): IECFieldElement;
      virtual; abstract;
    function Multiply(const b: IECFieldElement): IECFieldElement;
      virtual; abstract;
    function Divide(const b: IECFieldElement): IECFieldElement;
      virtual; abstract;
    function Negate(): IECFieldElement; virtual; abstract;
    function Square(): IECFieldElement; virtual; abstract;
    function Invert(): IECFieldElement; virtual; abstract;
    function Sqrt(): IECFieldElement; virtual; abstract;

    function MultiplyMinusProduct(const b, x, y: IECFieldElement)
      : IECFieldElement; virtual;

    function MultiplyPlusProduct(const b, x, y: IECFieldElement)
      : IECFieldElement; virtual;

    function SquareMinusProduct(const x, y: IECFieldElement)
      : IECFieldElement; virtual;

    function SquarePlusProduct(const x, y: IECFieldElement)
      : IECFieldElement; virtual;

    function SquarePow(pow: Int32): IECFieldElement; virtual;

    function TestBitZero(): Boolean; virtual;

    function Equals(const other: IECFieldElement): Boolean;
      reintroduce; virtual;

    function GetHashCode(): {$IFDEF DELPHI}Int32; {$ELSE}PtrInt;
{$ENDIF DELPHI}override;

    function ToString(): String; override;

    function GetEncoded(): TCryptoLibByteArray; virtual;

    property FieldName: string read GetFieldName;
    property FieldSize: Int32 read GetFieldSize;
    property BitLength: Int32 read GetBitLength;
    property IsOne: Boolean read GetIsOne;
    property IsZero: Boolean read GetIsZero;

  end;

type
  TAbstractFpFieldElement = class abstract(TECFieldElement,
    IAbstractFpFieldElement)

  end;

type
  TFpFieldElement = class(TAbstractFpFieldElement, IFpFieldElement)

  strict private
    Fq, Fr, Fx: TBigInteger;

    function GetQ: TBigInteger; inline;

    function CheckSqrt(const z: IECFieldElement): IECFieldElement; inline;
    function LucasSequence(const P, Q, K: TBigInteger)
      : TCryptoLibGenericArray<TBigInteger>;

  strict protected
    function ModAdd(const x1, x2: TBigInteger): TBigInteger; virtual;
    function ModDouble(const x: TBigInteger): TBigInteger; virtual;
    function ModHalf(const x: TBigInteger): TBigInteger; virtual;
    function ModHalfAbs(const x: TBigInteger): TBigInteger; virtual;
    function ModInverse(const x: TBigInteger): TBigInteger; virtual;
    function ModMult(const x1, x2: TBigInteger): TBigInteger; virtual;
    function ModReduce(const x: TBigInteger): TBigInteger; virtual;
    function ModSubtract(const x1, x2: TBigInteger): TBigInteger; virtual;

    /// <summary>
    /// return the field name for this field.
    /// </summary>
    /// <returns>
    /// return the string "Fp".
    /// </returns>
    function GetFieldName: String; override;
    function GetFieldSize: Int32; override;

  public
    constructor Create(const Q, x: TBigInteger); overload;
      deprecated 'Use ECCurve.FromBigInteger to construct field elements';

    constructor Create(const Q, r, x: TBigInteger); overload;

    destructor Destroy; override;

    function ToBigInteger(): TBigInteger; override;

    function Add(const b: IECFieldElement): IECFieldElement; override;
    function AddOne(): IECFieldElement; override;
    function Subtract(const b: IECFieldElement): IECFieldElement; override;

    function Multiply(const b: IECFieldElement): IECFieldElement; override;
    function Divide(const b: IECFieldElement): IECFieldElement; override;
    function Negate(): IECFieldElement; override;
    function Square(): IECFieldElement; override;

    function Invert(): IECFieldElement; override;

    /// <summary>
    /// return a sqrt root - the routine verifies that the calculation
    /// </summary>
    /// <returns>
    /// returns the right value - if none exists it returns null.
    /// </returns>
    function Sqrt(): IECFieldElement; override;

    function MultiplyMinusProduct(const b, x, y: IECFieldElement)
      : IECFieldElement; override;
    function MultiplyPlusProduct(const b, x, y: IECFieldElement)
      : IECFieldElement; override;

    function SquareMinusProduct(const x, y: IECFieldElement)
      : IECFieldElement; override;

    function SquarePlusProduct(const x, y: IECFieldElement)
      : IECFieldElement; override;

    property FieldName: string read GetFieldName;
    property FieldSize: Int32 read GetFieldSize;

    property Q: TBigInteger read GetQ;

    function Equals(const other: IFpFieldElement): Boolean; reintroduce;

    function GetHashCode(): {$IFDEF DELPHI}Int32; {$ELSE}PtrInt;
{$ENDIF DELPHI}override;

    class function CalculateResidue(const P: TBigInteger): TBigInteger; static;

  end;

type
  TAbstractF2mFieldElement = class abstract(TECFieldElement,
    IAbstractF2mFieldElement)

  public
    function Trace(): Int32; virtual;
    function HalfTrace(): IECFieldElement; virtual;

  end;

type
  /// **
  // * Class representing the Elements of the finite field
  // * <code>F<sub>2<sup>m</sup></sub></code> in polynomial basis (PB)
  // * representation. Both trinomial (Tpb) and pentanomial (Ppb) polynomial
  // * basis representations are supported. Gaussian normal basis (GNB)
  // * representation is not supported.
  // */
  TF2mFieldElement = class(TAbstractF2mFieldElement, IF2mFieldElement)

  strict private

  var
    Frepresentation, Fm: Int32;
    FKs: TCryptoLibInt32Array;
    Fx: TLongArray;
    // /**
    // * The exponent <code>m</code> of <code>F<sub>2<sup>m</sup></sub></code>.
    // */
    function GetM: Int32; inline;
    /// <summary>
    /// Tpb or Ppb.
    /// </summary>
    function GetRepresentation: Int32; inline;
    function GetKs: TCryptoLibInt32Array; inline;
    function GetX: TLongArray; inline;

    function GetK1: Int32; inline;
    function GetK2: Int32; inline;
    function GetK3: Int32; inline;

  strict protected

    function GetBitLength: Int32; override;
    function GetIsOne: Boolean; override;
    function GetIsZero: Boolean; override;

    function GetFieldName: String; override;
    function GetFieldSize: Int32; override;

  public

    const

    /// <summary>
    /// Indicates gaussian normal basis representation (GNB). Number
    /// chosen according to X9.62. GNB is not implemented at present. <br />
    /// </summary>
    Gnb = Int32(1);

    /// <summary>
    /// Indicates trinomial basis representation (Tpb). Number chosen
    /// according to X9.62. <br />
    /// </summary>
    Tpb = Int32(2);

    /// <summary>
    /// Indicates pentanomial basis representation (Ppb). Number chosen
    /// according to X9.62. <br />
    /// </summary>
    Ppb = Int32(3);

    // /**
    // * Constructor for Ppb.
    // * @param m  The exponent <code>m</code> of
    // * <code>F<sub>2<sup>m</sup></sub></code>.
    // * @param k1 The integer <code>k1</code> where <code>x<sup>m</sup> +
    // * x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code>
    // * represents the reduction polynomial <code>f(z)</code>.
    // * @param k2 The integer <code>k2</code> where <code>x<sup>m</sup> +
    // * x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code>
    // * represents the reduction polynomial <code>f(z)</code>.
    // * @param k3 The integer <code>k3</code> where <code>x<sup>m</sup> +
    // * x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code>
    // * represents the reduction polynomial <code>f(z)</code>.
    // * @param x The BigInteger representing the value of the field element.
    // */
    constructor Create(m, k1, k2, k3: Int32; const x: TBigInteger); overload;
      deprecated 'Use ECCurve.FromBigInteger to construct field elements';
    // /**
    // * Constructor for Tpb.
    // * @param m  The exponent <code>m</code> of
    // * <code>F<sub>2<sup>m</sup></sub></code>.
    // * @param k The integer <code>k</code> where <code>x<sup>m</sup> +
    // * x<sup>k</sup> + 1</code> represents the reduction
    // * polynomial <code>f(z)</code>.
    // * @param x The BigInteger representing the value of the field element.
    // */
    constructor Create(m, K: Int32; const x: TBigInteger); overload;
      deprecated 'Use ECCurve.FromBigInteger to construct field elements';

    constructor Create(m: Int32; const ks: TCryptoLibInt32Array;
      const x: TLongArray); overload;

    destructor Destroy; override;

    function TestBitZero(): Boolean; override;
    function ToBigInteger(): TBigInteger; override;

    function Add(const b: IECFieldElement): IECFieldElement; override;
    function AddOne(): IECFieldElement; override;
    function Subtract(const b: IECFieldElement): IECFieldElement; override;

    function Multiply(const b: IECFieldElement): IECFieldElement; override;
    function Divide(const b: IECFieldElement): IECFieldElement; override;
    function Negate(): IECFieldElement; override;
    function Square(): IECFieldElement; override;

    function Invert(): IECFieldElement; override;

    /// <summary>
    /// return a sqrt root - the routine verifies that the calculation
    /// </summary>
    /// <returns>
    /// returns the right value - if none exists it returns null.
    /// </returns>
    function Sqrt(): IECFieldElement; override;

    function MultiplyMinusProduct(const b, x, y: IECFieldElement)
      : IECFieldElement; override;
    function MultiplyPlusProduct(const b, x, y: IECFieldElement)
      : IECFieldElement; override;

    function SquareMinusProduct(const x, y: IECFieldElement)
      : IECFieldElement; override;

    function SquarePlusProduct(const x, y: IECFieldElement)
      : IECFieldElement; override;

    function SquarePow(pow: Int32): IECFieldElement; override;

    function Equals(const other: IF2mFieldElement): Boolean; reintroduce;

    function GetHashCode(): {$IFDEF DELPHI}Int32; {$ELSE}PtrInt;
{$ENDIF DELPHI}override;

    // /**
    // * Checks, if the ECFieldElements <code>a</code> and <code>b</code>
    // * are elements of the same field <code>F<sub>2<sup>m</sup></sub></code>
    // * (having the same representation).
    // * @param a field element.
    // * @param b field element to be compared.
    // * @throws ArgumentException if <code>a</code> and <code>b</code>
    // * are not elements of the same field
    // * <code>F<sub>2<sup>m</sup></sub></code> (having the same
    // * representation).
    // */
    class procedure CheckFieldElements(const a, b: IECFieldElement); static;

    // /**
    // * @return the representation of the field
    // * <code>F<sub>2<sup>m</sup></sub></code>, either of
    // * {@link F2mFieldElement.Tpb} (trinomial
    // * basis representation) or
    // * {@link F2mFieldElement.Ppb} (pentanomial
    // * basis representation).
    // */
    property Representation: Int32 read GetRepresentation;

    // /**
    // * @return the degree <code>m</code> of the reduction polynomial
    // * <code>f(z)</code>.
    // */
    property m: Int32 read GetM;
    // /**
    // * @return Tpb: The integer <code>k</code> where <code>x<sup>m</sup> +
    // * x<sup>k</sup> + 1</code> represents the reduction polynomial
    // * <code>f(z)</code>.<br/>
    // * Ppb: The integer <code>k1</code> where <code>x<sup>m</sup> +
    // * x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code>
    // * represents the reduction polynomial <code>f(z)</code>.<br/>
    // */
    property k1: Int32 read GetK1;
    // /**
    // * @return Tpb: Always returns <code>0</code><br/>
    // * Ppb: The integer <code>k2</code> where <code>x<sup>m</sup> +
    // * x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code>
    // * represents the reduction polynomial <code>f(z)</code>.<br/>
    // */
    property k2: Int32 read GetK2;
    // /**
    // * @return Tpb: Always set to <code>0</code><br/>
    // * Ppb: The integer <code>k3</code> where <code>x<sup>m</sup> +
    // * x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code>
    // * represents the reduction polynomial <code>f(z)</code>.<br/>
    // */
    property k3: Int32 read GetK3;

    property ks: TCryptoLibInt32Array read GetKs;

    /// <summary>
    /// The <c>LongArray</c> holding the bits.
    /// </summary>
    property x: TLongArray read GetX;

    property FieldName: string read GetFieldName;
    property FieldSize: Int32 read GetFieldSize;
    property BitLength: Int32 read GetBitLength;
    property IsOne: Boolean read GetIsOne;
    property IsZero: Boolean read GetIsZero;

  end;

implementation

{ TF2mFieldElement }

function TF2mFieldElement.GetKs: TCryptoLibInt32Array;
begin
  result := FKs;
end;

function TF2mFieldElement.GetM: Int32;
begin
  result := Fm;
end;

function TF2mFieldElement.GetRepresentation: Int32;
begin
  result := Frepresentation;
end;

function TF2mFieldElement.GetX: TLongArray;
begin
  result := Fx;
end;

function TF2mFieldElement.Add(const b: IECFieldElement): IECFieldElement;
var
  iarrClone: TLongArray;
  bF2m: IF2mFieldElement;
begin
  // No check performed here for performance reasons. Instead the
  // elements involved are checked in ECPoint.F2m
  // checkFieldElements(this, b);
  iarrClone := Fx.Copy();
  bF2m := b as IF2mFieldElement;
  iarrClone.AddShiftedByWords(bF2m.x, 0);
  result := TF2mFieldElement.Create(Fm, FKs, iarrClone);
end;

function TF2mFieldElement.AddOne: IECFieldElement;
begin
  result := TF2mFieldElement.Create(Fm, FKs, Fx.AddOne());
end;

class procedure TF2mFieldElement.CheckFieldElements(const a,
  b: IECFieldElement);
var
  aF2m, bF2m: IF2mFieldElement;
begin
  if (not(Supports(a, IF2mFieldElement, aF2m)) or
    (not(Supports(b, IF2mFieldElement, bF2m)))) then
  begin
    raise EArgumentCryptoLibException.CreateRes(@SInvalidFieldElement);
  end;

  if (aF2m.Representation <> bF2m.Representation) then
  begin
    // Should never occur
    raise EArgumentCryptoLibException.CreateRes(@SIncorrectRepresentation);
  end;

  if ((aF2m.m <> bF2m.m) or (not TArrayUtils.AreEqual(aF2m.ks, bF2m.ks))) then
  begin
    raise EArgumentCryptoLibException.CreateRes(@SInvalidFieldElements);
  end;
end;

constructor TF2mFieldElement.Create(m, K: Int32; const x: TBigInteger);
begin
  Create(m, K, 0, 0, x);
end;

constructor TF2mFieldElement.Create(m, k1, k2, k3: Int32; const x: TBigInteger);
begin
  Inherited Create();
  if (not(x.IsInitialized) or (x.SignValue < 0) or (x.BitLength > m)) then
  begin
    raise EArgumentCryptoLibException.CreateRes(@SInvalidValue2);
  end;

  if ((k2 = 0) and (k3 = 0)) then
  begin
    Frepresentation := Tpb;
    FKs := TCryptoLibInt32Array.Create(k1);
  end
  else
  begin
    if (k2 >= k3) then
    begin
      raise EArgumentCryptoLibException.CreateRes(@SInvalidK2Value);
    end;
    if (k2 <= 0) then
    begin
      raise EArgumentCryptoLibException.CreateRes(@SInvalidK2Value2);
    end;

    Frepresentation := Ppb;
    FKs := TCryptoLibInt32Array.Create(k1, k2, k3);
  end;

  Fm := m;
  Fx := TLongArray.Create(x);
end;

constructor TF2mFieldElement.Create(m: Int32; const ks: TCryptoLibInt32Array;
  const x: TLongArray);
begin
  Inherited Create();
  Fm := m;
  if (System.Length(ks) = 1) then
  begin
    Frepresentation := Tpb
  end
  else
  begin
    Frepresentation := Ppb;
  end;
  FKs := ks;
  Fx := x;
end;

destructor TF2mFieldElement.Destroy;
begin
  inherited Destroy;
end;

function TF2mFieldElement.Divide(const b: IECFieldElement): IECFieldElement;
var
  bInv: IECFieldElement;
begin
  // There may be more efficient implementations
  bInv := b.Invert();
  result := Multiply(bInv);
end;

function TF2mFieldElement.Equals(const other: IF2mFieldElement): Boolean;
begin
  if (other = Self as IF2mFieldElement) then
  begin
    result := true;
    Exit;
  end;
  if (Nil = other) then
  begin
    result := false;
    Exit;
  end;
  result := ((m = other.m) and (Representation = other.Representation) and
    TArrayUtils.AreEqual(ks, other.ks) and (x.Equals(other.x)));
end;

function TF2mFieldElement.GetBitLength: Int32;
begin
  result := Fx.Degree();
end;

function TF2mFieldElement.GetFieldName: String;
begin
  result := 'F2m';
end;

function TF2mFieldElement.GetFieldSize: Int32;
begin
  result := Fm;
end;

function TF2mFieldElement.GetHashCode: {$IFDEF DELPHI}Int32; {$ELSE}PtrInt;
{$ENDIF DELPHI}
begin
  result := Fx.GetHashCode() xor Fm xor TArrayUtils.GetArrayHashCode(FKs);
end;

function TF2mFieldElement.GetIsOne: Boolean;
begin
  result := Fx.IsOne();
end;

function TF2mFieldElement.GetIsZero: Boolean;
begin
  result := Fx.IsZero();
end;

function TF2mFieldElement.GetK1: Int32;
begin
  result := FKs[0];
end;

function TF2mFieldElement.GetK2: Int32;
begin
  if (System.Length(FKs) >= 2) then
  begin
    result := FKs[1];
  end
  else
  begin
    result := 0;
  end;
end;

function TF2mFieldElement.GetK3: Int32;
begin
  if (System.Length(FKs) >= 3) then
  begin
    result := FKs[2];
  end
  else
  begin
    result := 0;
  end;
end;

function TF2mFieldElement.Invert: IECFieldElement;
begin
  result := TF2mFieldElement.Create(Fm, FKs, Fx.ModInverse(Fm, FKs));
end;

function TF2mFieldElement.Multiply(const b: IECFieldElement): IECFieldElement;
begin
  // Right-to-left comb multiplication in the LongArray
  // Input: Binary polynomials a(z) and b(z) of degree at most m-1
  // Output: c(z) = a(z) * b(z) mod f(z)

  // No check performed here for performance reasons. Instead the
  // elements involved are checked in ECPoint.F2m
  // checkFieldElements(this, b);
  result := TF2mFieldElement.Create(Fm, FKs,
    Fx.ModMultiply((b as IF2mFieldElement).x, Fm, FKs));
end;

function TF2mFieldElement.MultiplyMinusProduct(const b, x, y: IECFieldElement)
  : IECFieldElement;
begin
  result := MultiplyPlusProduct(b, x, y);
end;

function TF2mFieldElement.MultiplyPlusProduct(const b, x, y: IECFieldElement)
  : IECFieldElement;
var
  ax, bx, xx, yx, ab, xy: TLongArray;
begin
  ax := Fx;
  bx := (b as IF2mFieldElement).x;
  xx := (x as IF2mFieldElement).x;
  yx := (y as IF2mFieldElement).x;

  ab := ax.Multiply(bx, Fm, FKs);
  xy := xx.Multiply(yx, Fm, FKs);

  if ((ab.Equals(ax)) or (ab.Equals(bx))) then
  begin
    ab := ab.Copy();
  end;

  ab.AddShiftedByWords(xy, 0);
  ab.Reduce(Fm, FKs);

  result := TF2mFieldElement.Create(Fm, FKs, ab);
end;

function TF2mFieldElement.Negate: IECFieldElement;
begin
  // -x == x holds for all x in F2m
  result := Self as IECFieldElement;
end;

function TF2mFieldElement.Sqrt: IECFieldElement;
begin
  if ((Fx.IsZero()) or (Fx.IsOne())) then
  begin
    result := Self as IECFieldElement;
  end
  else
  begin
    result := SquarePow(Fm - 1);
  end;
end;

function TF2mFieldElement.Square: IECFieldElement;
begin
  result := TF2mFieldElement.Create(Fm, FKs, Fx.ModSquare(Fm, FKs));
end;

function TF2mFieldElement.SquareMinusProduct(const x, y: IECFieldElement)
  : IECFieldElement;
begin
  result := SquarePlusProduct(x, y);
end;

function TF2mFieldElement.SquarePlusProduct(const x, y: IECFieldElement)
  : IECFieldElement;
var
  ax, xx, yx, aa, xy: TLongArray;
begin
  ax := Fx;
  xx := (x as IF2mFieldElement).x;
  yx := (y as IF2mFieldElement).x;

  aa := ax.Square(Fm, FKs);
  xy := xx.Multiply(yx, Fm, FKs);

  if (aa.Equals(ax)) then
  begin
    aa := aa.Copy();
  end;

  aa.AddShiftedByWords(xy, 0);
  aa.Reduce(Fm, FKs);

  result := TF2mFieldElement.Create(Fm, FKs, aa);
end;

function TF2mFieldElement.SquarePow(pow: Int32): IECFieldElement;
begin
  if pow < 1 then
  begin
    result := Self as IECFieldElement
  end
  else
  begin
    result := TF2mFieldElement.Create(Fm, FKs, Fx.ModSquareN(pow, Fm, FKs));
  end;
end;

function TF2mFieldElement.Subtract(const b: IECFieldElement): IECFieldElement;
begin
  // Addition and subtraction are the same in F2m
  result := Add(b);
end;

function TF2mFieldElement.TestBitZero: Boolean;
begin
  result := Fx.TestBitZero();
end;

function TF2mFieldElement.ToBigInteger: TBigInteger;
begin
  result := Fx.ToBigInteger();
end;

{ TECFieldElement }

constructor TECFieldElement.Create;
begin
  Inherited Create();
end;

destructor TECFieldElement.Destroy;
begin
  inherited Destroy;
end;

function TECFieldElement.Equals(const other: IECFieldElement): Boolean;
begin
  if (other = Self as IECFieldElement) then
  begin
    result := true;
    Exit;
  end;
  if (Nil = other) then
  begin
    result := false;
    Exit;
  end;
  result := ToBigInteger().Equals(other.ToBigInteger());
end;

function TECFieldElement.GetBitLength: Int32;
begin
  result := ToBigInteger().BitLength;
end;

function TECFieldElement.GetEncoded: TCryptoLibByteArray;
begin
  result := TBigIntegers.AsUnsignedByteArray((FieldSize + 7) div 8,
    ToBigInteger());
end;

function TECFieldElement.GetHashCode: {$IFDEF DELPHI}Int32; {$ELSE}PtrInt;
{$ENDIF DELPHI}
begin
  result := ToBigInteger().GetHashCode();
end;

function TECFieldElement.GetIsOne: Boolean;
begin
  result := BitLength = 1;
end;

function TECFieldElement.GetIsZero: Boolean;
begin
  result := 0 = ToBigInteger().SignValue;
end;

function TECFieldElement.MultiplyMinusProduct(const b, x, y: IECFieldElement)
  : IECFieldElement;
begin
  result := Multiply(b).Subtract(x.Multiply(y));
end;

function TECFieldElement.MultiplyPlusProduct(const b, x, y: IECFieldElement)
  : IECFieldElement;
begin
  result := Multiply(b).Add(x.Multiply(y));
end;

function TECFieldElement.SquareMinusProduct(const x, y: IECFieldElement)
  : IECFieldElement;
begin
  result := Square().Subtract(x.Multiply(y));
end;

function TECFieldElement.SquarePlusProduct(const x, y: IECFieldElement)
  : IECFieldElement;
begin
  result := Square().Add(x.Multiply(y));
end;

function TECFieldElement.SquarePow(pow: Int32): IECFieldElement;
var
  r: IECFieldElement;
  i: Int32;
begin
  r := Self as IECFieldElement;
  i := 0;
  while i < pow do
  begin
    r := r.Square();
    System.Inc(i);
  end;

  result := r;
end;

function TECFieldElement.TestBitZero: Boolean;
begin
  result := ToBigInteger().TestBit(0);
end;

function TECFieldElement.ToString: String;
begin
  result := ToBigInteger().ToString(16);
end;

{ TFpFieldElement }

function TFpFieldElement.GetQ: TBigInteger;
begin
  result := Fq;
end;

function TFpFieldElement.GetFieldSize: Int32;
begin
  result := Q.BitLength;
end;

function TFpFieldElement.Add(const b: IECFieldElement): IECFieldElement;
begin
  result := TFpFieldElement.Create(Fq, Fr, ModAdd(Fx, b.ToBigInteger()));
end;

function TFpFieldElement.AddOne: IECFieldElement;
var
  x2: TBigInteger;
begin
  x2 := Fx.Add(TBigInteger.One);
  if (x2.CompareTo(Q) = 0) then
  begin
    x2 := TBigInteger.Zero;
  end;
  result := TFpFieldElement.Create(Fq, Fr, x2);
end;

class function TFpFieldElement.CalculateResidue(const P: TBigInteger)
  : TBigInteger;
var
  BitLength: Int32;
  firstWord: TBigInteger;
begin
  BitLength := P.BitLength;
  if (BitLength >= 96) then
  begin
    firstWord := P.ShiftRight(BitLength - 64);
    if (firstWord.Int64Value = Int64(-1)) then
    begin
      result := TBigInteger.One.ShiftLeft(BitLength).Subtract(P);
      Exit;
    end;
    if ((BitLength and 7) = 0) then
    begin
      result := TBigInteger.One.ShiftLeft(BitLength shl 1).Divide(P).Negate();
      Exit;
    end;
  end;
  result := Default (TBigInteger);
end;

function TFpFieldElement.CheckSqrt(const z: IECFieldElement): IECFieldElement;
begin
  if (z.Square().Equals(Self as IECFieldElement)) then
  begin
    result := z;
  end
  else
  begin
    result := Nil;
  end;
end;

constructor TFpFieldElement.Create(const Q, x: TBigInteger);
begin
  Create(Q, CalculateResidue(Q), x);
end;

constructor TFpFieldElement.Create(const Q, r, x: TBigInteger);
begin
  Inherited Create();
  if (not(x.IsInitialized) or (x.SignValue < 0) or (x.CompareTo(Q) >= 0)) then
  begin
    raise EArgumentCryptoLibException.CreateRes(@SInvalidValue);
  end;

  Fq := Q;
  Fr := r;
  Fx := x;
end;

destructor TFpFieldElement.Destroy;
begin
  inherited Destroy;
end;

function TFpFieldElement.Divide(const b: IECFieldElement): IECFieldElement;
begin
  result := TFpFieldElement.Create(Fq, Fr,
    ModMult(Fx, ModInverse(b.ToBigInteger())));
end;

function TFpFieldElement.Equals(const other: IFpFieldElement): Boolean;
begin
  if (other = Self as IFpFieldElement) then
  begin
    result := true;
    Exit;
  end;

  if (other = Nil) then
  begin
    result := false;
    Exit;
  end;

  result := (Q.Equals(other.Q) and (Inherited Equals(other)));
end;

function TFpFieldElement.GetFieldName: String;
begin
  result := 'Fp';
end;

function TFpFieldElement.GetHashCode: {$IFDEF DELPHI}Int32; {$ELSE}PtrInt;
{$ENDIF DELPHI}
begin
  result := Q.GetHashCode() xor (Inherited GetHashCode());
end;

function TFpFieldElement.Invert: IECFieldElement;
begin
  // TODO Modular inversion can be faster for a (Generalized) Mersenne Prime.
  result := TFpFieldElement.Create(Fq, Fr, ModInverse(Fx));
end;

function TFpFieldElement.LucasSequence(const P, Q, K: TBigInteger)
  : TCryptoLibGenericArray<TBigInteger>;
var
  n, s, j: Int32;
  Uh, Vl, Vh, Ql, Qh: TBigInteger;
begin
  // TODO Research and apply "common-multiplicand multiplication here"

  n := K.BitLength;
  s := K.GetLowestSetBit();

{$IFDEF DEBUG}
  System.Assert(K.TestBit(s));
{$ENDIF DEBUG}
  Uh := TBigInteger.One;
  Vl := TBigInteger.Two;
  Vh := P;
  Ql := TBigInteger.One;
  Qh := TBigInteger.One;

  j := n - 1;

  while j >= s + 1 do
  begin
    Ql := ModMult(Ql, Qh);

    if (K.TestBit(j)) then
    begin
      Qh := ModMult(Ql, Q);
      Uh := ModMult(Uh, Vh);
      Vl := ModReduce(Vh.Multiply(Vl).Subtract(P.Multiply(Ql)));
      Vh := ModReduce(Vh.Multiply(Vh).Subtract(Qh.ShiftLeft(1)));
    end
    else
    begin
      Qh := Ql;
      Uh := ModReduce(Uh.Multiply(Vl).Subtract(Ql));
      Vh := ModReduce(Vh.Multiply(Vl).Subtract(P.Multiply(Ql)));
      Vl := ModReduce(Vl.Multiply(Vl).Subtract(Ql.ShiftLeft(1)));
    end;
    System.Dec(j);
  end;

  Ql := ModMult(Ql, Qh);
  Qh := ModMult(Ql, Q);
  Uh := ModReduce(Uh.Multiply(Vl).Subtract(Ql));
  Vl := ModReduce(Vh.Multiply(Vl).Subtract(P.Multiply(Ql)));
  Ql := ModMult(Ql, Qh);

  j := 1;

  while j <= s do
  begin
    Uh := ModMult(Uh, Vl);
    Vl := ModReduce(Vl.Multiply(Vl).Subtract(Ql.ShiftLeft(1)));
    Ql := ModMult(Ql, Ql);
    System.Inc(j);
  end;

  result := TCryptoLibGenericArray<TBigInteger>.Create(Uh, Vl);
end;

function TFpFieldElement.ModAdd(const x1, x2: TBigInteger): TBigInteger;
var
  x3: TBigInteger;
begin
  x3 := x1.Add(x2);
  if (x3.CompareTo(Q) >= 0) then
  begin
    x3 := x3.Subtract(Q);
  end;
  result := x3;
end;

function TFpFieldElement.ModDouble(const x: TBigInteger): TBigInteger;
var
  _2x: TBigInteger;
begin
  _2x := x.ShiftLeft(1);
  if (_2x.CompareTo(Q) >= 0) then
  begin
    _2x := _2x.Subtract(Q);
  end;
  result := _2x;
end;

function TFpFieldElement.ModHalf(const x: TBigInteger): TBigInteger;
var
  Lx: TBigInteger;
begin
  Lx := x;
  if (Lx.TestBit(0)) then
  begin
    Lx := Q.Add(Lx);
  end;
  result := Lx.ShiftRight(1);
end;

function TFpFieldElement.ModHalfAbs(const x: TBigInteger): TBigInteger;
var
  Lx: TBigInteger;
begin
  Lx := x;
  if (Lx.TestBit(0)) then
  begin
    Lx := Q.Subtract(Lx);
  end;
  result := Lx.ShiftRight(1);
end;

function TFpFieldElement.ModInverse(const x: TBigInteger): TBigInteger;
var
  bits, len: Int32;
  P, n, z: TCryptoLibUInt32Array;
begin
  bits := FieldSize;
  len := TBits.Asr32((bits + 31), 5);
  P := TNat.FromBigInteger(bits, Q);
  n := TNat.FromBigInteger(bits, x);
  z := TNat.Create(len);

  TMod.Invert(P, n, z);

  result := TNat.ToBigInteger(len, z);
end;

function TFpFieldElement.ModMult(const x1, x2: TBigInteger): TBigInteger;
begin
  result := ModReduce(x1.Multiply(x2));
end;

function TFpFieldElement.ModReduce(const x: TBigInteger): TBigInteger;
var
  negative, rIsOne: Boolean;
  qLen, d: Int32;
  qMod, u, v, mu, quot, bk1, Lx: TBigInteger;
begin
  Lx := x;
  if (not(Fr.IsInitialized)) then
  begin
    Lx := Lx.&Mod(Q);
  end
  else
  begin
    negative := Lx.SignValue < 0;
    if (negative) then
    begin
      Lx := Lx.Abs();
    end;
    qLen := Q.BitLength;
    if (Fr.SignValue > 0) then
    begin
      qMod := TBigInteger.One.ShiftLeft(qLen);
      rIsOne := Fr.Equals(TBigInteger.One);
      while (Lx.BitLength > (qLen + 1)) do
      begin
        u := Lx.ShiftRight(qLen);
        v := Lx.Remainder(qMod);
        if (not rIsOne) then
        begin
          u := u.Multiply(Fr);
        end;
        Lx := u.Add(v);
      end
    end
    else
    begin
      d := ((qLen - 1) and 31) + 1;
      mu := Fr.Negate();
      u := mu.Multiply(Lx.ShiftRight(qLen - d));
      quot := u.ShiftRight(qLen + d);
      v := quot.Multiply(Q);
      bk1 := TBigInteger.One.ShiftLeft(qLen + d);
      v := v.Remainder(bk1);
      Lx := Lx.Remainder(bk1);
      Lx := Lx.Subtract(v);
      if (Lx.SignValue < 0) then
      begin
        Lx := Lx.Add(bk1);
      end
    end;
    while (Lx.CompareTo(Q) >= 0) do
    begin
      Lx := Lx.Subtract(Q);
    end;
    if ((negative) and (Lx.SignValue <> 0)) then
    begin
      Lx := Q.Subtract(Lx);
    end;
  end;
  result := Lx;
end;

function TFpFieldElement.ModSubtract(const x1, x2: TBigInteger): TBigInteger;
var
  x3: TBigInteger;
begin
  x3 := x1.Subtract(x2);
  if (x3.SignValue < 0) then
  begin
    x3 := x3.Add(Q);
  end;
  result := x3;
end;

function TFpFieldElement.Multiply(const b: IECFieldElement): IECFieldElement;
begin
  result := TFpFieldElement.Create(Fq, Fr, ModMult(Fx, b.ToBigInteger()));
end;

function TFpFieldElement.MultiplyMinusProduct(const b, x, y: IECFieldElement)
  : IECFieldElement;
var
  ax, bx, xx, yx, ab, xy: TBigInteger;
begin
  ax := Fx;
  bx := b.ToBigInteger();
  xx := x.ToBigInteger();
  yx := y.ToBigInteger();
  ab := ax.Multiply(bx);
  xy := xx.Multiply(yx);
  result := TFpFieldElement.Create(Fq, Fr, ModReduce(ab.Subtract(xy)));
end;

function TFpFieldElement.MultiplyPlusProduct(const b, x, y: IECFieldElement)
  : IECFieldElement;
var
  ax, bx, xx, yx, ab, xy, sum: TBigInteger;
begin
  ax := Fx;
  bx := b.ToBigInteger();
  xx := x.ToBigInteger();
  yx := y.ToBigInteger();
  ab := ax.Multiply(bx);
  xy := xx.Multiply(yx);
  sum := ab.Add(xy);
  if ((Fr.IsInitialized) and (Fr.SignValue < 0) and
    (sum.BitLength > (Fq.BitLength shl 1))) then
  begin
    sum := sum.Subtract(Fq.ShiftLeft(Q.BitLength));
  end;
  result := TFpFieldElement.Create(Fq, Fr, ModReduce(sum));
end;

function TFpFieldElement.Negate: IECFieldElement;
begin
  if Fx.SignValue = 0 then
  begin
    result := Self as IECFieldElement
  end
  else
  begin
    result := TFpFieldElement.Create(Fq, Fr, Fq.Subtract(Fx));
  end;
end;

function TFpFieldElement.Sqrt: IECFieldElement;
var
  u, v, K, e, t1, t2, t3, t4, y, legendreExponent, x, fourX, qMinusOne,
    P: TBigInteger;
  tempRes: TCryptoLibGenericArray<TBigInteger>;
  CompareRes, ModReduceRes: Boolean;
begin
  if (IsZero or IsOne) then
  begin
    result := Self as IECFieldElement;
    Exit;
  end;

  if (not Fq.TestBit(0)) then
  begin
    raise ENotImplementedCryptoLibException.CreateRes(@SEvenValue);
  end;

  if (Fq.TestBit(1)) then // q == 4m + 3
  begin
    e := Fq.ShiftRight(2).Add(TBigInteger.One);
    result := CheckSqrt(TFpFieldElement.Create(Fq, Fr, Fx.ModPow(e, Fq))
      as IFpFieldElement);
    Exit;
  end;

  if (Fq.TestBit(2)) then // q == 8m + 5
  begin
    t1 := Fx.ModPow(Fq.ShiftRight(3), Fq);
    t2 := ModMult(t1, Fx);
    t3 := ModMult(t2, t1);

    if (t3.Equals(TBigInteger.One)) then
    begin
      result := CheckSqrt(TFpFieldElement.Create(Fq, Fr, t2)
        as IFpFieldElement);
      Exit;
    end;

    // TODO This is constant and could be precomputed
    t4 := TBigInteger.Two.ModPow(Fq.ShiftRight(2), Fq);

    y := ModMult(t2, t4);

    result := CheckSqrt(TFpFieldElement.Create(Fq, Fr, y) as IFpFieldElement);
    Exit;
  end;

  // q == 8m + 1

  legendreExponent := Fq.ShiftRight(1);
  if (not(Fx.ModPow(legendreExponent, Fq).Equals(TBigInteger.One))) then
  begin
    result := Nil;
    Exit;
  end;

  x := Fx;
  fourX := ModDouble(ModDouble(x));

  K := legendreExponent.Add(TBigInteger.One);
  qMinusOne := Fq.Subtract(TBigInteger.One);

  repeat

    repeat
      P := TBigInteger.Arbitrary(Fq.BitLength);

      CompareRes := P.CompareTo(Q) >= 0;
      ModReduceRes := (not ModReduce(P.Multiply(P).Subtract(fourX))
        .ModPow(legendreExponent, Q).Equals(qMinusOne));

    until ((not CompareRes) and (not ModReduceRes));

    tempRes := LucasSequence(P, x, K);
    u := tempRes[0];
    v := tempRes[1];

    if (ModMult(v, v).Equals(fourX)) then
    begin
      result := TFpFieldElement.Create(Fq, Fr, ModHalfAbs(v));
      Exit;
    end;

  until ((not u.Equals(TBigInteger.One)) or (not u.Equals(qMinusOne)));
  result := Nil;
end;

function TFpFieldElement.Square: IECFieldElement;
begin
  result := TFpFieldElement.Create(Fq, Fr, ModMult(Fx, Fx));
end;

function TFpFieldElement.SquareMinusProduct(const x, y: IECFieldElement)
  : IECFieldElement;
var
  ax, xx, yx, aa, xy: TBigInteger;
begin
  ax := Fx;
  xx := x.ToBigInteger();
  yx := y.ToBigInteger();
  aa := ax.Multiply(ax);
  xy := xx.Multiply(yx);
  result := TFpFieldElement.Create(Fq, Fr, ModReduce(aa.Subtract(xy)));
end;

function TFpFieldElement.SquarePlusProduct(const x, y: IECFieldElement)
  : IECFieldElement;
var
  ax, xx, yx, aa, xy, sum: TBigInteger;
begin
  ax := Fx;
  xx := x.ToBigInteger();
  yx := y.ToBigInteger();
  aa := ax.Multiply(ax);
  xy := xx.Multiply(yx);
  sum := aa.Add(xy);
  if ((Fr.IsInitialized) and (Fr.SignValue < 0) and
    (sum.BitLength > (Fq.BitLength shl 1))) then
  begin
    sum := sum.Subtract(Fq.ShiftLeft(Fq.BitLength));
  end;
  result := TFpFieldElement.Create(Fq, Fr, ModReduce(sum));
end;

function TFpFieldElement.Subtract(const b: IECFieldElement): IECFieldElement;
begin
  result := TFpFieldElement.Create(Fq, Fr, ModSubtract(Fx, b.ToBigInteger()));
end;

function TFpFieldElement.ToBigInteger: TBigInteger;
begin
  result := Fx;
end;

{ TAbstract2mFieldElement }

function TAbstractF2mFieldElement.HalfTrace: IECFieldElement;
var
  m, i: Int32;
  fe, ht: IECFieldElement;
begin
  m := FieldSize;
  if ((m and 1) = 0) then
  begin
    raise EArgumentCryptoLibException.CreateRes(@SHalfTraceUndefinedForM);
  end;

  fe := Self as IECFieldElement;
  ht := fe;
  i := 2;
  while i < m do
  begin
    fe := fe.SquarePow(2);
    ht := ht.Add(fe);
    System.Inc(i, 2);
  end;

  result := ht;
end;

function TAbstractF2mFieldElement.Trace: Int32;
var
  m, i: Int32;
  fe, tr: IECFieldElement;
begin
  m := FieldSize;
  fe := Self as IECFieldElement;
  tr := fe;

  i := 1;
  while i < m do
  begin
    fe := fe.Square();
    tr := tr.Add(fe);
    System.Inc(i);
  end;

  if (tr.IsZero) then
  begin
    result := 0;
    Exit;
  end;
  if (tr.IsOne) then
  begin
    result := 1;
    Exit;
  end;
  raise EArgumentCryptoLibException.CreateRes(@STraceInternalErrorCalculation);
end;

end.
