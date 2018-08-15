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

unit ClpECCurve;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SyncObjs,
  SysUtils,
  Generics.Collections,
  ClpIPreCompCallback,
  ClpECPoint,
  ClpCryptoLibTypes,
  ClpBigInteger,
  ClpBits,
  ClpIGlvEndomorphism,
  ClpECAlgorithms,
  ClpIECFieldElement,
  ClpECFieldElement,
  ClpLongArray,
  ClpGlvMultiplier,
  ClpWNafL2RMultiplier,
  ClpWTauNafMultiplier,
  ClpFiniteFields,
  ClpTnaf,
  ClpIECInterface,
  ClpIFiniteField,
  ClpIPreCompInfo;

resourcestring
  SUnSupportedCoordinateSystem = 'UnSupported Coordinate System';
  SCurrentCurve = 'Implementation returned Current Curve';
  SInvalidPointCoordinates = 'Invalid Point Coordinates';
  SInvalidAffineCoordinates = 'not valid for affine coordinates, "iso"';
  SInvalidPointOnCurve = 'must be non-null and on this curve, "point"';
  SInvalidPointOnCurve2 = 'Entries must be null or on this curve, "points"';
  SPointsNil = 'points';
  SInvalidRangeSpecified = 'Invalid Range Specified", "points"';
  SInvalidPointCompression = 'Invalid Point Compression';
  SInvalidK1 = 'k1 must be > 0';
  SInvalidK3 = 'k3 must be 0 if k2 == 0';
  SK2K1MisMatch = 'k2 must be > k1';
  SK3K2Mismatch = 'k3 must be > k2';
  SInvalidInfinityEncoding = 'Invalid Infinity Encoding, "encoded"';
  SInvalidPointEncoding = 'Invalid Point Encoding %u';
  SIncorrectLengthInfinityEncoding =
    'Incorrect Length for infinity encoding", "encoded"';
  SIncorrectLengthCompressedEncoding =
    'Incorrect Length for Compressed Encoding", "encoded"';
  SInvalidPoint = 'Invalid Point';
  SIncorrectLengthUnCompressedEncoding =
    'Incorrect Length for UnCompressed Encoding", "encoded"';
  SIncorrectLengthHybridEncoding =
    'Incorrect Length for Hybrid Encoding", "encoded"';
  SInConsistentYCoord =
    'Inconsistent Y Coordinate in Hybrid Encoding", "encoded"';

type

  /// <summary>
  /// Base class for an elliptic curve.
  /// </summary>
  TECCurve = class abstract(TInterfacedObject, IECCurve)

  strict private

    procedure SetCoord(const Value: Int32); inline;
    procedure SetEndomorphism(const Value: IECEndomorphism); inline;
    procedure SetMultiplier(const Value: IECMultiplier); inline;
    function GetField: IFiniteField; virtual;
    function GetA: IECFieldElement; virtual;
    function GetB: IECFieldElement; virtual;
    function GetOrder: TBigInteger; virtual;
    function GetCofactor: TBigInteger; virtual;
    function GetCoordinateSystem: Int32; virtual;

    class constructor CreateECCurve();
    class destructor DestroyECCurve();

  strict protected

    class var

      FLock: TCriticalSection;

  var
    Fm_field: IFiniteField;
    Fm_order, Fm_cofactor: TBigInteger;

    Fm_coord: Int32;

    Fm_endomorphism: IECEndomorphism;
    Fm_multiplier: IECMultiplier;
    Fm_a, Fm_b: IECFieldElement;

    constructor Create(const field: IFiniteField);

    function GetFieldSize: Int32; virtual; abstract;
    function GetInfinity: IECPoint; virtual; abstract;

    function CloneCurve(): IECCurve; virtual; abstract;

    function CreateRawPoint(const x, y: IECFieldElement;
      withCompression: Boolean): IECPoint; overload; virtual; abstract;

    function CreateRawPoint(const x, y: IECFieldElement;
      const zs: TCryptoLibGenericArray<IECFieldElement>;
      withCompression: Boolean): IECPoint; overload; virtual; abstract;

    function CreateDefaultMultiplier(): IECMultiplier; virtual;

    procedure CheckPoint(const point: IECPoint); virtual;

    procedure CheckPoints(const points: TCryptoLibGenericArray<IECPoint>);
      overload; virtual;

    procedure CheckPoints(const points: TCryptoLibGenericArray<IECPoint>;
      off, len: Int32); overload; virtual;

    function DecompressPoint(yTilde: Int32; const X1: TBigInteger): IECPoint;
      virtual; abstract;

  public

    const

    COORD_AFFINE = Int32(0);
    COORD_HOMOGENEOUS = Int32(1);
    COORD_JACOBIAN = Int32(2);
    COORD_JACOBIAN_CHUDNOVSKY = Int32(3);
    COORD_JACOBIAN_MODIFIED = Int32(4);
    COORD_LAMBDA_AFFINE = Int32(5);
    COORD_LAMBDA_PROJECTIVE = Int32(6);
    COORD_SKEWED = Int32(7);

  type
    TConfig = class(TInterfacedObject, IConfig)

    strict protected
    var
      Fouter: IECCurve;
      Fcoord: Int32;
      Fendomorphism: IECEndomorphism;
      Fmultiplier: IECMultiplier;

    public
      constructor Create(const outer: IECCurve; coord: Int32;
        const endomorphism: IECEndomorphism;
        const multiplier: IECMultiplier); overload;

      destructor Destroy(); override;

      function SetCoordinateSystem(coord: Int32): IConfig; inline;
      function SetEndomorphism(const endomorphism: IECEndomorphism)
        : IConfig; inline;
      function SetMultiplier(const multiplier: IECMultiplier): IConfig; inline;
      function CreateCurve(): IECCurve;

    end;

  function FromBigInteger(const x: TBigInteger): IECFieldElement;
    virtual; abstract;
  function IsValidFieldElement(const x: TBigInteger): Boolean; virtual;
    abstract;

  function Configure(): IConfig; virtual;
  function ValidatePoint(const x, y: TBigInteger): IECPoint; overload; virtual;

  function ValidatePoint(const x, y: TBigInteger; withCompression: Boolean)
    : IECPoint; overload; virtual;
    deprecated 'Per-point compression property will be removed';

  /// <summary>
  /// Create a cache-safe lookup table for the specified sequence of points.
  /// All the points MUST <br />belong to this <c>ECCurve</c> instance, and
  /// MUST already be normalized.
  /// </summary>
  function CreateCacheSafeLookupTable(const points
    : TCryptoLibGenericArray<IECPoint>; off, len: Int32)
    : IECLookupTable; virtual;

  function CreatePoint(const x, y: TBigInteger): IECPoint; overload; virtual;

  function CreatePoint(const x, y: TBigInteger; withCompression: Boolean)
    : IECPoint; overload; virtual;
    deprecated 'Per-point compression property will be removed';

  function SupportsCoordinateSystem(coord: Int32): Boolean; virtual;

  function GetPreCompInfo(const point: IECPoint; const name: String)
    : IPreCompInfo; virtual;

  /// <summary>
  /// Compute a <c>PreCompInfo</c> for a point on this curve, under a given
  /// name. Used by <c>ECMultiplier</c> to save the precomputation for this <c>
  /// ECPoint</c> for use by subsequent multiplication.
  /// </summary>
  /// <param name="point">
  /// The <c>ECPoint</c> to store precomputations for.
  /// </param>
  /// <param name="name">
  /// A <c>String</c> used to index precomputations of different types.
  /// </param>
  /// <param name="callback">
  /// Called to calculate the <c>PreCompInfo</c>
  /// </param>
  function Precompute(const point: IECPoint; const name: String;
    const callback: IPreCompCallback): IPreCompInfo; virtual;

  function ImportPoint(const p: IECPoint): IECPoint; virtual;

  /// <summary>
  /// Normalization ensures that any projective coordinate is 1, and
  /// therefore that the x, y coordinates reflect those of the equivalent
  /// point in an affine coordinate system. Where more than one point is to
  /// be normalized, this method will generally be more efficient than
  /// normalizing each point separately.
  /// </summary>
  /// <param name="points">
  /// An array of points that will be updated in place with their normalized
  /// versions, where necessary
  /// </param>
  procedure NormalizeAll(const points: TCryptoLibGenericArray<IECPoint>);
    overload; virtual;

  /// <summary>
  /// Normalization ensures that any projective coordinate is 1, and
  /// therefore that the x, y coordinates reflect those of the equivalent
  /// point in an affine coordinate system. Where more than one point is to
  /// be normalized, this method will generally be more efficient than
  /// normalizing each point separately. An (optional) z-scaling factor can
  /// be applied; effectively each z coordinate is scaled by this value prior
  /// to normalization (but only one actual multiplication is needed).
  /// </summary>
  /// <param name="points">
  /// An array of points that will be updated in place with their normalized
  /// versions, where necessary
  /// </param>
  /// <param name="off">
  /// The start of the range of points to normalize
  /// </param>
  /// <param name="len">
  /// The length of the range of points to normalize
  /// </param>
  /// <param name="iso">
  /// The (optional) z-scaling factor - can be null
  /// </param>
  procedure NormalizeAll(const points: TCryptoLibGenericArray<IECPoint>;
    off, len: Int32; const iso: IECFieldElement); overload; virtual;

  function GetEndomorphism(): IECEndomorphism; virtual;

  /// <summary>
  /// Sets the default <c>ECMultiplier</c>, unless already set.
  /// </summary>
  function GetMultiplier(): IECMultiplier; virtual;

  /// <summary>
  /// Decode a point on this curve from its ASN.1 encoding. The different
  /// encodings are taken account of, including point compression for <br /><c>
  /// F</c><b>p</b> (X9.62 s 4.2.1 pg 17).
  /// </summary>
  /// <returns>
  /// The decoded point.
  /// </returns>
  function DecodePoint(const encoded: TCryptoLibByteArray): IECPoint; virtual;

  property coord: Int32 write SetCoord;
  property endomorphism: IECEndomorphism write SetEndomorphism;
  property multiplier: IECMultiplier write SetMultiplier;

  property FieldSize: Int32 read GetFieldSize;

  property Infinity: IECPoint read GetInfinity;

  property field: IFiniteField read GetField;

  property A: IECFieldElement read GetA;

  property B: IECFieldElement read GetB;

  property Order: TBigInteger read GetOrder;

  property Cofactor: TBigInteger read GetCofactor;

  property CoordinateSystem: Int32 read GetCoordinateSystem;

  function Equals(const other: IECCurve): Boolean; reintroduce;
  function GetHashCode(): {$IFDEF DELPHI}Int32; {$ELSE}PtrInt;
{$ENDIF DELPHI}override;

  destructor Destroy; override;

  class function GetAllCoordinateSystems(): TCryptoLibInt32Array;
    static; inline;

  end;

type
  TDefaultLookupTable = class(TInterfacedObject, IDefaultLookupTable,
    IECLookupTable)
  strict private
  var
    Fm_outer: IECCurve;
    Fm_table: TCryptoLibByteArray;
    Fm_size: Int32;

  public
    constructor Create(const outer: IECCurve; const table: TCryptoLibByteArray;
      size: Int32);
    function GetSize: Int32; virtual;
    function Lookup(index: Int32): IECPoint; virtual;
    property size: Int32 read GetSize;

  end;

type
  TAbstractFpCurve = class(TECCurve, IAbstractFpCurve)

  strict protected

    constructor Create(const q: TBigInteger);
    function DecompressPoint(yTilde: Int32; const X1: TBigInteger)
      : IECPoint; override;

  public
    destructor Destroy; override;
    function IsValidFieldElement(const x: TBigInteger): Boolean; override;

  end;

type
  TDefaultF2mLookupTable = class(TInterfacedObject, IDefaultF2mLookupTable,
    IECLookupTable)
  strict private
  var
    Fm_outer: IF2mCurve;
    Fm_table: TCryptoLibInt64Array;
    Fm_size: Int32;

  public
    constructor Create(const outer: IF2mCurve;
      const table: TCryptoLibInt64Array; size: Int32);
    function GetSize: Int32; virtual;
    function Lookup(index: Int32): IECPoint; virtual;
    property size: Int32 read GetSize;

  end;

type
  TFpCurve = class(TAbstractFpCurve, IFpCurve)

  strict private
  const
    FP_DEFAULT_COORDS = Int32(TECCurve.COORD_JACOBIAN_MODIFIED);

  strict protected
  var
    Fm_q, Fm_r: TBigInteger;

    Fm_infinity: IFpPoint;

    constructor Create(const q, r: TBigInteger; const A, B: IECFieldElement);
      overload; deprecated 'Use constructor taking order/cofactor';
    constructor Create(const q, r: TBigInteger; const A, B: IECFieldElement;
      const Order, Cofactor: TBigInteger); overload;

    function GetQ: TBigInteger; virtual;
    function GetInfinity: IECPoint; override;
    function GetFieldSize: Int32; override;

    function CloneCurve(): IECCurve; override;
    function CreateRawPoint(const x, y: IECFieldElement;
      withCompression: Boolean): IECPoint; overload; override;

    function CreateRawPoint(const x, y: IECFieldElement;
      const zs: TCryptoLibGenericArray<IECFieldElement>;
      withCompression: Boolean): IECPoint; overload; override;

  public
    constructor Create(const q, A, B: TBigInteger); overload;
      deprecated 'Use constructor taking order/cofactor';
    constructor Create(const q, A, B, Order, Cofactor: TBigInteger); overload;

    destructor Destroy; override;

    function FromBigInteger(const x: TBigInteger): IECFieldElement; override;
    function ImportPoint(const p: IECPoint): IECPoint; override;

    function SupportsCoordinateSystem(coord: Int32): Boolean; override;

    property q: TBigInteger read GetQ;
    property Infinity: IECPoint read GetInfinity;
    property FieldSize: Int32 read GetFieldSize;

  end;

type
  TAbstractF2mCurve = class abstract(TECCurve, IAbstractF2mCurve)

  strict private

    /// <summary>
    /// The auxiliary values <c>s</c><b>0</b> and <c>s</c><b>1</b> used for
    /// partial modular reduction for Koblitz curves.
    /// </summary>
    Fsi: TCryptoLibGenericArray<TBigInteger>;

    class function BuildField(m, k1, k2, k3: Int32): IFiniteField; static;

  strict protected
    constructor Create(m, k1, k2, k3: Int32);

    /// <summary>
    /// Returns true if this is a Koblitz curve (ABC curve).
    /// </summary>
    /// <returns>
    /// true if this is a Koblitz curve (ABC curve), false otherwise
    /// </returns>
    function GetIsKoblitz: Boolean; virtual;

    function DecompressPoint(yTilde: Int32; const X1: TBigInteger)
      : IECPoint; override;

    // /**
    // * Solves a quadratic equation <code>z<sup>2</sup> + z = beta</code>(X9.62
    // * D.1.6) The other solution is <code>z + 1</code>.
    // *
    // * @param beta
    // *            The value to solve the qradratic equation for.
    // * @return the solution for <code>z<sup>2</sup> + z = beta</code> or
    // *         <code>null</code> if no solution exists.
    // */
    function SolveQuadraticEquation(const beta: IECFieldElement)
      : IECFieldElement;

  public

    destructor Destroy; override;

    function IsValidFieldElement(const x: TBigInteger): Boolean; override;

    function CreatePoint(const x, y: TBigInteger; withCompression: Boolean)
      : IECPoint; override;
      deprecated 'Per-point compression property will be removed';

    // /**
    // * @return the auxiliary values <code>s<sub>0</sub></code> and
    // * <code>s<sub>1</sub></code> used for partial modular reduction for
    // * Koblitz curves.
    // */
    function GetSi(): TCryptoLibGenericArray<TBigInteger>; virtual;

    property IsKoblitz: Boolean read GetIsKoblitz;

    class function Inverse(m: Int32; const ks: TCryptoLibInt32Array;
      const x: TBigInteger): TBigInteger; static; inline;

  end;

type
  // /**
  // * Elliptic curves over F2m. The Weierstrass equation is given by
  // * <code>y<sup>2</sup> + xy = x<sup>3</sup> + ax<sup>2</sup> + b</code>.
  // */
  TF2mCurve = class sealed(TAbstractF2mCurve, IF2mCurve)

  strict private
  const
    F2M_DEFAULT_COORDS = Int32(TECCurve.COORD_LAMBDA_PROJECTIVE);

  var
    // /**
    // * The exponent <code>m</code> of <code>F<sub>2<sup>m</sup></sub></code>.
    // */
    Fm: Int32;

    // /**
    // * TPB: The integer <code>k</code> where <code>x<sup>m</sup> +
    // * x<sup>k</sup> + 1</code> represents the reduction polynomial
    // * <code>f(z)</code>.<br/>
    // * PPB: The integer <code>k1</code> where <code>x<sup>m</sup> +
    // * x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code>
    // * represents the reduction polynomial <code>f(z)</code>.<br/>
    // */
    Fk1: Int32;

    // /**
    // * TPB: Always set to <code>0</code><br/>
    // * PPB: The integer <code>k2</code> where <code>x<sup>m</sup> +
    // * x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code>
    // * represents the reduction polynomial <code>f(z)</code>.<br/>
    // */
    Fk2: Int32;
    //
    // /**
    // * TPB: Always set to <code>0</code><br/>
    // * PPB: The integer <code>k3</code> where <code>x<sup>m</sup> +
    // * x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code>
    // * represents the reduction polynomial <code>f(z)</code>.<br/>
    // */
    Fk3: Int32;

    /// <summary>
    /// The point at infinity on this curve.
    /// </summary>
    Fm_infinity: IF2mPoint;

    constructor Create(m, k1, k2, k3: Int32; const A, B: IECFieldElement;
      const Order, Cofactor: TBigInteger); overload;

    function GetM: Int32; inline;
    function GetK1: Int32; inline;
    function GetK2: Int32; inline;
    function GetK3: Int32; inline;

  strict protected
    function GetFieldSize: Int32; override;
    function GetInfinity: IECPoint; override;

    function CloneCurve(): IECCurve; override;
    function CreateDefaultMultiplier(): IECMultiplier; override;

    function CreateRawPoint(const x, y: IECFieldElement;
      withCompression: Boolean): IECPoint; overload; override;

    function CreateRawPoint(const x, y: IECFieldElement;
      const zs: TCryptoLibGenericArray<IECFieldElement>;
      withCompression: Boolean): IECPoint; overload; override;

  public
    // /**
    // * Constructor for Trinomial Polynomial Basis (TPB).
    // * @param m  The exponent <code>m</code> of
    // * <code>F<sub>2<sup>m</sup></sub></code>.
    // * @param k The integer <code>k</code> where <code>x<sup>m</sup> +
    // * x<sup>k</sup> + 1</code> represents the reduction
    // * polynomial <code>f(z)</code>.
    // * @param a The coefficient <code>a</code> in the Weierstrass equation
    // * for non-supersingular elliptic curves over
    // * <code>F<sub>2<sup>m</sup></sub></code>.
    // * @param b The coefficient <code>b</code> in the Weierstrass equation
    // * for non-supersingular elliptic curves over
    // * <code>F<sub>2<sup>m</sup></sub></code>.
    // */
    constructor Create(m, k: Int32; const A, B: TBigInteger); overload;
      deprecated 'Use constructor taking order/cofactor';
    // /**
    // * Constructor for Trinomial Polynomial Basis (TPB).
    // * @param m  The exponent <code>m</code> of
    // * <code>F<sub>2<sup>m</sup></sub></code>.
    // * @param k The integer <code>k</code> where <code>x<sup>m</sup> +
    // * x<sup>k</sup> + 1</code> represents the reduction
    // * polynomial <code>f(z)</code>.
    // * @param a The coefficient <code>a</code> in the Weierstrass equation
    // * for non-supersingular elliptic curves over
    // * <code>F<sub>2<sup>m</sup></sub></code>.
    // * @param b The coefficient <code>b</code> in the Weierstrass equation
    // * for non-supersingular elliptic curves over
    // * <code>F<sub>2<sup>m</sup></sub></code>.
    // * @param order The order of the main subgroup of the elliptic curve.
    // * @param cofactor The cofactor of the elliptic curve, i.e.
    // * <code>#E<sub>a</sub>(F<sub>2<sup>m</sup></sub>) = h * n</code>.
    // */
    constructor Create(m, k: Int32;
      const A, B, Order, Cofactor: TBigInteger); overload;

    // /**
    // * Constructor for Pentanomial Polynomial Basis (PPB).
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
    // * @param a The coefficient <code>a</code> in the Weierstrass equation
    // * for non-supersingular elliptic curves over
    // * <code>F<sub>2<sup>m</sup></sub></code>.
    // * @param b The coefficient <code>b</code> in the Weierstrass equation
    // * for non-supersingular elliptic curves over
    // * <code>F<sub>2<sup>m</sup></sub></code>.
    // */

    constructor Create(m, k1, k2, k3: Int32; const A, B: TBigInteger); overload;
      deprecated 'Use constructor taking order/cofactor';
    // /**
    // * Constructor for Pentanomial Polynomial Basis (PPB).
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
    // * @param a The coefficient <code>a</code> in the Weierstrass equation
    // * for non-supersingular elliptic curves over
    // * <code>F<sub>2<sup>m</sup></sub></code>.
    // * @param b The coefficient <code>b</code> in the Weierstrass equation
    // * for non-supersingular elliptic curves over
    // * <code>F<sub>2<sup>m</sup></sub></code>.
    // * @param order The order of the main subgroup of the elliptic curve.
    // * @param cofactor The cofactor of the elliptic curve, i.e.
    // * <code>#E<sub>a</sub>(F<sub>2<sup>m</sup></sub>) = h * n</code>.
    // */
    constructor Create(m, k1, k2, k3: Int32;
      const A, B, Order, Cofactor: TBigInteger); overload;

    destructor Destroy; override;

    function SupportsCoordinateSystem(coord: Int32): Boolean; override;
    function FromBigInteger(const x: TBigInteger): IECFieldElement; override;

    /// <summary>
    /// Return true if curve uses a Trinomial basis.
    /// </summary>
    /// <returns>
    /// return true if curve Trinomial, false otherwise.
    /// </returns>
    function IsTrinomial(): Boolean; inline;

    function CreateCacheSafeLookupTable(const points
      : TCryptoLibGenericArray<IECPoint>; off, len: Int32)
      : IECLookupTable; override;

    property FieldSize: Int32 read GetFieldSize;
    property Infinity: IECPoint read GetInfinity;
    property m: Int32 read GetM;
    property k1: Int32 read GetK1;
    property k2: Int32 read GetK2;
    property k3: Int32 read GetK3;

  end;

implementation

{ TECCurve }

procedure TECCurve.CheckPoint(const point: IECPoint);
begin
  if ((point = Nil) or ((Self as IECCurve) <> point.Curve)) then
  begin
    raise EArgumentCryptoLibException.CreateRes(@SInvalidPointOnCurve);
  end;
end;

procedure TECCurve.CheckPoints(const points: TCryptoLibGenericArray<IECPoint>);
begin
  CheckPoints(points, 0, System.Length(points));
end;

procedure TECCurve.CheckPoints(const points: TCryptoLibGenericArray<IECPoint>;
  off, len: Int32);
var
  i: Int32;
  point: IECPoint;
begin
  if (points = Nil) then
  begin
    raise EArgumentNilCryptoLibException.CreateRes(@SPointsNil);
  end;
  if ((off < 0) or (len < 0) or (off > (System.Length(points) - len))) then
  begin
    raise EArgumentCryptoLibException.CreateRes(@SInvalidRangeSpecified);
  end;

  for i := 0 to System.Pred(len) do

  begin
    point := points[off + i];
    if ((point <> Nil) and ((Self as IECCurve) <> point.Curve)) then
    begin
      raise EArgumentCryptoLibException.CreateRes(@SInvalidPointOnCurve2);
    end;
  end;
end;

function TECCurve.Configure: IConfig;
begin
  Result := TConfig.Create(Self as IECCurve, Self.Fm_coord,
    Self.Fm_endomorphism, Self.Fm_multiplier);
end;

constructor TECCurve.Create(const field: IFiniteField);
begin
  inherited Create();
  Fm_field := field;
end;

function TECCurve.CreateCacheSafeLookupTable(const points
  : TCryptoLibGenericArray<IECPoint>; off, len: Int32): IECLookupTable;
var
  FE_BYTES, position, i, pxStart, pyStart, pxLen, pyLen: Int32;
  table, px, py: TCryptoLibByteArray;
  p: IECPoint;
begin
  FE_BYTES := (FieldSize + 7) div 8;
  System.SetLength(table, len * FE_BYTES * 2);
  position := 0;

  for i := 0 to System.Pred(len) do
  begin
    p := points[off + i];
    px := p.RawXCoord.ToBigInteger().ToByteArray();
    py := p.RawYCoord.ToBigInteger().ToByteArray();

    if System.Length(px) > FE_BYTES then
    begin
      pxStart := 1
    end
    else
    begin
      pxStart := 0
    end;

    pxLen := System.Length(px) - pxStart;

    if System.Length(py) > FE_BYTES then
    begin
      pyStart := 1
    end
    else
    begin
      pyStart := 0
    end;

    pyLen := System.Length(py) - pyStart;

    System.Move(px[pxStart], table[position + FE_BYTES - pxLen],
      pxLen * System.SizeOf(Byte));
    position := position + FE_BYTES;

    System.Move(py[pyStart], table[position + FE_BYTES - pyLen],
      pyLen * System.SizeOf(Byte));
    position := position + FE_BYTES;
  end;
  Result := TDefaultLookupTable.Create(Self as IECCurve, table, len);
end;

function TECCurve.CreateDefaultMultiplier: IECMultiplier;
var
  glvEndomorphism: IGlvEndomorphism;
begin
  if (Supports(Fm_endomorphism, IGlvEndomorphism, glvEndomorphism)) then
  begin
    Result := TGlvMultiplier.Create(Self as IECCurve, glvEndomorphism);
    Exit;
  end;

  Result := TWNafL2RMultiplier.Create();
end;

class constructor TECCurve.CreateECCurve;
begin
  FLock := TCriticalSection.Create;
end;

function TECCurve.CreatePoint(const x, y: TBigInteger): IECPoint;
begin
  Result := CreatePoint(x, y, false);
end;

function TECCurve.CreatePoint(const x, y: TBigInteger; withCompression: Boolean)
  : IECPoint;
begin
  Result := CreateRawPoint(FromBigInteger(x), FromBigInteger(y),
    withCompression);
end;

function TECCurve.DecodePoint(const encoded: TCryptoLibByteArray): IECPoint;
var
  x, y: TBigInteger;
  p: IECPoint;
  expectedLength, yTilde: Int32;
  ltype: Byte;
begin
  p := Nil;
  expectedLength := (FieldSize + 7) div 8;

  ltype := encoded[0];
  case ltype of
    $00: // infinity
      begin
        if (System.Length(encoded) <> 1) then
        begin
          raise EArgumentCryptoLibException.CreateRes
            (@SIncorrectLengthInfinityEncoding);
        end;

        p := Infinity;
      end;

    $02, // compressed
    $03: // compressed
      begin
        if (System.Length(encoded) <> (expectedLength + 1)) then
        begin
          raise EArgumentCryptoLibException.CreateRes
            (@SIncorrectLengthCompressedEncoding);
        end;

        yTilde := ltype and 1;
        x := TBigInteger.Create(1, encoded, 1, expectedLength);

        p := DecompressPoint(yTilde, x);
        // TODO Skip curve equation check?
        if ((not p.ImplIsValid(true, true))) then
        begin
          raise EArgumentCryptoLibException.CreateRes(@SInvalidPoint);
        end;
      end;

    $04: // uncompressed
      begin
        if (System.Length(encoded) <> ((2 * expectedLength) + 1)) then
        begin
          raise EArgumentCryptoLibException.CreateRes
            (@SIncorrectLengthUnCompressedEncoding);
        end;

        x := TBigInteger.Create(1, encoded, 1, expectedLength);
        y := TBigInteger.Create(1, encoded, 1 + expectedLength, expectedLength);

        p := ValidatePoint(x, y);
      end;

    $06, // hybrid
    $07: // hybrid
      begin
        if (System.Length(encoded) <> ((2 * expectedLength) + 1)) then
        begin
          raise EArgumentCryptoLibException.CreateRes
            (@SIncorrectLengthHybridEncoding);
        end;

        x := TBigInteger.Create(1, encoded, 1, expectedLength);
        y := TBigInteger.Create(1, encoded, 1 + expectedLength, expectedLength);

        if ((y.TestBit(0)) <> (ltype = $07)) then
        begin
          raise EArgumentCryptoLibException.CreateRes(@SInConsistentYCoord);
        end;

        p := ValidatePoint(x, y);
      end

  else
    begin
      raise EFormatCryptoLibException.CreateResFmt
        (@SInvalidPointEncoding, [ltype]);
    end;

  end;

  if ((ltype <> $00) and (p.IsInfinity)) then
  begin
    raise EArgumentCryptoLibException.CreateRes(@SInvalidInfinityEncoding);
  end;

  Result := p;
end;

destructor TECCurve.Destroy;
begin
  inherited Destroy;
end;

class destructor TECCurve.DestroyECCurve;
begin
  FLock.Free;
end;

function TECCurve.Equals(const other: IECCurve): Boolean;
begin
  if ((Self as IECCurve) = other) then
  begin
    Result := true;
    Exit;
  end;
  if (other = Nil) then
  begin
    Result := false;
    Exit;
  end;
  Result := (field as TObject).Equals(other.field as TObject) and
    (A.ToBigInteger().Equals(other.A.ToBigInteger())) and
    (B.ToBigInteger().Equals(other.B.ToBigInteger()));
end;

function TECCurve.GetA: IECFieldElement;
begin
  Result := Fm_a;
end;

class function TECCurve.GetAllCoordinateSystems: TCryptoLibInt32Array;
begin
  Result := TCryptoLibInt32Array.Create(COORD_AFFINE, COORD_HOMOGENEOUS,
    COORD_JACOBIAN, COORD_JACOBIAN_CHUDNOVSKY, COORD_JACOBIAN_MODIFIED,
    COORD_LAMBDA_AFFINE, COORD_LAMBDA_PROJECTIVE, COORD_SKEWED);
end;

function TECCurve.GetB: IECFieldElement;
begin
  Result := Fm_b;
end;

function TECCurve.GetCofactor: TBigInteger;
begin
  Result := Fm_cofactor;
end;

function TECCurve.GetCoordinateSystem: Int32;
begin
  Result := Fm_coord;
end;

function TECCurve.GetEndomorphism: IECEndomorphism;
begin
  Result := Fm_endomorphism;
end;

function TECCurve.GetField: IFiniteField;
begin
  Result := Fm_field;
end;

function TECCurve.GetHashCode: {$IFDEF DELPHI}Int32; {$ELSE}PtrInt;
{$ENDIF DELPHI}
begin
  Result := (field as TObject).GetHashCode()
    xor Int32(TBits.RotateLeft32(A.ToBigInteger().GetHashCode(), 8))
    xor Int32(TBits.RotateLeft32(B.ToBigInteger().GetHashCode(), 16));
end;

function TECCurve.GetMultiplier: IECMultiplier;
begin
  FLock.Acquire;
  try
    if (Fm_multiplier = Nil) then
    begin
      Fm_multiplier := CreateDefaultMultiplier();
    end;
    Result := Fm_multiplier;
  finally
    FLock.Release;
  end;

end;

function TECCurve.GetOrder: TBigInteger;
begin
  Result := Fm_order;
end;

function TECCurve.GetPreCompInfo(const point: IECPoint; const name: String)
  : IPreCompInfo;
var
  table: TDictionary<String, IPreCompInfo>;
begin
  CheckPoint(point);
  FLock.Acquire;
  try
    table := point.preCompTable;
    if table = Nil then
    begin
      Result := Nil;
    end
    else
    begin
      table.TryGetValue(name, Result);
    end;
  finally
    FLock.Release;
  end;
end;

function TECCurve.ImportPoint(const p: IECPoint): IECPoint;
var
  Lp: IECPoint;
begin
  if ((Self as IECCurve) = p.Curve) then
  begin
    Result := p;
    Exit;
  end;
  if (p.IsInfinity) then
  begin
    Result := Infinity;
    Exit;
  end;

  // TODO Default behaviour could be improved if the two curves have the same coordinate system by copying any Z coordinates.
  Lp := p.Normalize();

  Result := CreatePoint(Lp.XCoord.ToBigInteger(), Lp.YCoord.ToBigInteger(),
    Lp.IsCompressed);
end;

procedure TECCurve.NormalizeAll(const points: TCryptoLibGenericArray<IECPoint>;
  off, len: Int32; const iso: IECFieldElement);
var
  zs: TCryptoLibGenericArray<IECFieldElement>;
  indices: TCryptoLibInt32Array;
  count, i, j, index: Int32;
  p: IECPoint;
begin
  CheckPoints(points, off, len);
  case CoordinateSystem of
    COORD_AFFINE, COORD_LAMBDA_AFFINE:
      begin
        if (iso <> Nil) then
        begin
          raise EArgumentCryptoLibException.CreateRes
            (@SInvalidAffineCoordinates);
        end;

        Exit;
      end;
  end;

  // /*
  // * Figure out which of the points actually need to be normalized
  // */
  System.SetLength(zs, len);
  System.SetLength(indices, len);

  count := 0;
  for i := 0 to System.Pred(len) do

  begin
    p := points[off + i];
    if ((p <> Nil) and ((iso <> Nil) or (not(p.IsNormalized())))) then
    begin
      zs[count] := p.GetZCoord(0);
      indices[count] := off + i;
      System.Inc(count);
    end;
  end;

  if (count = 0) then
  begin
    Exit;
  end;

  TECAlgorithms.MontgomeryTrick(zs, 0, count, iso);

  for j := 0 to System.Pred(count) do

  begin
    index := indices[j];
    points[index] := points[index].Normalize(zs[j]);
  end;

end;

procedure TECCurve.NormalizeAll(const points: TCryptoLibGenericArray<IECPoint>);
begin
  NormalizeAll(points, 0, System.Length(points), Nil);
end;

procedure TECCurve.SetCoord(const Value: Int32);
begin
  Fm_coord := Value;
end;

procedure TECCurve.SetEndomorphism(const Value: IECEndomorphism);
begin
  Fm_endomorphism := Value;
end;

procedure TECCurve.SetMultiplier(const Value: IECMultiplier);
begin
  Fm_multiplier := Value;
end;

function TECCurve.Precompute(const point: IECPoint; const name: String;
  const callback: IPreCompCallback): IPreCompInfo;
var
  table: TDictionary<String, IPreCompInfo>;
  existing: IPreCompInfo;
begin
  CheckPoint(point);
  FLock.Acquire;
  try
    table := point.preCompTable;
    if table = Nil then
    begin
      table := TDictionary<String, IPreCompInfo>.Create(4);
      point.preCompTable := table;
    end;

    table.TryGetValue(name, existing);

    Result := callback.Precompute(existing);

    if (Result <> existing) then
    begin
      table.AddOrSetValue(name, Result);
    end;

  finally
    FLock.Release;
  end;
end;

function TECCurve.SupportsCoordinateSystem(coord: Int32): Boolean;
begin
  Result := coord = COORD_AFFINE;
end;

function TECCurve.ValidatePoint(const x, y: TBigInteger;
  withCompression: Boolean): IECPoint;
var
  p: IECPoint;
begin
  p := CreatePoint(x, y, withCompression);
  if (not p.IsValid()) then
  begin
    raise EArgumentCryptoLibException.CreateRes(@SInvalidPointCoordinates);
  end;
  Result := p;
end;

function TECCurve.ValidatePoint(const x, y: TBigInteger): IECPoint;
var
  p: IECPoint;
begin
  p := CreatePoint(x, y);
  if (not p.IsValid()) then
  begin
    raise EArgumentCryptoLibException.CreateRes(@SInvalidPointCoordinates);
  end;
  Result := p;
end;

{ TECCurve.TConfig }

constructor TECCurve.TConfig.Create(const outer: IECCurve; coord: Int32;
  const endomorphism: IECEndomorphism; const multiplier: IECMultiplier);
begin
  Inherited Create();
  Fouter := outer;
  Fcoord := coord;
  Fendomorphism := endomorphism;
  Fmultiplier := multiplier;
end;

function TECCurve.TConfig.CreateCurve: IECCurve;
var
  c: IECCurve;
begin
  if (not Fouter.SupportsCoordinateSystem(Fcoord)) then
  begin
    raise EInvalidOperationCryptoLibException.CreateRes
      (@SUnSupportedCoordinateSystem);
  end;

  c := Fouter.CloneCurve();
  if (c = Fouter) then
  begin
    raise EInvalidOperationCryptoLibException.CreateRes(@SCurrentCurve);
  end;

  c.coord := Fcoord;
  c.endomorphism := Fendomorphism;
  c.multiplier := Fmultiplier;

  Result := c;
end;

destructor TECCurve.TConfig.Destroy;
begin
  inherited Destroy;
end;

function TECCurve.TConfig.SetCoordinateSystem(coord: Int32): IConfig;
begin
  Fcoord := coord;
  Result := Self as IConfig;
end;

function TECCurve.TConfig.SetEndomorphism(const endomorphism
  : IECEndomorphism): IConfig;
begin
  Fendomorphism := endomorphism;
  Result := Self as IConfig;
end;

function TECCurve.TConfig.SetMultiplier(const multiplier
  : IECMultiplier): IConfig;
begin
  Fmultiplier := multiplier;
  Result := Self as IConfig;
end;

{ TAbstractFpCurve }

constructor TAbstractFpCurve.Create(const q: TBigInteger);
begin
  Inherited Create(TFiniteFields.GetPrimeField(q));
end;

function TAbstractFpCurve.DecompressPoint(yTilde: Int32; const X1: TBigInteger)
  : IECPoint;
var
  x, rhs, y: IECFieldElement;
begin
  x := FromBigInteger(X1);
  rhs := x.Square().Add(A).Multiply(x).Add(B);
  y := rhs.Sqrt();

  // /*
  // * If y is not a square, then we haven't got a point on the curve
  // */
  if (y = Nil) then
  begin
    raise EArgumentCryptoLibException.CreateRes(@SInvalidPointCompression);
  end;

  if (y.TestBitZero() <> (yTilde = 1)) then
  begin
    // Use the other root
    y := y.Negate();
  end;

  Result := CreateRawPoint(x, y, true);
end;

destructor TAbstractFpCurve.Destroy;
begin
  inherited Destroy;
end;

function TAbstractFpCurve.IsValidFieldElement(const x: TBigInteger): Boolean;
begin
  Result := (x.IsInitialized) and (x.SignValue >= 0) and
    (x.CompareTo(field.Characteristic) < 0);
end;

{ TFpCurve }

function TFpCurve.CloneCurve: IECCurve;
begin
  Result := TFpCurve.Create(Fm_q, Fm_r, Fm_a, Fm_b, Fm_order, Fm_cofactor);
end;

constructor TFpCurve.Create(const q, r: TBigInteger;
  const A, B: IECFieldElement; const Order, Cofactor: TBigInteger);
begin
  Inherited Create(q);
  Fm_q := q;
  Fm_r := r;
  Fm_infinity := TFpPoint.Create(Self as IECCurve, Nil, Nil, false);

  Fm_a := A;
  Fm_b := B;
  Fm_order := Order;
  Fm_cofactor := Cofactor;
  Fm_coord := FP_DEFAULT_COORDS;
end;

constructor TFpCurve.Create(const q, r: TBigInteger;
  const A, B: IECFieldElement);
begin
  Create(q, r, A, B, Default (TBigInteger), Default (TBigInteger));
end;

constructor TFpCurve.Create(const q, A, B, Order, Cofactor: TBigInteger);
begin
  Inherited Create(q);
  Fm_q := q;
  Fm_r := TFpFieldElement.CalculateResidue(q);
  Fm_infinity := TFpPoint.Create(Self as IECCurve, Nil, Nil, false);

  Fm_a := FromBigInteger(A);
  Fm_b := FromBigInteger(B);
  Fm_order := Order;
  Fm_cofactor := Cofactor;
  Fm_coord := FP_DEFAULT_COORDS;
end;

constructor TFpCurve.Create(const q, A, B: TBigInteger);
begin
  Create(q, A, B, Default (TBigInteger), Default (TBigInteger));
end;

function TFpCurve.CreateRawPoint(const x, y: IECFieldElement;
  const zs: TCryptoLibGenericArray<IECFieldElement>; withCompression: Boolean)
  : IECPoint;
begin
  Result := TFpPoint.Create(Self as IECCurve, x, y, zs, withCompression);
end;

destructor TFpCurve.Destroy;
begin
  inherited Destroy;
end;

function TFpCurve.CreateRawPoint(const x, y: IECFieldElement;
  withCompression: Boolean): IECPoint;
begin
  Result := TFpPoint.Create(Self as IECCurve, x, y, withCompression);
end;

function TFpCurve.FromBigInteger(const x: TBigInteger): IECFieldElement;
begin
  Result := TFpFieldElement.Create(Fm_q, Fm_r, x);
end;

function TFpCurve.GetFieldSize: Int32;
begin
  Result := Fm_q.BitLength;
end;

function TFpCurve.GetInfinity: IECPoint;
begin
  Result := Fm_infinity;
end;

function TFpCurve.GetQ: TBigInteger;
begin
  Result := Fm_q;
end;

function TFpCurve.ImportPoint(const p: IECPoint): IECPoint;
begin
  if ((Self as IECCurve <> p.Curve) and (CoordinateSystem = COORD_JACOBIAN) and
    (not p.IsInfinity)) then
  begin
    case p.Curve.CoordinateSystem of
      COORD_JACOBIAN, COORD_JACOBIAN_CHUDNOVSKY, COORD_JACOBIAN_MODIFIED:
        begin
          Result := TFpPoint.Create(Self as IECCurve,
            FromBigInteger(p.RawXCoord.ToBigInteger()),
            FromBigInteger(p.RawYCoord.ToBigInteger()),
            TCryptoLibGenericArray<IECFieldElement>.Create
            (FromBigInteger(p.GetZCoord(0).ToBigInteger())), p.IsCompressed);
          Exit;
        end;
    end;
  end;

  Result := (Inherited ImportPoint(p));
end;

function TFpCurve.SupportsCoordinateSystem(coord: Int32): Boolean;
begin
  case coord of
    COORD_AFFINE, COORD_HOMOGENEOUS, COORD_JACOBIAN, COORD_JACOBIAN_MODIFIED:
      begin
        Result := true;
      end
  else
    begin
      Result := false;
    end;
  end;
end;

{ TAbstractF2mCurve }

class function TAbstractF2mCurve.BuildField(m, k1, k2, k3: Int32): IFiniteField;
begin
  if (k1 = 0) then
  begin
    raise EArgumentCryptoLibException.CreateRes(@SInvalidK1);
  end;

  if (k2 = 0) then
  begin
    if (k3 <> 0) then
    begin
      raise EArgumentCryptoLibException.CreateRes(@SInvalidK3);
    end;

    Result := TFiniteFields.GetBinaryExtensionField
      (TCryptoLibInt32Array.Create(0, k1, m));
    Exit;
  end;

  if (k2 <= k1) then
  begin
    raise EArgumentCryptoLibException.CreateRes(@SK2K1MisMatch);
  end;

  if (k3 <= k2) then
  begin
    raise EArgumentCryptoLibException.CreateRes(@SK3K2Mismatch);
  end;

  Result := TFiniteFields.GetBinaryExtensionField(TCryptoLibInt32Array.Create(0,
    k1, k2, k3, m));
end;

constructor TAbstractF2mCurve.Create(m, k1, k2, k3: Int32);
begin
  Inherited Create(BuildField(m, k1, k2, k3));
end;

function TAbstractF2mCurve.CreatePoint(const x, y: TBigInteger;
  withCompression: Boolean): IECPoint;
var
  LX, LY: IECFieldElement;
begin
  LX := FromBigInteger(x);
  LY := FromBigInteger(y);

  case CoordinateSystem of
    COORD_LAMBDA_AFFINE, COORD_LAMBDA_PROJECTIVE:
      begin
        if (LX.IsZero) then
        begin
          if (not LY.Square().Equals(B)) then
          begin
            raise EArgumentCryptoLibException.Create('');
          end;
        end
        else
        begin
          // Y becomes Lambda (X + Y/X) here
          LY := LY.Divide(LX).Add(LX);
        end;
      end;
  end;

  Result := CreateRawPoint(LX, LY, withCompression);
end;

function TAbstractF2mCurve.DecompressPoint(yTilde: Int32; const X1: TBigInteger)
  : IECPoint;
var
  xp, yp, beta, z: IECFieldElement;
begin
  xp := FromBigInteger(X1);
  yp := Nil;
  if (xp.IsZero) then
  begin
    yp := B.Sqrt();
  end
  else
  begin
    beta := xp.Square().Invert().Multiply(B).Add(A).Add(xp);
    z := SolveQuadraticEquation(beta);

    if (z <> Nil) then
    begin
      if (z.TestBitZero() <> (yTilde = 1)) then
      begin
        z := z.AddOne();
      end;

      case CoordinateSystem of
        COORD_LAMBDA_AFFINE, COORD_LAMBDA_PROJECTIVE:
          begin
            yp := z.Add(xp);
          end
      else
        begin
          yp := z.Multiply(xp);
        end;
      end;

    end;

  end;

  if (yp = Nil) then
  begin
    raise EArgumentCryptoLibException.CreateRes(@SInvalidPointCompression);
  end;

  Result := CreateRawPoint(xp, yp, true);
end;

destructor TAbstractF2mCurve.Destroy;
begin
  inherited Destroy;
end;

function TAbstractF2mCurve.GetIsKoblitz: Boolean;
begin
  Result := (Fm_order.IsInitialized) and (Fm_cofactor.IsInitialized) and
    (Fm_b.IsOne) and (Fm_a.IsZero or Fm_a.IsOne);
end;

function TAbstractF2mCurve.GetSi: TCryptoLibGenericArray<TBigInteger>;
begin
  if (Fsi = Nil) then
  begin
    FLock.Acquire;
    try
      if (Fsi = Nil) then
      begin
        Fsi := TTnaf.GetSi(Self as IAbstractF2mCurve);
      end;
    finally
      FLock.Release;
    end;
  end;
  Result := Fsi;
end;

class function TAbstractF2mCurve.Inverse(m: Int32;
  const ks: TCryptoLibInt32Array; const x: TBigInteger): TBigInteger;
begin
  Result := TLongArray.Create(x).ModInverse(m, ks).ToBigInteger();
end;

function TAbstractF2mCurve.IsValidFieldElement(const x: TBigInteger): Boolean;
begin
  Result := (x.IsInitialized) and (x.SignValue >= 0) and
    (x.BitLength <= FieldSize);
end;

function TAbstractF2mCurve.SolveQuadraticEquation(const beta: IECFieldElement)
  : IECFieldElement;
var
  gamma, z, zeroElement, t, w, w2: IECFieldElement;
  m, i: Int32;
begin
  if (beta.IsZero) then
  begin
    Result := beta;
    Exit;
  end;

  zeroElement := FromBigInteger(TBigInteger.Zero);

  m := FieldSize;

  repeat
    t := FromBigInteger(TBigInteger.Arbitrary(m));
    z := zeroElement;
    w := beta;
    i := 1;
    while i < m do
    begin
      w2 := w.Square();
      z := z.Square().Add(w2.Multiply(t));
      w := w2.Add(beta);
      System.Inc(i);
    end;

    if (not w.IsZero) then
    begin
      Result := Nil;
      Exit;
    end;
    gamma := z.Square().Add(z);
  until (not(gamma.IsZero));

  Result := z;
end;

{ TF2mCurve }

function TF2mCurve.GetFieldSize: Int32;
begin
  Result := Fm;
end;

function TF2mCurve.GetInfinity: IECPoint;
begin
  Result := Fm_infinity;
end;

function TF2mCurve.GetK1: Int32;
begin
  Result := Fk1;
end;

function TF2mCurve.GetK2: Int32;
begin
  Result := Fk2;
end;

function TF2mCurve.GetK3: Int32;
begin
  Result := Fk3;
end;

function TF2mCurve.GetM: Int32;
begin
  Result := Fm;
end;

function TF2mCurve.IsTrinomial: Boolean;
begin
  Result := (k2 = 0) and (k3 = 0);
end;

function TF2mCurve.CloneCurve: IECCurve;
begin
  Result := TF2mCurve.Create(m, k1, k2, k3, Fm_a, Fm_b, Fm_order, Fm_cofactor);
end;

constructor TF2mCurve.Create(m, k: Int32; const A, B: TBigInteger);
begin
  Create(m, k, 0, 0, A, B, Default (TBigInteger), Default (TBigInteger));
end;

constructor TF2mCurve.Create(m, k1, k2, k3: Int32; const A, B: IECFieldElement;
  const Order, Cofactor: TBigInteger);
begin
  Inherited Create(m, k1, k2, k3);
  Fm := m;
  Fk1 := k1;
  Fk2 := k2;
  Fk3 := k3;
  Fm_order := Order;
  Fm_cofactor := Cofactor;

  Fm_infinity := TF2mPoint.Create(Self as IECCurve, Nil, Nil, false);
  Fm_a := A;
  Fm_b := B;
  Fm_coord := F2M_DEFAULT_COORDS;
end;

constructor TF2mCurve.Create(m, k: Int32;
  const A, B, Order, Cofactor: TBigInteger);
begin
  Create(m, k, 0, 0, A, B, Order, Cofactor);
end;

constructor TF2mCurve.Create(m, k1, k2, k3: Int32;
  const A, B, Order, Cofactor: TBigInteger);
begin
  Inherited Create(m, k1, k2, k3);
  Fm := m;
  Fk1 := k1;
  Fk2 := k2;
  Fk3 := k3;
  Fm_order := Order;
  Fm_cofactor := Cofactor;
  Fm_infinity := TF2mPoint.Create(Self as IECCurve, Nil, Nil, false);

  if (k1 = 0) then
  begin
    raise EArgumentCryptoLibException.CreateRes(@SInvalidK1);
  end;

  if (k2 = 0) then
  begin
    if (k3 <> 0) then
    begin
      raise EArgumentCryptoLibException.CreateRes(@SInvalidK3);
    end;
  end
  else
  begin
    if (k2 <= k1) then
    begin
      raise EArgumentCryptoLibException.CreateRes(@SK2K1MisMatch);
    end;

    if (k3 <= k2) then
    begin
      raise EArgumentCryptoLibException.CreateRes(@SK3K2Mismatch);
    end;
  end;

  Fm_a := FromBigInteger(A);
  Fm_b := FromBigInteger(B);
  Fm_coord := F2M_DEFAULT_COORDS;

end;

function TF2mCurve.CreateCacheSafeLookupTable(const points
  : TCryptoLibGenericArray<IECPoint>; off, len: Int32): IECLookupTable;
var
  FE_LONGS, position, i: Int32;
  table: TCryptoLibInt64Array;
  p: IECPoint;
begin
  FE_LONGS := (m + 63) div 64;
  System.SetLength(table, len * FE_LONGS * 2);

  position := 0;

  for i := 0 to System.Pred(len) do
  begin
    p := points[off + i];
    (p.RawXCoord as IF2mFieldElement).x.CopyTo(table, position);
    position := position + FE_LONGS;
    (p.RawYCoord as IF2mFieldElement).x.CopyTo(table, position);
    position := position + FE_LONGS;
  end;

  Result := TDefaultF2mLookupTable.Create(Self as IF2mCurve, table, len);
end;

constructor TF2mCurve.Create(m, k1, k2, k3: Int32; const A, B: TBigInteger);
begin
  Create(m, k1, k2, k3, A, B, Default (TBigInteger), Default (TBigInteger));
end;

function TF2mCurve.CreateDefaultMultiplier: IECMultiplier;
begin
  if (IsKoblitz) then
  begin
    Result := TWTauNafMultiplier.Create();
    Exit;
  end;

  Result := (Inherited CreateDefaultMultiplier());
end;

function TF2mCurve.CreateRawPoint(const x, y: IECFieldElement;
  withCompression: Boolean): IECPoint;
begin
  Result := TF2mPoint.Create(Self as IECCurve, x, y, withCompression);
end;

function TF2mCurve.CreateRawPoint(const x, y: IECFieldElement;
  const zs: TCryptoLibGenericArray<IECFieldElement>; withCompression: Boolean)
  : IECPoint;
begin
  Result := TF2mPoint.Create(Self as IECCurve, x, y, zs, withCompression);
end;

destructor TF2mCurve.Destroy;
begin
  inherited Destroy;
end;

function TF2mCurve.FromBigInteger(const x: TBigInteger): IECFieldElement;
begin
  Result := TF2mFieldElement.Create(Fm, Fk1, Fk2, Fk3, x);
end;

function TF2mCurve.SupportsCoordinateSystem(coord: Int32): Boolean;
begin
  case coord of
    COORD_AFFINE, COORD_HOMOGENEOUS, COORD_LAMBDA_PROJECTIVE:
      begin
        Result := true;
      end
  else
    begin
      Result := false;
    end;
  end;
end;

{ TDefaultLookupTable }

constructor TDefaultLookupTable.Create(const outer: IECCurve;
  const table: TCryptoLibByteArray; size: Int32);
begin
  Inherited Create();
  Fm_outer := outer;
  Fm_table := table;
  Fm_size := size;
end;

function TDefaultLookupTable.GetSize: Int32;
begin
  Result := Fm_size;
end;

function TDefaultLookupTable.Lookup(index: Int32): IECPoint;
var
  FE_BYTES, position, i, j: Int32;
  x, y: TCryptoLibByteArray;
  MASK: Byte;
  XFieldElement, YFieldElement: IECFieldElement;
begin
  FE_BYTES := (Fm_outer.FieldSize + 7) div 8;
  System.SetLength(x, FE_BYTES);
  System.SetLength(y, FE_BYTES);

  position := 0;

  for i := 0 to System.Pred(Fm_size) do
  begin

    MASK := Byte(TBits.Asr32((i xor index) - 1, 31));

    for j := 0 to System.Pred(FE_BYTES) do
    begin

      x[j] := x[j] xor Byte(Fm_table[position + j] and MASK);
      y[j] := y[j] xor Byte(Fm_table[position + FE_BYTES + j] and MASK);
    end;
    position := position + (FE_BYTES * 2);
  end;

  XFieldElement := Fm_outer.FromBigInteger(TBigInteger.Create(1, x));
  YFieldElement := Fm_outer.FromBigInteger(TBigInteger.Create(1, y));
  Result := Fm_outer.CreateRawPoint(XFieldElement, YFieldElement, false);
end;

{ TDefaultF2mLookupTable }

constructor TDefaultF2mLookupTable.Create(const outer: IF2mCurve;
  const table: TCryptoLibInt64Array; size: Int32);
begin
  Inherited Create();
  Fm_outer := outer;
  Fm_table := table;
  Fm_size := size;
end;

function TDefaultF2mLookupTable.GetSize: Int32;
begin
  Result := Fm_size;
end;

function TDefaultF2mLookupTable.Lookup(index: Int32): IECPoint;
var
  FE_LONGS, position, m, i, j: Int32;
  ks: TCryptoLibInt32Array;
  x, y: TCryptoLibInt64Array;
  MASK: Int64;
  XFieldElement, YFieldElement: IECFieldElement;
begin
  m := Fm_outer.m;
  if Fm_outer.IsTrinomial() then
  begin
    ks := TCryptoLibInt32Array.Create(Fm_outer.k1);
  end
  else
  begin
    ks := TCryptoLibInt32Array.Create(Fm_outer.k1, Fm_outer.k2, Fm_outer.k3);
  end;

  FE_LONGS := (Fm_outer.m + 63) div 64;
  System.SetLength(x, FE_LONGS);
  System.SetLength(y, FE_LONGS);

  position := 0;

  for i := 0 to System.Pred(Fm_size) do
  begin

    MASK := TBits.Asr32((i xor index) - 1, 31);

    for j := 0 to System.Pred(FE_LONGS) do
    begin

      x[j] := x[j] xor (Fm_table[position + j] and MASK);
      y[j] := y[j] xor (Fm_table[position + FE_LONGS + j] and MASK);
    end;
    position := position + (FE_LONGS * 2);
  end;

  XFieldElement := TF2mFieldElement.Create(m, ks, TLongArray.Create(x));
  YFieldElement := TF2mFieldElement.Create(m, ks, TLongArray.Create(y));
  Result := Fm_outer.CreateRawPoint(XFieldElement, YFieldElement, false);
end;

end.
