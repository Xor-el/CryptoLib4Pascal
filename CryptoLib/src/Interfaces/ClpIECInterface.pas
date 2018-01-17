{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                    Copyright (c) 2018 Ugochukwu Mmaduekwe                       * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }

{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }

{ *                              Acknowledgements:                                  * }
{ *                                                                                 * }
{ *        Thanks to Sphere 10 Software (http://sphere10.com) for sponsoring        * }
{ *                        the development of this library                          * }

{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit ClpIECInterface;

{$I ..\Include\CryptoLib.inc}

interface

uses
  Generics.Collections,
  ClpIECFieldElement,
  ClpCryptoLibTypes,
  ClpIFiniteField,
  ClpIPreCompInfo,
  ClpBigInteger;

type
  IECCurve = interface;

  IECPoint = interface(IInterface)
    ['{625704AF-950B-4B39-976B-573A8DC42790}']

    function GetIsInfinity: Boolean;
    function GetIsCompressed: Boolean;
    function GetpreCompTable: TDictionary<String, IPreCompInfo>;
    procedure SetpreCompTable(const Value: TDictionary<String, IPreCompInfo>);
    function GetCurve: IECCurve;
    function GetCurveCoordinateSystem: Int32;
    function GetX: IECFieldElement;
      deprecated 'Use AffineXCoord, or Normalize() and XCoord, instead';
    function GetY: IECFieldElement;
      deprecated 'Use AffineYCoord, or Normalize() and YCoord, instead';
    function GetAffineXCoord: IECFieldElement;
    function GetAffineYCoord: IECFieldElement;
    function GetXCoord: IECFieldElement;
    function GetYCoord: IECFieldElement;
    function GetCompressionYTilde: Boolean;

    function SatisfiesCofactor(): Boolean;
    function SatisfiesCurveEquation(): Boolean;
    function Detach(): IECPoint;

    function RawXCoord: IECFieldElement;

    function RawYCoord: IECFieldElement;

    function RawZCoords: TCryptoLibGenericArray<IECFieldElement>;

    function CreateScaledPoint(sx, sy: IECFieldElement): IECPoint;

    procedure CheckNormalized();

    property CurveCoordinateSystem: Int32 read GetCurveCoordinateSystem;

    property CompressionYTilde: Boolean read GetCompressionYTilde;

    function GetDetachedPoint(): IECPoint;
    function GetZCoord(index: Int32): IECFieldElement;
    function GetZCoords(): TCryptoLibGenericArray<IECFieldElement>;

    function IsNormalized(): Boolean;

    /// <summary>
    /// Normalization ensures that any projective coordinate is 1, and
    /// therefore that the x, y <br />coordinates reflect those of the
    /// equivalent point in an affine coordinate system.
    /// </summary>
    /// <returns>
    /// a new ECPoint instance representing the same point, but with
    /// normalized coordinates
    /// </returns>
    function Normalize(): IECPoint; overload;

    function Normalize(zInv: IECFieldElement): IECPoint; overload;

    function IsValid(): Boolean;

    function ScaleX(scale: IECFieldElement): IECPoint;
    function ScaleY(scale: IECFieldElement): IECPoint;

    function GetEncoded(): TCryptoLibByteArray; overload;
    function GetEncoded(compressed: Boolean): TCryptoLibByteArray; overload;

    function Add(b: IECPoint): IECPoint;
    function Subtract(b: IECPoint): IECPoint;
    function Negate(): IECPoint;
    function TimesPow2(e: Int32): IECPoint;

    function Twice(): IECPoint;
    function Multiply(b: TBigInteger): IECPoint;

    function TwicePlus(b: IECPoint): IECPoint;

    function ThreeTimes(): IECPoint;

    function Equals(other: IECPoint): Boolean;
    function GetHashCode(): {$IFDEF DELPHI}Int32; {$ELSE}PtrInt; {$ENDIF DELPHI}
    function ToString(): String;

    property preCompTable: TDictionary<String, IPreCompInfo>
      read GetpreCompTable write SetpreCompTable;

    /// <summary>
    /// <para>
    /// Normalizes this point, and then returns the affine x-coordinate.
    /// </para>
    /// <para>
    /// Note: normalization can be expensive, this method is deprecated
    /// in favour of caller-controlled normalization.
    /// </para>
    /// </summary>
    property x: IECFieldElement read GetX;
    /// <summary>
    /// <para>
    /// Normalizes this point, and then returns the affine y-coordinate.
    /// </para>
    /// <para>
    /// Note: normalization can be expensive, this method is deprecated
    /// in favour of caller-controlled normalization.
    /// </para>
    /// </summary>
    property y: IECFieldElement read GetY;

    /// <summary>
    /// Returns the affine x-coordinate after checking that this point is
    /// normalized.
    /// </summary>
    /// <value>
    /// The affine x-coordinate of this point
    /// </value>
    /// <exception cref="ClpCryptoLibTypes|EInvalidOperationCryptoLibException">
    /// if the point is not normalized
    /// </exception>
    property AffineXCoord: IECFieldElement read GetAffineXCoord;
    /// <summary>
    /// Returns the affine y-coordinate after checking that this point is
    /// normalized.
    /// </summary>
    /// <value>
    /// The affine y-coordinate of this point
    /// </value>
    /// <exception cref="ClpCryptoLibTypes|EInvalidOperationCryptoLibException">
    /// if the point is not normalized
    /// </exception>
    property AffineYCoord: IECFieldElement read GetAffineYCoord;

    /// <summary>
    /// Returns the x-coordinate. <br />Caution: depending on the curve's
    /// coordinate system, this may not be the same value as in an <br />
    /// affine coordinate system; use Normalize() to get a point where the
    /// coordinates have their <br />affine values, or use AffineXCoord if
    /// you expect the point to already have been normalized.
    /// </summary>
    /// <value>
    /// the x-coordinate of this point
    /// </value>
    property XCoord: IECFieldElement read GetXCoord;
    /// <summary>
    /// Returns the y-coordinate. <br />Caution: depending on the curve's
    /// coordinate system, this may not be the same value as in an <br />
    /// affine coordinate system; use Normalize() to get a point where the
    /// coordinates have their <br />affine values, or use AffineYCoord if
    /// you expect the point to already have been normalized.
    /// </summary>
    /// <value>
    /// the y-coordinate of this point
    /// </value>
    property YCoord: IECFieldElement read GetYCoord;

    property curve: IECCurve read GetCurve;

    property IsInfinity: Boolean read GetIsInfinity;

    property IsCompressed: Boolean read GetIsCompressed;
  end;

  IECPointBase = interface(IECPoint)
    ['{66AF58F3-2A82-41AA-B01F-AA4A67CA5E80}']

    /// <summary>
    /// return the field element encoded with point compression. (S 4.3.6)
    /// </summary>
    function GetEncoded(compressed: Boolean): TCryptoLibByteArray;

    /// <summary>
    /// Multiplies this <c>ECPoint</c> by the given number.
    /// </summary>
    /// <param name="k">
    /// The multiplicator.
    /// </param>
    /// <returns>
    /// <c>k * this</c>
    /// </returns>
    function Multiply(k: TBigInteger): IECPoint;

  end;

  IAbstractFpPoint = interface(IECPointBase)
    ['{57991B0C-7994-4130-93DC-02FEB42E131B}']

    function GetCompressionYTilde(): Boolean;

    function SatisfiesCurveEquation(): Boolean;

    property CompressionYTilde: Boolean read GetCompressionYTilde;

    function Subtract(b: IECPoint): IECPoint;

  end;

  IFpPoint = interface(IAbstractFpPoint)
    ['{4113EEFE-A0F1-439B-97FD-921CA1E0A814}']

    function Detach(): IECPoint;

    function Two(x: IECFieldElement): IECFieldElement;
    function Three(x: IECFieldElement): IECFieldElement;
    function Four(x: IECFieldElement): IECFieldElement;
    function Eight(x: IECFieldElement): IECFieldElement;
    function DoubleProductFromSquares(a, b, aSquared, bSquared: IECFieldElement)
      : IECFieldElement;

    function CalculateJacobianModifiedW(Z, ZSquared: IECFieldElement)
      : IECFieldElement;

    function GetJacobianModifiedW(): IECFieldElement;

    function TwiceJacobianModified(calculateW: Boolean): IFpPoint;

    function GetZCoord(index: Int32): IECFieldElement;
    // B.3 pg 62
    function Add(b: IECPoint): IECPoint;

    // B.3 pg 62
    function Twice(): IECPoint;

    function TwicePlus(b: IECPoint): IECPoint;

    function ThreeTimes(): IECPoint;

    function TimesPow2(e: Int32): IECPoint;

    function Negate(): IECPoint;

  end;

  IAbstractF2mPoint = interface(IECPointBase)
    ['{D5231494-74E4-4400-A2FE-8E512411515C}']

    function SatisfiesCurveEquation(): Boolean;

    function ScaleX(scale: IECFieldElement): IECPoint;
    function ScaleY(scale: IECFieldElement): IECPoint;

    function Subtract(b: IECPoint): IECPoint;

    function Tau(): IAbstractF2mPoint;

    function TauPow(pow: Int32): IAbstractF2mPoint;

  end;

  IF2mPoint = interface(IAbstractF2mPoint)
    ['{ADFE17E0-6A08-430A-970F-353DE2B9426C}']

    function GetYCoord: IECFieldElement;
    function GetCompressionYTilde: Boolean;

    function Detach(): IECPoint;
    property CompressionYTilde: Boolean read GetCompressionYTilde;

    function Add(b: IECPoint): IECPoint;

    function Twice(): IECPoint;

    function TwicePlus(b: IECPoint): IECPoint;

    function Negate(): IECPoint;

    property YCoord: IECFieldElement read GetYCoord;

  end;

  // type
  /// **
  // * Interface for classes encapsulating a point multiplication algorithm
  // * for <code>ECPoint</code>s.
  // */
  IECMultiplier = interface(IInterface)
    ['{08D01BBB-38C1-4416-867A-D42FAB51E3CB}']

    // /**
    // * Multiplies the <code>ECPoint p</code> by <code>k</code>, i.e.
    // * <code>p</code> is added <code>k</code> times to itself.
    // * @param p The <code>ECPoint</code> to be multiplied.
    // * @param k The factor by which <code>p</code> is multiplied.
    // * @return <code>p</code> multiplied by <code>k</code>.
    // */

    function Multiply(p: IECPoint; k: TBigInteger): IECPoint;

  end;

  // type
  IECPointMap = interface(IInterface)
    ['{73C2B23F-C05D-4916-8E30-14275F1051B6}']

    function Map(p: IECPoint): IECPoint;

  end;

  // type
  IECEndomorphism = interface(IInterface)

    ['{DFEE6FD7-C820-401D-8AD3-4DA9A7509DFD}']

    function GetPointMap: IECPointMap;

    function GetHasEfficientPointMap: Boolean;

    property PointMap: IECPointMap read GetPointMap;

    property HasEfficientPointMap: Boolean read GetHasEfficientPointMap;
  end;

  // type
  IConfig = interface;

  IECCurve = interface(IInterface)
    ['{F340C8A1-034D-4845-BDE7-A5F55FFDE71B}']

    procedure SetCoord(const Value: Int32);
    procedure SetEndomorphism(const Value: IECEndomorphism);
    procedure SetMultiplier(const Value: IECMultiplier);
    function GetFieldSize: Int32;
    function GetInfinity: IECPoint;
    function GetField: IFiniteField;
    function GetA: IECFieldElement;
    function GetB: IECFieldElement;
    function GetOrder: TBigInteger;
    function GetCofactor: TBigInteger;
    function GetCoordinateSystem: Int32;

    function CloneCurve(): IECCurve;

    function CreateRawPoint(x, y: IECFieldElement; withCompression: Boolean)
      : IECPoint; overload;

    function CreateRawPoint(x, y: IECFieldElement;
      zs: TCryptoLibGenericArray<IECFieldElement>; withCompression: Boolean)
      : IECPoint; overload;

    function CreateDefaultMultiplier(): IECMultiplier;

    procedure CheckPoint(point: IECPoint);

    procedure CheckPoints(points: TCryptoLibGenericArray<IECPoint>); overload;

    procedure CheckPoints(points: TCryptoLibGenericArray<IECPoint>;
      off, len: Int32); overload;

    function DecompressPoint(yTilde: Int32; X1: TBigInteger): IECPoint;

    property FieldSize: Int32 read GetFieldSize;
    function FromBigInteger(x: TBigInteger): IECFieldElement;
    function IsValidFieldElement(x: TBigInteger): Boolean;

    function Configure(): IConfig;
    function ValidatePoint(x, y: TBigInteger): IECPoint; overload;

    function ValidatePoint(x, y: TBigInteger; withCompression: Boolean)
      : IECPoint; overload;
      deprecated 'Per-point compression property will be removed';

    function CreatePoint(x, y: TBigInteger): IECPoint; overload;

    function CreatePoint(x, y: TBigInteger; withCompression: Boolean): IECPoint;
      overload; deprecated 'Per-point compression property will be removed';

    function SupportsCoordinateSystem(coord: Int32): Boolean;

    function GetPreCompInfo(point: IECPoint; const name: String): IPreCompInfo;

    /// <summary>
    /// Adds <c>PreCompInfo</c> for a point on this curve, under a given name.
    /// Used by <c>ECMultiplier</c> to save the precomputation for this <c>
    /// ECPoint</c> for use by subsequent multiplication.
    /// </summary>
    /// <param name="point">
    /// The <c>ECPoint</c> to store precomputations for.
    /// </param>
    /// <param name="name">
    /// A <c>String</c> used to index precomputations of different types.
    /// </param>
    /// <param name="preCompInfo">
    /// The values precomputed by the <c>ECMultiplier.</c>
    /// </param>
    procedure SetPreCompInfo(point: IECPoint; const name: String;
      preCompInfo: IPreCompInfo);

    function ImportPoint(p: IECPoint): IECPoint;

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
    procedure NormalizeAll(points: TCryptoLibGenericArray<IECPoint>); overload;

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
    procedure NormalizeAll(points: TCryptoLibGenericArray<IECPoint>;
      off, len: Int32; iso: IECFieldElement); overload;

    function GetEndomorphism(): IECEndomorphism;

    /// <summary>
    /// Sets the default <c>ECMultiplier</c>, unless already set.
    /// </summary>
    function GetMultiplier(): IECMultiplier;

    /// <summary>
    /// Decode a point on this curve from its ASN.1 encoding. The different
    /// encodings are taken account of, including point compression for <br /><c>
    /// F</c><b>p</b> (X9.62 s 4.2.1 pg 17).
    /// </summary>
    /// <returns>
    /// The decoded point.
    /// </returns>
    function DecodePoint(encoded: TCryptoLibByteArray): IECPoint;

    property coord: Int32 write SetCoord;
    property Endomorphism: IECEndomorphism write SetEndomorphism;
    property Multiplier: IECMultiplier write SetMultiplier;

    property Infinity: IECPoint read GetInfinity;

    property field: IFiniteField read GetField;

    property a: IECFieldElement read GetA;

    property b: IECFieldElement read GetB;

    property Order: TBigInteger read GetOrder;

    property Cofactor: TBigInteger read GetCofactor;

    property CoordinateSystem: Int32 read GetCoordinateSystem;

    function Equals(other: IECCurve): Boolean;
    function GetHashCode(): {$IFDEF DELPHI}Int32; {$ELSE}PtrInt;
{$ENDIF DELPHI}
  end;

  IConfig = interface(IInterface)

    ['{F4BD2FCC-FC9B-4FBB-8A3B-CC9031739D9F}']

    function SetCoordinateSystem(coord: Int32): IConfig;
    function SetEndomorphism(Endomorphism: IECEndomorphism): IConfig;
    function SetMultiplier(Multiplier: IECMultiplier): IConfig;
    function CreateCurve(): IECCurve;

  end;

type
  IAbstractFpCurve = interface(IECCurve)
    ['{D37FE528-66B3-4449-A95C-8658A9A89B85}']

    function DecompressPoint(yTilde: Int32; X1: TBigInteger): IECPoint;
    function IsValidFieldElement(x: TBigInteger): Boolean;

  end;

type
  IFpCurve = interface(IAbstractFpCurve)
    ['{73E49F8B-C63F-4F91-8F40-A4C3B15F47FF}']

    function GetQ: TBigInteger;
    function GetInfinity: IECPoint;
    function GetFieldSize: Int32;

    function CloneCurve(): IECCurve;
    function CreateRawPoint(x, y: IECFieldElement; withCompression: Boolean)
      : IECPoint; overload;

    function CreateRawPoint(x, y: IECFieldElement;
      zs: TCryptoLibGenericArray<IECFieldElement>; withCompression: Boolean)
      : IECPoint; overload;

    function SupportsCoordinateSystem(coord: Int32): Boolean;

    property q: TBigInteger read GetQ;
    property Infinity: IECPoint read GetInfinity;
    property FieldSize: Int32 read GetFieldSize;

    function FromBigInteger(x: TBigInteger): IECFieldElement;
    function ImportPoint(p: IECPoint): IECPoint;

  end;

type
  IAbstractF2mCurve = interface(IECCurve)
    ['{97782F77-89D4-410A-9343-518FAB97F349}']

    /// <summary>
    /// Returns true if this is a Koblitz curve (ABC curve).
    /// </summary>
    /// <returns>
    /// true if this is a Koblitz curve (ABC curve), false otherwise
    /// </returns>
    function GetIsKoblitz: Boolean;

    // /**
    // * Solves a quadratic equation <code>z<sup>2</sup> + z = beta</code>(X9.62
    // * D.1.6) The other solution is <code>z + 1</code>.
    // *
    // * @param beta
    // *            The value to solve the qradratic equation for.
    // * @return the solution for <code>z<sup>2</sup> + z = beta</code> or
    // *         <code>null</code> if no solution exists.
    // */
    function SolveQuadradicEquation(beta: IECFieldElement): IECFieldElement;

    function DecompressPoint(yTilde: Int32; X1: TBigInteger): IECPoint;

    function IsValidFieldElement(x: TBigInteger): Boolean;

    function CreatePoint(x, y: TBigInteger; withCompression: Boolean): IECPoint;
      deprecated 'Per-point compression property will be removed';

    // /**
    // * @return the auxiliary values <code>s<sub>0</sub></code> and
    // * <code>s<sub>1</sub></code> used for partial modular reduction for
    // * Koblitz curves.
    // */
    function GetSi(): TCryptoLibGenericArray<TBigInteger>;

    property IsKoblitz: Boolean read GetIsKoblitz;

  end;

type
  IF2mCurve = interface(IAbstractF2mCurve)
    ['{B1C98330-51ED-4C0C-91B1-319223483147}']

    function GetFieldSize: Int32;
    function GetInfinity: IECPoint;
    function GetM: Int32;
    function GetK1: Int32;
    function GetK2: Int32;
    function GetK3: Int32;

    function CloneCurve(): IECCurve;
    function CreateDefaultMultiplier(): IECMultiplier;

    function CreateRawPoint(x, y: IECFieldElement; withCompression: Boolean)
      : IECPoint; overload;

    function CreateRawPoint(x, y: IECFieldElement;
      zs: TCryptoLibGenericArray<IECFieldElement>; withCompression: Boolean)
      : IECPoint; overload;

    function SupportsCoordinateSystem(coord: Int32): Boolean;
    function FromBigInteger(x: TBigInteger): IECFieldElement;

    /// <summary>
    /// Return true if curve uses a Trinomial basis.
    /// </summary>
    /// <returns>
    /// return true if curve Trinomial, false otherwise.
    /// </returns>
    function IsTrinomial(): Boolean;

    property FieldSize: Int32 read GetFieldSize;
    property Infinity: IECPoint read GetInfinity;
    property m: Int32 read GetM;
    property k1: Int32 read GetK1;
    property k2: Int32 read GetK2;
    property k3: Int32 read GetK3;

  end;

  //

implementation

end.