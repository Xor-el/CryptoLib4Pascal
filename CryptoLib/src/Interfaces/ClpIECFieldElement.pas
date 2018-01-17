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

unit ClpIECFieldElement;

{$I ..\Include\CryptoLib.inc}

interface

uses
  ClpCryptoLibTypes,
  ClpLongArray,
  ClpBigInteger;

type
  IECFieldElement = interface(IInterface)
    ['{22B107FE-0F5A-4426-BBA0-C8E641E450B8}']

    function GetFieldName: String;
    function GetFieldSize: Int32;
    function GetBitLength: Int32;
    function GetIsOne: Boolean;
    function GetIsZero: Boolean;

    function ToBigInteger(): TBigInteger;
    function Add(b: IECFieldElement): IECFieldElement;
    function AddOne(): IECFieldElement;
    function Subtract(b: IECFieldElement): IECFieldElement;
    function Multiply(b: IECFieldElement): IECFieldElement;
    function Divide(b: IECFieldElement): IECFieldElement;
    function Negate(): IECFieldElement;
    function Square(): IECFieldElement;
    function Invert(): IECFieldElement;
    function Sqrt(): IECFieldElement;

    function MultiplyMinusProduct(b, x, y: IECFieldElement): IECFieldElement;

    function MultiplyPlusProduct(b, x, y: IECFieldElement): IECFieldElement;

    function SquareMinusProduct(x, y: IECFieldElement): IECFieldElement;

    function SquarePlusProduct(x, y: IECFieldElement): IECFieldElement;

    function SquarePow(pow: Int32): IECFieldElement;

    function TestBitZero(): Boolean;

    function Equals(other: IECFieldElement): Boolean;

    function GetHashCode(): {$IFDEF DELPHI}Int32; {$ELSE}PtrInt;
{$ENDIF DELPHI}
    function ToString(): String;

    function GetEncoded(): TCryptoLibByteArray;

    property FieldName: string read GetFieldName;
    property FieldSize: Int32 read GetFieldSize;
    property BitLength: Int32 read GetBitLength;
    property IsOne: Boolean read GetIsOne;
    property IsZero: Boolean read GetIsZero;

  end;

type
  IFpFieldElement = interface(IECFieldElement)

    ['{F5106EAC-DA8F-4815-8403-3D9C5438BF6F}']

    /// <summary>
    /// return the field name for this field.
    /// </summary>
    /// <returns>
    /// return the string "Fp".
    /// </returns>
    function GetFieldName: String;
    function GetFieldSize: Int32;
    function GetQ: TBigInteger;

    function CheckSqrt(z: IECFieldElement): IECFieldElement;
    function LucasSequence(P, Q, K: TBigInteger)
      : TCryptoLibGenericArray<TBigInteger>;

    function ModAdd(x1, x2: TBigInteger): TBigInteger;
    function ModDouble(x: TBigInteger): TBigInteger;
    function ModHalf(x: TBigInteger): TBigInteger;
    function ModHalfAbs(x: TBigInteger): TBigInteger;
    function ModInverse(x: TBigInteger): TBigInteger;
    function ModMult(x1, x2: TBigInteger): TBigInteger;
    function ModReduce(x: TBigInteger): TBigInteger;
    function ModSubtract(x1, x2: TBigInteger): TBigInteger;

    function ToBigInteger(): TBigInteger;

    property FieldName: string read GetFieldName;
    property FieldSize: Int32 read GetFieldSize;

    property Q: TBigInteger read GetQ;

    function Add(b: IECFieldElement): IECFieldElement;
    function AddOne(): IECFieldElement;
    function Subtract(b: IECFieldElement): IECFieldElement;

    function Multiply(b: IECFieldElement): IECFieldElement;
    function Divide(b: IECFieldElement): IECFieldElement;
    function Negate(): IECFieldElement;
    function Square(): IECFieldElement;

    function Invert(): IECFieldElement;

    /// <summary>
    /// return a sqrt root - the routine verifies that the calculation
    /// </summary>
    /// <returns>
    /// returns the right value - if none exists it returns null.
    /// </returns>
    function Sqrt(): IECFieldElement;

    function MultiplyMinusProduct(b, x, y: IECFieldElement): IECFieldElement;
    function MultiplyPlusProduct(b, x, y: IECFieldElement): IECFieldElement;

    function SquareMinusProduct(x, y: IECFieldElement): IECFieldElement;

    function SquarePlusProduct(x, y: IECFieldElement): IECFieldElement;

    function Equals(other: IFpFieldElement): Boolean;

    function GetHashCode(): {$IFDEF DELPHI}Int32; {$ELSE}PtrInt;
{$ENDIF DELPHI}
  end;

type
  IF2mFieldElement = interface(IECFieldElement)

    ['{1B29CD22-21C3-424B-9496-BF5F1E4662E8}']

    // /**
    // * The exponent <code>m</code> of <code>F<sub>2<sup>m</sup></sub></code>.
    // */
    function GetM: Int32;
    /// <summary>
    /// Tpb or Ppb.
    /// </summary>
    function GetRepresentation: Int32;
    function GetKs: TCryptoLibInt32Array;
    function GetX: TLongArray;

    function GetK1: Int32;
    function GetK2: Int32;
    function GetK3: Int32;

    function GetFieldName: String;
    function GetFieldSize: Int32;
    function GetBitLength: Int32;
    function GetIsOne: Boolean;
    function GetIsZero: Boolean;

    function TestBitZero(): Boolean;
    function ToBigInteger(): TBigInteger;

    function Add(b: IECFieldElement): IECFieldElement;
    function AddOne(): IECFieldElement;
    function Subtract(b: IECFieldElement): IECFieldElement;

    function Multiply(b: IECFieldElement): IECFieldElement;
    function Divide(b: IECFieldElement): IECFieldElement;
    function Negate(): IECFieldElement;
    function Square(): IECFieldElement;

    function Invert(): IECFieldElement;

    /// <summary>
    /// return a sqrt root - the routine verifies that the calculation
    /// </summary>
    /// <returns>
    /// returns the right value - if none exists it returns null.
    /// </returns>
    function Sqrt(): IECFieldElement;

    function MultiplyMinusProduct(b, x, y: IECFieldElement): IECFieldElement;
    function MultiplyPlusProduct(b, x, y: IECFieldElement): IECFieldElement;

    function SquareMinusProduct(x, y: IECFieldElement): IECFieldElement;

    function SquarePlusProduct(x, y: IECFieldElement): IECFieldElement;

    function SquarePow(pow: Int32): IECFieldElement;

    function Equals(other: IF2mFieldElement): Boolean;

    function GetHashCode(): {$IFDEF DELPHI}Int32; {$ELSE}PtrInt;
{$ENDIF DELPHI}
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

end.
