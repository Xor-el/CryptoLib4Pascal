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
    function Add(const b: IECFieldElement): IECFieldElement;
    function AddOne(): IECFieldElement;
    function Subtract(const b: IECFieldElement): IECFieldElement;
    function Multiply(const b: IECFieldElement): IECFieldElement;
    function Divide(const b: IECFieldElement): IECFieldElement;
    function Negate(): IECFieldElement;
    function Square(): IECFieldElement;
    function Invert(): IECFieldElement;
    function Sqrt(): IECFieldElement;

    function MultiplyMinusProduct(const b, x, y: IECFieldElement)
      : IECFieldElement;

    function MultiplyPlusProduct(const b, x, y: IECFieldElement)
      : IECFieldElement;

    function SquareMinusProduct(const x, y: IECFieldElement): IECFieldElement;

    function SquarePlusProduct(const x, y: IECFieldElement): IECFieldElement;

    function SquarePow(pow: Int32): IECFieldElement;

    function TestBitZero(): Boolean;

    function Equals(const other: IECFieldElement): Boolean;

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
  IAbstractFpFieldElement = interface(IECFieldElement)

    ['{C3FFD257-58FB-4730-B26A-E225C48F374E}']
  end;

type
  IFpFieldElement = interface(IAbstractFpFieldElement)

    ['{F5106EAC-DA8F-4815-8403-3D9C5438BF6F}']

    function GetQ: TBigInteger;

    function CheckSqrt(const z: IECFieldElement): IECFieldElement;
    function LucasSequence(const P, Q, K: TBigInteger)
      : TCryptoLibGenericArray<TBigInteger>;

    function ModAdd(const x1, x2: TBigInteger): TBigInteger;
    function ModDouble(const x: TBigInteger): TBigInteger;
    function ModHalf(const x: TBigInteger): TBigInteger;
    function ModHalfAbs(const x: TBigInteger): TBigInteger;
    function ModInverse(const x: TBigInteger): TBigInteger;
    function ModMult(const x1, x2: TBigInteger): TBigInteger;
    function ModReduce(const x: TBigInteger): TBigInteger;
    function ModSubtract(const x1, x2: TBigInteger): TBigInteger;

    property Q: TBigInteger read GetQ;

  end;

type
  IAbstractF2mFieldElement = interface(IECFieldElement)

    ['{EA6B19A3-77AF-4EDE-A96B-D736DBD71B81}']

    function Trace(): Int32;
    function HalfTrace(): IECFieldElement;
  end;

type
  IF2mFieldElement = interface(IAbstractF2mFieldElement)

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

  end;

implementation

end.
