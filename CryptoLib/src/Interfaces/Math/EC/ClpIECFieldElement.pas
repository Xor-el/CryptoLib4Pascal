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

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpBigInteger,
  ClpLongArray,
  ClpCryptoLibTypes;

type
  IECFieldElement = interface(IInterface)
    ['{A1B2C3D4-E5F6-7890-ABCD-EF1234567818}']

    function GetHashCode: {$IFDEF DELPHI}Int32{$ELSE}PtrInt{$ENDIF};
    function ToString: String;
    function GetFieldName: String;
    function GetFieldSize: Int32;

    property FieldName: String read GetFieldName;
    property FieldSize: Int32 read GetFieldSize;

    function ToBigInteger: TBigInteger;
    function GetEncoded: TCryptoLibByteArray;
    function GetEncodedLength: Int32;
    procedure EncodeTo(var ABuf: TCryptoLibByteArray; AOff: Int32);
    function GetIsOne: Boolean;
    function GetIsZero: Boolean;
    property IsOne: Boolean read GetIsOne;
    property IsZero: Boolean read GetIsZero;
    function GetBitLength: Int32;
    function TestBitZero: Boolean;
    function Equals(const AOther: IECFieldElement): Boolean;
    function Add(const AB: IECFieldElement): IECFieldElement;
    function AddOne: IECFieldElement;
    function Subtract(const AB: IECFieldElement): IECFieldElement;
    function Multiply(const AB: IECFieldElement): IECFieldElement;
    function Divide(const AB: IECFieldElement): IECFieldElement;
    function Negate: IECFieldElement;
    function Square: IECFieldElement;
    function Invert: IECFieldElement;
    function Sqrt: IECFieldElement;
    function MultiplyMinusProduct(const AB, AX, AY: IECFieldElement): IECFieldElement;
    function MultiplyPlusProduct(const AB, AX, AY: IECFieldElement): IECFieldElement;
    function SquareMinusProduct(const AX, AY: IECFieldElement): IECFieldElement;
    function SquarePlusProduct(const AX, AY: IECFieldElement): IECFieldElement;
    function SquarePow(APow: Int32): IECFieldElement;
  end;

  IAbstractFpFieldElement = interface(IECFieldElement)
    ['{B4339FF2-E999-4AF2-BDD2-64F88DEAD1AA}']
  end;

  IFpFieldElement = interface(IECFieldElement)
    ['{A1B2C3D4-E5F6-7890-ABCD-EF123456781A}']

    function GetQ: TBigInteger;

    property Q: TBigInteger read GetQ;
  end;

  IAbstractF2mFieldElement = interface(IECFieldElement)
    ['{A1B2C3D4-E5F6-7890-ABCD-EF123456781C}']

    function HalfTrace: IECFieldElement;
    function GetHasFastTrace: Boolean;
    function Trace: Int32;

    property HasFastTrace: Boolean read GetHasFastTrace;
  end;

  IF2mFieldElement = interface(IAbstractF2mFieldElement)
    ['{A1B2C3D4-E5F6-7890-ABCD-EF123456781B}']

    function GetRepresentation: Int32;
    function GetM: Int32;
    function GetK1: Int32;
    function GetK2: Int32;
    function GetK3: Int32;
    function GetX: TLongArray;

    property Representation: Int32 read GetRepresentation;
    property M: Int32 read GetM;
    property K1: Int32 read GetK1;
    property K2: Int32 read GetK2;
    property K3: Int32 read GetK3;
    property X: TLongArray read GetX;
  end;

implementation

end.
