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

unit ClpIECCommon;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpBigInteger,
  ClpIFiniteField,
  ClpIECFieldElement,
  ClpIPreCompCallback,
  ClpIPreCompInfo,
  ClpISecureRandom,
  ClpCryptoLibTypes;

type
  IECCurve = interface;
  IECCurveConfig = interface;
  IECPoint = interface;

  IECMultiplier = interface;
  IECEndomorphism = interface;
  IECLookupTable = interface;

  IECCurve = interface(IInterface)
    ['{A1B2C3D4-E5F6-7890-ABCD-EF1234567819}']
    function GetHashCode: {$IFDEF DELPHI}Int32{$ELSE}PtrInt{$ENDIF};
    function ToString: String;
    function GetFieldSize: Int32;
    function GetFieldElementEncodingLength: Int32;
    function GetField: IFiniteField;
    function GetInfinity: IECPoint;
    function GetOrder: TBigInteger;
    function GetCofactor: TBigInteger;
    function GetCoordinateSystem: Int32;
    function GetA: IECFieldElement;
    function GetB: IECFieldElement;
    function GetMultiplier: IECMultiplier;
    function Equals(const AOther: IECCurve): Boolean;
    property FieldSize: Int32 read GetFieldSize;
    property FieldElementEncodingLength: Int32 read GetFieldElementEncodingLength;
    property Field: IFiniteField read GetField;
    property Infinity: IECPoint read GetInfinity;
    property Order: TBigInteger read GetOrder;
    property Cofactor: TBigInteger read GetCofactor;
    property CoordinateSystem: Int32 read GetCoordinateSystem;
    property A: IECFieldElement read GetA;
    property B: IECFieldElement read GetB;
    property Multiplier: IECMultiplier read GetMultiplier;
    function FromBigInteger(const AX: TBigInteger): IECFieldElement;
    function CreatePoint(const AX, AY: TBigInteger): IECPoint;
    function CreateRawPoint(const AX, AY: IECFieldElement): IECPoint; overload;
    function CreateRawPoint(const AX, AY: IECFieldElement; const AZs: TCryptoLibGenericArray<IECFieldElement>): IECPoint; overload;
    function RandomFieldElement(const ARandom: ISecureRandom): IECFieldElement;
    function RandomFieldElementMult(const ARandom: ISecureRandom): IECFieldElement;
    function IsValidFieldElement(const AX: TBigInteger): Boolean;
    function GetAffinePointEncodingLength(ACompressed: Boolean): Int32;
    function CreateCacheSafeLookupTable(const APoints: TCryptoLibGenericArray<IECPoint>; AOff, ALen: Int32): IECLookupTable;
    function GetPreCompInfo(const APoint: IECPoint; const AName: String): IPreCompInfo;
    function GetEndomorphism: IECEndomorphism;
    procedure NormalizeAll(const APoints: TCryptoLibGenericArray<IECPoint>); overload;
    procedure NormalizeAll(const APoints: TCryptoLibGenericArray<IECPoint>; AOff, ALen: Int32; const AIso: IECFieldElement); overload;
    function ImportPoint(const AP: IECPoint): IECPoint;
    function Precompute(const APoint: IECPoint; const AName: String; const ACallback: IPreCompCallback): IPreCompInfo; overload;
    function Precompute(const AName: String; const ACallback: IPreCompCallback): IPreCompInfo; overload;
    function DecodePoint(const AEncoded: TCryptoLibByteArray): IECPoint;
    function SupportsCoordinateSystem(ACoord: Int32): Boolean;
    function Configure: IECCurveConfig;
    procedure ApplyConfig(ACoord: Int32; const AEndomorphism: IECEndomorphism; const AMultiplier: IECMultiplier);
    function CloneCurve: IECCurve;
    function ValidatePoint(const AX, AY: TBigInteger): IECPoint;
  end;

  IECCurveConfig = interface(IInterface)
    ['{C5D6E7F8-A9B0-1234-C5D6-E7F8A9B01236}']

    function SetCoordinateSystem(ACoord: Int32): IECCurveConfig;
    function SetEndomorphism(const AEndomorphism: IECEndomorphism): IECCurveConfig;
    function SetMultiplier(const AMultiplier: IECMultiplier): IECCurveConfig;
    function CreateCurve: IECCurve;
  end;

  IAbstractFpCurve = interface(IECCurve)
    ['{B2C3D4E5-F6A7-8901-BCDE-F12345678901}']
    function IsValidFieldElement(const AX: TBigInteger): Boolean;
    function RandomFieldElement(const ARandom: ISecureRandom): IECFieldElement;
    function RandomFieldElementMult(const ARandom: ISecureRandom): IECFieldElement;
    function DecompressPoint(AYTilde: Int32; const AX1: TBigInteger): IECPoint;
  end;

  IFpCurve = interface(IAbstractFpCurve)
    ['{B2C3D4E5-F6A7-8901-BCDE-F12345678902}']
  end;

  IAbstractF2mCurve = interface(IECCurve)
    ['{B2C3D4E5-F6A7-8901-BCDE-F12345678901}']
    function GetIsKoblitz: Boolean;
    function SolveQuadraticEquation(const ABeta: IECFieldElement): IECFieldElement;
    property IsKoblitz: Boolean read GetIsKoblitz;
  end;

  IF2mCurve = interface(IAbstractF2mCurve)
    ['{C3D4E5F6-A7B8-9012-CDEF-123456789013}']
  end;

  IECPoint = interface(IInterface)
    ['{A1B2C3D4-E5F6-7890-ABCD-EF1234567820}']

    function GetCurve: IECCurve;
    function GetIsInfinity: Boolean;
    function GetXCoord: IECFieldElement;
    function GetYCoord: IECFieldElement;
    function GetRawXCoord: IECFieldElement;
    function GetRawYCoord: IECFieldElement;
    function GetZCoord(AIndex: Int32): IECFieldElement;
    function IsNormalized: Boolean;
    function GetAffineXCoord: IECFieldElement;
    function GetAffineYCoord: IECFieldElement;
    function GetCompressionYTilde: Boolean;

    property Curve: IECCurve read GetCurve;
    property IsInfinity: Boolean read GetIsInfinity;
    property XCoord: IECFieldElement read GetXCoord;
    property YCoord: IECFieldElement read GetYCoord;
    property RawXCoord: IECFieldElement read GetRawXCoord;
    property RawYCoord: IECFieldElement read GetRawYCoord;
    property AffineXCoord: IECFieldElement read GetAffineXCoord;
    property AffineYCoord: IECFieldElement read GetAffineYCoord;

    function Normalize: IECPoint; overload;
    function Normalize(const AZInv: IECFieldElement): IECPoint; overload;
    function Detach: IECPoint;
    function GetDetachedPoint: IECPoint;

    function ScaleX(const AScale: IECFieldElement): IECPoint;
    function ScaleXNegateY(const AScale: IECFieldElement): IECPoint;
    function ScaleY(const AScale: IECFieldElement): IECPoint;
    function ScaleYNegateX(const AScale: IECFieldElement): IECPoint;

    function GetPreCompInfo(const AName: String): IPreCompInfo;
    function Precompute(const AName: String; const ACallback: IPreCompCallback): IPreCompInfo;
    function GetEncoded: TCryptoLibByteArray; overload;
    function GetEncoded(ACompressed: Boolean): TCryptoLibByteArray; overload;
    function GetEncodedLength(ACompressed: Boolean): Int32;
    procedure EncodeTo(ACompressed: Boolean; var ABuf: TCryptoLibByteArray; AOff: Int32);
    function IsValid: Boolean;
    function IsValidPartial: Boolean;
    function ImplIsValid(ADecompressed, ACheckOrder: Boolean): Boolean;
    function SatisfiesCurveEquation: Boolean;
    function SatisfiesOrder: Boolean;

    function Add(const AB: IECPoint): IECPoint;
    function Subtract(const AB: IECPoint): IECPoint;
    function Negate: IECPoint;
    function Twice: IECPoint;
    function Multiply(const AK: TBigInteger): IECPoint;
    function TimesPow2(AE: Int32): IECPoint;
    function TwicePlus(const AB: IECPoint): IECPoint;
    function ThreeTimes: IECPoint;
    function Equals(const AOther: IECPoint): Boolean;
    function GetHashCode: {$IFDEF DELPHI}Int32; {$ELSE}PtrInt; {$ENDIF DELPHI}
  end;

  IECPointBase = interface(IECPoint)
    ['{A1B2C3D4-E5F6-7890-ABCD-EF1234567830}']
  end;

  IAbstractFpPoint = interface(IECPointBase)
    ['{A1B2C3D4-E5F6-7890-ABCD-EF1234567831}']
  end;

  IFpPoint = interface(IAbstractFpPoint)
    ['{A1B2C3D4-E5F6-7890-ABCD-EF1234567832}']
  end;

  IAbstractF2mPoint = interface(IECPointBase)
    ['{A1B2C3D4-E5F6-7890-ABCD-EF1234567833}']
    function Tau: IAbstractF2mPoint;
    function TauPow(APow: Int32): IAbstractF2mPoint;
  end;

  IF2mPoint = interface(IAbstractF2mPoint)
    ['{A1B2C3D4-E5F6-7890-ABCD-EF1234567834}']
  end;

  IECPointMap = interface(IInterface)
    ['{A1B2C3D4-E5F6-7890-ABCD-EF1234567822}']
    function Map(const AP: IECPoint): IECPoint;
  end;

  IECEndomorphism = interface(IInterface)
    ['{E5F6A7B8-C9D0-1234-E5F6-A7B8C9D01235}']
    function GetPointMap: IECPointMap;
    function GetHasEfficientPointMap: Boolean;
    property PointMap: IECPointMap read GetPointMap;
    property HasEfficientPointMap: Boolean read GetHasEfficientPointMap;
  end;

  IGlvEndomorphism = interface(IECEndomorphism)
    ['{F6A7B8C9-D0E1-2345-F6A7-B8C9D0E12346}']
    function DecomposeScalar(const AK: TBigInteger): TCryptoLibGenericArray<TBigInteger>;
  end;

  IECLookupTable = interface(IInterface)
    ['{A1B2C3D4-E5F6-7890-ABCD-EF1234567821}']
    function GetSize: Int32;
    function Lookup(AIndex: Int32): IECPoint;
    function LookupVar(AIndex: Int32): IECPoint;
    property Size: Int32 read GetSize;
  end;

  IECMultiplier = interface(IInterface)
    ['{D4E5F6A7-B8C9-0123-D4E5-F6A7B8C90124}']

    function Multiply(const APoint: IECPoint; const AK: TBigInteger): IECPoint;
  end;

implementation

end.
