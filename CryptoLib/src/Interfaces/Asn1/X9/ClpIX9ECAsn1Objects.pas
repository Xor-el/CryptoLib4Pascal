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

unit ClpIX9ECAsn1Objects;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpIAsn1Core,
  ClpIAsn1Objects,
  ClpBigInteger,
  ClpIECC,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// Interface for X9FieldID.
  /// </summary>
  IX9FieldID = interface(IAsn1Encodable)
    ['{8A3B4C5D-6E7F-8901-A2B3-C4D5E6F7A8B9}']

    function GetFieldType: IDerObjectIdentifier;
    function GetParameters: IAsn1Object;

    property FieldType: IDerObjectIdentifier read GetFieldType;
    property Parameters: IAsn1Object read GetParameters;
  end;

  /// <summary>
  /// Interface for X9FieldElement.
  /// </summary>
  IX9FieldElement = interface(IAsn1Encodable)
    ['{1B2C3D4E-5F6A-7B8C-9D0E-1F2A3B4C5D6E}']

    function GetValue: IECFieldElement;

    property Value: IECFieldElement read GetValue;
  end;

  /// <summary>
  /// Interface for X9Curve.
  /// </summary>
  IX9Curve = interface(IAsn1Encodable)
    ['{2C3D4E5F-6A7B-8C9D-0E1F-2A3B4C5D6E7F}']

    function GetCurve: IECCurve;
    function GetSeed: IDerBitString;
    function GetSeedBytes: TCryptoLibByteArray;

    property Curve: IECCurve read GetCurve;
    property Seed: IDerBitString read GetSeed;
  end;

  /// <summary>
  /// Interface for X9ECPoint.
  /// </summary>
  IX9ECPoint = interface(IAsn1Encodable)
    ['{3D4E5F6A-7B8C-9D0E-1F2A-3B4C5D6E7F8A}']

    function GetPoint: IECPoint;
    function GetPointEncoding: IAsn1OctetString;
    function GetIsPointCompressed: Boolean;

    property Point: IECPoint read GetPoint;
    property PointEncoding: IAsn1OctetString read GetPointEncoding;
    property IsPointCompressed: Boolean read GetIsPointCompressed;
  end;

  /// <summary>
  /// Interface for X9ECParameters.
  /// </summary>
  IX9ECParameters = interface(IAsn1Encodable)
    ['{4E5F6A7B-8C9D-0E1F-2A3B-4C5D6E7F8A9B}']

    function GetCurve: IECCurve;
    function GetG: IECPoint;
    function GetN: TBigInteger;
    function GetH: TBigInteger;
    function GetCurveEntry: IX9Curve;
    function GetFieldIDEntry: IX9FieldID;
    function GetBaseEntry: IX9ECPoint;

    function GetSeed: TCryptoLibByteArray;

    property Curve: IECCurve read GetCurve;
    property G: IECPoint read GetG;
    property N: TBigInteger read GetN;
    property H: TBigInteger read GetH;
    property CurveEntry: IX9Curve read GetCurveEntry;
    property FieldIDEntry: IX9FieldID read GetFieldIDEntry;
    property BaseEntry: IX9ECPoint read GetBaseEntry;
  end;

  /// <summary>
  /// Interface for X962Parameters.
  /// </summary>
  IX962Parameters = interface(IAsn1Encodable)
    ['{D1E2F3A4-B5C6-7890-DEF1-23456789ABCD}']

    function GetParameters: IAsn1Object;
    function GetNamedCurve: IDerObjectIdentifier;
    function IsImplicitlyCA: Boolean;
    function IsNamedCurve: Boolean;

    property Parameters: IAsn1Object read GetParameters;
    property NamedCurve: IDerObjectIdentifier read GetNamedCurve;
  end;

implementation

end.
