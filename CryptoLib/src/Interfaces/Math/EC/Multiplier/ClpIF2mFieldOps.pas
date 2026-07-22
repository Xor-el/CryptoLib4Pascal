{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                           Author - Ugochukwu Mmaduekwe                          * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ *                                                                                 * }
{ *                              Acknowledgements:                                  * }
{ *                                                                                 * }
{ *      Thanks to Sphere 10 Software (http://www.sphere10.com/) for sponsoring     * }
{ *                         the development of this library                         * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit ClpIF2mFieldOps;

{$I ..\..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpBigInteger,
  ClpISecureRandom,
  ClpIECFieldElement,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// Constant-time GF(2^m) field arithmetic over a specific binary curve, exposing
  /// only what the López–Dahab Montgomery ladder needs.
  /// Each curve supplies an adapter over its existing (constant-time) binary field.
  /// </summary>
  IF2mFieldOps = interface(IInterface)
    ['{2A9C7E14-6B3D-4F81-A0C5-7E2D9B4F1836}']
    function GetFieldLongs: Int32;
    function GetCardinalityBits: Int32;
    procedure GetCardinality(const AZ: TCryptoLibUInt32Array; AInts: Int32);

    procedure Mul(const AX, AY, AZ: TCryptoLibUInt64Array);
    procedure Square(const AX, AZ: TCryptoLibUInt64Array);
    procedure Add(const AX, AY, AZ: TCryptoLibUInt64Array);
    procedure MulByB(const AX, AZ: TCryptoLibUInt64Array);
    procedure Inv(const AX, AZ: TCryptoLibUInt64Array);
    function IsZeroMask(const AX: TCryptoLibUInt64Array): UInt64;

    procedure RandomNonZero(const ARandom: ISecureRandom; const AZ: TCryptoLibUInt64Array);
    procedure FieldFromBigInteger(const AX: TBigInteger; const AZ: TCryptoLibUInt64Array);
    function CreateFieldElement(const AX: TCryptoLibUInt64Array): IECFieldElement;
  end;

implementation

end.
