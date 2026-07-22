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

unit ClpICTFieldOps;

{$I ..\..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpBigInteger,
  ClpISecureRandom,
  ClpIECFieldElement,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// Constant-time field arithmetic over a specific prime-field short-Weierstrass
  /// curve, exposing only what the homogeneous complete-formula layer needs. Each
  /// curve supplies an adapter over its existing (constant-time) Nat field.
  /// </summary>
  ICTFieldOps = interface(IInterface)
    ['{6F1B2A34-5C8D-4E90-B1A2-7C3D4E5F6A7B}']
    function GetFieldInts: Int32;
    function GetOrderBits: Int32;
    procedure GetOrder(const AZ: TCryptoLibUInt32Array; AInts: Int32);

    procedure Mul(const AX, AY, AZ: TCryptoLibUInt32Array);
    procedure Square(const AX, AZ: TCryptoLibUInt32Array);
    procedure Add(const AX, AY, AZ: TCryptoLibUInt32Array);
    procedure Sub(const AX, AY, AZ: TCryptoLibUInt32Array);
    procedure MulByB3(const AX, AZ: TCryptoLibUInt32Array);
    procedure MulByA(const AX, AZ: TCryptoLibUInt32Array);
    procedure Inv(const AX, AZ: TCryptoLibUInt32Array);
    function IsZero(const AX: TCryptoLibUInt32Array): Boolean;

    procedure RandomMult(const ARandom: ISecureRandom; const AZ: TCryptoLibUInt32Array);
    procedure FieldFromBigInteger(const AX: TBigInteger; const AZ: TCryptoLibUInt32Array);
    function CreateFieldElement(const AX: TCryptoLibUInt32Array): IECFieldElement;
    procedure FieldOne(const AZ: TCryptoLibUInt32Array);
  end;

implementation

end.
