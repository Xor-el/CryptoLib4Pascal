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

unit ClpIMlDsaCore;

{$I ..\..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpCryptoLibTypes;

type
  IMlDsaPolyVec = interface;

  IMlDsaSymmetric = interface(IInterface)
    ['{7AD72F84-31AA-4EAD-AB36-DF014DD0849A}']

    function GetStream128BlockBytes: Int32;
    function GetStream256BlockBytes: Int32;

    procedure Stream128Init(const ASeed: TCryptoLibByteArray; ANonce: UInt16);
    procedure Stream256Init(const ASeed: TCryptoLibByteArray; ANonce: UInt16);
    procedure Stream128SqueezeBlocks(const AOutput: TCryptoLibByteArray; AOffset, ASize: Int32);
    procedure Stream256SqueezeBlocks(const AOutput: TCryptoLibByteArray; AOffset, ASize: Int32);

    property Stream128BlockBytes: Int32 read GetStream128BlockBytes;
    property Stream256BlockBytes: Int32 read GetStream256BlockBytes;
  end;

  IMlDsaPoly = interface(IInterface)
    ['{B3C4D5E6-F708-9123-4567-89ABCDEF0123}']

    function GetCoeffs: TCryptoLibInt32Array;
    procedure SetCoeffs(const ACoeffs: TCryptoLibInt32Array);

    procedure CopyTo(const ATarget: IMlDsaPoly);
    procedure UniformBlocks(const ASeed: TCryptoLibByteArray; ANonce: UInt16);
    procedure UniformEta(const ASeed: TCryptoLibByteArray; ANonce: UInt16);
    procedure UniformGamma1(const ASeed: TCryptoLibByteArray; ANonce: UInt16);
    procedure PointwiseMontgomery(const AV, AW: IMlDsaPoly);
    procedure PointwiseAccountMontgomery(const AU, AV: IMlDsaPolyVec);
    procedure Add(const AA: IMlDsaPoly);
    procedure Subtract(const AB: IMlDsaPoly);
    procedure ReducePoly;
    procedure PolyNtt;
    procedure InverseNttToMont;
    procedure ConditionalAddQ;
    procedure Power2Round(const AA: IMlDsaPoly);
    procedure PolyT0Pack(const ABuf: TCryptoLibByteArray; AOff: Int32);
    procedure PolyT0Unpack(const ABuf: TCryptoLibByteArray; AOff: Int32);
    procedure PolyT1Pack(const ABuf: TCryptoLibByteArray; ABufOff: Int32);
    procedure PolyT1Unpack(const ABuf: TCryptoLibByteArray; ABufOff: Int32);
    procedure PolyEtaPack(const ABuf: TCryptoLibByteArray; AOff: Int32);
    procedure PolyEtaUnpack(const ABuf: TCryptoLibByteArray; AOff: Int32);
    procedure PackZ(const ABuf: TCryptoLibByteArray; AOffset: Int32);
    procedure UnpackZ(const ABuf: TCryptoLibByteArray; ABufOff: Int32);
    procedure Decompose(const AA: IMlDsaPoly);
    procedure PackW1(const ABuf: TCryptoLibByteArray; AOff: Int32);
    procedure Challenge(const ASeed: TCryptoLibByteArray; ASeedOff, ASeedLen: Int32);
    function CheckNorm(ABound: Int32): Boolean;
    function PolyMakeHint(const AA0, AA1: IMlDsaPoly): Int32;
    procedure PolyUseHint(const AA, AH: IMlDsaPoly);
    procedure ShiftLeft;

    property Coeffs: TCryptoLibInt32Array read GetCoeffs write SetCoeffs;
  end;

  IMlDsaPolyVec = interface(IInterface)
    ['{C4D5E6F7-0819-2345-6789-ABCDEF012345}']

    function GetLength: Int32;
    function GetPoly(AIndex: Int32): IMlDsaPoly;

    procedure Add(const AV: IMlDsaPolyVec);
    function CheckNorm(ABound: Int32): Boolean;
    procedure CopyTo(const AZ: IMlDsaPolyVec);
    procedure ConditionalAddQ;
    procedure Decompose(const AV: IMlDsaPolyVec);
    procedure InverseNttToMont;
    function MakeHint(const AV0, AV1: IMlDsaPolyVec): Int32;
    procedure Ntt;
    procedure PackW1(const ABuf: TCryptoLibByteArray; ABufOff: Int32);
    procedure PointwisePolyMontgomery(const AA: IMlDsaPoly; const AV: IMlDsaPolyVec);
    procedure Power2Round(const AV: IMlDsaPolyVec);
    procedure Reduce;
    procedure ShiftLeft;
    procedure Subtract(const AV: IMlDsaPolyVec);
    procedure UniformBlocks(const ARho: TCryptoLibByteArray; AT: Int32);
    procedure UniformEta(const ASeed: TCryptoLibByteArray; ANonce: UInt16);
    procedure UniformGamma1(const ASeed: TCryptoLibByteArray; ANonce: UInt16);
    procedure UseHint(const AA, AH: IMlDsaPolyVec);

    property Length: Int32 read GetLength;
  end;

  IMlDsaPolyVecMatrix = interface(IInterface)
    ['{D5E6F708-192A-3456-789A-BCDEF0123456}']

    procedure ExpandMatrix(const ARho: TCryptoLibByteArray);
    procedure PointwiseMontgomery(const AT, AV: IMlDsaPolyVec);
  end;

implementation

end.
