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

unit ClpIMlKemCore;

{$I ..\..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpIXof,
  ClpCryptoLibTypes;

type
  IMlKemPoly = interface(IInterface)
    ['{C8E4A1B2-3D5F-4E6A-9B0C-1D2E3F4A5B6C}']

    function GetCoeffs: TCryptoLibSmallIntArray;
    procedure SetCoeffs(const ACoeffs: TCryptoLibSmallIntArray);

    procedure GetNoiseEta2(const AXof: IXof; const ASeed: TCryptoLibByteArray;
      ASeedOff: Int32; ANonce: Byte);
    procedure GetNoiseEta3(const AXof: IXof; const ASeed: TCryptoLibByteArray;
      ASeedOff: Int32; ANonce: Byte);
    procedure PolyNtt;
    procedure PolyInverseNttToMont;
    procedure ToMont;
    procedure Add(const AA: IMlKemPoly);
    procedure Subtract(const AA: IMlKemPoly);
    procedure PolyReduce;
    procedure CompressPoly128(const ABuf: TCryptoLibByteArray; AOff: Int32);
    procedure CompressPoly160(const ABuf: TCryptoLibByteArray; AOff: Int32);
    procedure DecompressPoly128(const ABuf: TCryptoLibByteArray; AOff: Int32);
    procedure DecompressPoly160(const ABuf: TCryptoLibByteArray; AOff: Int32);
    procedure FromBytes(const ABuf: TCryptoLibByteArray; AOff: Int32);
    procedure ToBytes(const ABuf: TCryptoLibByteArray; AOff: Int32);
    procedure ToMsg(const AMsg: TCryptoLibByteArray);
    procedure FromMsg(const AMsg: TCryptoLibByteArray; AMsgOff: Int32);
    procedure CondSubQ;

    property Coeffs: TCryptoLibSmallIntArray read GetCoeffs write SetCoeffs;
  end;

  IMlKemPolyVec = interface(IInterface)
    ['{D9F5B2C3-4E6A-5F7B-0C1D-2E3F4A5B6C7D}']

    function GetK: Int32;
    function GetPoly(AIndex: Int32): IMlKemPoly;

    procedure Ntt;
    procedure InverseNttToMont;
    procedure Add(const AA: IMlKemPolyVec);
    procedure Reduce;
    procedure CompressPolyVec(const ABuf: TCryptoLibByteArray; AOff: Int32);
    procedure DecompressPolyVec(const ABuf: TCryptoLibByteArray; AOff: Int32);
    procedure FromBytes(const ABuf: TCryptoLibByteArray; AOff: Int32);
    procedure ToBytes(const ABuf: TCryptoLibByteArray; AOff: Int32);

    property K: Int32 read GetK;
  end;

  IMlKemIndCpa = interface(IInterface)
    ['{E0A6C3D4-5F7B-6A8C-1D2E-3F4A5B6C7D8E}']

    procedure GenerateKeyPair(const AD, AKp: TCryptoLibByteArray);
    procedure Decrypt(const AEncapsulation, ASk: TCryptoLibByteArray; AEncOff, ASkOff: Int32;
      const AMsg: TCryptoLibByteArray);
    procedure Encrypt(const APk, AMsg, ACoins: TCryptoLibByteArray;
      APkOff, AMsgOff, ACoinsOff: Int32; const AEncapsulation: TCryptoLibByteArray; AEncOff: Int32);
  end;

implementation

end.
