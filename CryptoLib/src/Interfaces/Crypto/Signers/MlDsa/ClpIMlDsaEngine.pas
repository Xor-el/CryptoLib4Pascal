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

unit ClpIMlDsaEngine;

{$I ..\..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpIMlDsaCore,
  ClpISecureRandom,
  ClpIXof,
  ClpCryptoLibTypes;

type
  IMlDsaEngine = interface(IInterface)
    ['{E6F70819-2A3B-4567-89AB-CDEF01234567}']

    function GetK: Int32;
    function GetL: Int32;
    function GetEta: Int32;
    function GetTau: Int32;
    function GetBeta: Int32;
    function GetGamma1: Int32;
    function GetGamma2: Int32;
    function GetOmega: Int32;
    function GetCTilde: Int32;
    function GetPolyVecHPackedBytes: Int32;
    function GetPolyZPackedBytes: Int32;
    function GetPolyW1PackedBytes: Int32;
    function GetPolyEtaPackedBytes: Int32;
    function GetCryptoPublicKeyBytes: Int32;
    function GetCryptoBytes: Int32;
    function GetPolyUniformGamma1NBytes: Int32;
    function GetSymmetric: IMlDsaSymmetric;

    procedure GenerateKeyPair(const ARandom: ISecureRandom; out ASeed: TCryptoLibByteArray;
      out ARho, AK, ATr, AS1, AS2, AT0, AEncT1: TCryptoLibByteArray);
    function DeriveT1(const ARho, AS1Enc, AS2Enc, AT0Enc: TCryptoLibByteArray): TCryptoLibByteArray;

    procedure MsgRepBegin(const ADigest: IXof; const ATr: TCryptoLibByteArray);
    function CreateMsgRepDigest: IXof;
    procedure MsgRepEndSign(const ADigest: IXof; var ASig: TCryptoLibByteArray; ASigLen: Int32;
      const ARho, AK, AT0Enc, AS1Enc, AS2Enc: TCryptoLibByteArray);
    function MsgRepEndVerify(const ADigest: IXof; const ASig: TCryptoLibByteArray; ASigLen: Int32;
      const ARho, AEncT1: TCryptoLibByteArray): Boolean;

    property K: Int32 read GetK;
    property L: Int32 read GetL;
    property Eta: Int32 read GetEta;
    property Tau: Int32 read GetTau;
    property Beta: Int32 read GetBeta;
    property Gamma1: Int32 read GetGamma1;
    property Gamma2: Int32 read GetGamma2;
    property Omega: Int32 read GetOmega;
    property CTilde: Int32 read GetCTilde;
    property PolyVecHPackedBytes: Int32 read GetPolyVecHPackedBytes;
    property PolyZPackedBytes: Int32 read GetPolyZPackedBytes;
    property PolyW1PackedBytes: Int32 read GetPolyW1PackedBytes;
    property PolyEtaPackedBytes: Int32 read GetPolyEtaPackedBytes;
    property CryptoPublicKeyBytes: Int32 read GetCryptoPublicKeyBytes;
    property CryptoBytes: Int32 read GetCryptoBytes;
    property PolyUniformGamma1NBytes: Int32 read GetPolyUniformGamma1NBytes;
    property Symmetric: IMlDsaSymmetric read GetSymmetric;
  end;

implementation

end.
