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

unit ClpIMlKemEngine;

{$I ..\..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpISecureRandom,
  ClpCryptoLibTypes;

type
  IMlKemEngine = interface(IInterface)
    ['{8683833B-4F0C-4DD6-B117-F96CACB9E7C0}']

    function GetK: Int32;
    function GetPolyVecBytes: Int32;
    function GetPolyCompressedBytes: Int32;
    function GetPolyVecCompressedBytes: Int32;
    function GetEta1: Int32;
    function GetIndCpaPublicKeyBytes: Int32;
    function GetIndCpaSecretKeyBytes: Int32;
    function GetPublicKeyBytes: Int32;
    function GetSecretKeyBytes: Int32;
    function GetCipherTextBytes: Int32;

    function CheckDecapKeyHash(const ADecapKey: TCryptoLibByteArray): Boolean;
    function CheckEncapKeyModulus(const AEncapKey: TCryptoLibByteArray): Boolean;
    function CopyEncapKey(const ADecapKey: TCryptoLibByteArray): TCryptoLibByteArray;

    procedure GenerateKemKeyPair(const ARandom: ISecureRandom;
      out ASeed, AEncoding: TCryptoLibByteArray);

    procedure KemDecrypt(const ADecapKey, AEncBuf: TCryptoLibByteArray; AEncOff: Int32;
      const ASecBuf: TCryptoLibByteArray; ASecOff: Int32);
    procedure KemEncrypt(const AEncapKey, ARandBytes: TCryptoLibByteArray;
      const AEncBuf: TCryptoLibByteArray; AEncOff: Int32;
      const ASecBuf: TCryptoLibByteArray; ASecOff: Int32);

    property K: Int32 read GetK;
    property PolyVecBytes: Int32 read GetPolyVecBytes;
    property PolyCompressedBytes: Int32 read GetPolyCompressedBytes;
    property PolyVecCompressedBytes: Int32 read GetPolyVecCompressedBytes;
    property Eta1: Int32 read GetEta1;
    property IndCpaPublicKeyBytes: Int32 read GetIndCpaPublicKeyBytes;
    property IndCpaSecretKeyBytes: Int32 read GetIndCpaSecretKeyBytes;
    property PublicKeyBytes: Int32 read GetPublicKeyBytes;
    property SecretKeyBytes: Int32 read GetSecretKeyBytes;
    property CipherTextBytes: Int32 read GetCipherTextBytes;
  end;

implementation

end.
