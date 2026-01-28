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

unit ClpIAttributeCertificateHolder;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpIAsn1Objects,
  ClpIX509Asn1Objects,
  ClpIX509Certificate,
  ClpBigInteger,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// The Holder object for attribute certificates.
  /// </summary>
  IAttributeCertificateHolder = interface
    ['{C2D3E4F5-A6B7-8901-CDEF-234567890ABC}']

    function GetDigestedObjectType: Int32;
    function GetDigestAlgorithm: String;
    function GetObjectDigest: TCryptoLibByteArray;
    function GetOtherObjectTypeID: String;
    function GetHolder: IHolder;
    function GetSerialNumber: TBigInteger;

    function GetEntityNames: TCryptoLibGenericArray<IX509Name>;
    function GetIssuer: TCryptoLibGenericArray<IX509Name>;
    function Clone: IAttributeCertificateHolder;
    function Match(const AX509Cert: IX509Certificate): Boolean;
    function Equals(const AOther: IAttributeCertificateHolder): Boolean;

    property DigestedObjectType: Int32 read GetDigestedObjectType;
    property DigestAlgorithm: String read GetDigestAlgorithm;
    property OtherObjectTypeID: String read GetOtherObjectTypeID;
    property SerialNumber: TBigInteger read GetSerialNumber;
    property Holder: IHolder read GetHolder;
  end;

implementation

end.

