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

unit ClpIDigestInfo;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpIAlgorithmIdentifier,
  ClpIAsn1Objects,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// Interface for the DigestInfo object.
  /// DigestInfo ::= SEQUENCE {
  ///   digestAlgorithm AlgorithmIdentifier,
  ///   digest OCTET STRING
  /// }
  /// </summary>
  IDigestInfo = interface(IAsn1Encodable)
    ['{A1B2C3D4-E5F6-7890-ABCD-0123456789AB}']

    function GetDigestAlgorithm: IAlgorithmIdentifier;
    function GetDigest: IAsn1OctetString;
    function GetDigestBytes: TCryptoLibByteArray;
    function GetDerEncoded: TCryptoLibByteArray;

    property DigestAlgorithm: IAlgorithmIdentifier read GetDigestAlgorithm;
    property Digest: IAsn1OctetString read GetDigest;

  end;

implementation

end.
