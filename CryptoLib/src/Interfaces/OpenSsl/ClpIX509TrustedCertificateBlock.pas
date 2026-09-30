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

unit ClpIX509TrustedCertificateBlock;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpIX509Certificate,
  ClpICertificateTrustBlock,
  ClpCryptoLibTypes;

type
  /// <summary>Holder for an OpenSSL trusted certificate block: a certificate paired with its trust
  /// metadata.</summary>
  IX509TrustedCertificateBlock = interface(IInterface)
    ['{D8B2F3C5-4E60-4B7D-8F9C-2A3B4C5D6E7F}']

    function GetCertificate: IX509Certificate;
    function GetTrustBlock: ICertificateTrustBlock;
    function GetEncoded: TCryptoLibByteArray;
  end;

implementation

end.
