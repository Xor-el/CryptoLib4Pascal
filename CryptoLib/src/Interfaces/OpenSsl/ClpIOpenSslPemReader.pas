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

unit ClpIOpenSslPemReader;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  Rtti,
  ClpIPemReader;

type
  /// <summary>
  /// Interface for OpenSSL PEM reader. Read OpenSSL PEM encoded streams containing
  /// X509 certificates, PKCS#8 encoded keys and PKCS#7/CMS objects; returns typed
  /// values as TValue (e.g. IX509Certificate, IAsymmetricKeyParameter, IAsymmetricCipherKeyPair).
  /// </summary>
  IOpenSslPemReader = interface(IPemReader)
    ['{068FE91C-61DC-43D9-B75B-5D8A04F86647}']
    function ReadObject(): TValue;
  end;

implementation

end.
