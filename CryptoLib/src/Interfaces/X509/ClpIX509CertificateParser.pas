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

unit ClpIX509CertificateParser;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  Classes,
  ClpCryptoLibTypes,
  ClpIX509Certificate;

type
  /// <summary>
  /// Interface for X.509 certificate parser.
  /// </summary>
  IX509CertificateParser = interface(IInterface)
    ['{B1119A4C-2901-4CC1-895E-6285385059F2}']

    /// <summary>
    /// Read a certificate from a byte array.
    /// </summary>
    /// <param name="AInput">The byte array containing the certificate</param>
    /// <returns>An X.509 certificate, or nil if no certificate found</returns>
    function ReadCertificate(const AInput: TCryptoLibByteArray): IX509Certificate; overload;

    /// <summary>
    /// Read certificates from a byte array.
    /// </summary>
    /// <param name="AInput">The byte array containing the certificates</param>
    /// <returns>A list of X.509 certificates</returns>
    function ReadCertificates(const AInput: TCryptoLibByteArray): TCryptoLibGenericArray<IX509Certificate>; overload;

    /// <summary>
    /// Read a certificate from a stream.
    /// </summary>
    /// <param name="AInStream">The input stream to read from</param>
    /// <returns>An X.509 certificate, or nil if no certificate found</returns>
    function ReadCertificate(const AInStream: TStream): IX509Certificate; overload;

    /// <summary>
    /// Read certificates from a stream.
    /// </summary>
    /// <param name="AInStream">The input stream to read from</param>
    /// <returns>A list of X.509 certificates</returns>
    function ReadCertificates(const AInStream: TStream): TCryptoLibGenericArray<IX509Certificate>; overload;

    /// <summary>
    /// Parse certificates from a stream (enumerable style).
    /// </summary>
    /// <param name="AInStream">The input stream to read from</param>
    /// <returns>An array of X.509 certificates</returns>
    function ParseCertificates(const AInStream: TStream): TCryptoLibGenericArray<IX509Certificate>;
  end;

implementation

end.
