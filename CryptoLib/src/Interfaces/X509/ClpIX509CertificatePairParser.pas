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

unit ClpIX509CertificatePairParser;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  Classes,
  ClpCryptoLibTypes,
  ClpIX509CertificatePair;

type
  /// <summary>
  /// Interface for X.509 certificate pair parser (cross certificate pairs).
  /// </summary>
  IX509CertificatePairParser = interface(IInterface)
    ['{B8C9D0E1-F234-5678-90AB-CDEF12345678}']

    /// <summary>
    /// Read a certificate pair from a byte array.
    /// </summary>
    function ReadCertificatePair(const AInput: TCryptoLibByteArray): IX509CertificatePair; overload;

    /// <summary>
    /// Read certificate pairs from a byte array.
    /// </summary>
    function ReadCertificatePairs(const AInput: TCryptoLibByteArray): TCryptoLibGenericArray<IX509CertificatePair>; overload;

    /// <summary>
    /// Read a certificate pair from a stream.
    /// </summary>
    function ReadCertificatePair(const AInStream: TStream): IX509CertificatePair; overload;

    /// <summary>
    /// Read certificate pairs from a stream.
    /// </summary>
    function ReadCertificatePairs(const AInStream: TStream): TCryptoLibGenericArray<IX509CertificatePair>; overload;
  end;

implementation

end.
