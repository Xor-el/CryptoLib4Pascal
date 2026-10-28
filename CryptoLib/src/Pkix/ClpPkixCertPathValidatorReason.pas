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

unit ClpPkixCertPathValidatorReason;

{$I ..\Include\CryptoLib.inc}

interface

type
  /// <summary>Why certification path validation failed (RFC 5280), for programmatic handling.</summary>
  TPkixCertPathValidatorReason = (Unspecified, Expired, NotYetValid, Revoked,
    UndeterminedRevocationStatus, InvalidSignature, AlgorithmConstrained, NameChaining,
    InvalidKeyUsage, InvalidPolicy, NoTrustAnchor, UnrecognizedCriticalExtension, NotCACertificate,
    PathTooLong, InvalidName, LimitExceeded);

implementation

end.
