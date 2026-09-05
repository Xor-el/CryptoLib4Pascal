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

unit ClpHpkeTypes;

{$I ..\..\Include\CryptoLib.inc}

{$SCOPEDENUMS ON}

interface

type
  /// <summary>
  /// HPKE operation modes (RFC 9180 sec. 5.1). The ordinal value is the wire
  /// mode identifier folded into the key schedule context.
  /// </summary>
  THpkeMode = (Base = $00, Psk = $01, Auth = $02, AuthPsk = $03);

  /// <summary>
  /// HPKE KEM identifiers (RFC 9180 sec. 7.1). The ordinal value is the IANA
  /// codepoint used in the suite id.
  /// </summary>
  THpkeKemId = (P256_SHA256 = 16, P384_SHA384 = 17, P521_SHA512 = 18,
    X25519_SHA256 = 32, X448_SHA512 = 33);

  /// <summary>
  /// HPKE KDF identifiers (RFC 9180 sec. 7.2).
  /// </summary>
  THpkeKdfId = (HkdfSha256 = 1, HkdfSha384 = 2, HkdfSha512 = 3);

  /// <summary>
  /// HPKE AEAD identifiers (RFC 9180 sec. 7.3). ExportOnly (0xFFFF) marks a
  /// suite that supports only secret export, never seal/open.
  /// </summary>
  THpkeAeadId = (AesGcm128 = 1, AesGcm256 = 2, ChaCha20Poly1305 = 3,
    ExportOnly = $FFFF);

implementation

end.
