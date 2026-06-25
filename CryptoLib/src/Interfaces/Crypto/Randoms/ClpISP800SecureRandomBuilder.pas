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

unit ClpISP800SecureRandomBuilder;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpCryptoLibTypes,
  ClpIDigest,
  ClpIMac,
  ClpIBlockCipher,
  ClpISecureRandom;

type
  /// <summary>
  /// Fluent builder for <see cref="ISecureRandom"/> instances based on SP 800-90A
  /// deterministic random bit generators.
  /// </summary>
  ISP800SecureRandomBuilder = interface(IInterface)
    ['{2A9D4E71-6B83-4F15-A8C2-9E3F5D7B4A10}']

    /// <summary>
    /// Set the personalization string for DRBGs created by this builder.
    /// </summary>
    /// <param name="APersonalizationString">
    /// Personalization string for the underlying DRBG, or <c>nil</c>.
    /// </param>
    /// <returns>This builder instance.</returns>
    function SetPersonalizationString(
      const APersonalizationString: TCryptoLibByteArray): ISP800SecureRandomBuilder;

    /// <summary>
    /// Set the security strength required for DRBGs used when building
    /// <see cref="ISecureRandom"/> instances.
    /// </summary>
    /// <param name="ASecurityStrength">Security strength in bits.</param>
    /// <returns>This builder instance.</returns>
    function SetSecurityStrength(
      ASecurityStrength: Int32): ISP800SecureRandomBuilder;

    /// <summary>
    /// Set the amount of entropy (in bits) requested from the entropy source on
    /// each seed or reseed.
    /// </summary>
    /// <param name="AEntropyBitsRequired">Entropy bits per seed/reseed operation.</param>
    /// <returns>This builder instance.</returns>
    function SetEntropyBitsRequired(
      AEntropyBitsRequired: Int32): ISP800SecureRandomBuilder;

    /// <summary>
    /// Build a <see cref="ISecureRandom"/> backed by a SP 800-90A Hash DRBG.
    /// </summary>
    /// <param name="ADigest">Digest algorithm for the underlying DRBG.</param>
    /// <param name="ANonce">Nonce value used in DRBG construction.</param>
    /// <param name="APredictionResistant">
    /// If <c>true</c>, the underlying DRBG reseeds on each byte request.
    /// </param>
    /// <returns>A secure random supported by a Hash DRBG.</returns>
    function BuildHash(const ADigest: IDigest; const ANonce: TCryptoLibByteArray;
      APredictionResistant: Boolean): ISecureRandom;

    /// <summary>
    /// Build a <see cref="ISecureRandom"/> backed by a SP 800-90A CTR DRBG.
    /// </summary>
    /// <param name="ACipher">Block cipher for the underlying DRBG.</param>
    /// <param name="AKeySizeInBits">Key size in bits for the block cipher.</param>
    /// <param name="ANonce">Nonce value used in DRBG construction.</param>
    /// <param name="APredictionResistant">
    /// If <c>true</c>, the underlying DRBG reseeds on each byte request.
    /// </param>
    /// <returns>A secure random supported by a CTR DRBG.</returns>
    function BuildCtr(const ACipher: IBlockCipher; AKeySizeInBits: Int32;
      const ANonce: TCryptoLibByteArray;
      APredictionResistant: Boolean): ISecureRandom;

    /// <summary>
    /// Build a <see cref="ISecureRandom"/> backed by a SP 800-90A HMAC DRBG.
    /// </summary>
    /// <param name="AHMac">HMAC instance for the underlying DRBG.</param>
    /// <param name="ANonce">Nonce value used in DRBG construction.</param>
    /// <param name="APredictionResistant">
    /// If <c>true</c>, the underlying DRBG reseeds on each byte request.
    /// </param>
    /// <returns>A secure random supported by an HMAC DRBG.</returns>
    function BuildHMac(const AHMac: IMac; const ANonce: TCryptoLibByteArray;
      APredictionResistant: Boolean): ISecureRandom;
  end;

implementation

end.
