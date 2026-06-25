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
  /// <summary>Fluent builder for SP 800-90A DRBG-backed secure random instances.</summary>
  ISP800SecureRandomBuilder = interface(IInterface)
    ['{2A9D4E71-6B83-4F15-A8C2-9E3F5D7B4A10}']

    function SetPersonalizationString(
      const APersonalizationString: TCryptoLibByteArray): ISP800SecureRandomBuilder;
    function SetSecurityStrength(
      ASecurityStrength: Int32): ISP800SecureRandomBuilder;
    function SetEntropyBitsRequired(
      AEntropyBitsRequired: Int32): ISP800SecureRandomBuilder;

    function BuildHash(const ADigest: IDigest; const ANonce: TCryptoLibByteArray;
      APredictionResistant: Boolean): ISecureRandom;
    function BuildCtr(const ACipher: IBlockCipher; AKeySizeInBits: Int32;
      const ANonce: TCryptoLibByteArray;
      APredictionResistant: Boolean): ISecureRandom;
    function BuildHMac(const AHMac: IMac; const ANonce: TCryptoLibByteArray;
      APredictionResistant: Boolean): ISecureRandom;
  end;

implementation

end.
