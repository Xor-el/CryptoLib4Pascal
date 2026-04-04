{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                           Author - Ugochukwu Mmaduekwe                          * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }

{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }

{ *                              Acknowledgements:                                  * }
{ *                                                                                 * }
{ *      Thanks to Sphere 10 Software (http://www.sphere10.com/) for sponsoring     * }
{ *                           development of this library                           * }

{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit ClpIPkcs8EncryptedPrivateKeyInfo;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpIPkcsAsn1Objects,
  ClpIDecryptorBuilderProvider,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// A holding class for a PKCS#8 encrypted private key info object that allows for its decryption.
  /// </summary>
  IPkcs8EncryptedPrivateKeyInfo = interface(IInterface)
    ['{C7D8E9F0-A1B2-4C3D-8E5F-6A7B8C9D0E1F}']

    /// <summary>
    /// Returns the underlying ASN.1 structure inside this object.
    /// </summary>
    function ToAsn1Structure: IEncryptedPrivateKeyInfo;

    /// <summary>
    /// Returns a copy of the encrypted data in this structure.
    /// </summary>
    function GetEncryptedData: TCryptoLibByteArray;

    /// <summary>
    /// Return a binary ASN.1 encoding of the EncryptedPrivateKeyInfo structure in this object.
    /// </summary>
    function GetEncoded: TCryptoLibByteArray;

    /// <summary>
    /// Get a decryptor from the passed in provider and decrypt the encrypted private key info,
    /// returning the result.
    /// </summary>
    function DecryptPrivateKeyInfo(const AInputDecryptorProvider: IDecryptorBuilderProvider): IPrivateKeyInfo;
  end;

implementation

end.
