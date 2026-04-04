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

unit ClpEncryptedPrivateKeyInfoFactory;

{$I ..\Include\CryptoLib.inc}

interface

uses
  Rtti,
  SysUtils,
  ClpValueHelper,
  ClpAsn1Objects,
  ClpIAsn1Objects,
  ClpIAsn1Core,
  ClpIX509Asn1Objects,
  ClpX509Asn1Objects,
  ClpIPkcsAsn1Objects,
  ClpPkcsAsn1Objects,
  ClpPkcsObjectIdentifiers,
  ClpIAsymmetricKeyParameter,
  ClpIBufferedCipher,
  ClpICipherParameters,
  ClpPrivateKeyInfoFactory,
  ClpPbeUtilities,
  ClpCipherUtilities,
  ClpISecureRandom,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// Factory for creating EncryptedPrivateKeyInfo structures.
  /// </summary>
  TEncryptedPrivateKeyInfoFactory = class sealed(TObject)
  public
    /// <summary>
    /// Create an EncryptedPrivateKeyInfo from an OID algorithm, passphrase, salt,
    /// iteration count, and asymmetric key parameter.
    /// </summary>
    class function CreateEncryptedPrivateKeyInfo(
      const AAlgorithm: IDerObjectIdentifier;
      const APassPhrase: TCryptoLibCharArray;
      const ASalt: TCryptoLibByteArray;
      AIterationCount: Int32;
      const AKey: IAsymmetricKeyParameter): IEncryptedPrivateKeyInfo; overload; static;

    /// <summary>
    /// Create an EncryptedPrivateKeyInfo from a string algorithm, passphrase, salt,
    /// iteration count, and asymmetric key parameter.
    /// </summary>
    class function CreateEncryptedPrivateKeyInfo(
      const AAlgorithm: String;
      const APassPhrase: TCryptoLibCharArray;
      const ASalt: TCryptoLibByteArray;
      AIterationCount: Int32;
      const AKey: IAsymmetricKeyParameter): IEncryptedPrivateKeyInfo; overload; static;

    /// <summary>
    /// Create an EncryptedPrivateKeyInfo from a string algorithm, passphrase, salt,
    /// iteration count, and PrivateKeyInfo.
    /// </summary>
    class function CreateEncryptedPrivateKeyInfo(
      const AAlgorithm: String;
      const APassPhrase: TCryptoLibCharArray;
      const ASalt: TCryptoLibByteArray;
      AIterationCount: Int32;
      const AKeyInfo: IPrivateKeyInfo): IEncryptedPrivateKeyInfo; overload; static;

    /// <summary>
    /// Create an EncryptedPrivateKeyInfo using PBES2 with explicit cipher and PRF algorithm OIDs,
    /// passphrase, salt, iteration count, random, and asymmetric key parameter.
    /// </summary>
    class function CreateEncryptedPrivateKeyInfo(
      const ACipherAlgorithm: IDerObjectIdentifier;
      const APrfAlgorithm: IDerObjectIdentifier;
      const APassPhrase: TCryptoLibCharArray;
      const ASalt: TCryptoLibByteArray;
      AIterationCount: Int32;
      const ARandom: ISecureRandom;
      const AKey: IAsymmetricKeyParameter): IEncryptedPrivateKeyInfo; overload; static;

    /// <summary>
    /// Create an EncryptedPrivateKeyInfo using PBES2 with explicit cipher and PRF algorithm OIDs,
    /// passphrase, salt, iteration count, random, and PrivateKeyInfo.
    /// </summary>
    class function CreateEncryptedPrivateKeyInfo(
      const ACipherAlgorithm: IDerObjectIdentifier;
      const APrfAlgorithm: IDerObjectIdentifier;
      const APassPhrase: TCryptoLibCharArray;
      const ASalt: TCryptoLibByteArray;
      AIterationCount: Int32;
      const ARandom: ISecureRandom;
      const AKeyInfo: IPrivateKeyInfo): IEncryptedPrivateKeyInfo; overload; static;
  end;

implementation

{ TEncryptedPrivateKeyInfoFactory }

class function TEncryptedPrivateKeyInfoFactory.CreateEncryptedPrivateKeyInfo(
  const AAlgorithm: IDerObjectIdentifier;
  const APassPhrase: TCryptoLibCharArray;
  const ASalt: TCryptoLibByteArray;
  AIterationCount: Int32;
  const AKey: IAsymmetricKeyParameter): IEncryptedPrivateKeyInfo;
begin
  Result := CreateEncryptedPrivateKeyInfo(
    AAlgorithm.Id, APassPhrase, ASalt, AIterationCount,
    TPrivateKeyInfoFactory.CreatePrivateKeyInfo(AKey));
end;

class function TEncryptedPrivateKeyInfoFactory.CreateEncryptedPrivateKeyInfo(
  const AAlgorithm: String;
  const APassPhrase: TCryptoLibCharArray;
  const ASalt: TCryptoLibByteArray;
  AIterationCount: Int32;
  const AKey: IAsymmetricKeyParameter): IEncryptedPrivateKeyInfo;
begin
  Result := CreateEncryptedPrivateKeyInfo(
    AAlgorithm, APassPhrase, ASalt, AIterationCount,
    TPrivateKeyInfoFactory.CreatePrivateKeyInfo(AKey));
end;

class function TEncryptedPrivateKeyInfoFactory.CreateEncryptedPrivateKeyInfo(
  const AAlgorithm: String;
  const APassPhrase: TCryptoLibCharArray;
  const ASalt: TCryptoLibByteArray;
  AIterationCount: Int32;
  const AKeyInfo: IPrivateKeyInfo): IEncryptedPrivateKeyInfo;
var
  LEngine: TValue;
  LCipher: IBufferedCipher;
  LPbeParameters: IAsn1Encodable;
  LCipherParameters: ICipherParameters;
  LEncoding: TCryptoLibByteArray;
  LOid: IDerObjectIdentifier;
  LEncryptionAlgorithm: IAlgorithmIdentifier;
  LEncryptedData: IDerOctetString;
begin
  LEngine := TPbeUtilities.CreateEngine(AAlgorithm);
  if not (LEngine.TryGetAsType<IBufferedCipher>(LCipher)) or (LCipher = nil) then
    raise ECryptoLibException.Create('Unknown encryption algorithm: ' + AAlgorithm);

  LPbeParameters := TPbeUtilities.GenerateAlgorithmParameters(
    AAlgorithm, ASalt, AIterationCount);
  LCipherParameters := TPbeUtilities.GenerateCipherParameters(
    AAlgorithm, APassPhrase, LPbeParameters);
  LCipher.Init(True, LCipherParameters);
  LEncoding := LCipher.DoFinal(AKeyInfo.GetEncoded());

  LOid := TPbeUtilities.GetObjectIdentifier(AAlgorithm);
  LEncryptionAlgorithm := TAlgorithmIdentifier.Create(LOid, LPbeParameters);
  LEncryptedData := TDerOctetString.FromContents(LEncoding);
  Result := TEncryptedPrivateKeyInfo.Create(LEncryptionAlgorithm, LEncryptedData) as IEncryptedPrivateKeyInfo;
end;

class function TEncryptedPrivateKeyInfoFactory.CreateEncryptedPrivateKeyInfo(
  const ACipherAlgorithm: IDerObjectIdentifier;
  const APrfAlgorithm: IDerObjectIdentifier;
  const APassPhrase: TCryptoLibCharArray;
  const ASalt: TCryptoLibByteArray;
  AIterationCount: Int32;
  const ARandom: ISecureRandom;
  const AKey: IAsymmetricKeyParameter): IEncryptedPrivateKeyInfo;
begin
  Result := CreateEncryptedPrivateKeyInfo(
    ACipherAlgorithm, APrfAlgorithm, APassPhrase, ASalt, AIterationCount, ARandom,
    TPrivateKeyInfoFactory.CreatePrivateKeyInfo(AKey));
end;

class function TEncryptedPrivateKeyInfoFactory.CreateEncryptedPrivateKeyInfo(
  const ACipherAlgorithm: IDerObjectIdentifier;
  const APrfAlgorithm: IDerObjectIdentifier;
  const APassPhrase: TCryptoLibCharArray;
  const ASalt: TCryptoLibByteArray;
  AIterationCount: Int32;
  const ARandom: ISecureRandom;
  const AKeyInfo: IPrivateKeyInfo): IEncryptedPrivateKeyInfo;
var
  LCipher: IBufferedCipher;
  LPbeParameters: IAsn1Encodable;
  LCipherParameters: ICipherParameters;
  LEncoding: TCryptoLibByteArray;
  LEncryptionAlgorithm: IAlgorithmIdentifier;
  LEncryptedData: IDerOctetString;
begin
  LCipher := TCipherUtilities.GetCipher(ACipherAlgorithm);
  if LCipher = nil then
    raise ECryptoLibException.Create('Unknown encryption algorithm: ' + ACipherAlgorithm.Id);

  LPbeParameters := TPbeUtilities.GenerateAlgorithmParameters(
    ACipherAlgorithm, APrfAlgorithm, ASalt, AIterationCount, ARandom);
  LCipherParameters := TPbeUtilities.GenerateCipherParameters(
    TPkcsObjectIdentifiers.IdPbeS2, APassPhrase, LPbeParameters);
  LCipher.Init(True, LCipherParameters);
  LEncoding := LCipher.DoFinal(AKeyInfo.GetEncoded());

  LEncryptionAlgorithm := TAlgorithmIdentifier.Create(TPkcsObjectIdentifiers.IdPbeS2, LPbeParameters);
  LEncryptedData := TDerOctetString.FromContents(LEncoding);
  Result := TEncryptedPrivateKeyInfo.Create(LEncryptionAlgorithm, LEncryptedData);
end;

end.
