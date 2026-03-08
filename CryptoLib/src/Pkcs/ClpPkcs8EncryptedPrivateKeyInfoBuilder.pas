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

unit ClpPkcs8EncryptedPrivateKeyInfoBuilder;

{$I ..\Include\CryptoLib.inc}

interface

uses
  Classes,
  SysUtils,
  ClpIPkcs8EncryptedPrivateKeyInfo,
  ClpPkcs8EncryptedPrivateKeyInfo,
  ClpIPkcsAsn1Objects,
  ClpPkcsAsn1Objects,
  ClpIX509Asn1Objects,
  ClpICipherBuilder,
  ClpICipher,
  ClpIAsn1Core,
  ClpAsn1Objects,
  ClpIAsn1Objects,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// Builder for PKCS#8 EncryptedPrivateKeyInfo.
  /// </summary>
  TPkcs8EncryptedPrivateKeyInfoBuilder = class sealed(TObject)
  strict private
    FPrivateKeyInfo: IPrivateKeyInfo;

  public
    /// <summary>
    /// Create a builder from a BER encoding of PrivateKeyInfo.
    /// </summary>
    constructor Create(const APrivateKeyInfo: TCryptoLibByteArray); overload;

    /// <summary>
    /// Create a builder from a PrivateKeyInfo instance.
    /// </summary>
    constructor Create(const APrivateKeyInfo: IPrivateKeyInfo); overload;

    /// <summary>
    /// Create the encrypted private key info using the passed in encryptor.
    /// </summary>
    /// <param name="AEncryptor">The encryptor to use.</param>
    /// <returns>An encrypted private key info containing the original private key info.</returns>
    function Build(const AEncryptor: ICipherBuilder): IPkcs8EncryptedPrivateKeyInfo;
  end;

implementation

{ TPkcs8EncryptedPrivateKeyInfoBuilder }

constructor TPkcs8EncryptedPrivateKeyInfoBuilder.Create(const APrivateKeyInfo: TCryptoLibByteArray);
begin
  Create(TPrivateKeyInfo.GetInstance(APrivateKeyInfo));
end;

constructor TPkcs8EncryptedPrivateKeyInfoBuilder.Create(const APrivateKeyInfo: IPrivateKeyInfo);
begin
  inherited Create();
  if APrivateKeyInfo = nil then
    raise EArgumentNilCryptoLibException.Create('privateKeyInfo');
  FPrivateKeyInfo := APrivateKeyInfo;
end;

function TPkcs8EncryptedPrivateKeyInfoBuilder.Build(const AEncryptor: ICipherBuilder): IPkcs8EncryptedPrivateKeyInfo;
var
  LEncryptionAlgorithm: IAlgorithmIdentifier;
  LOutputStream: TMemoryStream;
  LCipher: ICipher;
  LEncryptedBytes: TCryptoLibByteArray;
  LEncryptedData: IAsn1OctetString;
  LEncryptedPrivateKeyInfo: IEncryptedPrivateKeyInfo;
begin
  try
    LEncryptionAlgorithm := AEncryptor.AlgorithmDetails;

    LOutputStream := TMemoryStream.Create();
    try
      LCipher := AEncryptor.BuildCipher(LOutputStream);

      FPrivateKeyInfo.EncodeTo(LCipher.Stream);

      if LOutputStream.Size > 0 then
      begin
        SetLength(LEncryptedBytes, LOutputStream.Size);
        LOutputStream.Position := 0;
        LOutputStream.ReadBuffer(LEncryptedBytes[0], LOutputStream.Size);
      end
      else
        LEncryptedBytes := nil;

      LEncryptedData := TDerOctetString.WithContents(LEncryptedBytes);
      LEncryptedPrivateKeyInfo := TEncryptedPrivateKeyInfo.Create(LEncryptionAlgorithm, LEncryptedData);
      Result := TPkcs8EncryptedPrivateKeyInfo.Create(LEncryptedPrivateKeyInfo);
    finally
      LOutputStream.Free;
    end;
  except
    on E: Exception do
      raise EInvalidOperationCryptoLibException.Create('cannot encode privateKeyInfo');
  end;
end;

end.
