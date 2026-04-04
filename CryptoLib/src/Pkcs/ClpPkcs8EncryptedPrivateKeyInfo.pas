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

unit ClpPkcs8EncryptedPrivateKeyInfo;

{$I ..\Include\CryptoLib.inc}

interface

uses
  Classes,
  SysUtils,
  ClpIPkcs8EncryptedPrivateKeyInfo,
  ClpIPkcsAsn1Objects,
  ClpPkcsAsn1Objects,
  ClpICipher,
  ClpICipherBuilder,
  ClpIDecryptorBuilderProvider,
  ClpStreamUtilities,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// A holding class for a PKCS#8 encrypted private key info object that allows for its decryption.
  /// </summary>
  TPkcs8EncryptedPrivateKeyInfo = class(TInterfacedObject, IPkcs8EncryptedPrivateKeyInfo)
  strict private
    FEncryptedPrivateKeyInfo: IEncryptedPrivateKeyInfo;

    class function ParseBytes(const APkcs8Encoding: TCryptoLibByteArray): IEncryptedPrivateKeyInfo; static;

  public
    /// <summary>
    /// Base constructor from a PKCS#8 EncryptedPrivateKeyInfo object.
    /// </summary>
    constructor Create(const AEncryptedPrivateKeyInfo: IEncryptedPrivateKeyInfo); overload;

    /// <summary>
    /// Base constructor from a BER encoding of a PKCS#8 EncryptedPrivateKeyInfo object.
    /// </summary>
    constructor Create(const AEncryptedPrivateKeyInfo: TCryptoLibByteArray); overload;

    function ToAsn1Structure: IEncryptedPrivateKeyInfo;
    function GetEncryptedData: TCryptoLibByteArray;
    function GetEncoded: TCryptoLibByteArray;
    function DecryptPrivateKeyInfo(const AInputDecryptorProvider: IDecryptorBuilderProvider): IPrivateKeyInfo;
  end;

implementation

{ TPkcs8EncryptedPrivateKeyInfo }

class function TPkcs8EncryptedPrivateKeyInfo.ParseBytes(
  const APkcs8Encoding: TCryptoLibByteArray): IEncryptedPrivateKeyInfo;
begin
  try
    Result := TEncryptedPrivateKeyInfo.GetInstance(APkcs8Encoding);
  except
    on E: EArgumentCryptoLibException do
      raise EPkcsIOCryptoLibException.Create('malformed data: ' + E.Message);
    on E: Exception do
      raise EPkcsIOCryptoLibException.Create('malformed data: ' + E.Message);
  end;
end;

constructor TPkcs8EncryptedPrivateKeyInfo.Create(const AEncryptedPrivateKeyInfo: IEncryptedPrivateKeyInfo);
begin
  inherited Create();
  FEncryptedPrivateKeyInfo := AEncryptedPrivateKeyInfo;
end;

constructor TPkcs8EncryptedPrivateKeyInfo.Create(const AEncryptedPrivateKeyInfo: TCryptoLibByteArray);
begin
  Create(ParseBytes(AEncryptedPrivateKeyInfo));
end;

function TPkcs8EncryptedPrivateKeyInfo.ToAsn1Structure: IEncryptedPrivateKeyInfo;
begin
  Result := FEncryptedPrivateKeyInfo;
end;

function TPkcs8EncryptedPrivateKeyInfo.GetEncryptedData: TCryptoLibByteArray;
begin
  Result := FEncryptedPrivateKeyInfo.GetEncryptedDataBytes();
end;

function TPkcs8EncryptedPrivateKeyInfo.GetEncoded: TCryptoLibByteArray;
begin
  Result := FEncryptedPrivateKeyInfo.GetEncoded();
end;

function TPkcs8EncryptedPrivateKeyInfo.DecryptPrivateKeyInfo(
  const AInputDecryptorProvider: IDecryptorBuilderProvider): IPrivateKeyInfo;
var
  LDecryptorBuilder: ICipherBuilder;
  LEncIn: ICipher;
  LData: TCryptoLibByteArray;
  LSourceStream: TBytesStream;
  LEncryptedData: TCryptoLibByteArray;
begin
  try
    LDecryptorBuilder := AInputDecryptorProvider.CreateDecryptorBuilder(
      FEncryptedPrivateKeyInfo.EncryptionAlgorithm);

    LEncryptedData := FEncryptedPrivateKeyInfo.GetEncryptedDataBytes();
    LSourceStream := TBytesStream.Create(LEncryptedData);
    try
      LEncIn := LDecryptorBuilder.BuildCipher(LSourceStream);

      LData := TStreamUtilities.ReadAll(LEncIn.Stream);

      Result := TPrivateKeyInfo.GetInstance(LData);
    finally
      LSourceStream.Free;
    end;
  except
    on E: Exception do
      raise EPkcsCryptoLibException.Create('unable to read encrypted data: ' + E.Message);
  end;
end;

end.
