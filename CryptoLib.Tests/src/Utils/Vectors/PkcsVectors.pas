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

unit PkcsVectors;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  SysUtils,
  ClpCryptoLibTypes,
  ClpEncoders,
  CsvVectorParser,
  CsvVectorLoaderBase;

type
  TPkcs10Vectors = class sealed
  strict private
    class function DecodeRequest(const ABase64: string): TCryptoLibByteArray; static;
  public
    class function LoadRequestBytes(const AVectorId: string): TCryptoLibByteArray; static;
  end;

  TPkcs12StoreVectors = class sealed
  strict private
    class var
      FTable: TCsvVectorTable;
  public
    class function LoadStoreBytes(const AFixtureId: string): TCryptoLibByteArray; static;
    class function GetPassword(const AFixtureId: string): string; static;
    class constructor Create;
  end;

  TPkcsEncryptedPrivateKeyInfoVectors = class sealed
  strict private
    class var
      FTable: TCsvVectorTable;
  public
    class function LoadKeyBytes(const AVectorId: string): TCryptoLibByteArray; static;
    class function GetPassword(const AVectorId: string): string; static;
    class constructor Create;
  end;

implementation

const
  BasicCrRequestB64 =
    'MIHoMIGTAgEAMC4xDjAMBgNVBAMTBVRlc3QyMQ8wDQYDVQQKEwZBbmFUb20xCzAJBgNVBAYTAlNFMFww' +
    'DQYJKoZIhvcNAQEBBQADSwAwSAJBALlEt31Tzt2MlcOljvacJgzQVhmlMoqAOgqJ9Pgd3GuxZ7/WcIlg' +
    'W4QCB7WZT21O1YoghwBhPDMcNGrHei9kHQkCAwEAAaAAMA0GCSqGSIb3DQEBBQUAA0EANDEI4ecNtJ3u' +
    'HwGGlitNFq9WxcoZ0djbQJ5hABMotav6gtqlrwKXY2evaIrsNwkJtNdwwH18aQDUKCjOuBL38Q==';
  UniversalCrRequestB64 =
    'MIIB6TCCAVICAQAwgagxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMRQwEgYDVQQHEwtT' +
    'YW50YSBDbGFyYTEMMAoGA1UEChMDQUJCMVEwTwYDVQQLHEhQAAAAAAAAAG8AAAAAAAAAdwAAAAAAAABl' +
    'AAAAAAAAAHIAAAAAAAAAIAAAAAAAAABUAAAAAAAAABxIAAAAAAAARAAAAAAAAAAxDTALBgNVBAMTBGJs' +
    'dWUwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBANETRZ+6occCOrFxNhfKIp4CmMkxwhBNb7Tnn' +
    'ahpbM9O0r4hrBPcfYuL7u9YX/jN0YNUP+/CiT39HhSe/bikaBPDEyNsl988I8vXpiEdgxYq/+LTgGH' +
    'bjRsRYCkPtmzwBbuBldNF8bV7pu0v4UScSsExmGqqDlX1TbPU8KkPU1iTAgMBAAGgADANBgkqhkiG9' +
    'w0BAQQFAAOBgQAFbrs9qUwh93CtETk7DeUD5HcdCnxauo1bck44snSV6MZVOCIGaYu1501kmhEvAtV' +
    'VRr6SEHwimfQDDIjnrWwYsEr/DT6tkTZAbfRd3qUu3iKjT0H0vlUZp0hJ66mINtBM84uZFBfoXiWY8' +
    'M3FuAnGmvy6ah/dYtJorTxLKiGkew==';
  EmptyExtensionsRequestB64 =
    'MIICVDCCATwCAQAwADCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKy84oC/QPFkRBE04LIA' +
    '5njEulZx/EEh+J2spnThoRwk+oycYEVKp95NSfGTAoNjTwUvTdB9c1PCPE1DmgZIVLEVvouB7sZbMb' +
    'LSI0d//oMO/Wr/CZmvjPGB8DID7RJs0eqOgLgSuyBVrwbcSKtxH4NrNDsS5IZXCcE3xzkxMDdz72m9' +
    'jvIrl2ivi+YmJ7cJo3N+DBEqHZW28oytOmVo+8zhxvnHb9w26GJEOxN5zYbiIVW2vU9OfeF9te+Rhn' +
    'ks43PkYDDP2U4hR7q0BYrdkeWdA1ReleYyn/haeAoIVLZMANIOXobiqASKqSusVq9tLD677TAywl5A' +
    'Vq8GOBzlXZUCAwEAAaAPMA0GCSqGSIb3DQEJDjEAMA0GCSqGSIb3DQEBCwUAA4IBAQAXck62gJw1de' +
    'VOLVFAwBNVNXgJarHtDg3pauHTHvN+pSbdOTe1aRzbTt4/govtuuGZsGWlUqiglLpl6qeS7Pe9m+WJ' +
    'whH5yXnJ3yvy2Lc/XkeVQ0kt8uFg30UyrgKng6LDgUGFjDSiFr3dK8S/iYpDu/qpl1bWJPWmfmnIXz' +
    'ZWWvBdUTKlfoD9/NLIWINEzHQIBXGy2uLhutYOvDq0WDGOgtdFC8my/QajaJh5lo6mM/PlmcYjK286' +
    'EdGSIxdME7hoW/ljA5355S820QZDkYx1tI/Y/YaY5KVOntwfDQzQiwWZ2PtpTqSKKYe2Ujb362yaER' +
    'CE13DJC4Us9j8OOXcW';

{ TPkcs10Vectors }

class function TPkcs10Vectors.DecodeRequest(const ABase64: string): TCryptoLibByteArray;
begin
  Result := TBase64Encoder.Decode(ABase64);
end;

class function TPkcs10Vectors.LoadRequestBytes(const AVectorId: string): TCryptoLibByteArray;
begin
  if SameText(AVectorId, 'BasicCr') then
    Exit(DecodeRequest(BasicCrRequestB64));
  if SameText(AVectorId, 'UniversalCr') then
    Exit(DecodeRequest(UniversalCrRequestB64));
  if SameText(AVectorId, 'EmptyExtensions') then
    Exit(DecodeRequest(EmptyExtensionsRequestB64));
  raise Exception.CreateFmt('Unknown PKCS#10 vector: %s', [AVectorId]);
end;

{ TPkcs12StoreVectors }

class function TPkcs12StoreVectors.LoadStoreBytes(const AFixtureId: string)
  : TCryptoLibByteArray;
begin
  Result := TCsvVectorLoaderBase.LoadBytesById(FTable, 'FixtureId', AFixtureId, 'File',
    'Unknown PKCS#12 fixture: %s');
end;

class function TPkcs12StoreVectors.GetPassword(const AFixtureId: string): string;
begin
  Result := TCsvVectorLoaderBase.GetPasswordById(FTable, 'FixtureId', AFixtureId, 'Password',
    'Unknown PKCS#12 fixture: %s');
end;

class constructor TPkcs12StoreVectors.Create;
begin
  TCsvVectorLoaderBase.LoadCachedTable(FTable, 'Pkcs/Pkcs12Store/Manifest.csv');
end;

{ TPkcsEncryptedPrivateKeyInfoVectors }

class function TPkcsEncryptedPrivateKeyInfoVectors.LoadKeyBytes(const AVectorId: string)
  : TCryptoLibByteArray;
begin
  Result := TCsvVectorLoaderBase.LoadBytesById(FTable, 'VectorId', AVectorId, 'File',
    'Unknown EPKI vector: %s');
end;

class function TPkcsEncryptedPrivateKeyInfoVectors.GetPassword(const AVectorId: string): string;
begin
  Result := TCsvVectorLoaderBase.GetPasswordById(FTable, 'VectorId', AVectorId, 'Password',
    'Unknown EPKI vector: %s');
end;

class constructor TPkcsEncryptedPrivateKeyInfoVectors.Create;
begin
  TCsvVectorLoaderBase.LoadCachedTable(FTable, 'Pkcs/EncryptedPrivateKeyInfo/Manifest.csv');
end;

end.
