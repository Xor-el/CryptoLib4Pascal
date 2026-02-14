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

unit ClpCmsObjectIdentifiers;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpPkcsObjectIdentifiers,
  ClpX509ObjectIdentifiers,
  ClpIAsn1Objects;

type
  /// <summary>
  /// CMS Object Identifiers (RFC 3852, etc.); delegates to PKCS and X.509 OIDs.
  /// </summary>
  TCmsObjectIdentifiers = class sealed(TObject)

  strict private
    class var
    FData: IDerObjectIdentifier;
    FSignedData: IDerObjectIdentifier;
    FEnvelopedData: IDerObjectIdentifier;
    FSignedAndEnvelopedData: IDerObjectIdentifier;
    FDigestedData: IDerObjectIdentifier;
    FEncryptedData: IDerObjectIdentifier;
    FAuthenticatedData: IDerObjectIdentifier;
    FCompressedData: IDerObjectIdentifier;
    FAuthEnvelopedData: IDerObjectIdentifier;
    FTimestampedData: IDerObjectIdentifier;
    FZlibCompress: IDerObjectIdentifier;
    FIdRi: IDerObjectIdentifier;
    FIdRiOcspResponse: IDerObjectIdentifier;
    FIdRiScvp: IDerObjectIdentifier;
    FIdAlg: IDerObjectIdentifier;
    FIdRsassaPssShake128: IDerObjectIdentifier;
    FIdRsassaPssShake256: IDerObjectIdentifier;
    FIdEcdsaWithShake128: IDerObjectIdentifier;
    FIdEcdsaWithShake256: IDerObjectIdentifier;
    FIdOri: IDerObjectIdentifier;
    FIdOriKem: IDerObjectIdentifier;
    FIdAlgCekHkdfSha256: IDerObjectIdentifier;

    class function GetData: IDerObjectIdentifier; static; inline;
    class function GetSignedData: IDerObjectIdentifier; static; inline;
    class function GetEnvelopedData: IDerObjectIdentifier; static; inline;
    class function GetSignedAndEnvelopedData: IDerObjectIdentifier; static; inline;
    class function GetDigestedData: IDerObjectIdentifier; static; inline;
    class function GetEncryptedData: IDerObjectIdentifier; static; inline;
    class function GetAuthenticatedData: IDerObjectIdentifier; static; inline;
    class function GetCompressedData: IDerObjectIdentifier; static; inline;
    class function GetAuthEnvelopedData: IDerObjectIdentifier; static; inline;
    class function GetTimestampedData: IDerObjectIdentifier; static; inline;
    class function GetZlibCompress: IDerObjectIdentifier; static; inline;
    class function GetIdRi: IDerObjectIdentifier; static; inline;
    class function GetIdRiOcspResponse: IDerObjectIdentifier; static; inline;
    class function GetIdRiScvp: IDerObjectIdentifier; static; inline;
    class function GetIdAlg: IDerObjectIdentifier; static; inline;
    class function GetIdRsassaPssShake128: IDerObjectIdentifier; static; inline;
    class function GetIdRsassaPssShake256: IDerObjectIdentifier; static; inline;
    class function GetIdEcdsaWithShake128: IDerObjectIdentifier; static; inline;
    class function GetIdEcdsaWithShake256: IDerObjectIdentifier; static; inline;
    class function GetIdOri: IDerObjectIdentifier; static; inline;
    class function GetIdOriKem: IDerObjectIdentifier; static; inline;
    class function GetIdAlgCekHkdfSha256: IDerObjectIdentifier; static; inline;

    class procedure Boot(); static;
    class constructor CmsObjectIdentifiers();

  public
    class property Data: IDerObjectIdentifier read GetData;
    class property SignedData: IDerObjectIdentifier read GetSignedData;
    class property EnvelopedData: IDerObjectIdentifier read GetEnvelopedData;
    class property SignedAndEnvelopedData: IDerObjectIdentifier read GetSignedAndEnvelopedData;
    class property DigestedData: IDerObjectIdentifier read GetDigestedData;
    class property EncryptedData: IDerObjectIdentifier read GetEncryptedData;
    class property AuthenticatedData: IDerObjectIdentifier read GetAuthenticatedData;
    class property CompressedData: IDerObjectIdentifier read GetCompressedData;
    class property AuthEnvelopedData: IDerObjectIdentifier read GetAuthEnvelopedData;
    class property TimestampedData: IDerObjectIdentifier read GetTimestampedData;
    class property ZlibCompress: IDerObjectIdentifier read GetZlibCompress;

    class property IdRi: IDerObjectIdentifier read GetIdRi;

    class property IdRiOcspResponse: IDerObjectIdentifier read GetIdRiOcspResponse;
    class property IdRiScvp: IDerObjectIdentifier read GetIdRiScvp;

    class property IdAlg: IDerObjectIdentifier read GetIdAlg;

    class property IdRsassaPssShake128: IDerObjectIdentifier read GetIdRsassaPssShake128;
    class property IdRsassaPssShake256: IDerObjectIdentifier read GetIdRsassaPssShake256;
    class property IdEcdsaWithShake128: IDerObjectIdentifier read GetIdEcdsaWithShake128;
    class property IdEcdsaWithShake256: IDerObjectIdentifier read GetIdEcdsaWithShake256;

    class property IdOri: IDerObjectIdentifier read GetIdOri;
    class property IdOriKem: IDerObjectIdentifier read GetIdOriKem;

    class property IdAlgCekHkdfSha256: IDerObjectIdentifier read GetIdAlgCekHkdfSha256;
  end;

implementation

class procedure TCmsObjectIdentifiers.Boot;
begin
  FData := TPkcsObjectIdentifiers.Data;
  FSignedData := TPkcsObjectIdentifiers.SignedData;
  FEnvelopedData := TPkcsObjectIdentifiers.EnvelopedData;
  FSignedAndEnvelopedData := TPkcsObjectIdentifiers.SignedAndEnvelopedData;
  FDigestedData := TPkcsObjectIdentifiers.DigestedData;
  FEncryptedData := TPkcsObjectIdentifiers.EncryptedData;
  FAuthenticatedData := TPkcsObjectIdentifiers.IdCTAuthData;
  FCompressedData := TPkcsObjectIdentifiers.IdCTCompressedData;
  FAuthEnvelopedData := TPkcsObjectIdentifiers.IdCTAuthEnvelopedData;
  FTimestampedData := TPkcsObjectIdentifiers.IdCTTimestampedData;
  FZlibCompress := TPkcsObjectIdentifiers.IdAlgZlibCompress;

  FIdRi := TX509ObjectIdentifiers.IdPkix.Branch('16');
  FIdRiOcspResponse := FIdRi.Branch('2');
  FIdRiScvp := FIdRi.Branch('4');

  FIdAlg := TX509ObjectIdentifiers.PkixAlgorithms;
  FIdRsassaPssShake128 := TX509ObjectIdentifiers.IdRsassaPssShake128;
  FIdRsassaPssShake256 := TX509ObjectIdentifiers.IdRsassaPssShake256;
  FIdEcdsaWithShake128 := TX509ObjectIdentifiers.IdEcdsaWithShake128;
  FIdEcdsaWithShake256 := TX509ObjectIdentifiers.IdEcdsaWithShake256;

  FIdOri := TPkcsObjectIdentifiers.IdSmime.Branch('13');
  FIdOriKem := FIdOri.Branch('3');

  FIdAlgCekHkdfSha256 := TPkcsObjectIdentifiers.SmimeAlg.Branch('31');
end;

class constructor TCmsObjectIdentifiers.CmsObjectIdentifiers;
begin
  TCmsObjectIdentifiers.Boot();
end;

class function TCmsObjectIdentifiers.GetData: IDerObjectIdentifier;
begin
  Result := FData;
end;

class function TCmsObjectIdentifiers.GetSignedData: IDerObjectIdentifier;
begin
  Result := FSignedData;
end;

class function TCmsObjectIdentifiers.GetEnvelopedData: IDerObjectIdentifier;
begin
  Result := FEnvelopedData;
end;

class function TCmsObjectIdentifiers.GetSignedAndEnvelopedData: IDerObjectIdentifier;
begin
  Result := FSignedAndEnvelopedData;
end;

class function TCmsObjectIdentifiers.GetDigestedData: IDerObjectIdentifier;
begin
  Result := FDigestedData;
end;

class function TCmsObjectIdentifiers.GetEncryptedData: IDerObjectIdentifier;
begin
  Result := FEncryptedData;
end;

class function TCmsObjectIdentifiers.GetAuthenticatedData: IDerObjectIdentifier;
begin
  Result := FAuthenticatedData;
end;

class function TCmsObjectIdentifiers.GetCompressedData: IDerObjectIdentifier;
begin
  Result := FCompressedData;
end;

class function TCmsObjectIdentifiers.GetAuthEnvelopedData: IDerObjectIdentifier;
begin
  Result := FAuthEnvelopedData;
end;

class function TCmsObjectIdentifiers.GetTimestampedData: IDerObjectIdentifier;
begin
  Result := FTimestampedData;
end;

class function TCmsObjectIdentifiers.GetZlibCompress: IDerObjectIdentifier;
begin
  Result := FZlibCompress;
end;

class function TCmsObjectIdentifiers.GetIdRi: IDerObjectIdentifier;
begin
  Result := FIdRi;
end;

class function TCmsObjectIdentifiers.GetIdRiOcspResponse: IDerObjectIdentifier;
begin
  Result := FIdRiOcspResponse;
end;

class function TCmsObjectIdentifiers.GetIdRiScvp: IDerObjectIdentifier;
begin
  Result := FIdRiScvp;
end;

class function TCmsObjectIdentifiers.GetIdAlg: IDerObjectIdentifier;
begin
  Result := FIdAlg;
end;

class function TCmsObjectIdentifiers.GetIdRsassaPssShake128: IDerObjectIdentifier;
begin
  Result := FIdRsassaPssShake128;
end;

class function TCmsObjectIdentifiers.GetIdRsassaPssShake256: IDerObjectIdentifier;
begin
  Result := FIdRsassaPssShake256;
end;

class function TCmsObjectIdentifiers.GetIdEcdsaWithShake128: IDerObjectIdentifier;
begin
  Result := FIdEcdsaWithShake128;
end;

class function TCmsObjectIdentifiers.GetIdEcdsaWithShake256: IDerObjectIdentifier;
begin
  Result := FIdEcdsaWithShake256;
end;

class function TCmsObjectIdentifiers.GetIdOri: IDerObjectIdentifier;
begin
  Result := FIdOri;
end;

class function TCmsObjectIdentifiers.GetIdOriKem: IDerObjectIdentifier;
begin
  Result := FIdOriKem;
end;

class function TCmsObjectIdentifiers.GetIdAlgCekHkdfSha256: IDerObjectIdentifier;
begin
  Result := FIdAlgCekHkdfSha256;
end;

end.
