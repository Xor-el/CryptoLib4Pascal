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

unit ClpPkcsObjectIdentifiers;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpAsn1Objects,
  ClpIAsn1Objects;

type
  TPkcsObjectIdentifiers = class abstract(TObject)

  strict private

  const
    //
    // pkcs-1 OBJECT IDENTIFIER ::= {
    //       iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) 1 }
    //
    Pkcs1: String = '1.2.840.113549.1.1';

    //
    // pkcs-3 OBJECT IDENTIFIER ::= {
    // iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) 3 }
    //
    Pkcs3: String = '1.2.840.113549.1.3';

    //
    // pkcs-5 OBJECT IDENTIFIER ::= {
    // iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) 5 }
    //
    Pkcs5: String = '1.2.840.113549.1.5';

    //
    // object identifiers for digests
    //
    DigestAlgorithm: String = '1.2.840.113549.2';

  class var

    FIsBooted: Boolean;

    // PKCS#1 RSA OIDs
    FRsaEncryption,
    FMD2WithRsaEncryption,
    FMD4WithRsaEncryption,
    FMD5WithRsaEncryption,
    FSha1WithRsaEncryption,
    FSrsaOaepEncryptionSet,
    FIdRsaesOaep,
    FIdMgf1,
    FIdPSpecified,
    FIdRsassaPss,
    FSha256WithRsaEncryption,
    FSha384WithRsaEncryption,
    FSha512WithRsaEncryption,
    FSha224WithRsaEncryption,
    FSha512_224WithRsaEncryption,
    FSha512_256WithRsaEncryption,

    // PKCS#3
    FDhKeyAgreement,

    // PKCS#5
    FIdPbkdf2,

    // Digest algorithms
    FMD2, FMD4, FMD5,
    FIdHmacWithSha1, FIdHmacWithSha224, FIdHmacWithSha256,
    FIdHmacWithSha384, FIdHmacWithSha512,
    FIdHmacWithSha512_224, FIdHmacWithSha512_256
      : IDerObjectIdentifier;

    // PKCS#1 RSA getters
    class function GetRsaEncryption: IDerObjectIdentifier; static; inline;
    class function GetMD2WithRsaEncryption: IDerObjectIdentifier; static; inline;
    class function GetMD4WithRsaEncryption: IDerObjectIdentifier; static; inline;
    class function GetMD5WithRsaEncryption: IDerObjectIdentifier; static; inline;
    class function GetSha1WithRsaEncryption: IDerObjectIdentifier; static; inline;
    class function GetSrsaOaepEncryptionSet: IDerObjectIdentifier; static; inline;
    class function GetIdRsaesOaep: IDerObjectIdentifier; static; inline;
    class function GetIdMgf1: IDerObjectIdentifier; static; inline;
    class function GetIdPSpecified: IDerObjectIdentifier; static; inline;
    class function GetIdRsassaPss: IDerObjectIdentifier; static; inline;
    class function GetSha256WithRsaEncryption: IDerObjectIdentifier; static; inline;
    class function GetSha384WithRsaEncryption: IDerObjectIdentifier; static; inline;
    class function GetSha512WithRsaEncryption: IDerObjectIdentifier; static; inline;
    class function GetSha224WithRsaEncryption: IDerObjectIdentifier; static; inline;
    class function GetSha512_224WithRsaEncryption: IDerObjectIdentifier; static; inline;
    class function GetSha512_256WithRsaEncryption: IDerObjectIdentifier; static; inline;

    // PKCS#3
    class function GetDhKeyAgreement: IDerObjectIdentifier; static; inline;

    // PKCS#5
    class function GetIdPbkdf2: IDerObjectIdentifier; static; inline;

    // Digest algorithm getters
    class function GetMD2: IDerObjectIdentifier; static; inline;
    class function GetMD4: IDerObjectIdentifier; static; inline;
    class function GetMD5: IDerObjectIdentifier; static; inline;
    class function GetIdHmacWithSha1: IDerObjectIdentifier; static; inline;
    class function GetIdHmacWithSha224: IDerObjectIdentifier; static; inline;
    class function GetIdHmacWithSha256: IDerObjectIdentifier; static; inline;
    class function GetIdHmacWithSha384: IDerObjectIdentifier; static; inline;
    class function GetIdHmacWithSha512: IDerObjectIdentifier; static; inline;
    class function GetIdHmacWithSha512_224: IDerObjectIdentifier; static; inline;
    class function GetIdHmacWithSha512_256: IDerObjectIdentifier; static; inline;

    class constructor PkcsObjectIdentifiers();

  public

    //
    // PKCS#1 RSA OIDs
    //
    class property RsaEncryption: IDerObjectIdentifier read GetRsaEncryption;
    class property MD2WithRsaEncryption: IDerObjectIdentifier read GetMD2WithRsaEncryption;
    class property MD4WithRsaEncryption: IDerObjectIdentifier read GetMD4WithRsaEncryption;
    class property MD5WithRsaEncryption: IDerObjectIdentifier read GetMD5WithRsaEncryption;
    class property Sha1WithRsaEncryption: IDerObjectIdentifier read GetSha1WithRsaEncryption;
    class property SrsaOaepEncryptionSet: IDerObjectIdentifier read GetSrsaOaepEncryptionSet;
    class property IdRsaesOaep: IDerObjectIdentifier read GetIdRsaesOaep;
    class property IdMgf1: IDerObjectIdentifier read GetIdMgf1;
    class property IdPSpecified: IDerObjectIdentifier read GetIdPSpecified;
    class property IdRsassaPss: IDerObjectIdentifier read GetIdRsassaPss;
    class property Sha256WithRsaEncryption: IDerObjectIdentifier read GetSha256WithRsaEncryption;
    class property Sha384WithRsaEncryption: IDerObjectIdentifier read GetSha384WithRsaEncryption;
    class property Sha512WithRsaEncryption: IDerObjectIdentifier read GetSha512WithRsaEncryption;
    class property Sha224WithRsaEncryption: IDerObjectIdentifier read GetSha224WithRsaEncryption;
    class property Sha512_224WithRsaEncryption: IDerObjectIdentifier read GetSha512_224WithRsaEncryption;
    class property Sha512_256WithRsaEncryption: IDerObjectIdentifier read GetSha512_256WithRsaEncryption;

    //
    // PKCS#3
    //
    class property DhKeyAgreement: IDerObjectIdentifier read GetDhKeyAgreement;

    //
    // PKCS#5
    //
    class property IdPbkdf2: IDerObjectIdentifier read GetIdPbkdf2;

    //
    // Digest algorithms
    //
    class property MD2: IDerObjectIdentifier read GetMD2;
    class property MD4: IDerObjectIdentifier read GetMD4;
    class property MD5: IDerObjectIdentifier read GetMD5;

    class property IdHmacWithSha1: IDerObjectIdentifier read GetIdHmacWithSha1;
    class property IdHmacWithSha224: IDerObjectIdentifier read GetIdHmacWithSha224;
    class property IdHmacWithSha256: IDerObjectIdentifier read GetIdHmacWithSha256;
    class property IdHmacWithSha384: IDerObjectIdentifier read GetIdHmacWithSha384;
    class property IdHmacWithSha512: IDerObjectIdentifier read GetIdHmacWithSha512;
    class property IdHmacWithSha512_224: IDerObjectIdentifier read GetIdHmacWithSha512_224;
    class property IdHmacWithSha512_256: IDerObjectIdentifier read GetIdHmacWithSha512_256;

    class procedure Boot(); static;

  end;

implementation

{ TPkcsObjectIdentifiers }

class procedure TPkcsObjectIdentifiers.Boot;
begin
  if not FIsBooted then
  begin
    // PKCS#1 RSA
    FRsaEncryption := TDerObjectIdentifier.Create(Pkcs1 + '.1');
    FMD2WithRsaEncryption := TDerObjectIdentifier.Create(Pkcs1 + '.2');
    FMD4WithRsaEncryption := TDerObjectIdentifier.Create(Pkcs1 + '.3');
    FMD5WithRsaEncryption := TDerObjectIdentifier.Create(Pkcs1 + '.4');
    FSha1WithRsaEncryption := TDerObjectIdentifier.Create(Pkcs1 + '.5');
    FSrsaOaepEncryptionSet := TDerObjectIdentifier.Create(Pkcs1 + '.6');
    FIdRsaesOaep := TDerObjectIdentifier.Create(Pkcs1 + '.7');
    FIdMgf1 := TDerObjectIdentifier.Create(Pkcs1 + '.8');
    FIdPSpecified := TDerObjectIdentifier.Create(Pkcs1 + '.9');
    FIdRsassaPss := TDerObjectIdentifier.Create(Pkcs1 + '.10');
    FSha256WithRsaEncryption := TDerObjectIdentifier.Create(Pkcs1 + '.11');
    FSha384WithRsaEncryption := TDerObjectIdentifier.Create(Pkcs1 + '.12');
    FSha512WithRsaEncryption := TDerObjectIdentifier.Create(Pkcs1 + '.13');
    FSha224WithRsaEncryption := TDerObjectIdentifier.Create(Pkcs1 + '.14');
    FSha512_224WithRsaEncryption := TDerObjectIdentifier.Create(Pkcs1 + '.15');
    FSha512_256WithRsaEncryption := TDerObjectIdentifier.Create(Pkcs1 + '.16');

    // PKCS#3
    FDhKeyAgreement := TDerObjectIdentifier.Create(Pkcs3 + '.1');

    // PKCS#5
    FIdPbkdf2 := TDerObjectIdentifier.Create(Pkcs5 + '.12');

    // Digest algorithms
    FMD2 := TDerObjectIdentifier.Create(DigestAlgorithm + '.2');
    FMD4 := TDerObjectIdentifier.Create(DigestAlgorithm + '.4');
    FMD5 := TDerObjectIdentifier.Create(DigestAlgorithm + '.5');
    FIdHmacWithSha1 := TDerObjectIdentifier.Create(DigestAlgorithm + '.7');
    FIdHmacWithSha224 := TDerObjectIdentifier.Create(DigestAlgorithm + '.8');
    FIdHmacWithSha256 := TDerObjectIdentifier.Create(DigestAlgorithm + '.9');
    FIdHmacWithSha384 := TDerObjectIdentifier.Create(DigestAlgorithm + '.10');
    FIdHmacWithSha512 := TDerObjectIdentifier.Create(DigestAlgorithm + '.11');
    FIdHmacWithSha512_224 := TDerObjectIdentifier.Create(DigestAlgorithm + '.12');
    FIdHmacWithSha512_256 := TDerObjectIdentifier.Create(DigestAlgorithm + '.13');

    FIsBooted := True;
  end;
end;

// PKCS#1 RSA getters

class function TPkcsObjectIdentifiers.GetRsaEncryption: IDerObjectIdentifier;
begin
  Result := FRsaEncryption;
end;

class function TPkcsObjectIdentifiers.GetMD2WithRsaEncryption: IDerObjectIdentifier;
begin
  Result := FMD2WithRsaEncryption;
end;

class function TPkcsObjectIdentifiers.GetMD4WithRsaEncryption: IDerObjectIdentifier;
begin
  Result := FMD4WithRsaEncryption;
end;

class function TPkcsObjectIdentifiers.GetMD5WithRsaEncryption: IDerObjectIdentifier;
begin
  Result := FMD5WithRsaEncryption;
end;

class function TPkcsObjectIdentifiers.GetSha1WithRsaEncryption: IDerObjectIdentifier;
begin
  Result := FSha1WithRsaEncryption;
end;

class function TPkcsObjectIdentifiers.GetSrsaOaepEncryptionSet: IDerObjectIdentifier;
begin
  Result := FSrsaOaepEncryptionSet;
end;

class function TPkcsObjectIdentifiers.GetIdRsaesOaep: IDerObjectIdentifier;
begin
  Result := FIdRsaesOaep;
end;

class function TPkcsObjectIdentifiers.GetIdMgf1: IDerObjectIdentifier;
begin
  Result := FIdMgf1;
end;

class function TPkcsObjectIdentifiers.GetIdPSpecified: IDerObjectIdentifier;
begin
  Result := FIdPSpecified;
end;

class function TPkcsObjectIdentifiers.GetIdRsassaPss: IDerObjectIdentifier;
begin
  Result := FIdRsassaPss;
end;

class function TPkcsObjectIdentifiers.GetSha256WithRsaEncryption: IDerObjectIdentifier;
begin
  Result := FSha256WithRsaEncryption;
end;

class function TPkcsObjectIdentifiers.GetSha384WithRsaEncryption: IDerObjectIdentifier;
begin
  Result := FSha384WithRsaEncryption;
end;

class function TPkcsObjectIdentifiers.GetSha512WithRsaEncryption: IDerObjectIdentifier;
begin
  Result := FSha512WithRsaEncryption;
end;

class function TPkcsObjectIdentifiers.GetSha224WithRsaEncryption: IDerObjectIdentifier;
begin
  Result := FSha224WithRsaEncryption;
end;

class function TPkcsObjectIdentifiers.GetSha512_224WithRsaEncryption: IDerObjectIdentifier;
begin
  Result := FSha512_224WithRsaEncryption;
end;

class function TPkcsObjectIdentifiers.GetSha512_256WithRsaEncryption: IDerObjectIdentifier;
begin
  Result := FSha512_256WithRsaEncryption;
end;

// PKCS#3

class function TPkcsObjectIdentifiers.GetDhKeyAgreement: IDerObjectIdentifier;
begin
  Result := FDhKeyAgreement;
end;

// PKCS#5

class function TPkcsObjectIdentifiers.GetIdPbkdf2: IDerObjectIdentifier;
begin
  Result := FIdPbkdf2;
end;

// Digest algorithms

class function TPkcsObjectIdentifiers.GetMD2: IDerObjectIdentifier;
begin
  Result := FMD2;
end;

class function TPkcsObjectIdentifiers.GetMD4: IDerObjectIdentifier;
begin
  Result := FMD4;
end;

class function TPkcsObjectIdentifiers.GetMD5: IDerObjectIdentifier;
begin
  Result := FMD5;
end;

class function TPkcsObjectIdentifiers.GetIdHmacWithSha1: IDerObjectIdentifier;
begin
  Result := FIdHmacWithSha1;
end;

class function TPkcsObjectIdentifiers.GetIdHmacWithSha224: IDerObjectIdentifier;
begin
  Result := FIdHmacWithSha224;
end;

class function TPkcsObjectIdentifiers.GetIdHmacWithSha256: IDerObjectIdentifier;
begin
  Result := FIdHmacWithSha256;
end;

class function TPkcsObjectIdentifiers.GetIdHmacWithSha384: IDerObjectIdentifier;
begin
  Result := FIdHmacWithSha384;
end;

class function TPkcsObjectIdentifiers.GetIdHmacWithSha512: IDerObjectIdentifier;
begin
  Result := FIdHmacWithSha512;
end;

class function TPkcsObjectIdentifiers.GetIdHmacWithSha512_224: IDerObjectIdentifier;
begin
  Result := FIdHmacWithSha512_224;
end;

class function TPkcsObjectIdentifiers.GetIdHmacWithSha512_256: IDerObjectIdentifier;
begin
  Result := FIdHmacWithSha512_256;
end;

class constructor TPkcsObjectIdentifiers.PkcsObjectIdentifiers;
begin
  TPkcsObjectIdentifiers.Boot;
end;

end.


