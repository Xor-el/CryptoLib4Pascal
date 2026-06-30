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

unit ClpNistObjectIdentifiers;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpAsn1Objects,
  ClpIAsn1Objects;

type
  TNistObjectIdentifiers = class sealed(TObject)

  strict private

  class var
    FNistAlgorithm, FHashAlgs, FSigAlgs, FIdSha256, FIdSha384, FIdSha512,
      FIdSha224, FIdSha512_224, FIdSha512_256, FIdSha3_224, FIdSha3_256,
      FIdSha3_384, FIdSha3_512, FIdShake128, FIdShake256, FIdShake128Len, FIdShake256Len, FIdHMacWithSha3_224,
      FIdHMacWithSha3_256, FIdHMacWithSha3_384, FIdHMacWithSha3_512, FAES,
      FIdAES128Ecb, FIdAes128Cbc, FIdAes128Ofb, FIdAes128Cfb, FIdAes192Ecb,
      FIdAes192Cbc, FIdAes192Ofb, FIdAes192Cfb, FIdAes256Ecb, FIdAes256Cbc,
      FIdAes256Ofb, FIdAes256Cfb, FIdDsaWithSha2, FDsaWithSha224,
      FDsaWithSha256, FDsaWithSha384, FDsaWithSha512, FIdDsaWithSha3_224,
      FIdDsaWithSha3_256, FIdDsaWithSha3_384, FIdDsaWithSha3_512,
      FIdECDsaWithSha3_224, FIdECDsaWithSha3_256, FIdECDsaWithSha3_384,
      FIdECDsaWithSha3_512, FIdRsassaPkcs1V15WithSha3_224,
      FIdRsassaPkcs1V15WithSha3_256, FIdRsassaPkcs1V15WithSha3_384,
      FIdRsassaPkcs1V15WithSha3_512, FIdAes128Gcm, FIdAes192Gcm, FIdAes256Gcm,
      FIdAes128Ccm, FIdAes192Ccm, FIdAes256Ccm,
      FIdAes128Wrap, FIdAes128WrapPad,
      FIdAes192Wrap, FIdAes192WrapPad, FIdAes256Wrap,
      FIdAes256WrapPad,
      FKems, FIdMlDsa44, FIdMlDsa65, FIdMlDsa87,
      FIdHashMlDsa44WithSha512, FIdHashMlDsa65WithSha512, FIdHashMlDsa87WithSha512,
      FIdSlhDsaSha2_128s, FIdSlhDsaSha2_128f, FIdSlhDsaSha2_192s, FIdSlhDsaSha2_192f,
      FIdSlhDsaSha2_256s, FIdSlhDsaSha2_256f, FIdSlhDsaShake_128s, FIdSlhDsaShake_128f,
      FIdSlhDsaShake_192s, FIdSlhDsaShake_192f, FIdSlhDsaShake_256s, FIdSlhDsaShake_256f,
      FIdHashSlhDsaSha2_128sWithSha256, FIdHashSlhDsaSha2_128fWithSha256,
      FIdHashSlhDsaSha2_192sWithSha512, FIdHashSlhDsaSha2_192fWithSha512,
      FIdHashSlhDsaSha2_256sWithSha512, FIdHashSlhDsaSha2_256fWithSha512,
      FIdHashSlhDsaShake_128sWithShake128, FIdHashSlhDsaShake_128fWithShake128,
      FIdHashSlhDsaShake_192sWithShake256, FIdHashSlhDsaShake_192fWithShake256,
      FIdHashSlhDsaShake_256sWithShake256, FIdHashSlhDsaShake_256fWithShake256,
      FIdAlgMlKem512, FIdAlgMlKem768, FIdAlgMlKem1024: IDerObjectIdentifier;

    class function GetNistAlgorithm: IDerObjectIdentifier; static; inline;
    class function GetHashAlgs: IDerObjectIdentifier; static; inline;
    class function GetSigAlgs: IDerObjectIdentifier; static; inline;

    class function GetIdSha224: IDerObjectIdentifier; static; inline;
    class function GetIdSha256: IDerObjectIdentifier; static; inline;
    class function GetIdSha3_224: IDerObjectIdentifier; static; inline;
    class function GetIdSha3_256: IDerObjectIdentifier; static; inline;
    class function GetIdSha3_384: IDerObjectIdentifier; static; inline;
    class function GetIdSha3_512: IDerObjectIdentifier; static; inline;
    class function GetIdShake128: IDerObjectIdentifier; static; inline;
    class function GetIdShake256: IDerObjectIdentifier; static; inline;
    class function GetIdShake128Len: IDerObjectIdentifier; static; inline;
    class function GetIdShake256Len: IDerObjectIdentifier; static; inline;
    class function GetIdSha384: IDerObjectIdentifier; static; inline;
    class function GetIdSha512: IDerObjectIdentifier; static; inline;
    class function GetIdSha512_224: IDerObjectIdentifier; static; inline;
    class function GetIdSha512_256: IDerObjectIdentifier; static; inline;

    class function GetIdHMacWithSha3_224: IDerObjectIdentifier; static; inline;
    class function GetIdHMacWithSha3_256: IDerObjectIdentifier; static; inline;
    class function GetIdHMacWithSha3_384: IDerObjectIdentifier; static; inline;
    class function GetIdHMacWithSha3_512: IDerObjectIdentifier; static; inline;

    class function GetAES: IDerObjectIdentifier; static; inline;

    class function GetIdAes128Ecb: IDerObjectIdentifier; static; inline;
    class function GetIdAes128Cbc: IDerObjectIdentifier; static; inline;
    class function GetIdAes128Ofb: IDerObjectIdentifier; static; inline;
    class function GetIdAes128Cfb: IDerObjectIdentifier; static; inline;
    class function GetIdAes192Ecb: IDerObjectIdentifier; static; inline;
    class function GetIdAes192Cbc: IDerObjectIdentifier; static; inline;
    class function GetIdAes192Ofb: IDerObjectIdentifier; static; inline;
    class function GetIdAes192Cfb: IDerObjectIdentifier; static; inline;
    class function GetIdAes256Ecb: IDerObjectIdentifier; static; inline;
    class function GetIdAes256Cbc: IDerObjectIdentifier; static; inline;
    class function GetIdAes256Ofb: IDerObjectIdentifier; static; inline;
    class function GetIdAes256Cfb: IDerObjectIdentifier; static; inline;

    class function GetIdAes128Gcm: IDerObjectIdentifier; static; inline;
    class function GetIdAes192Gcm: IDerObjectIdentifier; static; inline;
    class function GetIdAes256Gcm: IDerObjectIdentifier; static; inline;

    class function GetIdAes128Ccm: IDerObjectIdentifier; static; inline;
    class function GetIdAes192Ccm: IDerObjectIdentifier; static; inline;
    class function GetIdAes256Ccm: IDerObjectIdentifier; static; inline;

    class function GetIdAes128Wrap: IDerObjectIdentifier; static; inline;
    class function GetIdAes128WrapPad: IDerObjectIdentifier; static; inline;
    class function GetIdAes192Wrap: IDerObjectIdentifier; static; inline;
    class function GetIdAes192WrapPad: IDerObjectIdentifier; static; inline;
    class function GetIdAes256Wrap: IDerObjectIdentifier; static; inline;
    class function GetIdAes256WrapPad: IDerObjectIdentifier; static; inline;

    class function GetIdDsaWithSha2: IDerObjectIdentifier; static; inline;
    class function GetDsaWithSha224: IDerObjectIdentifier; static; inline;
    class function GetDsaWithSha256: IDerObjectIdentifier; static; inline;
    class function GetDsaWithSha384: IDerObjectIdentifier; static; inline;
    class function GetDsaWithSha512: IDerObjectIdentifier; static; inline;

    class function GetIdDsaWithSha3_224: IDerObjectIdentifier; static; inline;
    class function GetIdDsaWithSha3_256: IDerObjectIdentifier; static; inline;
    class function GetIdDsaWithSha3_384: IDerObjectIdentifier; static; inline;
    class function GetIdDsaWithSha3_512: IDerObjectIdentifier; static; inline;

    class function GetIdECDsaWithSha3_224: IDerObjectIdentifier; static; inline;
    class function GetIdECDsaWithSha3_256: IDerObjectIdentifier; static; inline;
    class function GetIdECDsaWithSha3_384: IDerObjectIdentifier; static; inline;
    class function GetIdECDsaWithSha3_512: IDerObjectIdentifier; static; inline;
    class function GetIdRsassaPkcs1V15WithSha3_224: IDerObjectIdentifier; static; inline;
    class function GetIdRsassaPkcs1V15WithSha3_256: IDerObjectIdentifier; static; inline;
    class function GetIdRsassaPkcs1V15WithSha3_384: IDerObjectIdentifier; static; inline;
    class function GetIdRsassaPkcs1V15WithSha3_512: IDerObjectIdentifier; static; inline;

    class function GetKems: IDerObjectIdentifier; static; inline;
    class function GetIdMlDsa44: IDerObjectIdentifier; static; inline;
    class function GetIdMlDsa65: IDerObjectIdentifier; static; inline;
    class function GetIdMlDsa87: IDerObjectIdentifier; static; inline;
    class function GetIdHashMlDsa44WithSha512: IDerObjectIdentifier; static; inline;
    class function GetIdHashMlDsa65WithSha512: IDerObjectIdentifier; static; inline;
    class function GetIdHashMlDsa87WithSha512: IDerObjectIdentifier; static; inline;
    class function GetIdSlhDsaSha2_128s: IDerObjectIdentifier; static; inline;
    class function GetIdSlhDsaSha2_128f: IDerObjectIdentifier; static; inline;
    class function GetIdSlhDsaSha2_192s: IDerObjectIdentifier; static; inline;
    class function GetIdSlhDsaSha2_192f: IDerObjectIdentifier; static; inline;
    class function GetIdSlhDsaSha2_256s: IDerObjectIdentifier; static; inline;
    class function GetIdSlhDsaSha2_256f: IDerObjectIdentifier; static; inline;
    class function GetIdSlhDsaShake_128s: IDerObjectIdentifier; static; inline;
    class function GetIdSlhDsaShake_128f: IDerObjectIdentifier; static; inline;
    class function GetIdSlhDsaShake_192s: IDerObjectIdentifier; static; inline;
    class function GetIdSlhDsaShake_192f: IDerObjectIdentifier; static; inline;
    class function GetIdSlhDsaShake_256s: IDerObjectIdentifier; static; inline;
    class function GetIdSlhDsaShake_256f: IDerObjectIdentifier; static; inline;
    class function GetIdHashSlhDsaSha2_128sWithSha256: IDerObjectIdentifier; static; inline;
    class function GetIdHashSlhDsaSha2_128fWithSha256: IDerObjectIdentifier; static; inline;
    class function GetIdHashSlhDsaSha2_192sWithSha512: IDerObjectIdentifier; static; inline;
    class function GetIdHashSlhDsaSha2_192fWithSha512: IDerObjectIdentifier; static; inline;
    class function GetIdHashSlhDsaSha2_256sWithSha512: IDerObjectIdentifier; static; inline;
    class function GetIdHashSlhDsaSha2_256fWithSha512: IDerObjectIdentifier; static; inline;
    class function GetIdHashSlhDsaShake_128sWithShake128: IDerObjectIdentifier; static; inline;
    class function GetIdHashSlhDsaShake_128fWithShake128: IDerObjectIdentifier; static; inline;
    class function GetIdHashSlhDsaShake_192sWithShake256: IDerObjectIdentifier; static; inline;
    class function GetIdHashSlhDsaShake_192fWithShake256: IDerObjectIdentifier; static; inline;
    class function GetIdHashSlhDsaShake_256sWithShake256: IDerObjectIdentifier; static; inline;
    class function GetIdHashSlhDsaShake_256fWithShake256: IDerObjectIdentifier; static; inline;
    class function GetIdAlgMlKem512: IDerObjectIdentifier; static; inline;
    class function GetIdAlgMlKem768: IDerObjectIdentifier; static; inline;
    class function GetIdAlgMlKem1024: IDerObjectIdentifier; static; inline;

    class constructor Create();

  public

    //
    // NIST
    // iso/itu(2) joint-assign(16) us(840) organization(1) gov(101) csor(3)

    //
    // nistalgorithms(4)
    //
    class property NistAlgorithm: IDerObjectIdentifier read GetNistAlgorithm;
    class property HashAlgs: IDerObjectIdentifier read GetHashAlgs;
    class property SigAlgs: IDerObjectIdentifier read GetSigAlgs;

    class property IdSha256: IDerObjectIdentifier read GetIdSha256;
    class property IdSha384: IDerObjectIdentifier read GetIdSha384;
    class property IdSha512: IDerObjectIdentifier read GetIdSha512;
    class property IdSha224: IDerObjectIdentifier read GetIdSha224;
    class property IdSha512_224: IDerObjectIdentifier read GetIdSha512_224;
    class property IdSha512_256: IDerObjectIdentifier read GetIdSha512_256;
    class property IdSha3_224: IDerObjectIdentifier read GetIdSha3_224;
    class property IdSha3_256: IDerObjectIdentifier read GetIdSha3_256;
    class property IdSha3_384: IDerObjectIdentifier read GetIdSha3_384;
    class property IdSha3_512: IDerObjectIdentifier read GetIdSha3_512;
    class property IdShake128: IDerObjectIdentifier read GetIdShake128;
    class property IdShake256: IDerObjectIdentifier read GetIdShake256;
    class property IdShake128Len: IDerObjectIdentifier read GetIdShake128Len;
    class property IdShake256Len: IDerObjectIdentifier read GetIdShake256Len;

    class property IdHMacWithSha3_224: IDerObjectIdentifier
      read GetIdHMacWithSha3_224;
    class property IdHMacWithSha3_256: IDerObjectIdentifier
      read GetIdHMacWithSha3_256;
    class property IdHMacWithSha3_384: IDerObjectIdentifier
      read GetIdHMacWithSha3_384;
    class property IdHMacWithSha3_512: IDerObjectIdentifier
      read GetIdHMacWithSha3_512;

    class property AES: IDerObjectIdentifier read GetAES;

    class property IdAes128Ecb: IDerObjectIdentifier read GetIdAes128Ecb;
    class property IdAes128Cbc: IDerObjectIdentifier read GetIdAes128Cbc;
    class property IdAes128Ofb: IDerObjectIdentifier read GetIdAes128Ofb;
    class property IdAes128Cfb: IDerObjectIdentifier read GetIdAes128Cfb;
    class property IdAes192Ecb: IDerObjectIdentifier read GetIdAes192Ecb;
    class property IdAes192Cbc: IDerObjectIdentifier read GetIdAes192Cbc;
    class property IdAes192Ofb: IDerObjectIdentifier read GetIdAes192Ofb;
    class property IdAes192Cfb: IDerObjectIdentifier read GetIdAes192Cfb;
    class property IdAes256Ecb: IDerObjectIdentifier read GetIdAes256Ecb;
    class property IdAes256Cbc: IDerObjectIdentifier read GetIdAes256Cbc;
    class property IdAes256Ofb: IDerObjectIdentifier read GetIdAes256Ofb;
    class property IdAes256Cfb: IDerObjectIdentifier read GetIdAes256Cfb;

    class property IdAes128Gcm: IDerObjectIdentifier read GetIdAes128Gcm;
    class property IdAes192Gcm: IDerObjectIdentifier read GetIdAes192Gcm;
    class property IdAes256Gcm: IDerObjectIdentifier read GetIdAes256Gcm;

    class property IdAes128Ccm: IDerObjectIdentifier read GetIdAes128Ccm;
    class property IdAes192Ccm: IDerObjectIdentifier read GetIdAes192Ccm;
    class property IdAes256Ccm: IDerObjectIdentifier read GetIdAes256Ccm;

    class property IdAes128Wrap: IDerObjectIdentifier read GetIdAes128Wrap;
    class property IdAes128WrapPad: IDerObjectIdentifier read GetIdAes128WrapPad;
    class property IdAes192Wrap: IDerObjectIdentifier read GetIdAes192Wrap;
    class property IdAes192WrapPad: IDerObjectIdentifier read GetIdAes192WrapPad;
    class property IdAes256Wrap: IDerObjectIdentifier read GetIdAes256Wrap;
    class property IdAes256WrapPad: IDerObjectIdentifier read GetIdAes256WrapPad;

    class property IdDsaWithSha2: IDerObjectIdentifier read GetIdDsaWithSha2;
    class property DsaWithSha224: IDerObjectIdentifier read GetDsaWithSha224;
    class property DsaWithSha256: IDerObjectIdentifier read GetDsaWithSha256;
    class property DsaWithSha384: IDerObjectIdentifier read GetDsaWithSha384;
    class property DsaWithSha512: IDerObjectIdentifier read GetDsaWithSha512;

    class property IdDsaWithSha3_224: IDerObjectIdentifier
      read GetIdDsaWithSha3_224;
    class property IdDsaWithSha3_256: IDerObjectIdentifier
      read GetIdDsaWithSha3_256;
    class property IdDsaWithSha3_384: IDerObjectIdentifier
      read GetIdDsaWithSha3_384;
    class property IdDsaWithSha3_512: IDerObjectIdentifier
      read GetIdDsaWithSha3_512;

    class property IdECDsaWithSha3_224: IDerObjectIdentifier
      read GetIdECDsaWithSha3_224;
    class property IdECDsaWithSha3_256: IDerObjectIdentifier
      read GetIdECDsaWithSha3_256;
    class property IdECDsaWithSha3_384: IDerObjectIdentifier
      read GetIdECDsaWithSha3_384;
    class property IdECDsaWithSha3_512: IDerObjectIdentifier
      read GetIdECDsaWithSha3_512;
    class property IdRsassaPkcs1V15WithSha3_224: IDerObjectIdentifier
      read GetIdRsassaPkcs1V15WithSha3_224;
    class property IdRsassaPkcs1V15WithSha3_256: IDerObjectIdentifier
      read GetIdRsassaPkcs1V15WithSha3_256;
    class property IdRsassaPkcs1V15WithSha3_384: IDerObjectIdentifier
      read GetIdRsassaPkcs1V15WithSha3_384;
    class property IdRsassaPkcs1V15WithSha3_512: IDerObjectIdentifier
      read GetIdRsassaPkcs1V15WithSha3_512;

    class property Kems: IDerObjectIdentifier read GetKems;
    class property IdMlDsa44: IDerObjectIdentifier read GetIdMlDsa44;
    class property IdMlDsa65: IDerObjectIdentifier read GetIdMlDsa65;
    class property IdMlDsa87: IDerObjectIdentifier read GetIdMlDsa87;
    class property IdHashMlDsa44WithSha512: IDerObjectIdentifier
      read GetIdHashMlDsa44WithSha512;
    class property IdHashMlDsa65WithSha512: IDerObjectIdentifier
      read GetIdHashMlDsa65WithSha512;
    class property IdHashMlDsa87WithSha512: IDerObjectIdentifier
      read GetIdHashMlDsa87WithSha512;
    class property IdSlhDsaSha2_128s: IDerObjectIdentifier read GetIdSlhDsaSha2_128s;
    class property IdSlhDsaSha2_128f: IDerObjectIdentifier read GetIdSlhDsaSha2_128f;
    class property IdSlhDsaSha2_192s: IDerObjectIdentifier read GetIdSlhDsaSha2_192s;
    class property IdSlhDsaSha2_192f: IDerObjectIdentifier read GetIdSlhDsaSha2_192f;
    class property IdSlhDsaSha2_256s: IDerObjectIdentifier read GetIdSlhDsaSha2_256s;
    class property IdSlhDsaSha2_256f: IDerObjectIdentifier read GetIdSlhDsaSha2_256f;
    class property IdSlhDsaShake_128s: IDerObjectIdentifier read GetIdSlhDsaShake_128s;
    class property IdSlhDsaShake_128f: IDerObjectIdentifier read GetIdSlhDsaShake_128f;
    class property IdSlhDsaShake_192s: IDerObjectIdentifier read GetIdSlhDsaShake_192s;
    class property IdSlhDsaShake_192f: IDerObjectIdentifier read GetIdSlhDsaShake_192f;
    class property IdSlhDsaShake_256s: IDerObjectIdentifier read GetIdSlhDsaShake_256s;
    class property IdSlhDsaShake_256f: IDerObjectIdentifier read GetIdSlhDsaShake_256f;
    class property IdHashSlhDsaSha2_128sWithSha256: IDerObjectIdentifier
      read GetIdHashSlhDsaSha2_128sWithSha256;
    class property IdHashSlhDsaSha2_128fWithSha256: IDerObjectIdentifier
      read GetIdHashSlhDsaSha2_128fWithSha256;
    class property IdHashSlhDsaSha2_192sWithSha512: IDerObjectIdentifier
      read GetIdHashSlhDsaSha2_192sWithSha512;
    class property IdHashSlhDsaSha2_192fWithSha512: IDerObjectIdentifier
      read GetIdHashSlhDsaSha2_192fWithSha512;
    class property IdHashSlhDsaSha2_256sWithSha512: IDerObjectIdentifier
      read GetIdHashSlhDsaSha2_256sWithSha512;
    class property IdHashSlhDsaSha2_256fWithSha512: IDerObjectIdentifier
      read GetIdHashSlhDsaSha2_256fWithSha512;
    class property IdHashSlhDsaShake_128sWithShake128: IDerObjectIdentifier
      read GetIdHashSlhDsaShake_128sWithShake128;
    class property IdHashSlhDsaShake_128fWithShake128: IDerObjectIdentifier
      read GetIdHashSlhDsaShake_128fWithShake128;
    class property IdHashSlhDsaShake_192sWithShake256: IDerObjectIdentifier
      read GetIdHashSlhDsaShake_192sWithShake256;
    class property IdHashSlhDsaShake_192fWithShake256: IDerObjectIdentifier
      read GetIdHashSlhDsaShake_192fWithShake256;
    class property IdHashSlhDsaShake_256sWithShake256: IDerObjectIdentifier
      read GetIdHashSlhDsaShake_256sWithShake256;
    class property IdHashSlhDsaShake_256fWithShake256: IDerObjectIdentifier
      read GetIdHashSlhDsaShake_256fWithShake256;
    class property IdAlgMlKem512: IDerObjectIdentifier read GetIdAlgMlKem512;
    class property IdAlgMlKem768: IDerObjectIdentifier read GetIdAlgMlKem768;
    class property IdAlgMlKem1024: IDerObjectIdentifier read GetIdAlgMlKem1024;
  end;

implementation

{ TNistObjectIdentifiers }

class function TNistObjectIdentifiers.GetAES: IDerObjectIdentifier;
begin
  Result := FAES;
end;

class function TNistObjectIdentifiers.GetDsaWithSha224: IDerObjectIdentifier;
begin
  Result := FDsaWithSha224;
end;

class function TNistObjectIdentifiers.GetDsaWithSha256: IDerObjectIdentifier;
begin
  Result := FDsaWithSha256;
end;

class function TNistObjectIdentifiers.GetDsaWithSha384: IDerObjectIdentifier;
begin
  Result := FDsaWithSha384;
end;

class function TNistObjectIdentifiers.GetDsaWithSha512: IDerObjectIdentifier;
begin
  Result := FDsaWithSha512;
end;

class function TNistObjectIdentifiers.GetHashAlgs: IDerObjectIdentifier;
begin
  Result := FHashAlgs;
end;

class function TNistObjectIdentifiers.GetIdDsaWithSha2: IDerObjectIdentifier;
begin
  Result := FIdDsaWithSha2;
end;

class function TNistObjectIdentifiers.GetIdAes128Cbc: IDerObjectIdentifier;
begin
  Result := FIdAes128Cbc;
end;

class function TNistObjectIdentifiers.GetIdAes128Cfb: IDerObjectIdentifier;
begin
  Result := FIdAes128Cfb;
end;

class function TNistObjectIdentifiers.GetIdAes128Ecb: IDerObjectIdentifier;
begin
  Result := FIdAES128Ecb;
end;

class function TNistObjectIdentifiers.GetIdAes128Ofb: IDerObjectIdentifier;
begin
  Result := FIdAes128Ofb;
end;

class function TNistObjectIdentifiers.GetIdAes192Cbc: IDerObjectIdentifier;
begin
  Result := FIdAes192Cbc;
end;

class function TNistObjectIdentifiers.GetIdAes192Cfb: IDerObjectIdentifier;
begin
  Result := FIdAes192Cfb;
end;

class function TNistObjectIdentifiers.GetIdAes192Ecb: IDerObjectIdentifier;
begin
  Result := FIdAes192Ecb;
end;

class function TNistObjectIdentifiers.GetIdAes192Ofb: IDerObjectIdentifier;
begin
  Result := FIdAes192Ofb;
end;

class function TNistObjectIdentifiers.GetIdAes256Cbc: IDerObjectIdentifier;
begin
  Result := FIdAes256Cbc;
end;

class function TNistObjectIdentifiers.GetIdAes256Cfb: IDerObjectIdentifier;
begin
  Result := FIdAes256Cfb;
end;

class function TNistObjectIdentifiers.GetIdAes256Ecb: IDerObjectIdentifier;
begin
  Result := FIdAes256Ecb;
end;

class function TNistObjectIdentifiers.GetIdAes256Ofb: IDerObjectIdentifier;
begin
  Result := FIdAes256Ofb;
end;

class function TNistObjectIdentifiers.GetIdAes128Gcm: IDerObjectIdentifier;
begin
  Result := FIdAes128Gcm;
end;

class function TNistObjectIdentifiers.GetIdAes192Gcm: IDerObjectIdentifier;
begin
  Result := FIdAes192Gcm;
end;

class function TNistObjectIdentifiers.GetIdAes256Gcm: IDerObjectIdentifier;
begin
  Result := FIdAes256Gcm;
end;

class function TNistObjectIdentifiers.GetIdAes128Ccm: IDerObjectIdentifier;
begin
  Result := FIdAes128Ccm;
end;

class function TNistObjectIdentifiers.GetIdAes192Ccm: IDerObjectIdentifier;
begin
  Result := FIdAes192Ccm;
end;

class function TNistObjectIdentifiers.GetIdAes256Ccm: IDerObjectIdentifier;
begin
  Result := FIdAes256Ccm;
end;

class function TNistObjectIdentifiers.GetIdAes128Wrap: IDerObjectIdentifier;
begin
  Result := FIdAes128Wrap;
end;

class function TNistObjectIdentifiers.GetIdAes128WrapPad: IDerObjectIdentifier;
begin
  Result := FIdAes128WrapPad;
end;

class function TNistObjectIdentifiers.GetIdAes192Wrap: IDerObjectIdentifier;
begin
  Result := FIdAes192Wrap;
end;

class function TNistObjectIdentifiers.GetIdAes192WrapPad: IDerObjectIdentifier;
begin
  Result := FIdAes192WrapPad;
end;

class function TNistObjectIdentifiers.GetIdAes256Wrap: IDerObjectIdentifier;
begin
  Result := FIdAes256Wrap;
end;

class function TNistObjectIdentifiers.GetIdAes256WrapPad: IDerObjectIdentifier;
begin
  Result := FIdAes256WrapPad;
end;

class function TNistObjectIdentifiers.GetIdHMacWithSha3_224
  : IDerObjectIdentifier;
begin
  Result := FIdHMacWithSha3_224;
end;

class function TNistObjectIdentifiers.GetIdHMacWithSha3_256
  : IDerObjectIdentifier;
begin
  Result := FIdHMacWithSha3_256;
end;

class function TNistObjectIdentifiers.GetIdHMacWithSha3_384
  : IDerObjectIdentifier;
begin
  Result := FIdHMacWithSha3_384;
end;

class function TNistObjectIdentifiers.GetIdHMacWithSha3_512
  : IDerObjectIdentifier;
begin
  Result := FIdHMacWithSha3_512;
end;

class function TNistObjectIdentifiers.GetIdSha224: IDerObjectIdentifier;
begin
  Result := FIdSha224;
end;

class function TNistObjectIdentifiers.GetIdSha256: IDerObjectIdentifier;
begin
  Result := FIdSha256;
end;

class function TNistObjectIdentifiers.GetIdSha384: IDerObjectIdentifier;
begin
  Result := FIdSha384;
end;

class function TNistObjectIdentifiers.GetIdSha3_224: IDerObjectIdentifier;
begin
  Result := FIdSha3_224;
end;

class function TNistObjectIdentifiers.GetIdSha3_256: IDerObjectIdentifier;
begin
  Result := FIdSha3_256;
end;

class function TNistObjectIdentifiers.GetIdSha3_384: IDerObjectIdentifier;
begin
  Result := FIdSha3_384;
end;

class function TNistObjectIdentifiers.GetIdSha3_512: IDerObjectIdentifier;
begin
  Result := FIdSha3_512;
end;

class function TNistObjectIdentifiers.GetIdShake128: IDerObjectIdentifier;
begin
  Result := FIdShake128;
end;

class function TNistObjectIdentifiers.GetIdShake256: IDerObjectIdentifier;
begin
  Result := FIdShake256;
end;

class function TNistObjectIdentifiers.GetIdShake128Len: IDerObjectIdentifier;
begin
  Result := FIdShake128Len;
end;

class function TNistObjectIdentifiers.GetIdShake256Len: IDerObjectIdentifier;
begin
  Result := FIdShake256Len;
end;

class function TNistObjectIdentifiers.GetIdSha512: IDerObjectIdentifier;
begin
  Result := FIdSha512;
end;

class function TNistObjectIdentifiers.GetIdSha512_224: IDerObjectIdentifier;
begin
  Result := FIdSha512_224;
end;

class function TNistObjectIdentifiers.GetIdSha512_256: IDerObjectIdentifier;
begin
  Result := FIdSha512_256;
end;

class function TNistObjectIdentifiers.GetIdDsaWithSha3_224
  : IDerObjectIdentifier;
begin
  Result := FIdDsaWithSha3_224;
end;

class function TNistObjectIdentifiers.GetIdDsaWithSha3_256
  : IDerObjectIdentifier;
begin
  Result := FIdDsaWithSha3_256;
end;

class function TNistObjectIdentifiers.GetIdDsaWithSha3_384
  : IDerObjectIdentifier;
begin
  Result := FIdDsaWithSha3_384;
end;

class function TNistObjectIdentifiers.GetIdDsaWithSha3_512
  : IDerObjectIdentifier;
begin
  Result := FIdDsaWithSha3_512;
end;

class function TNistObjectIdentifiers.GetIdECDsaWithSha3_224
  : IDerObjectIdentifier;
begin
  Result := FIdECDsaWithSha3_224;
end;

class function TNistObjectIdentifiers.GetIdECDsaWithSha3_256
  : IDerObjectIdentifier;
begin
  Result := FIdECDsaWithSha3_256;
end;

class function TNistObjectIdentifiers.GetIdECDsaWithSha3_384
  : IDerObjectIdentifier;
begin
  Result := FIdECDsaWithSha3_384;
end;

class function TNistObjectIdentifiers.GetIdECDsaWithSha3_512
  : IDerObjectIdentifier;
begin
  Result := FIdECDsaWithSha3_512;
end;

class function TNistObjectIdentifiers.GetIdRsassaPkcs1V15WithSha3_224
  : IDerObjectIdentifier;
begin
  Result := FIdRsassaPkcs1V15WithSha3_224;
end;

class function TNistObjectIdentifiers.GetIdRsassaPkcs1V15WithSha3_256
  : IDerObjectIdentifier;
begin
  Result := FIdRsassaPkcs1V15WithSha3_256;
end;

class function TNistObjectIdentifiers.GetIdRsassaPkcs1V15WithSha3_384
  : IDerObjectIdentifier;
begin
  Result := FIdRsassaPkcs1V15WithSha3_384;
end;

class function TNistObjectIdentifiers.GetIdRsassaPkcs1V15WithSha3_512
  : IDerObjectIdentifier;
begin
  Result := FIdRsassaPkcs1V15WithSha3_512;
end;

class function TNistObjectIdentifiers.GetKems: IDerObjectIdentifier;
begin
  Result := FKems;
end;

class function TNistObjectIdentifiers.GetIdMlDsa44: IDerObjectIdentifier;
begin
  Result := FIdMlDsa44;
end;

class function TNistObjectIdentifiers.GetIdMlDsa65: IDerObjectIdentifier;
begin
  Result := FIdMlDsa65;
end;

class function TNistObjectIdentifiers.GetIdMlDsa87: IDerObjectIdentifier;
begin
  Result := FIdMlDsa87;
end;

class function TNistObjectIdentifiers.GetIdHashMlDsa44WithSha512: IDerObjectIdentifier;
begin
  Result := FIdHashMlDsa44WithSha512;
end;

class function TNistObjectIdentifiers.GetIdHashMlDsa65WithSha512: IDerObjectIdentifier;
begin
  Result := FIdHashMlDsa65WithSha512;
end;

class function TNistObjectIdentifiers.GetIdHashMlDsa87WithSha512: IDerObjectIdentifier;
begin
  Result := FIdHashMlDsa87WithSha512;
end;

class function TNistObjectIdentifiers.GetIdSlhDsaSha2_128s: IDerObjectIdentifier;
begin
  Result := FIdSlhDsaSha2_128s;
end;

class function TNistObjectIdentifiers.GetIdSlhDsaSha2_128f: IDerObjectIdentifier;
begin
  Result := FIdSlhDsaSha2_128f;
end;

class function TNistObjectIdentifiers.GetIdSlhDsaSha2_192s: IDerObjectIdentifier;
begin
  Result := FIdSlhDsaSha2_192s;
end;

class function TNistObjectIdentifiers.GetIdSlhDsaSha2_192f: IDerObjectIdentifier;
begin
  Result := FIdSlhDsaSha2_192f;
end;

class function TNistObjectIdentifiers.GetIdSlhDsaSha2_256s: IDerObjectIdentifier;
begin
  Result := FIdSlhDsaSha2_256s;
end;

class function TNistObjectIdentifiers.GetIdSlhDsaSha2_256f: IDerObjectIdentifier;
begin
  Result := FIdSlhDsaSha2_256f;
end;

class function TNistObjectIdentifiers.GetIdSlhDsaShake_128s: IDerObjectIdentifier;
begin
  Result := FIdSlhDsaShake_128s;
end;

class function TNistObjectIdentifiers.GetIdSlhDsaShake_128f: IDerObjectIdentifier;
begin
  Result := FIdSlhDsaShake_128f;
end;

class function TNistObjectIdentifiers.GetIdSlhDsaShake_192s: IDerObjectIdentifier;
begin
  Result := FIdSlhDsaShake_192s;
end;

class function TNistObjectIdentifiers.GetIdSlhDsaShake_192f: IDerObjectIdentifier;
begin
  Result := FIdSlhDsaShake_192f;
end;

class function TNistObjectIdentifiers.GetIdSlhDsaShake_256s: IDerObjectIdentifier;
begin
  Result := FIdSlhDsaShake_256s;
end;

class function TNistObjectIdentifiers.GetIdSlhDsaShake_256f: IDerObjectIdentifier;
begin
  Result := FIdSlhDsaShake_256f;
end;

class function TNistObjectIdentifiers.GetIdHashSlhDsaSha2_128sWithSha256: IDerObjectIdentifier;
begin
  Result := FIdHashSlhDsaSha2_128sWithSha256;
end;

class function TNistObjectIdentifiers.GetIdHashSlhDsaSha2_128fWithSha256: IDerObjectIdentifier;
begin
  Result := FIdHashSlhDsaSha2_128fWithSha256;
end;

class function TNistObjectIdentifiers.GetIdHashSlhDsaSha2_192sWithSha512: IDerObjectIdentifier;
begin
  Result := FIdHashSlhDsaSha2_192sWithSha512;
end;

class function TNistObjectIdentifiers.GetIdHashSlhDsaSha2_192fWithSha512: IDerObjectIdentifier;
begin
  Result := FIdHashSlhDsaSha2_192fWithSha512;
end;

class function TNistObjectIdentifiers.GetIdHashSlhDsaSha2_256sWithSha512: IDerObjectIdentifier;
begin
  Result := FIdHashSlhDsaSha2_256sWithSha512;
end;

class function TNistObjectIdentifiers.GetIdHashSlhDsaSha2_256fWithSha512: IDerObjectIdentifier;
begin
  Result := FIdHashSlhDsaSha2_256fWithSha512;
end;

class function TNistObjectIdentifiers.GetIdHashSlhDsaShake_128sWithShake128: IDerObjectIdentifier;
begin
  Result := FIdHashSlhDsaShake_128sWithShake128;
end;

class function TNistObjectIdentifiers.GetIdHashSlhDsaShake_128fWithShake128: IDerObjectIdentifier;
begin
  Result := FIdHashSlhDsaShake_128fWithShake128;
end;

class function TNistObjectIdentifiers.GetIdHashSlhDsaShake_192sWithShake256: IDerObjectIdentifier;
begin
  Result := FIdHashSlhDsaShake_192sWithShake256;
end;

class function TNistObjectIdentifiers.GetIdHashSlhDsaShake_192fWithShake256: IDerObjectIdentifier;
begin
  Result := FIdHashSlhDsaShake_192fWithShake256;
end;

class function TNistObjectIdentifiers.GetIdHashSlhDsaShake_256sWithShake256: IDerObjectIdentifier;
begin
  Result := FIdHashSlhDsaShake_256sWithShake256;
end;

class function TNistObjectIdentifiers.GetIdHashSlhDsaShake_256fWithShake256: IDerObjectIdentifier;
begin
  Result := FIdHashSlhDsaShake_256fWithShake256;
end;

class function TNistObjectIdentifiers.GetIdAlgMlKem512: IDerObjectIdentifier;
begin
  Result := FIdAlgMlKem512;
end;

class function TNistObjectIdentifiers.GetIdAlgMlKem768: IDerObjectIdentifier;
begin
  Result := FIdAlgMlKem768;
end;

class function TNistObjectIdentifiers.GetIdAlgMlKem1024: IDerObjectIdentifier;
begin
  Result := FIdAlgMlKem1024;
end;

class function TNistObjectIdentifiers.GetNistAlgorithm: IDerObjectIdentifier;
begin
  Result := FNistAlgorithm;
end;

class function TNistObjectIdentifiers.GetSigAlgs: IDerObjectIdentifier;
begin
  Result := FSigAlgs;
end;

class constructor TNistObjectIdentifiers.Create;
begin
  FNistAlgorithm := TDerObjectIdentifier.Create('2.16.840.1.101.3.4');
  FHashAlgs := NistAlgorithm.Branch('2');

  FIdSha256 := HashAlgs.Branch('1');
  FIdSha384 := HashAlgs.Branch('2');
  FIdSha512 := HashAlgs.Branch('3');
  FIdSha224 := HashAlgs.Branch('4');
  FIdSha512_224 := HashAlgs.Branch('5');
  FIdSha512_256 := HashAlgs.Branch('6');
  FIdSha3_224 := HashAlgs.Branch('7');
  FIdSha3_256 := HashAlgs.Branch('8');
  FIdSha3_384 := HashAlgs.Branch('9');
  FIdSha3_512 := HashAlgs.Branch('10');
  FIdShake128 := HashAlgs.Branch('11');
  FIdShake256 := HashAlgs.Branch('12');
  FIdShake128Len := HashAlgs.Branch('17');
  FIdShake256Len := HashAlgs.Branch('18');
  FIdHMacWithSha3_224 := HashAlgs.Branch('13');
  FIdHMacWithSha3_256 := HashAlgs.Branch('14');
  FIdHMacWithSha3_384 := HashAlgs.Branch('15');
  FIdHMacWithSha3_512 := HashAlgs.Branch('16');

  FAES := TDerObjectIdentifier.Create(NistAlgorithm.ID + '.1');

  FIdAES128Ecb := TDerObjectIdentifier.Create(AES.ID + '.1');
  FIdAes128Cbc := TDerObjectIdentifier.Create(AES.ID + '.2');
  FIdAes128Ofb := TDerObjectIdentifier.Create(AES.ID + '.3');
  FIdAes128Cfb := TDerObjectIdentifier.Create(AES.ID + '.4');
  FIdAes192Ecb := TDerObjectIdentifier.Create(AES.ID + '.21');
  FIdAes192Cbc := TDerObjectIdentifier.Create(AES.ID + '.22');
  FIdAes192Ofb := TDerObjectIdentifier.Create(AES.ID + '.23');
  FIdAes192Cfb := TDerObjectIdentifier.Create(AES.ID + '.24');
  FIdAes256Ecb := TDerObjectIdentifier.Create(AES.ID + '.41');
  FIdAes256Cbc := TDerObjectIdentifier.Create(AES.ID + '.42');
  FIdAes256Ofb := TDerObjectIdentifier.Create(AES.ID + '.43');
  FIdAes256Cfb := TDerObjectIdentifier.Create(AES.ID + '.44');

  FIdAes128Gcm := TDerObjectIdentifier.Create(AES.ID + '.6');
  FIdAes192Gcm := TDerObjectIdentifier.Create(AES.ID + '.26');
  FIdAes256Gcm := TDerObjectIdentifier.Create(AES.ID + '.46');

  FIdAes128Ccm := TDerObjectIdentifier.Create(AES.ID + '.7');
  FIdAes192Ccm := TDerObjectIdentifier.Create(AES.ID + '.27');
  FIdAes256Ccm := TDerObjectIdentifier.Create(AES.ID + '.47');

  FIdAes128Wrap := TDerObjectIdentifier.Create(AES.ID + '.5');
  FIdAes128WrapPad := TDerObjectIdentifier.Create(AES.ID + '.8');
  FIdAes192Wrap := TDerObjectIdentifier.Create(AES.ID + '.25');
  FIdAes192WrapPad := TDerObjectIdentifier.Create(AES.ID + '.28');
  FIdAes256Wrap := TDerObjectIdentifier.Create(AES.ID + '.45');
  FIdAes256WrapPad := TDerObjectIdentifier.Create(AES.ID + '.48');

  //
  // signatures
  //
  FSigAlgs := NistAlgorithm.Branch('3');
  FIdDsaWithSha2 := SigAlgs;

  FDsaWithSha224 := TDerObjectIdentifier.Create(SigAlgs.ID + '.1');
  FDsaWithSha256 := TDerObjectIdentifier.Create(SigAlgs.ID + '.2');
  FDsaWithSha384 := TDerObjectIdentifier.Create(SigAlgs.ID + '.3');
  FDsaWithSha512 := TDerObjectIdentifier.Create(SigAlgs.ID + '.4');

  FIdDsaWithSha3_224 := TDerObjectIdentifier.Create(SigAlgs.ID + '.5');
  FIdDsaWithSha3_256 := TDerObjectIdentifier.Create(SigAlgs.ID + '.6');
  FIdDsaWithSha3_384 := TDerObjectIdentifier.Create(SigAlgs.ID + '.7');
  FIdDsaWithSha3_512 := TDerObjectIdentifier.Create(SigAlgs.ID + '.8');

  // ECDSA with SHA-3
  FIdECDsaWithSha3_224 := TDerObjectIdentifier.Create(SigAlgs.ID + '.9');
  FIdECDsaWithSha3_256 := TDerObjectIdentifier.Create(SigAlgs.ID + '.10');
  FIdECDsaWithSha3_384 := TDerObjectIdentifier.Create(SigAlgs.ID + '.11');
  FIdECDsaWithSha3_512 := TDerObjectIdentifier.Create(SigAlgs.ID + '.12');

  // RSA PKCS #1 v1.5 Signature with SHA-3 family
  FIdRsassaPkcs1V15WithSha3_224 := TDerObjectIdentifier.Create(SigAlgs.ID + '.13');
  FIdRsassaPkcs1V15WithSha3_256 := TDerObjectIdentifier.Create(SigAlgs.ID + '.14');
  FIdRsassaPkcs1V15WithSha3_384 := TDerObjectIdentifier.Create(SigAlgs.ID + '.15');
  FIdRsassaPkcs1V15WithSha3_512 := TDerObjectIdentifier.Create(SigAlgs.ID + '.16');

  // "pure" ML-DSA
  FIdMlDsa44 := TDerObjectIdentifier.Create(SigAlgs.ID + '.17');
  FIdMlDsa65 := TDerObjectIdentifier.Create(SigAlgs.ID + '.18');
  FIdMlDsa87 := TDerObjectIdentifier.Create(SigAlgs.ID + '.19');

  // "pure" SLH-DSA
  FIdSlhDsaSha2_128s := TDerObjectIdentifier.Create(SigAlgs.ID + '.20');
  FIdSlhDsaSha2_128f := TDerObjectIdentifier.Create(SigAlgs.ID + '.21');
  FIdSlhDsaSha2_192s := TDerObjectIdentifier.Create(SigAlgs.ID + '.22');
  FIdSlhDsaSha2_192f := TDerObjectIdentifier.Create(SigAlgs.ID + '.23');
  FIdSlhDsaSha2_256s := TDerObjectIdentifier.Create(SigAlgs.ID + '.24');
  FIdSlhDsaSha2_256f := TDerObjectIdentifier.Create(SigAlgs.ID + '.25');
  FIdSlhDsaShake_128s := TDerObjectIdentifier.Create(SigAlgs.ID + '.26');
  FIdSlhDsaShake_128f := TDerObjectIdentifier.Create(SigAlgs.ID + '.27');
  FIdSlhDsaShake_192s := TDerObjectIdentifier.Create(SigAlgs.ID + '.28');
  FIdSlhDsaShake_192f := TDerObjectIdentifier.Create(SigAlgs.ID + '.29');
  FIdSlhDsaShake_256s := TDerObjectIdentifier.Create(SigAlgs.ID + '.30');
  FIdSlhDsaShake_256f := TDerObjectIdentifier.Create(SigAlgs.ID + '.31');

  // "pre-hash" ML-DSA
  FIdHashMlDsa44WithSha512 := TDerObjectIdentifier.Create(SigAlgs.ID + '.32');
  FIdHashMlDsa65WithSha512 := TDerObjectIdentifier.Create(SigAlgs.ID + '.33');
  FIdHashMlDsa87WithSha512 := TDerObjectIdentifier.Create(SigAlgs.ID + '.34');

  // "pre-hash" SLH-DSA
  FIdHashSlhDsaSha2_128sWithSha256 := TDerObjectIdentifier.Create(SigAlgs.ID + '.35');
  FIdHashSlhDsaSha2_128fWithSha256 := TDerObjectIdentifier.Create(SigAlgs.ID + '.36');
  FIdHashSlhDsaSha2_192sWithSha512 := TDerObjectIdentifier.Create(SigAlgs.ID + '.37');
  FIdHashSlhDsaSha2_192fWithSha512 := TDerObjectIdentifier.Create(SigAlgs.ID + '.38');
  FIdHashSlhDsaSha2_256sWithSha512 := TDerObjectIdentifier.Create(SigAlgs.ID + '.39');
  FIdHashSlhDsaSha2_256fWithSha512 := TDerObjectIdentifier.Create(SigAlgs.ID + '.40');
  FIdHashSlhDsaShake_128sWithShake128 := TDerObjectIdentifier.Create(SigAlgs.ID + '.41');
  FIdHashSlhDsaShake_128fWithShake128 := TDerObjectIdentifier.Create(SigAlgs.ID + '.42');
  FIdHashSlhDsaShake_192sWithShake256 := TDerObjectIdentifier.Create(SigAlgs.ID + '.43');
  FIdHashSlhDsaShake_192fWithShake256 := TDerObjectIdentifier.Create(SigAlgs.ID + '.44');
  FIdHashSlhDsaShake_256sWithShake256 := TDerObjectIdentifier.Create(SigAlgs.ID + '.45');
  FIdHashSlhDsaShake_256fWithShake256 := TDerObjectIdentifier.Create(SigAlgs.ID + '.46');

  // KEMs - Key-Establishment Mechanisms
  FKems := NistAlgorithm.Branch('4');
  FIdAlgMlKem512 := Kems.Branch('1');
  FIdAlgMlKem768 := Kems.Branch('2');
  FIdAlgMlKem1024 := Kems.Branch('3');
end;

end.
