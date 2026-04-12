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

    FIsBooted: Boolean;
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
      FIdAes128Wrap, FIdAes128WrapPad,
      FIdAes192Wrap, FIdAes192WrapPad, FIdAes256Wrap,
      FIdAes256WrapPad: IDerObjectIdentifier;

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

    class constructor NistObjectIdentifiers();

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

    class procedure Boot(); static;

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

class function TNistObjectIdentifiers.GetNistAlgorithm: IDerObjectIdentifier;
begin
  Result := FNistAlgorithm;
end;

class function TNistObjectIdentifiers.GetSigAlgs: IDerObjectIdentifier;
begin
  Result := FSigAlgs;
end;

class constructor TNistObjectIdentifiers.NistObjectIdentifiers;
begin
  TNistObjectIdentifiers.Boot;
end;

class procedure TNistObjectIdentifiers.Boot;
begin
  if not FIsBooted then
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

    FIsBooted := True;
  end;

end;

end.
