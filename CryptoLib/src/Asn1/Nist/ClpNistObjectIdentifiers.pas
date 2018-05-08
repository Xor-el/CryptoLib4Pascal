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

unit ClpNistObjectIdentifiers;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpDerObjectIdentifier,
  ClpIDerObjectIdentifier;

type
  TNistObjectIdentifiers = class sealed(TObject)

  strict private

    class var

      FNistAlgorithm, FHashAlgs, FAES, FIdSha256, FIdSha384, FIdSha512,
      FIdSha224, FIdSha512_224, FIdSha512_256, FIdSha3_224, FIdSha3_256,
      FIdSha3_384, FIdSha3_512, FIdAes128Cbc, FIdAes192Cbc,
      FIdAes256Cbc: IDerObjectIdentifier;

    class function GetNistAlgorithm: IDerObjectIdentifier; static; inline;
    class function GetHashAlgs: IDerObjectIdentifier; static; inline;
    class function GetAES: IDerObjectIdentifier; static; inline;
    class function GetIdSha224: IDerObjectIdentifier; static; inline;
    class function GetIdSha256: IDerObjectIdentifier; static; inline;
    class function GetIdSha3_224: IDerObjectIdentifier; static; inline;
    class function GetIdSha3_256: IDerObjectIdentifier; static; inline;
    class function GetIdSha3_384: IDerObjectIdentifier; static; inline;
    class function GetIdSha3_512: IDerObjectIdentifier; static; inline;
    class function GetIdSha384: IDerObjectIdentifier; static; inline;
    class function GetIdSha512: IDerObjectIdentifier; static; inline;
    class function GetIdSha512_224: IDerObjectIdentifier; static; inline;
    class function GetIdSha512_256: IDerObjectIdentifier; static; inline;
    class function GetIdAes128Cbc: IDerObjectIdentifier; static; inline;
    class function GetIdAes192Cbc: IDerObjectIdentifier; static; inline;
    class function GetIdAes256Cbc: IDerObjectIdentifier; static; inline;

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
    class property AES: IDerObjectIdentifier read GetAES;
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
    class property IdAes128Cbc: IDerObjectIdentifier read GetIdAes128Cbc;
    class property IdAes192Cbc: IDerObjectIdentifier read GetIdAes192Cbc;
    class property IdAes256Cbc: IDerObjectIdentifier read GetIdAes256Cbc;

    class procedure Boot(); static;

  end;

implementation

{ TNistObjectIdentifiers }

class procedure TNistObjectIdentifiers.Boot;
begin
  FNistAlgorithm := TDerObjectIdentifier.Create('2.16.840.1.101.3.4');
  FHashAlgs := NistAlgorithm.Branch('2');
  FAES := TDerObjectIdentifier.Create(NistAlgorithm.id + '.1');

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
  FIdAes128Cbc := TDerObjectIdentifier.Create(AES.id + '.2');
  FIdAes192Cbc := TDerObjectIdentifier.Create(AES.id + '.22');
  FIdAes256Cbc := TDerObjectIdentifier.Create(AES.id + '.42');
end;

class function TNistObjectIdentifiers.GetAES: IDerObjectIdentifier;
begin
  result := FAES;
end;

class function TNistObjectIdentifiers.GetHashAlgs: IDerObjectIdentifier;
begin
  result := FHashAlgs;
end;

class function TNistObjectIdentifiers.GetIdAes128Cbc: IDerObjectIdentifier;
begin
  result := FIdAes128Cbc;
end;

class function TNistObjectIdentifiers.GetIdAes192Cbc: IDerObjectIdentifier;
begin
  result := FIdAes192Cbc;
end;

class function TNistObjectIdentifiers.GetIdAes256Cbc: IDerObjectIdentifier;
begin
  result := FIdAes256Cbc;
end;

class function TNistObjectIdentifiers.GetIdSha224: IDerObjectIdentifier;
begin
  result := FIdSha224;
end;

class function TNistObjectIdentifiers.GetIdSha256: IDerObjectIdentifier;
begin
  result := FIdSha256;
end;

class function TNistObjectIdentifiers.GetIdSha384: IDerObjectIdentifier;
begin
  result := FIdSha384;
end;

class function TNistObjectIdentifiers.GetIdSha3_224: IDerObjectIdentifier;
begin
  result := FIdSha3_224;
end;

class function TNistObjectIdentifiers.GetIdSha3_256: IDerObjectIdentifier;
begin
  result := FIdSha3_256;
end;

class function TNistObjectIdentifiers.GetIdSha3_384: IDerObjectIdentifier;
begin
  result := FIdSha3_384;
end;

class function TNistObjectIdentifiers.GetIdSha3_512: IDerObjectIdentifier;
begin
  result := FIdSha3_512;
end;

class function TNistObjectIdentifiers.GetIdSha512: IDerObjectIdentifier;
begin
  result := FIdSha512;
end;

class function TNistObjectIdentifiers.GetIdSha512_224: IDerObjectIdentifier;
begin
  result := FIdSha512_224;
end;

class function TNistObjectIdentifiers.GetIdSha512_256: IDerObjectIdentifier;
begin
  result := FIdSha512_256;
end;

class function TNistObjectIdentifiers.GetNistAlgorithm: IDerObjectIdentifier;
begin
  result := FNistAlgorithm;
end;

class constructor TNistObjectIdentifiers.NistObjectIdentifiers;
begin
  TNistObjectIdentifiers.Boot;
end;

end.
