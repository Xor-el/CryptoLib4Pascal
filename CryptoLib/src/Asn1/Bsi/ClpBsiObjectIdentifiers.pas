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

unit ClpBsiObjectIdentifiers;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpAsn1Objects,
  ClpIAsn1Objects;

type
  /// <remarks>See https://www.bsi.bund.de/cae/servlet/contentblob/471398/publicationFile/30615/BSI-TR-03111_pdf.pdf</remarks>
  TBsiObjectIdentifiers = class abstract(TObject)
  strict private
    class var
      FIsBooted: Boolean;
      FBsiDe, FIdEcc, FAlgorithm, FEcdsaPlainSignatures,
      FEcdsaPlainSha1, FEcdsaPlainSha224, FEcdsaPlainSha256, FEcdsaPlainSha384,
      FEcdsaPlainSha512, FEcdsaPlainRipeMD160, FEcdsaPlainSha3_224,
      FEcdsaPlainSha3_256, FEcdsaPlainSha3_384, FEcdsaPlainSha3_512,
      FEckaEg, FEckaEgX963Kdf, FEckaEgX963KdfSha1, FEckaEgX963KdfSha224,
      FEckaEgX963KdfSha256, FEckaEgX963KdfSha384, FEckaEgX963KdfSha512,
      FEckaEgX963KdfRipeMD160, FEckaEgSessionKdf, FEckaEgSessionKdf3Des,
      FEckaEgSessionKdfAes128, FEckaEgSessionKdfAes192, FEckaEgSessionKdfAes256: IDerObjectIdentifier;

    class function GetBsiDe: IDerObjectIdentifier; static; inline;
    class function GetIdEcc: IDerObjectIdentifier; static; inline;
    class function GetAlgorithm: IDerObjectIdentifier; static; inline;
    class function GetEcdsaPlainSignatures: IDerObjectIdentifier; static; inline;
    class function GetEcdsaPlainSha1: IDerObjectIdentifier; static; inline;
    class function GetEcdsaPlainSha224: IDerObjectIdentifier; static; inline;
    class function GetEcdsaPlainSha256: IDerObjectIdentifier; static; inline;
    class function GetEcdsaPlainSha384: IDerObjectIdentifier; static; inline;
    class function GetEcdsaPlainSha512: IDerObjectIdentifier; static; inline;
    class function GetEcdsaPlainRipeMD160: IDerObjectIdentifier; static; inline;
    class function GetEcdsaPlainSha3_224: IDerObjectIdentifier; static; inline;
    class function GetEcdsaPlainSha3_256: IDerObjectIdentifier; static; inline;
    class function GetEcdsaPlainSha3_384: IDerObjectIdentifier; static; inline;
    class function GetEcdsaPlainSha3_512: IDerObjectIdentifier; static; inline;
    class function GetEckaEg: IDerObjectIdentifier; static; inline;
    class function GetEckaEgX963Kdf: IDerObjectIdentifier; static; inline;
    class function GetEckaEgX963KdfSha1: IDerObjectIdentifier; static; inline;
    class function GetEckaEgX963KdfSha224: IDerObjectIdentifier; static; inline;
    class function GetEckaEgX963KdfSha256: IDerObjectIdentifier; static; inline;
    class function GetEckaEgX963KdfSha384: IDerObjectIdentifier; static; inline;
    class function GetEckaEgX963KdfSha512: IDerObjectIdentifier; static; inline;
    class function GetEckaEgX963KdfRipeMD160: IDerObjectIdentifier; static; inline;
    class function GetEckaEgSessionKdf: IDerObjectIdentifier; static; inline;
    class function GetEckaEgSessionKdf3Des: IDerObjectIdentifier; static; inline;
    class function GetEckaEgSessionKdfAes128: IDerObjectIdentifier; static; inline;
    class function GetEckaEgSessionKdfAes192: IDerObjectIdentifier; static; inline;
    class function GetEckaEgSessionKdfAes256: IDerObjectIdentifier; static; inline;

    class constructor Create;
  public
    class property BsiDe: IDerObjectIdentifier read GetBsiDe;
    class property IdEcc: IDerObjectIdentifier read GetIdEcc;
    class property Algorithm: IDerObjectIdentifier read GetAlgorithm;
    class property EcdsaPlainSignatures: IDerObjectIdentifier read GetEcdsaPlainSignatures;
    class property EcdsaPlainSha1: IDerObjectIdentifier read GetEcdsaPlainSha1;
    class property EcdsaPlainSha224: IDerObjectIdentifier read GetEcdsaPlainSha224;
    class property EcdsaPlainSha256: IDerObjectIdentifier read GetEcdsaPlainSha256;
    class property EcdsaPlainSha384: IDerObjectIdentifier read GetEcdsaPlainSha384;
    class property EcdsaPlainSha512: IDerObjectIdentifier read GetEcdsaPlainSha512;
    class property EcdsaPlainRipeMD160: IDerObjectIdentifier read GetEcdsaPlainRipeMD160;
    class property EcdsaPlainSha3_224: IDerObjectIdentifier read GetEcdsaPlainSha3_224;
    class property EcdsaPlainSha3_256: IDerObjectIdentifier read GetEcdsaPlainSha3_256;
    class property EcdsaPlainSha3_384: IDerObjectIdentifier read GetEcdsaPlainSha3_384;
    class property EcdsaPlainSha3_512: IDerObjectIdentifier read GetEcdsaPlainSha3_512;
    class property EckaEg: IDerObjectIdentifier read GetEckaEg;
    class property EckaEgX963Kdf: IDerObjectIdentifier read GetEckaEgX963Kdf;
    class property EckaEgX963KdfSha1: IDerObjectIdentifier read GetEckaEgX963KdfSha1;
    class property EckaEgX963KdfSha224: IDerObjectIdentifier read GetEckaEgX963KdfSha224;
    class property EckaEgX963KdfSha256: IDerObjectIdentifier read GetEckaEgX963KdfSha256;
    class property EckaEgX963KdfSha384: IDerObjectIdentifier read GetEckaEgX963KdfSha384;
    class property EckaEgX963KdfSha512: IDerObjectIdentifier read GetEckaEgX963KdfSha512;
    class property EckaEgX963KdfRipeMD160: IDerObjectIdentifier read GetEckaEgX963KdfRipeMD160;
    class property EckaEgSessionKdf: IDerObjectIdentifier read GetEckaEgSessionKdf;
    class property EckaEgSessionKdf3Des: IDerObjectIdentifier read GetEckaEgSessionKdf3Des;
    class property EckaEgSessionKdfAes128: IDerObjectIdentifier read GetEckaEgSessionKdfAes128;
    class property EckaEgSessionKdfAes192: IDerObjectIdentifier read GetEckaEgSessionKdfAes192;
    class property EckaEgSessionKdfAes256: IDerObjectIdentifier read GetEckaEgSessionKdfAes256;

    class procedure Boot; static;
  end;

implementation

{ TBsiObjectIdentifiers }

class constructor TBsiObjectIdentifiers.Create;
begin
  Boot;
end;

class procedure TBsiObjectIdentifiers.Boot;
begin
  if not FIsBooted then
  begin
    FBsiDe := TDerObjectIdentifier.Create('0.4.0.127.0.7');
    FIdEcc := FBsiDe.Branch('1.1');
    FAlgorithm := FBsiDe.Branch('1');

    FEcdsaPlainSignatures := FIdEcc.Branch('4.1');
    FEcdsaPlainSha1 := FEcdsaPlainSignatures.Branch('1');
    FEcdsaPlainSha224 := FEcdsaPlainSignatures.Branch('2');
    FEcdsaPlainSha256 := FEcdsaPlainSignatures.Branch('3');
    FEcdsaPlainSha384 := FEcdsaPlainSignatures.Branch('4');
    FEcdsaPlainSha512 := FEcdsaPlainSignatures.Branch('5');
    FEcdsaPlainRipeMD160 := FEcdsaPlainSignatures.Branch('6');
    FEcdsaPlainSha3_224 := FEcdsaPlainSignatures.Branch('8');
    FEcdsaPlainSha3_256 := FEcdsaPlainSignatures.Branch('9');
    FEcdsaPlainSha3_384 := FEcdsaPlainSignatures.Branch('10');
    FEcdsaPlainSha3_512 := FEcdsaPlainSignatures.Branch('11');

    FEckaEg := FIdEcc.Branch('5.1');
    FEckaEgX963Kdf := FEckaEg.Branch('1');
    FEckaEgX963KdfSha1 := FEckaEgX963Kdf.Branch('1');
    FEckaEgX963KdfSha224 := FEckaEgX963Kdf.Branch('2');
    FEckaEgX963KdfSha256 := FEckaEgX963Kdf.Branch('3');
    FEckaEgX963KdfSha384 := FEckaEgX963Kdf.Branch('4');
    FEckaEgX963KdfSha512 := FEckaEgX963Kdf.Branch('5');
    FEckaEgX963KdfRipeMD160 := FEckaEgX963Kdf.Branch('6');

    FEckaEgSessionKdf := FEckaEg.Branch('2');
    FEckaEgSessionKdf3Des := FEckaEgSessionKdf.Branch('1');
    FEckaEgSessionKdfAes128 := FEckaEgSessionKdf.Branch('2');
    FEckaEgSessionKdfAes192 := FEckaEgSessionKdf.Branch('3');
    FEckaEgSessionKdfAes256 := FEckaEgSessionKdf.Branch('4');

    FIsBooted := True;
  end;
end;

class function TBsiObjectIdentifiers.GetAlgorithm: IDerObjectIdentifier;
begin
  Result := FAlgorithm;
end;

class function TBsiObjectIdentifiers.GetBsiDe: IDerObjectIdentifier;
begin
  Result := FBsiDe;
end;

class function TBsiObjectIdentifiers.GetEcdsaPlainRipeMD160: IDerObjectIdentifier;
begin
  Result := FEcdsaPlainRipeMD160;
end;

class function TBsiObjectIdentifiers.GetEcdsaPlainSha1: IDerObjectIdentifier;
begin
  Result := FEcdsaPlainSha1;
end;

class function TBsiObjectIdentifiers.GetEcdsaPlainSha224: IDerObjectIdentifier;
begin
  Result := FEcdsaPlainSha224;
end;

class function TBsiObjectIdentifiers.GetEcdsaPlainSha256: IDerObjectIdentifier;
begin
  Result := FEcdsaPlainSha256;
end;

class function TBsiObjectIdentifiers.GetEcdsaPlainSha384: IDerObjectIdentifier;
begin
  Result := FEcdsaPlainSha384;
end;

class function TBsiObjectIdentifiers.GetEcdsaPlainSha512: IDerObjectIdentifier;
begin
  Result := FEcdsaPlainSha512;
end;

class function TBsiObjectIdentifiers.GetEcdsaPlainSha3_224: IDerObjectIdentifier;
begin
  Result := FEcdsaPlainSha3_224;
end;

class function TBsiObjectIdentifiers.GetEcdsaPlainSha3_256: IDerObjectIdentifier;
begin
  Result := FEcdsaPlainSha3_256;
end;

class function TBsiObjectIdentifiers.GetEcdsaPlainSha3_384: IDerObjectIdentifier;
begin
  Result := FEcdsaPlainSha3_384;
end;

class function TBsiObjectIdentifiers.GetEcdsaPlainSha3_512: IDerObjectIdentifier;
begin
  Result := FEcdsaPlainSha3_512;
end;

class function TBsiObjectIdentifiers.GetEcdsaPlainSignatures: IDerObjectIdentifier;
begin
  Result := FEcdsaPlainSignatures;
end;

class function TBsiObjectIdentifiers.GetEckaEg: IDerObjectIdentifier;
begin
  Result := FEckaEg;
end;

class function TBsiObjectIdentifiers.GetEckaEgSessionKdf: IDerObjectIdentifier;
begin
  Result := FEckaEgSessionKdf;
end;

class function TBsiObjectIdentifiers.GetEckaEgSessionKdf3Des: IDerObjectIdentifier;
begin
  Result := FEckaEgSessionKdf3Des;
end;

class function TBsiObjectIdentifiers.GetEckaEgSessionKdfAes128: IDerObjectIdentifier;
begin
  Result := FEckaEgSessionKdfAes128;
end;

class function TBsiObjectIdentifiers.GetEckaEgSessionKdfAes192: IDerObjectIdentifier;
begin
  Result := FEckaEgSessionKdfAes192;
end;

class function TBsiObjectIdentifiers.GetEckaEgSessionKdfAes256: IDerObjectIdentifier;
begin
  Result := FEckaEgSessionKdfAes256;
end;

class function TBsiObjectIdentifiers.GetEckaEgX963Kdf: IDerObjectIdentifier;
begin
  Result := FEckaEgX963Kdf;
end;

class function TBsiObjectIdentifiers.GetEckaEgX963KdfRipeMD160: IDerObjectIdentifier;
begin
  Result := FEckaEgX963KdfRipeMD160;
end;

class function TBsiObjectIdentifiers.GetEckaEgX963KdfSha1: IDerObjectIdentifier;
begin
  Result := FEckaEgX963KdfSha1;
end;

class function TBsiObjectIdentifiers.GetEckaEgX963KdfSha224: IDerObjectIdentifier;
begin
  Result := FEckaEgX963KdfSha224;
end;

class function TBsiObjectIdentifiers.GetEckaEgX963KdfSha256: IDerObjectIdentifier;
begin
  Result := FEckaEgX963KdfSha256;
end;

class function TBsiObjectIdentifiers.GetEckaEgX963KdfSha384: IDerObjectIdentifier;
begin
  Result := FEckaEgX963KdfSha384;
end;

class function TBsiObjectIdentifiers.GetEckaEgX963KdfSha512: IDerObjectIdentifier;
begin
  Result := FEckaEgX963KdfSha512;
end;

class function TBsiObjectIdentifiers.GetIdEcc: IDerObjectIdentifier;
begin
  Result := FIdEcc;
end;

end.
