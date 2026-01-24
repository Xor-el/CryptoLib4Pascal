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

unit ClpOiwObjectIdentifiers;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpAsn1Objects,
  ClpIAsn1Objects;

type
  TOiwObjectIdentifiers = class abstract(TObject)
  strict private
    class var
      FIsBooted: Boolean;
      FMd4WithRsa, FMd5WithRsa, FMd4WithRsaEncryption, FDesEcb, FDesCbc, FDesOfb,
      FDesCfb, FDesEde, FIdSha1, FDsaWithSha1, FSha1WithRsa, FElGamalAlgorithm: IDerObjectIdentifier;

    class function GetMd4WithRsa: IDerObjectIdentifier; static; inline;
    class function GetMd5WithRsa: IDerObjectIdentifier; static; inline;
    class function GetMd4WithRsaEncryption: IDerObjectIdentifier; static; inline;
    class function GetDesEcb: IDerObjectIdentifier; static; inline;
    class function GetDesCbc: IDerObjectIdentifier; static; inline;
    class function GetDesOfb: IDerObjectIdentifier; static; inline;
    class function GetDesCfb: IDerObjectIdentifier; static; inline;
    class function GetDesEde: IDerObjectIdentifier; static; inline;
    class function GetIdSha1: IDerObjectIdentifier; static; inline;
    class function GetDsaWithSha1: IDerObjectIdentifier; static; inline;
    class function GetSha1WithRsa: IDerObjectIdentifier; static; inline;
    class function GetElGamalAlgorithm: IDerObjectIdentifier; static; inline;

    class constructor Create;
  public
    class property Md4WithRsa: IDerObjectIdentifier read GetMd4WithRsa;
    class property Md5WithRsa: IDerObjectIdentifier read GetMd5WithRsa;
    class property Md4WithRsaEncryption: IDerObjectIdentifier read GetMd4WithRsaEncryption;
    class property DesEcb: IDerObjectIdentifier read GetDesEcb;
    class property DesCbc: IDerObjectIdentifier read GetDesCbc;
    class property DesOfb: IDerObjectIdentifier read GetDesOfb;
    class property DesCfb: IDerObjectIdentifier read GetDesCfb;
    class property DesEde: IDerObjectIdentifier read GetDesEde;
    /// <summary>id-SHA1 OBJECT IDENTIFIER ::= { iso(1) identified-organization(3) oiw(14) secsig(3) algorithms(2) 26 }</summary>
    class property IdSha1: IDerObjectIdentifier read GetIdSha1;
    class property DsaWithSha1: IDerObjectIdentifier read GetDsaWithSha1;
    class property Sha1WithRsa: IDerObjectIdentifier read GetSha1WithRsa;
    /// <summary>ElGamal Algorithm OBJECT IDENTIFIER ::= { iso(1) identified-organization(3) oiw(14) dirservsig(7) algorithm(2) encryption(1) 1 }</summary>
    class property ElGamalAlgorithm: IDerObjectIdentifier read GetElGamalAlgorithm;

    class procedure Boot; static;
  end;

implementation

{ TOiwObjectIdentifiers }

class constructor TOiwObjectIdentifiers.Create;
begin
  Boot;
end;

class procedure TOiwObjectIdentifiers.Boot;
begin
  if not FIsBooted then
  begin
    FMd4WithRsa := TDerObjectIdentifier.Create('1.3.14.3.2.2');
    FMd5WithRsa := TDerObjectIdentifier.Create('1.3.14.3.2.3');
    FMd4WithRsaEncryption := TDerObjectIdentifier.Create('1.3.14.3.2.4');
    FDesEcb := TDerObjectIdentifier.Create('1.3.14.3.2.6');
    FDesCbc := TDerObjectIdentifier.Create('1.3.14.3.2.7');
    FDesOfb := TDerObjectIdentifier.Create('1.3.14.3.2.8');
    FDesCfb := TDerObjectIdentifier.Create('1.3.14.3.2.9');
    FDesEde := TDerObjectIdentifier.Create('1.3.14.3.2.17');
    FIdSha1 := TDerObjectIdentifier.Create('1.3.14.3.2.26');
    FDsaWithSha1 := TDerObjectIdentifier.Create('1.3.14.3.2.27');
    FSha1WithRsa := TDerObjectIdentifier.Create('1.3.14.3.2.29');
    FElGamalAlgorithm := TDerObjectIdentifier.Create('1.3.14.7.2.1.1');

    FIsBooted := True;
  end;
end;

class function TOiwObjectIdentifiers.GetDesCbc: IDerObjectIdentifier;
begin
  Result := FDesCbc;
end;

class function TOiwObjectIdentifiers.GetDesCfb: IDerObjectIdentifier;
begin
  Result := FDesCfb;
end;

class function TOiwObjectIdentifiers.GetDesEcb: IDerObjectIdentifier;
begin
  Result := FDesEcb;
end;

class function TOiwObjectIdentifiers.GetDesEde: IDerObjectIdentifier;
begin
  Result := FDesEde;
end;

class function TOiwObjectIdentifiers.GetDesOfb: IDerObjectIdentifier;
begin
  Result := FDesOfb;
end;

class function TOiwObjectIdentifiers.GetDsaWithSha1: IDerObjectIdentifier;
begin
  Result := FDsaWithSha1;
end;

class function TOiwObjectIdentifiers.GetElGamalAlgorithm: IDerObjectIdentifier;
begin
  Result := FElGamalAlgorithm;
end;

class function TOiwObjectIdentifiers.GetIdSha1: IDerObjectIdentifier;
begin
  Result := FIdSha1;
end;

class function TOiwObjectIdentifiers.GetMd4WithRsa: IDerObjectIdentifier;
begin
  Result := FMd4WithRsa;
end;

class function TOiwObjectIdentifiers.GetMd4WithRsaEncryption: IDerObjectIdentifier;
begin
  Result := FMd4WithRsaEncryption;
end;

class function TOiwObjectIdentifiers.GetMd5WithRsa: IDerObjectIdentifier;
begin
  Result := FMd5WithRsa;
end;

class function TOiwObjectIdentifiers.GetSha1WithRsa: IDerObjectIdentifier;
begin
  Result := FSha1WithRsa;
end;

end.
