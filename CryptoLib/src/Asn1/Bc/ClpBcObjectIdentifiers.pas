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

unit ClpBcObjectIdentifiers;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpAsn1Objects,
  ClpIAsn1Objects;

type
  TBcObjectIdentifiers = class abstract(TObject)
  strict private
    class var
      FIsBooted: Boolean;
      FBc, FBcPbe,
      FBcPbeSha1, FBcPbeSha256, FBcPbeSha384, FBcPbeSha512, FBcPbeSha224,
      FBcPbeSha1Pkcs5, FBcPbeSha1Pkcs12,
      FBcPbeSha256Pkcs5, FBcPbeSha256Pkcs12,
      FBcPbeSha1Pkcs12Aes128Cbc, FBcPbeSha1Pkcs12Aes192Cbc, FBcPbeSha1Pkcs12Aes256Cbc,
      FBcPbeSha256Pkcs12Aes128Cbc, FBcPbeSha256Pkcs12Aes192Cbc, FBcPbeSha256Pkcs12Aes256Cbc
        : IDerObjectIdentifier;

    class function GetBc: IDerObjectIdentifier; static; inline;
    class function GetBcPbe: IDerObjectIdentifier; static; inline;
    class function GetBcPbeSha1: IDerObjectIdentifier; static; inline;
    class function GetBcPbeSha256: IDerObjectIdentifier; static; inline;
    class function GetBcPbeSha384: IDerObjectIdentifier; static; inline;
    class function GetBcPbeSha512: IDerObjectIdentifier; static; inline;
    class function GetBcPbeSha224: IDerObjectIdentifier; static; inline;
    class function GetBcPbeSha1Pkcs5: IDerObjectIdentifier; static; inline;
    class function GetBcPbeSha1Pkcs12: IDerObjectIdentifier; static; inline;
    class function GetBcPbeSha256Pkcs5: IDerObjectIdentifier; static; inline;
    class function GetBcPbeSha256Pkcs12: IDerObjectIdentifier; static; inline;
    class function GetBcPbeSha1Pkcs12Aes128Cbc: IDerObjectIdentifier; static; inline;
    class function GetBcPbeSha1Pkcs12Aes192Cbc: IDerObjectIdentifier; static; inline;
    class function GetBcPbeSha1Pkcs12Aes256Cbc: IDerObjectIdentifier; static; inline;
    class function GetBcPbeSha256Pkcs12Aes128Cbc: IDerObjectIdentifier; static; inline;
    class function GetBcPbeSha256Pkcs12Aes192Cbc: IDerObjectIdentifier; static; inline;
    class function GetBcPbeSha256Pkcs12Aes256Cbc: IDerObjectIdentifier; static; inline;

    class constructor Create;
  public
    /// <summary>1.3.6.1.4.1.22554</summary>
    class property Bc: IDerObjectIdentifier read GetBc;
    /// <summary>pbe(1): 1.3.6.1.4.1.22554.1</summary>
    class property BcPbe: IDerObjectIdentifier read GetBcPbe;
    /// <summary>SHA-1(1): 1.3.6.1.4.1.22554.1.1</summary>
    class property BcPbeSha1: IDerObjectIdentifier read GetBcPbeSha1;
    /// <summary>SHA-256: 1.3.6.1.4.1.22554.1.2.1</summary>
    class property BcPbeSha256: IDerObjectIdentifier read GetBcPbeSha256;
    /// <summary>SHA-384: 1.3.6.1.4.1.22554.1.2.2</summary>
    class property BcPbeSha384: IDerObjectIdentifier read GetBcPbeSha384;
    /// <summary>SHA-512: 1.3.6.1.4.1.22554.1.2.3</summary>
    class property BcPbeSha512: IDerObjectIdentifier read GetBcPbeSha512;
    /// <summary>SHA-224: 1.3.6.1.4.1.22554.1.2.4</summary>
    class property BcPbeSha224: IDerObjectIdentifier read GetBcPbeSha224;
    /// <summary>SHA-1.PKCS5: 1.3.6.1.4.1.22554.1.1.1</summary>
    class property BcPbeSha1Pkcs5: IDerObjectIdentifier read GetBcPbeSha1Pkcs5;
    /// <summary>SHA-1.PKCS12: 1.3.6.1.4.1.22554.1.1.2</summary>
    class property BcPbeSha1Pkcs12: IDerObjectIdentifier read GetBcPbeSha1Pkcs12;
    /// <summary>SHA-256.PKCS5: 1.3.6.1.4.1.22554.1.2.1.1</summary>
    class property BcPbeSha256Pkcs5: IDerObjectIdentifier read GetBcPbeSha256Pkcs5;
    /// <summary>SHA-256.PKCS12: 1.3.6.1.4.1.22554.1.2.1.2</summary>
    class property BcPbeSha256Pkcs12: IDerObjectIdentifier read GetBcPbeSha256Pkcs12;
    /// <summary>1.3.6.1.4.1.22554.1.1.2.1.2</summary>
    class property BcPbeSha1Pkcs12Aes128Cbc: IDerObjectIdentifier read GetBcPbeSha1Pkcs12Aes128Cbc;
    /// <summary>1.3.6.1.4.1.22554.1.1.2.1.22</summary>
    class property BcPbeSha1Pkcs12Aes192Cbc: IDerObjectIdentifier read GetBcPbeSha1Pkcs12Aes192Cbc;
    /// <summary>1.3.6.1.4.1.22554.1.1.2.1.42</summary>
    class property BcPbeSha1Pkcs12Aes256Cbc: IDerObjectIdentifier read GetBcPbeSha1Pkcs12Aes256Cbc;
    /// <summary>1.3.6.1.4.1.22554.1.1.2.2.2</summary>
    class property BcPbeSha256Pkcs12Aes128Cbc: IDerObjectIdentifier read GetBcPbeSha256Pkcs12Aes128Cbc;
    /// <summary>1.3.6.1.4.1.22554.1.1.2.2.22</summary>
    class property BcPbeSha256Pkcs12Aes192Cbc: IDerObjectIdentifier read GetBcPbeSha256Pkcs12Aes192Cbc;
    /// <summary>1.3.6.1.4.1.22554.1.1.2.2.42</summary>
    class property BcPbeSha256Pkcs12Aes256Cbc: IDerObjectIdentifier read GetBcPbeSha256Pkcs12Aes256Cbc;

    class procedure Boot; static;
  end;

implementation

{ TBcObjectIdentifiers }

class constructor TBcObjectIdentifiers.Create;
begin
  Boot;
end;

class procedure TBcObjectIdentifiers.Boot;
begin
  if not FIsBooted then
  begin
    FBc := TDerObjectIdentifier.Create('1.3.6.1.4.1.22554');
    FBcPbe := FBc.Branch('1');
    FBcPbeSha1 := FBcPbe.Branch('1');
    FBcPbeSha256 := FBcPbe.Branch('2.1');
    FBcPbeSha384 := FBcPbe.Branch('2.2');
    FBcPbeSha512 := FBcPbe.Branch('2.3');
    FBcPbeSha224 := FBcPbe.Branch('2.4');
    FBcPbeSha1Pkcs5 := FBcPbeSha1.Branch('1');
    FBcPbeSha1Pkcs12 := FBcPbeSha1.Branch('2');
    FBcPbeSha256Pkcs5 := FBcPbeSha256.Branch('1');
    FBcPbeSha256Pkcs12 := FBcPbeSha256.Branch('2');
    FBcPbeSha1Pkcs12Aes128Cbc := FBcPbeSha1Pkcs12.Branch('1.2');
    FBcPbeSha1Pkcs12Aes192Cbc := FBcPbeSha1Pkcs12.Branch('1.22');
    FBcPbeSha1Pkcs12Aes256Cbc := FBcPbeSha1Pkcs12.Branch('1.42');
    FBcPbeSha256Pkcs12Aes128Cbc := FBcPbeSha256Pkcs12.Branch('1.2');
    FBcPbeSha256Pkcs12Aes192Cbc := FBcPbeSha256Pkcs12.Branch('1.22');
    FBcPbeSha256Pkcs12Aes256Cbc := FBcPbeSha256Pkcs12.Branch('1.42');

    FIsBooted := True;
  end;
end;

class function TBcObjectIdentifiers.GetBc: IDerObjectIdentifier;
begin
  Result := FBc;
end;

class function TBcObjectIdentifiers.GetBcPbe: IDerObjectIdentifier;
begin
  Result := FBcPbe;
end;

class function TBcObjectIdentifiers.GetBcPbeSha1: IDerObjectIdentifier;
begin
  Result := FBcPbeSha1;
end;

class function TBcObjectIdentifiers.GetBcPbeSha256: IDerObjectIdentifier;
begin
  Result := FBcPbeSha256;
end;

class function TBcObjectIdentifiers.GetBcPbeSha384: IDerObjectIdentifier;
begin
  Result := FBcPbeSha384;
end;

class function TBcObjectIdentifiers.GetBcPbeSha512: IDerObjectIdentifier;
begin
  Result := FBcPbeSha512;
end;

class function TBcObjectIdentifiers.GetBcPbeSha224: IDerObjectIdentifier;
begin
  Result := FBcPbeSha224;
end;

class function TBcObjectIdentifiers.GetBcPbeSha1Pkcs5: IDerObjectIdentifier;
begin
  Result := FBcPbeSha1Pkcs5;
end;

class function TBcObjectIdentifiers.GetBcPbeSha1Pkcs12: IDerObjectIdentifier;
begin
  Result := FBcPbeSha1Pkcs12;
end;

class function TBcObjectIdentifiers.GetBcPbeSha256Pkcs5: IDerObjectIdentifier;
begin
  Result := FBcPbeSha256Pkcs5;
end;

class function TBcObjectIdentifiers.GetBcPbeSha256Pkcs12: IDerObjectIdentifier;
begin
  Result := FBcPbeSha256Pkcs12;
end;

class function TBcObjectIdentifiers.GetBcPbeSha1Pkcs12Aes128Cbc: IDerObjectIdentifier;
begin
  Result := FBcPbeSha1Pkcs12Aes128Cbc;
end;

class function TBcObjectIdentifiers.GetBcPbeSha1Pkcs12Aes192Cbc: IDerObjectIdentifier;
begin
  Result := FBcPbeSha1Pkcs12Aes192Cbc;
end;

class function TBcObjectIdentifiers.GetBcPbeSha1Pkcs12Aes256Cbc: IDerObjectIdentifier;
begin
  Result := FBcPbeSha1Pkcs12Aes256Cbc;
end;

class function TBcObjectIdentifiers.GetBcPbeSha256Pkcs12Aes128Cbc: IDerObjectIdentifier;
begin
  Result := FBcPbeSha256Pkcs12Aes128Cbc;
end;

class function TBcObjectIdentifiers.GetBcPbeSha256Pkcs12Aes192Cbc: IDerObjectIdentifier;
begin
  Result := FBcPbeSha256Pkcs12Aes192Cbc;
end;

class function TBcObjectIdentifiers.GetBcPbeSha256Pkcs12Aes256Cbc: IDerObjectIdentifier;
begin
  Result := FBcPbeSha256Pkcs12Aes256Cbc;
end;

end.
