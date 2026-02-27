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

unit ClpGnuObjectIdentifiers;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpAsn1Objects,
  ClpIAsn1Objects;

type
  /// <summary>GNU project OIDs (1.3.6.1.4.1.11591)</summary>
  TGnuObjectIdentifiers = class abstract(TObject)
  strict private
    class var
      FIsBooted: Boolean;
      FGnu, FGnuPG, FNotation, FPkaAddress, FGnuRadar,
      FDigestAlgorithm, FTiger192,
      FEncryptionAlgorithm, FSerpent,
      FSerpent128Ecb, FSerpent128Cbc, FSerpent128Ofb, FSerpent128Cfb,
      FSerpent192Ecb, FSerpent192Cbc, FSerpent192Ofb, FSerpent192Cfb,
      FSerpent256Ecb, FSerpent256Cbc, FSerpent256Ofb, FSerpent256Cfb,
      FCrc, FCrc32,
      FEllipticCurve, FEd25519: IDerObjectIdentifier;

    class function GetGnu: IDerObjectIdentifier; static; inline;
    class function GetGnuPG: IDerObjectIdentifier; static; inline;
    class function GetNotation: IDerObjectIdentifier; static; inline;
    class function GetPkaAddress: IDerObjectIdentifier; static; inline;
    class function GetGnuRadar: IDerObjectIdentifier; static; inline;
    class function GetDigestAlgorithm: IDerObjectIdentifier; static; inline;
    class function GetTiger192: IDerObjectIdentifier; static; inline;
    class function GetEncryptionAlgorithm: IDerObjectIdentifier; static; inline;
    class function GetSerpent: IDerObjectIdentifier; static; inline;
    class function GetSerpent128Ecb: IDerObjectIdentifier; static; inline;
    class function GetSerpent128Cbc: IDerObjectIdentifier; static; inline;
    class function GetSerpent128Ofb: IDerObjectIdentifier; static; inline;
    class function GetSerpent128Cfb: IDerObjectIdentifier; static; inline;
    class function GetSerpent192Ecb: IDerObjectIdentifier; static; inline;
    class function GetSerpent192Cbc: IDerObjectIdentifier; static; inline;
    class function GetSerpent192Ofb: IDerObjectIdentifier; static; inline;
    class function GetSerpent192Cfb: IDerObjectIdentifier; static; inline;
    class function GetSerpent256Ecb: IDerObjectIdentifier; static; inline;
    class function GetSerpent256Cbc: IDerObjectIdentifier; static; inline;
    class function GetSerpent256Ofb: IDerObjectIdentifier; static; inline;
    class function GetSerpent256Cfb: IDerObjectIdentifier; static; inline;
    class function GetCrc: IDerObjectIdentifier; static; inline;
    class function GetCrc32: IDerObjectIdentifier; static; inline;
    class function GetEllipticCurve: IDerObjectIdentifier; static; inline;
    class function GetEd25519: IDerObjectIdentifier; static; inline;

    class constructor Create;
  public
    /// <summary>1.3.6.1.4.1.11591.1 - GNU Radius</summary>
    class property Gnu: IDerObjectIdentifier read GetGnu;
    /// <summary>1.3.6.1.4.1.11591.2 - GnuPG</summary>
    class property GnuPG: IDerObjectIdentifier read GetGnuPG;
    /// <summary>1.3.6.1.4.1.11591.2.1 - notation</summary>
    class property Notation: IDerObjectIdentifier read GetNotation;
    /// <summary>1.3.6.1.4.1.11591.2.1.1 - pkaAddress</summary>
    class property PkaAddress: IDerObjectIdentifier read GetPkaAddress;
    /// <summary>1.3.6.1.4.1.11591.3 - GNU Radar</summary>
    class property GnuRadar: IDerObjectIdentifier read GetGnuRadar;
    /// <summary>1.3.6.1.4.1.11591.12 - digestAlgorithm</summary>
    class property DigestAlgorithm: IDerObjectIdentifier read GetDigestAlgorithm;
    /// <summary>1.3.6.1.4.1.11591.12.2 - TIGER/192</summary>
    class property Tiger192: IDerObjectIdentifier read GetTiger192;
    /// <summary>1.3.6.1.4.1.11591.13 - encryptionAlgorithm</summary>
    class property EncryptionAlgorithm: IDerObjectIdentifier read GetEncryptionAlgorithm;
    /// <summary>1.3.6.1.4.1.11591.13.2 - Serpent</summary>
    class property Serpent: IDerObjectIdentifier read GetSerpent;
    /// <summary>1.3.6.1.4.1.11591.13.2.1 - Serpent-128-ECB</summary>
    class property Serpent128Ecb: IDerObjectIdentifier read GetSerpent128Ecb;
    /// <summary>1.3.6.1.4.1.11591.13.2.2 - Serpent-128-CBC</summary>
    class property Serpent128Cbc: IDerObjectIdentifier read GetSerpent128Cbc;
    /// <summary>1.3.6.1.4.1.11591.13.2.3 - Serpent-128-OFB</summary>
    class property Serpent128Ofb: IDerObjectIdentifier read GetSerpent128Ofb;
    /// <summary>1.3.6.1.4.1.11591.13.2.4 - Serpent-128-CFB</summary>
    class property Serpent128Cfb: IDerObjectIdentifier read GetSerpent128Cfb;
    /// <summary>1.3.6.1.4.1.11591.13.2.21 - Serpent-192-ECB</summary>
    class property Serpent192Ecb: IDerObjectIdentifier read GetSerpent192Ecb;
    /// <summary>1.3.6.1.4.1.11591.13.2.22 - Serpent-192-CBC</summary>
    class property Serpent192Cbc: IDerObjectIdentifier read GetSerpent192Cbc;
    /// <summary>1.3.6.1.4.1.11591.13.2.23 - Serpent-192-OFB</summary>
    class property Serpent192Ofb: IDerObjectIdentifier read GetSerpent192Ofb;
    /// <summary>1.3.6.1.4.1.11591.13.2.24 - Serpent-192-CFB</summary>
    class property Serpent192Cfb: IDerObjectIdentifier read GetSerpent192Cfb;
    /// <summary>1.3.6.1.4.1.11591.13.2.41 - Serpent-256-ECB</summary>
    class property Serpent256Ecb: IDerObjectIdentifier read GetSerpent256Ecb;
    /// <summary>1.3.6.1.4.1.11591.13.2.42 - Serpent-256-CBC</summary>
    class property Serpent256Cbc: IDerObjectIdentifier read GetSerpent256Cbc;
    /// <summary>1.3.6.1.4.1.11591.13.2.43 - Serpent-256-OFB</summary>
    class property Serpent256Ofb: IDerObjectIdentifier read GetSerpent256Ofb;
    /// <summary>1.3.6.1.4.1.11591.13.2.44 - Serpent-256-CFB</summary>
    class property Serpent256Cfb: IDerObjectIdentifier read GetSerpent256Cfb;
    /// <summary>1.3.6.1.4.1.11591.14 - CRC algorithms</summary>
    class property Crc: IDerObjectIdentifier read GetCrc;
    /// <summary>1.3.6.1.4.1.11591.14.1 - CRC 32</summary>
    class property Crc32: IDerObjectIdentifier read GetCrc32;
    /// <summary>1.3.6.1.4.1.11591.15 - ellipticCurve</summary>
    class property EllipticCurve: IDerObjectIdentifier read GetEllipticCurve;
    /// <summary>1.3.6.1.4.1.11591.15.1 - Ed25519</summary>
    class property Ed25519: IDerObjectIdentifier read GetEd25519;

    class procedure Boot; static;
  end;

implementation

{ TGnuObjectIdentifiers }

class constructor TGnuObjectIdentifiers.Create;
begin
  Boot;
end;

class procedure TGnuObjectIdentifiers.Boot;
begin
  if not FIsBooted then
  begin
    FGnu := TDerObjectIdentifier.Create('1.3.6.1.4.1.11591.1');
    FGnuPG := TDerObjectIdentifier.Create('1.3.6.1.4.1.11591.2');
    FNotation := TDerObjectIdentifier.Create('1.3.6.1.4.1.11591.2.1');
    FPkaAddress := TDerObjectIdentifier.Create('1.3.6.1.4.1.11591.2.1.1');
    FGnuRadar := TDerObjectIdentifier.Create('1.3.6.1.4.1.11591.3');
    FDigestAlgorithm := TDerObjectIdentifier.Create('1.3.6.1.4.1.11591.12');
    FTiger192 := TDerObjectIdentifier.Create('1.3.6.1.4.1.11591.12.2');
    FEncryptionAlgorithm := TDerObjectIdentifier.Create('1.3.6.1.4.1.11591.13');
    FSerpent := TDerObjectIdentifier.Create('1.3.6.1.4.1.11591.13.2');
    FSerpent128Ecb := TDerObjectIdentifier.Create('1.3.6.1.4.1.11591.13.2.1');
    FSerpent128Cbc := TDerObjectIdentifier.Create('1.3.6.1.4.1.11591.13.2.2');
    FSerpent128Ofb := TDerObjectIdentifier.Create('1.3.6.1.4.1.11591.13.2.3');
    FSerpent128Cfb := TDerObjectIdentifier.Create('1.3.6.1.4.1.11591.13.2.4');
    FSerpent192Ecb := TDerObjectIdentifier.Create('1.3.6.1.4.1.11591.13.2.21');
    FSerpent192Cbc := TDerObjectIdentifier.Create('1.3.6.1.4.1.11591.13.2.22');
    FSerpent192Ofb := TDerObjectIdentifier.Create('1.3.6.1.4.1.11591.13.2.23');
    FSerpent192Cfb := TDerObjectIdentifier.Create('1.3.6.1.4.1.11591.13.2.24');
    FSerpent256Ecb := TDerObjectIdentifier.Create('1.3.6.1.4.1.11591.13.2.41');
    FSerpent256Cbc := TDerObjectIdentifier.Create('1.3.6.1.4.1.11591.13.2.42');
    FSerpent256Ofb := TDerObjectIdentifier.Create('1.3.6.1.4.1.11591.13.2.43');
    FSerpent256Cfb := TDerObjectIdentifier.Create('1.3.6.1.4.1.11591.13.2.44');
    FCrc := TDerObjectIdentifier.Create('1.3.6.1.4.1.11591.14');
    FCrc32 := TDerObjectIdentifier.Create('1.3.6.1.4.1.11591.14.1');
    FEllipticCurve := TDerObjectIdentifier.Create('1.3.6.1.4.1.11591.15');
    FEd25519 := FEllipticCurve.Branch('1');

    FIsBooted := True;
  end;
end;

class function TGnuObjectIdentifiers.GetGnu: IDerObjectIdentifier;
begin
  Result := FGnu;
end;

class function TGnuObjectIdentifiers.GetGnuPG: IDerObjectIdentifier;
begin
  Result := FGnuPG;
end;

class function TGnuObjectIdentifiers.GetNotation: IDerObjectIdentifier;
begin
  Result := FNotation;
end;

class function TGnuObjectIdentifiers.GetPkaAddress: IDerObjectIdentifier;
begin
  Result := FPkaAddress;
end;

class function TGnuObjectIdentifiers.GetGnuRadar: IDerObjectIdentifier;
begin
  Result := FGnuRadar;
end;

class function TGnuObjectIdentifiers.GetDigestAlgorithm: IDerObjectIdentifier;
begin
  Result := FDigestAlgorithm;
end;

class function TGnuObjectIdentifiers.GetTiger192: IDerObjectIdentifier;
begin
  Result := FTiger192;
end;

class function TGnuObjectIdentifiers.GetEncryptionAlgorithm: IDerObjectIdentifier;
begin
  Result := FEncryptionAlgorithm;
end;

class function TGnuObjectIdentifiers.GetSerpent: IDerObjectIdentifier;
begin
  Result := FSerpent;
end;

class function TGnuObjectIdentifiers.GetSerpent128Ecb: IDerObjectIdentifier;
begin
  Result := FSerpent128Ecb;
end;

class function TGnuObjectIdentifiers.GetSerpent128Cbc: IDerObjectIdentifier;
begin
  Result := FSerpent128Cbc;
end;

class function TGnuObjectIdentifiers.GetSerpent128Ofb: IDerObjectIdentifier;
begin
  Result := FSerpent128Ofb;
end;

class function TGnuObjectIdentifiers.GetSerpent128Cfb: IDerObjectIdentifier;
begin
  Result := FSerpent128Cfb;
end;

class function TGnuObjectIdentifiers.GetSerpent192Ecb: IDerObjectIdentifier;
begin
  Result := FSerpent192Ecb;
end;

class function TGnuObjectIdentifiers.GetSerpent192Cbc: IDerObjectIdentifier;
begin
  Result := FSerpent192Cbc;
end;

class function TGnuObjectIdentifiers.GetSerpent192Ofb: IDerObjectIdentifier;
begin
  Result := FSerpent192Ofb;
end;

class function TGnuObjectIdentifiers.GetSerpent192Cfb: IDerObjectIdentifier;
begin
  Result := FSerpent192Cfb;
end;

class function TGnuObjectIdentifiers.GetSerpent256Ecb: IDerObjectIdentifier;
begin
  Result := FSerpent256Ecb;
end;

class function TGnuObjectIdentifiers.GetSerpent256Cbc: IDerObjectIdentifier;
begin
  Result := FSerpent256Cbc;
end;

class function TGnuObjectIdentifiers.GetSerpent256Ofb: IDerObjectIdentifier;
begin
  Result := FSerpent256Ofb;
end;

class function TGnuObjectIdentifiers.GetSerpent256Cfb: IDerObjectIdentifier;
begin
  Result := FSerpent256Cfb;
end;

class function TGnuObjectIdentifiers.GetCrc: IDerObjectIdentifier;
begin
  Result := FCrc;
end;

class function TGnuObjectIdentifiers.GetCrc32: IDerObjectIdentifier;
begin
  Result := FCrc32;
end;

class function TGnuObjectIdentifiers.GetEllipticCurve: IDerObjectIdentifier;
begin
  Result := FEllipticCurve;
end;

class function TGnuObjectIdentifiers.GetEd25519: IDerObjectIdentifier;
begin
  Result := FEd25519;
end;

end.
