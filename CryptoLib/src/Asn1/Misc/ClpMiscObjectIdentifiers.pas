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

unit ClpMiscObjectIdentifiers;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpAsn1Objects,
  ClpIAsn1Objects;

type
  TMiscObjectIdentifiers = class abstract(TObject)
  strict private
    class var
      FIsBooted: Boolean;
      FNetscape, FNetscapeCertType, FNetscapeBaseUrl, FNetscapeRevocationUrl,
      FNetscapeCARevocationUrl, FNetscapeRenewalUrl, FNetscapeCAPolicyUrl,
      FNetscapeSslServerName, FNetscapeCertComment, FVerisign,
      FVerisignCzagExtension, FVerisignPrivate_6_9, FVerisignOnSiteJurisdictionHash,
      FVerisignBitString_6_13, FVerisignDnbDunsNumber, FVerisignIssStrongCrypto,
      FNovell, FNovellSecurityAttribs, FEntrust, FEntrustVersionExtension,
      FCast5Cbc, FHmacSha1, FAsSysSecAlgIdeaCbc, FCryptlib, FCryptlibAlgorithm,
      FCryptlibAlgorithmBlowfishEcb, FCryptlibAlgorithmBlowfishCbc,
      FCryptlibAlgorithmBlowfishCfb, FCryptlibAlgorithmBlowfishOfb, FBlake2,
      FIdBlake2b160, FIdBlake2b256, FIdBlake2b384, FIdBlake2b512, FIdBlake2s128,
      FIdBlake2s160, FIdBlake2s224, FIdBlake2s256, FBlake3, FBlake3_256,
      FIdScrypt, FIdAlgComposite, FIdCompositeKey, FIdOraclePkcs12TrustedKeyUsage: IDerObjectIdentifier;

    class function GetNetscape: IDerObjectIdentifier; static; inline;
    class function GetNetscapeCertType: IDerObjectIdentifier; static; inline;
    class function GetNetscapeBaseUrl: IDerObjectIdentifier; static; inline;
    class function GetNetscapeRevocationUrl: IDerObjectIdentifier; static; inline;
    class function GetNetscapeCARevocationUrl: IDerObjectIdentifier; static; inline;
    class function GetNetscapeRenewalUrl: IDerObjectIdentifier; static; inline;
    class function GetNetscapeCAPolicyUrl: IDerObjectIdentifier; static; inline;
    class function GetNetscapeSslServerName: IDerObjectIdentifier; static; inline;
    class function GetNetscapeCertComment: IDerObjectIdentifier; static; inline;
    class function GetVerisign: IDerObjectIdentifier; static; inline;
    class function GetVerisignCzagExtension: IDerObjectIdentifier; static; inline;
    class function GetVerisignPrivate_6_9: IDerObjectIdentifier; static; inline;
    class function GetVerisignOnSiteJurisdictionHash: IDerObjectIdentifier; static; inline;
    class function GetVerisignBitString_6_13: IDerObjectIdentifier; static; inline;
    class function GetVerisignDnbDunsNumber: IDerObjectIdentifier; static; inline;
    class function GetVerisignIssStrongCrypto: IDerObjectIdentifier; static; inline;
    class function GetNovell: IDerObjectIdentifier; static; inline;
    class function GetNovellSecurityAttribs: IDerObjectIdentifier; static; inline;
    class function GetEntrust: IDerObjectIdentifier; static; inline;
    class function GetEntrustVersionExtension: IDerObjectIdentifier; static; inline;
    class function GetCast5Cbc: IDerObjectIdentifier; static; inline;
    class function GetHmacSha1: IDerObjectIdentifier; static; inline;
    class function GetAsSysSecAlgIdeaCbc: IDerObjectIdentifier; static; inline;
    class function GetCryptlib: IDerObjectIdentifier; static; inline;
    class function GetCryptlibAlgorithm: IDerObjectIdentifier; static; inline;
    class function GetCryptlibAlgorithmBlowfishEcb: IDerObjectIdentifier; static; inline;
    class function GetCryptlibAlgorithmBlowfishCbc: IDerObjectIdentifier; static; inline;
    class function GetCryptlibAlgorithmBlowfishCfb: IDerObjectIdentifier; static; inline;
    class function GetCryptlibAlgorithmBlowfishOfb: IDerObjectIdentifier; static; inline;
    class function GetBlake2: IDerObjectIdentifier; static; inline;
    class function GetIdBlake2b160: IDerObjectIdentifier; static; inline;
    class function GetIdBlake2b256: IDerObjectIdentifier; static; inline;
    class function GetIdBlake2b384: IDerObjectIdentifier; static; inline;
    class function GetIdBlake2b512: IDerObjectIdentifier; static; inline;
    class function GetIdBlake2s128: IDerObjectIdentifier; static; inline;
    class function GetIdBlake2s160: IDerObjectIdentifier; static; inline;
    class function GetIdBlake2s224: IDerObjectIdentifier; static; inline;
    class function GetIdBlake2s256: IDerObjectIdentifier; static; inline;
    class function GetBlake3: IDerObjectIdentifier; static; inline;
    class function GetBlake3_256: IDerObjectIdentifier; static; inline;
    class function GetIdScrypt: IDerObjectIdentifier; static; inline;
    class function GetIdAlgComposite: IDerObjectIdentifier; static; inline;
    class function GetIdCompositeKey: IDerObjectIdentifier; static; inline;
    class function GetIdOraclePkcs12TrustedKeyUsage: IDerObjectIdentifier; static; inline;

    class constructor Create;
  public
    class property Netscape: IDerObjectIdentifier read GetNetscape;
    class property NetscapeCertType: IDerObjectIdentifier read GetNetscapeCertType;
    class property NetscapeBaseUrl: IDerObjectIdentifier read GetNetscapeBaseUrl;
    class property NetscapeRevocationUrl: IDerObjectIdentifier read GetNetscapeRevocationUrl;
    class property NetscapeCARevocationUrl: IDerObjectIdentifier read GetNetscapeCARevocationUrl;
    class property NetscapeRenewalUrl: IDerObjectIdentifier read GetNetscapeRenewalUrl;
    class property NetscapeCAPolicyUrl: IDerObjectIdentifier read GetNetscapeCAPolicyUrl;
    class property NetscapeSslServerName: IDerObjectIdentifier read GetNetscapeSslServerName;
    class property NetscapeCertComment: IDerObjectIdentifier read GetNetscapeCertComment;
    class property Verisign: IDerObjectIdentifier read GetVerisign;
    class property VerisignCzagExtension: IDerObjectIdentifier read GetVerisignCzagExtension;
    class property VerisignPrivate_6_9: IDerObjectIdentifier read GetVerisignPrivate_6_9;
    class property VerisignOnSiteJurisdictionHash: IDerObjectIdentifier read GetVerisignOnSiteJurisdictionHash;
    class property VerisignBitString_6_13: IDerObjectIdentifier read GetVerisignBitString_6_13;
    class property VerisignDnbDunsNumber: IDerObjectIdentifier read GetVerisignDnbDunsNumber;
    class property VerisignIssStrongCrypto: IDerObjectIdentifier read GetVerisignIssStrongCrypto;
    class property Novell: IDerObjectIdentifier read GetNovell;
    class property NovellSecurityAttribs: IDerObjectIdentifier read GetNovellSecurityAttribs;
    class property Entrust: IDerObjectIdentifier read GetEntrust;
    class property EntrustVersionExtension: IDerObjectIdentifier read GetEntrustVersionExtension;
    class property Cast5Cbc: IDerObjectIdentifier read GetCast5Cbc;
    class property HmacSha1: IDerObjectIdentifier read GetHmacSha1;
    class property AsSysSecAlgIdeaCbc: IDerObjectIdentifier read GetAsSysSecAlgIdeaCbc;
    class property Cryptlib: IDerObjectIdentifier read GetCryptlib;
    class property CryptlibAlgorithm: IDerObjectIdentifier read GetCryptlibAlgorithm;
    class property CryptlibAlgorithmBlowfishEcb: IDerObjectIdentifier read GetCryptlibAlgorithmBlowfishEcb;
    class property CryptlibAlgorithmBlowfishCbc: IDerObjectIdentifier read GetCryptlibAlgorithmBlowfishCbc;
    class property CryptlibAlgorithmBlowfishCfb: IDerObjectIdentifier read GetCryptlibAlgorithmBlowfishCfb;
    class property CryptlibAlgorithmBlowfishOfb: IDerObjectIdentifier read GetCryptlibAlgorithmBlowfishOfb;
    class property Blake2: IDerObjectIdentifier read GetBlake2;
    class property IdBlake2b160: IDerObjectIdentifier read GetIdBlake2b160;
    class property IdBlake2b256: IDerObjectIdentifier read GetIdBlake2b256;
    class property IdBlake2b384: IDerObjectIdentifier read GetIdBlake2b384;
    class property IdBlake2b512: IDerObjectIdentifier read GetIdBlake2b512;
    class property IdBlake2s128: IDerObjectIdentifier read GetIdBlake2s128;
    class property IdBlake2s160: IDerObjectIdentifier read GetIdBlake2s160;
    class property IdBlake2s224: IDerObjectIdentifier read GetIdBlake2s224;
    class property IdBlake2s256: IDerObjectIdentifier read GetIdBlake2s256;
    class property Blake3: IDerObjectIdentifier read GetBlake3;
    class property Blake3_256: IDerObjectIdentifier read GetBlake3_256;
    class property IdScrypt: IDerObjectIdentifier read GetIdScrypt;
    class property IdAlgComposite: IDerObjectIdentifier read GetIdAlgComposite;
    class property IdCompositeKey: IDerObjectIdentifier read GetIdCompositeKey;
    class property IdOraclePkcs12TrustedKeyUsage: IDerObjectIdentifier read GetIdOraclePkcs12TrustedKeyUsage;

    class procedure Boot; static;
  end;

implementation

{ TMiscObjectIdentifiers }

class constructor TMiscObjectIdentifiers.Create;
begin
  Boot;
end;

class procedure TMiscObjectIdentifiers.Boot;
begin
  if not FIsBooted then
  begin
    FNetscape := TDerObjectIdentifier.Create('2.16.840.1.113730.1');
    FNetscapeCertType := FNetscape.Branch('1');
    FNetscapeBaseUrl := FNetscape.Branch('2');
    FNetscapeRevocationUrl := FNetscape.Branch('3');
    FNetscapeCARevocationUrl := FNetscape.Branch('4');
    FNetscapeRenewalUrl := FNetscape.Branch('7');
    FNetscapeCAPolicyUrl := FNetscape.Branch('8');
    FNetscapeSslServerName := FNetscape.Branch('12');
    FNetscapeCertComment := FNetscape.Branch('13');

    FVerisign := TDerObjectIdentifier.Create('2.16.840.1.113733.1');
    FVerisignCzagExtension := FVerisign.Branch('6.3');
    FVerisignPrivate_6_9 := FVerisign.Branch('6.9');
    FVerisignOnSiteJurisdictionHash := FVerisign.Branch('6.11');
    FVerisignBitString_6_13 := FVerisign.Branch('6.13');
    FVerisignDnbDunsNumber := FVerisign.Branch('6.15');
    FVerisignIssStrongCrypto := FVerisign.Branch('8.1');

    FNovell := TDerObjectIdentifier.Create('2.16.840.1.113719');
    FNovellSecurityAttribs := FNovell.Branch('1.9.4.1');

    FEntrust := TDerObjectIdentifier.Create('1.2.840.113533.7');
    FEntrustVersionExtension := FEntrust.Branch('65.0');
    FCast5Cbc := FEntrust.Branch('66.10');

    FHmacSha1 := TDerObjectIdentifier.Create('1.3.6.1.5.5.8.1.2');
    FAsSysSecAlgIdeaCbc := TDerObjectIdentifier.Create('1.3.6.1.4.1.188.7.1.1.2');

    FCryptlib := TDerObjectIdentifier.Create('1.3.6.1.4.1.3029');
    FCryptlibAlgorithm := FCryptlib.Branch('1');
    FCryptlibAlgorithmBlowfishEcb := FCryptlibAlgorithm.Branch('1.1');
    FCryptlibAlgorithmBlowfishCbc := FCryptlibAlgorithm.Branch('1.2');
    FCryptlibAlgorithmBlowfishCfb := FCryptlibAlgorithm.Branch('1.3');
    FCryptlibAlgorithmBlowfishOfb := FCryptlibAlgorithm.Branch('1.4');

    FBlake2 := TDerObjectIdentifier.Create('1.3.6.1.4.1.1722.12.2');
    FIdBlake2b160 := FBlake2.Branch('1.5');
    FIdBlake2b256 := FBlake2.Branch('1.8');
    FIdBlake2b384 := FBlake2.Branch('1.12');
    FIdBlake2b512 := FBlake2.Branch('1.16');
    FIdBlake2s128 := FBlake2.Branch('2.4');
    FIdBlake2s160 := FBlake2.Branch('2.5');
    FIdBlake2s224 := FBlake2.Branch('2.7');
    FIdBlake2s256 := FBlake2.Branch('2.8');
    FBlake3 := FBlake2.Branch('3');
    FBlake3_256 := FBlake3.Branch('8');

    FIdScrypt := TDerObjectIdentifier.Create('1.3.6.1.4.1.11591.4.11');
    FIdAlgComposite := TDerObjectIdentifier.Create('1.3.6.1.4.1.18227.2.1');
    FIdCompositeKey := TDerObjectIdentifier.Create('2.16.840.1.114027.80.4.1');
    FIdOraclePkcs12TrustedKeyUsage := TDerObjectIdentifier.Create('2.16.840.1.113894.746875.1.1');

    FIsBooted := True;
  end;
end;

class function TMiscObjectIdentifiers.GetAsSysSecAlgIdeaCbc: IDerObjectIdentifier;
begin
  Result := FAsSysSecAlgIdeaCbc;
end;

class function TMiscObjectIdentifiers.GetBlake2: IDerObjectIdentifier;
begin
  Result := FBlake2;
end;

class function TMiscObjectIdentifiers.GetBlake3: IDerObjectIdentifier;
begin
  Result := FBlake3;
end;

class function TMiscObjectIdentifiers.GetBlake3_256: IDerObjectIdentifier;
begin
  Result := FBlake3_256;
end;

class function TMiscObjectIdentifiers.GetCast5Cbc: IDerObjectIdentifier;
begin
  Result := FCast5Cbc;
end;

class function TMiscObjectIdentifiers.GetCryptlib: IDerObjectIdentifier;
begin
  Result := FCryptlib;
end;

class function TMiscObjectIdentifiers.GetCryptlibAlgorithm: IDerObjectIdentifier;
begin
  Result := FCryptlibAlgorithm;
end;

class function TMiscObjectIdentifiers.GetCryptlibAlgorithmBlowfishCbc: IDerObjectIdentifier;
begin
  Result := FCryptlibAlgorithmBlowfishCbc;
end;

class function TMiscObjectIdentifiers.GetCryptlibAlgorithmBlowfishCfb: IDerObjectIdentifier;
begin
  Result := FCryptlibAlgorithmBlowfishCfb;
end;

class function TMiscObjectIdentifiers.GetCryptlibAlgorithmBlowfishEcb: IDerObjectIdentifier;
begin
  Result := FCryptlibAlgorithmBlowfishEcb;
end;

class function TMiscObjectIdentifiers.GetCryptlibAlgorithmBlowfishOfb: IDerObjectIdentifier;
begin
  Result := FCryptlibAlgorithmBlowfishOfb;
end;

class function TMiscObjectIdentifiers.GetEntrust: IDerObjectIdentifier;
begin
  Result := FEntrust;
end;

class function TMiscObjectIdentifiers.GetEntrustVersionExtension: IDerObjectIdentifier;
begin
  Result := FEntrustVersionExtension;
end;

class function TMiscObjectIdentifiers.GetHmacSha1: IDerObjectIdentifier;
begin
  Result := FHmacSha1;
end;

class function TMiscObjectIdentifiers.GetIdAlgComposite: IDerObjectIdentifier;
begin
  Result := FIdAlgComposite;
end;

class function TMiscObjectIdentifiers.GetIdBlake2b160: IDerObjectIdentifier;
begin
  Result := FIdBlake2b160;
end;

class function TMiscObjectIdentifiers.GetIdBlake2b256: IDerObjectIdentifier;
begin
  Result := FIdBlake2b256;
end;

class function TMiscObjectIdentifiers.GetIdBlake2b384: IDerObjectIdentifier;
begin
  Result := FIdBlake2b384;
end;

class function TMiscObjectIdentifiers.GetIdBlake2b512: IDerObjectIdentifier;
begin
  Result := FIdBlake2b512;
end;

class function TMiscObjectIdentifiers.GetIdBlake2s128: IDerObjectIdentifier;
begin
  Result := FIdBlake2s128;
end;

class function TMiscObjectIdentifiers.GetIdBlake2s160: IDerObjectIdentifier;
begin
  Result := FIdBlake2s160;
end;

class function TMiscObjectIdentifiers.GetIdBlake2s224: IDerObjectIdentifier;
begin
  Result := FIdBlake2s224;
end;

class function TMiscObjectIdentifiers.GetIdBlake2s256: IDerObjectIdentifier;
begin
  Result := FIdBlake2s256;
end;

class function TMiscObjectIdentifiers.GetIdCompositeKey: IDerObjectIdentifier;
begin
  Result := FIdCompositeKey;
end;

class function TMiscObjectIdentifiers.GetIdOraclePkcs12TrustedKeyUsage: IDerObjectIdentifier;
begin
  Result := FIdOraclePkcs12TrustedKeyUsage;
end;

class function TMiscObjectIdentifiers.GetIdScrypt: IDerObjectIdentifier;
begin
  Result := FIdScrypt;
end;

class function TMiscObjectIdentifiers.GetNetscape: IDerObjectIdentifier;
begin
  Result := FNetscape;
end;

class function TMiscObjectIdentifiers.GetNetscapeBaseUrl: IDerObjectIdentifier;
begin
  Result := FNetscapeBaseUrl;
end;

class function TMiscObjectIdentifiers.GetNetscapeCARevocationUrl: IDerObjectIdentifier;
begin
  Result := FNetscapeCARevocationUrl;
end;

class function TMiscObjectIdentifiers.GetNetscapeCAPolicyUrl: IDerObjectIdentifier;
begin
  Result := FNetscapeCAPolicyUrl;
end;

class function TMiscObjectIdentifiers.GetNetscapeCertComment: IDerObjectIdentifier;
begin
  Result := FNetscapeCertComment;
end;

class function TMiscObjectIdentifiers.GetNetscapeCertType: IDerObjectIdentifier;
begin
  Result := FNetscapeCertType;
end;

class function TMiscObjectIdentifiers.GetNetscapeRenewalUrl: IDerObjectIdentifier;
begin
  Result := FNetscapeRenewalUrl;
end;

class function TMiscObjectIdentifiers.GetNetscapeRevocationUrl: IDerObjectIdentifier;
begin
  Result := FNetscapeRevocationUrl;
end;

class function TMiscObjectIdentifiers.GetNetscapeSslServerName: IDerObjectIdentifier;
begin
  Result := FNetscapeSslServerName;
end;

class function TMiscObjectIdentifiers.GetNovell: IDerObjectIdentifier;
begin
  Result := FNovell;
end;

class function TMiscObjectIdentifiers.GetNovellSecurityAttribs: IDerObjectIdentifier;
begin
  Result := FNovellSecurityAttribs;
end;

class function TMiscObjectIdentifiers.GetVerisign: IDerObjectIdentifier;
begin
  Result := FVerisign;
end;

class function TMiscObjectIdentifiers.GetVerisignBitString_6_13: IDerObjectIdentifier;
begin
  Result := FVerisignBitString_6_13;
end;

class function TMiscObjectIdentifiers.GetVerisignCzagExtension: IDerObjectIdentifier;
begin
  Result := FVerisignCzagExtension;
end;

class function TMiscObjectIdentifiers.GetVerisignDnbDunsNumber: IDerObjectIdentifier;
begin
  Result := FVerisignDnbDunsNumber;
end;

class function TMiscObjectIdentifiers.GetVerisignIssStrongCrypto: IDerObjectIdentifier;
begin
  Result := FVerisignIssStrongCrypto;
end;

class function TMiscObjectIdentifiers.GetVerisignOnSiteJurisdictionHash: IDerObjectIdentifier;
begin
  Result := FVerisignOnSiteJurisdictionHash;
end;

class function TMiscObjectIdentifiers.GetVerisignPrivate_6_9: IDerObjectIdentifier;
begin
  Result := FVerisignPrivate_6_9;
end;

end.
