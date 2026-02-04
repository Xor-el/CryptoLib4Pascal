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

unit ClpMacUtilities;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  Generics.Collections,
  ClpAsn1Objects,
  ClpCollectionUtilities,
  ClpAsn1Comparers,
  ClpCryptoLibComparers,
  ClpCryptoLibTypes,
  ClpDigestUtilities,
  ClpIAsn1Objects,
  ClpICipherParameters,
  ClpIMac,
  ClpIanaObjectIdentifiers,
  ClpMiscObjectIdentifiers,
  ClpNistObjectIdentifiers,
  ClpOiwObjectIdentifiers,
  ClpPkcsObjectIdentifiers,
  ClpRosstandartObjectIdentifiers,
  ClpHMac,
  ClpStringUtilities;

resourcestring
  SOidNil = 'OID Cannot be Nil';
  SAlgorithmNil = 'Algorithm Cannot be Nil';
  SUnRecognizedMac = 'Mac "%s" not recognised.';
  SUnRecognizedMacOid = 'Mac OID not recognised.';

type
  /// <summary>
  /// Utility class for creating IMac (HMAC) objects from names/OIDs.
  /// </summary>
  TMacUtilities = class sealed(TObject)
  strict private
    class var
      FAlgorithmMap: TDictionary<String, String>;
      FAlgorithmOidMap: TDictionary<IDerObjectIdentifier, String>;

    class function GetMechanism(const AAlgorithm: String): String; static;
    class function GetMacForMechanism(const AMechanism: String): IMac; static;
    class procedure Boot; static;
    class constructor Create;
    class destructor Destroy;
  public
    class function GetAlgorithmName(const AOid: IDerObjectIdentifier): String; static;
    class function GetMac(const AOid: IDerObjectIdentifier): IMac; overload; static;
    class function GetMac(const AAlgorithm: String): IMac; overload; static;
    class function CalculateMac(const AAlgorithm: String; const ACp: ICipherParameters;
      const AInput: TCryptoLibByteArray): TCryptoLibByteArray; static;
    class function DoFinal(const AMac: IMac): TCryptoLibByteArray; overload; static;
    class function DoFinal(const AMac: IMac; const AInput: TCryptoLibByteArray): TCryptoLibByteArray; overload; static;
  end;

implementation

{ TMacUtilities }

class procedure TMacUtilities.Boot;
begin
  FAlgorithmMap := TDictionary<String, String>.Create(TCryptoLibComparers.OrdinalIgnoreCaseEqualityComparer);
  FAlgorithmOidMap := TDictionary<IDerObjectIdentifier, String>.Create(TAsn1Comparers.OidEqualityComparer);

  TIanaObjectIdentifiers.Boot;
  TPkcsObjectIdentifiers.Boot;
  TMiscObjectIdentifiers.Boot;
  TNistObjectIdentifiers.Boot;
  TRosstandartObjectIdentifiers.Boot;
  TOiwObjectIdentifiers.Boot;

  FAlgorithmOidMap.AddOrSetValue(TIanaObjectIdentifiers.HmacMD5, 'HMAC-MD5');
  FAlgorithmOidMap.AddOrSetValue(TIanaObjectIdentifiers.HmacRipeMD160, 'HMAC-RIPEMD160');
  FAlgorithmOidMap.AddOrSetValue(TIanaObjectIdentifiers.HmacSha1, 'HMAC-SHA1');
  FAlgorithmOidMap.AddOrSetValue(TIanaObjectIdentifiers.HmacTiger, 'HMAC-TIGER');

  FAlgorithmOidMap.AddOrSetValue(TPkcsObjectIdentifiers.IdHmacWithSha1, 'HMAC-SHA1');
  FAlgorithmOidMap.AddOrSetValue(TMiscObjectIdentifiers.HmacSha1, 'HMAC-SHA1');
  FAlgorithmOidMap.AddOrSetValue(TPkcsObjectIdentifiers.IdHmacWithSha224, 'HMAC-SHA224');
  FAlgorithmOidMap.AddOrSetValue(TPkcsObjectIdentifiers.IdHmacWithSha256, 'HMAC-SHA256');
  FAlgorithmOidMap.AddOrSetValue(TPkcsObjectIdentifiers.IdHmacWithSha384, 'HMAC-SHA384');
  FAlgorithmOidMap.AddOrSetValue(TPkcsObjectIdentifiers.IdHmacWithSha512, 'HMAC-SHA512');
  FAlgorithmOidMap.AddOrSetValue(TPkcsObjectIdentifiers.IdHmacWithSha512_224, 'HMAC-SHA512-224');
  FAlgorithmOidMap.AddOrSetValue(TPkcsObjectIdentifiers.IdHmacWithSha512_256, 'HMAC-SHA512-256');

  FAlgorithmOidMap.AddOrSetValue(TNistObjectIdentifiers.IdHMacWithSha3_224, 'HMAC-SHA3-224');
  FAlgorithmOidMap.AddOrSetValue(TNistObjectIdentifiers.IdHMacWithSha3_256, 'HMAC-SHA3-256');
  FAlgorithmOidMap.AddOrSetValue(TNistObjectIdentifiers.IdHMacWithSha3_384, 'HMAC-SHA3-384');
  FAlgorithmOidMap.AddOrSetValue(TNistObjectIdentifiers.IdHMacWithSha3_512, 'HMAC-SHA3-512');

  FAlgorithmOidMap.AddOrSetValue(TRosstandartObjectIdentifiers.IdTc26HmacGost3411_12_256, 'HMAC-GOST3411-2012-256');
  FAlgorithmOidMap.AddOrSetValue(TRosstandartObjectIdentifiers.IdTc26HmacGost3411_12_512, 'HMAC-GOST3411-2012-512');

  FAlgorithmMap.AddOrSetValue('PBEWITHHMACSHA', 'PBEWITHHMACSHA1');
  FAlgorithmOidMap.AddOrSetValue(TOiwObjectIdentifiers.IdSha1, 'PBEWITHHMACSHA1');
end;

class constructor TMacUtilities.Create;
begin
  Boot;
end;

class destructor TMacUtilities.Destroy;
begin
  FAlgorithmMap.Free;
  FAlgorithmOidMap.Free;
end;

class function TMacUtilities.GetMechanism(const AAlgorithm: String): String;
var
  LOid: IDerObjectIdentifier;
  LMechanism: String;
begin
  if FAlgorithmMap.TryGetValue(AAlgorithm, LMechanism) then
  begin
    Result := LMechanism;
    Exit;
  end;
  if TDerObjectIdentifier.TryFromID(AAlgorithm, LOid) and FAlgorithmOidMap.TryGetValue(LOid, LMechanism) then
  begin
    Result := LMechanism;
    Exit;
  end;
  Result := '';
end;

class function TMacUtilities.GetMacForMechanism(const AMechanism: String): IMac;
var
  LMechanism: String;
  LDigestName: String;
begin
  Result := nil;
  LMechanism := AMechanism;
  if TStringUtilities.StartsWith(LMechanism, 'PBEWITH') then
    LMechanism := TStringUtilities.Substring(LMechanism, System.Length('PBEWITH') + 1);

  if TStringUtilities.StartsWith(LMechanism, 'HMAC') then
  begin
    if TStringUtilities.StartsWith(LMechanism, 'HMAC-') or TStringUtilities.StartsWith(LMechanism, 'HMAC/') then
      LDigestName := TStringUtilities.Substring(LMechanism, 6)
    else
      LDigestName := TStringUtilities.Substring(LMechanism, 5);
    if LDigestName = 'SHA512-224' then
      LDigestName := 'SHA-512/224'
    else if LDigestName = 'SHA512-256' then
      LDigestName := 'SHA-512/256';
    Result := THMac.Create(TDigestUtilities.GetDigest(LDigestName));
  end;
end;

class function TMacUtilities.GetAlgorithmName(const AOid: IDerObjectIdentifier): String;
begin
  Result := TCollectionUtilities.GetValueOrNull<IDerObjectIdentifier, String>(FAlgorithmOidMap, AOid);
end;

class function TMacUtilities.GetMac(const AOid: IDerObjectIdentifier): IMac;
var
  LMechanism: String;
  LMac: IMac;
begin
  if AOid = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SOidNil);
  if FAlgorithmOidMap.TryGetValue(AOid, LMechanism) then
  begin
    LMac := GetMacForMechanism(LMechanism);
    if LMac <> nil then
    begin
      Result := LMac;
      Exit;
    end;
  end;
  raise ESecurityUtilityCryptoLibException.CreateRes(@SUnRecognizedMacOid);
end;

class function TMacUtilities.GetMac(const AAlgorithm: String): IMac;
var
  LMechanism: String;
  LMac: IMac;
begin
  if AAlgorithm = '' then
    raise EArgumentNilCryptoLibException.CreateRes(@SAlgorithmNil);
  LMechanism := GetMechanism(AAlgorithm);
  if LMechanism = '' then
    LMechanism := UpperCase(AAlgorithm);
  LMac := GetMacForMechanism(LMechanism);
  if LMac <> nil then
  begin
    Result := LMac;
    Exit;
  end;
  raise ESecurityUtilityCryptoLibException.CreateResFmt(@SUnRecognizedMac, [AAlgorithm]);
end;

class function TMacUtilities.CalculateMac(const AAlgorithm: String; const ACp: ICipherParameters;
  const AInput: TCryptoLibByteArray): TCryptoLibByteArray;
var
  LMac: IMac;
begin
  LMac := GetMac(AAlgorithm);
  LMac.Init(ACp);
  LMac.BlockUpdate(AInput, 0, System.Length(AInput));
  Result := DoFinal(LMac);
end;

class function TMacUtilities.DoFinal(const AMac: IMac): TCryptoLibByteArray;
begin
  System.SetLength(Result, AMac.GetMacSize());
  AMac.DoFinal(Result, 0);
end;

class function TMacUtilities.DoFinal(const AMac: IMac; const AInput: TCryptoLibByteArray): TCryptoLibByteArray;
begin
  AMac.BlockUpdate(AInput, 0, System.Length(AInput));
  Result := DoFinal(AMac);
end;

end.
