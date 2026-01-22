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

unit ClpX509SignatureUtilities;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  Generics.Collections,
  ClpAsn1Objects,
  ClpIAsn1Objects,
  ClpIX509Asn1Objects,
  ClpX509Asn1Objects,
  ClpPkcsObjectIdentifiers,
  ClpIPkcsAsn1Objects,
  ClpPkcsAsn1Objects,
  ClpX9ObjectIdentifiers,
  ClpNistObjectIdentifiers,
  ClpTeleTrusTObjectIdentifiers,
  ClpOiwObjectIdentifiers,
  ClpCryptoProObjectIdentifiers,
  ClpRosstandartObjectIdentifiers,
  ClpSignerUtilities,
  ClpX509Utilities,
  ClpCryptoLibComparers,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// Internal utilities for X509 signature operations.
  /// </summary>
  TX509SignatureUtilities = class sealed(TObject)

  strict private
    class var
      FAlgorithms: TDictionary<String, IDerObjectIdentifier>;
      FExParams: TDictionary<String, IAsn1Encodable>;
      FNoParams: TDictionary<IDerObjectIdentifier, IAlgorithmIdentifier>;

    class function GetDigestName(const ADigestAlgOid: IDerObjectIdentifier): String; static;
    class procedure Boot; static;
    class constructor Create;

  public
    class function GetSignatureName(const ASigAlgID: IAlgorithmIdentifier): String; static;
    class function GetSigOid(const ASigName: String): IDerObjectIdentifier; static;
    class function GetSigAlgID(const AAlgorithmName: String): IAlgorithmIdentifier; static;
    class function GetSigNames: TCryptoLibStringArray; static;

  end;

implementation

{ TX509SignatureUtilities }

class constructor TX509SignatureUtilities.Create;
begin
  Boot;
end;

class procedure TX509SignatureUtilities.Boot;
begin
  FAlgorithms := TDictionary<String, IDerObjectIdentifier>.Create(TCryptoLibComparers.OrdinalIgnoreCaseEqualityComparer);
  FExParams := TDictionary<String, IAsn1Encodable>.Create();
  FNoParams := TDictionary<IDerObjectIdentifier, IAlgorithmIdentifier>.Create(TCryptoLibComparers.OidEqualityComparer);

  // Initialize algorithms - same as TX509Utilities
  // MD2 algorithms
  FAlgorithms.Add('MD2WITHRSAENCRYPTION', TPkcsObjectIdentifiers.MD2WithRsaEncryption);
  FAlgorithms.Add('MD2WITHRSA', TPkcsObjectIdentifiers.MD2WithRsaEncryption);

  // MD5 algorithms
  FAlgorithms.Add('MD5WITHRSAENCRYPTION', TPkcsObjectIdentifiers.MD5WithRsaEncryption);
  FAlgorithms.Add('MD5WITHRSA', TPkcsObjectIdentifiers.MD5WithRsaEncryption);

  // SHA1 algorithms
  FAlgorithms.Add('SHA1WITHRSAENCRYPTION', TPkcsObjectIdentifiers.Sha1WithRsaEncryption);
  FAlgorithms.Add('SHA-1WITHRSAENCRYPTION', TPkcsObjectIdentifiers.Sha1WithRsaEncryption);
  FAlgorithms.Add('SHA1WITHRSA', TPkcsObjectIdentifiers.Sha1WithRsaEncryption);
  FAlgorithms.Add('SHA-1WITHRSA', TPkcsObjectIdentifiers.Sha1WithRsaEncryption);

  // SHA224 algorithms
  FAlgorithms.Add('SHA224WITHRSAENCRYPTION', TPkcsObjectIdentifiers.Sha224WithRsaEncryption);
  FAlgorithms.Add('SHA-224WITHRSAENCRYPTION', TPkcsObjectIdentifiers.Sha224WithRsaEncryption);
  FAlgorithms.Add('SHA224WITHRSA', TPkcsObjectIdentifiers.Sha224WithRsaEncryption);
  FAlgorithms.Add('SHA-224WITHRSA', TPkcsObjectIdentifiers.Sha224WithRsaEncryption);

  // SHA256 algorithms
  FAlgorithms.Add('SHA256WITHRSAENCRYPTION', TPkcsObjectIdentifiers.Sha256WithRsaEncryption);
  FAlgorithms.Add('SHA-256WITHRSAENCRYPTION', TPkcsObjectIdentifiers.Sha256WithRsaEncryption);
  FAlgorithms.Add('SHA256WITHRSA', TPkcsObjectIdentifiers.Sha256WithRsaEncryption);
  FAlgorithms.Add('SHA-256WITHRSA', TPkcsObjectIdentifiers.Sha256WithRsaEncryption);

  // SHA384 algorithms
  FAlgorithms.Add('SHA384WITHRSAENCRYPTION', TPkcsObjectIdentifiers.Sha384WithRsaEncryption);
  FAlgorithms.Add('SHA-384WITHRSAENCRYPTION', TPkcsObjectIdentifiers.Sha384WithRsaEncryption);
  FAlgorithms.Add('SHA384WITHRSA', TPkcsObjectIdentifiers.Sha384WithRsaEncryption);
  FAlgorithms.Add('SHA-384WITHRSA', TPkcsObjectIdentifiers.Sha384WithRsaEncryption);

  // SHA512 algorithms
  FAlgorithms.Add('SHA512WITHRSAENCRYPTION', TPkcsObjectIdentifiers.Sha512WithRsaEncryption);
  FAlgorithms.Add('SHA-512WITHRSAENCRYPTION', TPkcsObjectIdentifiers.Sha512WithRsaEncryption);
  FAlgorithms.Add('SHA512WITHRSA', TPkcsObjectIdentifiers.Sha512WithRsaEncryption);
  FAlgorithms.Add('SHA-512WITHRSA', TPkcsObjectIdentifiers.Sha512WithRsaEncryption);

  // SHA512(224) algorithms
  FAlgorithms.Add('SHA512(224)WITHRSAENCRYPTION', TPkcsObjectIdentifiers.Sha512_224WithRSAEncryption);
  FAlgorithms.Add('SHA-512(224)WITHRSAENCRYPTION', TPkcsObjectIdentifiers.Sha512_224WithRSAEncryption);
  FAlgorithms.Add('SHA512(224)WITHRSA', TPkcsObjectIdentifiers.Sha512_224WithRSAEncryption);
  FAlgorithms.Add('SHA-512(224)WITHRSA', TPkcsObjectIdentifiers.Sha512_224WithRSAEncryption);

  // SHA512(256) algorithms
  FAlgorithms.Add('SHA512(256)WITHRSAENCRYPTION', TPkcsObjectIdentifiers.Sha512_256WithRSAEncryption);
  FAlgorithms.Add('SHA-512(256)WITHRSAENCRYPTION', TPkcsObjectIdentifiers.Sha512_256WithRSAEncryption);
  FAlgorithms.Add('SHA512(256)WITHRSA', TPkcsObjectIdentifiers.Sha512_256WithRSAEncryption);
  FAlgorithms.Add('SHA-512(256)WITHRSA', TPkcsObjectIdentifiers.Sha512_256WithRSAEncryption);

  // RSA-PSS algorithms
  FAlgorithms.Add('SHA1WITHRSAANDMGF1', TPkcsObjectIdentifiers.IdRsassaPss);
  FAlgorithms.Add('SHA224WITHRSAANDMGF1', TPkcsObjectIdentifiers.IdRsassaPss);
  FAlgorithms.Add('SHA256WITHRSAANDMGF1', TPkcsObjectIdentifiers.IdRsassaPss);
  FAlgorithms.Add('SHA384WITHRSAANDMGF1', TPkcsObjectIdentifiers.IdRsassaPss);
  FAlgorithms.Add('SHA512WITHRSAANDMGF1', TPkcsObjectIdentifiers.IdRsassaPss);

  // RIPEMD algorithms
  FAlgorithms.Add('RIPEMD160WITHRSAENCRYPTION', TTeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD160);
  FAlgorithms.Add('RIPEMD160WITHRSA', TTeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD160);
  FAlgorithms.Add('RIPEMD128WITHRSAENCRYPTION', TTeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD128);
  FAlgorithms.Add('RIPEMD128WITHRSA', TTeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD128);
  FAlgorithms.Add('RIPEMD256WITHRSAENCRYPTION', TTeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD256);
  FAlgorithms.Add('RIPEMD256WITHRSA', TTeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD256);

  // DSA algorithms
  FAlgorithms.Add('SHA1WITHDSA', TX9ObjectIdentifiers.IdDsaWithSha1);
  FAlgorithms.Add('DSAWITHSHA1', TX9ObjectIdentifiers.IdDsaWithSha1);
  FAlgorithms.Add('SHA224WITHDSA', TNistObjectIdentifiers.DsaWithSha224);
  FAlgorithms.Add('SHA256WITHDSA', TNistObjectIdentifiers.DsaWithSha256);
  FAlgorithms.Add('SHA384WITHDSA', TNistObjectIdentifiers.DsaWithSha384);
  FAlgorithms.Add('SHA512WITHDSA', TNistObjectIdentifiers.DsaWithSha512);

  // ECDSA algorithms
  FAlgorithms.Add('SHA1WITHECDSA', TX9ObjectIdentifiers.ECDsaWithSha1);
  FAlgorithms.Add('ECDSAWITHSHA1', TX9ObjectIdentifiers.ECDsaWithSha1);
  FAlgorithms.Add('SHA224WITHECDSA', TX9ObjectIdentifiers.ECDsaWithSha224);
  FAlgorithms.Add('SHA256WITHECDSA', TX9ObjectIdentifiers.ECDsaWithSha256);
  FAlgorithms.Add('SHA384WITHECDSA', TX9ObjectIdentifiers.ECDsaWithSha384);
  FAlgorithms.Add('SHA512WITHECDSA', TX9ObjectIdentifiers.ECDsaWithSha512);

  // GOST algorithms
  FAlgorithms.Add('GOST3411WITHGOST3410', TCryptoProObjectIdentifiers.GostR3411x94WithGostR3410x94);
  FAlgorithms.Add('GOST3411WITHGOST3410-94', TCryptoProObjectIdentifiers.GostR3411x94WithGostR3410x94);
  FAlgorithms.Add('GOST3411WITHECGOST3410', TCryptoProObjectIdentifiers.GostR3411x94WithGostR3410x2001);
  FAlgorithms.Add('GOST3411WITHECGOST3410-2001', TCryptoProObjectIdentifiers.GostR3411x94WithGostR3410x2001);
  FAlgorithms.Add('GOST3411WITHGOST3410-2001', TCryptoProObjectIdentifiers.GostR3411x94WithGostR3410x2001);

  // Add no-params entries for algorithms that don't require parameters
  FNoParams.Add(TX9ObjectIdentifiers.IdDsaWithSha1, TAlgorithmIdentifier.Create(TX9ObjectIdentifiers.IdDsaWithSha1));
  FNoParams.Add(TX9ObjectIdentifiers.ECDsaWithSha1, TAlgorithmIdentifier.Create(TX9ObjectIdentifiers.ECDsaWithSha1));
  FNoParams.Add(TX9ObjectIdentifiers.ECDsaWithSha224, TAlgorithmIdentifier.Create(TX9ObjectIdentifiers.ECDsaWithSha224));
  FNoParams.Add(TX9ObjectIdentifiers.ECDsaWithSha256, TAlgorithmIdentifier.Create(TX9ObjectIdentifiers.ECDsaWithSha256));
  FNoParams.Add(TX9ObjectIdentifiers.ECDsaWithSha384, TAlgorithmIdentifier.Create(TX9ObjectIdentifiers.ECDsaWithSha384));
  FNoParams.Add(TX9ObjectIdentifiers.ECDsaWithSha512, TAlgorithmIdentifier.Create(TX9ObjectIdentifiers.ECDsaWithSha512));
end;

class function TX509SignatureUtilities.GetDigestName(const ADigestAlgOid: IDerObjectIdentifier): String;
begin
  if TPkcsObjectIdentifiers.MD5.Equals(ADigestAlgOid) then
    Result := 'MD5'
  else if TOiwObjectIdentifiers.IdSha1.Equals(ADigestAlgOid) then
    Result := 'SHA1'
  else if TNistObjectIdentifiers.IdSha224.Equals(ADigestAlgOid) then
    Result := 'SHA224'
  else if TNistObjectIdentifiers.IdSha256.Equals(ADigestAlgOid) then
    Result := 'SHA256'
  else if TNistObjectIdentifiers.IdSha384.Equals(ADigestAlgOid) then
    Result := 'SHA384'
  else if TNistObjectIdentifiers.IdSha512.Equals(ADigestAlgOid) then
    Result := 'SHA512'
  else if TNistObjectIdentifiers.IdSha512_224.Equals(ADigestAlgOid) then
    Result := 'SHA512(224)'
  else if TNistObjectIdentifiers.IdSha512_256.Equals(ADigestAlgOid) then
    Result := 'SHA512(256)'
  else if TTeleTrusTObjectIdentifiers.RipeMD128.Equals(ADigestAlgOid) then
    Result := 'RIPEMD128'
  else if TTeleTrusTObjectIdentifiers.RipeMD160.Equals(ADigestAlgOid) then
    Result := 'RIPEMD160'
  else if TTeleTrusTObjectIdentifiers.RipeMD256.Equals(ADigestAlgOid) then
    Result := 'RIPEMD256'
  else if TCryptoProObjectIdentifiers.GostR3411.Equals(ADigestAlgOid) then
    Result := 'GOST3411'
  else if TRosstandartObjectIdentifiers.id_tc26_gost_3411_12_256.Equals(ADigestAlgOid) then
    Result := 'GOST3411-2012-256'
  else if TRosstandartObjectIdentifiers.id_tc26_gost_3411_12_512.Equals(ADigestAlgOid) then
    Result := 'GOST3411-2012-512'
  else
    Result := ADigestAlgOid.Id;
end;

class function TX509SignatureUtilities.GetSignatureName(const ASigAlgID: IAlgorithmIdentifier): String;
var
  LSigAlgOid: IDerObjectIdentifier;
  LSigAlgParams: IAsn1Encodable;
  LRsassaPssParams: IRsassaPssParameters;
  LECdsaParams: IAlgorithmIdentifier;
begin
  if ASigAlgID = nil then
  begin
    Result := '';
    Exit;
  end;

  LSigAlgOid := ASigAlgID.Algorithm;
  LSigAlgParams := ASigAlgID.Parameters;

  if not TX509Utilities.IsAbsentParameters(LSigAlgParams) then
  begin
    if TPkcsObjectIdentifiers.IdRsassaPss.Equals(LSigAlgOid) then
    begin
      LRsassaPssParams := TRsassaPssParameters.GetInstance(LSigAlgParams as TObject);
      Result := GetDigestName(LRsassaPssParams.HashAlgorithm.Algorithm) + 'withRSAandMGF1';
      Exit;
    end;
    if TX9ObjectIdentifiers.ECDsaWithSha2.Equals(LSigAlgOid) then
    begin
      LECdsaParams := TAlgorithmIdentifier.GetInstance(LSigAlgParams as TObject);
      Result := GetDigestName(LECdsaParams.Algorithm) + 'withECDSA';
      Exit;
    end;
  end;

  Result := TSignerUtilities.GetEncodingName(LSigAlgOid);
  if Result = '' then
    Result := LSigAlgOid.Id;
end;

class function TX509SignatureUtilities.GetSigOid(const ASigName: String): IDerObjectIdentifier;
var
  LUpperName: String;
begin
  if ASigName = '' then
  begin
    Result := nil;
    Exit;
  end;

  LUpperName := UpperCase(ASigName);
  if not FAlgorithms.TryGetValue(LUpperName, Result) then
  begin
    // Try to parse as OID string
    try
      Result := TDerObjectIdentifier.Create(ASigName);
    except
      Result := nil;
    end;
  end;
end;

class function TX509SignatureUtilities.GetSigAlgID(const AAlgorithmName: String): IAlgorithmIdentifier;
var
  LSigOid: IDerObjectIdentifier;
  LNoParamsAlgID: IAlgorithmIdentifier;
  LExplicitParams: IAsn1Encodable;
begin
  LSigOid := GetSigOid(AAlgorithmName);

  if LSigOid = nil then
  begin
    Result := nil;
    Exit;
  end;

  // Check for no-params algorithms
  if FNoParams.TryGetValue(LSigOid, LNoParamsAlgID) then
  begin
    Result := LNoParamsAlgID;
    Exit;
  end;

  // Check for explicit parameters
  if FExParams.TryGetValue(AAlgorithmName, LExplicitParams) then
  begin
    Result := TAlgorithmIdentifier.Create(LSigOid, LExplicitParams);
    Exit;
  end;

  // Default: OID with NULL parameters
  Result := TAlgorithmIdentifier.Create(LSigOid, TDerNull.Instance);
end;

class function TX509SignatureUtilities.GetSigNames: TCryptoLibStringArray;
var
  LList: TList<String>;
  LName: String;
begin
  LList := TList<String>.Create();
  try
    for LName in FAlgorithms.Keys do
    begin
      LList.Add(LName);
    end;
    Result := LList.ToArray();
  finally
    LList.Free;
  end;
end;

end.
