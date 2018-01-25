{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                    Copyright (c) 2018 Ugochukwu Mmaduekwe                       * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }

{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }

{ *                              Acknowledgements:                                  * }
{ *                                                                                 * }
{ *        Thanks to Sphere 10 Software (http://sphere10.com) for sponsoring        * }
{ *                        the development of this library                          * }

{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit ClpSignerUtilities;

{$I ..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  Generics.Collections,
  ClpCryptoLibTypes,
  HlpHashFactory,
  HlpIHash,
  ClpDsaDigestSigner,
  ClpX9ObjectIdentifiers,
  ClpTeleTrusTObjectIdentifiers,
  ClpCryptoProObjectIdentifiers,
  ClpECDsaSigner,
  ClpIECDsaSigner,
  ClpISigner,
  ClpIDerObjectIdentifier;

resourcestring
  SMechanismNil = 'Mechanism';
  SAlgorithmNil = 'Algorithm';
  SUnRecognizedAlgorithm = 'Signer " %s " not recognised.';

type

  /// <summary>
  /// Signer Utility class contains methods that can not be specifically
  /// grouped into other classes.
  /// </summary>
  TSignerUtilities = class sealed(TObject)

  strict private

  class var

    Falgorithms: TDictionary<String, String>;
    Foids: TDictionary<String, IDerObjectIdentifier>;

    class function GetAlgorithms: TCryptoLibStringArray; static; inline;

    class constructor CreateSignerUtilities();
    class destructor DestroySignerUtilities();

  public

    /// <summary>
    /// Returns an ObjectIdentifier for a given encoding.
    /// </summary>
    /// <param name="mechanism">A string representation of the encoding.</param>
    /// <returns>A DerObjectIdentifier, null if the OID is not available.</returns>
    // TODO Don't really want to support this
    class function GetObjectIdentifier(mechanism: String): IDerObjectIdentifier;
      static; inline;

    class function GetEncodingName(const oid: IDerObjectIdentifier): String;
      static; inline;

    class function GetSigner(const id: IDerObjectIdentifier): ISigner; overload;
      static; inline;

    class function GetSigner(algorithm: String): ISigner; overload; static;

    class property Algorithms: TCryptoLibStringArray read GetAlgorithms;

  end;

implementation

{ TSignerUtilities }

class constructor TSignerUtilities.CreateSignerUtilities;
begin
  Falgorithms := TDictionary<String, String>.Create();
  Foids := TDictionary<String, IDerObjectIdentifier>.Create();

  TX9ObjectIdentifiers.Boot;
  TTeleTrusTObjectIdentifiers.Boot;
  TCryptoProObjectIdentifiers.Boot;

  Falgorithms.Add('NONEWITHECDSA', 'NONEwithECDSA');
  Falgorithms.Add('ECDSAWITHNONE', 'NONEwithECDSA');

  Falgorithms.Add('ECDSA', 'SHA-1withECDSA');
  Falgorithms.Add('SHA1/ECDSA', 'SHA-1withECDSA');
  Falgorithms.Add('SHA-1/ECDSA', 'SHA-1withECDSA');
  Falgorithms.Add('ECDSAWITHSHA1', 'SHA-1withECDSA');
  Falgorithms.Add('ECDSAWITHSHA-1', 'SHA-1withECDSA');
  Falgorithms.Add('SHA1WITHECDSA', 'SHA-1withECDSA');
  Falgorithms.Add('SHA-1WITHECDSA', 'SHA-1withECDSA');
  Falgorithms.Add(TX9ObjectIdentifiers.ECDsaWithSha1.id, 'SHA-1withECDSA');
  Falgorithms.Add(TTeleTrusTObjectIdentifiers.ECSignWithSha1.id,
    'SHA-1withECDSA');

  Falgorithms.Add('SHA224/ECDSA', 'SHA-224withECDSA');
  Falgorithms.Add('SHA-224/ECDSA', 'SHA-224withECDSA');
  Falgorithms.Add('ECDSAWITHSHA224', 'SHA-224withECDSA');
  Falgorithms.Add('ECDSAWITHSHA-224', 'SHA-224withECDSA');
  Falgorithms.Add('SHA224WITHECDSA', 'SHA-224withECDSA');
  Falgorithms.Add('SHA-224WITHECDSA', 'SHA-224withECDSA');
  Falgorithms.Add(TX9ObjectIdentifiers.ECDsaWithSha224.id, 'SHA-224withECDSA');

  Falgorithms.Add('SHA256/ECDSA', 'SHA-256withECDSA');
  Falgorithms.Add('SHA-256/ECDSA', 'SHA-256withECDSA');
  Falgorithms.Add('ECDSAWITHSHA256', 'SHA-256withECDSA');
  Falgorithms.Add('ECDSAWITHSHA-256', 'SHA-256withECDSA');
  Falgorithms.Add('SHA256WITHECDSA', 'SHA-256withECDSA');
  Falgorithms.Add('SHA-256WITHECDSA', 'SHA-256withECDSA');
  Falgorithms.Add(TX9ObjectIdentifiers.ECDsaWithSha256.id, 'SHA-256withECDSA');

  Falgorithms.Add('SHA384/ECDSA', 'SHA-384withECDSA');
  Falgorithms.Add('SHA-384/ECDSA', 'SHA-384withECDSA');
  Falgorithms.Add('ECDSAWITHSHA384', 'SHA-384withECDSA');
  Falgorithms.Add('ECDSAWITHSHA-384', 'SHA-384withECDSA');
  Falgorithms.Add('SHA384WITHECDSA', 'SHA-384withECDSA');
  Falgorithms.Add('SHA-384WITHECDSA', 'SHA-384withECDSA');
  Falgorithms.Add(TX9ObjectIdentifiers.ECDsaWithSha384.id, 'SHA-384withECDSA');

  Falgorithms.Add('SHA512/ECDSA', 'SHA-512withECDSA');
  Falgorithms.Add('SHA-512/ECDSA', 'SHA-512withECDSA');
  Falgorithms.Add('ECDSAWITHSHA512', 'SHA-512withECDSA');
  Falgorithms.Add('ECDSAWITHSHA-512', 'SHA-512withECDSA');
  Falgorithms.Add('SHA512WITHECDSA', 'SHA-512withECDSA');
  Falgorithms.Add('SHA-512WITHECDSA', 'SHA-512withECDSA');
  Falgorithms.Add(TX9ObjectIdentifiers.ECDsaWithSha512.id, 'SHA-512withECDSA');

  Falgorithms.Add('RIPEMD160/ECDSA', 'RIPEMD160withECDSA');
  Falgorithms.Add('ECDSAWITHRIPEMD160', 'RIPEMD160withECDSA');
  Falgorithms.Add('RIPEMD160WITHECDSA', 'RIPEMD160withECDSA');
  Falgorithms.Add(TTeleTrusTObjectIdentifiers.ECSignWithRipeMD160.id,
    'RIPEMD160withECDSA');

  // Falgorithms.Add('GOST-3410', 'GOST3410');
  // Falgorithms.Add('GOST-3410-94', 'GOST3410');
  // Falgorithms.Add('GOST3411WITHGOST3410', 'GOST3410');
  // Falgorithms.Add(TCryptoProObjectIdentifiers.GostR3411x94WithGostR3410x94.id,
  // 'GOST3410');

  // Falgorithms.Add('ECGOST-3410', 'ECGOST3410');
  // Falgorithms.Add('ECGOST-3410-2001', 'ECGOST3410');
  // Falgorithms.Add('GOST3411WITHECGOST3410', 'ECGOST3410');
  // Falgorithms.Add(TCryptoProObjectIdentifiers.GostR3411x94WithGostR3410x2001.id,
  // 'ECGOST3410');

  Foids.Add('SHA-1withECDSA', TX9ObjectIdentifiers.ECDsaWithSha1);
  Foids.Add('SHA-224withECDSA', TX9ObjectIdentifiers.ECDsaWithSha224);
  Foids.Add('SHA-256withECDSA', TX9ObjectIdentifiers.ECDsaWithSha256);
  Foids.Add('SHA-384withECDSA', TX9ObjectIdentifiers.ECDsaWithSha384);
  Foids.Add('SHA-512withECDSA', TX9ObjectIdentifiers.ECDsaWithSha512);

  // Foids.Add('GOST3410',
  // TCryptoProObjectIdentifiers.GostR3411x94WithGostR3410x94);
  //
  // Foids.Add('ECGOST3410',
  // TCryptoProObjectIdentifiers.GostR3411x94WithGostR3410x2001);

end;

class destructor TSignerUtilities.DestroySignerUtilities;
begin
  Falgorithms.Free;
  Foids.Free;
end;

class function TSignerUtilities.GetAlgorithms: TCryptoLibStringArray;
begin
  Result := Foids.Keys.ToArray;
end;

class function TSignerUtilities.GetEncodingName
  (const oid: IDerObjectIdentifier): String;
begin
  Falgorithms.TryGetValue(oid.id, Result);
end;

class function TSignerUtilities.GetObjectIdentifier(mechanism: String)
  : IDerObjectIdentifier;
var
  aliased: string;
begin
  if (mechanism = '') then
  begin
    raise EArgumentNilCryptoLibException.CreateRes(@SMechanismNil);
  end;

  mechanism := AnsiUpperCase(mechanism);
  if (Falgorithms.TryGetValue(mechanism, aliased)) then
  begin
    mechanism := aliased;
  end;

  Foids.TryGetValue(mechanism, Result);
end;

class function TSignerUtilities.GetSigner
  (const id: IDerObjectIdentifier): ISigner;
begin
  Result := GetSigner(id.id);
end;

class function TSignerUtilities.GetSigner(algorithm: String): ISigner;
var
  mechanism: string;
  HashInstance: IHash;
begin
  if (algorithm = '') then
  begin
    raise EArgumentNilCryptoLibException.CreateRes(@SAlgorithmNil);
  end;

  algorithm := AnsiUpperCase(algorithm);

  if (not Falgorithms.TryGetValue(algorithm, mechanism)) then
  begin
    mechanism := algorithm;
  end;

  if (mechanism = 'NONEwithECDSA') then
  begin
    HashInstance := THashFactory.TNullDigestFactory.CreateNullDigest();
    HashInstance.Initialize;
    Result := (TDsaDigestSigner.Create(TECDsaSigner.Create() as IECDsaSigner,
      HashInstance));
    Exit;
  end;
  if (mechanism = 'SHA-1withECDSA') then
  begin
    HashInstance := THashFactory.TCrypto.CreateSHA1();
    HashInstance.Initialize;
    Result := (TDsaDigestSigner.Create(TECDsaSigner.Create() as IECDsaSigner,
      HashInstance));
    Exit;
  end;
  if (mechanism = 'SHA-224withECDSA') then
  begin
    HashInstance := THashFactory.TCrypto.CreateSHA2_224();
    HashInstance.Initialize;
    Result := (TDsaDigestSigner.Create(TECDsaSigner.Create() as IECDsaSigner,
      HashInstance));
    Exit;
  end;
  if (mechanism = 'SHA-256withECDSA') then
  begin
    HashInstance := THashFactory.TCrypto.CreateSHA2_256();
    HashInstance.Initialize;
    Result := (TDsaDigestSigner.Create(TECDsaSigner.Create() as IECDsaSigner,
      HashInstance));
    Exit;
  end;
  if (mechanism = 'SHA-384withECDSA') then
  begin
    HashInstance := THashFactory.TCrypto.CreateSHA2_384();
    HashInstance.Initialize;
    Result := (TDsaDigestSigner.Create(TECDsaSigner.Create() as IECDsaSigner,
      HashInstance));
    Exit;
  end;
  if (mechanism = 'SHA-512withECDSA') then
  begin
    HashInstance := THashFactory.TCrypto.CreateSHA2_512();
    HashInstance.Initialize;
    Result := (TDsaDigestSigner.Create(TECDsaSigner.Create() as IECDsaSigner,
      HashInstance));
    Exit;
  end;

  if (mechanism = 'RIPEMD160withECDSA') then
  begin
    HashInstance := THashFactory.TCrypto.CreateRIPEMD160();
    HashInstance.Initialize;
    Result := (TDsaDigestSigner.Create(TECDsaSigner.Create() as IECDsaSigner,
      HashInstance));
    Exit;
  end;

  raise ESecurityUtilityCryptoLibException.CreateResFmt(@SUnRecognizedAlgorithm,
    [algorithm]);

end;

end.
