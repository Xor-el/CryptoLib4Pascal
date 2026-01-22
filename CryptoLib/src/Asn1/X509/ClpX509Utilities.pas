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

unit ClpX509Utilities;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  Classes,
  Generics.Collections,
  ClpAsn1Objects,
  ClpIAsn1Objects,
  ClpIX509Asn1Objects,
  ClpX509Asn1Objects,
  ClpIX509Certificate,
  ClpIStreamCalculator,
  ClpIBlockResult,
  ClpIDigestFactory,
  ClpIMacFactory,
  ClpIVerifierFactory,
  ClpISignatureFactory,
  ClpPkcsObjectIdentifiers,
  ClpX9ObjectIdentifiers,
  ClpNistObjectIdentifiers,
  ClpTeleTrusTObjectIdentifiers,
  ClpCryptoProObjectIdentifiers,
  ClpCryptoLibTypes,
  ClpArrayUtils,
  ClpCollectionUtilities;

type
  /// <summary>
  /// Internal utilities for X509 operations.
  /// </summary>
  TX509Utilities = class sealed(TObject)

  strict private
    class var
      FAlgorithms: TDictionary<String, IDerObjectIdentifier>;

    class procedure Boot; static;
    class constructor Create;

  public
    class function AreEquivalentAlgorithms(const AId1, AId2: IAlgorithmIdentifier): Boolean; static;
    class function CalculateDigest(const ADigestAlgorithm: IAlgorithmIdentifier;
      const AAsn1Encodable: IAsn1Encodable): TCryptoLibByteArray; overload; static;
    class function CalculateDigest(const ADigestFactory: IDigestFactory;
      const ABuf: TCryptoLibByteArray): TCryptoLibByteArray; overload; static;
    class function CalculateDigest(const ADigestFactory: IDigestFactory;
      const ABuf: TCryptoLibByteArray; AOff, ALen: Int32): TCryptoLibByteArray; overload; static;
    class function CalculateDigest(const ADigestFactory: IDigestFactory;
      const AAsn1Encodable: IAsn1Encodable): TCryptoLibByteArray; overload; static;
    class function CalculateResult<TResult>(const AStreamCalculator: IStreamCalculator<TResult>;
      const ABuf: TCryptoLibByteArray; AOff, ALen: Int32): TResult; overload; static;
    class function CalculateResult<TResult>(const AStreamCalculator: IStreamCalculator<TResult>;
      const AAsn1Encodable: IAsn1Encodable): TResult; overload; static;
    class function CollectDerBitString(const AResult: IBlockResult): IDerBitString; static;
    // TODO: CreateIssuerSerial methods require IssuerSerial class which doesn't exist yet
    // class function CreateIssuerSerial(const ACertificate: IX509Certificate): IIssuerSerial; overload; static;
    // class function CreateIssuerSerial(const ACertificate: IX509CertificateStructure): IIssuerSerial; overload; static;
    class function GenerateBitString(const AStreamCalculator: IStreamCalculator<IBlockResult>;
      const AAsn1Encodable: IAsn1Encodable): IDerBitString; static;
    class function GenerateDigest(const ADigestFactory: IDigestFactory;
      const AAsn1Encodable: IAsn1Encodable): IDerBitString; static;
    class function GenerateMac(const AMacFactory: IMacFactory;
      const AAsn1Encodable: IAsn1Encodable): IDerBitString; static;
    class function GenerateSignature(const ASignatureFactory: ISignatureFactory;
      const AAsn1Encodable: IAsn1Encodable): IDerBitString; static;
    class function GetAlgNames: TCryptoLibStringArray; static;
    class function HasAbsentParameters(const AAlgID: IAlgorithmIdentifier): Boolean; static;
    class function IsAbsentParameters(const AParameters: IAsn1Encodable): Boolean; static;
    class function VerifyMac(const AMacFactory: IMacFactory;
      const AAsn1Encodable: IAsn1Encodable; const AExpected: IDerBitString): Boolean; static;
    class function VerifySignature(const AVerifierFactory: IVerifierFactory;
      const AAsn1Encodable: IAsn1Encodable; const ASignature: IDerBitString): Boolean; static;

  end;

implementation

uses
  ClpDigestUtilities,
  ClpDefaultDigestCalculator,
  ClpDefaultDigestResult,
  ClpIDigest,
  ClpIVerifier,
  ClpCryptoLibComparers;

{ TX509Utilities }

class constructor TX509Utilities.Create;
begin
  Boot;
end;

class procedure TX509Utilities.Boot;
begin
  FAlgorithms := TDictionary<String, IDerObjectIdentifier>.Create(TCryptoLibComparers.OrdinalIgnoreCaseEqualityComparer);

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
end;

class function TX509Utilities.AreEquivalentAlgorithms(const AId1, AId2: IAlgorithmIdentifier): Boolean;
begin
  if not AId1.Algorithm.Equals(AId2.Algorithm) then
  begin
    Result := False;
    Exit;
  end;

  // TODO Java has a property to control whether absent parameters can match NULL parameters
  if HasAbsentParameters(AId1) and HasAbsentParameters(AId2) then
  begin
    Result := True;
    Exit;
  end;

  Result := AId1.Parameters.Equals(AId2.Parameters);
end;

class function TX509Utilities.CalculateDigest(const ADigestAlgorithm: IAlgorithmIdentifier;
  const AAsn1Encodable: IAsn1Encodable): TCryptoLibByteArray;
var
  LDigest: IDigest;
  LDigestCalculator: IStreamCalculator<IBlockResult>;
  LDigestResult: IBlockResult;
begin
  LDigest := TDigestUtilities.GetDigest(ADigestAlgorithm.Algorithm);
  LDigestCalculator := TDefaultDigestCalculator.Create(LDigest);
  LDigestResult := CalculateResult<IBlockResult>(LDigestCalculator, AAsn1Encodable);
  Result := LDigestResult.Collect();
end;

class function TX509Utilities.CalculateDigest(const ADigestFactory: IDigestFactory;
  const ABuf: TCryptoLibByteArray): TCryptoLibByteArray;
begin
  Result := CalculateDigest(ADigestFactory, ABuf, 0, System.Length(ABuf));
end;

class function TX509Utilities.CalculateDigest(const ADigestFactory: IDigestFactory;
  const ABuf: TCryptoLibByteArray; AOff, ALen: Int32): TCryptoLibByteArray;
var
  LDigestCalculator: IStreamCalculator<IBlockResult>;
  LDigestResult: IBlockResult;
begin
  LDigestCalculator := ADigestFactory.CreateCalculator();
  LDigestResult := CalculateResult<IBlockResult>(LDigestCalculator, ABuf, AOff, ALen);
  Result := LDigestResult.Collect();
end;

class function TX509Utilities.CalculateDigest(const ADigestFactory: IDigestFactory;
  const AAsn1Encodable: IAsn1Encodable): TCryptoLibByteArray;
var
  LDigestCalculator: IStreamCalculator<IBlockResult>;
  LDigestResult: IBlockResult;
begin
  LDigestCalculator := ADigestFactory.CreateCalculator();
  LDigestResult := CalculateResult<IBlockResult>(LDigestCalculator, AAsn1Encodable);
  Result := LDigestResult.Collect();
end;

class function TX509Utilities.CalculateResult<TResult>(const AStreamCalculator: IStreamCalculator<TResult>;
  const ABuf: TCryptoLibByteArray; AOff, ALen: Int32): TResult;
var
  LStream: TStream;
begin
  LStream := AStreamCalculator.Stream;
  try
    LStream.WriteBuffer(ABuf[AOff], ALen);
  finally
    LStream.Free;
  end;
  Result := AStreamCalculator.GetResult();
end;

class function TX509Utilities.CalculateResult<TResult>(const AStreamCalculator: IStreamCalculator<TResult>;
  const AAsn1Encodable: IAsn1Encodable): TResult;
var
  LStream: TStream;
begin
  LStream := AStreamCalculator.Stream;
  try
    AAsn1Encodable.EncodeTo(LStream, TAsn1Encodable.Der);
  finally
    LStream.Free;
  end;
  Result := AStreamCalculator.GetResult();
end;

class function TX509Utilities.CollectDerBitString(const AResult: IBlockResult): IDerBitString;
var
  LData: TCryptoLibByteArray;
begin
  LData := AResult.Collect();
  Result := TDerBitString.Create(LData);
end;

// TODO: Implement when IssuerSerial class is available
// class function TX509Utilities.CreateIssuerSerial(const ACertificate: IX509Certificate): IIssuerSerial;
// begin
//   Result := CreateIssuerSerial(ACertificate.CertificateStructure);
// end;
//
// class function TX509Utilities.CreateIssuerSerial(const ACertificate: IX509CertificateStructure): IIssuerSerial;
// begin
//   Result := TIssuerSerial.Create(ACertificate.Issuer, ACertificate.SerialNumber);
// end;

class function TX509Utilities.GenerateBitString(const AStreamCalculator: IStreamCalculator<IBlockResult>;
  const AAsn1Encodable: IAsn1Encodable): IDerBitString;
var
  LResult: IBlockResult;
begin
  LResult := CalculateResult<IBlockResult>(AStreamCalculator, AAsn1Encodable);
  Result := CollectDerBitString(LResult);
end;

class function TX509Utilities.GenerateDigest(const ADigestFactory: IDigestFactory;
  const AAsn1Encodable: IAsn1Encodable): IDerBitString;
begin
  Result := GenerateBitString(ADigestFactory.CreateCalculator(), AAsn1Encodable);
end;

class function TX509Utilities.GenerateMac(const AMacFactory: IMacFactory;
  const AAsn1Encodable: IAsn1Encodable): IDerBitString;
begin
  Result := GenerateBitString(AMacFactory.CreateCalculator(), AAsn1Encodable);
end;

class function TX509Utilities.GenerateSignature(const ASignatureFactory: ISignatureFactory;
  const AAsn1Encodable: IAsn1Encodable): IDerBitString;
begin
  Result := GenerateBitString(ASignatureFactory.CreateCalculator(), AAsn1Encodable);
end;

class function TX509Utilities.GetAlgNames: TCryptoLibStringArray;
var
  LList: TList<String>;
  LKey: String;
begin
  LList := TList<String>.Create();
  try
    for LKey in FAlgorithms.Keys do
    begin
      LList.Add(LKey);
    end;
    Result := LList.ToArray();
  finally
    LList.Free;
  end;
end;

class function TX509Utilities.HasAbsentParameters(const AAlgID: IAlgorithmIdentifier): Boolean;
begin
  Result := IsAbsentParameters(AAlgID.Parameters);
end;

class function TX509Utilities.IsAbsentParameters(const AParameters: IAsn1Encodable): Boolean;
begin
  Result := (AParameters = nil) or TDerNull.Instance.Equals(AParameters);
end;

class function TX509Utilities.VerifyMac(const AMacFactory: IMacFactory;
  const AAsn1Encodable: IAsn1Encodable; const AExpected: IDerBitString): Boolean;
var
  LResult: TCryptoLibByteArray;
begin
  LResult := CalculateResult<IBlockResult>(AMacFactory.CreateCalculator(), AAsn1Encodable).Collect();
  Result := TArrayUtils.ConstantTimeAreEqual(LResult, AExpected.GetOctets());
end;

class function TX509Utilities.VerifySignature(const AVerifierFactory: IVerifierFactory;
  const AAsn1Encodable: IAsn1Encodable; const ASignature: IDerBitString): Boolean;
var
  LCalculator: IStreamCalculator<IVerifier>;
  LResult: IVerifier;
begin
  LCalculator := AVerifierFactory.CreateCalculator();
  LResult := CalculateResult<IVerifier>(LCalculator, AAsn1Encodable);
  Result := LResult.IsVerified(ASignature.GetOctets());
end;

end.
