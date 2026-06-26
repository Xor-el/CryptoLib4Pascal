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

unit ClpSP800SecureRandomBuilder;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpCryptoLibTypes,
  ClpIDigest,
  ClpIMac,
  ClpIBlockCipher,
  ClpISecureRandom,
  ClpIEntropySource,
  ClpIEntropySourceProvider,
  ClpIDrbgProvider,
  ClpISP80090Drbg,
  ClpISP800SecureRandomBuilder,
  ClpSP800SecureRandom,
  ClpCryptoServicesRegistrar,
  ClpBasicEntropySourceProvider,
  ClpHashSP800Drbg,
  ClpHMacSP800Drbg,
  ClpCtrSP800Drbg;

resourcestring
  SEntropySourceNil = 'entropySource cannot be nil';
  SEntropySourceProviderNil = 'entropySourceProvider cannot be nil';
  SDigestNil = 'digest cannot be nil';
  SHMacNil = 'hMac cannot be nil';
  SBlockCipherNil = 'blockCipher cannot be nil';

type
  /// <summary>
  /// Fluent builder for <see cref="TSP800SecureRandom"/> instances
  /// using Hash, HMAC, or AES CTR DRBG.
  /// </summary>
  TSP800SecureRandomBuilder = class sealed(TInterfacedObject, ISP800SecureRandomBuilder)
  strict private
  type
    THashDrbgProvider = class sealed(TInterfacedObject, IDrbgProvider)
    strict private
      FDigest: IDigest;
      FNonce: TCryptoLibByteArray;
      FPersonalizationString: TCryptoLibByteArray;
      FSecurityStrength: Int32;
    public
      constructor Create(const ADigest: IDigest;
        const ANonce, APersonalizationString: TCryptoLibByteArray;
        ASecurityStrength: Int32);
      function Get(const AEntropySource: IEntropySource): ISP80090Drbg;
    end;

    THMacDrbgProvider = class sealed(TInterfacedObject, IDrbgProvider)
    strict private
      FHMac: IMac;
      FNonce: TCryptoLibByteArray;
      FPersonalizationString: TCryptoLibByteArray;
      FSecurityStrength: Int32;
    public
      constructor Create(const AHMac: IMac;
        const ANonce, APersonalizationString: TCryptoLibByteArray;
        ASecurityStrength: Int32);
      function Get(const AEntropySource: IEntropySource): ISP80090Drbg;
    end;

    TCtrDrbgProvider = class sealed(TInterfacedObject, IDrbgProvider)
    strict private
      FBlockCipher: IBlockCipher;
      FKeySizeInBits: Int32;
      FNonce: TCryptoLibByteArray;
      FPersonalizationString: TCryptoLibByteArray;
      FSecurityStrength: Int32;
    public
      constructor Create(const ABlockCipher: IBlockCipher; AKeySizeInBits: Int32;
        const ANonce, APersonalizationString: TCryptoLibByteArray;
        ASecurityStrength: Int32);
      function Get(const AEntropySource: IEntropySource): ISP80090Drbg;
    end;

  var
    FRandom: ISecureRandom;
    FEntropySourceProvider: IEntropySourceProvider;
    FPersonalizationString: TCryptoLibByteArray;
    FSecurityStrength: Int32;
    FEntropyBitsRequired: Int32;

  public
    /// <summary>
    /// Create a builder using the default secure random as entropy with 256-bit defaults.
    /// </summary>
    constructor Create(); overload;
    /// <summary>
    /// Create a builder backed by <paramref name="AEntropySource"/>.
    /// </summary>
    constructor Create(const AEntropySource: ISecureRandom;
      APredictionResistant: Boolean); overload;
    /// <summary>
    /// Create a builder using a custom entropy source provider.
    /// </summary>
    constructor Create(const AEntropySourceProvider: IEntropySourceProvider);
      overload;

    function SetPersonalizationString(
      const APersonalizationString: TCryptoLibByteArray)
      : ISP800SecureRandomBuilder;
    function SetSecurityStrength(
      ASecurityStrength: Int32): ISP800SecureRandomBuilder;
    function SetEntropyBitsRequired(
      AEntropyBitsRequired: Int32): ISP800SecureRandomBuilder;

    /// <summary>Build a Hash_DRBG-backed secure random.</summary>
    function BuildHash(const ADigest: IDigest;
      const ANonce: TCryptoLibByteArray;
      APredictionResistant: Boolean): ISecureRandom;
    /// <summary>Build an AES CTR_DRBG-backed secure random.</summary>
    function BuildCtr(const ACipher: IBlockCipher; AKeySizeInBits: Int32;
      const ANonce: TCryptoLibByteArray;
      APredictionResistant: Boolean): ISecureRandom;
    /// <summary>Build an HMAC_DRBG-backed secure random.</summary>
    function BuildHMac(const AHMac: IMac; const ANonce: TCryptoLibByteArray;
      APredictionResistant: Boolean): ISecureRandom;
  end;

implementation

{ TSP800SecureRandomBuilder.THashDrbgProvider }

constructor TSP800SecureRandomBuilder.THashDrbgProvider.Create(
  const ADigest: IDigest; const ANonce, APersonalizationString: TCryptoLibByteArray;
  ASecurityStrength: Int32);
begin
  inherited Create;
  FDigest := ADigest;
  FNonce := ANonce;
  FPersonalizationString := APersonalizationString;
  FSecurityStrength := ASecurityStrength;
end;

function TSP800SecureRandomBuilder.THashDrbgProvider.Get(
  const AEntropySource: IEntropySource): ISP80090Drbg;
begin
  Result := THashSP800Drbg.Create(FDigest, FSecurityStrength, AEntropySource,
    FPersonalizationString, FNonce);
end;

{ TSP800SecureRandomBuilder.THMacDrbgProvider }

constructor TSP800SecureRandomBuilder.THMacDrbgProvider.Create(
  const AHMac: IMac; const ANonce, APersonalizationString: TCryptoLibByteArray;
  ASecurityStrength: Int32);
begin
  inherited Create;
  FHMac := AHMac;
  FNonce := ANonce;
  FPersonalizationString := APersonalizationString;
  FSecurityStrength := ASecurityStrength;
end;

function TSP800SecureRandomBuilder.THMacDrbgProvider.Get(
  const AEntropySource: IEntropySource): ISP80090Drbg;
begin
  Result := THMacSP800Drbg.Create(FHMac, FSecurityStrength, AEntropySource,
    FPersonalizationString, FNonce);
end;

{ TSP800SecureRandomBuilder.TCtrDrbgProvider }

constructor TSP800SecureRandomBuilder.TCtrDrbgProvider.Create(
  const ABlockCipher: IBlockCipher; AKeySizeInBits: Int32;
  const ANonce, APersonalizationString: TCryptoLibByteArray;
  ASecurityStrength: Int32);
begin
  inherited Create;
  FBlockCipher := ABlockCipher;
  FKeySizeInBits := AKeySizeInBits;
  FNonce := ANonce;
  FPersonalizationString := APersonalizationString;
  FSecurityStrength := ASecurityStrength;
end;

function TSP800SecureRandomBuilder.TCtrDrbgProvider.Get(
  const AEntropySource: IEntropySource): ISP80090Drbg;
begin
  Result := TCtrSP800Drbg.Create(FBlockCipher, FKeySizeInBits,
    FSecurityStrength, AEntropySource, FPersonalizationString, FNonce);
end;

{ TSP800SecureRandomBuilder }

function TSP800SecureRandomBuilder.BuildCtr(const ACipher: IBlockCipher;
  AKeySizeInBits: Int32; const ANonce: TCryptoLibByteArray;
  APredictionResistant: Boolean): ISecureRandom;
begin
  if ACipher = nil then
  begin
    raise EArgumentNilCryptoLibException.CreateRes(@SBlockCipherNil);
  end;

  Result := TSP800SecureRandom.Create(FRandom,
    FEntropySourceProvider.Get(FEntropyBitsRequired),
    TCtrDrbgProvider.Create(ACipher, AKeySizeInBits, ANonce,
    FPersonalizationString, FSecurityStrength) as IDrbgProvider, APredictionResistant);
end;

function TSP800SecureRandomBuilder.BuildHash(const ADigest: IDigest;
  const ANonce: TCryptoLibByteArray;
  APredictionResistant: Boolean): ISecureRandom;
begin
  if ADigest = nil then
  begin
    raise EArgumentNilCryptoLibException.CreateRes(@SDigestNil);
  end;

  Result := TSP800SecureRandom.Create(FRandom,
    FEntropySourceProvider.Get(FEntropyBitsRequired),
    THashDrbgProvider.Create(ADigest, ANonce, FPersonalizationString,
    FSecurityStrength) as IDrbgProvider, APredictionResistant);
end;

function TSP800SecureRandomBuilder.BuildHMac(const AHMac: IMac;
  const ANonce: TCryptoLibByteArray;
  APredictionResistant: Boolean): ISecureRandom;
begin
  if AHMac = nil then
  begin
    raise EArgumentNilCryptoLibException.CreateRes(@SHMacNil);
  end;

  Result := TSP800SecureRandom.Create(FRandom,
    FEntropySourceProvider.Get(FEntropyBitsRequired),
    THMacDrbgProvider.Create(AHMac, ANonce, FPersonalizationString,
    FSecurityStrength) as IDrbgProvider, APredictionResistant);
end;

constructor TSP800SecureRandomBuilder.Create;
begin
  Create(TCryptoServicesRegistrar.GetSecureRandom(), False);
end;

constructor TSP800SecureRandomBuilder.Create(
  const AEntropySource: ISecureRandom; APredictionResistant: Boolean);
begin
  inherited Create;

  if AEntropySource = nil then
  begin
    raise EArgumentNilCryptoLibException.CreateRes(@SEntropySourceNil);
  end;

  FRandom := AEntropySource;
  FEntropySourceProvider := TBasicEntropySourceProvider.Create(AEntropySource,
    APredictionResistant);
  FSecurityStrength := 256;
  FEntropyBitsRequired := 256;
end;

constructor TSP800SecureRandomBuilder.Create(
  const AEntropySourceProvider: IEntropySourceProvider);
begin
  inherited Create;

  if AEntropySourceProvider = nil then
  begin
    raise EArgumentNilCryptoLibException.CreateRes(@SEntropySourceProviderNil);
  end;

  FRandom := nil;
  FEntropySourceProvider := AEntropySourceProvider;
  FSecurityStrength := 256;
  FEntropyBitsRequired := 256;
end;

function TSP800SecureRandomBuilder.SetEntropyBitsRequired(
  AEntropyBitsRequired: Int32): ISP800SecureRandomBuilder;
begin
  FEntropyBitsRequired := AEntropyBitsRequired;
  Result := Self;
end;

function TSP800SecureRandomBuilder.SetPersonalizationString(
  const APersonalizationString: TCryptoLibByteArray): ISP800SecureRandomBuilder;
begin
  FPersonalizationString := APersonalizationString;
  Result := Self;
end;

function TSP800SecureRandomBuilder.SetSecurityStrength(
  ASecurityStrength: Int32): ISP800SecureRandomBuilder;
begin
  FSecurityStrength := ASecurityStrength;
  Result := Self;
end;

end.
