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

unit SecureRandomExampleUtilities;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$HINTS OFF}
{$WARNINGS OFF}
{$ENDIF FPC}

uses
  SysUtils,
  ClpCryptoLibTypes,
  ClpCryptoLibExceptions,
  ClpSecureRandom,
  ClpISecureRandom,
  ClpCryptoApiRandomGenerator,
  ClpICryptoApiRandomGenerator,
  ClpSP800SecureRandomBuilder,
  ClpISP800SecureRandomBuilder,
  ClpDigestUtilities,
  ClpIDigest,
  ClpHMac,
  ClpIMac,
  ClpAesUtilities,
  ClpIBlockCipher,
  ClpConverters,
  ClpDateTimeUtilities;

resourcestring
  SNonceRequired =
    'Nonce is required: each SP 800-90A DRBG instantiation needs a unique nonce ' +
    '(not secret, but must not be reused across independent instantiations)';

type
  /// <summary>
  /// Factories for SP 800-90A DRBG-backed <see cref="ISecureRandom"/> instances,
  /// mirroring a compliance-oriented setup with OS CSPRNG as the entropy feeder.
  /// </summary>
  TSecureRandomExampleUtilities = class sealed
  strict private
    class function OsEntropy: ISecureRandom; static;
    class procedure ValidateNonce(const ANonce: TCryptoLibByteArray); static;
    class function CreateConfiguredBuilder(const AEntropySource: ISecureRandom;
      ASecurityStrength, AEntropyBitsRequired: Int32;
      const APersonalizationString: TCryptoLibByteArray): ISP800SecureRandomBuilder; static;
  public
    /// <summary>
    /// OS CSPRNG wrapped as <see cref="ISecureRandom"/> for use as a DRBG entropy feeder only.
    /// </summary>
    class function CreateOsEntropySource: ISecureRandom; static;

    /// <summary>
    /// Build a Hash_DRBG (SHA-256) backed secure random at 256-bit security strength.
    /// </summary>
    /// <param name="ANonce">
    /// Caller-supplied nonce; must be unique per DRBG instantiation.
    /// </param>
    class function CreateHashDrbgSecureRandom(const ANonce: TCryptoLibByteArray;
      ASecurityStrength: Int32 = 256; AEntropyBitsRequired: Int32 = 256;
      APredictionResistant: Boolean = False;
      const APersonalizationString: TCryptoLibByteArray = nil;
      const AEntropySource: ISecureRandom = nil): ISecureRandom; static;

    /// <summary>
    /// Build an HMAC_DRBG (HMAC-SHA-256) backed secure random at 256-bit security strength.
    /// </summary>
    class function CreateHMacDrbgSecureRandom(const ANonce: TCryptoLibByteArray;
      ASecurityStrength: Int32 = 256; AEntropyBitsRequired: Int32 = 256;
      APredictionResistant: Boolean = False;
      const APersonalizationString: TCryptoLibByteArray = nil;
      const AEntropySource: ISecureRandom = nil): ISecureRandom; static;

    /// <summary>
    /// Build a CTR_DRBG (AES-256) backed secure random at 256-bit security strength.
    /// </summary>
    class function CreateCtrDrbgSecureRandom(const ANonce: TCryptoLibByteArray;
      ASecurityStrength: Int32 = 256; AEntropyBitsRequired: Int32 = 256;
      APredictionResistant: Boolean = False;
      const APersonalizationString: TCryptoLibByteArray = nil;
      const AEntropySource: ISecureRandom = nil): ISecureRandom; static;

    /// <summary>
    /// Demo-only helper showing one way to derive a unique nonce for examples.
    /// Production code should use an application-specific, stable nonce strategy.
    /// </summary>
    class function DemoBuildUniqueNonce(const ALabel: string): TCryptoLibByteArray; static;
  end;

implementation

{ TSecureRandomExampleUtilities }

class function TSecureRandomExampleUtilities.CreateConfiguredBuilder(
  const AEntropySource: ISecureRandom; ASecurityStrength, AEntropyBitsRequired: Int32;
  const APersonalizationString: TCryptoLibByteArray): ISP800SecureRandomBuilder;
begin
  Result := TSP800SecureRandomBuilder.Create(AEntropySource, False);
  Result.SetSecurityStrength(ASecurityStrength);
  Result.SetEntropyBitsRequired(AEntropyBitsRequired);
  if APersonalizationString <> nil then
    Result.SetPersonalizationString(APersonalizationString);
end;

class function TSecureRandomExampleUtilities.CreateCtrDrbgSecureRandom(
  const ANonce: TCryptoLibByteArray; ASecurityStrength, AEntropyBitsRequired: Int32;
  APredictionResistant: Boolean; const APersonalizationString: TCryptoLibByteArray;
  const AEntropySource: ISecureRandom): ISecureRandom;
var
  LEntropy: ISecureRandom;
  LBuilder: ISP800SecureRandomBuilder;
  LEngine: IBlockCipher;
begin
  ValidateNonce(ANonce);
  if AEntropySource <> nil then
    LEntropy := AEntropySource
  else
    LEntropy := OsEntropy;
  LBuilder := CreateConfiguredBuilder(LEntropy, ASecurityStrength,
    AEntropyBitsRequired, APersonalizationString);
  LEngine := TAesUtilities.CreateEngine();
  Result := LBuilder.BuildCtr(LEngine, 256, ANonce, APredictionResistant);
end;

class function TSecureRandomExampleUtilities.CreateHashDrbgSecureRandom(
  const ANonce: TCryptoLibByteArray; ASecurityStrength, AEntropyBitsRequired: Int32;
  APredictionResistant: Boolean; const APersonalizationString: TCryptoLibByteArray;
  const AEntropySource: ISecureRandom): ISecureRandom;
var
  LEntropy: ISecureRandom;
  LBuilder: ISP800SecureRandomBuilder;
  LDigest: IDigest;
begin
  ValidateNonce(ANonce);
  if AEntropySource <> nil then
    LEntropy := AEntropySource
  else
    LEntropy := OsEntropy;
  LBuilder := CreateConfiguredBuilder(LEntropy, ASecurityStrength,
    AEntropyBitsRequired, APersonalizationString);
  LDigest := TDigestUtilities.GetDigest('SHA-256');
  Result := LBuilder.BuildHash(LDigest, ANonce, APredictionResistant);
end;

class function TSecureRandomExampleUtilities.CreateHMacDrbgSecureRandom(
  const ANonce: TCryptoLibByteArray; ASecurityStrength, AEntropyBitsRequired: Int32;
  APredictionResistant: Boolean; const APersonalizationString: TCryptoLibByteArray;
  const AEntropySource: ISecureRandom): ISecureRandom;
var
  LEntropy: ISecureRandom;
  LBuilder: ISP800SecureRandomBuilder;
  LHMac: IMac;
begin
  ValidateNonce(ANonce);
  if AEntropySource <> nil then
    LEntropy := AEntropySource
  else
    LEntropy := OsEntropy;
  LBuilder := CreateConfiguredBuilder(LEntropy, ASecurityStrength,
    AEntropyBitsRequired, APersonalizationString);
  LHMac := THMac.Create(TDigestUtilities.GetDigest('SHA-256'));
  Result := LBuilder.BuildHMac(LHMac, ANonce, APredictionResistant);
end;

class function TSecureRandomExampleUtilities.CreateOsEntropySource: ISecureRandom;
begin
  Result := OsEntropy;
end;

class function TSecureRandomExampleUtilities.DemoBuildUniqueNonce(const ALabel: string)
  : TCryptoLibByteArray;
begin
  Result := TConverters.ConvertStringToBytes(
    Format('CryptoLibExamples::%s::%d', [ALabel, TDateTimeUtilities.CurrentUnixMs]),
    TEncoding.UTF8);
end;

class function TSecureRandomExampleUtilities.OsEntropy: ISecureRandom;
begin
  Result := TSecureRandom.Create(TCryptoApiRandomGenerator.Create()
    as ICryptoApiRandomGenerator);
end;

class procedure TSecureRandomExampleUtilities.ValidateNonce(
  const ANonce: TCryptoLibByteArray);
begin
  if (ANonce = nil) or (System.Length(ANonce) = 0) then
    raise EArgumentCryptoLibException.CreateRes(@SNonceRequired);
end;

end.
