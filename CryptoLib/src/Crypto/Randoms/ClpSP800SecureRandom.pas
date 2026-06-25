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

unit ClpSP800SecureRandom;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SyncObjs,
  ClpCryptoLibTypes,
  ClpISecureRandom,
  ClpSecureRandom,
  ClpIEntropySource,
  ClpEntropyUtilities,
  ClpISP80090Drbg,
  ClpIDrbgProvider;

type
  /// <summary>
  /// Thread-safe <see cref="ISecureRandom"/> wrapper around an
  /// SP 800-90A DRBG. Lazily instantiates the DRBG on first use and automatically
  /// reseeds when <see cref="ISP80090Drbg.Generate"/> returns
  /// <c>-1</c>.
  /// </summary>
  TSP800SecureRandom = class(TSecureRandom, ISecureRandom)
  strict private
    FDrbgProvider: IDrbgProvider;
    FPredictionResistant: Boolean;
    FRandomSource: ISecureRandom;
    FEntropySource: IEntropySource;
    FDrbg: ISP80090Drbg;
    FLock: TCriticalSection;

  public
    /// <summary>
    /// Create an SP 800-90A secure random backed by <paramref name="ADrbgProvider"/>.
    /// </summary>
    /// <param name="ARandomSource">
    /// Optional secure random whose seed is updated by <see cref="SetSeed"/>; may be nil.
    /// </param>
    /// <param name="AEntropySource">
    /// Entropy source passed to the DRBG provider when the DRBG is created.
    /// </param>
    /// <param name="ADrbgProvider">Factory that constructs the concrete DRBG instance.</param>
    /// <param name="APredictionResistant">
    /// When true, each <see cref="NextBytes"/> call requests prediction resistance.
    /// </param>
    constructor Create(const ARandomSource: ISecureRandom;
      const AEntropySource: IEntropySource; const ADrbgProvider: IDrbgProvider;
      APredictionResistant: Boolean);
    destructor Destroy; override;

    /// <summary>
    /// Forward seed material to the configured <see cref="ISecureRandom"/> when present.
    /// Does not reseed the DRBG directly.
    /// </summary>
    procedure SetSeed(const ASeed: TCryptoLibByteArray); overload; override;
    procedure SetSeed(ASeed: Int64); overload; override;
    procedure NextBytes(const ABuf: TCryptoLibByteArray); overload; override;
    procedure NextBytes(const ABuf: TCryptoLibByteArray; AOff, ALen: Int32);
      overload; override;
    /// <summary>
    /// Assemble seed bytes from the configured entropy source.
    /// </summary>
    function GenerateSeed(ALength: Int32): TCryptoLibByteArray; override;
    /// <summary>
    /// Explicitly reseed the underlying DRBG with optional additional input.
    /// </summary>
    procedure Reseed(const AAdditionalInput: TCryptoLibByteArray); virtual;
  end;

implementation

{ TSP800SecureRandom }

constructor TSP800SecureRandom.Create(const ARandomSource: ISecureRandom;
  const AEntropySource: IEntropySource; const ADrbgProvider: IDrbgProvider;
  APredictionResistant: Boolean);
begin
  inherited Create(nil);
  FRandomSource := ARandomSource;
  FEntropySource := AEntropySource;
  FDrbgProvider := ADrbgProvider;
  FPredictionResistant := APredictionResistant;
  FLock := TCriticalSection.Create();
end;

destructor TSP800SecureRandom.Destroy;
begin
  FLock.Free;
  inherited Destroy;
end;

function TSP800SecureRandom.GenerateSeed(
  ALength: Int32): TCryptoLibByteArray;
begin
  Result := TEntropyUtilities.GenerateSeed(FEntropySource, ALength);
end;

procedure TSP800SecureRandom.NextBytes(const ABuf: TCryptoLibByteArray);
begin
  NextBytes(ABuf, 0, System.Length(ABuf));
end;

procedure TSP800SecureRandom.NextBytes(const ABuf: TCryptoLibByteArray; AOff,
  ALen: Int32);
begin
  FLock.Acquire;
  try
    if FDrbg = nil then
    begin
      FDrbg := FDrbgProvider.Get(FEntropySource);
    end;

    // Auto-reseed when Generate returns -1 (reseed interval exceeded)
    if FDrbg.Generate(ABuf, AOff, ALen, nil, FPredictionResistant) < 0 then
    begin
      FDrbg.Reseed(nil);
      FDrbg.Generate(ABuf, AOff, ALen, nil, FPredictionResistant);
    end;
  finally
    FLock.Release;
  end;
end;

procedure TSP800SecureRandom.Reseed(const AAdditionalInput: TCryptoLibByteArray);
begin
  FLock.Acquire;
  try
    if FDrbg = nil then
    begin
      FDrbg := FDrbgProvider.Get(FEntropySource);
    end;
    FDrbg.Reseed(AAdditionalInput);
  finally
    FLock.Release;
  end;
end;

procedure TSP800SecureRandom.SetSeed(const ASeed: TCryptoLibByteArray);
begin
  FLock.Acquire;
  try
    if FRandomSource <> nil then
    begin
      FRandomSource.SetSeed(ASeed);
    end;
  finally
    FLock.Release;
  end;
end;

procedure TSP800SecureRandom.SetSeed(ASeed: Int64);
begin
  FLock.Acquire;
  try
    if FRandomSource <> nil then
    begin
      FRandomSource.SetSeed(ASeed);
    end;
  finally
    FLock.Release;
  end;
end;

end.
