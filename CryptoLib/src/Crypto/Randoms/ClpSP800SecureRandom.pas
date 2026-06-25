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
  TSP800SecureRandom = class(TSecureRandom, ISecureRandom)
  strict private
    FDrbgProvider: IDrbgProvider;
    FPredictionResistant: Boolean;
    FRandomSource: ISecureRandom;
    FEntropySource: IEntropySource;
    FDrbg: ISP80090Drbg;
    FLock: TCriticalSection;

  public
    constructor Create(const ARandomSource: ISecureRandom;
      const AEntropySource: IEntropySource; const ADrbgProvider: IDrbgProvider;
      APredictionResistant: Boolean);
    destructor Destroy; override;

    procedure SetSeed(const ASeed: TCryptoLibByteArray); overload; override;
    procedure SetSeed(ASeed: Int64); overload; override;
    procedure NextBytes(const ABuf: TCryptoLibByteArray); overload; override;
    procedure NextBytes(const ABuf: TCryptoLibByteArray; AOff, ALen: Int32);
      overload; override;
    function GenerateSeed(ALength: Int32): TCryptoLibByteArray; override;
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
