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

unit ClpSecureRandom;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SyncObjs,
  SysUtils,
  ClpBitOperations,
  ClpCryptoLibTypes,
  ClpCryptoLibExceptions,
  ClpDateTimeUtilities,
  ClpDateTimeHelper,
  ClpIDigest,
  ClpIRandomGenerator,
  ClpRandom,
  ClpOSRandomProvider,
  ClpDigestUtilities,
  ClpStringUtilities,
  ClpCryptoApiRandomGenerator,
  ClpICryptoApiRandomGenerator,
  ClpDigestRandomGenerator,
  ClpIDigestRandomGenerator,
  ClpISecureRandom,
  ClpPack;

resourcestring
  SAlgorithmNil = 'algorithm cannot be nil';
  SUnrecognizedPRNGAlgorithm = 'unrecognized PRNG algorithm: %s';
  SMaxValueCannotBeNegative = 'maxValue cannot be negative';
  SInvalidMaxValue = 'maxValue cannot be less than minValue';

type
  TSecureRandom = class(TRandom, ISecureRandom)

  strict private
  class var
    FCounter: Int64;
    FMasterRandom: ISecureRandom;
    FDoubleScale: Double;
    FLock: TCriticalSection;

    class function GetMasterRandom: ISecureRandom; static; inline;

    class function NextCounterValue(): Int64; static; inline;

    class function CreatePrng(const ADigestName: String; AAutoSeed: Boolean): IDigestRandomGenerator; static; inline;

    class procedure AutoSeed(const AGenerator: IRandomGenerator;
      ASeedLength: Int32); static;

    class constructor Create(); overload;
    class destructor Destroy();

  strict protected
  var
    FGenerator: IRandomGenerator;

  public
    /// <summary>Use the specified instance of IRandomGenerator as random source.</summary>
    /// <remarks>
    /// This constructor performs no seeding of either the <c>IRandomGenerator</c> or the
    /// constructed <c>SecureRandom</c>. It is the responsibility of the client to provide
    /// proper seed material as necessary/appropriate for the given <c>IRandomGenerator</c>
    /// implementation.
    /// </remarks>
    /// <param name="AGenerator">The source to generate all random bytes from.</param>
    constructor Create(const AGenerator: IRandomGenerator); overload;
    constructor Create(); overload;

    function GenerateSeed(ALength: Int32): TCryptoLibByteArray; virtual;
    procedure SetSeed(const ASeed: TCryptoLibByteArray); overload; virtual;
    procedure SetSeed(ASeed: Int64); overload; virtual;

    procedure NextBytes(const ABuf: TCryptoLibByteArray); overload; override;
    procedure NextBytes(const ABuf: TCryptoLibByteArray; AOff, ALen: Int32);
      overload; virtual;
    function NextInt32(): Int32; virtual;
    function NextInt64(): Int64; virtual;

    function NextDouble(): Double; override;

    function Next(): Int32; overload; override;
    function Next(AMaxValue: Int32): Int32; overload; override;
    function Next(AMinValue, AMaxValue: Int32): Int32; overload; override;

    class function GetNextBytes(const ASecureRandom: ISecureRandom;
      ALength: Int32): TCryptoLibByteArray; static;

    /// <summary>
    /// Create and auto-seed an instance based on the given algorithm.
    /// </summary>
    /// <remarks>Equivalent to GetInstance(AAlgorithm, true)</remarks>
    /// <param name="AAlgorithm">e.g. "SHA256PRNG"</param>
    class function GetInstance(const AAlgorithm: String): ISecureRandom; overload; static; inline;
    /// <summary>
    /// Create an instance based on the given algorithm, with optional auto-seeding
    /// </summary>
    /// <param name="AAlgorithm">e.g. "SHA256PRNG"</param>
    /// <param name="AAutoSeed">If true, the instance will be auto-seeded.</param>
    class function GetInstance(const AAlgorithm: String; AAutoSeed: Boolean): ISecureRandom; overload; static;
    class property MasterRandom: ISecureRandom read GetMasterRandom;

  end;

implementation

{ TSecureRandom }

constructor TSecureRandom.Create(const AGenerator: IRandomGenerator);
begin
  inherited Create(0);
  FGenerator := AGenerator;
end;

class function TSecureRandom.GetMasterRandom: ISecureRandom;
begin
  Result := FMasterRandom;
end;

class function TSecureRandom.GetNextBytes(const ASecureRandom: ISecureRandom;
  ALength: Int32): TCryptoLibByteArray;
begin
  System.SetLength(Result, ALength);
  ASecureRandom.NextBytes(Result);
end;

function TSecureRandom.Next(AMaxValue: Int32): Int32;
var
  LBits: Int32;
begin
  if (AMaxValue < 2) then
  begin
    if (AMaxValue < 0) then
    begin
      raise EArgumentOutOfRangeCryptoLibException.CreateRes(@SMaxValueCannotBeNegative);
    end;

    Result := 0;
    Exit;
  end;

  // Test whether AMaxValue is a power of 2
  if ((AMaxValue and (AMaxValue - 1)) = 0) then
  begin
    LBits := NextInt32() and System.High(Int32);
    Result := Int32(TBitOperations.Asr64((Int64(LBits) * AMaxValue), 31));
    Exit;
  end;

  repeat
    LBits := NextInt32() and System.High(Int32);
    Result := LBits mod AMaxValue;
    // Ignore results near overflow
  until (LBits - Result + (AMaxValue - 1)) >= 0;

end;

function TSecureRandom.Next(AMinValue, AMaxValue: Int32): Int32;
var
  LDiff, LI: Int32;
begin
  if (AMaxValue <= AMinValue) then
  begin
    if (AMaxValue = AMinValue) then
    begin
      Result := AMinValue;
      Exit;
    end;

    raise EArgumentCryptoLibException.CreateRes(@SInvalidMaxValue);
  end;

  LDiff := AMaxValue - AMinValue;
  if (LDiff > 0) then
  begin
    Result := AMinValue + Next(LDiff);
    Exit;
  end;

  while True do
  begin
    LI := NextInt32();

    if ((LI >= AMinValue) and (LI < AMaxValue)) then
    begin
      Result := LI;
      Exit;
    end;
  end;
end;

function TSecureRandom.Next: Int32;
begin
  Result := NextInt32() and System.High(Int32);
end;

procedure TSecureRandom.NextBytes(const ABuf: TCryptoLibByteArray);
begin
  FGenerator.NextBytes(ABuf);
end;

procedure TSecureRandom.NextBytes(const ABuf: TCryptoLibByteArray; AOff, ALen: Int32);
begin
  FGenerator.NextBytes(ABuf, AOff, ALen);
end;

class function TSecureRandom.NextCounterValue: Int64;
begin
  FLock.Acquire;
  try
    System.Inc(FCounter);
    Result := FCounter;
  finally
    FLock.Release;
  end;
end;

function TSecureRandom.NextDouble: Double;
var
  LValue: UInt64;
begin
  LValue := UInt64(NextInt64()) shr 11;
  Result := LValue * FDoubleScale;
end;

function TSecureRandom.NextInt32: Int32;
var
  LBytes: TCryptoLibByteArray;
begin
  System.SetLength(LBytes, 4);
  NextBytes(LBytes);
  Result := Int32(TPack.BE_To_UInt32(LBytes));
end;

function TSecureRandom.NextInt64: Int64;
var
  LBytes: TCryptoLibByteArray;
begin
  System.SetLength(LBytes, 8);
  NextBytes(LBytes);
  Result := Int64(TPack.BE_To_UInt64(LBytes));
end;

class constructor TSecureRandom.Create;
begin
  FLock := TCriticalSection.Create;
  FCounter := TDateTimeUtilities.DateTimeToTicks(Now.ToUniversalTime());
  FMasterRandom := TSecureRandom.Create(TCryptoApiRandomGenerator.Create()
      as ICryptoApiRandomGenerator);
  FDoubleScale := 1.0 / (UInt64(1) shl 53);
end;

class destructor TSecureRandom.Destroy;
begin
  FLock.Free;
end;

procedure TSecureRandom.SetSeed(ASeed: Int64);
begin
  FGenerator.AddSeedMaterial(ASeed);
end;

procedure TSecureRandom.SetSeed(const ASeed: TCryptoLibByteArray);
begin
  FGenerator.AddSeedMaterial(ASeed);
end;

class procedure TSecureRandom.AutoSeed(const AGenerator: IRandomGenerator;
  ASeedLength: Int32);
var
  LSeed: TCryptoLibByteArray;
begin
  AGenerator.AddSeedMaterial(NextCounterValue());
  System.SetLength(LSeed, ASeedLength);
  TOSRandomProvider.Instance.GetBytes(LSeed);
  AGenerator.AddSeedMaterial(LSeed);
end;

class function TSecureRandom.CreatePrng(const ADigestName: String;
  AAutoSeed: Boolean): IDigestRandomGenerator;
var
  LDigest: IDigest;
  LPrng: IDigestRandomGenerator;
begin
  LDigest := TDigestUtilities.GetDigest(ADigestName);
  if (LDigest = nil) then
  begin
    Result := nil;
    Exit;
  end;

  LPrng := TDigestRandomGenerator.Create(LDigest);
  if (AAutoSeed) then
  begin
    AutoSeed(LPrng, 2 * LDigest.GetDigestSize);
  end;
  Result := LPrng;
end;

constructor TSecureRandom.Create;
begin
  Create(CreatePrng('SHA256', True));
end;

class function TSecureRandom.GetInstance(const AAlgorithm: String; AAutoSeed: Boolean): ISecureRandom;
var
  LDigestName: String;
  LPrng: IDigestRandomGenerator;
  LPrngSuffixLen: Int32;
begin
  if AAlgorithm = '' then
  begin
    raise EArgumentNilCryptoLibException.CreateRes(@SAlgorithmNil);
  end;

  LPrngSuffixLen := Length('PRNG');
  if TStringUtilities.EndsWith(AAlgorithm, 'PRNG', True) then
  begin
    LDigestName := Copy(AAlgorithm, 1, Length(AAlgorithm) - LPrngSuffixLen);

    LPrng := CreatePrng(LDigestName, AAutoSeed);
    if (LPrng <> nil) then
    begin
      Result := TSecureRandom.Create(LPrng);
      Exit;
    end;
  end;

  raise EArgumentCryptoLibException.CreateResFmt(@SUnrecognizedPRNGAlgorithm,
    [AAlgorithm]);
end;

class function TSecureRandom.GetInstance(const AAlgorithm: String) : ISecureRandom;
begin
  Result := GetInstance(AAlgorithm, True);
end;

function TSecureRandom.GenerateSeed(ALength: Int32): TCryptoLibByteArray;
begin
  System.SetLength(Result, ALength);
  TOSRandomProvider.Instance.GetBytes(Result);
end;

end.
