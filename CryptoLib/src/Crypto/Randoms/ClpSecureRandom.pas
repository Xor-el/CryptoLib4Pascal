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

unit ClpSecureRandom;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  Math,
  SyncObjs,
  SysUtils,
  DateUtils,
  ClpBitUtilities,
  ClpCryptoLibTypes,
  ClpDateTimeUtilities,
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
  ClpPlatformUtilities;

resourcestring
  SUnRecognisedPRNGAlgorithm = 'Unrecognised PRNG Algorithm: %s "algorithm"';
  SCannotBeNegative = 'Cannot be Negative  "maxValue"';
  SInvalidMaxValue = 'maxValue Cannot be Less Than minValue';

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

    class procedure Boot(); static;

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
      raise EArgumentOutOfRangeCryptoLibException.CreateRes(@SCannotBeNegative);
    end;

    Result := 0;
    Exit;
  end;

  // Test whether AMaxValue is a power of 2
  if ((AMaxValue and (AMaxValue - 1)) = 0) then
  begin
    LBits := NextInt32() and System.High(Int32);
    Result := Int32(TBitUtilities.Asr64((Int64(LBits) * AMaxValue), 31));
    Exit;
  end;

  repeat
    LBits := NextInt32() and System.High(Int32);
    Result := LBits mod AMaxValue;
    // Ignore results near overflow
  until (not((LBits - (Result + (AMaxValue - 1))) < 0));

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

  Result := 0; // to make FixInsight Happy :)

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
  // TODO when we upgrade to FPC 3.2.0 enable and remove locks above
  // {$IFDEF FPC}
  // Result := InterLockedIncrement64(FCounter);
  // {$ELSE}
  // Result := TInterlocked.Increment(FCounter);
  // {$ENDIF}
end;

function TSecureRandom.NextDouble: Double;
begin
  Result := UInt64(NextInt64()) / FDoubleScale;
end;

function TSecureRandom.NextInt32: Int32;
var
  LTempRes: UInt32;
  LBytes: TCryptoLibByteArray;
begin
  System.SetLength(LBytes, 4);
  NextBytes(LBytes);

  LTempRes := LBytes[0];
  LTempRes := LTempRes shl 8;
  LTempRes := LTempRes or LBytes[1];
  LTempRes := LTempRes shl 8;
  LTempRes := LTempRes or LBytes[2];
  LTempRes := LTempRes shl 8;
  LTempRes := LTempRes or LBytes[3];
  Result := Int32(LTempRes);
end;

function TSecureRandom.NextInt64: Int64;
begin
  Result := (Int64(UInt32(NextInt32())) shl 32) or (Int64(UInt32(NextInt32())));
end;

class constructor TSecureRandom.Create;
begin
  TSecureRandom.Boot;
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

class function TSecureRandom.CreatePrng(const ADigestName: String;
  AAutoSeed: Boolean): IDigestRandomGenerator;
var
  LDigest: IDigest;
  LPrng: IDigestRandomGenerator;
  LSeedLength: Int32;
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
    LSeedLength := 2 * LDigest.GetDigestSize;
    LPrng.AddSeedMaterial(NextCounterValue());
    LPrng.AddSeedMaterial(GetNextBytes(MasterRandom, LSeedLength));
  end;
  Result := LPrng;
end;

class procedure TSecureRandom.Boot;
begin
  if FLock = nil then
  begin
    FLock := TCriticalSection.Create;
    FCounter := TDateTimeUtilities.DateTimeToTicks(TTimeZone.Local.ToUniversalTime(Now));
    FMasterRandom := TSecureRandom.Create(TCryptoApiRandomGenerator.Create()
      as ICryptoApiRandomGenerator);
    FDoubleScale := Power(2.0, 64.0);
    TOSRandomProvider.Boot;
  end;
end;

constructor TSecureRandom.Create;
begin
  Create(CreatePrng('SHA256', True));
end;

class function TSecureRandom.GetInstance(const AAlgorithm: String; AAutoSeed: Boolean): ISecureRandom;
var
  LUpper, LDigestName: String;
  LPrng: IDigestRandomGenerator;
  LPrngIndex: Int32;
begin
  LUpper := TStringUtilities.ToUpperInvariant(AAlgorithm);

  if TStringUtilities.EndsWith(LUpper, 'PRNG', True) then
  begin
    LPrngIndex := TStringUtilities.LastIndexOf(LUpper, 'PRNG');
    if LPrngIndex > 0 then
    begin
      LDigestName := TStringUtilities.Substring(LUpper, 1, LPrngIndex - 1);
    end
    else
    begin
      LDigestName := '';
    end;

    LPrng := CreatePrng(LDigestName, AAutoSeed);
    if (LPrng <> nil) then
    begin
      Result := TSecureRandom.Create(LPrng);
      Exit;
    end;
  end;

  raise EArgumentCryptoLibException.CreateResFmt(@SUnRecognisedPRNGAlgorithm,
    [AAlgorithm]);

end;

class function TSecureRandom.GetInstance(const AAlgorithm: String) : ISecureRandom;
begin
  Result := GetInstance(AAlgorithm, True);
end;

function TSecureRandom.GenerateSeed(ALength: Int32): TCryptoLibByteArray;
begin
  Result := GetNextBytes(MasterRandom, ALength);
end;

end.
