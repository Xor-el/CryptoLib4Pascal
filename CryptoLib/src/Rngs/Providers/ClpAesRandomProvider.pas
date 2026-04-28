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

unit ClpAesRandomProvider;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SyncObjs,
  ClpAesUtilities,
  ClpIBlockCipher,
  ClpIKeyParameter,
  ClpKeyParameter,
  ClpIBufferedCipher,
  ClpBufferedBlockCipher,
  ClpArrayUtilities,
  ClpOSRandomProvider,
  ClpBaseRandomProvider,
  ClpIRandomSourceProvider,
  ClpCryptoLibTypes;

resourcestring
  SInvalidAesRngSeedLength =
    'AES RNG Seed Length must be either one of these "128/192/256 bits".';

type
  /// <summary>
  /// AES-based random source provider.
  /// Implements counter-based AES PRNG with automatic reseeding.
  /// </summary>
  TAesRandomProvider = class sealed(TBaseRandomProvider)

  strict private
  const
    CounterSize = Int32(16);
  class var
    FInstance: IRandomSourceProvider;
    FLock: TCriticalSection;

  var
    FInternalLock: TCriticalSection;
    FCounter: TCryptoLibByteArray;
    FAesRngSeedLength, FBytesSinceSeed, FReseedAfterBytes: Int32;
    FCipher: IBufferedCipher;

    class function GetInstance: IRandomSourceProvider; static;
    class function CreateProvider: IRandomSourceProvider; static;

    class function OsProviderAvailable: Boolean; static;
    class procedure GetRawEntropy(const AEntropy: TCryptoLibByteArray); inline;

    class procedure Boot(); static;
    class constructor Create();
    class destructor Destroy();

    class procedure ValidateAesRngSeedLength(ASeedLength: Int32);

    constructor Create(const AAesRngSeed: TCryptoLibByteArray;
      AReseedAfterBytes: Int32); overload;

    procedure DoIncrementCounter();

    /// <summary>
    /// Re-key the cipher with state blending for forward security.
    /// Encrypts the current counter under the existing key to produce a
    /// 16-byte mix block, XORs that into the leading bytes of AAesRngSeed,
    /// and installs the result as the new key. An attacker who learns the
    /// new seed cannot reconstruct prior output without the previous key.
    /// For 192/256-bit keys only the first 16 bytes are mixed; the remainder
    /// comes directly from AAesRngSeed (fresh OS entropy).
    /// Must be called with FInternalLock already held by the caller.
    /// </summary>
    procedure DoSeedLocked(const AAesRngSeed: TCryptoLibByteArray);

  public
    constructor Create(AAesRngSeedLength: Int32 = 32;
      AReseedAfterBytes: Int32 = 1024 * 1024); overload;

    destructor Destroy; override;

    function GetIsAvailable: Boolean; override;
    function GetName: String; override;

    procedure GetBytes(const AData: TCryptoLibByteArray); override;

    class property Instance: IRandomSourceProvider read GetInstance;

  end;

implementation

{ TAesRandomProvider }

class function TAesRandomProvider.GetInstance: IRandomSourceProvider;
begin
  if FInstance = nil then
  begin
    FLock.Enter;
    try
      if FInstance = nil then
      begin
        FInstance := CreateProvider();
      end;
    finally
      FLock.Leave;
    end;
  end;
  Result := FInstance;
end;

class function TAesRandomProvider.CreateProvider: IRandomSourceProvider;
begin
  Result := TAesRandomProvider.Create();
end;

class function TAesRandomProvider.OsProviderAvailable: Boolean;
begin
  try
    Result := TOSRandomProvider.Instance.GetIsAvailable;
  except
    Result := False;
  end;
end;

class procedure TAesRandomProvider.ValidateAesRngSeedLength(ASeedLength: Int32);
begin
  if ((ASeedLength < 16) or (ASeedLength > 32) or ((ASeedLength and 7) <> 0))
  then
  begin
    raise EArgumentCryptoLibException.CreateRes(@SInvalidAesRngSeedLength);
  end;
end;

class procedure TAesRandomProvider.GetRawEntropy(
  const AEntropy: TCryptoLibByteArray);
begin
  TOSRandomProvider.Instance.GetBytes(AEntropy);
end;

class procedure TAesRandomProvider.Boot;
begin
  if FLock = nil then
  begin
    FLock := TCriticalSection.Create;
  end;
  GetInstance;
end;

class constructor TAesRandomProvider.Create();
begin
  Boot();
end;

class destructor TAesRandomProvider.Destroy();
begin
  FLock.Free;
  FInstance := nil;
end;

procedure TAesRandomProvider.DoIncrementCounter;
var
  LI: Int32;
begin
  // Big-endian increment: byte 15 (rightmost) carries leftward.
  for LI := System.High(FCounter) downto System.Low(FCounter) do
  begin
    System.Inc(FCounter[LI]);
    if (FCounter[LI] <> 0) then
      Break;
  end;
end;

procedure TAesRandomProvider.DoSeedLocked(
  const AAesRngSeed: TCryptoLibByteArray);
var
  LMix, LNewKey: TCryptoLibByteArray;
  LKeyLen, LMixLen, LI: Int32;
begin
  LMix := FCipher.DoFinal(FCounter);
  try
    LKeyLen := System.Length(AAesRngSeed);
    System.SetLength(LNewKey, LKeyLen);
    System.Move(AAesRngSeed[0], LNewKey[0], LKeyLen * System.SizeOf(Byte));

    // XOR mix into the leading min(16, LKeyLen) bytes of the new key.
    LMixLen := LKeyLen;
    if LMixLen > CounterSize then
      LMixLen := CounterSize;
    for LI := 0 to LMixLen - 1 do
      LNewKey[LI] := LNewKey[LI] xor LMix[LI];

    FCipher.Init(True, TKeyParameter.Create(LNewKey) as IKeyParameter);
    FBytesSinceSeed := 0;
  finally
    TArrayUtilities.Fill<Byte>(LMix, 0, System.Length(LMix), Byte(0));
    TArrayUtilities.Fill<Byte>(LNewKey, 0, System.Length(LNewKey), Byte(0));
  end;
end;

constructor TAesRandomProvider.Create(const AAesRngSeed: TCryptoLibByteArray;
  AReseedAfterBytes: Int32);
var
  LAesRngSeed: TCryptoLibByteArray;
begin
  inherited Create();
  LAesRngSeed := System.Copy(AAesRngSeed);
  FInternalLock := TCriticalSection.Create;

  FCipher := TBufferedBlockCipher.Create(TAesUtilities.CreateEngine());
  FAesRngSeedLength := System.Length(LAesRngSeed);
  FReseedAfterBytes := AReseedAfterBytes;
  ValidateAesRngSeedLength(FAesRngSeedLength);

  // Randomise the initial counter so two instances seeded at the same
  // instant still diverge immediately.
  System.SetLength(FCounter, CounterSize);
  GetRawEntropy(FCounter);

  // Direct Init on first seed - no prior state to mix.
  FCipher.Init(True, TKeyParameter.Create(LAesRngSeed) as IKeyParameter);
  FBytesSinceSeed := 0;

  TArrayUtilities.Fill<Byte>(LAesRngSeed, 0, System.Length(LAesRngSeed), Byte(0));
end;

constructor TAesRandomProvider.Create(AAesRngSeedLength,
  AReseedAfterBytes: Int32);
var
  LSeed: TCryptoLibByteArray;
begin
  System.SetLength(LSeed, AAesRngSeedLength);
  try
    GetRawEntropy(LSeed); // pure entropy from OS
    Create(LSeed, AReseedAfterBytes);
  finally
    TArrayUtilities.Fill<Byte>(LSeed, 0, System.Length(LSeed), Byte(0));
  end;
end;

destructor TAesRandomProvider.Destroy;
begin
  FInternalLock.Free;
  inherited Destroy;
end;

procedure TAesRandomProvider.GetBytes(const AData: TCryptoLibByteArray);
var
  LDataLength, LOffset, LResultLength: Int32;
  LSeed, LResult: TCryptoLibByteArray;
  LNeedReseed: Boolean;
begin
  LDataLength := System.Length(AData);
  if LDataLength <= 0 then
    Exit;

  FInternalLock.Acquire;
  try
    // Reseed check is inside the lock so the check-then-reseed-then-generate
    // sequence is atomic across threads.
    LNeedReseed := (FBytesSinceSeed > FReseedAfterBytes);
    if LNeedReseed then
    begin
      System.SetLength(LSeed, FAesRngSeedLength);
      try
        GetRawEntropy(LSeed);
        DoSeedLocked(LSeed);
      finally
        TArrayUtilities.Fill<Byte>(LSeed, 0, System.Length(LSeed), Byte(0));
      end;
    end;

    LOffset := 0;

    while (LDataLength shr 4) > 0 do
    begin
      DoIncrementCounter;
      LResultLength := FCipher.DoFinal(FCounter, AData, LOffset);

      System.Inc(LOffset, LResultLength);
      System.Inc(FBytesSinceSeed, LResultLength);
      System.Dec(LDataLength, LResultLength);
    end;

    if LDataLength > 0 then
    begin
      DoIncrementCounter;
      LResult := FCipher.DoFinal(FCounter);
      try
        System.Move(LResult[0], AData[LOffset],
          LDataLength * System.SizeOf(Byte));
        System.Inc(FBytesSinceSeed, LDataLength);
        // Zero the bytes we did NOT consume so they cannot be read from the
        // heap after LResult is released.
        TArrayUtilities.Fill<Byte>(LResult, LDataLength,
          System.Length(LResult) - LDataLength, Byte(0));
      finally
        TArrayUtilities.Fill<Byte>(LResult, 0,
          System.Length(LResult), Byte(0));
      end;
    end;

  finally
    FInternalLock.Release;
  end;
end;

function TAesRandomProvider.GetIsAvailable: Boolean;
begin
  Result := OsProviderAvailable;
end;

function TAesRandomProvider.GetName: String;
begin
  Result := 'AES';
end;

end.
