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

unit ClpAesRandomProvider;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SyncObjs,
  ClpAesEngine,
  ClpIAesEngine,
  ClpIBlockCipher,
  ClpIKeyParameter,
  ClpKeyParameter,
  ClpIBufferedCipher,
  ClpIBufferedBlockCipher,
  ClpBufferedBlockCipher,
  ClpArrayUtilities,
  ClpOSRandomProvider,
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
  TAesRandomProvider = class sealed(TInterfacedObject, IRandomSourceProvider)

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

    class procedure GetRawEntropy(const AEntropy: TCryptoLibByteArray); inline;

    class procedure Boot(); static;
    class constructor Create();
    class destructor Destroy();

    class procedure ValidateAesRngSeedLength(ASeedLength: Int32);

    constructor Create(const AAesRngSeed: TCryptoLibByteArray; AReseedAfterBytes: Int32); overload;

    procedure DoIncrementCounter();

    procedure DoSeed(const AAesRngSeed: TCryptoLibByteArray);

  public
    constructor Create(AAesRngSeedLength: Int32 = 32; AReseedAfterBytes: Int32 = 1024 * 1024); overload;

    destructor Destroy; override;

    function GetIsAvailable: Boolean;
    function GetName: String;

    procedure GetBytes(const AData: TCryptoLibByteArray);
    procedure GetNonZeroBytes(const AData: TCryptoLibByteArray);

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

class procedure TAesRandomProvider.ValidateAesRngSeedLength(ASeedLength: Int32);
begin
  if ((ASeedLength < 16) or (ASeedLength > 32) or ((ASeedLength and 7) <> 0))
  then
  begin
    raise EArgumentCryptoLibException.CreateRes(@SInvalidAesRngSeedLength);
  end;
end;

class procedure TAesRandomProvider.GetRawEntropy(const AEntropy
  : TCryptoLibByteArray);
begin
  TOSRandomProvider.Instance.GetBytes(AEntropy);
end;

class procedure TAesRandomProvider.Boot;
begin
  if FLock = nil then
  begin
    FLock := TCriticalSection.Create;
  end;
  // Trigger instance creation
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
  for LI := System.Low(FCounter) to System.High(FCounter) do
  begin
    System.Inc(FCounter[LI]);
    // Check whether we need to loop again to carry the one.
    if (FCounter[LI] <> 0) then
    begin
      break;
    end;
  end;
end;

procedure TAesRandomProvider.DoSeed(const AAesRngSeed: TCryptoLibByteArray);
var
  LKeyParameter: IKeyParameter;
begin
  LKeyParameter := TKeyParameter.Create(AAesRngSeed);
  FInternalLock.Acquire;
  try
    FCipher.Init(True, LKeyParameter);
    FBytesSinceSeed := 0;
  finally
    FInternalLock.Release;
  end;
end;

constructor TAesRandomProvider.Create(const AAesRngSeed: TCryptoLibByteArray; AReseedAfterBytes: Int32);
var
  LAesEngine: IAesEngine;
  LBlockCipher: IBlockCipher;
  LAesRngSeed: TCryptoLibByteArray;
begin
  inherited Create();
  LAesRngSeed := System.Copy(AAesRngSeed);
  FInternalLock := TCriticalSection.Create;
  // Set up engine
  LAesEngine := TAesEngine.Create();
  LBlockCipher := LAesEngine as IBlockCipher; // ECB no padding
  FCipher := TBufferedBlockCipher.Create(LBlockCipher) as IBufferedBlockCipher;
  System.SetLength(FCounter, CounterSize);
  FAesRngSeedLength := System.Length(LAesRngSeed);
  FReseedAfterBytes := AReseedAfterBytes;
  ValidateAesRngSeedLength(FAesRngSeedLength);
  try
    DoSeed(LAesRngSeed);
  finally
    TArrayUtilities.Fill<Byte>(LAesRngSeed, 0, System.Length(LAesRngSeed), Byte(0)); // clear key from memory
  end;
end;

constructor TAesRandomProvider.Create(AAesRngSeedLength, AReseedAfterBytes: Int32);
var
  LSeed: TCryptoLibByteArray;
begin
  System.SetLength(LSeed, AAesRngSeedLength);
  try
    GetRawEntropy(LSeed); // pure entropy from OS
    Create(LSeed, AReseedAfterBytes);
  finally
    TArrayUtilities.Fill<Byte>(LSeed, 0, System.Length(LSeed), Byte(0)); // clear seed from memory
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
begin
  LDataLength := System.Length(AData);
  if LDataLength <= 0 then
  begin
    Exit;
  end;

  if (FBytesSinceSeed > FReseedAfterBytes) then
  begin
    System.SetLength(LSeed, FAesRngSeedLength);
    try
      GetRawEntropy(LSeed); // pure entropy from OS
      DoSeed(LSeed);
    finally
      TArrayUtilities.Fill<Byte>(LSeed, 0, System.Length(LSeed), Byte(0)); // clear seed from memory
    end;
  end;

  LOffset := 0;

  FInternalLock.Acquire;
  try
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
      System.Move(LResult[0], AData[LOffset], LDataLength * System.SizeOf(Byte));
      System.Inc(FBytesSinceSeed, LDataLength);
    end;

  finally
    FInternalLock.Release;
  end;
end;

procedure TAesRandomProvider.GetNonZeroBytes(const AData: TCryptoLibByteArray);
var
  LI: Int32;
  LTmp: TCryptoLibByteArray;
begin
  GetBytes(AData);
  System.SetLength(LTmp, 1);
  for LI := System.Low(AData) to System.High(AData) do
  begin
    while AData[LI] = 0 do
    begin
      GetBytes(LTmp);
      AData[LI] := LTmp[0];
    end;
  end;
end;

function TAesRandomProvider.GetIsAvailable: Boolean;
begin
  Result := True; // AES PRNG is always available
end;

function TAesRandomProvider.GetName: String;
begin
  Result := 'AES';
end;

end.
