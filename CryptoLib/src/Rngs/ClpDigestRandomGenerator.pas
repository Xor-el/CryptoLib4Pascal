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

unit ClpDigestRandomGenerator;

{$I ..\Include\CryptoLib.inc}

interface

uses
  SyncObjs,
  ClpIDigest,
  ClpConverters,
  ClpCryptoLibTypes,
  ClpIDigestRandomGenerator,
  ClpIRandomGenerator;

type
  /// **
  // * Random generation based on the digest with counter. Calling AddSeedMaterial will
  // * always increase the entropy of the hash.
  // * <p>
  // * Internal access to the digest is synchronized so a single one of these can be shared.
  // * </p>
  // */
  TDigestRandomGenerator = class sealed(TInterfacedObject, IDigestRandomGenerator, IRandomGenerator)

  strict private
  const
    CycleCount = Int64(10);

  var
    FLock: TCriticalSection;
    FstateCounter, FseedCounter: Int64;
    Fdigest: IDigest;
    Fstate, Fseed: TCryptoLibByteArray;

    procedure CycleSeed(); inline;
    procedure GenerateState(); inline;
    procedure DigestAddCounter(ASeedVal: Int64); inline;
    procedure DigestUpdate(const AInSeed: TCryptoLibByteArray); inline;
    procedure DigestDoFinal(const AResult: TCryptoLibByteArray); inline;

  public

    constructor Create(const ADigest: IDigest);
    destructor Destroy; override;
    procedure AddSeedMaterial(const AInSeed: TCryptoLibByteArray);
      overload; inline;
    procedure AddSeedMaterial(ARSeed: Int64); overload; inline;
    procedure NextBytes(const ABytes: TCryptoLibByteArray); overload; inline;
    procedure NextBytes(const ABytes: TCryptoLibByteArray;
      AStart, ALen: Int32); overload;

  end;

implementation

{ TDigestRandomGenerator }

procedure TDigestRandomGenerator.DigestAddCounter(ASeedVal: Int64);
var
  LBytes: TCryptoLibByteArray;
begin
  System.SetLength(LBytes, 8);
  LBytes := TConverters.ReadUInt64AsBytesLE(UInt64(ASeedVal));
  FDigest.BlockUpdate(LBytes, 0, System.Length(LBytes));
end;

procedure TDigestRandomGenerator.DigestUpdate(const AInSeed
  : TCryptoLibByteArray);
begin
  FDigest.BlockUpdate(AInSeed, 0, System.Length(AInSeed));
end;

procedure TDigestRandomGenerator.DigestDoFinal(const AResult
  : TCryptoLibByteArray);
begin
  FDigest.DoFinal(AResult, 0);
end;

procedure TDigestRandomGenerator.AddSeedMaterial(ARSeed: Int64);
begin
  FLock.Acquire;
  try
    DigestAddCounter(ARSeed);
    DigestUpdate(FSeed);
    DigestDoFinal(FSeed);
  finally
    FLock.Release;
  end;
end;

procedure TDigestRandomGenerator.AddSeedMaterial(const AInSeed
  : TCryptoLibByteArray);
begin
  FLock.Acquire;
  try
    DigestUpdate(AInSeed);
    DigestUpdate(FSeed);
    DigestDoFinal(FSeed);
  finally
    FLock.Release;
  end;
end;

constructor TDigestRandomGenerator.Create(const ADigest: IDigest);
begin
  inherited Create();
  FLock := TCriticalSection.Create;
  FDigest := ADigest;
  System.SetLength(FSeed, ADigest.GetDigestSize);
  FSeedCounter := 1;
  System.SetLength(FState, ADigest.GetDigestSize);
  FStateCounter := 1;
end;

procedure TDigestRandomGenerator.CycleSeed;
begin
  DigestUpdate(FSeed);
  DigestAddCounter(FSeedCounter);
  System.Inc(FSeedCounter);
  DigestDoFinal(FSeed);
end;

destructor TDigestRandomGenerator.Destroy;
begin
  FLock.Free;
  inherited Destroy;
end;

procedure TDigestRandomGenerator.GenerateState;
begin
  DigestAddCounter(FStateCounter);
  System.Inc(FStateCounter);
  DigestUpdate(FState);
  DigestUpdate(FSeed);
  DigestDoFinal(FState);

  if ((FStateCounter mod CycleCount) = 0) then
  begin
    CycleSeed();
  end;
end;

procedure TDigestRandomGenerator.NextBytes(const ABytes: TCryptoLibByteArray);
begin
  NextBytes(ABytes, 0, System.Length(ABytes));
end;

procedure TDigestRandomGenerator.NextBytes(const ABytes: TCryptoLibByteArray;
  AStart, ALen: Int32);
var
  LStateOff, LEndPoint: Int32;
  LI: Int32;
begin
  FLock.Acquire;
  try
    LStateOff := 0;
    GenerateState();
    LEndPoint := AStart + ALen;

    for LI := AStart to System.Pred(LEndPoint) do
    begin
      if (LStateOff = System.Length(FState)) then
      begin
        GenerateState();
        LStateOff := 0;
      end;
      ABytes[LI] := FState[LStateOff];
      System.Inc(LStateOff);
    end;

  finally
    FLock.Release;
  end;
end;

end.
