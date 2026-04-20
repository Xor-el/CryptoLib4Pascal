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

unit ClpFusedKernelRegistry;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  SyncObjs,
  Generics.Collections,
  ClpIBlockCipher,
  ClpCryptoLibTypes,
  ClpFusedModeDirection,
  ClpIFusedGcmKernel,
  ClpIFusedOcbKernel,
  ClpIFusedCcmKernel,
  ClpIFusedEaxKernel,
  ClpIFusedGcmSivKernel;

type
  /// <summary>
  ///   Process-wide kill switch for every fused AEAD kernel registered
  ///   with the registry. When ForceDisabled is True, every TryAcquireX
  ///   returns False without walking the factory list, so modes route
  ///   through their scalar fallbacks. Used by the dual-mode test
  ///   harness to prove both paths agree byte-for-byte.
  /// </summary>
  TFusedKernelGate = class sealed(TObject)
  strict private
    class var FForceDisabled: Boolean;
  public
    class property ForceDisabled: Boolean read FForceDisabled write FForceDisabled;
  end;

  /// <summary>
  ///   Open factory-based resolver for the fused AEAD kernel family
  ///   (GCM, OCB, CCM, EAX, GCM-SIV). Accelerator units register an
  ///   IFused&lt;Mode&gt;KernelFactory in their initialization block;
  ///   modes resolve a kernel via TryAcquire&lt;Mode&gt; at Init time.
  ///   Factories are kept sorted by TFusedKernelPriority descending so
  ///   higher-priority accelerators win. TryCreate failures are
  ///   expected and the registry walks to the next factory.
  ///   Lookups are thread-safe: a single TCriticalSection guards
  ///   insertion / removal / snapshot; TryAcquireX takes a snapshot
  ///   under the lock then releases it before invoking factory
  ///   TryCreate, so factory work never serialises other call sites.
  /// </summary>
  TFusedKernelRegistry = class sealed(TObject)
  strict private
    class var FLock: TCriticalSection;
    class var FGcmFactories: TList<IFusedGcmKernelFactory>;
    class var FOcbFactories: TList<IFusedOcbKernelFactory>;
    class var FCcmFactories: TList<IFusedCcmKernelFactory>;
    class var FEaxFactories: TList<IFusedEaxKernelFactory>;
    class var FGcmSivFactories: TList<IFusedGcmSivKernelFactory>;

    class function SnapshotGcmFactories: TCryptoLibGenericArray<IFusedGcmKernelFactory>; static;
    class function SnapshotOcbFactories: TCryptoLibGenericArray<IFusedOcbKernelFactory>; static;
    class function SnapshotCcmFactories: TCryptoLibGenericArray<IFusedCcmKernelFactory>; static;
    class function SnapshotEaxFactories: TCryptoLibGenericArray<IFusedEaxKernelFactory>; static;
    class function SnapshotGcmSivFactories: TCryptoLibGenericArray<IFusedGcmSivKernelFactory>; static;

    class constructor Create;
    class destructor Destroy;
  public
    /// <summary>Register a factory. Insertion keeps the list sorted by
    /// Ord(Priority) descending; equal priorities retain registration
    /// order. Duplicate registrations (same interface identity) are
    /// silently ignored.</summary>
    class procedure RegisterGcmFactory(const AFactory: IFusedGcmKernelFactory); static;
    class procedure RegisterOcbFactory(const AFactory: IFusedOcbKernelFactory); static;
    class procedure RegisterCcmFactory(const AFactory: IFusedCcmKernelFactory); static;
    class procedure RegisterEaxFactory(const AFactory: IFusedEaxKernelFactory); static;
    class procedure RegisterGcmSivFactory(const AFactory: IFusedGcmSivKernelFactory); static;

    /// <summary>Remove AFactory. No-op if not registered.</summary>
    class procedure UnregisterGcmFactory(const AFactory: IFusedGcmKernelFactory); static;
    class procedure UnregisterOcbFactory(const AFactory: IFusedOcbKernelFactory); static;
    class procedure UnregisterCcmFactory(const AFactory: IFusedCcmKernelFactory); static;
    class procedure UnregisterEaxFactory(const AFactory: IFusedEaxKernelFactory); static;
    class procedure UnregisterGcmSivFactory(const AFactory: IFusedGcmSivKernelFactory); static;

    /// <summary>Walk the factory list (highest priority first) and
    /// return the first kernel whose TryCreate succeeds. Returns False
    /// with AKernel = nil when the gate is ForceDisabled, when no
    /// factory is registered, or when every TryCreate returns False.
    /// Never raises.</summary>
    class function TryAcquireGcm(const ACipher: IBlockCipher;
      ADirection: TFusedModeDirection;
      AHPowers: Pointer;
      out AKernel: IFusedGcmKernel): Boolean; static;
    class function TryAcquireOcb(const ACipher: IBlockCipher;
      ADirection: TFusedModeDirection;
      out AKernel: IFusedOcbKernel): Boolean; static;
    class function TryAcquireCcm(const ACipher: IBlockCipher;
      ADirection: TFusedModeDirection;
      out AKernel: IFusedCcmKernel): Boolean; static;
    class function TryAcquireEax(const ACipher: IBlockCipher;
      ADirection: TFusedModeDirection;
      out AKernel: IFusedEaxKernel): Boolean; static;
    /// <summary>GCM-SIV variant: AHPowers is forwarded to the factory
    /// and captured by reference by the returned kernel; it MUST
    /// outlive the kernel.</summary>
    class function TryAcquireGcmSiv(const ACipher: IBlockCipher;
      ADirection: TFusedModeDirection;
      AHPowers: Pointer;
      out AKernel: IFusedGcmSivKernel): Boolean; static;

    /// <summary>Snapshot of ProviderName strings in current priority
    /// order. Used for diagnostics and test assertions.</summary>
    class function GetRegisteredGcmProviders: TCryptoLibStringArray; static;
    class function GetRegisteredOcbProviders: TCryptoLibStringArray; static;
    class function GetRegisteredCcmProviders: TCryptoLibStringArray; static;
    class function GetRegisteredEaxProviders: TCryptoLibStringArray; static;
    class function GetRegisteredGcmSivProviders: TCryptoLibStringArray; static;
  end;

implementation

{ TFusedKernelRegistry }

class constructor TFusedKernelRegistry.Create;
begin
  FLock := TCriticalSection.Create;
  FGcmFactories := TList<IFusedGcmKernelFactory>.Create;
  FOcbFactories := TList<IFusedOcbKernelFactory>.Create;
  FCcmFactories := TList<IFusedCcmKernelFactory>.Create;
  FEaxFactories := TList<IFusedEaxKernelFactory>.Create;
  FGcmSivFactories := TList<IFusedGcmSivKernelFactory>.Create;
end;

class destructor TFusedKernelRegistry.Destroy;
begin
  FGcmSivFactories.Free;
  FEaxFactories.Free;
  FCcmFactories.Free;
  FOcbFactories.Free;
  FGcmFactories.Free;
  FLock.Free;
end;

{ ---- Register --------------------------------------------------------------- }

class procedure TFusedKernelRegistry.RegisterGcmFactory(
  const AFactory: IFusedGcmKernelFactory);
var
  LI: Int32;
  LInserted: Boolean;
  LPriority: Int32;
begin
  if AFactory = nil then Exit;
  FLock.Enter;
  try
    if FGcmFactories.IndexOf(AFactory) >= 0 then Exit;
    LPriority := Ord(AFactory.Priority);
    LInserted := False;
    for LI := 0 to FGcmFactories.Count - 1 do
    begin
      if LPriority > Ord(FGcmFactories[LI].Priority) then
      begin
        FGcmFactories.Insert(LI, AFactory);
        LInserted := True;
        Break;
      end;
    end;
    if not LInserted then
      FGcmFactories.Add(AFactory);
  finally
    FLock.Leave;
  end;
end;

class procedure TFusedKernelRegistry.RegisterOcbFactory(
  const AFactory: IFusedOcbKernelFactory);
var
  LI: Int32;
  LInserted: Boolean;
  LPriority: Int32;
begin
  if AFactory = nil then Exit;
  FLock.Enter;
  try
    if FOcbFactories.IndexOf(AFactory) >= 0 then Exit;
    LPriority := Ord(AFactory.Priority);
    LInserted := False;
    for LI := 0 to FOcbFactories.Count - 1 do
    begin
      if LPriority > Ord(FOcbFactories[LI].Priority) then
      begin
        FOcbFactories.Insert(LI, AFactory);
        LInserted := True;
        Break;
      end;
    end;
    if not LInserted then
      FOcbFactories.Add(AFactory);
  finally
    FLock.Leave;
  end;
end;

class procedure TFusedKernelRegistry.RegisterCcmFactory(
  const AFactory: IFusedCcmKernelFactory);
var
  LI: Int32;
  LInserted: Boolean;
  LPriority: Int32;
begin
  if AFactory = nil then Exit;
  FLock.Enter;
  try
    if FCcmFactories.IndexOf(AFactory) >= 0 then Exit;
    LPriority := Ord(AFactory.Priority);
    LInserted := False;
    for LI := 0 to FCcmFactories.Count - 1 do
    begin
      if LPriority > Ord(FCcmFactories[LI].Priority) then
      begin
        FCcmFactories.Insert(LI, AFactory);
        LInserted := True;
        Break;
      end;
    end;
    if not LInserted then
      FCcmFactories.Add(AFactory);
  finally
    FLock.Leave;
  end;
end;

class procedure TFusedKernelRegistry.RegisterEaxFactory(
  const AFactory: IFusedEaxKernelFactory);
var
  LI: Int32;
  LInserted: Boolean;
  LPriority: Int32;
begin
  if AFactory = nil then Exit;
  FLock.Enter;
  try
    if FEaxFactories.IndexOf(AFactory) >= 0 then Exit;
    LPriority := Ord(AFactory.Priority);
    LInserted := False;
    for LI := 0 to FEaxFactories.Count - 1 do
    begin
      if LPriority > Ord(FEaxFactories[LI].Priority) then
      begin
        FEaxFactories.Insert(LI, AFactory);
        LInserted := True;
        Break;
      end;
    end;
    if not LInserted then
      FEaxFactories.Add(AFactory);
  finally
    FLock.Leave;
  end;
end;

class procedure TFusedKernelRegistry.RegisterGcmSivFactory(
  const AFactory: IFusedGcmSivKernelFactory);
var
  LI: Int32;
  LInserted: Boolean;
  LPriority: Int32;
begin
  if AFactory = nil then Exit;
  FLock.Enter;
  try
    if FGcmSivFactories.IndexOf(AFactory) >= 0 then Exit;
    LPriority := Ord(AFactory.Priority);
    LInserted := False;
    for LI := 0 to FGcmSivFactories.Count - 1 do
    begin
      if LPriority > Ord(FGcmSivFactories[LI].Priority) then
      begin
        FGcmSivFactories.Insert(LI, AFactory);
        LInserted := True;
        Break;
      end;
    end;
    if not LInserted then
      FGcmSivFactories.Add(AFactory);
  finally
    FLock.Leave;
  end;
end;

{ ---- Unregister ------------------------------------------------------------- }

class procedure TFusedKernelRegistry.UnregisterGcmFactory(
  const AFactory: IFusedGcmKernelFactory);
var
  LIdx: Int32;
begin
  if AFactory = nil then Exit;
  FLock.Enter;
  try
    LIdx := FGcmFactories.IndexOf(AFactory);
    if LIdx >= 0 then
      FGcmFactories.Delete(LIdx);
  finally
    FLock.Leave;
  end;
end;

class procedure TFusedKernelRegistry.UnregisterOcbFactory(
  const AFactory: IFusedOcbKernelFactory);
var
  LIdx: Int32;
begin
  if AFactory = nil then Exit;
  FLock.Enter;
  try
    LIdx := FOcbFactories.IndexOf(AFactory);
    if LIdx >= 0 then
      FOcbFactories.Delete(LIdx);
  finally
    FLock.Leave;
  end;
end;

class procedure TFusedKernelRegistry.UnregisterCcmFactory(
  const AFactory: IFusedCcmKernelFactory);
var
  LIdx: Int32;
begin
  if AFactory = nil then Exit;
  FLock.Enter;
  try
    LIdx := FCcmFactories.IndexOf(AFactory);
    if LIdx >= 0 then
      FCcmFactories.Delete(LIdx);
  finally
    FLock.Leave;
  end;
end;

class procedure TFusedKernelRegistry.UnregisterEaxFactory(
  const AFactory: IFusedEaxKernelFactory);
var
  LIdx: Int32;
begin
  if AFactory = nil then Exit;
  FLock.Enter;
  try
    LIdx := FEaxFactories.IndexOf(AFactory);
    if LIdx >= 0 then
      FEaxFactories.Delete(LIdx);
  finally
    FLock.Leave;
  end;
end;

class procedure TFusedKernelRegistry.UnregisterGcmSivFactory(
  const AFactory: IFusedGcmSivKernelFactory);
var
  LIdx: Int32;
begin
  if AFactory = nil then Exit;
  FLock.Enter;
  try
    LIdx := FGcmSivFactories.IndexOf(AFactory);
    if LIdx >= 0 then
      FGcmSivFactories.Delete(LIdx);
  finally
    FLock.Leave;
  end;
end;

{ ---- Snapshots -------------------------------------------------------------- }

class function TFusedKernelRegistry.SnapshotGcmFactories: TCryptoLibGenericArray<IFusedGcmKernelFactory>;
var
  LI, LCount: Int32;
begin
  FLock.Enter;
  try
    LCount := FGcmFactories.Count;
    System.SetLength(Result, LCount);
    for LI := 0 to LCount - 1 do
      Result[LI] := FGcmFactories[LI];
  finally
    FLock.Leave;
  end;
end;

class function TFusedKernelRegistry.SnapshotOcbFactories: TCryptoLibGenericArray<IFusedOcbKernelFactory>;
var
  LI, LCount: Int32;
begin
  FLock.Enter;
  try
    LCount := FOcbFactories.Count;
    System.SetLength(Result, LCount);
    for LI := 0 to LCount - 1 do
      Result[LI] := FOcbFactories[LI];
  finally
    FLock.Leave;
  end;
end;

class function TFusedKernelRegistry.SnapshotCcmFactories: TCryptoLibGenericArray<IFusedCcmKernelFactory>;
var
  LI, LCount: Int32;
begin
  FLock.Enter;
  try
    LCount := FCcmFactories.Count;
    System.SetLength(Result, LCount);
    for LI := 0 to LCount - 1 do
      Result[LI] := FCcmFactories[LI];
  finally
    FLock.Leave;
  end;
end;

class function TFusedKernelRegistry.SnapshotEaxFactories: TCryptoLibGenericArray<IFusedEaxKernelFactory>;
var
  LI, LCount: Int32;
begin
  FLock.Enter;
  try
    LCount := FEaxFactories.Count;
    System.SetLength(Result, LCount);
    for LI := 0 to LCount - 1 do
      Result[LI] := FEaxFactories[LI];
  finally
    FLock.Leave;
  end;
end;

class function TFusedKernelRegistry.SnapshotGcmSivFactories: TCryptoLibGenericArray<IFusedGcmSivKernelFactory>;
var
  LI, LCount: Int32;
begin
  FLock.Enter;
  try
    LCount := FGcmSivFactories.Count;
    System.SetLength(Result, LCount);
    for LI := 0 to LCount - 1 do
      Result[LI] := FGcmSivFactories[LI];
  finally
    FLock.Leave;
  end;
end;

{ ---- TryAcquire ------------------------------------------------------------- }

class function TFusedKernelRegistry.TryAcquireGcm(const ACipher: IBlockCipher;
  ADirection: TFusedModeDirection; AHPowers: Pointer;
  out AKernel: IFusedGcmKernel): Boolean;
var
  LSnapshot: TCryptoLibGenericArray<IFusedGcmKernelFactory>;
  LI: Int32;
begin
  AKernel := nil;
  Result := False;
  if TFusedKernelGate.ForceDisabled then Exit;
  if ACipher = nil then Exit;
  if AHPowers = nil then Exit;
  LSnapshot := SnapshotGcmFactories;
  for LI := 0 to System.Length(LSnapshot) - 1 do
  begin
    if LSnapshot[LI].TryCreate(ACipher, ADirection, AHPowers, AKernel) and (AKernel <> nil) then
    begin
      Result := True;
      Exit;
    end;
  end;
  AKernel := nil;
end;

class function TFusedKernelRegistry.TryAcquireOcb(const ACipher: IBlockCipher;
  ADirection: TFusedModeDirection; out AKernel: IFusedOcbKernel): Boolean;
var
  LSnapshot: TCryptoLibGenericArray<IFusedOcbKernelFactory>;
  LI: Int32;
begin
  AKernel := nil;
  Result := False;
  if TFusedKernelGate.ForceDisabled then Exit;
  if ACipher = nil then Exit;
  LSnapshot := SnapshotOcbFactories;
  for LI := 0 to System.Length(LSnapshot) - 1 do
  begin
    if LSnapshot[LI].TryCreate(ACipher, ADirection, AKernel) and (AKernel <> nil) then
    begin
      Result := True;
      Exit;
    end;
  end;
  AKernel := nil;
end;

class function TFusedKernelRegistry.TryAcquireCcm(const ACipher: IBlockCipher;
  ADirection: TFusedModeDirection; out AKernel: IFusedCcmKernel): Boolean;
var
  LSnapshot: TCryptoLibGenericArray<IFusedCcmKernelFactory>;
  LI: Int32;
begin
  AKernel := nil;
  Result := False;
  if TFusedKernelGate.ForceDisabled then Exit;
  if ACipher = nil then Exit;
  LSnapshot := SnapshotCcmFactories;
  for LI := 0 to System.Length(LSnapshot) - 1 do
  begin
    if LSnapshot[LI].TryCreate(ACipher, ADirection, AKernel) and (AKernel <> nil) then
    begin
      Result := True;
      Exit;
    end;
  end;
  AKernel := nil;
end;

class function TFusedKernelRegistry.TryAcquireEax(const ACipher: IBlockCipher;
  ADirection: TFusedModeDirection; out AKernel: IFusedEaxKernel): Boolean;
var
  LSnapshot: TCryptoLibGenericArray<IFusedEaxKernelFactory>;
  LI: Int32;
begin
  AKernel := nil;
  Result := False;
  if TFusedKernelGate.ForceDisabled then Exit;
  if ACipher = nil then Exit;
  LSnapshot := SnapshotEaxFactories;
  for LI := 0 to System.Length(LSnapshot) - 1 do
  begin
    if LSnapshot[LI].TryCreate(ACipher, ADirection, AKernel) and (AKernel <> nil) then
    begin
      Result := True;
      Exit;
    end;
  end;
  AKernel := nil;
end;

class function TFusedKernelRegistry.TryAcquireGcmSiv(const ACipher: IBlockCipher;
  ADirection: TFusedModeDirection; AHPowers: Pointer;
  out AKernel: IFusedGcmSivKernel): Boolean;
var
  LSnapshot: TCryptoLibGenericArray<IFusedGcmSivKernelFactory>;
  LI: Int32;
begin
  AKernel := nil;
  Result := False;
  if TFusedKernelGate.ForceDisabled then Exit;
  if AHPowers = nil then Exit;
  LSnapshot := SnapshotGcmSivFactories;
  for LI := 0 to System.Length(LSnapshot) - 1 do
  begin
    if LSnapshot[LI].TryCreate(ACipher, ADirection, AHPowers, AKernel) and (AKernel <> nil) then
    begin
      Result := True;
      Exit;
    end;
  end;
  AKernel := nil;
end;

{ ---- Provider queries ------------------------------------------------------- }

class function TFusedKernelRegistry.GetRegisteredGcmProviders: TCryptoLibStringArray;
var
  LSnapshot: TCryptoLibGenericArray<IFusedGcmKernelFactory>;
  LI: Int32;
begin
  LSnapshot := SnapshotGcmFactories;
  System.SetLength(Result, System.Length(LSnapshot));
  for LI := 0 to System.Length(LSnapshot) - 1 do
    Result[LI] := LSnapshot[LI].ProviderName;
end;

class function TFusedKernelRegistry.GetRegisteredOcbProviders: TCryptoLibStringArray;
var
  LSnapshot: TCryptoLibGenericArray<IFusedOcbKernelFactory>;
  LI: Int32;
begin
  LSnapshot := SnapshotOcbFactories;
  System.SetLength(Result, System.Length(LSnapshot));
  for LI := 0 to System.Length(LSnapshot) - 1 do
    Result[LI] := LSnapshot[LI].ProviderName;
end;

class function TFusedKernelRegistry.GetRegisteredCcmProviders: TCryptoLibStringArray;
var
  LSnapshot: TCryptoLibGenericArray<IFusedCcmKernelFactory>;
  LI: Int32;
begin
  LSnapshot := SnapshotCcmFactories;
  System.SetLength(Result, System.Length(LSnapshot));
  for LI := 0 to System.Length(LSnapshot) - 1 do
    Result[LI] := LSnapshot[LI].ProviderName;
end;

class function TFusedKernelRegistry.GetRegisteredEaxProviders: TCryptoLibStringArray;
var
  LSnapshot: TCryptoLibGenericArray<IFusedEaxKernelFactory>;
  LI: Int32;
begin
  LSnapshot := SnapshotEaxFactories;
  System.SetLength(Result, System.Length(LSnapshot));
  for LI := 0 to System.Length(LSnapshot) - 1 do
    Result[LI] := LSnapshot[LI].ProviderName;
end;

class function TFusedKernelRegistry.GetRegisteredGcmSivProviders: TCryptoLibStringArray;
var
  LSnapshot: TCryptoLibGenericArray<IFusedGcmSivKernelFactory>;
  LI: Int32;
begin
  LSnapshot := SnapshotGcmSivFactories;
  System.SetLength(Result, System.Length(LSnapshot));
  for LI := 0 to System.Length(LSnapshot) - 1 do
    Result[LI] := LSnapshot[LI].ProviderName;
end;

end.
