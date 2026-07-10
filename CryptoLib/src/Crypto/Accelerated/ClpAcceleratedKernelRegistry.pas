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

unit ClpAcceleratedKernelRegistry;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  SyncObjs,
  Generics.Collections,
  ClpIBlockCipher,
  ClpCryptoLibTypes,
  ClpAcceleratedKernelTypes,
  ClpIAcceleratedKernelFactory,
  ClpIAcceleratedGcmKernel,
  ClpIAcceleratedOcbKernel,
  ClpIAcceleratedCcmKernel,
  ClpIAcceleratedEaxKernel,
  ClpIAcceleratedGcmSivKernel,
  ClpIAcceleratedCtrKernel,
  ClpIAcceleratedCbcKernel,
  ClpIStreamCipher,
  ClpIAcceleratedChaCha20Poly1305Kernel;

type
  /// <summary>
  ///   Process-wide kill switch for every registered accelerated kernel. When
  ///   ForceDisabled is True, every TryAcquireX returns False without walking
  ///   the factory list, so modes route through their scalar fallbacks. Used by
  ///   the dual-path test harness to prove both paths agree byte-for-byte.
  /// </summary>
  TAcceleratedKernelGate = class sealed(TObject)
  strict private
    class var FForceDisabled: Boolean;
  public
    class property ForceDisabled: Boolean read FForceDisabled write FForceDisabled;
  end;

  /// <summary>
  ///   Open, priority-ordered resolver for the whole accelerated-kernel family. Every
  ///   factory - block-cipher AEAD or stream-cipher AEAD alike - is registered
  ///   through the family-agnostic IAcceleratedKernelFactory into a single
  ///   priority-sorted list (highest Priority first; equal priorities keep
  ///   registration order). A per-mode TryAcquireX re-discovers the concrete
  ///   family with Supports() and calls its typed TryCreate. An external
  ///   consumer registers its own IAccelerated&lt;X&gt;KernelFactory and resolves it
  ///   through the public GetSnapshot + a Supports walk - no framework edit and
  ///   no central enum. Thread-safe: one TCriticalSection guards mutation and
  ///   snapshotting; TryAcquireX snapshots under the lock then releases it before
  ///   invoking factory TryCreate, so factory work never serialises other call
  ///   sites.
  /// </summary>
  TAcceleratedKernelRegistry = class sealed(TObject)
  strict private
    class var FLock: TCriticalSection;
    class var FFactories: TList<IAcceleratedKernelFactory>;
    class function Snapshot: TCryptoLibGenericArray<IAcceleratedKernelFactory>; static;
    class constructor Create;
    class destructor Destroy;
  public
    /// <summary>Register a factory of any family. Insertion keeps the single
    /// list sorted by Ord(Priority) descending; equal priorities retain
    /// registration order. Duplicate registrations (same interface identity)
    /// are silently ignored.</summary>
    class procedure Register(const AFactory: IAcceleratedKernelFactory); static;
    /// <summary>Remove AFactory. No-op if not registered.</summary>
    class procedure Unregister(const AFactory: IAcceleratedKernelFactory); static;
    /// <summary>Priority-ordered snapshot of every registered factory. External
    /// consumers filter it with Supports() to their own factory interface to
    /// resolve an accelerated kernel the framework never enumerated.</summary>
    class function GetSnapshot: TCryptoLibGenericArray<IAcceleratedKernelFactory>; static;

    class procedure RegisterGcmFactory(const AFactory: IAcceleratedGcmKernelFactory); static;
    class procedure RegisterOcbFactory(const AFactory: IAcceleratedOcbKernelFactory); static;
    class procedure RegisterCcmFactory(const AFactory: IAcceleratedCcmKernelFactory); static;
    class procedure RegisterEaxFactory(const AFactory: IAcceleratedEaxKernelFactory); static;
    class procedure RegisterGcmSivFactory(const AFactory: IAcceleratedGcmSivKernelFactory); static;
    class procedure RegisterCtrFactory(const AFactory: IAcceleratedCtrKernelFactory); static;
    class procedure RegisterCbcFactory(const AFactory: IAcceleratedCbcKernelFactory); static;
    class procedure RegisterChaCha20Poly1305Factory(const AFactory: IAcceleratedChaCha20Poly1305KernelFactory); static;

    class procedure UnregisterGcmFactory(const AFactory: IAcceleratedGcmKernelFactory); static;
    class procedure UnregisterOcbFactory(const AFactory: IAcceleratedOcbKernelFactory); static;
    class procedure UnregisterCcmFactory(const AFactory: IAcceleratedCcmKernelFactory); static;
    class procedure UnregisterEaxFactory(const AFactory: IAcceleratedEaxKernelFactory); static;
    class procedure UnregisterGcmSivFactory(const AFactory: IAcceleratedGcmSivKernelFactory); static;
    class procedure UnregisterCtrFactory(const AFactory: IAcceleratedCtrKernelFactory); static;
    class procedure UnregisterCbcFactory(const AFactory: IAcceleratedCbcKernelFactory); static;
    class procedure UnregisterChaCha20Poly1305Factory(const AFactory: IAcceleratedChaCha20Poly1305KernelFactory); static;

    class function TryAcquireGcm(const ACipher: IBlockCipher;
      ADirection: TAcceleratedKernelDirection; AHPowers: Pointer;
      out AKernel: IAcceleratedGcmKernel): Boolean; static;
    class function TryAcquireOcb(const ACipher: IBlockCipher;
      ADirection: TAcceleratedKernelDirection; out AKernel: IAcceleratedOcbKernel): Boolean; static;
    class function TryAcquireCcm(const ACipher: IBlockCipher;
      ADirection: TAcceleratedKernelDirection; out AKernel: IAcceleratedCcmKernel): Boolean; static;
    class function TryAcquireEax(const ACipher: IBlockCipher;
      ADirection: TAcceleratedKernelDirection; out AKernel: IAcceleratedEaxKernel): Boolean; static;
    class function TryAcquireGcmSiv(const ACipher: IBlockCipher;
      ADirection: TAcceleratedKernelDirection; AHPowers: Pointer;
      out AKernel: IAcceleratedGcmSivKernel): Boolean; static;
    class function TryAcquireCtr(const ACipher: IBlockCipher;
      ADirection: TAcceleratedKernelDirection; out AKernel: IAcceleratedCtrKernel): Boolean; static;
    class function TryAcquireCbc(const ACipher: IBlockCipher;
      ADirection: TAcceleratedKernelDirection; out AKernel: IAcceleratedCbcKernel): Boolean; static;
    class function TryAcquireChaCha20Poly1305(const ACipher: IStreamCipher;
      ADirection: TAcceleratedKernelDirection; out AKernel: IAcceleratedChaCha20Poly1305Kernel): Boolean; static;

    /// <summary>Snapshot of ProviderName strings in current priority order.
    /// Used for diagnostics and test assertions.</summary>
    class function GetRegisteredGcmProviders: TCryptoLibStringArray; static;
    class function GetRegisteredOcbProviders: TCryptoLibStringArray; static;
    class function GetRegisteredCcmProviders: TCryptoLibStringArray; static;
    class function GetRegisteredEaxProviders: TCryptoLibStringArray; static;
    class function GetRegisteredGcmSivProviders: TCryptoLibStringArray; static;
    class function GetRegisteredCtrProviders: TCryptoLibStringArray; static;
    class function GetRegisteredCbcProviders: TCryptoLibStringArray; static;
    class function GetRegisteredChaCha20Poly1305Providers: TCryptoLibStringArray; static;
  end;

implementation

{ TAcceleratedKernelRegistry }

class constructor TAcceleratedKernelRegistry.Create;
begin
  FLock := TCriticalSection.Create;
  FFactories := TList<IAcceleratedKernelFactory>.Create;
end;

class destructor TAcceleratedKernelRegistry.Destroy;
begin
  FFactories.Free;
  FLock.Free;
end;

class procedure TAcceleratedKernelRegistry.Register(const AFactory: IAcceleratedKernelFactory);
var
  LI, LPriority: Int32;
  LInserted: Boolean;
begin
  if AFactory = nil then Exit;
  FLock.Enter;
  try
    if FFactories.IndexOf(AFactory) >= 0 then Exit;
    LPriority := Ord(AFactory.Priority);
    LInserted := False;
    for LI := 0 to FFactories.Count - 1 do
    begin
      if LPriority > Ord(FFactories[LI].Priority) then
      begin
        FFactories.Insert(LI, AFactory);
        LInserted := True;
        Break;
      end;
    end;
    if not LInserted then
      FFactories.Add(AFactory);
  finally
    FLock.Leave;
  end;
end;

class procedure TAcceleratedKernelRegistry.Unregister(const AFactory: IAcceleratedKernelFactory);
var
  LIdx: Int32;
begin
  if AFactory = nil then Exit;
  FLock.Enter;
  try
    LIdx := FFactories.IndexOf(AFactory);
    if LIdx >= 0 then
      FFactories.Delete(LIdx);
  finally
    FLock.Leave;
  end;
end;

class function TAcceleratedKernelRegistry.Snapshot: TCryptoLibGenericArray<IAcceleratedKernelFactory>;
var
  LI, LCount: Int32;
begin
  FLock.Enter;
  try
    LCount := FFactories.Count;
    System.SetLength(Result, LCount);
    for LI := 0 to LCount - 1 do
      Result[LI] := FFactories[LI];
  finally
    FLock.Leave;
  end;
end;

class function TAcceleratedKernelRegistry.GetSnapshot: TCryptoLibGenericArray<IAcceleratedKernelFactory>;
begin
  Result := Snapshot;
end;

{ ---- Register / Unregister wrappers ---------------------------------------- }

class procedure TAcceleratedKernelRegistry.RegisterGcmFactory(
  const AFactory: IAcceleratedGcmKernelFactory);
begin
  Register(AFactory);
end;

class procedure TAcceleratedKernelRegistry.RegisterOcbFactory(
  const AFactory: IAcceleratedOcbKernelFactory);
begin
  Register(AFactory);
end;

class procedure TAcceleratedKernelRegistry.RegisterCcmFactory(
  const AFactory: IAcceleratedCcmKernelFactory);
begin
  Register(AFactory);
end;

class procedure TAcceleratedKernelRegistry.RegisterEaxFactory(
  const AFactory: IAcceleratedEaxKernelFactory);
begin
  Register(AFactory);
end;

class procedure TAcceleratedKernelRegistry.RegisterGcmSivFactory(
  const AFactory: IAcceleratedGcmSivKernelFactory);
begin
  Register(AFactory);
end;

class procedure TAcceleratedKernelRegistry.RegisterCtrFactory(
  const AFactory: IAcceleratedCtrKernelFactory);
begin
  Register(AFactory);
end;

class procedure TAcceleratedKernelRegistry.RegisterCbcFactory(
  const AFactory: IAcceleratedCbcKernelFactory);
begin
  Register(AFactory);
end;

class procedure TAcceleratedKernelRegistry.RegisterChaCha20Poly1305Factory(
  const AFactory: IAcceleratedChaCha20Poly1305KernelFactory);
begin
  Register(AFactory);
end;

class procedure TAcceleratedKernelRegistry.UnregisterGcmFactory(
  const AFactory: IAcceleratedGcmKernelFactory);
begin
  Unregister(AFactory);
end;

class procedure TAcceleratedKernelRegistry.UnregisterOcbFactory(
  const AFactory: IAcceleratedOcbKernelFactory);
begin
  Unregister(AFactory);
end;

class procedure TAcceleratedKernelRegistry.UnregisterCcmFactory(
  const AFactory: IAcceleratedCcmKernelFactory);
begin
  Unregister(AFactory);
end;

class procedure TAcceleratedKernelRegistry.UnregisterEaxFactory(
  const AFactory: IAcceleratedEaxKernelFactory);
begin
  Unregister(AFactory);
end;

class procedure TAcceleratedKernelRegistry.UnregisterGcmSivFactory(
  const AFactory: IAcceleratedGcmSivKernelFactory);
begin
  Unregister(AFactory);
end;

class procedure TAcceleratedKernelRegistry.UnregisterCtrFactory(
  const AFactory: IAcceleratedCtrKernelFactory);
begin
  Unregister(AFactory);
end;

class procedure TAcceleratedKernelRegistry.UnregisterCbcFactory(
  const AFactory: IAcceleratedCbcKernelFactory);
begin
  Unregister(AFactory);
end;

class procedure TAcceleratedKernelRegistry.UnregisterChaCha20Poly1305Factory(
  const AFactory: IAcceleratedChaCha20Poly1305KernelFactory);
begin
  Unregister(AFactory);
end;

{ ---- TryAcquire ------------------------------------------------------------- }

class function TAcceleratedKernelRegistry.TryAcquireGcm(const ACipher: IBlockCipher;
  ADirection: TAcceleratedKernelDirection; AHPowers: Pointer;
  out AKernel: IAcceleratedGcmKernel): Boolean;
var
  LSnap: TCryptoLibGenericArray<IAcceleratedKernelFactory>;
  LI: Int32;
  LFac: IAcceleratedGcmKernelFactory;
begin
  AKernel := nil;
  Result := False;
  if TAcceleratedKernelGate.ForceDisabled then Exit;
  if ACipher = nil then Exit;
  if AHPowers = nil then Exit;
  LSnap := Snapshot;
  for LI := 0 to System.Length(LSnap) - 1 do
  begin
    if Supports(LSnap[LI], IAcceleratedGcmKernelFactory, LFac) and
      LFac.TryCreate(ACipher, ADirection, AHPowers, AKernel) and (AKernel <> nil) then
    begin
      Result := True;
      Exit;
    end;
  end;
  AKernel := nil;
end;

class function TAcceleratedKernelRegistry.TryAcquireOcb(const ACipher: IBlockCipher;
  ADirection: TAcceleratedKernelDirection; out AKernel: IAcceleratedOcbKernel): Boolean;
var
  LSnap: TCryptoLibGenericArray<IAcceleratedKernelFactory>;
  LI: Int32;
  LFac: IAcceleratedOcbKernelFactory;
begin
  AKernel := nil;
  Result := False;
  if TAcceleratedKernelGate.ForceDisabled then Exit;
  if ACipher = nil then Exit;
  LSnap := Snapshot;
  for LI := 0 to System.Length(LSnap) - 1 do
  begin
    if Supports(LSnap[LI], IAcceleratedOcbKernelFactory, LFac) and
      LFac.TryCreate(ACipher, ADirection, AKernel) and (AKernel <> nil) then
    begin
      Result := True;
      Exit;
    end;
  end;
  AKernel := nil;
end;

class function TAcceleratedKernelRegistry.TryAcquireCcm(const ACipher: IBlockCipher;
  ADirection: TAcceleratedKernelDirection; out AKernel: IAcceleratedCcmKernel): Boolean;
var
  LSnap: TCryptoLibGenericArray<IAcceleratedKernelFactory>;
  LI: Int32;
  LFac: IAcceleratedCcmKernelFactory;
begin
  AKernel := nil;
  Result := False;
  if TAcceleratedKernelGate.ForceDisabled then Exit;
  if ACipher = nil then Exit;
  LSnap := Snapshot;
  for LI := 0 to System.Length(LSnap) - 1 do
  begin
    if Supports(LSnap[LI], IAcceleratedCcmKernelFactory, LFac) and
      LFac.TryCreate(ACipher, ADirection, AKernel) and (AKernel <> nil) then
    begin
      Result := True;
      Exit;
    end;
  end;
  AKernel := nil;
end;

class function TAcceleratedKernelRegistry.TryAcquireEax(const ACipher: IBlockCipher;
  ADirection: TAcceleratedKernelDirection; out AKernel: IAcceleratedEaxKernel): Boolean;
var
  LSnap: TCryptoLibGenericArray<IAcceleratedKernelFactory>;
  LI: Int32;
  LFac: IAcceleratedEaxKernelFactory;
begin
  AKernel := nil;
  Result := False;
  if TAcceleratedKernelGate.ForceDisabled then Exit;
  if ACipher = nil then Exit;
  LSnap := Snapshot;
  for LI := 0 to System.Length(LSnap) - 1 do
  begin
    if Supports(LSnap[LI], IAcceleratedEaxKernelFactory, LFac) and
      LFac.TryCreate(ACipher, ADirection, AKernel) and (AKernel <> nil) then
    begin
      Result := True;
      Exit;
    end;
  end;
  AKernel := nil;
end;

class function TAcceleratedKernelRegistry.TryAcquireGcmSiv(const ACipher: IBlockCipher;
  ADirection: TAcceleratedKernelDirection; AHPowers: Pointer;
  out AKernel: IAcceleratedGcmSivKernel): Boolean;
var
  LSnap: TCryptoLibGenericArray<IAcceleratedKernelFactory>;
  LI: Int32;
  LFac: IAcceleratedGcmSivKernelFactory;
begin
  AKernel := nil;
  Result := False;
  if TAcceleratedKernelGate.ForceDisabled then Exit;
  if AHPowers = nil then Exit;
  LSnap := Snapshot;
  for LI := 0 to System.Length(LSnap) - 1 do
  begin
    if Supports(LSnap[LI], IAcceleratedGcmSivKernelFactory, LFac) and
      LFac.TryCreate(ACipher, ADirection, AHPowers, AKernel) and (AKernel <> nil) then
    begin
      Result := True;
      Exit;
    end;
  end;
  AKernel := nil;
end;

class function TAcceleratedKernelRegistry.TryAcquireCtr(const ACipher: IBlockCipher;
  ADirection: TAcceleratedKernelDirection; out AKernel: IAcceleratedCtrKernel): Boolean;
var
  LSnap: TCryptoLibGenericArray<IAcceleratedKernelFactory>;
  LI: Int32;
  LFac: IAcceleratedCtrKernelFactory;
begin
  AKernel := nil;
  Result := False;
  if TAcceleratedKernelGate.ForceDisabled then Exit;
  if ACipher = nil then Exit;
  LSnap := Snapshot;
  for LI := 0 to System.Length(LSnap) - 1 do
  begin
    if Supports(LSnap[LI], IAcceleratedCtrKernelFactory, LFac) and
      LFac.TryCreate(ACipher, ADirection, AKernel) and (AKernel <> nil) then
    begin
      Result := True;
      Exit;
    end;
  end;
  AKernel := nil;
end;

class function TAcceleratedKernelRegistry.TryAcquireCbc(const ACipher: IBlockCipher;
  ADirection: TAcceleratedKernelDirection; out AKernel: IAcceleratedCbcKernel): Boolean;
var
  LSnap: TCryptoLibGenericArray<IAcceleratedKernelFactory>;
  LI: Int32;
  LFac: IAcceleratedCbcKernelFactory;
begin
  AKernel := nil;
  Result := False;
  if TAcceleratedKernelGate.ForceDisabled then Exit;
  if ACipher = nil then Exit;
  LSnap := Snapshot;
  for LI := 0 to System.Length(LSnap) - 1 do
  begin
    if Supports(LSnap[LI], IAcceleratedCbcKernelFactory, LFac) and
      LFac.TryCreate(ACipher, ADirection, AKernel) and (AKernel <> nil) then
    begin
      Result := True;
      Exit;
    end;
  end;
  AKernel := nil;
end;

class function TAcceleratedKernelRegistry.TryAcquireChaCha20Poly1305(const ACipher: IStreamCipher;
  ADirection: TAcceleratedKernelDirection; out AKernel: IAcceleratedChaCha20Poly1305Kernel): Boolean;
var
  LSnap: TCryptoLibGenericArray<IAcceleratedKernelFactory>;
  LI: Int32;
  LFac: IAcceleratedChaCha20Poly1305KernelFactory;
begin
  AKernel := nil;
  Result := False;
  if TAcceleratedKernelGate.ForceDisabled then Exit;
  if ACipher = nil then Exit;
  LSnap := Snapshot;
  for LI := 0 to System.Length(LSnap) - 1 do
  begin
    if Supports(LSnap[LI], IAcceleratedChaCha20Poly1305KernelFactory, LFac) and
      LFac.TryCreate(ACipher, ADirection, AKernel) and (AKernel <> nil) then
    begin
      Result := True;
      Exit;
    end;
  end;
  AKernel := nil;
end;

{ ---- Provider queries ------------------------------------------------------- }

class function TAcceleratedKernelRegistry.GetRegisteredGcmProviders: TCryptoLibStringArray;
var
  LSnap: TCryptoLibGenericArray<IAcceleratedKernelFactory>;
  LI, LN: Int32;
  LFac: IAcceleratedGcmKernelFactory;
begin
  LSnap := Snapshot;
  System.SetLength(Result, 0);
  LN := 0;
  for LI := 0 to System.Length(LSnap) - 1 do
    if Supports(LSnap[LI], IAcceleratedGcmKernelFactory, LFac) then
    begin
      System.SetLength(Result, LN + 1);
      Result[LN] := LFac.ProviderName;
      Inc(LN);
    end;
end;

class function TAcceleratedKernelRegistry.GetRegisteredOcbProviders: TCryptoLibStringArray;
var
  LSnap: TCryptoLibGenericArray<IAcceleratedKernelFactory>;
  LI, LN: Int32;
  LFac: IAcceleratedOcbKernelFactory;
begin
  LSnap := Snapshot;
  System.SetLength(Result, 0);
  LN := 0;
  for LI := 0 to System.Length(LSnap) - 1 do
    if Supports(LSnap[LI], IAcceleratedOcbKernelFactory, LFac) then
    begin
      System.SetLength(Result, LN + 1);
      Result[LN] := LFac.ProviderName;
      Inc(LN);
    end;
end;

class function TAcceleratedKernelRegistry.GetRegisteredCcmProviders: TCryptoLibStringArray;
var
  LSnap: TCryptoLibGenericArray<IAcceleratedKernelFactory>;
  LI, LN: Int32;
  LFac: IAcceleratedCcmKernelFactory;
begin
  LSnap := Snapshot;
  System.SetLength(Result, 0);
  LN := 0;
  for LI := 0 to System.Length(LSnap) - 1 do
    if Supports(LSnap[LI], IAcceleratedCcmKernelFactory, LFac) then
    begin
      System.SetLength(Result, LN + 1);
      Result[LN] := LFac.ProviderName;
      Inc(LN);
    end;
end;

class function TAcceleratedKernelRegistry.GetRegisteredEaxProviders: TCryptoLibStringArray;
var
  LSnap: TCryptoLibGenericArray<IAcceleratedKernelFactory>;
  LI, LN: Int32;
  LFac: IAcceleratedEaxKernelFactory;
begin
  LSnap := Snapshot;
  System.SetLength(Result, 0);
  LN := 0;
  for LI := 0 to System.Length(LSnap) - 1 do
    if Supports(LSnap[LI], IAcceleratedEaxKernelFactory, LFac) then
    begin
      System.SetLength(Result, LN + 1);
      Result[LN] := LFac.ProviderName;
      Inc(LN);
    end;
end;

class function TAcceleratedKernelRegistry.GetRegisteredGcmSivProviders: TCryptoLibStringArray;
var
  LSnap: TCryptoLibGenericArray<IAcceleratedKernelFactory>;
  LI, LN: Int32;
  LFac: IAcceleratedGcmSivKernelFactory;
begin
  LSnap := Snapshot;
  System.SetLength(Result, 0);
  LN := 0;
  for LI := 0 to System.Length(LSnap) - 1 do
    if Supports(LSnap[LI], IAcceleratedGcmSivKernelFactory, LFac) then
    begin
      System.SetLength(Result, LN + 1);
      Result[LN] := LFac.ProviderName;
      Inc(LN);
    end;
end;

class function TAcceleratedKernelRegistry.GetRegisteredCtrProviders: TCryptoLibStringArray;
var
  LSnap: TCryptoLibGenericArray<IAcceleratedKernelFactory>;
  LI, LN: Int32;
  LFac: IAcceleratedCtrKernelFactory;
begin
  LSnap := Snapshot;
  System.SetLength(Result, 0);
  LN := 0;
  for LI := 0 to System.Length(LSnap) - 1 do
    if Supports(LSnap[LI], IAcceleratedCtrKernelFactory, LFac) then
    begin
      System.SetLength(Result, LN + 1);
      Result[LN] := LFac.ProviderName;
      Inc(LN);
    end;
end;

class function TAcceleratedKernelRegistry.GetRegisteredCbcProviders: TCryptoLibStringArray;
var
  LSnap: TCryptoLibGenericArray<IAcceleratedKernelFactory>;
  LI, LN: Int32;
  LFac: IAcceleratedCbcKernelFactory;
begin
  LSnap := Snapshot;
  System.SetLength(Result, 0);
  LN := 0;
  for LI := 0 to System.Length(LSnap) - 1 do
    if Supports(LSnap[LI], IAcceleratedCbcKernelFactory, LFac) then
    begin
      System.SetLength(Result, LN + 1);
      Result[LN] := LFac.ProviderName;
      Inc(LN);
    end;
end;

class function TAcceleratedKernelRegistry.GetRegisteredChaCha20Poly1305Providers: TCryptoLibStringArray;
var
  LSnap: TCryptoLibGenericArray<IAcceleratedKernelFactory>;
  LI, LN: Int32;
  LFac: IAcceleratedChaCha20Poly1305KernelFactory;
begin
  LSnap := Snapshot;
  System.SetLength(Result, 0);
  LN := 0;
  for LI := 0 to System.Length(LSnap) - 1 do
    if Supports(LSnap[LI], IAcceleratedChaCha20Poly1305KernelFactory, LFac) then
    begin
      System.SetLength(Result, LN + 1);
      Result[LN] := LFac.ProviderName;
      Inc(LN);
    end;
end;

end.
