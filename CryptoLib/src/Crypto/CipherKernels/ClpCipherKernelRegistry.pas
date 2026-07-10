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

unit ClpCipherKernelRegistry;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  SyncObjs,
  Generics.Collections,
  ClpIBlockCipher,
  ClpCryptoLibTypes,
  ClpCipherKernelTypes,
  ClpICipherKernelFactory,
  ClpIGcmKernel,
  ClpIOcbKernel,
  ClpICcmKernel,
  ClpIEaxKernel,
  ClpIGcmSivKernel,
  ClpICtrKernel,
  ClpICbcKernel,
  ClpIStreamCipher,
  ClpIChaCha20Poly1305Kernel;

type
  /// <summary>
  ///   Process-wide kill switch for every registered cipher kernel. When
  ///   ForceDisabled is True, every TryAcquireX returns False without walking
  ///   the factory list, so modes route through their scalar fallbacks. Used by
  ///   the dual-path test harness to prove both paths agree byte-for-byte.
  /// </summary>
  TCipherKernelGate = class sealed(TObject)
  strict private
    class var FForceDisabled: Boolean;
  public
    class property ForceDisabled: Boolean read FForceDisabled write FForceDisabled;
  end;

  /// <summary>
  ///   Open, priority-ordered resolver for the whole cipher-kernel family. Every
  ///   factory - block-cipher AEAD or stream-cipher AEAD alike - is registered
  ///   through the family-agnostic ICipherKernelFactory into a single
  ///   priority-sorted list (highest Priority first; equal priorities keep
  ///   registration order). A per-mode TryAcquireX re-discovers the concrete
  ///   family with Supports() and calls its typed TryCreate. An external
  ///   consumer registers its own I&lt;X&gt;KernelFactory and resolves it
  ///   through the public GetSnapshot + a Supports walk - no framework edit and
  ///   no central enum. Thread-safe: one TCriticalSection guards mutation and
  ///   snapshotting; TryAcquireX snapshots under the lock then releases it before
  ///   invoking factory TryCreate, so factory work never serialises other call
  ///   sites.
  /// </summary>
  TCipherKernelRegistry = class sealed(TObject)
  strict private
    class var FLock: TCriticalSection;
    class var FFactories: TList<ICipherKernelFactory>;
    class function Snapshot: TCryptoLibGenericArray<ICipherKernelFactory>; static;
    class constructor Create;
    class destructor Destroy;
  public
    /// <summary>Register a factory of any family. Insertion keeps the single
    /// list sorted by Ord(Priority) descending; equal priorities retain
    /// registration order. Duplicate registrations (same interface identity)
    /// are silently ignored.</summary>
    class procedure Register(const AFactory: ICipherKernelFactory); static;
    /// <summary>Remove AFactory. No-op if not registered.</summary>
    class procedure Unregister(const AFactory: ICipherKernelFactory); static;
    /// <summary>Priority-ordered snapshot of every registered factory. External
    /// consumers filter it with Supports() to their own factory interface to
    /// resolve a cipher kernel the framework never enumerated.</summary>
    class function GetSnapshot: TCryptoLibGenericArray<ICipherKernelFactory>; static;

    class function TryAcquireGcm(const ACipher: IBlockCipher;
      ADirection: TCipherKernelDirection; AHPowers: Pointer;
      out AKernel: IGcmKernel): Boolean; static;
    class function TryAcquireOcb(const ACipher: IBlockCipher;
      ADirection: TCipherKernelDirection; out AKernel: IOcbKernel): Boolean; static;
    class function TryAcquireCcm(const ACipher: IBlockCipher;
      ADirection: TCipherKernelDirection; out AKernel: ICcmKernel): Boolean; static;
    class function TryAcquireEax(const ACipher: IBlockCipher;
      ADirection: TCipherKernelDirection; out AKernel: IEaxKernel): Boolean; static;
    class function TryAcquireGcmSiv(const ACipher: IBlockCipher;
      ADirection: TCipherKernelDirection; AHPowers: Pointer;
      out AKernel: IGcmSivKernel): Boolean; static;
    class function TryAcquireCtr(const ACipher: IBlockCipher;
      ADirection: TCipherKernelDirection; out AKernel: ICtrKernel): Boolean; static;
    class function TryAcquireCbc(const ACipher: IBlockCipher;
      ADirection: TCipherKernelDirection; out AKernel: ICbcKernel): Boolean; static;
    class function TryAcquireChaCha20Poly1305(const ACipher: IStreamCipher;
      ADirection: TCipherKernelDirection; out AKernel: IChaCha20Poly1305Kernel): Boolean; static;

    /// <summary>Provider-name list (priority order) of every registered factory
    /// supporting AFactoryIID. Pass a per-mode factory interface, e.g.
    /// GetRegisteredProviders(IGcmKernelFactory). Diagnostics/tests.</summary>
    class function GetRegisteredProviders(const AFactoryIID: TGUID): TCryptoLibStringArray; static;
  end;

implementation

{ TCipherKernelRegistry }

class constructor TCipherKernelRegistry.Create;
begin
  FLock := TCriticalSection.Create;
  FFactories := TList<ICipherKernelFactory>.Create;
end;

class destructor TCipherKernelRegistry.Destroy;
begin
  FFactories.Free;
  FLock.Free;
end;

class procedure TCipherKernelRegistry.Register(const AFactory: ICipherKernelFactory);
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

class procedure TCipherKernelRegistry.Unregister(const AFactory: ICipherKernelFactory);
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

class function TCipherKernelRegistry.Snapshot: TCryptoLibGenericArray<ICipherKernelFactory>;
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

class function TCipherKernelRegistry.GetSnapshot: TCryptoLibGenericArray<ICipherKernelFactory>;
begin
  Result := Snapshot;
end;

{ ---- TryAcquire ------------------------------------------------------------- }

class function TCipherKernelRegistry.TryAcquireGcm(const ACipher: IBlockCipher;
  ADirection: TCipherKernelDirection; AHPowers: Pointer;
  out AKernel: IGcmKernel): Boolean;
var
  LSnap: TCryptoLibGenericArray<ICipherKernelFactory>;
  LI: Int32;
  LFac: IGcmKernelFactory;
begin
  AKernel := nil;
  Result := False;
  if TCipherKernelGate.ForceDisabled then Exit;
  if ACipher = nil then Exit;
  if AHPowers = nil then Exit;
  LSnap := Snapshot;
  for LI := 0 to System.Length(LSnap) - 1 do
  begin
    if Supports(LSnap[LI], IGcmKernelFactory, LFac) and
      LFac.TryCreate(ACipher, ADirection, AHPowers, AKernel) and (AKernel <> nil) then
    begin
      Result := True;
      Exit;
    end;
  end;
  AKernel := nil;
end;

class function TCipherKernelRegistry.TryAcquireOcb(const ACipher: IBlockCipher;
  ADirection: TCipherKernelDirection; out AKernel: IOcbKernel): Boolean;
var
  LSnap: TCryptoLibGenericArray<ICipherKernelFactory>;
  LI: Int32;
  LFac: IOcbKernelFactory;
begin
  AKernel := nil;
  Result := False;
  if TCipherKernelGate.ForceDisabled then Exit;
  if ACipher = nil then Exit;
  LSnap := Snapshot;
  for LI := 0 to System.Length(LSnap) - 1 do
  begin
    if Supports(LSnap[LI], IOcbKernelFactory, LFac) and
      LFac.TryCreate(ACipher, ADirection, AKernel) and (AKernel <> nil) then
    begin
      Result := True;
      Exit;
    end;
  end;
  AKernel := nil;
end;

class function TCipherKernelRegistry.TryAcquireCcm(const ACipher: IBlockCipher;
  ADirection: TCipherKernelDirection; out AKernel: ICcmKernel): Boolean;
var
  LSnap: TCryptoLibGenericArray<ICipherKernelFactory>;
  LI: Int32;
  LFac: ICcmKernelFactory;
begin
  AKernel := nil;
  Result := False;
  if TCipherKernelGate.ForceDisabled then Exit;
  if ACipher = nil then Exit;
  LSnap := Snapshot;
  for LI := 0 to System.Length(LSnap) - 1 do
  begin
    if Supports(LSnap[LI], ICcmKernelFactory, LFac) and
      LFac.TryCreate(ACipher, ADirection, AKernel) and (AKernel <> nil) then
    begin
      Result := True;
      Exit;
    end;
  end;
  AKernel := nil;
end;

class function TCipherKernelRegistry.TryAcquireEax(const ACipher: IBlockCipher;
  ADirection: TCipherKernelDirection; out AKernel: IEaxKernel): Boolean;
var
  LSnap: TCryptoLibGenericArray<ICipherKernelFactory>;
  LI: Int32;
  LFac: IEaxKernelFactory;
begin
  AKernel := nil;
  Result := False;
  if TCipherKernelGate.ForceDisabled then Exit;
  if ACipher = nil then Exit;
  LSnap := Snapshot;
  for LI := 0 to System.Length(LSnap) - 1 do
  begin
    if Supports(LSnap[LI], IEaxKernelFactory, LFac) and
      LFac.TryCreate(ACipher, ADirection, AKernel) and (AKernel <> nil) then
    begin
      Result := True;
      Exit;
    end;
  end;
  AKernel := nil;
end;

class function TCipherKernelRegistry.TryAcquireGcmSiv(const ACipher: IBlockCipher;
  ADirection: TCipherKernelDirection; AHPowers: Pointer;
  out AKernel: IGcmSivKernel): Boolean;
var
  LSnap: TCryptoLibGenericArray<ICipherKernelFactory>;
  LI: Int32;
  LFac: IGcmSivKernelFactory;
begin
  AKernel := nil;
  Result := False;
  if TCipherKernelGate.ForceDisabled then Exit;
  if AHPowers = nil then Exit;
  LSnap := Snapshot;
  for LI := 0 to System.Length(LSnap) - 1 do
  begin
    if Supports(LSnap[LI], IGcmSivKernelFactory, LFac) and
      LFac.TryCreate(ACipher, ADirection, AHPowers, AKernel) and (AKernel <> nil) then
    begin
      Result := True;
      Exit;
    end;
  end;
  AKernel := nil;
end;

class function TCipherKernelRegistry.TryAcquireCtr(const ACipher: IBlockCipher;
  ADirection: TCipherKernelDirection; out AKernel: ICtrKernel): Boolean;
var
  LSnap: TCryptoLibGenericArray<ICipherKernelFactory>;
  LI: Int32;
  LFac: ICtrKernelFactory;
begin
  AKernel := nil;
  Result := False;
  if TCipherKernelGate.ForceDisabled then Exit;
  if ACipher = nil then Exit;
  LSnap := Snapshot;
  for LI := 0 to System.Length(LSnap) - 1 do
  begin
    if Supports(LSnap[LI], ICtrKernelFactory, LFac) and
      LFac.TryCreate(ACipher, ADirection, AKernel) and (AKernel <> nil) then
    begin
      Result := True;
      Exit;
    end;
  end;
  AKernel := nil;
end;

class function TCipherKernelRegistry.TryAcquireCbc(const ACipher: IBlockCipher;
  ADirection: TCipherKernelDirection; out AKernel: ICbcKernel): Boolean;
var
  LSnap: TCryptoLibGenericArray<ICipherKernelFactory>;
  LI: Int32;
  LFac: ICbcKernelFactory;
begin
  AKernel := nil;
  Result := False;
  if TCipherKernelGate.ForceDisabled then Exit;
  if ACipher = nil then Exit;
  LSnap := Snapshot;
  for LI := 0 to System.Length(LSnap) - 1 do
  begin
    if Supports(LSnap[LI], ICbcKernelFactory, LFac) and
      LFac.TryCreate(ACipher, ADirection, AKernel) and (AKernel <> nil) then
    begin
      Result := True;
      Exit;
    end;
  end;
  AKernel := nil;
end;

class function TCipherKernelRegistry.TryAcquireChaCha20Poly1305(const ACipher: IStreamCipher;
  ADirection: TCipherKernelDirection; out AKernel: IChaCha20Poly1305Kernel): Boolean;
var
  LSnap: TCryptoLibGenericArray<ICipherKernelFactory>;
  LI: Int32;
  LFac: IChaCha20Poly1305KernelFactory;
begin
  AKernel := nil;
  Result := False;
  if TCipherKernelGate.ForceDisabled then Exit;
  if ACipher = nil then Exit;
  LSnap := Snapshot;
  for LI := 0 to System.Length(LSnap) - 1 do
  begin
    if Supports(LSnap[LI], IChaCha20Poly1305KernelFactory, LFac) and
      LFac.TryCreate(ACipher, ADirection, AKernel) and (AKernel <> nil) then
    begin
      Result := True;
      Exit;
    end;
  end;
  AKernel := nil;
end;

class function TCipherKernelRegistry.GetRegisteredProviders(
  const AFactoryIID: TGUID): TCryptoLibStringArray;
var
  LSnap: TCryptoLibGenericArray<ICipherKernelFactory>;
  LI, LN: Int32;
begin
  LSnap := Snapshot;
  Result := nil;
  LN := 0;
  for LI := 0 to System.Length(LSnap) - 1 do
    if Supports(LSnap[LI], AFactoryIID) then
    begin
      System.SetLength(Result, LN + 1);
      Result[LN] := LSnap[LI].ProviderName;
      Inc(LN);
    end;
end;

end.
