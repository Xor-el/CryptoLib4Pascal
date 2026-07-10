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

unit AcceleratedExternalRegistrationTests;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  SysUtils,
{$IFDEF FPC}
  fpcunit,
  testregistry,
{$ELSE}
  TestFramework,
{$ENDIF FPC}
  ClpIBlockCipher,
  ClpAcceleratedKernelTypes,
  ClpIAcceleratedGcmKernel,
  ClpAcceleratedKernelRegistry,
  ClpCryptoLibTypes;

type
  /// <summary>
  ///   No-op third-party GCM kernel factory used by the external
  ///   registration pin tests. TryCreate always returns False so no
  ///   code path (production or test) actually acquires this factory
  ///   as an accelerated kernel; its only observable effect is its presence
  ///   in the registry's public diagnostic lists.
  /// </summary>
  TMockExternalGcmKernelFactory = class sealed(TInterfacedObject,
    IAcceleratedGcmKernelFactory)
  public
    function ProviderName: String;
    function Priority: TAcceleratedKernelPriority;
    function TryCreate(const ACipher: IBlockCipher;
      ADirection: TAcceleratedKernelDirection; AHPowers: Pointer;
      out AKernel: IAcceleratedGcmKernel): Boolean;
  end;

  /// <summary>
  ///   Pins the "external parties register without modifying
  ///   CryptoLib" contract. A mock third-party factory is registered
  ///   from test code exactly the way a consumer's own unit would
  ///   register from its initialization block. The tests assert that:
  ///     * after Register, GetRegisteredProviders(IAcceleratedGcmKernelFactory)
  ///       reflects the mock;
  ///     * registration is strictly additive -- every provider that
  ///       was already present is still present afterwards (defaults
  ///       coexist);
  ///     * Unregister returns the provider list to its
  ///       prior state.
  ///   Any future change that silently regresses this external
  ///   registration contract will trip a red test here.
  /// </summary>
  TTestAcceleratedExternalRegistration = class(TTestCase)
  strict private
    class function ProvidersContain(const AList: TCryptoLibStringArray;
      const AName: String): Boolean; static;
  published
    procedure TestExternalRegistrationAddsProvider;
    procedure TestExternalRegistrationIsStrictlyAdditive;
    procedure TestExternalUnregistrationRestoresPriorList;
    procedure TestDuplicateExternalRegistrationIsIgnored;
  end;

const
  CMockExternalProviderName = 'MOCK-EXT-GCM';

implementation

resourcestring
  SMockMustBePresent =
    'Mock external GCM factory must appear in ' +
    'GetRegisteredProviders(IAcceleratedGcmKernelFactory) after Register.';
  SMockMustBeAbsent =
    'Mock external GCM factory must be absent from ' +
    'GetRegisteredProviders(IAcceleratedGcmKernelFactory) after Unregister.';
  SCountMustGrowByOne =
    'External Register must grow the provider count by ' +
    'exactly one (non-duplicate factory).';
  SCountMustRestoreBaseline =
    'External Unregister must restore the provider count ' +
    'to its pre-registration baseline.';
  SDefaultsMustSurvive =
    'Every provider present before external registration must still ' +
    'be reported afterwards (registration is strictly additive).';
  SDuplicateMustBeIgnored =
    'Register MUST silently ignore duplicate registrations ' +
    '(same interface identity).';

{ TMockExternalGcmKernelFactory }

function TMockExternalGcmKernelFactory.ProviderName: String;
begin
  Result := CMockExternalProviderName;
end;

function TMockExternalGcmKernelFactory.Priority: TAcceleratedKernelPriority;
begin
  // Fallback is the lowest rank so this mock never intercepts real
  // GCM acquires on any platform where a genuine in-tree factory is
  // also registered. The mock's entire purpose is to appear in the
  // diagnostic list, not to be picked up by TryAcquireGcm.
  Result := TAcceleratedKernelPriority.Fallback;
end;

function TMockExternalGcmKernelFactory.TryCreate(const ACipher: IBlockCipher;
  ADirection: TAcceleratedKernelDirection; AHPowers: Pointer;
  out AKernel: IAcceleratedGcmKernel): Boolean;
begin
  AKernel := nil;
  Result := False;
end;

{ TTestAcceleratedExternalRegistration }

class function TTestAcceleratedExternalRegistration.ProvidersContain(
  const AList: TCryptoLibStringArray; const AName: String): Boolean;
var
  LIndex: Int32;
begin
  Result := False;
  for LIndex := 0 to System.Length(AList) - 1 do
    if AList[LIndex] = AName then
    begin
      Result := True;
      Exit;
    end;
end;

procedure TTestAcceleratedExternalRegistration.TestExternalRegistrationAddsProvider;
var
  LFactory: IAcceleratedGcmKernelFactory;
  LProviders: TCryptoLibStringArray;
begin
  LFactory := TMockExternalGcmKernelFactory.Create();
  TAcceleratedKernelRegistry.Register(LFactory);
  try
    LProviders := TAcceleratedKernelRegistry.GetRegisteredProviders(IAcceleratedGcmKernelFactory);
    CheckTrue(ProvidersContain(LProviders, CMockExternalProviderName),
      SMockMustBePresent);
  finally
    TAcceleratedKernelRegistry.Unregister(LFactory);
  end;
end;

procedure TTestAcceleratedExternalRegistration.TestExternalRegistrationIsStrictlyAdditive;
var
  LFactory: IAcceleratedGcmKernelFactory;
  LBaseline, LAfter: TCryptoLibStringArray;
  LIndex: Int32;
begin
  LBaseline := TAcceleratedKernelRegistry.GetRegisteredProviders(IAcceleratedGcmKernelFactory);
  LFactory := TMockExternalGcmKernelFactory.Create();
  TAcceleratedKernelRegistry.Register(LFactory);
  try
    LAfter := TAcceleratedKernelRegistry.GetRegisteredProviders(IAcceleratedGcmKernelFactory);
    CheckEquals(System.Length(LBaseline) + 1, System.Length(LAfter),
      SCountMustGrowByOne);
    // Every baseline name must survive the registration.
    for LIndex := 0 to System.Length(LBaseline) - 1 do
      CheckTrue(ProvidersContain(LAfter, LBaseline[LIndex]),
        SDefaultsMustSurvive);
  finally
    TAcceleratedKernelRegistry.Unregister(LFactory);
  end;
end;

procedure TTestAcceleratedExternalRegistration.TestExternalUnregistrationRestoresPriorList;
var
  LFactory: IAcceleratedGcmKernelFactory;
  LBaseline, LAfterUnregister: TCryptoLibStringArray;
  LIndex: Int32;
begin
  LBaseline := TAcceleratedKernelRegistry.GetRegisteredProviders(IAcceleratedGcmKernelFactory);
  LFactory := TMockExternalGcmKernelFactory.Create();
  TAcceleratedKernelRegistry.Register(LFactory);
  TAcceleratedKernelRegistry.Unregister(LFactory);

  LAfterUnregister := TAcceleratedKernelRegistry.GetRegisteredProviders(IAcceleratedGcmKernelFactory);
  CheckEquals(System.Length(LBaseline), System.Length(LAfterUnregister),
    SCountMustRestoreBaseline);
  CheckFalse(ProvidersContain(LAfterUnregister, CMockExternalProviderName),
    SMockMustBeAbsent);
  for LIndex := 0 to System.Length(LBaseline) - 1 do
    CheckTrue(ProvidersContain(LAfterUnregister, LBaseline[LIndex]),
      SDefaultsMustSurvive);
end;

procedure TTestAcceleratedExternalRegistration.TestDuplicateExternalRegistrationIsIgnored;
var
  LFactory: IAcceleratedGcmKernelFactory;
  LBaseline, LAfter: TCryptoLibStringArray;
begin
  LBaseline := TAcceleratedKernelRegistry.GetRegisteredProviders(IAcceleratedGcmKernelFactory);
  LFactory := TMockExternalGcmKernelFactory.Create();
  TAcceleratedKernelRegistry.Register(LFactory);
  try
    TAcceleratedKernelRegistry.Register(LFactory);
    LAfter := TAcceleratedKernelRegistry.GetRegisteredProviders(IAcceleratedGcmKernelFactory);
    CheckEquals(System.Length(LBaseline) + 1, System.Length(LAfter),
      SDuplicateMustBeIgnored);
  finally
    TAcceleratedKernelRegistry.Unregister(LFactory);
  end;
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestAcceleratedExternalRegistration);
{$ELSE}
  RegisterTest(TTestAcceleratedExternalRegistration.Suite);
{$ENDIF FPC}

end.
