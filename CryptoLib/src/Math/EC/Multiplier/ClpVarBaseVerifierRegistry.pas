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

unit ClpVarBaseVerifierRegistry;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  SyncObjs,
  Generics.Collections,
  ClpBigInteger,
  ClpIECVarBaseVerifier;

type
  /// <summary>Process-wide registry of fast variable-time double-scalar verifiers
  /// keyed by group order, so <c>TECAlgorithms.SumOfTwoMultiplies</c> can pick a
  /// re-hosted verify path for a curve without depending on the curve's concrete
  /// type. Absence means "use the generic wNAF/GLV path". The verify path is
  /// public-input only, so this registry never touches a secret scalar.</summary>
  TVarBaseVerifierRegistry = class sealed(TObject)
  strict private
    class var FLock: TCriticalSection;
    class var FMap: TDictionary<String, IECVarBaseVerifier>;
    class var FEnabled: Boolean;
    class function KeyOf(const AOrder: TBigInteger): String; static; inline;
  public
    class constructor Create;
    class destructor Destroy;
    class procedure Register(const AOrder: TBigInteger; const AVerifier: IECVarBaseVerifier); static;
    class function TryGet(const AOrder: TBigInteger; out AVerifier: IECVarBaseVerifier): Boolean; static;
    /// <summary>Global switch for the re-hosted verify path; when False callers take
    /// their generic wNAF/GLV fallback. Default True. Used as the differential test
    /// gate (old vs new verify).</summary>
    class property Enabled: Boolean read FEnabled write FEnabled;
  end;

implementation

{ TVarBaseVerifierRegistry }

class constructor TVarBaseVerifierRegistry.Create;
begin
  FLock := TCriticalSection.Create;
  FMap := TDictionary<String, IECVarBaseVerifier>.Create;
  FEnabled := True;
end;

class destructor TVarBaseVerifierRegistry.Destroy;
begin
  FMap.Free;
  FLock.Free;
end;

class function TVarBaseVerifierRegistry.KeyOf(const AOrder: TBigInteger): String;
begin
  Result := AOrder.ToString(16);
end;

class procedure TVarBaseVerifierRegistry.Register(const AOrder: TBigInteger;
  const AVerifier: IECVarBaseVerifier);
begin
  FLock.Acquire;
  try
    FMap.AddOrSetValue(KeyOf(AOrder), AVerifier);
  finally
    FLock.Release;
  end;
end;

class function TVarBaseVerifierRegistry.TryGet(const AOrder: TBigInteger;
  out AVerifier: IECVarBaseVerifier): Boolean;
begin
  if not FEnabled then
    Exit(False);
  FLock.Acquire;
  try
    Result := FMap.TryGetValue(KeyOf(AOrder), AVerifier);
  finally
    FLock.Release;
  end;
end;

end.
