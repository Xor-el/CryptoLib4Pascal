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

unit ClpScalarFieldRegistry;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  SyncObjs,
  Generics.Collections,
  ClpBigInteger,
  ClpIScalarFieldOps;

type
  /// <summary>Process-wide registry of scalar-field ops keyed by group order, so
  /// the ECDSA signer can look up a constant-time nonce-math path for a curve
  /// without depending on the curve's concrete type. Absence means "use the
  /// generic BigInteger path".</summary>
  TScalarFieldRegistry = class sealed(TObject)
  strict private
    class var FLock: TCriticalSection;
    class var FMap: TDictionary<String, IScalarFieldOps>;
    class var FEnabled: Boolean;
    class function KeyOf(const AOrder: TBigInteger): String; static; inline;
  public
    class constructor Create;
    class destructor Destroy;
    class procedure Register(const AOrder: TBigInteger; const AOps: IScalarFieldOps); static;
    class function TryGet(const AOrder: TBigInteger; out AOps: IScalarFieldOps): Boolean; static;
    /// <summary>Global switch for the constant-time scalar-field path; when False
    /// callers take their generic fallback. Default True.</summary>
    class property Enabled: Boolean read FEnabled write FEnabled;
  end;

implementation

{ TScalarFieldRegistry }

class constructor TScalarFieldRegistry.Create;
begin
  FLock := TCriticalSection.Create;
  FMap := TDictionary<String, IScalarFieldOps>.Create;
  FEnabled := True;
end;

class destructor TScalarFieldRegistry.Destroy;
begin
  FMap.Free;
  FLock.Free;
end;

class function TScalarFieldRegistry.KeyOf(const AOrder: TBigInteger): String;
begin
  Result := AOrder.ToString(16);
end;

class procedure TScalarFieldRegistry.Register(const AOrder: TBigInteger;
  const AOps: IScalarFieldOps);
begin
  FLock.Acquire;
  try
    FMap.AddOrSetValue(KeyOf(AOrder), AOps);
  finally
    FLock.Release;
  end;
end;

class function TScalarFieldRegistry.TryGet(const AOrder: TBigInteger;
  out AOps: IScalarFieldOps): Boolean;
begin
  if not FEnabled then
    Exit(False);
  FLock.Acquire;
  try
    Result := FMap.TryGetValue(KeyOf(AOrder), AOps);
  finally
    FLock.Release;
  end;
end;

end.
