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

unit ClpCryptoLibConfig;

{$I ..\Include\CryptoLib.inc}

interface

uses
  ClpNullable,
  ClpCryptoLibTypes;

resourcestring
  SMaxPolicyNodesNotPositive = 'the valid policy tree node ceiling must be greater than zero, got %d';

type
  /// <summary>
  /// The X.509 and certification path settings, reached as <c>TCryptoLibConfig.X509</c>.
  /// </summary>
  TX509Config = class sealed(TObject)

  strict private
  const
    /// <summary>
    /// The ceiling on valid-policy-tree nodes, bounding the tree growth a crafted chain can
    /// provoke during RFC 5280 6.1.3 (d) policy processing. Read it through
    /// <see cref="MaxPolicyNodes" />, which reports it whenever nothing has been set.
    /// </summary>
    DefaultMaxPolicyNodes = Int32(8192);

  class var
    /// <summary>
    /// Nullable rather than sentinel-encoded, so no legal value has to double as "unset". The
    /// Boolean settings need no such treatment: unset and False are indistinguishable to a caller.
    /// </summary>
    FMaxPolicyNodes: TNullable<Int32>;
    FSgp22NameConstraints: Boolean;
    FAllowLenientRfc822Name: Boolean;
    FAllowLenientIPAddressMask: Boolean;

    class function GetMaxPolicyNodes: Int32; static;
    class procedure SetMaxPolicyNodes(AValue: Int32); static;
    class function GetSgp22NameConstraints: Boolean; static;
    class procedure SetSgp22NameConstraints(AValue: Boolean); static;
    class function GetAllowLenientRfc822Name: Boolean; static;
    class procedure SetAllowLenientRfc822Name(AValue: Boolean); static;
    class function GetAllowLenientIPAddressMask: Boolean; static;
    class procedure SetAllowLenientIPAddressMask(AValue: Boolean); static;

  public
    /// <summary>Restores this area's settings to their defaults.</summary>
    class procedure ResetToDefaults(); static;

    /// <summary>
    /// The ceiling on valid-policy-tree nodes. Assigning less than one raises; call
    /// <see cref="ResetToDefaults" /> to go back to the default.
    /// </summary>
    class property MaxPolicyNodes: Int32 read GetMaxPolicyNodes write SetMaxPolicyNodes;

    /// <summary>
    /// Applies the relaxed directoryName matching that eUICC certificate profiles expect, in place
    /// of the RFC 5280 4.2.1.10 subtree rules. Off by default.
    /// </summary>
    class property Sgp22NameConstraints: Boolean read GetSgp22NameConstraints
      write SetSgp22NameConstraints;

    /// <summary>
    /// Accepts an rfc822Name constraint whose form RFC 5280 4.2.1.10 does not permit, rather than
    /// rejecting it outright. Off by default.
    /// </summary>
    class property AllowLenientRfc822Name: Boolean read GetAllowLenientRfc822Name
      write SetAllowLenientRfc822Name;

    /// <summary>
    /// Salvages a non-contiguous iPAddress constraint mask by rounding it to the most restrictive
    /// contiguous mask for its context, instead of rejecting it. Off by default; salvaging can only
    /// tighten validation.
    /// </summary>
    class property AllowLenientIPAddressMask: Boolean read GetAllowLenientIPAddressMask
      write SetAllowLenientIPAddressMask;
  end;

  /// <summary>Class reference, so the settings are reachable without an instance.</summary>
  TCryptoLibConfigX509 = class of TX509Config;

  /// <summary>
  /// Process-wide switches that relax or tighten what the library accepts, grouped by area.
  /// </summary>
  /// <remarks>
  /// Reached through an area rather than a flat list: <c>TCryptoLibConfig.X509.MaxPolicyNodes</c>.
  /// Grouping keeps settings that share a short name in different areas from colliding.
  ///
  /// These are global: changing one affects every thread, and a value set by one caller is seen by
  /// the next. Anything that should vary per operation belongs on that operation's parameters (for
  /// path validation, <c>IPkixParameters</c>) rather than here. A test that changes one MUST call
  /// <see cref="ResetToDefaults" /> in its TearDown, or it silently changes the behaviour of every
  /// test that runs after it.
  /// </remarks>
  TCryptoLibConfig = class sealed(TObject)

  strict private
    class function GetX509: TCryptoLibConfigX509; static;

  public
    /// <summary>Restores every area's settings to their defaults.</summary>
    class procedure ResetToDefaults(); static;

    /// <summary>The X.509 and certification path settings.</summary>
    class property X509: TCryptoLibConfigX509 read GetX509;
  end;

implementation

{ TX509Config }

class procedure TX509Config.ResetToDefaults();
begin
  FMaxPolicyNodes := TNullable<Int32>.None;
  FSgp22NameConstraints := False;
  FAllowLenientRfc822Name := False;
  FAllowLenientIPAddressMask := False;
end;

class function TX509Config.GetMaxPolicyNodes: Int32;
begin
  if FMaxPolicyNodes.HasValue then
    Result := FMaxPolicyNodes.Value
  else
    Result := DefaultMaxPolicyNodes;
end;

class procedure TX509Config.SetMaxPolicyNodes(AValue: Int32);
begin
  // refuse a ceiling no chain could satisfy rather than quietly reverting to the default
  if AValue < 1 then
    raise EArgumentCryptoLibException.CreateResFmt(@SMaxPolicyNodesNotPositive, [AValue]);

  FMaxPolicyNodes := TNullable<Int32>.Some(AValue);
end;

class function TX509Config.GetSgp22NameConstraints: Boolean;
begin
  Result := FSgp22NameConstraints;
end;

class procedure TX509Config.SetSgp22NameConstraints(AValue: Boolean);
begin
  FSgp22NameConstraints := AValue;
end;

class function TX509Config.GetAllowLenientRfc822Name: Boolean;
begin
  Result := FAllowLenientRfc822Name;
end;

class procedure TX509Config.SetAllowLenientRfc822Name(AValue: Boolean);
begin
  FAllowLenientRfc822Name := AValue;
end;

class function TX509Config.GetAllowLenientIPAddressMask: Boolean;
begin
  Result := FAllowLenientIPAddressMask;
end;

class procedure TX509Config.SetAllowLenientIPAddressMask(AValue: Boolean);
begin
  FAllowLenientIPAddressMask := AValue;
end;

{ TCryptoLibConfig }

class function TCryptoLibConfig.GetX509: TCryptoLibConfigX509;
begin
  Result := TX509Config;
end;

class procedure TCryptoLibConfig.ResetToDefaults();
begin
  TX509Config.ResetToDefaults();
end;

end.
