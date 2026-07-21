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
  SConfigCeilingNotPositive = 'the %s must be greater than zero, got %d';
  SConfigValueNegative = 'the %s must not be negative, got %d';

type
  /// <summary>
  /// The ASN.1 parsing settings, reached as <c>TCryptoLibConfig.Asn1</c>.
  /// </summary>
  TAsn1Config = class sealed(TObject)

  strict private
  const
    /// <summary>
    /// Recursion budget applied to constructed-object nesting when <see cref="MaxDepth" /> is
    /// unset. Read it through <see cref="MaxDepth" />, which reports it whenever nothing has
    /// been set.
    /// </summary>
    DefaultMaxDepth = Int32(64);
    /// <summary>
    /// Byte ceiling applied to a stream whose length cannot be inferred, when
    /// <see cref="MaxLimit" /> is unset. Unbounded by default.
    /// </summary>
    DefaultMaxLimit = High(Int32);

  class var
    FAllowUnsafeInteger: Boolean;
    FMaxDepth: TNullable<Int32>;
    FMaxLimit: TNullable<Int32>;

    class function GetAllowUnsafeInteger: Boolean; static;
    class procedure SetAllowUnsafeInteger(AValue: Boolean); static;
    class function GetMaxDepth: Int32; static;
    class procedure SetMaxDepth(AValue: Int32); static;
    class function GetMaxLimit: Int32; static;
    class procedure SetMaxLimit(AValue: Int32); static;

  public
    /// <summary>Restores this area's settings to their defaults.</summary>
    class procedure ResetToDefaults(); static;

    /// <summary>
    /// Accepts a DER INTEGER carrying redundant leading sign bytes, which the encoding rules
    /// forbid, rather than rejecting it outright. Off by default.
    /// </summary>
    class property AllowUnsafeInteger: Boolean read GetAllowUnsafeInteger
      write SetAllowUnsafeInteger;

    /// <summary>
    /// The ceiling on constructed-object nesting, bounding the recursion a crafted stream can
    /// provoke. A negative value is tolerated and clamped to zero where it is applied; call
    /// <see cref="ResetToDefaults" /> to go back to the default.
    /// </summary>
    class property MaxDepth: Int32 read GetMaxDepth write SetMaxDepth;

    /// <summary>
    /// The byte ceiling applied when a stream's length cannot be inferred, bounding an
    /// unbounded read. A negative value is tolerated and clamped to zero where it is applied;
    /// call <see cref="ResetToDefaults" /> to go back to the default (unbounded).
    /// </summary>
    class property MaxLimit: Int32 read GetMaxLimit write SetMaxLimit;
  end;

  /// <summary>Class reference, so the settings are reachable without an instance.</summary>
  TCryptoLibConfigAsn1 = class of TAsn1Config;

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
    FAllowNonDerTbsCertificate: Boolean;

    class function GetMaxPolicyNodes: Int32; static;
    class procedure SetMaxPolicyNodes(AValue: Int32); static;
    class function GetSgp22NameConstraints: Boolean; static;
    class procedure SetSgp22NameConstraints(AValue: Boolean); static;
    class function GetAllowLenientRfc822Name: Boolean; static;
    class procedure SetAllowLenientRfc822Name(AValue: Boolean); static;
    class function GetAllowLenientIPAddressMask: Boolean; static;
    class procedure SetAllowLenientIPAddressMask(AValue: Boolean); static;
    class function GetAllowNonDerTbsCertificate: Boolean; static;
    class procedure SetAllowNonDerTbsCertificate(AValue: Boolean); static;

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

    /// <summary>
    /// Accepts a TBSCertificate whose fields are not in strict DER form, rather than rejecting it.
    /// Off by default.
    /// </summary>
    class property AllowNonDerTbsCertificate: Boolean read GetAllowNonDerTbsCertificate
      write SetAllowNonDerTbsCertificate;
  end;

  /// <summary>Class reference, so the settings are reachable without an instance.</summary>
  TCryptoLibConfigX509 = class of TX509Config;

  /// <summary>
  /// The Diffie-Hellman settings, reached as <c>TCryptoLibConfig.DH</c>.
  /// </summary>
  TDHConfig = class sealed(TObject)

  strict private
  const
    /// <summary>
    /// The DH modulus bit-length ceiling applied to externally supplied keys when
    /// <see cref="MaxSize" /> is unset.
    /// </summary>
    DefaultMaxSize = Int32(16384);

  class var
    FMaxSize: TNullable<Int32>;

    class function GetMaxSize: Int32; static;
    class procedure SetMaxSize(AValue: Int32); static;

  public
    /// <summary>Restores this area's settings to their defaults.</summary>
    class procedure ResetToDefaults(); static;

    /// <summary>
    /// The maximum DH modulus bit length accepted for externally supplied keys. Assigning less
    /// than one raises; call <see cref="ResetToDefaults" /> to go back to the default.
    /// </summary>
    class property MaxSize: Int32 read GetMaxSize write SetMaxSize;
  end;

  /// <summary>Class reference, so the settings are reachable without an instance.</summary>
  TCryptoLibConfigDH = class of TDHConfig;

  /// <summary>
  /// The DSA settings, reached as <c>TCryptoLibConfig.Dsa</c>.
  /// </summary>
  TDsaConfig = class sealed(TObject)

  strict private
  const
    /// <summary>
    /// The DSA modulus bit-length ceiling applied to externally supplied keys when
    /// <see cref="MaxSize" /> is unset.
    /// </summary>
    DefaultMaxSize = Int32(16384);

  class var
    FMaxSize: TNullable<Int32>;

    class function GetMaxSize: Int32; static;
    class procedure SetMaxSize(AValue: Int32); static;

  public
    /// <summary>Restores this area's settings to their defaults.</summary>
    class procedure ResetToDefaults(); static;

    /// <summary>
    /// The maximum DSA modulus bit length accepted for externally supplied keys. Assigning less
    /// than one raises; call <see cref="ResetToDefaults" /> to go back to the default.
    /// </summary>
    class property MaxSize: Int32 read GetMaxSize write SetMaxSize;
  end;

  /// <summary>Class reference, so the settings are reachable without an instance.</summary>
  TCryptoLibConfigDsa = class of TDsaConfig;

  /// <summary>
  /// The RSA settings, reached as <c>TCryptoLibConfig.Rsa</c>.
  /// </summary>
  TRsaConfig = class sealed(TObject)

  strict private
  const
    /// <summary>
    /// The RSA modulus bit-length ceiling applied to externally supplied keys when
    /// <see cref="MaxSize" /> is unset.
    /// </summary>
    DefaultMaxSize = Int32(16384);

  class var
    FMaxSize: TNullable<Int32>;
    /// <summary>
    /// Nullable rather than sentinel-encoded: the effective default is a bit-length-dependent
    /// count computed by the caller, and <c>0</c> is a legal value that disables the test, so
    /// "unset" cannot be folded onto any integer.
    /// </summary>
    FMaxMRTests: TNullable<Int32>;

    class function GetMaxSize: Int32; static;
    class procedure SetMaxSize(AValue: Int32); static;
    class function GetMaxMRTests: TNullable<Int32>; static;
    class procedure SetMaxMRTests(const AValue: TNullable<Int32>); static;

  public
    /// <summary>Restores this area's settings to their defaults.</summary>
    class procedure ResetToDefaults(); static;

    /// <summary>
    /// The maximum RSA modulus bit length accepted for externally supplied keys. Assigning less
    /// than one raises; call <see cref="ResetToDefaults" /> to go back to the default.
    /// </summary>
    class property MaxSize: Int32 read GetMaxSize write SetMaxSize;

    /// <summary>
    /// The enhanced Miller-Rabin iteration count for externally supplied moduli. When unset a
    /// bit-length-dependent count is used; <c>0</c> disables composite testing. Assigning a
    /// negative value raises.
    /// </summary>
    class property MaxMRTests: TNullable<Int32> read GetMaxMRTests write SetMaxMRTests;
  end;

  /// <summary>Class reference, so the settings are reachable without an instance.</summary>
  TCryptoLibConfigRsa = class of TRsaConfig;

  /// <summary>
  /// The elliptic-curve settings, reached as <c>TCryptoLibConfig.EC</c>. The prime-field (Fp)
  /// and binary-field (F2m) ceilings are separate, mirroring the reference's <c>EC.Fp_*</c> /
  /// <c>EC.F2m_*</c> keys.
  /// </summary>
  TECConfig = class sealed(TObject)

  strict private
  const
    /// <summary>Prime-field bit-length ceiling when <see cref="FpMaxSize" /> is unset (2 * 521).</summary>
    DefaultFpMaxSize = Int32(1042);
    /// <summary>Binary-field degree ceiling when <see cref="F2mMaxSize" /> is unset (2 * 571).</summary>
    DefaultF2mMaxSize = Int32(1142);
    /// <summary>Primality certainty when <see cref="FpCertainty" /> is unset.</summary>
    DefaultFpCertainty = Int32(100);

  class var
    FFpMaxSize: TNullable<Int32>;
    FF2mMaxSize: TNullable<Int32>;
    FFpCertainty: TNullable<Int32>;

    class function GetFpMaxSize: Int32; static;
    class procedure SetFpMaxSize(AValue: Int32); static;
    class function GetF2mMaxSize: Int32; static;
    class procedure SetF2mMaxSize(AValue: Int32); static;
    class function GetFpCertainty: Int32; static;
    class procedure SetFpCertainty(AValue: Int32); static;

  public
    /// <summary>Restores this area's settings to their defaults.</summary>
    class procedure ResetToDefaults(); static;

    /// <summary>
    /// The maximum bit length accepted for a prime-field (Fp) curve. Assigning less than one
    /// raises; call <see cref="ResetToDefaults" /> to go back to the default.
    /// </summary>
    class property FpMaxSize: Int32 read GetFpMaxSize write SetFpMaxSize;

    /// <summary>
    /// The maximum degree accepted for a binary-field (F2m) curve. Assigning less than one
    /// raises; call <see cref="ResetToDefaults" /> to go back to the default.
    /// </summary>
    class property F2mMaxSize: Int32 read GetF2mMaxSize write SetF2mMaxSize;

    /// <summary>
    /// The primality certainty used when validating a prime-field (Fp) curve. Zero is legal;
    /// assigning a negative value raises.
    /// </summary>
    class property FpCertainty: Int32 read GetFpCertainty write SetFpCertainty;
  end;

  /// <summary>Class reference, so the settings are reachable without an instance.</summary>
  TCryptoLibConfigEC = class of TECConfig;

  /// <summary>
  /// The password-based encryption settings, reached as <c>TCryptoLibConfig.Pbe</c>.
  /// </summary>
  TPbeConfig = class sealed(TObject)

  strict private
  const
    /// <summary>Iteration-count ceiling when <see cref="MaxIterationCount" /> is unset.</summary>
    DefaultMaxIterationCount = Int32(5000000);

  class var
    FMaxIterationCount: TNullable<Int32>;

    class function GetMaxIterationCount: Int32; static;
    class procedure SetMaxIterationCount(AValue: Int32); static;

  public
    /// <summary>Restores this area's settings to their defaults.</summary>
    class procedure ResetToDefaults(); static;

    /// <summary>
    /// The ceiling on the PBE iteration count, bounding the work a crafted parameter set can
    /// demand. Assigning less than one raises; call <see cref="ResetToDefaults" /> to go back to
    /// the default.
    /// </summary>
    class property MaxIterationCount: Int32 read GetMaxIterationCount write SetMaxIterationCount;
  end;

  /// <summary>Class reference, so the settings are reachable without an instance.</summary>
  TCryptoLibConfigPbe = class of TPbeConfig;

  /// <summary>
  /// The PKCS#12 settings, reached as <c>TCryptoLibConfig.Pkcs12</c>.
  /// </summary>
  TPkcs12Config = class sealed(TObject)

  strict private
  const
    /// <summary>Iteration-count ceiling when <see cref="MaxIterationCount" /> is unset.</summary>
    DefaultMaxIterationCount = Int32(5000000);

  class var
    FMaxIterationCount: TNullable<Int32>;
    FIgnoreUselessPassword: Boolean;

    class function GetMaxIterationCount: Int32; static;
    class procedure SetMaxIterationCount(AValue: Int32); static;
    class function GetIgnoreUselessPassword: Boolean; static;
    class procedure SetIgnoreUselessPassword(AValue: Boolean); static;

  public
    /// <summary>Restores this area's settings to their defaults.</summary>
    class procedure ResetToDefaults(); static;

    /// <summary>
    /// The ceiling on the PKCS#12 iteration count, bounding the work a crafted keystore can
    /// demand. Assigning less than one raises; call <see cref="ResetToDefaults" /> to go back to
    /// the default.
    /// </summary>
    class property MaxIterationCount: Int32 read GetMaxIterationCount write SetMaxIterationCount;

    /// <summary>
    /// Loads a PKCS#12 keystore whose integrity is not password-protected without demanding a
    /// password, rather than rejecting it. Off by default.
    /// </summary>
    class property IgnoreUselessPassword: Boolean read GetIgnoreUselessPassword
      write SetIgnoreUselessPassword;
  end;

  /// <summary>Class reference, so the settings are reachable without an instance.</summary>
  TCryptoLibConfigPkcs12 = class of TPkcs12Config;

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
    class function GetAsn1: TCryptoLibConfigAsn1; static;
    class function GetX509: TCryptoLibConfigX509; static;
    class function GetDH: TCryptoLibConfigDH; static;
    class function GetDsa: TCryptoLibConfigDsa; static;
    class function GetRsa: TCryptoLibConfigRsa; static;
    class function GetEC: TCryptoLibConfigEC; static;
    class function GetPbe: TCryptoLibConfigPbe; static;
    class function GetPkcs12: TCryptoLibConfigPkcs12; static;

  public
    /// <summary>Restores every area's settings to their defaults.</summary>
    class procedure ResetToDefaults(); static;

    /// <summary>The ASN.1 parsing settings.</summary>
    class property Asn1: TCryptoLibConfigAsn1 read GetAsn1;

    /// <summary>The X.509 and certification path settings.</summary>
    class property X509: TCryptoLibConfigX509 read GetX509;

    /// <summary>The Diffie-Hellman settings.</summary>
    class property DH: TCryptoLibConfigDH read GetDH;

    /// <summary>The DSA settings.</summary>
    class property Dsa: TCryptoLibConfigDsa read GetDsa;

    /// <summary>The RSA settings.</summary>
    class property Rsa: TCryptoLibConfigRsa read GetRsa;

    /// <summary>The elliptic-curve settings.</summary>
    class property EC: TCryptoLibConfigEC read GetEC;

    /// <summary>The password-based encryption settings.</summary>
    class property Pbe: TCryptoLibConfigPbe read GetPbe;

    /// <summary>The PKCS#12 settings.</summary>
    class property Pkcs12: TCryptoLibConfigPkcs12 read GetPkcs12;
  end;

implementation

{ TAsn1Config }

class procedure TAsn1Config.ResetToDefaults();
begin
  FAllowUnsafeInteger := False;
  FMaxDepth := TNullable<Int32>.None;
  FMaxLimit := TNullable<Int32>.None;
end;

class function TAsn1Config.GetAllowUnsafeInteger: Boolean;
begin
  Result := FAllowUnsafeInteger;
end;

class procedure TAsn1Config.SetAllowUnsafeInteger(AValue: Boolean);
begin
  FAllowUnsafeInteger := AValue;
end;

class function TAsn1Config.GetMaxDepth: Int32;
begin
  if FMaxDepth.HasValue then
    Result := FMaxDepth.Value
  else
    Result := DefaultMaxDepth;
end;

class procedure TAsn1Config.SetMaxDepth(AValue: Int32);
begin
  // a negative value is clamped to zero at the point of use
  FMaxDepth := TNullable<Int32>.Some(AValue);
end;

class function TAsn1Config.GetMaxLimit: Int32;
begin
  if FMaxLimit.HasValue then
    Result := FMaxLimit.Value
  else
    Result := DefaultMaxLimit;
end;

class procedure TAsn1Config.SetMaxLimit(AValue: Int32);
begin
  // a negative value is clamped to zero at the point of use
  FMaxLimit := TNullable<Int32>.Some(AValue);
end;

{ TX509Config }

class procedure TX509Config.ResetToDefaults();
begin
  FMaxPolicyNodes := TNullable<Int32>.None;
  FSgp22NameConstraints := False;
  FAllowLenientRfc822Name := False;
  FAllowLenientIPAddressMask := False;
  FAllowNonDerTbsCertificate := False;
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

class function TX509Config.GetAllowNonDerTbsCertificate: Boolean;
begin
  Result := FAllowNonDerTbsCertificate;
end;

class procedure TX509Config.SetAllowNonDerTbsCertificate(AValue: Boolean);
begin
  FAllowNonDerTbsCertificate := AValue;
end;

{ TDHConfig }

class procedure TDHConfig.ResetToDefaults();
begin
  FMaxSize := TNullable<Int32>.None;
end;

class function TDHConfig.GetMaxSize: Int32;
begin
  if FMaxSize.HasValue then
    Result := FMaxSize.Value
  else
    Result := DefaultMaxSize;
end;

class procedure TDHConfig.SetMaxSize(AValue: Int32);
begin
  if AValue < 1 then
    raise EArgumentCryptoLibException.CreateResFmt(@SConfigCeilingNotPositive,
      ['maximum DH modulus bit length', AValue]);

  FMaxSize := TNullable<Int32>.Some(AValue);
end;

{ TDsaConfig }

class procedure TDsaConfig.ResetToDefaults();
begin
  FMaxSize := TNullable<Int32>.None;
end;

class function TDsaConfig.GetMaxSize: Int32;
begin
  if FMaxSize.HasValue then
    Result := FMaxSize.Value
  else
    Result := DefaultMaxSize;
end;

class procedure TDsaConfig.SetMaxSize(AValue: Int32);
begin
  if AValue < 1 then
    raise EArgumentCryptoLibException.CreateResFmt(@SConfigCeilingNotPositive,
      ['maximum DSA modulus bit length', AValue]);

  FMaxSize := TNullable<Int32>.Some(AValue);
end;

{ TRsaConfig }

class procedure TRsaConfig.ResetToDefaults();
begin
  FMaxSize := TNullable<Int32>.None;
  FMaxMRTests := TNullable<Int32>.None;
end;

class function TRsaConfig.GetMaxSize: Int32;
begin
  if FMaxSize.HasValue then
    Result := FMaxSize.Value
  else
    Result := DefaultMaxSize;
end;

class procedure TRsaConfig.SetMaxSize(AValue: Int32);
begin
  if AValue < 1 then
    raise EArgumentCryptoLibException.CreateResFmt(@SConfigCeilingNotPositive,
      ['maximum RSA modulus bit length', AValue]);

  FMaxSize := TNullable<Int32>.Some(AValue);
end;

class function TRsaConfig.GetMaxMRTests: TNullable<Int32>;
begin
  Result := FMaxMRTests;
end;

class procedure TRsaConfig.SetMaxMRTests(const AValue: TNullable<Int32>);
begin
  if AValue.HasValue and (AValue.Value < 0) then
    raise EArgumentCryptoLibException.CreateResFmt(@SConfigValueNegative,
      ['RSA Miller-Rabin iteration count', AValue.Value]);

  FMaxMRTests := AValue;
end;

{ TECConfig }

class procedure TECConfig.ResetToDefaults();
begin
  FFpMaxSize := TNullable<Int32>.None;
  FF2mMaxSize := TNullable<Int32>.None;
  FFpCertainty := TNullable<Int32>.None;
end;

class function TECConfig.GetFpMaxSize: Int32;
begin
  if FFpMaxSize.HasValue then
    Result := FFpMaxSize.Value
  else
    Result := DefaultFpMaxSize;
end;

class procedure TECConfig.SetFpMaxSize(AValue: Int32);
begin
  if AValue < 1 then
    raise EArgumentCryptoLibException.CreateResFmt(@SConfigCeilingNotPositive,
      ['maximum prime-field curve bit length', AValue]);

  FFpMaxSize := TNullable<Int32>.Some(AValue);
end;

class function TECConfig.GetF2mMaxSize: Int32;
begin
  if FF2mMaxSize.HasValue then
    Result := FF2mMaxSize.Value
  else
    Result := DefaultF2mMaxSize;
end;

class procedure TECConfig.SetF2mMaxSize(AValue: Int32);
begin
  if AValue < 1 then
    raise EArgumentCryptoLibException.CreateResFmt(@SConfigCeilingNotPositive,
      ['maximum binary-field curve degree', AValue]);

  FF2mMaxSize := TNullable<Int32>.Some(AValue);
end;

class function TECConfig.GetFpCertainty: Int32;
begin
  if FFpCertainty.HasValue then
    Result := FFpCertainty.Value
  else
    Result := DefaultFpCertainty;
end;

class procedure TECConfig.SetFpCertainty(AValue: Int32);
begin
  if AValue < 0 then
    raise EArgumentCryptoLibException.CreateResFmt(@SConfigValueNegative,
      ['prime-field curve primality certainty', AValue]);

  FFpCertainty := TNullable<Int32>.Some(AValue);
end;

{ TPbeConfig }

class procedure TPbeConfig.ResetToDefaults();
begin
  FMaxIterationCount := TNullable<Int32>.None;
end;

class function TPbeConfig.GetMaxIterationCount: Int32;
begin
  if FMaxIterationCount.HasValue then
    Result := FMaxIterationCount.Value
  else
    Result := DefaultMaxIterationCount;
end;

class procedure TPbeConfig.SetMaxIterationCount(AValue: Int32);
begin
  if AValue < 1 then
    raise EArgumentCryptoLibException.CreateResFmt(@SConfigCeilingNotPositive,
      ['maximum PBE iteration count', AValue]);

  FMaxIterationCount := TNullable<Int32>.Some(AValue);
end;

{ TPkcs12Config }

class procedure TPkcs12Config.ResetToDefaults();
begin
  FMaxIterationCount := TNullable<Int32>.None;
  FIgnoreUselessPassword := False;
end;

class function TPkcs12Config.GetMaxIterationCount: Int32;
begin
  if FMaxIterationCount.HasValue then
    Result := FMaxIterationCount.Value
  else
    Result := DefaultMaxIterationCount;
end;

class procedure TPkcs12Config.SetMaxIterationCount(AValue: Int32);
begin
  if AValue < 1 then
    raise EArgumentCryptoLibException.CreateResFmt(@SConfigCeilingNotPositive,
      ['maximum PKCS#12 iteration count', AValue]);

  FMaxIterationCount := TNullable<Int32>.Some(AValue);
end;

class function TPkcs12Config.GetIgnoreUselessPassword: Boolean;
begin
  Result := FIgnoreUselessPassword;
end;

class procedure TPkcs12Config.SetIgnoreUselessPassword(AValue: Boolean);
begin
  FIgnoreUselessPassword := AValue;
end;

{ TCryptoLibConfig }

class function TCryptoLibConfig.GetAsn1: TCryptoLibConfigAsn1;
begin
  Result := TAsn1Config;
end;

class function TCryptoLibConfig.GetX509: TCryptoLibConfigX509;
begin
  Result := TX509Config;
end;

class function TCryptoLibConfig.GetDH: TCryptoLibConfigDH;
begin
  Result := TDHConfig;
end;

class function TCryptoLibConfig.GetDsa: TCryptoLibConfigDsa;
begin
  Result := TDsaConfig;
end;

class function TCryptoLibConfig.GetRsa: TCryptoLibConfigRsa;
begin
  Result := TRsaConfig;
end;

class function TCryptoLibConfig.GetEC: TCryptoLibConfigEC;
begin
  Result := TECConfig;
end;

class function TCryptoLibConfig.GetPbe: TCryptoLibConfigPbe;
begin
  Result := TPbeConfig;
end;

class function TCryptoLibConfig.GetPkcs12: TCryptoLibConfigPkcs12;
begin
  Result := TPkcs12Config;
end;

class procedure TCryptoLibConfig.ResetToDefaults();
begin
  TAsn1Config.ResetToDefaults();
  TX509Config.ResetToDefaults();
  TDHConfig.ResetToDefaults();
  TDsaConfig.ResetToDefaults();
  TRsaConfig.ResetToDefaults();
  TECConfig.ResetToDefaults();
  TPbeConfig.ResetToDefaults();
  TPkcs12Config.ResetToDefaults();
end;

end.
