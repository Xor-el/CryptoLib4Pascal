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

{ Paired constant-time subjects and their known-leaky controls, each wrapped as a
  TDudectOp so both legs (dudect timing, ctgrind/Valgrind taint) drive the exact
  same call shape and only the implementation differs.

    #  Subject (must stay clean)                Control (must fire)
    1  TX25519 ladder                           (none - clean baseline)
    2  secp256r1 default (TFpCTMultiplier value-type) TWNafL2RMultiplier, same curve
    3  sect283k1 default (F2m Montgomery ladder)TWTauNafMultiplier, same curve
    4  TAesBitSlicedEngine block                TAesEngine (T-table) block
    5  TBasicGcmMultiplier (ImplMul64) GHASH    TTables4kGcmMultiplier GHASH
    6  ModOddInverse (safegcd)                  ModOddInverseVar (variable-time)

  Varied secret per pair: EC scalar (2,3), AES key (4), the multiplied block (5),
  the inverted value (6), the ladder scalar (1). Class 0 = a fixed secret, class 1
  = a fresh random secret (drawn from a per-op deterministic stream).

  The two legs split the controls by leak TYPE, and each subject is proven clean by
  whichever leg attributes cleanly:

    * dudect (timing) proves the CONTROL-FLOW / iteration-count leaks: wNAF (2),
      tau-NAF (3) and variable-time Euclid (6) separate by a large mean, so their
      controls fire; the CT subjects (fixed window, F2m ladder, safegcd core) stay
      clean. AES (4) and GHASH (5) run as clean SUBJECTS ONLY under dudect - their
      leaky counterparts are table access-pattern (cache) leaks that stay below
      dudect's noise floor on a hot-L1 microbenchmark.

    * Valgrind/ctgrind (taint) proves the MEMORY-ACCESS leaks deterministically:
      the T-table AES and 4k-table GHASH controls index tables by secret-derived
      bytes and fire; X25519, bit-sliced AES and ImplMul64 GHASH stay clean.
      Poisoning is exposed only for these byte-clean families, where the secret is
      a contiguous buffer feeding the routine directly. EC and modular inverse are
      NOT taint-checked: byte-poisoning their scalar would flag the
      non-constant-time TBigInteger front-end rather than the multiplier/inverter
      (a known ctgrind limitation), which is exactly why their controls live in the
      dudect leg. }

unit CtSubjects;

{$IFDEF FPC}
{$MODE DELPHI}
{$WARNINGS OFF}
{$ENDIF FPC}

{$SCOPEDENUMS ON}

interface

uses
  CtDudect;

type
  { Builds one measured op for a given deterministic seed. An interface (not a bare
    function pointer) so a factory can carry construction state - e.g. an EC curve
    and multiplier kind - without a closure (Delphi mode has no anonymous methods). }
  ICtOpFactory = interface
    ['{4B8F1C2A-7D3E-4A9B-8C15-6E2F0A9D4B73}']
    function Make(ASeed: UInt64): TDudectOp;
  end;

  { One dudect registry row: a subject and (optionally) its paired leaky control,
    plus the per-row sampling budget (op cost spans microseconds to milliseconds). }
  TCtRow = record
    Name: string;
    SubjectLabel: string;
    ControlLabel: string;         // '' when the row has no control
    SubjectFactory: ICtOpFactory;
    ControlFactory: ICtOpFactory;  // nil when the row has no control
    Cfg: TDudectConfig;
  end;

  TCtRowArray = array of TCtRow;

  { One Valgrind target. ExpectLeak = True  -> known-leaky control, MUST fire;
                          ExpectLeak = False -> CT subject, MUST stay clean. }
  TCtVgTarget = record
    Name: string;
    Factory: ICtOpFactory;
    ExpectLeak: Boolean;
  end;

  TCtVgTargetArray = array of TCtVgTarget;

function GetDudectRows: TCtRowArray;
function GetValgrindTargets: TCtVgTargetArray;

implementation

uses
  CtOps,
  SysUtils;

type
  // Plain per-op constructor; wrapped by TFnFactory into an ICtOpFactory so the
  // stateless subjects need no boilerplate factory class.
  TCtOpFactory = function(ASeed: UInt64): TDudectOp;

  TFnFactory = class(TInterfacedObject, ICtOpFactory)
  strict private
    FFn: TCtOpFactory;
  public
    constructor Create(AFn: TCtOpFactory);
    function Make(ASeed: UInt64): TDudectOp;
  end;

constructor TFnFactory.Create(AFn: TCtOpFactory);
begin
  inherited Create;
  FFn := AFn;
end;

function TFnFactory.Make(ASeed: UInt64): TDudectOp;
begin
  Result := FFn(ASeed);
end;

// Wrap a plain op constructor as an ICtOpFactory.
function Fn(AFn: TCtOpFactory): ICtOpFactory;
begin
  Result := TFnFactory.Create(AFn);
end;

{ ============================== EC factory =============================== }

type
  TEcFactory = class(TInterfacedObject, ICtOpFactory)
  strict private
    FCurveName: string;
    FKind: TEcMulKind;
  public
    constructor Create(const ACurveName: string; AKind: TEcMulKind);
    function Make(ASeed: UInt64): TDudectOp;
  end;

constructor TEcFactory.Create(const ACurveName: string; AKind: TEcMulKind);
begin
  inherited Create;
  FCurveName := ACurveName;
  FKind := AKind;
end;

function TEcFactory.Make(ASeed: UInt64): TDudectOp;
begin
  Result := CtOps.MakeEc(FCurveName, FKind, ASeed);
end;

// Scalar-mult factory for a curve + multiplier kind.
function Ec(const ACurveName: string; AKind: TEcMulKind): ICtOpFactory;
begin
  Result := TEcFactory.Create(ACurveName, AKind);
end;

{ ============================== registries =============================== }

{ Per-row seed = SplitMix64 finalizer over FNV-1a(row name). The name is the row's
  identity (the --row filter matches on it), so this drops manual seed numbering and
  cannot collide silently (a duplicate name is rejected by AddRow). Every run prints
  its per-row seed, so any log reproduces regardless of this policy. }
function SeedForName(const AName: string): UInt64;
var
  LI: Int32;
  LZ: UInt64;
begin
  LZ := UInt64($CBF29CE484222325); // FNV-1a offset basis
  for LI := 1 to System.Length(AName) do
    LZ := (LZ xor UInt64(Ord(AName[LI]))) * UInt64($100000001B3);
  LZ := LZ + UInt64($9E3779B97F4A7C15); // SplitMix64 finalizer
  LZ := (LZ xor (LZ shr 30)) * UInt64($BF58476D1CE4E5B9);
  LZ := (LZ xor (LZ shr 27)) * UInt64($94D049BB133111EB);
  Result := LZ xor (LZ shr 31);
end;

function ExpensiveCfg: TDudectConfig;
begin
  Result := TDudectConfig.Default;
  Result.WarmupSamples := 1000;
  Result.BatchSamples := 2000;
  Result.MaxSamples := 20000;
  Result.MinSamplesForDecision := 6000;
end;

function MediumCfg: TDudectConfig;
begin
  Result := TDudectConfig.Default;
  Result.WarmupSamples := 3000;
  Result.BatchSamples := 10000;
  Result.MaxSamples := 300000;
  Result.MinSamplesForDecision := 40000;
end;

function CheapCfg: TDudectConfig;
begin
  Result := TDudectConfig.Default;
  Result.WarmupSamples := 20000;
  Result.BatchSamples := 100000;
  Result.MaxSamples := 2000000;
  Result.MinSamplesForDecision := 200000;
end;

type
  { Append-only builder for the two registries: rows/targets accrue via AddRow /
    AddTarget, so adding an algo is one call - no SetLength/index bookkeeping and no
    hand-picked row seed to collide. }
  TCtRegistrar = record
  strict private
    FRows: TCtRowArray;
    FTargets: TCtVgTargetArray;
  public
    procedure AddRow(const AName, ASubjectLabel, AControlLabel: string;
      const ASubject, AControl: ICtOpFactory; const ACfg: TDudectConfig);
    procedure AddTarget(const AName: string; const AFactory: ICtOpFactory;
      AExpectLeak: Boolean);
    property Rows: TCtRowArray read FRows;
    property Targets: TCtVgTargetArray read FTargets;
  end;

procedure TCtRegistrar.AddRow(const AName, ASubjectLabel, AControlLabel: string;
  const ASubject, AControl: ICtOpFactory; const ACfg: TDudectConfig);
var
  LI: Int32;
  LCfg: TDudectConfig;
begin
  for LI := 0 to System.Length(FRows) - 1 do
    if FRows[LI].Name = AName then
      raise Exception.CreateFmt('duplicate CT row name: %s', [AName]);
  LI := System.Length(FRows);
  System.SetLength(FRows, LI + 1);
  LCfg := ACfg;
  LCfg.Seed := SeedForName(AName); // name-derived, reproducible, collision-checked
  FRows[LI].Name := AName;
  FRows[LI].SubjectLabel := ASubjectLabel;
  FRows[LI].ControlLabel := AControlLabel;
  FRows[LI].SubjectFactory := ASubject;
  FRows[LI].ControlFactory := AControl;
  FRows[LI].Cfg := LCfg;
end;

procedure TCtRegistrar.AddTarget(const AName: string;
  const AFactory: ICtOpFactory; AExpectLeak: Boolean);
var
  LI: Int32;
begin
  LI := System.Length(FTargets);
  System.SetLength(FTargets, LI + 1);
  FTargets[LI].Name := AName;
  FTargets[LI].Factory := AFactory;
  FTargets[LI].ExpectLeak := AExpectLeak;
end;

function GetDudectRows: TCtRowArray;
var
  LReg: TCtRegistrar;
begin
  LReg.AddRow('X25519', 'X25519 ladder', '',
    Fn(@MakeX25519), nil, MediumCfg);
  LReg.AddRow('X448', 'X448 ladder', '',
    Fn(@MakeX448), nil, MediumCfg);
  // Ed25519/Ed448 whole-sign: byte-seed secret like X25519, but exercising the
  // comb [k]G + scalar arithmetic. Clean-baseline (no variable-time signer to pair).
  LReg.AddRow('Ed25519 sign', 'CT sign', '',
    Fn(@MakeEd25519), nil, MediumCfg);
  LReg.AddRow('Ed448 sign', 'CT sign', '',
    Fn(@MakeEd448), nil, MediumCfg);
  LReg.AddRow('secp256r1 [d]Q', 'value-type CT', 'wNAF (var-time)',
    Ec('secp256r1', TEcMulKind.Default), Ec('secp256r1', TEcMulKind.WNaf),
    ExpensiveCfg);
  LReg.AddRow('sect283k1 [d]Q', 'F2m Montgomery CT', 'WTauNAF (var-time)',
    Ec('sect283k1', TEcMulKind.Default), Ec('sect283k1', TEcMulKind.WTau),
    ExpensiveCfg);
  // AES bit-sliced is a clean-subject demonstration only. The T-table engine's
  // leak is a fine cache-timing effect (key-dependent table lines) that stays
  // below dudect's noise floor on a hot-L1 microbenchmark; it is caught
  // deterministically by the Valgrind/ctgrind leg instead (see GetValgrindTargets).
  LReg.AddRow('AES-128 block', 'Bit-sliced (CT)', '',
    Fn(@MakeAesBitsliced), nil, CheapCfg);
  // GHASH ImplMul64 is a clean-subject demonstration only. Like AES, the 4k-table
  // engine's leak is a table access-pattern effect that stays below dudect's noise
  // floor on a hot-L1 microbenchmark; it is caught deterministically by the
  // Valgrind/ctgrind leg (data-dependent table index) instead.
  LReg.AddRow('GHASH', 'ImplMul64 (CT)', '',
    Fn(@MakeGhashBasic), nil, CheapCfg);
  // #6 tests the safegcd CORE (TMod.ModOddInverse on fixed-width Nats); #7 tests
  // the full TBigInteger WRAPPER - the exact ECDSA signer call k^-1 mod n - so the
  // nonce inverse is measured end-to-end, not just at the core.
  LReg.AddRow('mod-inv (core)', 'safegcd core (CT)', 'variable-time core',
    Fn(@MakeModInvSafe), Fn(@MakeModInvVar), MediumCfg);
  LReg.AddRow('mod-inv (wrapper)', 'safegcd wrapper (CT)', 'variable-time wrapper',
    Fn(@MakeModInvWrapperSafe), Fn(@MakeModInvWrapperVar), MediumCfg);
  // The remaining prime curves also run the value-type CT multiplier; measure each
  // explicitly against its wNAF (variable-time) control.
  LReg.AddRow('secp256k1 [d]Q', 'value-type CT', 'wNAF (var-time)',
    Ec('secp256k1', TEcMulKind.Default), Ec('secp256k1', TEcMulKind.WNaf),
    ExpensiveCfg);
  LReg.AddRow('secp384r1 [d]Q', 'value-type CT', 'wNAF (var-time)',
    Ec('secp384r1', TEcMulKind.Default), Ec('secp384r1', TEcMulKind.WNaf),
    ExpensiveCfg);
  LReg.AddRow('secp521r1 [d]Q', 'value-type CT', 'wNAF (var-time)',
    Ec('secp521r1', TEcMulKind.Default), Ec('secp521r1', TEcMulKind.WNaf),
    ExpensiveCfg);
  // Fixed-base comb [k]G on the reused generator: same CT primitives as [d]Q,
  // paired against wNAF-on-G (variable-time) controls.
  LReg.AddRow('secp256r1 [k]G comb', 'value-type comb (CT)', 'wNAF (var-time)',
    Ec('secp256r1', TEcMulKind.Comb), Ec('secp256r1', TEcMulKind.WNaf),
    ExpensiveCfg);
  LReg.AddRow('secp256k1 [k]G comb', 'value-type comb (CT)', 'wNAF (var-time)',
    Ec('secp256k1', TEcMulKind.Comb), Ec('secp256k1', TEcMulKind.WNaf),
    ExpensiveCfg);
  LReg.AddRow('secp384r1 [k]G comb', 'value-type comb (CT)', 'wNAF (var-time)',
    Ec('secp384r1', TEcMulKind.Comb), Ec('secp384r1', TEcMulKind.WNaf),
    ExpensiveCfg);
  LReg.AddRow('secp521r1 [k]G comb', 'value-type comb (CT)', 'wNAF (var-time)',
    Ec('secp521r1', TEcMulKind.Comb), Ec('secp521r1', TEcMulKind.WNaf),
    ExpensiveCfg);
  // FixedTimeEquals: the CT byte compare behind the AES same-key Init gate.
  // Control = early-exit compare (first-vs-last mismatch position separates and
  // fires); subject = the full-scan FixedTimeEquals (must stay flat).
  LReg.AddRow('FixedTimeEquals', 'CT compare (position-indep)', 'early-exit compare',
    Fn(@MakeCtCompareFixed), Fn(@MakeCtCompareVar), CheapCfg);
  Result := LReg.Rows;
end;

function GetValgrindTargets: TCtVgTargetArray;
var
  LReg: TCtRegistrar;
begin
  LReg.AddTarget('x25519', Fn(@MakeX25519), False);
  LReg.AddTarget('x448', Fn(@MakeX448), False);
  // Ed25519/Ed448 sign: the seed is a poisonable byte buffer (hashed before use),
  // so it taint-checks cleanly like X25519, unlike the EC BigInteger scalars.
  LReg.AddTarget('ed25519', Fn(@MakeEd25519), False);
  LReg.AddTarget('ed448', Fn(@MakeEd448), False);
  LReg.AddTarget('aes-bitsliced', Fn(@MakeAesBitsliced), False);
  LReg.AddTarget('aes-ttable', Fn(@MakeAesTable), True);
  LReg.AddTarget('ghash-basic', Fn(@MakeGhashBasic), False);
  LReg.AddTarget('ghash-4k', Fn(@MakeGhashTable4k), True);
  Result := LReg.Targets;
end;

end.
