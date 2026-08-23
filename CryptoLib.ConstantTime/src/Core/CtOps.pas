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

{ Constant-time measured ops and the crypto they exercise: the TDudectOp subclasses
  for each paired subject/control, plus the plain factory functions that build them.
  CtSubjects wires these into the dudect / Valgrind registries. }

unit CtOps;

{$IFDEF FPC}
{$MODE DELPHI}
{$WARNINGS OFF}
{$ENDIF FPC}

{$SCOPEDENUMS ON}

interface

uses
  CtDudect;

type
  { Every EC row is one curve x one multiplier kind, so a single factory carries
    both coordinates instead of a per-(curve,kind) function. TEcMulKind.Default = the curve's
    own CT multiplier ([d]Q), TEcMulKind.Comb = its fixed-base CT comb ([k]G on the reused
    generator), TEcMulKind.WNaf / TEcMulKind.WTau = the variable-time controls. }
  TEcMulKind = (Default, Comb, WNaf, WTau);

function MakeX25519(ASeed: UInt64): TDudectOp;
function MakeX448(ASeed: UInt64): TDudectOp;
function MakeEd25519(ASeed: UInt64): TDudectOp;
function MakeEd448(ASeed: UInt64): TDudectOp;
function MakeAesBitsliced(ASeed: UInt64): TDudectOp;
function MakeAesTable(ASeed: UInt64): TDudectOp;
function MakeGhashBasic(ASeed: UInt64): TDudectOp;
function MakeGhashTable4k(ASeed: UInt64): TDudectOp;
function MakeModInvSafe(ASeed: UInt64): TDudectOp;
function MakeModInvVar(ASeed: UInt64): TDudectOp;
function MakeModInvWrapperSafe(ASeed: UInt64): TDudectOp;
function MakeModInvWrapperVar(ASeed: UInt64): TDudectOp;
function MakeCtCompareFixed(ASeed: UInt64): TDudectOp;
function MakeCtCompareVar(ASeed: UInt64): TDudectOp;

// Scalar-mult op for a curve + multiplier kind (was TEcFactory.Make).
function MakeEc(const ACurveName: string; AKind: TEcMulKind; ASeed: UInt64): TDudectOp;

implementation

uses
  SysUtils,
  ClpCryptoLibTypes,
  ClpArrayUtilities,
  ClpBigInteger,
  ClpBigIntegerUtilities,
  ClpMod,
  ClpNat,
  ClpCustomNamedCurves,
  ClpIX9ECAsn1Objects,
  ClpIECCommon,
  ClpMultipliers,
  ClpX25519,
  ClpX448,
  ClpEd25519,
  ClpEd448,
  ClpIBlockCipher,
  ClpAesEngine,
  ClpAesBitSlicedEngine,
  ClpKeyParameter,
  ClpIKeyParameter,
  ClpIGcmMultiplier,
  ClpBasicGcmMultiplier,
  ClpTables4kGcmMultiplier;

const
  AES_BLOCK = Int32(16);
  GHASH_BLOCK = Int32(16);
  // Length for the FixedTimeEquals subject. The routine is length-generic (the
  // AES same-key gate compares 16/32-byte keys); a longer span both gives the
  // leaky early-exit control a decisive first-vs-last-byte separation and makes
  // the CT subject's timing less noise-sensitive than a very short op.
  CMP_LEN = Int32(1024);

{ Build a scalar in [1, N-1] from raw bytes (reproducible via the caller's stream). }
function ScalarFromBytes(const ABytes: TBytes; const AN: TBigInteger): TBigInteger;
begin
  Result := TBigInteger.Create(Int32(1), ABytes).&Mod(AN);
  if Result.SignValue = 0 then
    Result := TBigInteger.One;
end;

{ Base for the byte-secret subjects (X25519 scalar, AES key, GHASH block) - the
  families whose secret is a contiguous buffer feeding the routine directly, so they
  are both dudect-timed AND ctgrind-poisonable. Holds the reused secret / fixed /
  output buffers, the four taint accessors, and the class-symmetric prep. A subclass
  sets the buffer sizes and the fixed pattern in its constructor, provides RunOp, and
  optionally overrides AfterSecretPrepared for secret-dependent setup that is NOT the
  timed op (e.g. an AES key schedule). FOut may alias FSecret for in-place routines. }
type
  TCtByteBufferOp = class abstract(TDudectOp)
  strict protected
    FRnd: TCtRandom;
    FSecret, FFixed, FScratch, FOut: TBytes;
    FSecretLen: Int32;
    procedure AfterSecretPrepared; virtual;
  public
    procedure PrepareSecret(AClass: Int32); override;
    function SecretPtr: Pointer; override;
    function SecretLen: Int32; override;
    function OutputPtr: Pointer; override;
    function OutputLen: Int32; override;
  end;

procedure TCtByteBufferOp.AfterSecretPrepared;
begin
  // Default: no extra secret-dependent setup.
end;

procedure TCtByteBufferOp.PrepareSecret(AClass: Int32);
begin
  // Class-symmetric preparation: BOTH classes draw a fresh random into scratch, then
  // Move exactly one source into FSecret - the fixed value for class 0, the drawn
  // random for class 1. Identical work per class (one draw + one Move); only the
  // moved value differs. (Overwriting FSecret in place for class 0 only - the naive
  // shape - gives class 0 an extra Move, a prep asymmetry that a fast op like GHASH
  // resolves as a false timing signal on a coarse clock.)
  if System.Length(FScratch) <> FSecretLen then
    System.SetLength(FScratch, FSecretLen);
  FRnd.NextBytes(FScratch, 0, FSecretLen);
  if AClass = 0 then
    System.Move(FFixed[0], FSecret[0], FSecretLen)
  else
    System.Move(FScratch[0], FSecret[0], FSecretLen);
  AfterSecretPrepared;
end;

function TCtByteBufferOp.SecretPtr: Pointer;
begin
  Result := @FSecret[0];
end;

function TCtByteBufferOp.SecretLen: Int32;
begin
  Result := FSecretLen;
end;

function TCtByteBufferOp.OutputPtr: Pointer;
begin
  Result := @FOut[0];
end;

function TCtByteBufferOp.OutputLen: Int32;
begin
  Result := System.Length(FOut);
end;

{ ============================ #1  X25519 ladder ============================ }

type
  TX25519Op = class sealed(TCtByteBufferOp)
  strict private
    FPoint: TBytes;
  public
    constructor Create(ASeed: UInt64);
    procedure RunOp; override;
  end;

constructor TX25519Op.Create(ASeed: UInt64);
begin
  inherited Create;
  FRnd := TCtRandom.Create(ASeed);
  FSecretLen := TX25519.ScalarSize;
  System.SetLength(FSecret, FSecretLen);
  System.SetLength(FOut, TX25519.PointSize);
  System.SetLength(FPoint, TX25519.PointSize);
  FPoint[0] := 9; // canonical X25519 base point u = 9
  // Fixed class = all-zero scalar (a timing-extreme constant): a variable-time
  // subject separates most from random against it, a constant-time one does not.
  // SetLength already zero-fills FFixed.
  System.SetLength(FFixed, FSecretLen);
end;

procedure TX25519Op.RunOp;
begin
  TX25519.ScalarMult(FSecret, 0, FPoint, 0, FOut, 0);
end;

{ ============================== X448 ladder ================================ }

type
  TX448Op = class sealed(TCtByteBufferOp)
  strict private
    FPoint: TBytes;
  public
    constructor Create(ASeed: UInt64);
    procedure RunOp; override;
  end;

constructor TX448Op.Create(ASeed: UInt64);
begin
  inherited Create;
  FRnd := TCtRandom.Create(ASeed);
  FSecretLen := TX448.ScalarSize;
  System.SetLength(FSecret, FSecretLen);
  System.SetLength(FOut, TX448.PointSize);
  System.SetLength(FPoint, TX448.PointSize);
  FPoint[0] := 5; // canonical X448 base point u = 5
  System.SetLength(FFixed, FSecretLen);
end;

procedure TX448Op.RunOp;
begin
  TX448.ScalarMult(FSecret, 0, FPoint, 0, FOut, 0);
end;

{ ===================== Ed25519 / Ed448 signature ========================== }

// The poisoned secret is the private seed; the whole sign (seed hash -> scalar
// -> fixed-base comb [k]G -> encode) must be constant-time. Adds the comb +
// scalar-arithmetic coverage the X25519/X448 ladders do not exercise.
type
  TEd25519SignOp = class sealed(TCtByteBufferOp)
  strict private
    FSigner: TEd25519;
    FMsg: TBytes;
  public
    constructor Create(ASeed: UInt64);
    destructor Destroy; override;
    procedure RunOp; override;
  end;

  TEd448SignOp = class sealed(TCtByteBufferOp)
  strict private
    FSigner: TEd448;
    FMsg, FCtx: TBytes;
  public
    constructor Create(ASeed: UInt64);
    destructor Destroy; override;
    procedure RunOp; override;
  end;

constructor TEd25519SignOp.Create(ASeed: UInt64);
begin
  inherited Create;
  FRnd := TCtRandom.Create(ASeed);
  FSigner := TEd25519.Create;
  FSecretLen := TEd25519.SecretKeySize;
  System.SetLength(FSecret, FSecretLen);
  System.SetLength(FFixed, FSecretLen);
  System.SetLength(FMsg, 32);
  FRnd.NextBytes(FMsg, 0, System.Length(FMsg));
  System.SetLength(FOut, TEd25519.SignatureSize);
end;

destructor TEd25519SignOp.Destroy;
begin
  FSigner.Free;
  inherited Destroy;
end;

procedure TEd25519SignOp.RunOp;
begin
  FSigner.Sign(FSecret, 0, FMsg, 0, System.Length(FMsg), FOut, 0);
end;

constructor TEd448SignOp.Create(ASeed: UInt64);
begin
  inherited Create;
  FRnd := TCtRandom.Create(ASeed);
  FSigner := TEd448.Create;
  FSecretLen := TEd448.SecretKeySize;
  System.SetLength(FSecret, FSecretLen);
  System.SetLength(FFixed, FSecretLen);
  System.SetLength(FMsg, 32);
  FRnd.NextBytes(FMsg, 0, System.Length(FMsg));
  System.SetLength(FCtx, 0);
  System.SetLength(FOut, TEd448.SignatureSize);
end;

destructor TEd448SignOp.Destroy;
begin
  FSigner.Free;
  inherited Destroy;
end;

procedure TEd448SignOp.RunOp;
begin
  FSigner.Sign(FSecret, 0, FCtx, FMsg, 0, System.Length(FMsg), FOut, 0);
end;

{ ====================== #2/#3  EC scalar multiplication ==================== }

type
  TECMulOp = class sealed(TDudectOp)
  strict private
    FRnd: TCtRandom;
    FMul: IECMultiplier;
    FQ: IECPoint;
    FN: TBigInteger;
    FFixedK, FK: TBigInteger;
    FResult: IECPoint;
    FScalarBytes: TBytes;
    FScalarByteLen: Int32;
  public
    constructor Create(const AMul: IECMultiplier; const AQ: IECPoint;
      const AN: TBigInteger; ASeed: UInt64);
    procedure PrepareSecret(AClass: Int32); override;
    procedure RunOp; override;
  end;

constructor TECMulOp.Create(const AMul: IECMultiplier; const AQ: IECPoint;
  const AN: TBigInteger; ASeed: UInt64);
begin
  inherited Create;
  FRnd := TCtRandom.Create(ASeed);
  FMul := AMul;
  FQ := AQ;
  FN := AN;
  // A few extra bytes over the modulus width keep the mod-reduction bias tiny.
  FScalarByteLen := ((FN.BitLength + 7) div 8) + 8;
  System.SetLength(FScalarBytes, FScalarByteLen);
  // Fixed class = scalar 1: a variable-time (wNAF/tau-NAF) multiplier runs far
  // fewer additions for it than for a random scalar (strong mean separation),
  // while a constant-time multiplier blinds it to full length like any other.
  FFixedK := TBigInteger.One;
end;

procedure TECMulOp.PrepareSecret(AClass: Int32);
begin
  if AClass = 0 then
    FK := FFixedK
  else
  begin
    FRnd.NextBytes(FScalarBytes, 0, FScalarByteLen);
    FK := ScalarFromBytes(FScalarBytes, FN);
  end;
end;

procedure TECMulOp.RunOp;
begin
  FResult := FMul.Multiply(FQ, FK).Normalize();
end;

{ Force a fresh key schedule so a block cipher's same-key Init fast path cannot
  make the untimed prep asymmetric by class: init a neutral key first, then the
  real key, so BOTH classes take the (destructive) rebuild path. Without this a
  constant-key class would skip the rebuild and dudect would measure prep
  asymmetry, not the timed op (CT-leak-detector methodology trap #5). Shared so
  any future engine-Init subject can stay class-symmetric the same way. }
procedure PrimeBlockCipherClassSymmetric(const AEngine: IBlockCipher;
  AForEncryption: Boolean; const ANeutralKey, AKey: TCryptoLibByteArray);
begin
  AEngine.Init(AForEncryption, TKeyParameter.Create(ANeutralKey) as IKeyParameter);
  AEngine.Init(AForEncryption, TKeyParameter.Create(AKey) as IKeyParameter);
end;

{ =========================== #4  AES block cipher ========================= }

type
  TBlockCipherFactory = function: IBlockCipher;

  TAesOp = class sealed(TCtByteBufferOp)
  strict private
    FFactory: TBlockCipherFactory;
    FEngine: IBlockCipher;
    FNeutralKey, FIn: TBytes;
  strict protected
    procedure AfterSecretPrepared; override;
  public
    constructor Create(AFactory: TBlockCipherFactory; AKeyLen: Int32; ASeed: UInt64);
    procedure RunOp; override;
    procedure RunPoisonedRoutine; override;
  end;

constructor TAesOp.Create(AFactory: TBlockCipherFactory; AKeyLen: Int32; ASeed: UInt64);
var
  LI: Int32;
begin
  inherited Create;
  FRnd := TCtRandom.Create(ASeed);
  FFactory := AFactory;
  FEngine := AFactory();
  FSecretLen := AKeyLen;
  System.SetLength(FSecret, FSecretLen);
  // Fixed key = a NON-extreme constant (see the base class comment): constant so
  // cropping separates it from the random class, but not all-zero - a degenerate
  // key schedule would create its own artifact and falsely flag the CT subject.
  System.SetLength(FFixed, FSecretLen);
  for LI := 0 to FSecretLen - 1 do
    FFixed[LI] := Byte(LI * 7 + 3);
  // Neutral key: a constant distinct from both the fixed and (any) random key, used
  // to force a fresh key schedule per sample (see AfterSecretPrepared).
  System.SetLength(FNeutralKey, FSecretLen);
  for LI := 0 to FSecretLen - 1 do
    FNeutralKey[LI] := Byte(LI * 13 + 7);
  System.SetLength(FIn, AES_BLOCK);
  System.SetLength(FOut, AES_BLOCK);
  for LI := 0 to AES_BLOCK - 1 do
    FIn[LI] := Byte(LI * 17 + 1); // fixed plaintext, same for every sample
end;

procedure TAesOp.AfterSecretPrepared;
begin
  // Force a fresh key schedule per sample so the engine's same-key Init gate cannot
  // make the untimed prep asymmetric by class (methodology trap #5, see
  // PrimeBlockCipherClassSymmetric).
  PrimeBlockCipherClassSymmetric(FEngine, True, FNeutralKey, FSecret);
end;

procedure TAesOp.RunOp;
begin
  FEngine.ProcessBlock(FIn, 0, FOut, 0);
end;

procedure TAesOp.RunPoisonedRoutine;
var
  LEngine: IBlockCipher;
  LKp: IKeyParameter;
begin
  // Use a FRESH engine so the schedule-reuse gate cannot trigger: on a virgin
  // engine FScheduleReady is False, so the reuse check short-circuits before the
  // key compare and the poisoned Init takes the full REBUILD path - key
  // expansion (S-box indexed by key bytes in the T-table engine) AND the block
  // transform run under taint, which is the primitive this subject asserts. The
  // gate's key-change compare is a deliberate one-bit signal (documented on
  // TAbstractAesEngine) and is intentionally kept out of the taint scope; a
  // reused schedule would run ProcessBlock on pre-poison round keys and test
  // nothing.
  LEngine := FFactory();
  LKp := TKeyParameter.Create(FSecret);
  LEngine.Init(True, LKp);
  LEngine.ProcessBlock(FIn, 0, FOut, 0);
end;

{ ============================== #5  GHASH ================================= }

type
  TGhashOp = class sealed(TCtByteBufferOp)
  strict private
    FMul: IGcmMultiplier;
  public
    constructor Create(const AMul: IGcmMultiplier; ASeed: UInt64);
    procedure RunOp; override;
  end;

constructor TGhashOp.Create(const AMul: IGcmMultiplier; ASeed: UInt64);
var
  LH: TBytes;
  LI: Int32;
begin
  inherited Create;
  FRnd := TCtRandom.Create(ASeed);
  FMul := AMul;
  // Fixed hash subkey H; the varied secret is the multiplied block (the value that
  // drives the table access pattern in the 4k engine).
  System.SetLength(LH, GHASH_BLOCK);
  for LI := 0 to GHASH_BLOCK - 1 do
    LH[LI] := Byte(LI * 31 + 7);
  FMul.Init(LH);
  FSecretLen := GHASH_BLOCK;
  System.SetLength(FSecret, FSecretLen);
  // Fixed block = a NON-extreme constant (see the base class comment): constant-but-
  // typical so it separates from random via cropping for the leaky 4k control,
  // without an all-zero artifact falsely flagging the CT ImplMul64 subject.
  System.SetLength(FFixed, FSecretLen);
  for LI := 0 to GHASH_BLOCK - 1 do
    FFixed[LI] := Byte(LI * 13 + 5);
  FOut := FSecret; // X is transformed in place; output aliases the secret
end;

procedure TGhashOp.RunOp;
begin
  FMul.MultiplyH(FSecret); // mutates FSecret in place (X := X * H)
end;

{ ======================= #6  modular inverse (mod n) ====================== }

{ We exercise the safegcd CORE (TMod.ModOddInverse on fixed-width Nats) rather
  than the TBigInteger wrapper. The wrapper's TNat.FromBigInteger / ToBigInteger
  conversions are magnitude-dependent (not constant-time), so testing the public
  API would flag the conversions, not the algorithm - the same reason the EC
  subjects test the multiplier (which blinds the scalar to full width) and not raw
  BigInteger. The CT-scoped primitive - the one X25519/EC field inversion actually
  calls - is the TMod core, and that is what must be clean here. Class 0 and 1 are
  both full-width Nats; only their contents differ. }
type
  TModInvOp = class sealed(TDudectOp)
  strict private
    FRnd: TCtRandom;
    FSafeGcd: Boolean;
    FModulus, FFixedBig: TBigInteger;
    FBits, FLen: Int32;
    FM, FZ, FX: TCryptoLibUInt32Array;
    FScalarBytes: TBytes;
    FScalarByteLen: Int32;
    FSinkU: UInt32;
    FSinkB: Boolean;
  public
    constructor Create(ASafeGcd: Boolean; const AModulus: TBigInteger; ASeed: UInt64);
    procedure PrepareSecret(AClass: Int32); override;
    procedure RunOp; override;
  end;

constructor TModInvOp.Create(ASafeGcd: Boolean; const AModulus: TBigInteger;
  ASeed: UInt64);
begin
  inherited Create;
  FRnd := TCtRandom.Create(ASeed);
  FSafeGcd := ASafeGcd;
  FModulus := AModulus;
  FBits := AModulus.BitLength;
  FM := TNat.FromBigInteger(FBits, AModulus);
  FLen := System.Length(FM);
  FZ := TNat.Create(FLen);
  // Fixed class = n-1 (full width): variable-time Euclid finds its inverse (n-1)
  // in a couple of steps - a strong mean separation - while safegcd runs the same
  // fixed number of divsteps as for any other full-width input.
  FFixedBig := AModulus.Subtract(TBigInteger.One);
  FScalarByteLen := ((FBits + 7) div 8) + 8;
  System.SetLength(FScalarBytes, FScalarByteLen);
  FX := TNat.FromBigInteger(FBits, FFixedBig);
end;

procedure TModInvOp.PrepareSecret(AClass: Int32);
var
  LRand, LK: TBigInteger;
begin
  // Untimed, but kept ALLOCATION-SYMMETRIC across classes: TMod.ModOddInverse
  // allocates internally each call, so an asymmetric heap-churn here (only class 1
  // allocating) would correlate the heap state with the class and show up as a
  // false timing signal. Both classes therefore run the identical draw + convert
  // sequence; only the resulting value differs.
  FRnd.NextBytes(FScalarBytes, 0, FScalarByteLen);
  LRand := ScalarFromBytes(FScalarBytes, FModulus);
  if AClass = 0 then
    LK := FFixedBig
  else
    LK := LRand;
  FX := TNat.FromBigInteger(FBits, LK);
end;

procedure TModInvOp.RunOp;
begin
  // Modulus is the (odd, prime) curve order, so every X in [1, n-1] is invertible.
  if FSafeGcd then
    FSinkU := TMod.ModOddInverse(FM, FX, FZ)
  else
    FSinkB := TMod.ModOddInverseVar(FM, FX, FZ);
end;

{ =============== #7  modular inverse - TBigInteger WRAPPER ================ }

{ Measures the exact ECDSA signer call shape: TBigIntegerUtilities.ModOddInverse
  (n, k) - see ClpECDsaSigner - the FULL BigInteger wrapper (FromBigInteger ->
  TMod core -> ToBigInteger), not just the core (#6). This turns "core-measured +
  wrapper-CT-by-construction" into an end-to-end measurement. k is a nonce strictly
  in [1, n-1] (as in signing), so the wrapper's magnitude-dependent range-reduction
  branch stays dead and the fixed-width marshalling is word-count-invariant for
  crypto-size nonces (a random k mod n is full width with overwhelming probability).
  Fixed class = n-1 (full width, no word-count artifact vs random; its inverse is
  n-1, which variable-time Euclid finds in ~2 steps, so the control separates). Prep
  is allocation-symmetric; the timed RunOp is ONLY the ModOddInverse call. }
type
  TModInvWrapperOp = class sealed(TDudectOp)
  strict private
    FRnd: TCtRandom;
    FSafeGcd: Boolean;
    FModulus, FFixedBig, FK, FResult: TBigInteger;
    FScalarBytes: TBytes;
    FScalarByteLen: Int32;
  public
    constructor Create(ASafeGcd: Boolean; const AModulus: TBigInteger; ASeed: UInt64);
    procedure PrepareSecret(AClass: Int32); override;
    procedure RunOp; override;
  end;

constructor TModInvWrapperOp.Create(ASafeGcd: Boolean; const AModulus: TBigInteger;
  ASeed: UInt64);
begin
  inherited Create;
  FRnd := TCtRandom.Create(ASeed);
  FSafeGcd := ASafeGcd;
  FModulus := AModulus;
  FFixedBig := AModulus.Subtract(TBigInteger.One);
  FScalarByteLen := ((AModulus.BitLength + 7) div 8) + 8;
  System.SetLength(FScalarBytes, FScalarByteLen);
end;

procedure TModInvWrapperOp.PrepareSecret(AClass: Int32);
var
  LRand: TBigInteger;
begin
  // Allocation-symmetric, untimed: both classes draw + build a BigInteger; input
  // construction stays OUT of the timed region, only the resulting value differs.
  // (This is the trap the report hit - an asymmetric per-class alloc reads as a
  // false timing signal because the wrapper allocates internally each call.)
  FRnd.NextBytes(FScalarBytes, 0, FScalarByteLen);
  LRand := ScalarFromBytes(FScalarBytes, FModulus); // strictly in [1, n-1]
  if AClass = 0 then
    FK := FFixedBig
  else
    FK := LRand;
end;

procedure TModInvWrapperOp.RunOp;
begin
  // The exact signer call: k^-1 mod n through the full TBigInteger wrapper.
  if FSafeGcd then
    FResult := TBigIntegerUtilities.ModOddInverse(FModulus, FK)
  else
    FResult := TBigIntegerUtilities.ModOddInverseVar(FModulus, FK);
end;

{ =================== #8  FixedTimeEquals (CT byte compare) ================ }

{ Guards the load-bearing constant-time comparison behind the AES engine's
  same-key Init gate (TArrayUtilities.FixedTimeEquals). Property under test:
  mismatch-POSITION independence. Both classes are MISSES (candidate <> reference)
  differing only in WHERE the single differing byte sits - class 0 at the first
  byte, class 1 at the last. A full-scan CT compare is flat; the leaky control
  (early-exit) returns after 1 byte for class 0 vs CMP_LEN bytes for class 1, so it
  separates and fires. This is deliberately NOT a same-vs-different test (that would
  just confirm the gate skips on a hit, which is by design); it proves the compare
  cannot be turned into a byte-at-a-time key-recovery oracle. }
type
  TCtCompareOp = class sealed(TDudectOp)
  strict private
    FVarTime: Boolean;
    FRef, FCand: TBytes;
    FLen: Int32;
    FSink: UInt32;
    function VarTimeEquals: Boolean;
  public
    constructor Create(AVarTime: Boolean; ALen: Int32);
    procedure PrepareSecret(AClass: Int32); override;
    procedure RunOp; override;
  end;

constructor TCtCompareOp.Create(AVarTime: Boolean; ALen: Int32);
var
  LI: Int32;
begin
  inherited Create;
  FVarTime := AVarTime;
  FLen := ALen;
  // Fixed resident reference; the candidate is its copy with exactly one byte
  // flipped per sample (position chosen by class in PrepareSecret).
  System.SetLength(FRef, FLen);
  for LI := 0 to FLen - 1 do
    FRef[LI] := Byte(LI * 29 + 11);
  System.SetLength(FCand, FLen);
end;

procedure TCtCompareOp.PrepareSecret(AClass: Int32);
begin
  // Class-symmetric prep. Both classes copy FRef then store BOTH ends in the SAME
  // order (head, then tail last), so the store pattern - and thus the timed
  // compare's entry cache/store-forward state - is identical by class. Only the
  // VALUES differ: exactly one end is flipped, placing the lone mismatch at the
  // first byte (class 0) or the last (class 1). Both remain misses; only the
  // position of the difference (the secret under test) varies.
  System.Move(FRef[0], FCand[0], FLen);
  if AClass = 0 then
  begin
    FCand[0] := Byte(FRef[0] xor $FF);
    FCand[FLen - 1] := FRef[FLen - 1];
  end
  else
  begin
    FCand[0] := FRef[0];
    FCand[FLen - 1] := Byte(FRef[FLen - 1] xor $FF);
  end;
end;

function TCtCompareOp.VarTimeEquals: Boolean;
var
  LI: Int32;
begin
  // Deliberately leaky twin: early-exit on the first differing byte.
  for LI := 0 to FLen - 1 do
    if FRef[LI] <> FCand[LI] then
      Exit(False);
  Result := True;
end;

procedure TCtCompareOp.RunOp;
begin
  // Sink the result into a field so the compare cannot be elided.
  if FVarTime then
    FSink := FSink xor UInt32(Ord(VarTimeEquals))
  else
    FSink := FSink xor
      UInt32(Ord(TArrayUtilities.FixedTimeEquals(FLen, FRef, 0, FCand, 0)));
end;

{ ============================== factories ================================ }

function BuildEcMultiplier(const AX9: IX9ECParameters;
  AKind: TEcMulKind): IECMultiplier;
begin
  case AKind of
    TEcMulKind.Comb:
      Result := AX9.Curve.BasePointMultiplier;
    TEcMulKind.WNaf:
      Result := TWNafL2RMultiplier.Create as IECMultiplier;
    TEcMulKind.WTau:
      Result := TWTauNafMultiplier.Create as IECMultiplier;
  else
    Result := AX9.Curve.Multiplier; // TEcMulKind.Default
  end;
end;

function NewBitslicedEngine: IBlockCipher;
begin
  Result := TAesBitSlicedEngine.Create as IBlockCipher;
end;

function NewTableEngine: IBlockCipher;
begin
  Result := TAesEngine.Create as IBlockCipher;
end;

function P256Order: TBigInteger;
begin
  Result := TCustomNamedCurves.GetByName('secp256r1').N;
end;

function MakeX25519(ASeed: UInt64): TDudectOp;
begin
  Result := TX25519Op.Create(ASeed);
end;

function MakeX448(ASeed: UInt64): TDudectOp;
begin
  Result := TX448Op.Create(ASeed);
end;

function MakeEd25519(ASeed: UInt64): TDudectOp;
begin
  Result := TEd25519SignOp.Create(ASeed);
end;

function MakeEd448(ASeed: UInt64): TDudectOp;
begin
  Result := TEd448SignOp.Create(ASeed);
end;

function MakeAesBitsliced(ASeed: UInt64): TDudectOp;
begin
  Result := TAesOp.Create(@NewBitslicedEngine, 16, ASeed);
end;

function MakeAesTable(ASeed: UInt64): TDudectOp;
begin
  Result := TAesOp.Create(@NewTableEngine, 16, ASeed);
end;

function MakeGhashBasic(ASeed: UInt64): TDudectOp;
begin
  Result := TGhashOp.Create(TBasicGcmMultiplier.Create as IGcmMultiplier, ASeed);
end;

function MakeGhashTable4k(ASeed: UInt64): TDudectOp;
begin
  Result := TGhashOp.Create(TTables4kGcmMultiplier.Create as IGcmMultiplier, ASeed);
end;

function MakeModInvSafe(ASeed: UInt64): TDudectOp;
begin
  Result := TModInvOp.Create(True, P256Order, ASeed);
end;

function MakeModInvVar(ASeed: UInt64): TDudectOp;
begin
  Result := TModInvOp.Create(False, P256Order, ASeed);
end;

function MakeModInvWrapperSafe(ASeed: UInt64): TDudectOp;
begin
  Result := TModInvWrapperOp.Create(True, P256Order, ASeed);
end;

function MakeModInvWrapperVar(ASeed: UInt64): TDudectOp;
begin
  Result := TModInvWrapperOp.Create(False, P256Order, ASeed);
end;

// FixedTimeEquals: data is deterministic, so the op needs no per-run seed (ASeed
// still drives dudect's own class scheduling via the row Cfg).
function MakeCtCompareFixed(ASeed: UInt64): TDudectOp;
begin
  Result := TCtCompareOp.Create(False, CMP_LEN);
end;

function MakeCtCompareVar(ASeed: UInt64): TDudectOp;
begin
  Result := TCtCompareOp.Create(True, CMP_LEN);
end;

function MakeEc(const ACurveName: string; AKind: TEcMulKind; ASeed: UInt64): TDudectOp;
var
  LX9: IX9ECParameters;
begin
  LX9 := TCustomNamedCurves.GetByName(ACurveName);
  Result := TECMulOp.Create(BuildEcMultiplier(LX9, AKind), LX9.G, LX9.N, ASeed);
end;

end.
