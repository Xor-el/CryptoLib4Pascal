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
    2  P-256 default (TFpCTMultiplier value-type) TWNafL2RMultiplier, same curve
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

interface

uses
  CtDudect;

type
  TCtOpFactory = function(ASeed: UInt64): TDudectOp;

  { One dudect registry row: a subject and (optionally) its paired leaky control,
    plus the per-row sampling budget (op cost spans microseconds to milliseconds). }
  TCtRow = record
    Name: string;
    SubjectLabel: string;
    ControlLabel: string;      // '' when the row has no control
    MakeSubject: TCtOpFactory;
    MakeControl: TCtOpFactory;  // nil when the row has no control
    Cfg: TDudectConfig;
  end;

  TCtRowArray = array of TCtRow;

  { One Valgrind target. ExpectLeak = True  -> known-leaky control, MUST fire;
                          ExpectLeak = False -> CT subject, MUST stay clean. }
  TCtVgTarget = record
    Name: string;
    Make: TCtOpFactory;
    ExpectLeak: Boolean;
  end;

  TCtVgTargetArray = array of TCtVgTarget;

function GetDudectRows: TCtRowArray;
function GetValgrindTargets: TCtVgTargetArray;

implementation

uses
  SysUtils,
  ClpCryptoLibTypes,
  ClpBigInteger,
  ClpBigIntegerUtilities,
  ClpMod,
  ClpNat,
  ClpCustomNamedCurves,
  ClpIX9ECAsn1Objects,
  ClpIECCommon,
  ClpMultipliers,
  ClpX25519,
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

{ Build a scalar in [1, N-1] from raw bytes (reproducible via the caller's stream). }
function ScalarFromBytes(const ABytes: TBytes; const AN: TBigInteger): TBigInteger;
begin
  Result := TBigInteger.Create(Int32(1), ABytes).&Mod(AN);
  if Result.SignValue = 0 then
    Result := TBigInteger.One;
end;

{ ============================ #1  X25519 ladder ============================ }

type
  TX25519Op = class sealed(TDudectOp)
  strict private
    FRnd: TCtRandom;
    FScalar, FPoint, FOut, FFixed: TBytes;
  public
    constructor Create(ASeed: UInt64);
    procedure PrepareSecret(AClass: Int32); override;
    procedure RunOp; override;
    function SecretPtr: Pointer; override;
    function SecretLen: Int32; override;
    function OutputPtr: Pointer; override;
    function OutputLen: Int32; override;
  end;

constructor TX25519Op.Create(ASeed: UInt64);
begin
  inherited Create;
  FRnd := TCtRandom.Create(ASeed);
  System.SetLength(FScalar, TX25519.ScalarSize);
  System.SetLength(FOut, TX25519.PointSize);
  System.SetLength(FPoint, TX25519.PointSize);
  FPoint[0] := 9; // canonical X25519 base point u = 9
  // Fixed class = all-zero scalar (a timing-extreme constant); dynamic arrays are
  // already zero-filled by SetLength. A variable-time subject separates most from
  // random against an extreme fixed value; a constant-time one does not.
  System.SetLength(FFixed, TX25519.ScalarSize);
end;

procedure TX25519Op.PrepareSecret(AClass: Int32);
begin
  // Class-symmetric preparation: always draw, overwrite for the fixed class, so
  // the untimed prep leaves identical cache/predictor state for both classes.
  FRnd.NextBytes(FScalar, 0, TX25519.ScalarSize);
  if AClass = 0 then
    System.Move(FFixed[0], FScalar[0], TX25519.ScalarSize);
end;

procedure TX25519Op.RunOp;
begin
  TX25519.ScalarMult(FScalar, 0, FPoint, 0, FOut, 0);
end;

function TX25519Op.SecretPtr: Pointer;
begin
  Result := @FScalar[0];
end;

function TX25519Op.SecretLen: Int32;
begin
  Result := TX25519.ScalarSize;
end;

function TX25519Op.OutputPtr: Pointer;
begin
  Result := @FOut[0];
end;

function TX25519Op.OutputLen: Int32;
begin
  Result := TX25519.PointSize;
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

{ =========================== #4  AES block cipher ========================= }

type
  TAesOp = class sealed(TDudectOp)
  strict private
    FRnd: TCtRandom;
    FEngine: IBlockCipher;
    FKey, FFixedKey, FIn, FOut: TBytes;
    FKeyLen: Int32;
  public
    constructor Create(const AEngine: IBlockCipher; AKeyLen: Int32; ASeed: UInt64);
    procedure PrepareSecret(AClass: Int32); override;
    procedure RunOp; override;
    procedure RunPoisonedRoutine; override;
    function SecretPtr: Pointer; override;
    function SecretLen: Int32; override;
    function OutputPtr: Pointer; override;
    function OutputLen: Int32; override;
  end;

constructor TAesOp.Create(const AEngine: IBlockCipher; AKeyLen: Int32; ASeed: UInt64);
var
  LI: Int32;
begin
  inherited Create;
  FRnd := TCtRandom.Create(ASeed);
  FEngine := AEngine;
  FKeyLen := AKeyLen;
  System.SetLength(FKey, FKeyLen);
  // Fixed key = a NON-extreme constant. The fixed class only needs to be constant
  // (low variance) so cropping separates it from the random class; an all-zero
  // extreme would instead create its own artifact (degenerate key schedule) and
  // falsely flag the constant-time subject.
  System.SetLength(FFixedKey, FKeyLen);
  for LI := 0 to FKeyLen - 1 do
    FFixedKey[LI] := Byte(LI * 7 + 3);
  System.SetLength(FIn, AES_BLOCK);
  System.SetLength(FOut, AES_BLOCK);
  for LI := 0 to AES_BLOCK - 1 do
    FIn[LI] := Byte(LI * 17 + 1); // fixed plaintext, same for every sample
end;

procedure TAesOp.PrepareSecret(AClass: Int32);
var
  LKp: IKeyParameter;
begin
  // Class-symmetric preparation (always draw + build a key schedule); overwrite
  // with the fixed key for class 0. ProcessBlock is the measured op.
  FRnd.NextBytes(FKey, 0, FKeyLen);
  if AClass = 0 then
    System.Move(FFixedKey[0], FKey[0], FKeyLen);
  LKp := TKeyParameter.Create(FKey);
  FEngine.Init(True, LKp);
end;

procedure TAesOp.RunOp;
begin
  FEngine.ProcessBlock(FIn, 0, FOut, 0);
end;

procedure TAesOp.RunPoisonedRoutine;
var
  LKp: IKeyParameter;
begin
  // Under taint the whole key-dependent path runs: schedule (S-box indexed by key
  // bytes in the T-table engine) and the block transform.
  LKp := TKeyParameter.Create(FKey);
  FEngine.Init(True, LKp);
  FEngine.ProcessBlock(FIn, 0, FOut, 0);
end;

function TAesOp.SecretPtr: Pointer;
begin
  Result := @FKey[0];
end;

function TAesOp.SecretLen: Int32;
begin
  Result := FKeyLen;
end;

function TAesOp.OutputPtr: Pointer;
begin
  Result := @FOut[0];
end;

function TAesOp.OutputLen: Int32;
begin
  Result := AES_BLOCK;
end;

{ ============================== #5  GHASH ================================= }

type
  TGhashOp = class sealed(TDudectOp)
  strict private
    FRnd: TCtRandom;
    FMul: IGcmMultiplier;
    FX, FFixedBlock: TBytes;
  public
    constructor Create(const AMul: IGcmMultiplier; ASeed: UInt64);
    procedure PrepareSecret(AClass: Int32); override;
    procedure RunOp; override;
    function SecretPtr: Pointer; override;
    function SecretLen: Int32; override;
    function OutputPtr: Pointer; override;
    function OutputLen: Int32; override;
  end;

constructor TGhashOp.Create(const AMul: IGcmMultiplier; ASeed: UInt64);
var
  LH: TBytes;
  LI: Int32;
begin
  inherited Create;
  FRnd := TCtRandom.Create(ASeed);
  FMul := AMul;
  // Fixed hash subkey H; the varied secret is the multiplied block (the value
  // that drives the table access pattern in the 4k engine).
  System.SetLength(LH, GHASH_BLOCK);
  for LI := 0 to GHASH_BLOCK - 1 do
    LH[LI] := Byte(LI * 31 + 7);
  FMul.Init(LH);
  System.SetLength(FX, GHASH_BLOCK);
  // Fixed block = a NON-extreme constant (see the AES note): constant-but-typical
  // so it separates from random via cropping for the leaky 4k control, without an
  // all-zero artifact falsely flagging the constant-time ImplMul64 subject.
  System.SetLength(FFixedBlock, GHASH_BLOCK);
  for LI := 0 to GHASH_BLOCK - 1 do
    FFixedBlock[LI] := Byte(LI * 13 + 5);
end;

procedure TGhashOp.PrepareSecret(AClass: Int32);
begin
  // Class-symmetric preparation: always draw, overwrite for the fixed class.
  FRnd.NextBytes(FX, 0, GHASH_BLOCK);
  if AClass = 0 then
    System.Move(FFixedBlock[0], FX[0], GHASH_BLOCK);
end;

procedure TGhashOp.RunOp;
begin
  FMul.MultiplyH(FX); // mutates FX in place (X := X * H)
end;

function TGhashOp.SecretPtr: Pointer;
begin
  Result := @FX[0];
end;

function TGhashOp.SecretLen: Int32;
begin
  Result := GHASH_BLOCK;
end;

function TGhashOp.OutputPtr: Pointer;
begin
  Result := @FX[0]; // X is transformed in place
end;

function TGhashOp.OutputLen: Int32;
begin
  Result := GHASH_BLOCK;
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

{ ============================== factories ================================ }

function MakeX25519(ASeed: UInt64): TDudectOp;
begin
  Result := TX25519Op.Create(ASeed);
end;

function BuildEcOp(const ACurveName: string; const AMul: IECMultiplier;
  ASeed: UInt64): TDudectOp;
var
  LX9: IX9ECParameters;
begin
  LX9 := TCustomNamedCurves.GetByName(ACurveName);
  Result := TECMulOp.Create(AMul, LX9.G, LX9.N, ASeed);
end;

function MakeP256CT(ASeed: UInt64): TDudectOp;
var
  LX9: IX9ECParameters;
begin
  LX9 := TCustomNamedCurves.GetByName('secp256r1');
  Result := TECMulOp.Create(LX9.Curve.Multiplier, LX9.G, LX9.N, ASeed);
end;

function MakeP256WNaf(ASeed: UInt64): TDudectOp;
begin
  Result := BuildEcOp('secp256r1', TWNafL2RMultiplier.Create as IECMultiplier, ASeed);
end;

function MakeSect283CT(ASeed: UInt64): TDudectOp;
var
  LX9: IX9ECParameters;
begin
  LX9 := TCustomNamedCurves.GetByName('sect283k1');
  Result := TECMulOp.Create(LX9.Curve.Multiplier, LX9.G, LX9.N, ASeed);
end;

function MakeSect283WTau(ASeed: UInt64): TDudectOp;
begin
  Result := BuildEcOp('sect283k1', TWTauNafMultiplier.Create as IECMultiplier, ASeed);
end;

function MakeSecp256k1CT(ASeed: UInt64): TDudectOp;
var
  LX9: IX9ECParameters;
begin
  LX9 := TCustomNamedCurves.GetByName('secp256k1');
  Result := TECMulOp.Create(LX9.Curve.Multiplier, LX9.G, LX9.N, ASeed);
end;

function MakeSecp256k1WNaf(ASeed: UInt64): TDudectOp;
begin
  Result := BuildEcOp('secp256k1', TWNafL2RMultiplier.Create as IECMultiplier, ASeed);
end;

function MakeSecp384r1CT(ASeed: UInt64): TDudectOp;
var
  LX9: IX9ECParameters;
begin
  LX9 := TCustomNamedCurves.GetByName('secp384r1');
  Result := TECMulOp.Create(LX9.Curve.Multiplier, LX9.G, LX9.N, ASeed);
end;

function MakeSecp384r1WNaf(ASeed: UInt64): TDudectOp;
begin
  Result := BuildEcOp('secp384r1', TWNafL2RMultiplier.Create as IECMultiplier, ASeed);
end;

function MakeSecp521r1CT(ASeed: UInt64): TDudectOp;
var
  LX9: IX9ECParameters;
begin
  LX9 := TCustomNamedCurves.GetByName('secp521r1');
  Result := TECMulOp.Create(LX9.Curve.Multiplier, LX9.G, LX9.N, ASeed);
end;

function MakeSecp521r1WNaf(ASeed: UInt64): TDudectOp;
begin
  Result := BuildEcOp('secp521r1', TWNafL2RMultiplier.Create as IECMultiplier, ASeed);
end;

{ Fixed-base comb subjects: the same TFpPointOps CT primitives as [d]Q, driven
  through the fixed-base multiplier ([k]G on the reused generator). Paired with
  the existing wNAF-on-G controls. }
function MakeSecp256r1Comb(ASeed: UInt64): TDudectOp;
var
  LX9: IX9ECParameters;
begin
  LX9 := TCustomNamedCurves.GetByName('secp256r1');
  Result := TECMulOp.Create(LX9.Curve.BasePointMultiplier, LX9.G, LX9.N, ASeed);
end;

function MakeSecp256k1Comb(ASeed: UInt64): TDudectOp;
var
  LX9: IX9ECParameters;
begin
  LX9 := TCustomNamedCurves.GetByName('secp256k1');
  Result := TECMulOp.Create(LX9.Curve.BasePointMultiplier, LX9.G, LX9.N, ASeed);
end;

function MakeSecp384r1Comb(ASeed: UInt64): TDudectOp;
var
  LX9: IX9ECParameters;
begin
  LX9 := TCustomNamedCurves.GetByName('secp384r1');
  Result := TECMulOp.Create(LX9.Curve.BasePointMultiplier, LX9.G, LX9.N, ASeed);
end;

function MakeSecp521r1Comb(ASeed: UInt64): TDudectOp;
var
  LX9: IX9ECParameters;
begin
  LX9 := TCustomNamedCurves.GetByName('secp521r1');
  Result := TECMulOp.Create(LX9.Curve.BasePointMultiplier, LX9.G, LX9.N, ASeed);
end;

function MakeAesBitsliced(ASeed: UInt64): TDudectOp;
begin
  Result := TAesOp.Create(TAesBitSlicedEngine.Create as IBlockCipher, 16, ASeed);
end;

function MakeAesTable(ASeed: UInt64): TDudectOp;
begin
  Result := TAesOp.Create(TAesEngine.Create as IBlockCipher, 16, ASeed);
end;

function MakeGhashBasic(ASeed: UInt64): TDudectOp;
begin
  Result := TGhashOp.Create(TBasicGcmMultiplier.Create as IGcmMultiplier, ASeed);
end;

function MakeGhashTable4k(ASeed: UInt64): TDudectOp;
begin
  Result := TGhashOp.Create(TTables4kGcmMultiplier.Create as IGcmMultiplier, ASeed);
end;

function P256Order: TBigInteger;
begin
  Result := TCustomNamedCurves.GetByName('secp256r1').N;
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

{ ============================== registries =============================== }

function ExpensiveCfg(ASeed: UInt64): TDudectConfig;
begin
  Result := TDudectConfig.Default;
  Result.WarmupSamples := 1000;
  Result.BatchSamples := 2000;
  Result.MaxSamples := 20000;
  Result.MinSamplesForDecision := 6000;
  Result.Seed := ASeed;
end;

function MediumCfg(ASeed: UInt64): TDudectConfig;
begin
  Result := TDudectConfig.Default;
  Result.WarmupSamples := 3000;
  Result.BatchSamples := 10000;
  Result.MaxSamples := 300000;
  Result.MinSamplesForDecision := 40000;
  Result.Seed := ASeed;
end;

function CheapCfg(ASeed: UInt64): TDudectConfig;
begin
  Result := TDudectConfig.Default;
  Result.WarmupSamples := 20000;
  Result.BatchSamples := 100000;
  Result.MaxSamples := 2000000;
  Result.MinSamplesForDecision := 200000;
  Result.Seed := ASeed;
end;

function MakeRow(const AName, ASubjectLabel, AControlLabel: string;
  AMakeSubject, AMakeControl: TCtOpFactory; const ACfg: TDudectConfig): TCtRow;
begin
  Result.Name := AName;
  Result.SubjectLabel := ASubjectLabel;
  Result.ControlLabel := AControlLabel;
  Result.MakeSubject := AMakeSubject;
  Result.MakeControl := AMakeControl;
  Result.Cfg := ACfg;
end;

function GetDudectRows: TCtRowArray;
begin
  System.SetLength(Result, 14);
  Result[0] := MakeRow('X25519', 'X25519 ladder', '',
    @MakeX25519, nil, MediumCfg(UInt64($0000000000000001)));
  Result[1] := MakeRow('P-256 [d]Q', 'value-type CT', 'wNAF (var-time)',
    @MakeP256CT, @MakeP256WNaf, ExpensiveCfg(UInt64($0000000000000002)));
  Result[2] := MakeRow('sect283k1 [d]Q', 'F2m Montgomery CT', 'WTauNAF (var-time)',
    @MakeSect283CT, @MakeSect283WTau, ExpensiveCfg(UInt64($0000000000000003)));
  // AES bit-sliced is a clean-subject demonstration only. The T-table engine's
  // leak is a fine cache-timing effect (key-dependent table lines) that stays
  // below dudect's noise floor on a hot-L1 microbenchmark; it is caught
  // deterministically by the Valgrind/ctgrind leg instead (see GetValgrindTargets).
  Result[3] := MakeRow('AES-128 block', 'Bit-sliced (CT)', '',
    @MakeAesBitsliced, nil, CheapCfg(UInt64($0000000000000004)));
  // GHASH ImplMul64 is a clean-subject demonstration only. Like AES, the 4k-table
  // engine's leak is a table access-pattern effect that stays below dudect's noise
  // floor on a hot-L1 microbenchmark; it is caught deterministically by the
  // Valgrind/ctgrind leg (data-dependent table index) instead.
  Result[4] := MakeRow('GHASH', 'ImplMul64 (CT)', '',
    @MakeGhashBasic, nil, CheapCfg(UInt64($0000000000000005)));
  // #6 tests the safegcd CORE (TMod.ModOddInverse on fixed-width Nats); #7 tests
  // the full TBigInteger WRAPPER - the exact ECDSA signer call k^-1 mod n - so the
  // nonce inverse is measured end-to-end, not just at the core.
  Result[5] := MakeRow('mod-inv (core)', 'safegcd core (CT)', 'variable-time core',
    @MakeModInvSafe, @MakeModInvVar, MediumCfg(UInt64($0000000000000006)));
  Result[6] := MakeRow('mod-inv (wrapper)', 'safegcd wrapper (CT)', 'variable-time wrapper',
    @MakeModInvWrapperSafe, @MakeModInvWrapperVar, MediumCfg(UInt64($0000000000000007)));
  // The remaining prime curves also run the value-type CT multiplier; measure each
  // explicitly against its wNAF (variable-time) control.
  Result[7] := MakeRow('secp256k1 [d]Q', 'value-type CT', 'wNAF (var-time)',
    @MakeSecp256k1CT, @MakeSecp256k1WNaf, ExpensiveCfg(UInt64($0000000000000008)));
  Result[8] := MakeRow('secp384r1 [d]Q', 'value-type CT', 'wNAF (var-time)',
    @MakeSecp384r1CT, @MakeSecp384r1WNaf, ExpensiveCfg(UInt64($0000000000000009)));
  Result[9] := MakeRow('secp521r1 [d]Q', 'value-type CT', 'wNAF (var-time)',
    @MakeSecp521r1CT, @MakeSecp521r1WNaf, ExpensiveCfg(UInt64($000000000000000A)));
  // Fixed-base comb [k]G on the reused generator: same CT primitives as [d]Q,
  // paired against wNAF-on-G (variable-time) controls.
  Result[10] := MakeRow('secp256r1 [k]G comb', 'value-type comb (CT)', 'wNAF (var-time)',
    @MakeSecp256r1Comb, @MakeP256WNaf, ExpensiveCfg(UInt64($000000000000000B)));
  Result[11] := MakeRow('secp256k1 [k]G comb', 'value-type comb (CT)', 'wNAF (var-time)',
    @MakeSecp256k1Comb, @MakeSecp256k1WNaf, ExpensiveCfg(UInt64($000000000000000C)));
  Result[12] := MakeRow('secp384r1 [k]G comb', 'value-type comb (CT)', 'wNAF (var-time)',
    @MakeSecp384r1Comb, @MakeSecp384r1WNaf, ExpensiveCfg(UInt64($000000000000000D)));
  Result[13] := MakeRow('secp521r1 [k]G comb', 'value-type comb (CT)', 'wNAF (var-time)',
    @MakeSecp521r1Comb, @MakeSecp521r1WNaf, ExpensiveCfg(UInt64($000000000000000E)));
end;

function MakeVg(const AName: string; AMake: TCtOpFactory;
  AExpectLeak: Boolean): TCtVgTarget;
begin
  Result.Name := AName;
  Result.Make := AMake;
  Result.ExpectLeak := AExpectLeak;
end;

function GetValgrindTargets: TCtVgTargetArray;
begin
  System.SetLength(Result, 5);
  Result[0] := MakeVg('x25519', @MakeX25519, False);
  Result[1] := MakeVg('aes-bitsliced', @MakeAesBitsliced, False);
  Result[2] := MakeVg('aes-ttable', @MakeAesTable, True);
  Result[3] := MakeVg('ghash-basic', @MakeGhashBasic, False);
  Result[4] := MakeVg('ghash-4k', @MakeGhashTable4k, True);
end;

end.
