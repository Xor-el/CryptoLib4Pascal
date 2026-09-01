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

unit ClpRsaBlinding;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SyncObjs,
  SysUtils,
  ClpBigInteger,
  ClpBigIntegerUtilities,
  ClpIMontKernelContext,
  ClpPack,
  ClpArrayUtilities,
  ClpRsaBlindingTypes,
  ClpIRsaBlinding,
  ClpISecureRandom,
  ClpCryptoLibTypes,
  ClpCryptoLibExceptions;

resourcestring
  SBlindingInverseFailed =
    'unable to derive an RSA blinding inverse (modulus not relatively prime to the drawn factors)';

type

  /// <summary>
  /// Shared skeleton for the per-key RSA blinding cache. Owns the lock, the refresh
  /// policy, and the strategy-agnostic work: generating a fresh random r and deriving
  /// the plain pair (A = r^e, Ai = r^-1). Each signature advances the cache (square, or
  /// refresh every <c>RefreshInterval</c>) under the lock, then blinds/signs/unblinds on
  /// its own snapshot outside the lock, so one key can be signed concurrently.
  ///
  /// A concrete strategy supplies only the representation-specific steps; the factory
  /// picks the Montgomery-kernel strategy when it engages for the key's width, otherwise
  /// the portable BigInteger strategy.
  /// </summary>
  TRsaBlindingBase = class abstract(TInterfacedObject, IRsaBlinding)
  strict private
  const
    RefreshInterval = Int32(32);
    MaxInverseRetries = Int32(64);
  var
    FLock: TCriticalSection;
    FExponent: TBigInteger;
    FRandom: ISecureRandom;
    FCounter: Int32;
    FHasPair: Boolean;
    procedure Refresh;
  strict protected
    FModulus: TBigInteger;
    FModContext: IMontKernelContext;
    // store a freshly generated plain pair in the strategy's representation.
    procedure DoRefresh(const ABlind, AUnblind: TBigInteger); virtual; abstract;
    // advance the cached pair: (A, Ai) -> (A^2, Ai^2), the pair for r^2.
    procedure DoAdvance; virtual; abstract;
    // copy the advanced pair into this signature's private snapshot.
    procedure DoSnapshot(out APair: TRsaBlindingPair); virtual; abstract;
    function DoBlind(const APair: TRsaBlindingPair; const AInput: TBigInteger): TBigInteger; virtual; abstract;
    function DoUnblind(const APair: TRsaBlindingPair; const AResult: TBigInteger): TBigInteger; virtual; abstract;
  public
    constructor Create(const AModulus, AExponent: TBigInteger;
      const ARandom: ISecureRandom; const AModContext: IMontKernelContext);
    destructor Destroy; override;
    class function NewBlinding(const AModulus, AExponent: TBigInteger;
      const ARandom: ISecureRandom; const AModContext: IMontKernelContext): IRsaBlinding; static;
    procedure Acquire(out APair: TRsaBlindingPair);
    function Blind(const APair: TRsaBlindingPair; const AInput: TBigInteger): TBigInteger;
    function Unblind(const APair: TRsaBlindingPair; const AResult: TBigInteger): TBigInteger;
  end;

implementation

type

  /// <summary>Scalar BigInteger blinding strategy (kernel-free fallback).</summary>
  TScalarRsaBlinding = class sealed(TRsaBlindingBase)
  strict private
    FBlind, FUnblind: TBigInteger;
  strict protected
    procedure DoRefresh(const ABlind, AUnblind: TBigInteger); override;
    procedure DoAdvance; override;
    procedure DoSnapshot(out APair: TRsaBlindingPair); override;
    function DoBlind(const APair: TRsaBlindingPair; const AInput: TBigInteger): TBigInteger; override;
    function DoUnblind(const APair: TRsaBlindingPair; const AResult: TBigInteger): TBigInteger; override;
  end;

  /// <summary>Montgomery-kernel blinding strategy: the factors live permanently in
  /// Montgomery form and blind/unblind/square are kernel multiplies.</summary>
  TKernelRsaBlinding = class sealed(TRsaBlindingBase)
  strict private
    FN64: Int32;
    FBlindMont, FUnblindMont, FKernelScratch: TCryptoLibUInt64Array;
    function ToLimbs(const AValue: TBigInteger): TCryptoLibUInt64Array;
    function FromLimbs(const ALimbs: TCryptoLibUInt64Array): TBigInteger;
    procedure Wipe(const ALimbs: TCryptoLibUInt64Array);
  strict protected
    procedure DoRefresh(const ABlind, AUnblind: TBigInteger); override;
    procedure DoAdvance; override;
    procedure DoSnapshot(out APair: TRsaBlindingPair); override;
    function DoBlind(const APair: TRsaBlindingPair; const AInput: TBigInteger): TBigInteger; override;
    function DoUnblind(const APair: TRsaBlindingPair; const AResult: TBigInteger): TBigInteger; override;
  public
    constructor Create(const AModulus, AExponent: TBigInteger;
      const ARandom: ISecureRandom; const AContext: IMontKernelContext);
    destructor Destroy; override;
  end;

{ TRsaBlindingBase }

constructor TRsaBlindingBase.Create(const AModulus, AExponent: TBigInteger;
  const ARandom: ISecureRandom; const AModContext: IMontKernelContext);
begin
  inherited Create;
  FLock := TCriticalSection.Create;
  FModulus := AModulus;
  FExponent := AExponent;
  FRandom := ARandom;
  FModContext := AModContext;
  FCounter := 0;
  FHasPair := False;
end;

destructor TRsaBlindingBase.Destroy;
begin
  FLock.Free;
  inherited Destroy;
end;

class function TRsaBlindingBase.NewBlinding(const AModulus, AExponent: TBigInteger;
  const ARandom: ISecureRandom; const AModContext: IMontKernelContext): IRsaBlinding;
begin
  // reuse the key's shared modulus context when the kernel engages for its width;
  // otherwise the portable strategy.
  if (AModContext <> nil) and AModContext.Engaged then
    Result := TKernelRsaBlinding.Create(AModulus, AExponent, ARandom, AModContext)
  else
    Result := TScalarRsaBlinding.Create(AModulus, AExponent, ARandom, AModContext);
end;

procedure TRsaBlindingBase.Refresh;
var
  LR, LBlind, LUnblind: TBigInteger;
  LTries: Int32;
begin
  LTries := 0;
  while True do
  begin
    // floor at 2: r=1 would yield an identity pair for a whole refresh cycle.
    LR := TBigIntegerUtilities.CreateRandomInRange(TBigInteger.Two,
      FModulus.Subtract(TBigInteger.One), FRandom);
    try
      // r^-1 mod n exists iff gcd(r, n) = 1; a shared factor is astronomically
      // unlikely for random r < n = p*q, but bounded-retry rather than trust it.
      LUnblind := TBigIntegerUtilities.ModOddInverse(FModulus, LR);
      Break;
    except
      on E: EArithmeticCryptoLibException do
      begin
        System.Inc(LTries);
        if LTries >= MaxInverseRetries then
          raise EInvalidOperationCryptoLibException.CreateRes(@SBlindingInverseFailed);
      end;
    end;
  end;
  // reuse the key's cached context for r^e; a disengaged context falls through to scalar.
  LBlind := LR.ModPowMont(FExponent, FModulus, FModContext);
  DoRefresh(LBlind, LUnblind);
  FCounter := 0;
  FHasPair := True;
end;

procedure TRsaBlindingBase.Acquire(out APair: TRsaBlindingPair);
begin
  FLock.Acquire;
  try
    if (not FHasPair) or (FCounter >= RefreshInterval) then
      Refresh
    else
      DoAdvance;
    System.Inc(FCounter);
    DoSnapshot(APair);
  finally
    FLock.Release;
  end;
end;

function TRsaBlindingBase.Blind(const APair: TRsaBlindingPair;
  const AInput: TBigInteger): TBigInteger;
begin
  Result := DoBlind(APair, AInput);
end;

function TRsaBlindingBase.Unblind(const APair: TRsaBlindingPair;
  const AResult: TBigInteger): TBigInteger;
begin
  Result := DoUnblind(APair, AResult);
end;

{ TScalarRsaBlinding }

procedure TScalarRsaBlinding.DoRefresh(const ABlind, AUnblind: TBigInteger);
begin
  FBlind := ABlind;
  FUnblind := AUnblind;
end;

procedure TScalarRsaBlinding.DoAdvance;
begin
  FBlind := FBlind.Multiply(FBlind).&Mod(FModulus);
  FUnblind := FUnblind.Multiply(FUnblind).&Mod(FModulus);
end;

procedure TScalarRsaBlinding.DoSnapshot(out APair: TRsaBlindingPair);
begin
  APair.Blind := FBlind;
  APair.Unblind := FUnblind;
end;

function TScalarRsaBlinding.DoBlind(const APair: TRsaBlindingPair;
  const AInput: TBigInteger): TBigInteger;
begin
  Result := APair.Blind.Multiply(AInput).&Mod(FModulus);
end;

function TScalarRsaBlinding.DoUnblind(const APair: TRsaBlindingPair;
  const AResult: TBigInteger): TBigInteger;
begin
  Result := APair.Unblind.Multiply(AResult).&Mod(FModulus);
end;

{ TKernelRsaBlinding }

constructor TKernelRsaBlinding.Create(const AModulus, AExponent: TBigInteger;
  const ARandom: ISecureRandom; const AContext: IMontKernelContext);
begin
  inherited Create(AModulus, AExponent, ARandom, AContext);
  FN64 := AContext.N64;
  System.SetLength(FBlindMont, FN64);
  System.SetLength(FUnblindMont, FN64);
  System.SetLength(FKernelScratch, FN64 + 2);
end;

destructor TKernelRsaBlinding.Destroy;
begin
  Wipe(FBlindMont);
  Wipe(FUnblindMont);
  Wipe(FKernelScratch);
  inherited Destroy;
end;

function TKernelRsaBlinding.ToLimbs(const AValue: TBigInteger): TCryptoLibUInt64Array;
begin
  System.SetLength(Result, FN64);
  AValue.ToUInt64sLittleEndian(Result, FN64);
end;

function TKernelRsaBlinding.FromLimbs(const ALimbs: TCryptoLibUInt64Array): TBigInteger;
var
  LBytes: TCryptoLibByteArray;
  LI: Int32;
begin
  System.SetLength(LBytes, FN64 * 8);
  for LI := 0 to FN64 - 1 do
    TPack.UInt64_To_BE(ALimbs[FN64 - 1 - LI], LBytes, LI * 8);
  Result := TBigInteger.Create(Int32(1), LBytes, True);
end;

procedure TKernelRsaBlinding.Wipe(const ALimbs: TCryptoLibUInt64Array);
begin
  TArrayUtilities.Fill(ALimbs, 0, System.Length(ALimbs), UInt64(0));
end;

procedure TKernelRsaBlinding.DoRefresh(const ABlind, AUnblind: TBigInteger);
var
  LLimbs: TCryptoLibUInt64Array;
begin
  // move both factors into Montgomery form; the MontMul overwrites the whole buffer,
  // so the superseded pair leaves no residue.
  LLimbs := ToLimbs(ABlind);
  FModContext.ToMontgomery(FKernelScratch, LLimbs, FBlindMont);
  Wipe(LLimbs);
  LLimbs := ToLimbs(AUnblind);
  FModContext.ToMontgomery(FKernelScratch, LLimbs, FUnblindMont);
  Wipe(LLimbs);
end;

procedure TKernelRsaBlinding.DoAdvance;
begin
  FModContext.Sqr(FKernelScratch, FBlindMont, FBlindMont);
  FModContext.Sqr(FKernelScratch, FUnblindMont, FUnblindMont);
end;

procedure TKernelRsaBlinding.DoSnapshot(out APair: TRsaBlindingPair);
begin
  // copy the advanced pair into this signature's private buffers so the cache can
  // advance again while the signature runs outside the lock.
  System.SetLength(APair.BlindMont, FN64);
  System.SetLength(APair.UnblindMont, FN64);
  System.Move(FBlindMont[0], APair.BlindMont[0], FN64 * System.SizeOf(UInt64));
  System.Move(FUnblindMont[0], APair.UnblindMont[0], FN64 * System.SizeOf(UInt64));
  System.SetLength(APair.Scratch, FN64 + 2);
end;

function TKernelRsaBlinding.DoBlind(const APair: TRsaBlindingPair;
  const AInput: TBigInteger): TBigInteger;
var
  LOut: TCryptoLibUInt64Array;
begin
  // MontMul(input, A*R) = input*A mod n, back in the plain domain.
  System.SetLength(LOut, FN64);
  FModContext.Mul(APair.Scratch, ToLimbs(AInput), APair.BlindMont, LOut);
  Result := FromLimbs(LOut);
end;

function TKernelRsaBlinding.DoUnblind(const APair: TRsaBlindingPair;
  const AResult: TBigInteger): TBigInteger;
var
  LOut: TCryptoLibUInt64Array;
begin
  // MontMul(s, Ai*R) = s*Ai mod n, back in the plain domain.
  System.SetLength(LOut, FN64);
  FModContext.Mul(APair.Scratch, ToLimbs(AResult), APair.UnblindMont, LOut);
  Result := FromLimbs(LOut);
end;

end.
