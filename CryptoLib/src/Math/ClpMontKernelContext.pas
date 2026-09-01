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

unit ClpMontKernelContext;

{$I ..\Include\CryptoLib.inc}

interface

uses
  ClpMontKernelSimd,
  ClpIMontKernelContext,
  ClpCryptoLibTypes,
  ClpCryptoLibExceptions;

resourcestring
  SMontKernelUnavailable =
    'Montgomery kernel unavailable after the width probe succeeded';

type

  /// <summary>Concrete <see cref="IMontKernelContext"/>: builds the context (n0', R^2,
  /// limbs) once and drives the Montgomery kernel.</summary>
  TMontKernelContext = class sealed(TInterfacedObject, IMontKernelContext)
  strict private
  var
    FCtx, FRR: TCryptoLibUInt64Array;
    FN64: Int32;
    FEngaged: Boolean;
    function GetN64: Int32;
    function GetEngaged: Boolean;
  public
    /// <summary>Build from the low <c>AN64</c> 64-bit limbs of an odd modulus and its
    /// precomputed <c>R^2 mod n</c> (also <c>AN64</c> limbs; computed by the caller so
    /// this unit stays limb-only). <c>Engaged</c> reports whether the kernel engages for
    /// this width; if not, the caller must use a scalar path. Pass <c>ARRLimbs = nil</c>
    /// to probe engagement without <c>R^2</c> when the caller never enters Montgomery form
    /// (<c>ToMontgomery</c> then raises).</summary>
    constructor Create(const AModulusLimbs, ARRLimbs: TCryptoLibUInt64Array; AN64: Int32);
    function MatchesModulus(const AModulusLimbs: TCryptoLibUInt64Array): Boolean;
    procedure Mul(const AScratch, AX, AY, ADst: TCryptoLibUInt64Array);
    procedure Sqr(const AScratch, AX, ADst: TCryptoLibUInt64Array);
    procedure ToMontgomery(const AScratch, ABase, ADst: TCryptoLibUInt64Array);
  end;

implementation

{ TMontKernelContext }

constructor TMontKernelContext.Create(const AModulusLimbs,
  ARRLimbs: TCryptoLibUInt64Array; AN64: Int32);
var
  LN0: UInt64;
  LI: Int32;
  LProbe, LInput: TCryptoLibUInt64Array;
begin
  inherited Create;
  FEngaged := False;
  if AN64 < 2 then
    Exit;
  FN64 := AN64;
  System.SetLength(FCtx, FN64 + 2);
  FCtx[1] := UInt64(FN64);
  System.Move(AModulusLimbs[0], FCtx[2], FN64 * System.SizeOf(UInt64));
  LN0 := AModulusLimbs[0];
  for LI := 1 to 5 do
    LN0 := LN0 * (UInt64(2) - AModulusLimbs[0] * LN0);
  FCtx[0] := UInt64(0) - LN0;
  if ARRLimbs <> nil then
  begin
    System.SetLength(FRR, FN64);
    System.Move(ARRLimbs[0], FRR[0], FN64 * System.SizeOf(UInt64));
  end;
  // probe with a throwaway N64+2 CIOS accumulator over a zeroed N64 input; the result
  // buffer must not alias the input.
  System.SetLength(LProbe, FN64 + 2);
  System.SetLength(LInput, FN64);
  FEngaged := TMontKernelSimd.TryMontMul(PUInt64(@LProbe[0]), PUInt64(@LInput[0]),
    PUInt64(@LInput[0]), PUInt64(@FCtx[0]));
end;

function TMontKernelContext.GetN64: Int32;
begin
  Result := FN64;
end;

function TMontKernelContext.GetEngaged: Boolean;
begin
  Result := FEngaged;
end;

function TMontKernelContext.MatchesModulus(const AModulusLimbs: TCryptoLibUInt64Array): Boolean;
var
  LI: Int32;
begin
  Result := False;
  if (not FEngaged) or (System.Length(AModulusLimbs) <> FN64) then
    Exit;
  for LI := 0 to FN64 - 1 do
    if AModulusLimbs[LI] <> FCtx[2 + LI] then
      Exit;
  Result := True;
end;

procedure TMontKernelContext.Mul(const AScratch, AX, AY, ADst: TCryptoLibUInt64Array);
begin
  if not FEngaged then
    raise EInvalidOperationCryptoLibException.CreateRes(@SMontKernelUnavailable);
  // the width was probed at build; a False here means the kernel was disabled since,
  // leaving the scratch unwritten - never publish it as a result.
  if not TMontKernelSimd.TryMontMul(PUInt64(@AScratch[0]), PUInt64(@AX[0]),
    PUInt64(@AY[0]), PUInt64(@FCtx[0])) then
    raise EInvalidOperationCryptoLibException.CreateRes(@SMontKernelUnavailable);
  System.Move(AScratch[0], ADst[0], FN64 * System.SizeOf(UInt64));
end;

procedure TMontKernelContext.Sqr(const AScratch, AX, ADst: TCryptoLibUInt64Array);
begin
  if not FEngaged then
    raise EInvalidOperationCryptoLibException.CreateRes(@SMontKernelUnavailable);
  if TMontKernelSimd.TryMontSqr(PUInt64(@AScratch[0]), PUInt64(@AX[0]),
    PUInt64(@FCtx[0])) then
    System.Move(AScratch[0], ADst[0], FN64 * System.SizeOf(UInt64))
  else
    Mul(AScratch, AX, AX, ADst);
end;

procedure TMontKernelContext.ToMontgomery(const AScratch, ABase, ADst: TCryptoLibUInt64Array);
begin
  if FRR = nil then
    raise EInvalidOperationCryptoLibException.CreateRes(@SMontKernelUnavailable);
  Mul(AScratch, ABase, FRR, ADst);
end;

end.
