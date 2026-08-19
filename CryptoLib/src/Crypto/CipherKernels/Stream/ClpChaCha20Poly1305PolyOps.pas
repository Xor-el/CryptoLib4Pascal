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

unit ClpChaCha20Poly1305PolyOps;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpCryptoLibTypes,
  ClpBinaryPrimitives;

type
  // Poly1305 state shared by the fused ChaCha20-Poly1305 kernels. The shape is
  // the asm ABI and is radix-selected by target: radix-2^26 on i386 (five 26-bit
  // limbs, poly1305-donna-32), radix-2^64 elsewhere (x86-64, aarch64). Exactly
  // one arm compiles per build, so the record has a single layout; the fused
  // kernel and block loop read/write the fields at their fixed offsets and the
  // FoldFromInput direction flag (0 encrypt, 1 decrypt) selects the fused fold.
  TChaCha20Poly1305PolyState = record
{$IFDEF CRYPTOLIB_I386_ASM}
    // radix-2^26: h/r/s at 4-byte spacing; FoldFromInput at byte 72.
    H0, H1, H2, H3, H4: UInt32;
    R0, R1, R2, R3, R4: UInt32;
    S1, S2, S3, S4: UInt32;
    Pad0, Pad1, Pad2, Pad3: UInt32;
    FoldFromInput: UInt32;
{$ELSE}
    // radix-2^64: r0..pad1 at [base + 8*k], FoldFromInput at byte 64; h0/h1/h2
    // are the running accumulator (in/out).
    R0, R1, S1, H0, H1, H2, Pad0, Pad1, FoldFromInput: UInt64;
{$ENDIF}
  end;

  // Arch-neutral Poly1305 field arithmetic shared by the fused kernels: the
  // per-message clamp and the final reduce-and-tag. The message block absorb
  // itself is the arch-specific asm (each kernel's UpdatePoly).
  TChaCha20Poly1305PolyOps = class sealed
  public
    // Clamp r from the 32-byte one-time poly key, derive the s = 5*r fold terms,
    // load the pad, and zero the accumulator.
    class procedure ClampInit(var AState: TChaCha20Poly1305PolyState;
      APolyKey: PByte); static;
    // Reduce h mod 2^130-5 (branch-free conditional subtract) and add the pad,
    // emitting the 16-byte tag; then zero the accumulator. Call after every
    // message and length block has been absorbed.
    class procedure ReduceAndTag(var AState: TChaCha20Poly1305PolyState;
      ATagOut: PByte); static;
  end;

implementation

{$IFDEF CRYPTOLIB_I386_ASM}
const
  MASK26 = UInt32($3FFFFFF);
{$ENDIF}

class procedure TChaCha20Poly1305PolyOps.ClampInit(
  var AState: TChaCha20Poly1305PolyState; APolyKey: PByte);
{$IFDEF CRYPTOLIB_I386_ASM}
var
  LT0, LT1, LT2, LT3: UInt32;
begin
  // Clamp r and split into five 26-bit limbs (the clamp masks are folded into
  // the split), then s = 5*r for the 2^130==5 fold; zero the accumulator.
  LT0 := TBinaryPrimitives.ReadUInt32LittleEndian(APolyKey, 0);
  LT1 := TBinaryPrimitives.ReadUInt32LittleEndian(APolyKey, 4);
  LT2 := TBinaryPrimitives.ReadUInt32LittleEndian(APolyKey, 8);
  LT3 := TBinaryPrimitives.ReadUInt32LittleEndian(APolyKey, 12);
  AState.R0 := LT0 and UInt32($3FFFFFF);
  AState.R1 := ((LT0 shr 26) or (LT1 shl 6)) and UInt32($3FFFF03);
  AState.R2 := ((LT1 shr 20) or (LT2 shl 12)) and UInt32($3FFC0FF);
  AState.R3 := ((LT2 shr 14) or (LT3 shl 18)) and UInt32($3F03FFF);
  AState.R4 := (LT3 shr 8) and UInt32($00FFFFF);
  AState.S1 := AState.R1 * 5;
  AState.S2 := AState.R2 * 5;
  AState.S3 := AState.R3 * 5;
  AState.S4 := AState.R4 * 5;
  AState.Pad0 := TBinaryPrimitives.ReadUInt32LittleEndian(APolyKey, 16);
  AState.Pad1 := TBinaryPrimitives.ReadUInt32LittleEndian(APolyKey, 20);
  AState.Pad2 := TBinaryPrimitives.ReadUInt32LittleEndian(APolyKey, 24);
  AState.Pad3 := TBinaryPrimitives.ReadUInt32LittleEndian(APolyKey, 28);
  AState.H0 := 0;
  AState.H1 := 0;
  AState.H2 := 0;
  AState.H3 := 0;
  AState.H4 := 0;
end;
{$ELSE}
var
  LR0, LR1: UInt64;
begin
  // Standard clamp: r &= 0x0ffffffc0ffffffc0ffffffc0fffffff.
  LR0 := TBinaryPrimitives.ReadUInt64LittleEndian(APolyKey, 0) and
    UInt64($0FFFFFFC0FFFFFFF);
  LR1 := TBinaryPrimitives.ReadUInt64LittleEndian(APolyKey, 8) and
    UInt64($0FFFFFFC0FFFFFFC);
  AState.R0 := LR0;
  AState.R1 := LR1;
  // r1 has its low 2 bits clear, so s1 = r1 + (r1 >> 2) = 5*r1/4 folds 2^130==5.
  AState.S1 := LR1 + (LR1 shr 2);
  AState.Pad0 := TBinaryPrimitives.ReadUInt64LittleEndian(APolyKey, 16);
  AState.Pad1 := TBinaryPrimitives.ReadUInt64LittleEndian(APolyKey, 24);
  AState.H0 := 0;
  AState.H1 := 0;
  AState.H2 := 0;
end;
{$ENDIF}

class procedure TChaCha20Poly1305PolyOps.ReduceAndTag(
  var AState: TChaCha20Poly1305PolyState; ATagOut: PByte);
{$IFDEF CRYPTOLIB_I386_ASM}
var
  LH0, LH1, LH2, LH3, LH4, LG0, LG1, LG2, LG3, LG4, LC, LMask, LNMask,
    LW0, LW1, LW2, LW3: UInt32;
  LF: UInt64;
begin
  // Final carry, reduce mod 2^130-5 (branch-free conditional subtract of p),
  // add the pad, and serialize the 16-byte tag (radix-2^26 donna finalize).
  LH0 := AState.H0;
  LH1 := AState.H1;
  LH2 := AState.H2;
  LH3 := AState.H3;
  LH4 := AState.H4;
  LC := LH1 shr 26; LH1 := LH1 and MASK26; System.Inc(LH2, LC);
  LC := LH2 shr 26; LH2 := LH2 and MASK26; System.Inc(LH3, LC);
  LC := LH3 shr 26; LH3 := LH3 and MASK26; System.Inc(LH4, LC);
  LC := LH4 shr 26; LH4 := LH4 and MASK26; System.Inc(LH0, LC * 5);
  LC := LH0 shr 26; LH0 := LH0 and MASK26; System.Inc(LH1, LC);
  // g = h + 5 then subtract 2^130; g4's borrow (high bit) means h < p.
  LG0 := LH0 + 5; LC := LG0 shr 26; LG0 := LG0 and MASK26;
  LG1 := LH1 + LC; LC := LG1 shr 26; LG1 := LG1 and MASK26;
  LG2 := LH2 + LC; LC := LG2 shr 26; LG2 := LG2 and MASK26;
  LG3 := LH3 + LC; LC := LG3 shr 26; LG3 := LG3 and MASK26;
  LG4 := LH4 + LC - (UInt32(1) shl 26);
  // mask = all-ones to select g (h >= p), 0 to keep h (h < p).
  LMask := UInt32(0) - (UInt32(1) - (LG4 shr 31));
  LNMask := not LMask;
  LH0 := (LH0 and LNMask) or (LG0 and LMask);
  LH1 := (LH1 and LNMask) or (LG1 and LMask);
  LH2 := (LH2 and LNMask) or (LG2 and LMask);
  LH3 := (LH3 and LNMask) or (LG3 and LMask);
  LH4 := (LH4 and LNMask) or (LG4 and LMask);
  // pack the five 26-bit limbs into four 32-bit words
  LW0 := LH0 or (LH1 shl 26);
  LW1 := (LH1 shr 6) or (LH2 shl 20);
  LW2 := (LH2 shr 12) or (LH3 shl 14);
  LW3 := (LH3 shr 18) or (LH4 shl 8);
  // tag = (h + pad) mod 2^128, little-endian
  LF := UInt64(LW0) + AState.Pad0; LW0 := UInt32(LF);
  LF := UInt64(LW1) + AState.Pad1 + (LF shr 32); LW1 := UInt32(LF);
  LF := UInt64(LW2) + AState.Pad2 + (LF shr 32); LW2 := UInt32(LF);
  LF := UInt64(LW3) + AState.Pad3 + (LF shr 32); LW3 := UInt32(LF);
  TBinaryPrimitives.WriteUInt32LittleEndian(ATagOut, 0, LW0);
  TBinaryPrimitives.WriteUInt32LittleEndian(ATagOut, 4, LW1);
  TBinaryPrimitives.WriteUInt32LittleEndian(ATagOut, 8, LW2);
  TBinaryPrimitives.WriteUInt32LittleEndian(ATagOut, 12, LW3);
  AState.H0 := 0;
  AState.H1 := 0;
  AState.H2 := 0;
  AState.H3 := 0;
  AState.H4 := 0;
end;
{$ELSE}
var
  LH0, LH1, LH2, LG0, LG1, LG2, LC, LMask, LT: UInt64;
begin
  LH0 := AState.H0;
  LH1 := AState.H1;
  LH2 := AState.H2;
  // g = h + 5 (h2 stays small, so one conditional subtract of p suffices).
  LG0 := LH0 + 5;
  LC := UInt64(Ord(LG0 < LH0));
  LG1 := LH1 + LC;
  LC := UInt64(Ord(LG1 < LH1));
  LG2 := LH2 + LC;
  // g >= 2^130 iff h >= p: select g (reduced) else h, branch-free.
  LMask := UInt64(0) - ((LG2 shr 2) and 1);
  LH0 := (LG0 and LMask) or (LH0 and (not LMask));
  LH1 := (LG1 and LMask) or (LH1 and (not LMask));
  // tag = (h + pad) mod 2^128.
  LT := LH0 + AState.Pad0;
  LC := UInt64(Ord(LT < LH0));
  LH0 := LT;
  LH1 := LH1 + AState.Pad1 + LC;
  TBinaryPrimitives.WriteUInt64LittleEndian(ATagOut, 0, LH0);
  TBinaryPrimitives.WriteUInt64LittleEndian(ATagOut, 8, LH1);
  AState.H0 := 0;
  AState.H1 := 0;
  AState.H2 := 0;
end;
{$ENDIF}

end.
