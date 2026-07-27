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

unit ClpGaloisFieldUtilities;

{$I ..\Include\CryptoLib.inc}

interface

uses
  ClpBitOperations,
  ClpCryptoLibTypes;

type
  /// <summary>
  ///   Representation-neutral GF(2^128) primitives shared by the block-cipher
  ///   MAC / mode constructions (CMAC/OMAC, EAX, OCB). Distinct from the GHASH /
  ///   GCM field arithmetic in TGcmUtilities, which uses the reflected ($E1)
  ///   representation; these use the standard big-endian, MSB-first form.
  /// </summary>
  TGaloisFieldUtilities = class sealed(TObject)
  public
    /// <summary>
    ///   GF doubling (ADst := ASrc * x) in the standard big-endian, MSB-first
    ///   representation, with block-size-aware reduction: the x^128+x^7+x^2+x+1
    ///   constant ($87) for 16-byte blocks, x^64+x^4+x^3+x+1 ($1B) otherwise.
    ///   Branchless. Shared by CMAC (Lu/Lu2 subkeys), EAX (OMAC B/P subkeys) and
    ///   OCB (the L ladder). ASrc and ADst may alias (each source byte is read
    ///   before its destination is written).
    /// </summary>
    class procedure DoubleBlock(const ASrc, ADst: TCryptoLibByteArray); static;
  end;

implementation

{ TGaloisFieldUtilities }

class procedure TGaloisFieldUtilities.DoubleBlock(const ASrc,
  ADst: TCryptoLibByteArray);
var
  LI, LXorVal: Int32;
  LB, LCarry: UInt32;
begin
  LCarry := 0;
  LI := System.Length(ASrc);
  while LI > 0 do
  begin
    System.Dec(LI);
    LB := ASrc[LI];
    ADst[LI] := Byte((LB shl 1) or LCarry);
    LCarry := (LB shr 7) and 1;
  end;
  if System.Length(ASrc) = 16 then
    LXorVal := $87
  else
    LXorVal := $1B;
  // Branchless reduction: XOR the polynomial constant into the last byte iff the
  // top bit carried out (Asr32(k,0)=k when carry=1; Asr32(k,8)=0 when carry=0).
  ADst[System.Length(ASrc) - 1] := ADst[System.Length(ASrc) - 1]
    xor Byte(TBitOperations.Asr32(LXorVal, (1 - Int32(LCarry)) shl 3));
end;

end.
