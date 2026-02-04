{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                Copyright (c) 2018 - 20XX Ugochukwu Mmaduekwe                    * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }

{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }

{ *                              Acknowledgements:                                  * }
{ *                                                                                 * }
{ *      Thanks to Sphere 10 Software (http://www.sphere10.com/) for sponsoring     * }
{ *                           development of this library                           * }

{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit ClpWnaf;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpBitOperations,
  ClpCryptoLibTypes;

type
  TWnaf = class sealed
  public
    class procedure GetSignedVar(const AN: TCryptoLibUInt32Array; AWidth: Int32;
      AWs: TCryptoLibShortIntArray); static;
  end;

implementation

{ TWnaf }

class procedure TWnaf.GetSignedVar(const AN: TCryptoLibUInt32Array; AWidth: Int32;
  AWs: TCryptoLibShortIntArray);
var
  LT: TCryptoLibUInt32Array;
  Lc, LNext, LWord: UInt32;
  LtPos, LI, LJ, LLead, LSign, LWord16, LSkip, LDigit: Int32;
begin
  {$IFDEF DEBUG}
  System.Assert((2 <= AWidth) and (AWidth <= 8));
  {$ENDIF}
  System.SetLength(LT, System.Length(AN) * 2);

  if (AN[System.High(AN)] shr 31) <> 0 then
    Lc := $FFFFFFFF
  else
    Lc := 0;

  LtPos := System.Length(LT);
  LI := System.Length(AN);
  while LI > 0 do
  begin
    System.Dec(LI);
    LNext := AN[LI];
    System.Dec(LtPos);
    LT[LtPos] := (LNext shr 16) or (Lc shl 16);
    Lc := LNext;
    System.Dec(LtPos);
    LT[LtPos] := Lc;
  end;

  LJ := 0;
  LLead := 32 - AWidth;
  LSign := 0;

  LI := 0;
  while LI < System.Length(LT) do
  begin
    LWord := LT[LI];
    while LJ < 16 do
    begin
      LWord16 := Int32(UInt32(LWord) shr (UInt32(LJ) and 31));
      LSkip := TBitOperations.NumberOfTrailingZeros32(UInt32((LSign xor LWord16) or (1 shl 16)));
      if LSkip > 0 then
      begin
        LJ := LJ + LSkip;
        continue;
      end;
      LDigit := (LWord16 or 1) shl LLead;
      LSign := TBitOperations.Asr32(LDigit, 31);
      AWs[(LI shl 4) + LJ] := ShortInt(TBitOperations.Asr32(LDigit, LLead));
      LJ := LJ + AWidth;
    end;
    LJ := LJ - 16;
    System.Inc(LI);
  end;
  {$IFDEF DEBUG}
  System.Assert(LSign = TBitOperations.Asr32(Int32(AN[System.High(AN)]), 31));
  {$ENDIF}
end;

end.
