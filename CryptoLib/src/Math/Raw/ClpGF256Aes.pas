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

unit ClpGF256Aes;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpInterleave,
  ClpBitOperations,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// GF(2^8) arithmetic for the AES reduction polynomial.
  /// </summary>
  TGF256Aes = class sealed(TObject)
  public
    class function Mul(AA, AB: Int32): Int32; static;
    class function Sqr(AA: Int32): Int32; static;
    class function Inv(AA: Int32): Int32; static;
  end;

implementation

{ TGF256Aes }

class function TGF256Aes.Mul(AA, AB: Int32): Int32;
var
  LB, LC, LD, LE, LF: Int32;
begin
  LB := AB and $FF;

  LC := (LB shl 4) and -(AA and $10)
    xor (LB shl 5) and -(AA and $20)
    xor (LB shl 6) and -(AA and $40)
    xor (LB shl 7) and -(AA and $80);
  LD := (LB shl 0) and -(AA and $01)
    xor (LB shl 1) and -(AA and $02)
    xor (LB shl 2) and -(AA and $04)
    xor (LB shl 3) and -(AA and $08);

  LE := TBitOperations.Asr32(LC, 8);
  LE := LE xor (LE shl 1);
  LE := LE xor (LE shl 3);
  LD := LD xor LE;

  LF := TBitOperations.Asr32(LD, 8);
  LD := (LD xor LC) and $FF;
  LF := LF xor (LF shl 1);
  LF := LF xor (LF shl 3);
  LD := LD xor LF;

  Result := LD;
end;

class function TGF256Aes.Sqr(AA: Int32): Int32;
var
  LC, LHi: Int32;
begin
  LC := Int32(TInterleave.Expand4to8(Byte(AA)));
  LHi := $1B00 and -(AA and $10)
    xor $6C00 and -(AA and $20)
    xor $AB00 and -(AA and $40)
    xor $9A00 and -(AA and $80);
  Result := LC xor TBitOperations.Asr32(LHi, 8);
end;

class function TGF256Aes.Inv(AA: Int32): Int32;
var
  LA, LA2, LA4, LA6, LA8, LA14, LA28, LA56, LA112, LA126, LA252, LA254: Int32;
begin
  LA := AA and $FF;
  LA2 := Sqr(LA);
  LA4 := Sqr(LA2);
  LA8 := Sqr(LA4);
  LA6 := Mul(LA4, LA2);
  LA14 := Mul(LA8, LA6);
  LA28 := Sqr(LA14);
  LA56 := Sqr(LA28);
  LA112 := Sqr(LA56);
  LA126 := Mul(LA112, LA14);
  LA252 := Sqr(LA126);
  LA254 := Mul(LA252, LA2);
  Result := LA254;
end;

end.
