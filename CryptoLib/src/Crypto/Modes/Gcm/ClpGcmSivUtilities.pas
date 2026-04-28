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

unit ClpGcmSivUtilities;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpCryptoLibTypes;

type
  TGcmSivUtilities = class sealed(TObject)
  public
    /// <summary>
    ///   In-place GHASH-variant MulX over GF(2^128) with the GCM
    ///   irreducible polynomial x^128 + x^7 + x^2 + x + 1, on a
    ///   16-byte buffer in GCM canonical (big-endian) byte order.
    /// </summary>
    class procedure MulX(const AValue: TCryptoLibByteArray); static;
  end;

implementation

{ TGcmSivUtilities }

class procedure TGcmSivUtilities.MulX(const AValue: TCryptoLibByteArray);
var
  LMask, LValue: Byte;
  LI: Int32;
begin
  LMask := 0;
  for LI := 0 to 15 do
  begin
    LValue := AValue[LI];
    AValue[LI] := Byte(((LValue shr 1) and (not Byte($80))) or LMask);
    if (LValue and 1) = 0 then
      LMask := 0
    else
      LMask := $80;
  end;
  if LMask <> 0 then
    AValue[0] := AValue[0] xor Byte($E1);
end;

end.
