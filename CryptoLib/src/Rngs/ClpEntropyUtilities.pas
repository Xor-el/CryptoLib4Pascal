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

unit ClpEntropyUtilities;

{$I ..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpCryptoLibTypes,
  ClpIEntropySource;

type
  TEntropyUtilities = class sealed(TObject)
  public
    class function GenerateSeed(const AEntropySource: IEntropySource;
      ANumBytes: Int32): TCryptoLibByteArray; static;
  end;

implementation

{ TEntropyUtilities }

class function TEntropyUtilities.GenerateSeed(const AEntropySource: IEntropySource;
  ANumBytes: Int32): TCryptoLibByteArray;
var
  LCount, LToCopy: Int32;
  LEntropy: TCryptoLibByteArray;
begin
  System.SetLength(Result, ANumBytes);
  LCount := 0;
  while LCount < ANumBytes do
  begin
    LEntropy := AEntropySource.GetEntropy;
    LToCopy := ANumBytes - LCount;
    if LToCopy > System.Length(LEntropy) then
      LToCopy := System.Length(LEntropy);
    System.Move(LEntropy[0], Result[LCount], LToCopy * System.SizeOf(Byte));
    Inc(LCount, LToCopy);
  end;
end;

end.
