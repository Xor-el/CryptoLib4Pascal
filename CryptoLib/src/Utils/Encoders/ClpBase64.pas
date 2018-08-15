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

unit ClpBase64;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SbpBase64,
{$IFDEF DELPHI}
  SbpIBase64,
{$ENDIF DELPHI}
  ClpCryptoLibTypes;

type
  TBase64 = class sealed(TObject)

  public
    class function Encode(const Input: TCryptoLibByteArray): String; static;
    class function Decode(const Input: String): TCryptoLibByteArray; static;
  end;

implementation

{ TBase64 }

class function TBase64.Decode(const Input: String): TCryptoLibByteArray;
begin
  result := SbpBase64.TBase64.Default.Decode(Input);
end;

class function TBase64.Encode(const Input: TCryptoLibByteArray): String;
begin
  result := SbpBase64.TBase64.Default.Encode(Input);
end;

end.
