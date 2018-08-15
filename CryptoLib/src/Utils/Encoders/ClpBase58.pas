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

unit ClpBase58;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SbpBase58,
{$IFDEF DELPHI}
  SbpIBase58,
{$ENDIF DELPHI}
  ClpCryptoLibTypes;

type
  TBase58 = class sealed(TObject)

  public
    class function Encode(const Input: TCryptoLibByteArray): String; static;
    class function Decode(const Input: String): TCryptoLibByteArray; static;
  end;

implementation

{ TBase58 }

class function TBase58.Decode(const Input: String): TCryptoLibByteArray;
begin
  result := SbpBase58.TBase58.BitCoin.Decode(Input);
end;

class function TBase58.Encode(const Input: TCryptoLibByteArray): String;
begin
  result := SbpBase58.TBase58.BitCoin.Encode(Input);
end;

end.
