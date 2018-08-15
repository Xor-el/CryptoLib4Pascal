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

unit ClpHex;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SbpBase16,
  ClpCryptoLibTypes;

type
  THex = class sealed(TObject)

  public
    class function Decode(const Hex: String): TCryptoLibByteArray; static;
    class function Encode(const Input: TCryptoLibByteArray;
      UpperCase: Boolean = True): String; static;
  end;

implementation

{ THex }

class function THex.Decode(const Hex: String): TCryptoLibByteArray;
begin
  result := SbpBase16.TBase16.Decode(Hex);
end;

class function THex.Encode(const Input: TCryptoLibByteArray;
  UpperCase: Boolean): String;
begin
  case UpperCase of
    True:
      result := SbpBase16.TBase16.EncodeUpper(Input);
    False:
      result := SbpBase16.TBase16.EncodeLower(Input);
  end;
end;

end.
