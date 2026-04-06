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

unit ClpEncoders;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SbpBase16,
  SbpBase58,
  SbpBase64,
{$IFDEF DELPHI}
  SbpIBase58,
  SbpIBase64,
{$ENDIF DELPHI}
  ClpCryptoLibTypes;

type
  TBase58 = class sealed(TObject)

  public
    class function Encode(const Input: TCryptoLibByteArray): String; static;
    class function Decode(const Input: String): TCryptoLibByteArray; static;
  end;

type
  TBase64 = class sealed(TObject)

  public
    class function Encode(const Input: TCryptoLibByteArray): String; static;
    class function Decode(const Input: String): TCryptoLibByteArray; static;
  end;

type
  THex = class sealed(TObject)

  public
    class function Decode(const Hex: String): TCryptoLibByteArray; static;
    class function Encode(const Input: TCryptoLibByteArray;
      UpperCase: Boolean = True): String; static;
  end;

implementation

uses SbpBase16Alphabet, {SbpIBase16,} SbpICodingAlphabet;

{ TBase58 }

class function TBase58.Decode(const Input: String): TCryptoLibByteArray;
begin
  result := SbpBase58.TBase58.BitCoin.Decode(Input);
end;

class function TBase58.Encode(const Input: TCryptoLibByteArray): String;
begin
  result := SbpBase58.TBase58.BitCoin.Encode(Input);
end;

{ TBase64 }

class function TBase64.Decode(const Input: String): TCryptoLibByteArray;
begin
  result := SbpBase64.TBase64.Default.Decode(Input);
end;

class function TBase64.Encode(const Input: TCryptoLibByteArray): String;
begin
  result := SbpBase64.TBase64.Default.Encode(Input);
end;

{ THex }

class function THex.Decode(const Hex: String): TCryptoLibByteArray;
begin
  with SbpBase16.TBase16.Create(TBase16Alphabet.Create('0123456789ABCDEF') as ICodingAlphabet) do
    try;
      result := Decode(Hex);
    finally
      Free;
    end;
end;

class function THex.Encode(const Input: TCryptoLibByteArray;
  UpperCase: Boolean): String;
var
  Base16: SbpBase16.TBase16;
begin
  if UpperCase then
    Base16 := SbpBase16.TBase16.Create(TBase16Alphabet.Create('0123456789ABCDEF') as ICodingAlphabet)
  else
    Base16 := SbpBase16.TBase16.Create(TBase16Alphabet.Create('0123456789abcdef') as ICodingAlphabet);
  try
    result := Base16.Encode(Input)
  finally
    Base16.Free;
  end;
end;

end.
