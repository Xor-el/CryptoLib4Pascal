{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                    Copyright (c) 2018 Ugochukwu Mmaduekwe                       * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }

{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }

{ *                              Acknowledgements:                                  * }
{ *                                                                                 * }
{ *        Thanks to Sphere 10 Software (http://sphere10.com) for sponsoring        * }
{ *                        the development of this library                          * }

{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit ClpBase64;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
{$IFDEF DELPHIXE7_UP}
  System.NetEncoding,
{$ENDIF DELPHIXE7_UP}
{$IFDEF DELPHI}
  Classes,
  EncdDecd,
{$ENDIF DELPHI}
{$IFDEF FPC}
  base64,
{$ENDIF FPC}
  SysUtils,
  ClpCryptoLibTypes;

type
  TBase64 = class sealed(TObject)

  public
    class function Encode(Input: TCryptoLibByteArray): String; static;
    class function Decode(const Input:
{$IFDEF FPC}UnicodeString{$ELSE}String{$ENDIF FPC})
      : TCryptoLibByteArray; static;
  end;

implementation

{ TBase64 }

class function TBase64.Decode(const Input:
{$IFDEF FPC}UnicodeString{$ELSE}String{$ENDIF FPC}): TCryptoLibByteArray;
begin
{$IFDEF DELPHIXE7_UP}
  Result := TNetEncoding.base64.DecodeStringToBytes(Input);
{$ELSE}
{$IFDEF DELPHI}
  Result := DecodeBase64(Input);
{$ENDIF DELPHI}
{$ENDIF DELPHIXE7_UP}
{$IFDEF FPC}
  Result := TEncoding.UTF8.GetBytes
    (UnicodeString(DecodeStringBase64(String(Input))));
{$ENDIF FPC}
end;

class function TBase64.Encode(Input: TCryptoLibByteArray): String;
var
{$IFDEF DELPHIXE7_UP}
  TempHolder: TCryptoLibByteArray;
{$ELSE}
{$IFDEF DELPHI}
  TempHolder: TBytesStream;
{$ENDIF DELPHI}
{$ENDIF DELPHIXE7_UP}
{$IFDEF FPC}
  TempHolder: String;
{$ENDIF FPC}
begin
{$IFDEF DELPHIXE7_UP}
  TempHolder := Input;
{$ELSE}
{$IFDEF DELPHI}
  TempHolder := TBytesStream.Create(Input);
{$ENDIF DELPHI}
{$ENDIF DELPHIXE7_UP}
{$IFDEF FPC}
  TempHolder := EncodeStringBase64(String(TEncoding.UTF8.GetString(Input)));
{$ENDIF FPC}
{$IFDEF DELPHIXE7_UP}
  Result := StringReplace(TNetEncoding.base64.EncodeBytesToString(TempHolder),
    sLineBreak, '', [rfReplaceAll]);
{$ELSE}
{$IFDEF DELPHI}
  try
    Result := StringReplace(String(EncodeBase64(TempHolder.Memory,
      TempHolder.Size)), sLineBreak, '', [rfReplaceAll]);
  finally
    TempHolder.Free;
  end;
{$ENDIF DELPHI}
{$ENDIF DELPHIXE7_UP}
{$IFDEF FPC}
  Result := TempHolder;
{$ENDIF FPC}
end;

end.
