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

unit ClpConverters;

{$I ..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpCryptoLibTypes;

resourcestring
  SEncodingInstanceNil = 'Encoding Instance Cannot Be Nil';

type
  TConverters = class sealed(TObject)

  public

    class function ConvertStringToBytes(const AInput: String;
      AEncoding: TEncoding): TCryptoLibByteArray; overload; static;

    class function ConvertBytesToString(const AInput: TCryptoLibByteArray;
      const AEncoding: TEncoding): String; overload; static;

    class function ConvertCharArrayToString(const AInput: TCryptoLibCharArray): String; static;

    class function ConvertStringToCharArray(const AInput: String): TCryptoLibCharArray; static;

  end;

implementation

{ TConverters }

class function TConverters.ConvertStringToBytes(const AInput: String;
  AEncoding: TEncoding): TCryptoLibByteArray;
begin
  if AEncoding = nil then
  begin
    raise EArgumentNilCryptoLibException.CreateRes(@SEncodingInstanceNil);
  end;

{$IFDEF FPC}
  Result := AEncoding.GetBytes(UnicodeString(AInput));
{$ELSE}
  Result := AEncoding.GetBytes(AInput);
{$ENDIF FPC}
end;

class function TConverters.ConvertBytesToString(const AInput: TCryptoLibByteArray;
  const AEncoding: TEncoding): String;
begin
  if AEncoding = nil then
  begin
    raise EArgumentNilCryptoLibException.CreateRes(@SEncodingInstanceNil);
  end;

{$IFDEF FPC}
  Result := String(AEncoding.GetString(AInput));
{$ELSE}
  Result := AEncoding.GetString(AInput);
{$ENDIF FPC}
end;

class function TConverters.ConvertCharArrayToString(const AInput: TCryptoLibCharArray): String;
begin
  if (AInput = nil) or (System.Length(AInput) = 0) then
    Result := ''
  else
    System.SetString(Result, PChar(@AInput[0]), System.Length(AInput));
end;

class function TConverters.ConvertStringToCharArray(const AInput: String): TCryptoLibCharArray;
var
  LI: Int32;
begin
  System.SetLength(Result, System.Length(AInput));
  for LI := 0 to System.Length(AInput) - 1 do
    Result[LI] := AInput[LI + 1];
end;

end.
