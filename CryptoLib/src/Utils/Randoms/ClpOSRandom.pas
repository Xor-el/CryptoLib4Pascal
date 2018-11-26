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

unit ClpOSRandom;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
{$IF DEFINED(MSWINDOWS)}
  Windows,
{$ELSE}
  Classes,
  SysUtils,
{$IFEND MSWINDOWS}
  ClpCryptoLibTypes;

resourcestring
{$IF DEFINED(MSWINDOWS)}
  SMSWIndowsCryptoAPIAvailableGenerationError =
    'An Error Occured while generating random data using MS WIndows Crypto API.';
{$ELSE}
  SUnixRandomReadError =
    'An Error Occured while reading random data from /dev/urandom or /dev/random.';
{$IFEND MSWINDOWS}

type

  /// <summary>
  /// <para>
  /// TOSRandom Number Class.
  /// </para>
  /// <para>
  /// This class returns random bytes from an OS-specific randomness
  /// source. The returned data should be unpredictable enough for
  /// cryptographic applications, though its exact quality depends on the
  /// OS implementation. On a UNIX-like system this will query
  /// /dev/urandom or /dev/random (if the former is not available) , and
  /// on MSWINDOWS it will use CryptGenRandom().
  /// </para>
  /// </summary>

  TOSRandom = class sealed(TObject)

  strict private

    class function NoZeroes(const data: TCryptoLibByteArray): Boolean;
      static; inline;

{$IF DEFINED(MSWINDOWS)}
    class function GenRandomBytesWindows(len: Int32; const data: PByte): Int32;
{$ELSE}
    class function GenRandomBytesUnix(len: Int32; const data: PByte): Int32;
{$IFEND $MSWINDOWS}
  public

    class procedure GetBytes(const data: TCryptoLibByteArray); static;
    class procedure GetNonZeroBytes(const data: TCryptoLibByteArray); static;

  end;

{$IFDEF MSWINDOWS}

const
  ADVAPI32 = 'advapi32.dll';

function CryptAcquireContextW(phProv: Pointer; pszContainer: LPCWSTR;
  pszProvider: LPCWSTR; dwProvType: DWORD; dwFlags: DWORD): BOOL; stdcall;
  external ADVAPI32 Name 'CryptAcquireContextW';

function CryptGenRandom(hProv: THandle; dwLen: DWORD; pbBuffer: PByte): BOOL;
  stdcall; external ADVAPI32 Name 'CryptGenRandom';

function CryptReleaseContext(hProv: THandle; dwFlags: DWORD): BOOL; stdcall;
  external ADVAPI32 Name 'CryptReleaseContext';
{$ENDIF MSWINDOWS}

implementation

class function TOSRandom.NoZeroes(const data: TCryptoLibByteArray): Boolean;
var
  i: Int32;
begin
  Result := True;
  for i := System.Low(data) to System.High(data) do
  begin
    if data[i] = 0 then
    begin
      Result := False;
      Exit;
    end;
  end;

end;

{$IF DEFINED(MSWINDOWS)}

class function TOSRandom.GenRandomBytesWindows(len: Int32;
  const data: PByte): Int32;
var
  hProv: THandle;
const
  PROV_RSA_FULL = 1;
  CRYPT_VERIFYCONTEXT = DWORD($F0000000);
  CRYPT_SILENT = $00000040;
begin
  if not CryptAcquireContextW(@hProv, nil, nil, PROV_RSA_FULL,
    CRYPT_VERIFYCONTEXT or CRYPT_SILENT) then
  begin
    Result := HResultFromWin32(GetLastError);
    Exit;
  end;

  try
    if not CryptGenRandom(hProv, len, data) then
    begin
      Result := HResultFromWin32(GetLastError);
      Exit;
    end;
  finally
    CryptReleaseContext(hProv, 0);
  end;

  Result := S_OK;
end;

{$ELSE}

class function TOSRandom.GenRandomBytesUnix(len: Int32;
  const data: PByte): Int32;
var
  LStream: TFileStream;
  RandGen: String;
begin
  RandGen := '/dev/urandom';
  if not FileExists(RandGen) then
  begin
    RandGen := '/dev/random';
    if not FileExists(RandGen) then
    begin
      Result := -1;
      Exit;
    end;
  end;

  LStream := TFileStream.Create(RandGen, fmOpenRead);

  try
    try
      LStream.ReadBuffer(data[0], len);
      Result := 0;
    except
      Result := -1;
    end;
  finally
    LStream.Free;
  end;
end;

{$IFEND MSWINDOWS}

class procedure TOSRandom.GetBytes(const data: TCryptoLibByteArray);
var
  count: Int32;
begin
  count := System.Length(data);
{$IF DEFINED(MSWINDOWS)}
  if GenRandomBytesWindows(count, PByte(data)) <> 0 then
  begin
    raise EAccessCryptoLibException.CreateRes
      (@SMSWIndowsCryptoAPIAvailableGenerationError);
  end;
{$ELSE}
  if GenRandomBytesUnix(count, PByte(data)) <> 0 then
  begin
    raise EAccessCryptoLibException.CreateRes(@SUnixRandomReadError);
  end;
{$IFEND MSWINDOWS}
end;

class procedure TOSRandom.GetNonZeroBytes(const data: TCryptoLibByteArray);
begin
  repeat
    TOSRandom.GetBytes(data);
  until (NoZeroes(data));
end;

end.
