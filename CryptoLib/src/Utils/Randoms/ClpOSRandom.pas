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
{$IFDEF MSWINDOWS}
  Windows
{$ELSE}
    Classes
{$ENDIF MSWINDOWS},
  SysUtils,
  ClpCryptoLibTypes;

resourcestring
{$IFDEF MSWINDOWS}
  SWindowsCryptoAPIUnavailable =
    'Unfortunately, Windows Crypto API is not available on this OS.';
  SWindowsCryptoAPIAvailableGenerationError =
    'WIndows Crypto API is available on this OS but an error occured while using it.';
{$ELSE}
  SUnixRandomUnavailable =
    '/dev/urandom or /dev/random is not available on this OS.';
  SUnixRandomReadError =
    '/dev/urandom or /dev/random found but an error occured while reading it (probably due to insufficient block of data to be read).';
{$ENDIF MSWINDOWS}

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
  /// on Windows it will use CryptGenRandom().
  /// </para>
  /// </summary>

  TOSRandom = class sealed(TObject)

  strict private

    class function NoZeroes(const data: TCryptoLibByteArray): Boolean;
      static; inline;

{$IFDEF MSWINDOWS}

  type
    TWCCryptAcquireContextA = function(phProv: Pointer; pszContainer: LPCSTR;
      pszProvider: LPCSTR; dwProvType: DWORD; dwFlags: DWORD): BOOL; stdcall;
    TWCCryptReleaseContext = function(hProv: Pointer; dwFlags: DWORD)
      : BOOL; stdcall;
    TWCCryptGenRandom = function(hProv: ULONG; dwLen: DWORD; pbBuffer: PBYTE)
      : BOOL; stdcall;
{$ENDIF MSWINDOWS}

  class var
{$IFDEF MSWINDOWS}
    FwinCryptOk: Int32; // Windows Random function available
    FhProvider: ULONG; // Windows HCryptProvider Handle
    FWinCryptHndl: THandle;
    FWCCryptAcquireContextA: TWCCryptAcquireContextA;
    FWCCryptReleaseContext: TWCCryptReleaseContext;
    FWCCryptGenRandom: TWCCryptGenRandom;
{$ELSE}
    FunixCryptOk: Int32; // Unix Random /dev/urandom or /dev/random available
    FStream: TFileStream;
{$ENDIF MSWINDOWS}
    class constructor CreateOSRandom();
    class destructor DestroyOSRandom();

  public

    class procedure GetBytes(const data: TCryptoLibByteArray); static;
    class procedure GetNonZeroBytes(const data: TCryptoLibByteArray); static;

  end;

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

class constructor TOSRandom.CreateOSRandom;
{$IFNDEF MSWINDOWS}
var
  RandGen: string;
{$ENDIF MSWINDOWS}
begin
{$IFDEF MSWINDOWS}
  FWinCryptHndl := LoadLibrary(PChar('advapi32.dll'));
  if (FWinCryptHndl < 32) then
  begin
    FwinCryptOk := -1;
    Exit;
  end;
  @FWCCryptAcquireContextA := GetProcAddress(FWinCryptHndl,
    'CryptAcquireContextA');
  @FWCCryptReleaseContext := GetProcAddress(FWinCryptHndl,
    'CryptReleaseContext');
  @FWCCryptGenRandom := GetProcAddress(FWinCryptHndl, 'CryptGenRandom');

  if FWCCryptAcquireContextA(@FhProvider, Nil, Nil, 1 { PROV_RSA_FULL } ,
    $F0000000 { CRYPT_VERIFYCONTEXT } ) then
  begin
    FwinCryptOk := 1;
  end;
{$ELSE}
  RandGen := '/dev/urandom';
  if not FileExists(RandGen) then
  begin
    if not FileExists('/dev/random') then
    begin
      FunixCryptOk := -1;
      Exit;
    end;
    RandGen := '/dev/random';
  end;
  FStream := TFileStream.Create(RandGen, fmOpenRead);
  FunixCryptOk := 1;

{$ENDIF MSWINDOWS}
end;

class destructor TOSRandom.DestroyOSRandom;
begin
{$IFDEF MSWINDOWS}
  if (FhProvider > 0) then
  begin
    FWCCryptReleaseContext(@FhProvider, 0);
  end;
{$ELSE}
  FStream.Free;
{$ENDIF MSWINDOWS}
end;

class procedure TOSRandom.GetBytes(const data: TCryptoLibByteArray);
var
  count: Int32;
begin
  count := System.Length(data);
{$IFDEF MSWINDOWS}
  if FwinCryptOk = 1 then
  begin
    if FWCCryptGenRandom(FhProvider, UInt32(count), PBYTE(data)) then
    begin
      Exit;
    end
    else
    begin
      raise EAccessCryptoLibException.CreateRes
        (@SWindowsCryptoAPIAvailableGenerationError);
    end;
  end
  else
  begin
    raise EAccessCryptoLibException.CreateRes(@SWindowsCryptoAPIUnavailable);
  end;
{$ELSE}
  if FunixCryptOk = 1 then
  begin
    try
      FStream.ReadBuffer(data[0], count);
    except
      raise EAccessCryptoLibException.CreateRes(@SUnixRandomReadError);
    end;
  end
  else
  begin
    raise EAccessCryptoLibException.CreateRes(@SUnixRandomUnavailable);
  end;

{$ENDIF MSWINDOWS}
end;

class procedure TOSRandom.GetNonZeroBytes(const data: TCryptoLibByteArray);
begin
  repeat
    TOSRandom.GetBytes(data);
  until (NoZeroes(data));
end;

end.
