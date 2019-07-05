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
{$IFDEF CRYPTOLIB_MSWINDOWS}
  Windows,
{$ENDIF} // ENDIF CRYPTOLIB_MSWINDOWS
{$IFDEF CRYPTOLIB_APPLE}
{$IFDEF FPC}
{$LINKFRAMEWORK Security}
{$IFDEF CRYPTOLIB_MACOS}
  CocoaAll,
{$ENDIF} // ENDIF CRYPTOLIB_MACOS
{$ELSE}
  // Macapi.Dispatch, or
  Macapi.ObjCRuntime,
{$IFDEF CRYPTOLIB_IOS}
  iOSapi.Foundation,
{$ENDIF} // ENDIF CRYPTOLIB_IOS
{$IFDEF CRYPTOLIB_MACOS}
  Macapi.AppKit,
  Macapi.Foundation,
{$ENDIF} // ENDIF CRYPTOLIB_MACOS
{$ENDIF}  // ENDIF FPC
{$ENDIF}   // ENDIF CRYPTOLIB_APPLE
{$IFDEF CRYPTOLIB_UNIX}
  Classes,
{$IFDEF FPC}
  BaseUnix,
{$IFDEF CRYPTOLIB_HAS_GETRANDOM}
  dl,
{$ENDIF}
{$ELSE}
  Posix.Errno,
{$IFDEF CRYPTOLIB_HAS_GETRANDOM}
  Posix.Dlfcn,
{$ENDIF}
{$ENDIF}
{$ENDIF}  // ENDIF CRYPTOLIB_UNIX
{$IFDEF CRYPTOLIB_PUREBSD}
  // PureBSD (NetBSD, FreeBSD, OpenBSD)
{$ENDIF}  // ENDIF CRYPTOLIB_PUREBSD
{$IF DEFINED(CRYPTOLIB_MSWINDOWS) OR DEFINED(CRYPTOLIB_UNIX)}
  SysUtils,
{$IFEND}  // ENDIF CRYPTOLIB_MSWINDOWS OR CRYPTOLIB_UNIX
  ClpCryptoLibTypes;

resourcestring
{$IFDEF CRYPTOLIB_MSWINDOWS}
  SMSWIndowsCryptographyAPIGenerationError =
    'An Error Occured while generating random data using MS Windows Cryptography API.';
{$ENDIF}
{$IFDEF CRYPTOLIB_APPLE}
  SAppleSecRandomCopyBytesGenerationError =
    'An Error Occured while generating random data using SecRandomCopyBytes API.';
{$ENDIF}
{$IFDEF CRYPTOLIB_LINUX}
  SLinuxGetRandomError =
    'An Error Occured while generating random data using getRandom API';
{$ENDIF}
{$IFDEF CRYPTOLIB_SOLARIS}
  SSolarisGetRandomError =
    'An Error Occured while generating random data using getRandom API';
{$ENDIF}
{$IFDEF CRYPTOLIB_GENERIC_BSD}
  SArc4RandomBufGenerationError =
    'An Error Occured while generating random data using arc4random_buf API.';
{$ENDIF}
  // {$IFDEF CRYPTOLIB_UNIX}
  // SRandomDeviceReadError =
  // 'An Error Occured while reading random data from random device (file)';
  // {$ENDIF}

type

  /// <summary>
  /// <para>
  /// TOSRandom Number Class.
  /// </para>
  /// <para>
  /// This class returns random bytes from an OS-specific randomness
  /// source. The returned data should be unpredictable enough for
  /// cryptographic applications, though it's exact quality depends on
  /// the OS implementation.
  /// </para>
  /// <list type="table">
  /// <listheader>
  /// <term>OS</term>
  /// <description>Interface</description>
  /// </listheader>
  /// <item>
  /// <term>Linux, Android</term>
  /// <description><see href="http://man7.org/linux/man-pages/man2/getrandom.2.html">
  /// getrandom</see> system call if available, otherwise ( <b>
  /// /dev/urandom</b> or <b>/dev/random</b>) (which ever is
  /// available)</description>
  /// </item>
  /// <item>
  /// <term>Solaris</term>
  /// <description><see href="https://docs.oracle.com/cd/E88353_01/html/E37841/getrandom-2.html">
  /// getrandom</see> system call if available, otherwise ( <see href="https://docs.oracle.com/cd/E86824_01/html/E54777/random-7d.html">
  /// /dev/urandom or /dev/random</see>) (which ever is
  /// available)</description>
  /// </item>
  /// <item>
  /// <term>Windows</term>
  /// <description><see href="https://docs.microsoft.com/en-us/windows/desktop/api/wincrypt/nf-wincrypt-cryptgenrandom">
  /// CryptGenRandom</see> for <b>XP</b>, <see href="https://docs.microsoft.com/en-us/windows/desktop/api/bcrypt/nf-bcrypt-bcryptgenrandom">
  /// BCryptGenRandom</see> for <b>Vista</b> Upwards</description>
  /// </item>
  /// <item>
  /// <term>Mac OS X</term>
  /// <description><see href="https://developer.apple.com/documentation/security/1399291-secrandomcopybytes?language=objc">
  /// SecRandomCopyBytes</see> for <b>10.7+,</b> ( /dev/urandom
  /// or /dev/random) (which ever is available) for &lt; <b>10.7</b><br /></description>
  /// </item>
  /// <item>
  /// <term>iOS</term>
  /// <description><see href="https://developer.apple.com/documentation/security/1399291-secrandomcopybytes?language=objc">
  /// SecRandomCopyBytes</see><br /></description>
  /// </item>
  /// <item>
  /// <term>FreeBSD</term>
  /// <description><see href="https://www.freebsd.org/cgi/man.cgi?query=arc4random&amp;sektion=3&amp;manpath=FreeBSD+12.0-RELEASE+and+Ports">
  /// arc4random_buf</see></description>
  /// </item>
  /// <item>
  /// <term>NetBSD</term>
  /// <description><see href="https://www.netbsd.org/~riastradh/tmp/20141116/arc4random.html">
  /// arc4random_buf</see></description>
  /// </item>
  /// <item>
  /// <term>OpenBSD</term>
  /// <description><see href="http://man.openbsd.org/cgi-bin/man.cgi/OpenBSD-current/man3/arc4random.3">
  /// arc4random_buf</see></description>
  /// </item>
  /// <item>
  /// <term>DragonFly</term>
  /// <description><see href="https://www.dragonflybsd.org/cgi/web-man?command=arc4random&amp;section=3">
  /// arc4random_buf</see></description>
  /// </item>
  /// </list>
  /// </summary>
  TOSRandom = class sealed(TObject)

  strict private

    // ================================================================//

{$IFDEF CRYPTOLIB_UNIX}
  const
    EINTR = {$IFDEF FPC}ESysEINTR {$ELSE}Posix.Errno.EINTR{$ENDIF};

    class function ErrorNo: Int32; static; inline;

{$IFDEF CRYPTOLIB_HAS_GETRANDOM}

  const
    GRND_DEFAULT: Int32 = $0000;

{$IFDEF CRYPTOLIB_LINUX}
    LIBC_SO = 'libc.so.6';
{$ENDIF}
{$IFDEF CRYPTOLIB_SOLARIS}
    LIBC_SO = 'libc.so.1';
{$ENDIF}

  type
    TGetRandom = function(pbBuffer: PByte; buflen: LongWord; flags: UInt32)
      : Int32; cdecl;

  class var

    FIsGetRandomSupportedOnOS: Boolean;
    FGetRandom: TGetRandom;

    class function GetIsGetRandomSupportedOnOS(): Boolean; static; inline;

    class function IsGetRandomAvailable(): Boolean; static;

    class property IsGetRandomSupportedOnOS: Boolean
      read GetIsGetRandomSupportedOnOS;

{$ENDIF}
{$ENDIF}
    // ================================================================//

{$IFDEF CRYPTOLIB_MSWINDOWS}

  type
    BCRYPT_ALG_HANDLE = THandle;
    NTStatus = HRESULT;

    TBCryptGenRandom = function(hAlgorithm: BCRYPT_ALG_HANDLE; pbBuffer: PUCHAR;
      cbBuffer, dwFlags: ULONG): NTStatus; stdcall;

    TBCryptOpenAlgorithmProvider = function(phAlgorithm: PVOID;
      pszAlgId, pszImplementation: LPCWSTR; dwFlags: ULONG): NTStatus; stdcall;

    TBCryptCloseAlgorithmProvider = function(hAlgorithm: BCRYPT_ALG_HANDLE;
      dwFlags: ULONG): NTStatus; stdcall;

  class var

    FIsCngBCryptGenRandomSupportedOnOS: Boolean;
    FBCryptGenRandom: TBCryptGenRandom;
    FBCryptOpenAlgorithmProvider: TBCryptOpenAlgorithmProvider;
    FBCryptCloseAlgorithmProvider: TBCryptCloseAlgorithmProvider;

    class function GetIsCngBCryptGenRandomSupportedOnOS(): Boolean;
      static; inline;

    class function IsCngBCryptGenRandomAvailable(): Boolean; static;
    class function GenRandomBytesWindows(len: Int32; data: PByte)
      : Int32; static;
    class property IsCngBCryptGenRandomSupportedOnOS: Boolean
      read GetIsCngBCryptGenRandomSupportedOnOS;
{$ENDIF}

    // ================================================================//
{$IFDEF CRYPTOLIB_APPLE}
    class function GenRandomBytesApple(len: Int32; data: PByte): Int32; static;
{$ENDIF}
    // ================================================================//
{$IFDEF CRYPTOLIB_LINUX}
    class function GenRandomBytesLinux(len: Int32; data: PByte): Int32; static;
{$ENDIF}
    // ================================================================//
{$IFDEF CRYPTOLIB_SOLARIS}
    class function GenRandomBytesSolaris(len: Int32; data: PByte)
      : Int32; static;
{$ENDIF}
    // ================================================================//
{$IFDEF CRYPTOLIB_GENERIC_BSD}
    class function GenRandomBytesGenericBSD(len: Int32; data: PByte)
      : Int32; static;
{$ENDIF}
    // ================================================================//
{$IFDEF CRYPTOLIB_UNIX}
    class function dev_random_device_read(len: Int32; data: PByte)
      : Int32; static;
{$ENDIF}
    // ================================================================//

    class function NoZeroes(const data: TCryptoLibByteArray): Boolean;
      static; inline;
    class procedure Boot(); static;
    class constructor OSRandom();

  public
    class procedure GetBytes(const data: TCryptoLibByteArray); static;
    class procedure GetNonZeroBytes(const data: TCryptoLibByteArray); static;

  end;

  // ************************************************************************//

{$IFDEF CRYPTOLIB_MSWINDOWS}

const
  ADVAPI32 = 'advapi32.dll';

function CryptAcquireContextW(phProv: Pointer; pszContainer: LPCWSTR;
  pszProvider: LPCWSTR; dwProvType: DWORD; dwFlags: DWORD): BOOL; stdcall;
  external ADVAPI32 Name 'CryptAcquireContextW';

function CryptGenRandom(hProv: THandle; dwLen: DWORD; pbBuffer: PByte): BOOL;
  stdcall; external ADVAPI32 Name 'CryptGenRandom';

function CryptReleaseContext(hProv: THandle; dwFlags: DWORD): BOOL; stdcall;
  external ADVAPI32 Name 'CryptReleaseContext';
{$ENDIF}
// ************************************************************************//
{$IFDEF CRYPTOLIB_APPLE}
{$IFDEF FPC}

type
  // similar to a TOpaqueData already defined in newer FPC but not available in 3.0.4
  __SecRandom = record
  end;

  // similar to POpaqueData (or an OpaquePointer) already defined in newer FPC but not available in 3.0.4
  SecRandomRef = ^__SecRandom;

function SecRandomCopyBytes(rnd: SecRandomRef; count: LongWord; bytes: PByte)
  : Int32; cdecl; external;

{$ELSE}

type
  SecRandomRef = Pointer;

const
  libSecurity = '/System/Library/Frameworks/Security.framework/Security';

function SecRandomCopyBytes(rnd: SecRandomRef; count: LongWord; bytes: PByte)
  : Int32; cdecl; external libSecurity Name _PU + 'SecRandomCopyBytes';

{$ENDIF}
{$ENDIF}
// ************************************************************************//
{$IFDEF CRYPTOLIB_GENERIC_BSD}
procedure arc4random_buf(bytes: PByte; count: LongWord); cdecl; external;
'c' name 'arc4random_buf';
{$ENDIF}

implementation

class function TOSRandom.NoZeroes(const data: TCryptoLibByteArray): Boolean;
var
  i: Int32;
begin
  result := True;
  for i := System.Low(data) to System.High(data) do
  begin
    if data[i] = 0 then
    begin
      result := False;
      Exit;
    end;
  end;
end;

class procedure TOSRandom.Boot;
begin
{$IFDEF CRYPTOLIB_MSWINDOWS}
  FIsCngBCryptGenRandomSupportedOnOS := IsCngBCryptGenRandomAvailable();
{$ENDIF}
{$IFDEF CRYPTOLIB_HAS_GETRANDOM}
  FIsGetRandomSupportedOnOS := IsGetRandomAvailable();
{$ENDIF}
end;

class constructor TOSRandom.OSRandom;
begin
  TOSRandom.Boot();
end;

{$IFDEF CRYPTOLIB_MSWINDOWS}

class function TOSRandom.GetIsCngBCryptGenRandomSupportedOnOS(): Boolean;
begin
  result := FIsCngBCryptGenRandomSupportedOnOS;
end;

class function TOSRandom.IsCngBCryptGenRandomAvailable(): Boolean;
const
  BCRYPT = 'bcrypt.dll';
var
  ModuleHandle: THandle;

  function GetProcedureAddress(const AProcedureName: String;
    var AFunctionFound: Boolean): Pointer;
  begin
    result := GetProcAddress(ModuleHandle, PChar(AProcedureName));
    if result = Nil then
    begin
      AFunctionFound := False;
    end;
  end;

begin
  result := False;
  ModuleHandle := SafeLoadLibrary(PChar(BCRYPT), SEM_FAILCRITICALERRORS);
  if ModuleHandle <> 0 then
  begin
    result := True;
    FBCryptOpenAlgorithmProvider :=
      GetProcedureAddress('BCryptOpenAlgorithmProvider', result);
    FBCryptCloseAlgorithmProvider :=
      GetProcedureAddress('BCryptCloseAlgorithmProvider', result);
    FBCryptGenRandom := GetProcedureAddress('BCryptGenRandom', result);
  end;
end;

class function TOSRandom.GenRandomBytesWindows(len: Int32; data: PByte): Int32;

  function BCRYPT_SUCCESS(AStatus: NTStatus): Boolean; inline;
  begin
    result := AStatus >= 0;
  end;

var
  hProv: THandle;
const
  PROV_RSA_FULL = 1;
  CRYPT_VERIFYCONTEXT = DWORD($F0000000);
  CRYPT_SILENT = $00000040;
  // BCryptOpenAlgorithmProvider.AlgorithmID
  BCRYPT_RNG_ALGORITHM: WideString = 'RNG';

begin
  if IsCngBCryptGenRandomSupportedOnOS then
  begin
    // Windows Vista and Above
    if (not BCRYPT_SUCCESS(FBCryptOpenAlgorithmProvider(@hProv,
      PWideChar(BCRYPT_RNG_ALGORITHM), nil, 0))) then
    begin
      result := HResultFromWin32(GetLastError);
      Exit;
    end;

    try
      if (not BCRYPT_SUCCESS(FBCryptGenRandom(hProv, PUCHAR(data),
        ULONG(len), 0))) then
      begin
        result := HResultFromWin32(GetLastError);
        Exit;
      end;
    finally
      FBCryptCloseAlgorithmProvider(hProv, 0);
    end;
  end
  else
  begin
    // Below Windows Vista
    if not CryptAcquireContextW(@hProv, nil, nil, PROV_RSA_FULL,
      CRYPT_VERIFYCONTEXT or CRYPT_SILENT) then
    begin
      result := HResultFromWin32(GetLastError);
      Exit;
    end;

    try
      if not CryptGenRandom(hProv, DWORD(len), data) then
      begin
        result := HResultFromWin32(GetLastError);
        Exit;
      end;
    finally
      CryptReleaseContext(hProv, 0);
    end;
  end;
  result := S_OK;
end;

{$ENDIF}
{$IFDEF CRYPTOLIB_APPLE}

class function TOSRandom.GenRandomBytesApple(len: Int32; data: PByte): Int32;

  function kSecRandomDefault: SecRandomRef;
  begin
{$IFDEF FPC}
    result := Nil;
{$ELSE}
    result := CocoaPointerConst(libSecurity, 'kSecRandomDefault');
{$ENDIF}
  end;

begin
{$IF DEFINED(CRYPTOLIB_MACOS)}
  // >= (Mac OS X 10.7+)
  if NSAppKitVersionNumber >= 1138 then // NSAppKitVersionNumber10_7
  begin
    writeln('SecRandomCopyBytes');
    result := SecRandomCopyBytes(kSecRandomDefault, LongWord(len), data);
  end
  else
  begin
    // fallback for when SecRandomCopyBytes API is not available
    writeln('dev/urandom');
    result := dev_random_device_read(len, data);
  end;
{$ELSE}
  result := SecRandomCopyBytes(kSecRandomDefault, LongWord(len), data);
{$IFEND}
end;

{$ENDIF}
{$IFDEF CRYPTOLIB_UNIX}

class function TOSRandom.dev_random_device_read(len: Int32; data: PByte): Int32;
var
  LStream: TFileStream;
  RandGen: String;
  got, MaxChunkSize: Int32;
begin
  MaxChunkSize := len;
  RandGen := '/dev/urandom';
{$IFDEF CRYPTOLIB_SOLARIS}
  MaxChunkSize := 128 * 1040; // 128 * 1040 bytes
{$ENDIF}
  if not FileExists(RandGen) then
  begin
{$IFDEF CRYPTOLIB_SOLARIS}
    MaxChunkSize := 1040; // 1040 bytes
{$ENDIF}
    RandGen := '/dev/random';

    if not FileExists(RandGen) then
    begin
      result := -1;
      Exit;
    end;
  end;

  LStream := TFileStream.Create(RandGen, fmOpenRead);

  try
    while (len > 0) do
    begin
      if len <= MaxChunkSize then
      begin
        MaxChunkSize := len;
      end;

      got := LStream.Read(data^, MaxChunkSize);

      if (got = 0) then
      begin
        if ErrorNo = EINTR then
        begin
          continue;
        end;

        result := -1;
        Exit;
      end;

      System.Inc(data, got);
      System.Dec(len, got);
    end;
    result := 0;
  finally
    LStream.Free;
  end;
end;
{$ENDIF}
{$IFDEF CRYPTOLIB_UNIX}

class function TOSRandom.ErrorNo: Int32;
begin
  result := Errno;
end;
{$ENDIF}
{$IFDEF CRYPTOLIB_HAS_GETRANDOM}

class function TOSRandom.GetIsGetRandomSupportedOnOS(): Boolean;
begin
  result := FIsGetRandomSupportedOnOS;
end;

class function TOSRandom.IsGetRandomAvailable(): Boolean;
var
  Lib: {$IFDEF FPC} PtrInt {$ELSE} NativeUInt {$ENDIF};
begin
  FGetRandom := Nil;
  Lib := {$IFDEF FPC}PtrInt{$ENDIF}(dlopen(LIBC_SO, RTLD_NOW));
  if Lib <> 0 then
  begin
    FGetRandom := dlsym(Lib, 'getrandom');
    dlclose(Lib);
  end;
  result := System.Assigned(FGetRandom);
end;

{$ENDIF}
{$IFDEF CRYPTOLIB_LINUX}

class function TOSRandom.GenRandomBytesLinux(len: Int32; data: PByte): Int32;
var
  got: Int32;
begin

  if IsGetRandomSupportedOnOS then
  begin
    writeln('getRandom');
    while (len > 0) do
    begin

      got := FGetRandom(data, LongWord(len), GRND_DEFAULT);

      if (got < 0) then
      begin
        if ErrorNo = EINTR then
        begin
          continue;
        end;
        result := -1;
        Exit;
      end;
      System.Inc(data, got);
      System.Dec(len, got);
    end;
    result := 0;
  end
  else
  begin
    writeln('dev/urandom');
    // fallback for when getrandom API is not available
    result := dev_random_device_read(len, data);
  end;
end;
{$ENDIF}
{$IFDEF CRYPTOLIB_SOLARIS}

class function TOSRandom.GenRandomBytesSolaris(len: Int32; data: PByte): Int32;
var
  got, MaxChunkSize: Int32;
begin
  MaxChunkSize := 256; // 256 bytes

  if IsGetRandomSupportedOnOS then
  begin
    while (len > 0) do
    begin
      if len <= MaxChunkSize then
      begin
        MaxChunkSize := len;
      end;

      got := FGetRandom(data, LongWord(MaxChunkSize), GRND_DEFAULT);

      if (got = 0) then
      begin
        if ErrorNo = EINTR then
        begin
          continue;
        end;
        result := -1;
        Exit;
      end;
      System.Inc(data, got);
      System.Dec(len, got);
    end;
    result := 0;
  end
  else
  begin
    // fallback for when getrandom API is not available
    result := dev_random_device_read(len, data);
  end;
end;
{$ENDIF}
{$IFDEF CRYPTOLIB_GENERIC_BSD}

class function TOSRandom.GenRandomBytesGenericBSD(len: Int32;
  data: PByte): Int32;

begin
  arc4random_buf(data, LongWord(len));
  result := 0;
end;
{$ENDIF}

class procedure TOSRandom.GetBytes(const data: TCryptoLibByteArray);
var
  count: Int32;
begin
  count := System.Length(data);

  if count <= 0 then
  begin
    Exit;
  end;

{$IF DEFINED(CRYPTOLIB_MSWINDOWS)}
  if GenRandomBytesWindows(count, PByte(data)) <> 0 then
  begin
    raise EOSRandomCryptoLibException.CreateRes
      (@SMSWIndowsCryptographyAPIGenerationError);
  end;

{$ELSEIF DEFINED(CRYPTOLIB_APPLE)}
  if GenRandomBytesApple(count, PByte(data)) <> 0 then
  begin
    raise EOSRandomCryptoLibException.CreateRes
      (@SAppleSecRandomCopyBytesGenerationError);
  end;

{$ELSEIF DEFINED(CRYPTOLIB_LINUX)}
  if GenRandomBytesLinux(count, PByte(data)) <> 0 then
  begin
    raise EOSRandomCryptoLibException.CreateRes(@SLinuxGetRandomError);
  end;

{$ELSEIF DEFINED(CRYPTOLIB_SOLARIS)}
  if GenRandomBytesSolaris(count, PByte(data)) <> 0 then
  begin
    raise EOSRandomCryptoLibException.CreateRes(@SSolarisGetRandomError);
  end;

{$ELSEIF DEFINED(CRYPTOLIB_GENERIC_BSD)}
  if GenRandomBytesGenericBSD(count, PByte(data)) <> 0 then
  begin
    raise EOSRandomCryptoLibException.CreateRes(@SArc4RandomBufGenerationError);
  end;
  // {$ELSEIF DEFINED(CRYPTOLIB_UNDEFINED_UNIX_VARIANTS)}
  // // fallback option for other Undefined Unix OSes
  // if dev_random_device_read(count, PByte(data)) <> 0 then
  // begin
  // raise EOSRandomCryptoLibException.CreateRes(@SRandomDeviceReadError);
  // end;
{$ELSE}
{$MESSAGE ERROR 'UNSUPPORTED TARGET.'}
{$IFEND}
end;

class procedure TOSRandom.GetNonZeroBytes(const data: TCryptoLibByteArray);
begin
  repeat
    TOSRandom.GetBytes(data);
  until (NoZeroes(data));
end;

end.
