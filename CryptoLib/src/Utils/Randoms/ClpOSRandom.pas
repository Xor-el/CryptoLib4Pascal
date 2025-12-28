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
{$IFDEF CRYPTOLIB_GENERIC_BSD}
  // GenericBSD (NetBSD, FreeBSD, OpenBSD, DragonFlyBSD)
{$ENDIF}  // ENDIF CRYPTOLIB_GENERIC_BSD
{$IF DEFINED(CRYPTOLIB_MSWINDOWS) OR DEFINED(CRYPTOLIB_UNIX)}
  SysUtils,
{$IFEND}  // ENDIF CRYPTOLIB_MSWINDOWS OR CRYPTOLIB_UNIX
  ClpArrayUtils,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// Public interface for OS random implementations.
  /// Implement this interface to provide a custom random source.
  /// </summary>
  IOSRandom = interface(IInterface)
    ['{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}']
    procedure GetBytes(const data: TCryptoLibByteArray);
    procedure GetNonZeroBytes(const data: TCryptoLibByteArray);
  end;

  /// <summary>
  /// Abstract base class for OS random implementations.
  /// Provides common GetNonZeroBytes logic.
  /// </summary>
  TBaseOSRandom = class abstract(TInterfacedObject, IOSRandom)
  protected
    procedure DoGetBytes(const data: TCryptoLibByteArray); virtual; abstract;
  public
    procedure GetBytes(const data: TCryptoLibByteArray);
    procedure GetNonZeroBytes(const data: TCryptoLibByteArray);
  end;

  // =========================================================================
  // Platform-specific implementations
  // =========================================================================

{$IFDEF CRYPTOLIB_MSWINDOWS}
  /// <summary>
  /// Windows implementation using RtlGenRandom, CryptGenRandom, or BCryptGenRandom.
  /// </summary>
  TWindowsOSRandom = class sealed(TBaseOSRandom)
  strict private
  const
    BCRYPT = 'bcrypt.dll';
    ADVAPI32 = 'advapi32.dll';
    SGenerationError =
      'An Error Occured while generating random data using MS Windows Cryptography API.';

  type
    BCRYPT_ALG_HANDLE = THandle;
    NTStatus = HRESULT;

    TBCryptGenRandom = function(hAlgorithm: BCRYPT_ALG_HANDLE; pbBuffer: PUCHAR;
      cbBuffer, dwFlags: ULONG): NTStatus; stdcall;

    TBCryptOpenAlgorithmProvider = function(phAlgorithm: PVOID;
      pszAlgId, pszImplementation: LPCWSTR; dwFlags: ULONG): NTStatus; stdcall;

    TBCryptCloseAlgorithmProvider = function(hAlgorithm: BCRYPT_ALG_HANDLE;
      dwFlags: ULONG): NTStatus; stdcall;

    TCryptGenRandom = function(hProv: THandle; dwLen: DWORD; pbBuffer: PByte)
      : BOOL; stdcall;

    TCryptAcquireContextW = function(phProv: Pointer; pszContainer: LPCWSTR;
      pszProvider: LPCWSTR; dwProvType: DWORD; dwFlags: DWORD): BOOL; stdcall;

    TCryptReleaseContext = function(hProv: THandle; dwFlags: DWORD)
      : BOOL; stdcall;

    TRtlGenRandom = function(RandomBuffer: PVOID; RandomBufferLength: ULONG)
      : Boolean; stdcall;

  class var
    FIsCngBCryptGenRandomSupportedOnOS: Boolean;
    FBCryptGenRandom: TBCryptGenRandom;
    FBCryptOpenAlgorithmProvider: TBCryptOpenAlgorithmProvider;
    FBCryptCloseAlgorithmProvider: TBCryptCloseAlgorithmProvider;

    FIsCryptGenRandomSupportedOnOS: Boolean;
    FCryptGenRandom: TCryptGenRandom;
    FCryptAcquireContextW: TCryptAcquireContextW;
    FCryptReleaseContext: TCryptReleaseContext;

    FIsRtlGenRandomSupportedOnOS: Boolean;
    FRtlGenRandom: TRtlGenRandom;

    class function GetProcedureAddress(ModuleHandle: THandle;
      const AProcedureName: String; var AFunctionFound: Boolean): Pointer; static;

    class function IsCngBCryptGenRandomAvailable(): Boolean; static;
    class function IsCryptGenRandomAvailable(): Boolean; static;
    class function IsRtlGenRandomAvailable(): Boolean; static;

    class function GenRandomBytesWindows(len: Int32; data: PByte): Int32; static;

  protected
    procedure DoGetBytes(const data: TCryptoLibByteArray); override;

  public
    class procedure Boot(); static;
    class constructor Create();
  end;
{$ENDIF}

{$IFDEF CRYPTOLIB_APPLE}
  /// <summary>
  /// Apple (macOS/iOS) implementation using SecRandomCopyBytes.
  /// </summary>
  TAppleOSRandom = class sealed(TBaseOSRandom)
  strict private
  const
    SGenerationError =
      'An Error Occured while generating random data using SecRandomCopyBytes API.';

{$IFDEF CRYPTOLIB_UNIX}
    class function ReadFromRandomDevice(len: Int32; data: PByte): Int32; static;
{$ENDIF}
    class function GenRandomBytesApple(len: Int32; data: PByte): Int32; static;

  protected
    procedure DoGetBytes(const data: TCryptoLibByteArray); override;
  end;
{$ENDIF}

{$IFDEF CRYPTOLIB_LINUX}
  /// <summary>
  /// Linux/Android implementation using getrandom() or /dev/urandom.
  /// </summary>
  TLinuxOSRandom = class sealed(TBaseOSRandom)
  strict private
  const
    EINTR = {$IFDEF FPC}ESysEINTR{$ELSE}Posix.Errno.EINTR{$ENDIF};
    GRND_DEFAULT: Int32 = $0000;
{$IFDEF CRYPTOLIB_ANDROID}
    LIBC_SO = 'libc.so';
{$ELSE}
    LIBC_SO = 'libc.so.6';
{$ENDIF}
    SGenerationError =
      'An Error Occured while generating random data using getRandom API';

  type
    TGetRandom = function(pbBuffer: PByte; buflen: LongWord; flags: UInt32)
      : Int32; cdecl;

  class var
    FIsGetRandomSupportedOnOS: Boolean;
    FGetRandom: TGetRandom;

    class function ErrorNo: Int32; static; inline;
    class function IsGetRandomAvailable(): Boolean; static;
    class function ReadFromRandomDevice(len: Int32; data: PByte): Int32; static;
    class function GenRandomBytesLinux(len: Int32; data: PByte): Int32; static;

  protected
    procedure DoGetBytes(const data: TCryptoLibByteArray); override;

  public
    class procedure Boot(); static;
    class constructor Create();
  end;
{$ENDIF}

{$IFDEF CRYPTOLIB_SOLARIS}
  /// <summary>
  /// Solaris implementation using getrandom() or /dev/urandom.
  /// </summary>
  TSolarisOSRandom = class sealed(TBaseOSRandom)
  strict private
  const
    EINTR = {$IFDEF FPC}ESysEINTR{$ELSE}Posix.Errno.EINTR{$ENDIF};
    GRND_DEFAULT: Int32 = $0000;
    LIBC_SO = 'libc.so.1';
    SGenerationError =
      'An Error Occured while generating random data using getRandom API';

  type
    TGetRandom = function(pbBuffer: PByte; buflen: LongWord; flags: UInt32)
      : Int32; cdecl;

  class var
    FIsGetRandomSupportedOnOS: Boolean;
    FGetRandom: TGetRandom;

    class function ErrorNo: Int32; static; inline;
    class function IsGetRandomAvailable(): Boolean; static;
    class function ReadFromRandomDevice(len: Int32; data: PByte): Int32; static;
    class function GenRandomBytesSolaris(len: Int32; data: PByte): Int32; static;

  protected
    procedure DoGetBytes(const data: TCryptoLibByteArray); override;

  public
    class procedure Boot(); static;
    class constructor Create();
  end;
{$ENDIF}

{$IFDEF CRYPTOLIB_GENERIC_BSD}
  /// <summary>
  /// BSD (FreeBSD/NetBSD/OpenBSD/DragonFlyBSD) implementation using arc4random_buf.
  /// </summary>
  TGenericBSDOSRandom = class sealed(TBaseOSRandom)
  strict private
  const
    SGenerationError =
      'An Error Occured while generating random data using arc4random_buf API.';

    class function GenRandomBytesGenericBSD(len: Int32; data: PByte): Int32; static;

  protected
    procedure DoGetBytes(const data: TCryptoLibByteArray); override;
  end;
{$ENDIF}

  // =========================================================================
  // Static accessor (maintains backward compatibility)
  // =========================================================================

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
  /// <para>
  /// Set the Instance property to provide a custom IOSRandom implementation.
  /// </para>
  /// </summary>
  TOSRandom = class sealed(TObject)
  strict private
  class var
    FInstance: IOSRandom;

    class function GetInstance: IOSRandom; static; inline;
    class procedure SetInstance(const AValue: IOSRandom); static; inline;

  public
    class procedure Boot(); static;
    class procedure GetBytes(const data: TCryptoLibByteArray); static;
    class procedure GetNonZeroBytes(const data: TCryptoLibByteArray); static;

    /// <summary>
    /// The OS random instance. Can be replaced with a custom implementation.
    /// </summary>
    class property Instance: IOSRandom read GetInstance write SetInstance;

    class constructor OSRandom();
  end;

  // =========================================================================
  // External declarations for Apple and BSD
  // =========================================================================

{$IFDEF CRYPTOLIB_APPLE}
{$IFDEF FPC}

type
  // similar to a TOpaqueData already defined in newer FPC but not available in 3.0.4
  // TODO when we upgrade to FPC 3.2.0, remove " __SecRandom = record end;" declaration
  __SecRandom = record
  end;

  // similar to POpaqueData (or an OpaquePointer) already defined in newer FPC but not available in 3.0.4
  // TODO when we upgrade to FPC 3.2.0, use inbuilt OpaquePointer instead
  // replace "SecRandomRef = ^__SecRandom;" with "SecRandomRef = OpaquePointer;"

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

{$IFDEF CRYPTOLIB_GENERIC_BSD}
procedure arc4random_buf(bytes: PByte; count: LongWord); cdecl;
  external 'c' name 'arc4random_buf';
{$ENDIF}

implementation

// ===========================================================================
// TBaseOSRandom
// ===========================================================================

procedure TBaseOSRandom.GetBytes(const data: TCryptoLibByteArray);
begin
  if System.Length(data) > 0 then
    DoGetBytes(data);
end;

procedure TBaseOSRandom.GetNonZeroBytes(const data: TCryptoLibByteArray);
begin
  repeat
    GetBytes(data);
  until TArrayUtils.NoZeroes(data);
end;

// ===========================================================================
// TWindowsOSRandom
// ===========================================================================

{$IFDEF CRYPTOLIB_MSWINDOWS}

class constructor TWindowsOSRandom.Create;
begin
  TWindowsOSRandom.Boot();
end;

class procedure TWindowsOSRandom.Boot;
begin
  FIsCngBCryptGenRandomSupportedOnOS := IsCngBCryptGenRandomAvailable();
  FIsCryptGenRandomSupportedOnOS := IsCryptGenRandomAvailable();
  FIsRtlGenRandomSupportedOnOS := IsRtlGenRandomAvailable();
end;

class function TWindowsOSRandom.GetProcedureAddress(ModuleHandle: THandle;
  const AProcedureName: String; var AFunctionFound: Boolean): Pointer;
begin
  Result := GetProcAddress(ModuleHandle, PChar(AProcedureName));
  if Result = Nil then
  begin
    AFunctionFound := False;
  end;
end;

class function TWindowsOSRandom.IsCngBCryptGenRandomAvailable: Boolean;
var
  ModuleHandle: THandle;
begin
  Result := False;
  ModuleHandle := SafeLoadLibrary(BCRYPT, SEM_FAILCRITICALERRORS);
  if ModuleHandle <> 0 then
  begin
    Result := True;
    FBCryptOpenAlgorithmProvider := GetProcedureAddress(ModuleHandle,
      'BCryptOpenAlgorithmProvider', Result);
    FBCryptCloseAlgorithmProvider := GetProcedureAddress(ModuleHandle,
      'BCryptCloseAlgorithmProvider', Result);
    FBCryptGenRandom := GetProcedureAddress(ModuleHandle,
      'BCryptGenRandom', Result);
  end;
end;

class function TWindowsOSRandom.IsCryptGenRandomAvailable: Boolean;
var
  ModuleHandle: THandle;
begin
  Result := False;
  ModuleHandle := SafeLoadLibrary(ADVAPI32, SEM_FAILCRITICALERRORS);
  if ModuleHandle <> 0 then
  begin
    Result := True;
    FCryptAcquireContextW := GetProcedureAddress(ModuleHandle,
      'CryptAcquireContextW', Result);
    FCryptReleaseContext := GetProcedureAddress(ModuleHandle,
      'CryptReleaseContext', Result);
    FCryptGenRandom := GetProcedureAddress(ModuleHandle,
      'CryptGenRandom', Result);
  end;
end;

class function TWindowsOSRandom.IsRtlGenRandomAvailable: Boolean;
var
  ModuleHandle: THandle;
begin
  Result := False;
  ModuleHandle := SafeLoadLibrary(ADVAPI32, SEM_FAILCRITICALERRORS);
  if ModuleHandle <> 0 then
  begin
    Result := True;
    FRtlGenRandom := GetProcedureAddress(ModuleHandle,
      'SystemFunction036', Result);
  end;
end;

class function TWindowsOSRandom.GenRandomBytesWindows(len: Int32; data: PByte): Int32;

  function BCRYPT_SUCCESS(AStatus: NTStatus): Boolean; inline;
  begin
    Result := AStatus >= 0;
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
  // first check if RtlGenRandom is available to avoid the memory overhead
  // of pulling in 'CryptoAPI'
  if FIsRtlGenRandomSupportedOnOS then
  begin
    // Availability: Windows XP / Server 2003 and Above
    if not FRtlGenRandom(data, ULONG(len)) then
    begin
      Result := HResultFromWin32(GetLastError);
      Exit;
    end;
  end
  else if FIsCryptGenRandomSupportedOnOS then
  begin
    // Availability: Windows XP / Server 2003 and Above
    if not FCryptAcquireContextW(@hProv, nil, nil, PROV_RSA_FULL,
      CRYPT_VERIFYCONTEXT or CRYPT_SILENT) then
    begin
      Result := HResultFromWin32(GetLastError);
      Exit;
    end;

    try
      if not FCryptGenRandom(hProv, DWORD(len), data) then
      begin
        Result := HResultFromWin32(GetLastError);
        Exit;
      end;
    finally
      FCryptReleaseContext(hProv, 0);
    end;
  end
  else if FIsCngBCryptGenRandomSupportedOnOS then
  begin
    // Availability: Windows Vista / Server 2008 and Above
    if (not BCRYPT_SUCCESS(FBCryptOpenAlgorithmProvider(@hProv,
      PWideChar(BCRYPT_RNG_ALGORITHM), nil, 0))) then
    begin
      Result := HResultFromWin32(GetLastError);
      Exit;
    end;

    try
      if (not BCRYPT_SUCCESS(FBCryptGenRandom(hProv, PUCHAR(data),
        ULONG(len), 0))) then
      begin
        Result := HResultFromWin32(GetLastError);
        Exit;
      end;
    finally
      FBCryptCloseAlgorithmProvider(hProv, 0);
    end;
  end
  else
  begin
    // should never happen but who knows :)
    Result := S_FALSE;
    Exit;
  end;
  Result := S_OK;
end;

procedure TWindowsOSRandom.DoGetBytes(const data: TCryptoLibByteArray);
var
  count: Int32;
begin
  count := System.Length(data);
  if GenRandomBytesWindows(count, PByte(data)) <> 0 then
  begin
    raise EOSRandomCryptoLibException.Create(SGenerationError);
  end;
end;

{$ENDIF}

// ===========================================================================
// TAppleOSRandom
// ===========================================================================

{$IFDEF CRYPTOLIB_APPLE}

{$IFDEF CRYPTOLIB_UNIX}
class function TAppleOSRandom.ReadFromRandomDevice(len: Int32; data: PByte): Int32;
var
  LStream: TFileStream;
  RandGen: String;
  got, MaxChunkSize: Int32;
const
  EINTR = {$IFDEF FPC}ESysEINTR{$ELSE}Posix.Errno.EINTR{$ENDIF};
begin
  MaxChunkSize := len;
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
    while (len > 0) do
    begin
      if len <= MaxChunkSize then
      begin
        MaxChunkSize := len;
      end;

      got := LStream.Read(data^, MaxChunkSize);

      if (got = 0) then
      begin
        if Errno = EINTR then
        begin
          continue;
        end;

        Result := -1;
        Exit;
      end;

      System.Inc(data, got);
      System.Dec(len, got);
    end;
    Result := 0;
  finally
    LStream.Free;
  end;
end;
{$ENDIF}

class function TAppleOSRandom.GenRandomBytesApple(len: Int32; data: PByte): Int32;

  function kSecRandomDefault: SecRandomRef;
  begin
{$IFDEF FPC}
    Result := Nil;
{$ELSE}
    Result := CocoaPointerConst(libSecurity, 'kSecRandomDefault');
{$ENDIF}
  end;

begin
{$IF DEFINED(CRYPTOLIB_MACOS)}
  // >= (Mac OS X 10.7+)
  if NSAppKitVersionNumber >= 1138 then // NSAppKitVersionNumber10_7
  begin
    Result := SecRandomCopyBytes(kSecRandomDefault, LongWord(len), data);
  end
  else
  begin
    // fallback for when SecRandomCopyBytes API is not available
    Result := ReadFromRandomDevice(len, data);
  end;
{$ELSE}
  Result := SecRandomCopyBytes(kSecRandomDefault, LongWord(len), data);
{$IFEND}
end;

procedure TAppleOSRandom.DoGetBytes(const data: TCryptoLibByteArray);
var
  count: Int32;
begin
  count := System.Length(data);
  if GenRandomBytesApple(count, PByte(data)) <> 0 then
  begin
    raise EOSRandomCryptoLibException.Create(SGenerationError);
  end;
end;

{$ENDIF}

// ===========================================================================
// TLinuxOSRandom
// ===========================================================================

{$IFDEF CRYPTOLIB_LINUX}

class constructor TLinuxOSRandom.Create;
begin
  TLinuxOSRandom.Boot();
end;

class procedure TLinuxOSRandom.Boot;
begin
  FIsGetRandomSupportedOnOS := IsGetRandomAvailable();
end;

class function TLinuxOSRandom.ErrorNo: Int32;
begin
  Result := Errno;
end;

class function TLinuxOSRandom.IsGetRandomAvailable: Boolean;
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
  Result := System.Assigned(FGetRandom);
end;

class function TLinuxOSRandom.ReadFromRandomDevice(len: Int32; data: PByte): Int32;
var
  LStream: TFileStream;
  RandGen: String;
  got, MaxChunkSize: Int32;
begin
  MaxChunkSize := len;
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

        Result := -1;
        Exit;
      end;

      System.Inc(data, got);
      System.Dec(len, got);
    end;
    Result := 0;
  finally
    LStream.Free;
  end;
end;

class function TLinuxOSRandom.GenRandomBytesLinux(len: Int32; data: PByte): Int32;
var
  got: Int32;
begin
  if FIsGetRandomSupportedOnOS then
  begin
    while (len > 0) do
    begin
      got := FGetRandom(data, LongWord(len), GRND_DEFAULT);

      if (got < 0) then
      begin
        if ErrorNo = EINTR then
        begin
          continue;
        end;
        Result := -1;
        Exit;
      end;
      System.Inc(data, got);
      System.Dec(len, got);
    end;
    Result := 0;
  end
  else
  begin
    // fallback for when getrandom API is not available
    Result := ReadFromRandomDevice(len, data);
  end;
end;

procedure TLinuxOSRandom.DoGetBytes(const data: TCryptoLibByteArray);
var
  count: Int32;
begin
  count := System.Length(data);
  if GenRandomBytesLinux(count, PByte(data)) <> 0 then
  begin
    raise EOSRandomCryptoLibException.Create(SGenerationError);
  end;
end;

{$ENDIF}

// ===========================================================================
// TSolarisOSRandom
// ===========================================================================

{$IFDEF CRYPTOLIB_SOLARIS}

class constructor TSolarisOSRandom.Create;
begin
  TSolarisOSRandom.Boot();
end;

class procedure TSolarisOSRandom.Boot;
begin
  FIsGetRandomSupportedOnOS := IsGetRandomAvailable();
end;

class function TSolarisOSRandom.ErrorNo: Int32;
begin
  Result := Errno;
end;

class function TSolarisOSRandom.IsGetRandomAvailable: Boolean;
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
  Result := System.Assigned(FGetRandom);
end;

class function TSolarisOSRandom.ReadFromRandomDevice(len: Int32; data: PByte): Int32;
var
  LStream: TFileStream;
  RandGen: String;
  got, MaxChunkSize: Int32;
begin
  MaxChunkSize := 128 * 1040; // 128 * 1040 bytes
  RandGen := '/dev/urandom';

  if not FileExists(RandGen) then
  begin
    MaxChunkSize := 1040; // 1040 bytes
    RandGen := '/dev/random';

    if not FileExists(RandGen) then
    begin
      Result := -1;
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

        Result := -1;
        Exit;
      end;

      System.Inc(data, got);
      System.Dec(len, got);
    end;
    Result := 0;
  finally
    LStream.Free;
  end;
end;

class function TSolarisOSRandom.GenRandomBytesSolaris(len: Int32; data: PByte): Int32;
var
  got, MaxChunkSize: Int32;
begin
  MaxChunkSize := 256; // 256 bytes

  if FIsGetRandomSupportedOnOS then
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
        Result := -1;
        Exit;
      end;
      System.Inc(data, got);
      System.Dec(len, got);
    end;
    Result := 0;
  end
  else
  begin
    // fallback for when getrandom API is not available
    Result := ReadFromRandomDevice(len, data);
  end;
end;

procedure TSolarisOSRandom.DoGetBytes(const data: TCryptoLibByteArray);
var
  count: Int32;
begin
  count := System.Length(data);
  if GenRandomBytesSolaris(count, PByte(data)) <> 0 then
  begin
    raise EOSRandomCryptoLibException.Create(SGenerationError);
  end;
end;

{$ENDIF}

// ===========================================================================
// TGenericBSDOSRandom
// ===========================================================================

{$IFDEF CRYPTOLIB_GENERIC_BSD}

class function TGenericBSDOSRandom.GenRandomBytesGenericBSD(len: Int32;
  data: PByte): Int32;
begin
  arc4random_buf(data, LongWord(len));
  Result := 0;
end;

procedure TGenericBSDOSRandom.DoGetBytes(const data: TCryptoLibByteArray);
var
  count: Int32;
begin
  count := System.Length(data);
  if GenRandomBytesGenericBSD(count, PByte(data)) <> 0 then
  begin
    raise EOSRandomCryptoLibException.Create(SGenerationError);
  end;
end;

{$ENDIF}

// ===========================================================================
// TOSRandom (Static Accessor)
// ===========================================================================

class constructor TOSRandom.OSRandom;
begin
{$IFDEF CRYPTOLIB_MSWINDOWS}
  FInstance := TWindowsOSRandom.Create;
{$ENDIF}
{$IFDEF CRYPTOLIB_APPLE}
  FInstance := TAppleOSRandom.Create;
{$ENDIF}
{$IFDEF CRYPTOLIB_LINUX}
  FInstance := TLinuxOSRandom.Create;
{$ENDIF}
{$IFDEF CRYPTOLIB_SOLARIS}
  FInstance := TSolarisOSRandom.Create;
{$ENDIF}
{$IFDEF CRYPTOLIB_GENERIC_BSD}
  FInstance := TGenericBSDOSRandom.Create;
{$ENDIF}
end;

class function TOSRandom.GetInstance: IOSRandom;
begin
  Result := FInstance;
end;

class procedure TOSRandom.SetInstance(const AValue: IOSRandom);
begin
  FInstance := AValue;
end;

class procedure TOSRandom.Boot;
begin
{$IFDEF CRYPTOLIB_MSWINDOWS}
  TWindowsOSRandom.Boot;
{$ENDIF}
{$IFDEF CRYPTOLIB_LINUX}
  TLinuxOSRandom.Boot;
{$ENDIF}
{$IFDEF CRYPTOLIB_SOLARIS}
  TSolarisOSRandom.Boot;
{$ENDIF}
end;

class procedure TOSRandom.GetBytes(const data: TCryptoLibByteArray);
begin
  FInstance.GetBytes(data);
end;

class procedure TOSRandom.GetNonZeroBytes(const data: TCryptoLibByteArray);
begin
  FInstance.GetNonZeroBytes(data);
end;

end.
