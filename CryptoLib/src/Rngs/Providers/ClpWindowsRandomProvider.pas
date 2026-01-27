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

unit ClpWindowsRandomProvider;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
{$IFDEF CRYPTOLIB_MSWINDOWS}
  Windows,
{$ENDIF}
  SysUtils,
  ClpCryptoLibTypes,
  ClpIRandomSourceProvider;

resourcestring
  SMSWIndowsCryptographyAPIGenerationError =
    'An Error Occured while generating random data using MS Windows Cryptography API.';

type
  /// <summary>
  /// Windows OS random source provider.
  /// Implements Windows random APIs in order: RtlGenRandom -> CryptGenRandom -> BCryptGenRandom
  /// </summary>
  TWindowsRandomProvider = class sealed(TInterfacedObject, IRandomSourceProvider)

  strict private
  const
    BCRYPT = 'bcrypt.dll';
    ADVAPI32 = 'advapi32.dll';

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

  var
    FIsCngBCryptGenRandomSupportedOnOS: Boolean;
    FIsCryptGenRandomSupportedOnOS: Boolean;
    FIsRtlGenRandomSupportedOnOS: Boolean;
    FBCryptGenRandom: TBCryptGenRandom;
    FBCryptOpenAlgorithmProvider: TBCryptOpenAlgorithmProvider;
    FBCryptCloseAlgorithmProvider: TBCryptCloseAlgorithmProvider;
    FCryptGenRandom: TCryptGenRandom;
    FCryptAcquireContextW: TCryptAcquireContextW;
    FCryptReleaseContext: TCryptReleaseContext;
    FRtlGenRandom: TRtlGenRandom;

    function GetProcedureAddress(AModuleHandle: THandle;
      const AProcedureName: String; var AFunctionFound: Boolean): Pointer;

    function IsCngBCryptGenRandomAvailable(): Boolean;
    function IsCryptGenRandomAvailable(): Boolean;
    function IsRtlGenRandomAvailable(): Boolean;

    function GenRandomBytesWindows(ALen: Int32; AData: PByte): Int32;

  public
    constructor Create();

    procedure GetBytes(const AData: TCryptoLibByteArray);
    procedure GetNonZeroBytes(const AData: TCryptoLibByteArray);
    function GetIsAvailable: Boolean;
    function GetName: String;

  end;

implementation

uses
  ClpArrayUtilities;

{ TWindowsRandomProvider }

constructor TWindowsRandomProvider.Create;
begin
  inherited Create();
  FIsCngBCryptGenRandomSupportedOnOS := IsCngBCryptGenRandomAvailable();
  FIsCryptGenRandomSupportedOnOS := IsCryptGenRandomAvailable();
  FIsRtlGenRandomSupportedOnOS := IsRtlGenRandomAvailable();
end;

function TWindowsRandomProvider.GetProcedureAddress(AModuleHandle: THandle;
  const AProcedureName: String; var AFunctionFound: Boolean): Pointer;
begin
  result := GetProcAddress(AModuleHandle, PChar(AProcedureName));
  if result = nil then
  begin
    AFunctionFound := False;
  end;
end;

function TWindowsRandomProvider.IsCngBCryptGenRandomAvailable(): Boolean;
var
  LModuleHandle: THandle;
  LFunctionFound: Boolean;
begin
  result := False;
  LModuleHandle := SafeLoadLibrary(BCRYPT, SEM_FAILCRITICALERRORS);
  if LModuleHandle <> 0 then
  begin
    result := True;
    LFunctionFound := True;
    FBCryptOpenAlgorithmProvider := GetProcedureAddress(LModuleHandle,
      'BCryptOpenAlgorithmProvider', LFunctionFound);
    result := result and LFunctionFound;
    LFunctionFound := True;
    FBCryptCloseAlgorithmProvider := GetProcedureAddress(LModuleHandle,
      'BCryptCloseAlgorithmProvider', LFunctionFound);
    result := result and LFunctionFound;
    LFunctionFound := True;
    FBCryptGenRandom := GetProcedureAddress(LModuleHandle,
      'BCryptGenRandom', LFunctionFound);
    result := result and LFunctionFound;
  end;
end;

function TWindowsRandomProvider.IsCryptGenRandomAvailable(): Boolean;
var
  LModuleHandle: THandle;
  LFunctionFound: Boolean;
begin
  result := False;
  LModuleHandle := SafeLoadLibrary(ADVAPI32, SEM_FAILCRITICALERRORS);
  if LModuleHandle <> 0 then
  begin
    result := True;
    LFunctionFound := True;
    FCryptAcquireContextW := GetProcedureAddress(LModuleHandle,
      'CryptAcquireContextW', LFunctionFound);
    result := result and LFunctionFound;
    LFunctionFound := True;
    FCryptReleaseContext := GetProcedureAddress(LModuleHandle,
      'CryptReleaseContext', LFunctionFound);
    result := result and LFunctionFound;
    LFunctionFound := True;
    FCryptGenRandom := GetProcedureAddress(LModuleHandle,
      'CryptGenRandom', LFunctionFound);
    result := result and LFunctionFound;
  end;
end;

function TWindowsRandomProvider.IsRtlGenRandomAvailable(): Boolean;
var
  LModuleHandle: THandle;
  LFunctionFound: Boolean;
begin
  result := False;
  LModuleHandle := SafeLoadLibrary(ADVAPI32, SEM_FAILCRITICALERRORS);
  if LModuleHandle <> 0 then
  begin
    result := True;
    LFunctionFound := True;
    FRtlGenRandom := GetProcedureAddress(LModuleHandle,
      'SystemFunction036', LFunctionFound);
    result := result and LFunctionFound;
  end;
end;

function TWindowsRandomProvider.GenRandomBytesWindows(ALen: Int32;
  AData: PByte): Int32;

  function BCRYPT_SUCCESS(AStatus: NTStatus): Boolean; inline;
  begin
    result := AStatus >= 0;
  end;

var
  LhProv: THandle;
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
    if not FRtlGenRandom(AData, ULONG(ALen)) then
    begin
      result := HResultFromWin32(GetLastError);
      Exit;
    end;
  end
  else if FIsCryptGenRandomSupportedOnOS then
  begin
    // Availability: Windows XP / Server 2003 and Above
    if not FCryptAcquireContextW(@LhProv, nil, nil, PROV_RSA_FULL,
      CRYPT_VERIFYCONTEXT or CRYPT_SILENT) then
    begin
      result := HResultFromWin32(GetLastError);
      Exit;
    end;

    try
      if not FCryptGenRandom(LhProv, DWORD(ALen), AData) then
      begin
        result := HResultFromWin32(GetLastError);
        Exit;
      end;
    finally
      FCryptReleaseContext(LhProv, 0);
    end;
  end
  else if FIsCngBCryptGenRandomSupportedOnOS then
  begin
    // Availability: Windows Vista / Server 2008 and Above
    if (not BCRYPT_SUCCESS(FBCryptOpenAlgorithmProvider(@LhProv,
      PWideChar(BCRYPT_RNG_ALGORITHM), nil, 0))) then
    begin
      result := HResultFromWin32(GetLastError);
      Exit;
    end;

    try
      if (not BCRYPT_SUCCESS(FBCryptGenRandom(LhProv, PUCHAR(AData),
        ULONG(ALen), 0))) then
      begin
        result := HResultFromWin32(GetLastError);
        Exit;
      end;
    finally
      FBCryptCloseAlgorithmProvider(LhProv, 0);
    end;
  end
  else
  begin
    // should never happen but who knows :)
    result := S_FALSE;
    Exit;
  end;
  result := S_OK;
end;

procedure TWindowsRandomProvider.GetBytes(const AData: TCryptoLibByteArray);
var
  LCount: Int32;
begin
  LCount := System.Length(AData);

  if LCount <= 0 then
  begin
    Exit;
  end;

{$IFDEF CRYPTOLIB_MSWINDOWS}
  if GenRandomBytesWindows(LCount, PByte(AData)) <> 0 then
  begin
    raise EOSRandomCryptoLibException.CreateRes
      (@SMSWIndowsCryptographyAPIGenerationError);
  end;
{$ELSE}
  raise EOSRandomCryptoLibException.Create('WindowsRandomProvider is only available on Windows');
{$ENDIF}
end;

procedure TWindowsRandomProvider.GetNonZeroBytes(const AData: TCryptoLibByteArray);
begin
  repeat
    GetBytes(AData);
  until (TArrayUtilities.NoZeroes(AData));
end;

function TWindowsRandomProvider.GetIsAvailable: Boolean;
begin
{$IFDEF CRYPTOLIB_MSWINDOWS}
  result := FIsRtlGenRandomSupportedOnOS or FIsCryptGenRandomSupportedOnOS or
    FIsCngBCryptGenRandomSupportedOnOS;
{$ELSE}
  result := False;
{$ENDIF}
end;

function TWindowsRandomProvider.GetName: String;
begin
  result := 'Windows';
end;

end.
