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

{$IFDEF CRYPTOLIB_MSWINDOWS}
uses
  Windows,
  SysUtils,
  ClpCryptoLibTypes,
  ClpIRandomSourceProvider;

resourcestring
  SWindowsCryptoApiGenerationError =
    'An Error Occurred while generating random data using MS Windows Cryptography API.';

type
  /// <summary>
  /// Windows OS random source provider.
  /// Implements Windows random APIs in order: BCryptGenRandom -> RtlGenRandom -> CryptGenRandom
  /// </summary>
  TWindowsRandomProvider = class sealed(TInterfacedObject, IRandomSourceProvider)

  strict private
  const
    BCRYPT_DLL = 'bcrypt.dll';
    ADVAPI32_DLL = 'advapi32.dll';
    BCRYPT_USE_SYSTEM_PREFERRED_RNG = $00000002;

  type
    BCRYPT_ALG_HANDLE = THandle;
    NTStatus = HRESULT;

    TBCryptGenRandom = function(AAlgorithm: BCRYPT_ALG_HANDLE;
      ABuffer: PUCHAR; ABufferSize: ULONG; AFlags: ULONG): NTStatus; stdcall;

    TCryptGenRandom = function(AProviderHandle: THandle; ALength: DWORD;
      ABuffer: PByte): BOOL; stdcall;

    TCryptAcquireContextW = function(AProviderHandle: Pointer;
      AContainer: LPCWSTR; AProvider: LPCWSTR; AProviderType: DWORD;
      AFlags: DWORD): BOOL; stdcall;

    TCryptReleaseContext = function(AProviderHandle: THandle;
      AFlags: DWORD): BOOL; stdcall;

    TRtlGenRandom = function(ABuffer: PVOID;
      ABufferLength: ULONG): Boolean; stdcall;

  var
    FHasBCryptGenRandom: Boolean;
    FHasCryptGenRandom: Boolean;
    FHasRtlGenRandom: Boolean;
    FBCryptModuleHandle: THandle;
    FAdvapi32ModuleHandle: THandle;
    FBCryptGenRandom: TBCryptGenRandom;
    FCryptGenRandom: TCryptGenRandom;
    FCryptAcquireContextW: TCryptAcquireContextW;
    FCryptReleaseContext: TCryptReleaseContext;
    FRtlGenRandom: TRtlGenRandom;

    class function BCRYPT_SUCCESS(AStatus: NTStatus): Boolean;
      static; inline;

    function GetProcedureAddress(AModuleHandle: THandle;
      const AProcedureName: String; var AFunctionFound: Boolean): Pointer;

    function IsBCryptGenRandomAvailable(): Boolean;
    function IsCryptGenRandomAvailable(): Boolean;
    function IsRtlGenRandomAvailable(): Boolean;

    function GenRandomBytesWindows(ALen: Int32; AData: PByte): Int32;

  public
    constructor Create();
    destructor Destroy; override;

    procedure GetBytes(const AData: TCryptoLibByteArray);
    procedure GetNonZeroBytes(const AData: TCryptoLibByteArray);
    function GetIsAvailable: Boolean;
    function GetName: String;

  end;

{$ENDIF}

implementation

{$IFDEF CRYPTOLIB_MSWINDOWS}

{ TWindowsRandomProvider }

constructor TWindowsRandomProvider.Create;
begin
  inherited Create();
  FBCryptModuleHandle := 0;
  FAdvapi32ModuleHandle := 0;
  // Load advapi32.dll once for both RtlGenRandom and CryptGenRandom
  FAdvapi32ModuleHandle := SafeLoadLibrary(ADVAPI32_DLL, SEM_FAILCRITICALERRORS);
  // Priority order: BCryptGenRandom -> RtlGenRandom -> CryptGenRandom
  FHasBCryptGenRandom := IsBCryptGenRandomAvailable();
  FHasRtlGenRandom := IsRtlGenRandomAvailable();
  FHasCryptGenRandom := IsCryptGenRandomAvailable();
end;

destructor TWindowsRandomProvider.Destroy;
begin
  if FBCryptModuleHandle <> 0 then
  begin
    FreeLibrary(FBCryptModuleHandle);
    FBCryptModuleHandle := 0;
  end;
  if FAdvapi32ModuleHandle <> 0 then
  begin
    FreeLibrary(FAdvapi32ModuleHandle);
    FAdvapi32ModuleHandle := 0;
  end;
  inherited Destroy;
end;

class function TWindowsRandomProvider.BCRYPT_SUCCESS(
  AStatus: NTStatus): Boolean;
begin
  Result := AStatus >= 0;
end;

function TWindowsRandomProvider.GetProcedureAddress(AModuleHandle: THandle;
  const AProcedureName: String; var AFunctionFound: Boolean): Pointer;
begin
  Result := GetProcAddress(AModuleHandle, PChar(AProcedureName));
  if Result = nil then
  begin
    AFunctionFound := False;
  end;
end;

function TWindowsRandomProvider.IsBCryptGenRandomAvailable(): Boolean;
var
  LFunctionFound: Boolean;
  LTestBuffer: array[0..7] of Byte;
begin
  Result := False;
  FBCryptModuleHandle := SafeLoadLibrary(BCRYPT_DLL, SEM_FAILCRITICALERRORS);
  if FBCryptModuleHandle <> 0 then
  begin
    LFunctionFound := True;
    FBCryptGenRandom := GetProcedureAddress(FBCryptModuleHandle,
      'BCryptGenRandom', LFunctionFound);
    if LFunctionFound then
    begin
      // Probe: verify BCRYPT_USE_SYSTEM_PREFERRED_RNG works on this OS version
      // (requires Windows Vista SP2+ or Windows Server 2008+)
      Result := BCRYPT_SUCCESS(FBCryptGenRandom(0, @LTestBuffer[0], 8,
        BCRYPT_USE_SYSTEM_PREFERRED_RNG));
    end;
    if not Result then
    begin
      FreeLibrary(FBCryptModuleHandle);
      FBCryptModuleHandle := 0;
      FBCryptGenRandom := nil;
    end;
  end;
end;

function TWindowsRandomProvider.IsRtlGenRandomAvailable(): Boolean;
var
  LFunctionFound: Boolean;
begin
  Result := False;
  if FAdvapi32ModuleHandle <> 0 then
  begin
    LFunctionFound := True;
    FRtlGenRandom := GetProcedureAddress(FAdvapi32ModuleHandle,
      'SystemFunction036', LFunctionFound);
    Result := LFunctionFound;
  end;
end;

function TWindowsRandomProvider.IsCryptGenRandomAvailable(): Boolean;
var
  LFunctionFound: Boolean;
begin
  Result := False;
  if FAdvapi32ModuleHandle <> 0 then
  begin
    Result := True;
    LFunctionFound := True;
    FCryptAcquireContextW := GetProcedureAddress(FAdvapi32ModuleHandle,
      'CryptAcquireContextW', LFunctionFound);
    Result := Result and LFunctionFound;
    LFunctionFound := True;
    FCryptReleaseContext := GetProcedureAddress(FAdvapi32ModuleHandle,
      'CryptReleaseContext', LFunctionFound);
    Result := Result and LFunctionFound;
    LFunctionFound := True;
    FCryptGenRandom := GetProcedureAddress(FAdvapi32ModuleHandle,
      'CryptGenRandom', LFunctionFound);
    Result := Result and LFunctionFound;
  end;
end;

function TWindowsRandomProvider.GenRandomBytesWindows(ALen: Int32;
  AData: PByte): Int32;
var
  LProviderHandle: THandle;
const
  PROV_RSA_FULL = 1;
  CRYPT_VERIFYCONTEXT = DWORD($F0000000);
  CRYPT_SILENT = $00000040;
begin
  // Priority order: BCryptGenRandom -> RtlGenRandom -> CryptGenRandom
  if FHasBCryptGenRandom then
  begin
    // Availability: Windows Vista SP2+ / Server 2008 and Above
    // Uses BCRYPT_USE_SYSTEM_PREFERRED_RNG to avoid per-call provider overhead
    if not BCRYPT_SUCCESS(FBCryptGenRandom(0, PUCHAR(AData),
      ULONG(ALen), BCRYPT_USE_SYSTEM_PREFERRED_RNG)) then
    begin
      Result := HResultFromWin32(GetLastError);
      Exit;
    end;
  end
  else if FHasRtlGenRandom then
  begin
    // Availability: Windows XP / Server 2003 and Above
    if not FRtlGenRandom(AData, ULONG(ALen)) then
    begin
      Result := HResultFromWin32(GetLastError);
      Exit;
    end;
  end
  else if FHasCryptGenRandom then
  begin
    // Availability: Windows XP / Server 2003 and Above
    if not FCryptAcquireContextW(@LProviderHandle, nil, nil, PROV_RSA_FULL,
      CRYPT_VERIFYCONTEXT or CRYPT_SILENT) then
    begin
      Result := HResultFromWin32(GetLastError);
      Exit;
    end;

    try
      if not FCryptGenRandom(LProviderHandle, DWORD(ALen), AData) then
      begin
        Result := HResultFromWin32(GetLastError);
        Exit;
      end;
    finally
      FCryptReleaseContext(LProviderHandle, 0);
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

procedure TWindowsRandomProvider.GetBytes(const AData: TCryptoLibByteArray);
var
  LCount: Int32;
begin
  LCount := System.Length(AData);

  if LCount <= 0 then
  begin
    Exit;
  end;

  if GenRandomBytesWindows(LCount, PByte(AData)) <> 0 then
  begin
    raise EOSRandomCryptoLibException.CreateRes
      (@SWindowsCryptoApiGenerationError);
  end;
end;

procedure TWindowsRandomProvider.GetNonZeroBytes(const AData: TCryptoLibByteArray);
var
  LI: Int32;
  LTmp: TCryptoLibByteArray;
begin
  GetBytes(AData);
  System.SetLength(LTmp, 1);
  for LI := System.Low(AData) to System.High(AData) do
  begin
    while AData[LI] = 0 do
    begin
      GetBytes(LTmp);
      AData[LI] := LTmp[0];
    end;
  end;
end;

function TWindowsRandomProvider.GetIsAvailable: Boolean;
begin
  Result := FHasBCryptGenRandom or FHasRtlGenRandom or FHasCryptGenRandom;
end;

function TWindowsRandomProvider.GetName: String;
begin
  Result := 'Windows';
end;

{$ENDIF}

end.
