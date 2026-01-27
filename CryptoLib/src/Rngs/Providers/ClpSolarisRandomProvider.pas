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

unit ClpSolarisRandomProvider;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
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
{$ENDIF}
  SysUtils,
  ClpCryptoLibTypes,
  ClpIRandomSourceProvider;

resourcestring
  SSolarisGetRandomError =
    'An Error Occured while generating random data using getRandom API';

type
{$IFDEF CRYPTOLIB_HAS_GETRANDOM}
{$IFDEF CRYPTOLIB_SOLARIS}
const
  LIBC_SO = 'libc.so.1';
{$ENDIF}

type
  TGetRandom = function(pbBuffer: PByte; buflen: LongWord; flags: UInt32)
    : Int32; cdecl;
{$ENDIF}

  /// <summary>
  /// Solaris OS random source provider.
  /// Implements Solaris getrandom and /dev/urandom fallback
  /// </summary>
  TSolarisRandomProvider = class sealed(TInterfacedObject, IRandomSourceProvider)

  strict private
{$IFDEF CRYPTOLIB_UNIX}
  const
    EINTR = {$IFDEF FPC}ESysEINTR {$ELSE}Posix.Errno.EINTR{$ENDIF};
    GRND_DEFAULT: Int32 = $0000;

    function ErrorNo: Int32;
    function DevRandomDeviceRead(ALen: Int32; AData: PByte): Int32;
{$ENDIF}
{$IFDEF CRYPTOLIB_HAS_GETRANDOM}
  var
    FIsGetRandomSupportedOnOS: Boolean;
    FGetRandom: TGetRandom;

    function IsGetRandomAvailable(): Boolean;
{$ENDIF}
    function GenRandomBytesSolaris(ALen: Int32; AData: PByte): Int32;

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

{ TSolarisRandomProvider }

constructor TSolarisRandomProvider.Create;
begin
  inherited Create();
{$IFDEF CRYPTOLIB_HAS_GETRANDOM}
  FIsGetRandomSupportedOnOS := IsGetRandomAvailable();
{$ENDIF}
end;

{$IFDEF CRYPTOLIB_UNIX}

function TSolarisRandomProvider.ErrorNo: Int32;
begin
  result := Errno;
end;

function TSolarisRandomProvider.DevRandomDeviceRead(ALen: Int32;
  AData: PByte): Int32;
var
  LStream: TFileStream;
  LRandGen: String;
  LGot, LMaxChunkSize: Int32;
begin
  LMaxChunkSize := 128 * 1040; // 128 * 1040 bytes
  LRandGen := '/dev/urandom';

  if not FileExists(LRandGen) then
  begin
    LMaxChunkSize := 1040; // 1040 bytes
    LRandGen := '/dev/random';

    if not FileExists(LRandGen) then
    begin
      result := -1;
      Exit;
    end;
  end;

  LStream := TFileStream.Create(LRandGen, fmOpenRead);

  try
    while (ALen > 0) do
    begin
      if ALen <= LMaxChunkSize then
      begin
        LMaxChunkSize := ALen;
      end;

      LGot := LStream.Read(AData^, LMaxChunkSize);

      if (LGot = 0) then
      begin
        if ErrorNo = EINTR then
        begin
          continue;
        end;

        result := -1;
        Exit;
      end;

      System.Inc(AData, LGot);
      System.Dec(ALen, LGot);
    end;
    result := 0;
  finally
    LStream.Free;
  end;
end;

{$ENDIF}
{$IFDEF CRYPTOLIB_HAS_GETRANDOM}

function TSolarisRandomProvider.IsGetRandomAvailable(): Boolean;
var
  LLib: {$IFDEF FPC} PtrInt {$ELSE} NativeUInt {$ENDIF};
begin
  FGetRandom := nil;
  LLib := {$IFDEF FPC}PtrInt{$ENDIF}(dlopen(LIBC_SO, RTLD_NOW));
  if LLib <> 0 then
  begin
    FGetRandom := dlsym(LLib, 'getrandom');
    dlclose(LLib);
  end;
  result := System.Assigned(FGetRandom);
end;

{$ENDIF}

function TSolarisRandomProvider.GenRandomBytesSolaris(ALen: Int32;
  AData: PByte): Int32;
var
  LGot, LMaxChunkSize: Int32;
begin
  LMaxChunkSize := 256; // 256 bytes

{$IFDEF CRYPTOLIB_SOLARIS}
{$IFDEF CRYPTOLIB_HAS_GETRANDOM}
  if FIsGetRandomSupportedOnOS then
  begin
    while (ALen > 0) do
    begin
      if ALen <= LMaxChunkSize then
      begin
        LMaxChunkSize := ALen;
      end;

      LGot := FGetRandom(AData, LongWord(LMaxChunkSize), GRND_DEFAULT);

      if (LGot = 0) then
      begin
        if ErrorNo = EINTR then
        begin
          continue;
        end;
        result := -1;
        Exit;
      end;
      System.Inc(AData, LGot);
      System.Dec(ALen, LGot);
    end;
    result := 0;
  end
  else
  begin
    // fallback for when getrandom API is not available
    result := DevRandomDeviceRead(ALen, AData);
  end;
{$ELSE}
  result := DevRandomDeviceRead(ALen, AData);
{$ENDIF}
{$ELSE}
  result := -1;
{$ENDIF}
end;

procedure TSolarisRandomProvider.GetBytes(const AData: TCryptoLibByteArray);
var
  LCount: Int32;
begin
  LCount := System.Length(AData);

  if LCount <= 0 then
  begin
    Exit;
  end;

{$IFDEF CRYPTOLIB_SOLARIS}
  if GenRandomBytesSolaris(LCount, PByte(AData)) <> 0 then
  begin
    raise EOSRandomCryptoLibException.CreateRes(@SSolarisGetRandomError);
  end;
{$ELSE}
  raise EOSRandomCryptoLibException.Create('SolarisRandomProvider is only available on Solaris');
{$ENDIF}
end;

procedure TSolarisRandomProvider.GetNonZeroBytes(const AData: TCryptoLibByteArray);
begin
  repeat
    GetBytes(AData);
  until (TArrayUtilities.NoZeroes(AData));
end;

function TSolarisRandomProvider.GetIsAvailable: Boolean;
begin
{$IFDEF CRYPTOLIB_SOLARIS}
  result := True;
{$ELSE}
  result := False;
{$ENDIF}
end;

function TSolarisRandomProvider.GetName: String;
begin
  result := 'Solaris';
end;

end.
