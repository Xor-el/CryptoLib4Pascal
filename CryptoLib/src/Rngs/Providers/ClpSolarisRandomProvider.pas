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

{$IFDEF CRYPTOLIB_SOLARIS}
uses
{$IFDEF FPC}
{$IFDEF CRYPTOLIB_HAS_GETRANDOM}
  dl,
{$ENDIF}
{$ELSE}
{$IFDEF CRYPTOLIB_HAS_GETRANDOM}
  Posix.Dlfcn,
{$ENDIF}
{$ENDIF}
  SysUtils,
  ClpCryptoLibTypes,
  ClpIRandomSourceProvider;

resourcestring
  SSolarisGetRandomError =
    'An Error Occurred while generating random data using getRandom API';

type
{$IFDEF CRYPTOLIB_HAS_GETRANDOM}
const
  LIBC_SO = 'libc.so.1';

  // Solaris getrandom flags (from sys/random.h)
  GRND_NONBLOCK = $0001;  // Don't block; return EAGAIN if no entropy
  GRND_RANDOM   = $0002;  // Use /dev/random pool instead of /dev/urandom

  // Maximum buffer size supported by Solaris getrandom (EINVAL if exceeded)
  SolarisGetRandomMaxBuffer = 1024;

type
  TGetRandom = function(ABuffer: PByte; ABufferLength: NativeUInt;
    AFlags: UInt32): NativeInt; cdecl;
{$ENDIF}

  /// <summary>
  /// Solaris OS random source provider.
  /// Implements Solaris getrandom and /dev/urandom fallback
  /// </summary>
  TSolarisRandomProvider = class sealed(TInterfacedObject, IRandomSourceProvider)

  strict private
{$IFDEF CRYPTOLIB_HAS_GETRANDOM}
  var
    FHasGetRandom: Boolean;
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

{$ENDIF}

implementation

{$IFDEF CRYPTOLIB_SOLARIS}
uses
  ClpDevRandomReader;

{ TSolarisRandomProvider }

constructor TSolarisRandomProvider.Create;
begin
  inherited Create();
{$IFDEF CRYPTOLIB_HAS_GETRANDOM}
  FHasGetRandom := IsGetRandomAvailable();
{$ENDIF}
end;

{$IFDEF CRYPTOLIB_HAS_GETRANDOM}

function TSolarisRandomProvider.IsGetRandomAvailable(): Boolean;
var
  LLib: NativeUInt;
begin
  FGetRandom := nil;
  LLib := {$IFDEF FPC}NativeUInt{$ENDIF}(dlopen(LIBC_SO, RTLD_NOW));
  if LLib <> 0 then
  begin
    FGetRandom := dlsym(LLib, 'getrandom');
    dlclose(LLib);
  end;
  Result := System.Assigned(FGetRandom);
end;

{$ENDIF}

function TSolarisRandomProvider.GenRandomBytesSolaris(ALen: Int32;
  AData: PByte): Int32;
var
  LBytesRead: NativeInt;
  LMaxChunkSize: Int32;
begin
  LMaxChunkSize := SolarisGetRandomMaxBuffer;

{$IFDEF CRYPTOLIB_HAS_GETRANDOM}
  if FHasGetRandom then
  begin
    while (ALen > 0) do
    begin
      if ALen <= LMaxChunkSize then
      begin
        LMaxChunkSize := ALen;
      end;

      LBytesRead := FGetRandom(AData, NativeUInt(LMaxChunkSize), 0);

      // Hardened: covers 0 (error per Solaris docs) and -1 (EAGAIN defensive)
      if (LBytesRead <= 0) then
      begin
        if TDevRandomReader.GetErrNo = EINTR then
        begin
          continue;
        end;
        Result := -1;
        Exit;
      end;
      System.Inc(AData, LBytesRead);
      System.Dec(ALen, LBytesRead);
    end;
    Result := 0;
  end
  else
  begin
    // fallback for when getrandom API is not available
    Result := TDevRandomReader.Read(ALen, AData, SolarisGetRandomMaxBuffer);
  end;
{$ELSE}
  Result := TDevRandomReader.Read(ALen, AData, SolarisGetRandomMaxBuffer);
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

  if GenRandomBytesSolaris(LCount, PByte(AData)) <> 0 then
  begin
    raise EOSRandomCryptoLibException.CreateRes(@SSolarisGetRandomError);
  end;
end;

procedure TSolarisRandomProvider.GetNonZeroBytes(const AData: TCryptoLibByteArray);
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

function TSolarisRandomProvider.GetIsAvailable: Boolean;
begin
  Result := True;
end;

function TSolarisRandomProvider.GetName: String;
begin
  Result := 'Solaris';
end;

{$ENDIF}

end.
