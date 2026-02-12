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

unit ClpLinuxRandomProvider;

{$I ..\..\Include\CryptoLib.inc}

interface

{$IFDEF CRYPTOLIB_LINUX}
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
  SLinuxGetRandomError =
    'An Error Occurred while generating random data using getRandom API';

type
{$IFDEF CRYPTOLIB_HAS_GETRANDOM}
{$IFDEF CRYPTOLIB_ANDROID}
const
  LIBC_SO = 'libc.so';
{$ELSE}
const
  LIBC_SO = 'libc.so.6';
{$ENDIF}

const
  GRND_NONBLOCK = $0001;  // Don't block; return EAGAIN if no entropy
  GRND_RANDOM   = $0002;  // Use /dev/random pool instead of /dev/urandom

type
  TGetRandom = function(ABuffer: PByte; ABufferLength: NativeUInt;
    AFlags: UInt32): NativeInt; cdecl;
{$ENDIF}

  /// <summary>
  /// Linux OS random source provider.
  /// Implements Linux getrandom and /dev/urandom fallback
  /// </summary>
  TLinuxRandomProvider = class sealed(TInterfacedObject, IRandomSourceProvider)

  strict private
{$IFDEF CRYPTOLIB_HAS_GETRANDOM}
  var
    FHasGetRandom: Boolean;
    FGetRandom: TGetRandom;

    function IsGetRandomAvailable(): Boolean;
{$ENDIF}
    function GenRandomBytesLinux(ALen: Int32; AData: PByte): Int32;

  public
    constructor Create();

    procedure GetBytes(const AData: TCryptoLibByteArray);
    procedure GetNonZeroBytes(const AData: TCryptoLibByteArray);
    function GetIsAvailable: Boolean;
    function GetName: String;

  end;

{$ENDIF}

implementation

{$IFDEF CRYPTOLIB_LINUX}
uses
  ClpDevRandomReader;

{ TLinuxRandomProvider }

constructor TLinuxRandomProvider.Create;
begin
  inherited Create();
{$IFDEF CRYPTOLIB_HAS_GETRANDOM}
  FHasGetRandom := IsGetRandomAvailable();
{$ENDIF}
end;

{$IFDEF CRYPTOLIB_HAS_GETRANDOM}

function TLinuxRandomProvider.IsGetRandomAvailable(): Boolean;
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

function TLinuxRandomProvider.GenRandomBytesLinux(ALen: Int32;
  AData: PByte): Int32;
var
  LBytesRead: NativeInt;
begin
{$IFDEF CRYPTOLIB_HAS_GETRANDOM}
  if FHasGetRandom then
  begin
    while (ALen > 0) do
    begin
      LBytesRead := FGetRandom(AData, NativeUInt(ALen), 0);

      if (LBytesRead < 0) then
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
    Result := TDevRandomReader.Read(ALen, AData, ALen);
  end;
{$ELSE}
  Result := TDevRandomReader.Read(ALen, AData, ALen);
{$ENDIF}
end;

procedure TLinuxRandomProvider.GetBytes(const AData: TCryptoLibByteArray);
var
  LCount: Int32;
begin
  LCount := System.Length(AData);

  if LCount <= 0 then
  begin
    Exit;
  end;

  if GenRandomBytesLinux(LCount, PByte(AData)) <> 0 then
  begin
    raise EOSRandomCryptoLibException.CreateRes(@SLinuxGetRandomError);
  end;
end;

procedure TLinuxRandomProvider.GetNonZeroBytes(const AData: TCryptoLibByteArray);
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

function TLinuxRandomProvider.GetIsAvailable: Boolean;
begin
  Result := True;
end;

function TLinuxRandomProvider.GetName: String;
begin
  Result := 'Linux';
end;

{$ENDIF}

end.
