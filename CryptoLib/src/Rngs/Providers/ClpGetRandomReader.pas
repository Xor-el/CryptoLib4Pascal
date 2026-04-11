{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                           Author - Ugochukwu Mmaduekwe                          * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }

{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }

{ *                              Acknowledgements:                                  * }
{ *                                                                                 * }
{ *      Thanks to Sphere 10 Software (http://www.sphere10.com/) for sponsoring     * }
{ *                           development of this library                           * }

{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit ClpGetRandomReader;

{$I ..\..\Include\CryptoLib.inc}

interface

{$IFDEF CRYPTOLIB_HAS_GETRANDOM}
uses
{$IFDEF FPC}
  dl,
{$ELSE}
  Posix.Dlfcn,
{$ENDIF}
  Math,
  SysUtils,
  ClpUnixLikeRngCommon;

const
  /// <summary>getrandom(2) flag: do not block (may return EAGAIN).</summary>
  GRND_NONBLOCK = UInt32(1);
  /// <summary>getrandom(2) flag: read from /dev/random (blocking).</summary>
  GRND_RANDOM = UInt32(2);

type
  TGetRandomFunc = function(ABuffer: PByte; ABufferLength: NativeUInt;
    AFlags: UInt32): NativeInt; cdecl;

  /// <summary>
  /// Resolves libc getrandom from the already-loaded program (dlopen(nil)+dlsym),
  /// avoiding glibc/musl-specific libc sonames. Used by Linux, Android, Solaris
  /// random providers when CRYPTOLIB_HAS_GETRANDOM is defined.
  /// </summary>
  TGetRandomReader = class sealed
  public
    /// <summary>
    /// Resolves getrandom; returns True and sets AFn when the symbol is found.
    /// </summary>
    class function TryResolve(out AFn: TGetRandomFunc): Boolean; static;

    /// <summary>
    /// Reads ALength bytes using AFn. AMaxChunkSize is the OS random provider's
    /// per-call byte limit (must be &gt; 0 when ALength &gt; 0).
    /// AFlags: getrandom flags (e.g. GRND_NONBLOCK); passed through to the syscall.
    /// AZeroBytesIsFailure: True for Solaris; False for Linux/Android.
    /// ALength &lt; 0 returns -1; ALength = 0 succeeds without calling AFn.
    /// Returns 0 on success, -1 on failure.
    /// </summary>
    class function Read(const AFn: TGetRandomFunc; AMaxChunkSize: Int32;
      AFlags: UInt32; ALength: Int32; AData: PByte;
      AZeroBytesIsFailure: Boolean): Int32; static;
  end;

{$ENDIF}

implementation

{$IFDEF CRYPTOLIB_HAS_GETRANDOM}

{ TGetRandomReader }

class function TGetRandomReader.TryResolve(out AFn: TGetRandomFunc): Boolean;
var
  LHandle: Pointer;
  LSymbol: Pointer;
begin
  AFn := nil;
  LHandle := dlopen(nil, RTLD_NOW);

  if LHandle = nil then
  begin
    Result := False;
    Exit;
  end;
  try
    LSymbol := dlsym(LHandle, 'getrandom');

    if LSymbol = nil then
    begin
      Result := False;
      Exit;
    end;
    AFn := TGetRandomFunc(LSymbol);
    Result := True;
  finally
    dlclose(LHandle);
  end;
end;

class function TGetRandomReader.Read(const AFn: TGetRandomFunc; AMaxChunkSize: Int32;
  AFlags: UInt32; ALength: Int32; AData: PByte;
  AZeroBytesIsFailure: Boolean): Int32;
var
  LBytesRead: NativeInt;
  LChunk: Int32;
  LErr: Int32;
begin
  if not System.Assigned(AFn) then
  begin
    Result := -1;
    Exit;
  end;

  if ALength < 0 then
  begin
    Result := -1;
    Exit;
  end;
  if ALength = 0 then
  begin
    Result := 0;
    Exit;
  end;

  if AMaxChunkSize <= 0 then
  begin
    Result := -1;
    Exit;
  end;

  while ALength > 0 do
  begin
    LChunk := Math.Min(ALength, AMaxChunkSize);

    LBytesRead := AFn(AData, NativeUInt(LChunk), AFlags);

    if AZeroBytesIsFailure then
    begin
      if LBytesRead <= 0 then
      begin
        LErr := TUnixLikeRngCommon.GetErrNo;
        if (LErr = EINTR) or (LErr = EAGAIN) then
        begin
          continue;
        end;
        Result := -1;
        Exit;
      end;
    end
    else
    begin
      if LBytesRead < 0 then
      begin
        LErr := TUnixLikeRngCommon.GetErrNo;
        if (LErr = EINTR) or (LErr = EAGAIN) then
        begin
          continue;
        end;
        Result := -1;
        Exit;
      end;
      if LBytesRead = 0 then
      begin
        Result := -1;
        Exit;
      end;
    end;

    System.Inc(AData, LBytesRead);
    System.Dec(ALength, LBytesRead);
  end;
  Result := 0;
end;

{$ENDIF}

end.
