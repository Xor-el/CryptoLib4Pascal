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

unit ClpDevRandomReader;

{$I ..\..\Include\CryptoLib.inc}

interface

{$IFDEF CRYPTOLIB_UNIX}
uses
  Classes,
{$IFDEF FPC}
  BaseUnix,
{$ELSE}
  Posix.Errno,
{$ENDIF}
  SysUtils;

const
  EINTR = {$IFDEF FPC}ESysEINTR{$ELSE}Posix.Errno.EINTR{$ENDIF};

type
  /// <summary>
  /// Shared utility for reading cryptographically random bytes from
  /// /dev/urandom (preferred) or /dev/random (fallback) device files.
  /// Used by Apple, Linux, Solaris, and Unix random providers.
  /// </summary>
  TDevRandomReader = class sealed
  public
    /// <summary>
    /// Returns the current errno value from the OS.
    /// </summary>
    class function GetErrNo: Int32; static; inline;

    /// <summary>
    /// Reads ALength random bytes into AData from /dev/urandom or /dev/random.
    /// AMaxChunkSize controls the maximum number of bytes read per iteration.
    /// Pass ALength to read in a single chunk.
    /// Returns 0 on success, -1 on failure.
    /// </summary>
    class function Read(ALength: Int32; AData: PByte;
      AMaxChunkSize: Int32): Int32; static;
  end;

{$ENDIF}

implementation

{$IFDEF CRYPTOLIB_UNIX}

{ TDevRandomReader }

class function TDevRandomReader.GetErrNo: Int32;
begin
  Result := Errno;
end;

class function TDevRandomReader.Read(ALength: Int32; AData: PByte;
  AMaxChunkSize: Int32): Int32;
var
  LStream: TFileStream;
  LDevicePath: String;
  LBytesRead: Int32;
begin
  LDevicePath := '/dev/urandom';

  if not FileExists(LDevicePath) then
  begin
    LDevicePath := '/dev/random';

    if not FileExists(LDevicePath) then
    begin
      Result := -1;
      Exit;
    end;
  end;

  LStream := TFileStream.Create(LDevicePath, fmOpenRead);

  try
    while (ALength > 0) do
    begin
      if ALength <= AMaxChunkSize then
      begin
        AMaxChunkSize := ALength;
      end;

      LBytesRead := LStream.Read(AData^, AMaxChunkSize);

      if (LBytesRead = 0) then
      begin
        if GetErrNo = EINTR then
        begin
          continue;
        end;

        Result := -1;
        Exit;
      end;

      System.Inc(AData, LBytesRead);
      System.Dec(ALength, LBytesRead);
    end;
    Result := 0;
  finally
    LStream.Free;
  end;
end;

{$ENDIF}

end.
