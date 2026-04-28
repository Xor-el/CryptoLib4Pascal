{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                           Author - Ugochukwu Mmaduekwe                          * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ *                                                                                 * }
{ *                              Acknowledgements:                                  * }
{ *                                                                                 * }
{ *      Thanks to Sphere 10 Software (http://www.sphere10.com/) for sponsoring     * }
{ *                         the development of this library                         * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit ClpDevRandomReader;

{$I ..\..\Include\CryptoLib.inc}

interface

{$IFDEF CRYPTOLIB_HAS_DEVRANDOM}
uses
  Classes,
  Math,
  SysUtils,
  ClpUnixLikeRngCommon;

type
  /// <summary>
  /// Shared utility for reading cryptographically random bytes from
  /// /dev/urandom (preferred) or /dev/random (fallback) device files.
  /// Used by Apple, Linux, Solaris, and Unix random providers.
  /// </summary>
  TDevRandomReader = class sealed
  public

    /// <summary>
    /// Reads ALength random bytes into AData from /dev/urandom or /dev/random.
    /// AMaxChunkSize is the maximum bytes per TStream.Read; must be &gt; 0 when
    /// ALength &gt; 0 (same contract as TGetRandomReader.Read&apos;s AMaxChunk).
    /// ALength &lt; 0 returns -1; ALength = 0 succeeds without opening devices.
    /// Returns 0 on success, -1 on failure.
    /// </summary>
    class function Read(ALength: Int32; AData: PByte;
      AMaxChunkSize: Int32): Int32; static;
  end;

{$ENDIF}

implementation

{$IFDEF CRYPTOLIB_HAS_DEVRANDOM}

{ TDevRandomReader }

class function TDevRandomReader.Read(ALength: Int32; AData: PByte;
  AMaxChunkSize: Int32): Int32;
var
  LStream: TFileStream;
  LDevicePath: String;
  LBytesRead: Int32;
  LChunk: Int32;
begin
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
    while ALength > 0 do
    begin
      LChunk := Math.Min(ALength, AMaxChunkSize);

      LBytesRead := LStream.Read(AData^, LChunk);

      if (LBytesRead = 0) then
      begin
        if TUnixLikeRngCommon.GetErrNo = EINTR then
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
