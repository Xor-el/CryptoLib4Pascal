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

unit ClpUnixRandomProvider;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
{$IFDEF CRYPTOLIB_UNIX}
  Classes,
{$IFDEF FPC}
  BaseUnix,
{$ELSE}
  Posix.Errno,
{$ENDIF}
{$ENDIF}
  SysUtils,
  ClpCryptoLibTypes,
  ClpIRandomSourceProvider;

resourcestring
  SRandomDeviceReadError =
    'An Error Occured while reading random data from random device (file)';

type
  /// <summary>
  /// Unix OS random source provider (fallback for other Unix systems).
  /// Implements /dev/urandom fallback
  /// </summary>
  TUnixRandomProvider = class sealed(TInterfacedObject, IRandomSourceProvider)

  strict private
{$IFDEF CRYPTOLIB_UNIX}
  const
    EINTR = {$IFDEF FPC}ESysEINTR {$ELSE}Posix.Errno.EINTR{$ENDIF};

    function ErrorNo: Int32;
    function DevRandomDeviceRead(ALen: Int32; AData: PByte): Int32;
{$ENDIF}

  public
    constructor Create();

    procedure GetBytes(const AData: TCryptoLibByteArray);
    procedure GetNonZeroBytes(const AData: TCryptoLibByteArray);
    function GetIsAvailable: Boolean;
    function GetName: String;

  end;

implementation

uses
  ClpArrayUtils;

{ TUnixRandomProvider }

constructor TUnixRandomProvider.Create;
begin
  inherited Create();
end;

{$IFDEF CRYPTOLIB_UNIX}

function TUnixRandomProvider.ErrorNo: Int32;
begin
  result := Errno;
end;

function TUnixRandomProvider.DevRandomDeviceRead(ALen: Int32;
  AData: PByte): Int32;
var
  LStream: TFileStream;
  LRandGen: String;
  LGot, LMaxChunkSize: Int32;
begin
  LMaxChunkSize := ALen;
  LRandGen := '/dev/urandom';

  if not FileExists(LRandGen) then
  begin
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

procedure TUnixRandomProvider.GetBytes(const AData: TCryptoLibByteArray);
var
  LCount: Int32;
begin
  LCount := System.Length(AData);

  if LCount <= 0 then
  begin
    Exit;
  end;

{$IFDEF CRYPTOLIB_UNIX}
  if DevRandomDeviceRead(LCount, PByte(AData)) <> 0 then
  begin
    raise EOSRandomCryptoLibException.CreateRes(@SRandomDeviceReadError);
  end;
{$ELSE}
  raise EOSRandomCryptoLibException.Create('UnixRandomProvider is only available on Unix platforms');
{$ENDIF}
end;

procedure TUnixRandomProvider.GetNonZeroBytes(const AData: TCryptoLibByteArray);
begin
  repeat
    GetBytes(AData);
  until (TArrayUtils.NoZeroes(AData));
end;

function TUnixRandomProvider.GetIsAvailable: Boolean;
begin
{$IFDEF CRYPTOLIB_UNIX}
  result := True;
{$ELSE}
  result := False;
{$ENDIF}
end;

function TUnixRandomProvider.GetName: String;
begin
  result := 'Unix';
end;

end.
