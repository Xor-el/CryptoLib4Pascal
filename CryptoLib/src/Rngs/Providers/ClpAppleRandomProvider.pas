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

unit ClpAppleRandomProvider;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
{$IFDEF CRYPTOLIB_APPLE}
{$IFDEF FPC}
{$LINKFRAMEWORK Security}
{$IFDEF CRYPTOLIB_MACOS}
  CocoaAll,
{$ENDIF}
{$ELSE}
  Macapi.ObjCRuntime,
{$IFDEF CRYPTOLIB_IOS}
  iOSapi.Foundation,
{$ENDIF}
{$IFDEF CRYPTOLIB_MACOS}
  Macapi.AppKit,
  Macapi.Foundation,
{$ENDIF}
{$ENDIF}
{$ENDIF}
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
  SAppleSecRandomCopyBytesGenerationError =
    'An Error Occured while generating random data using SecRandomCopyBytes API.';

type
{$IFDEF CRYPTOLIB_APPLE}
{$IFDEF FPC}
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

  /// <summary>
  /// Apple OS random source provider.
  /// Implements Apple SecRandomCopyBytes and /dev/urandom fallback
  /// </summary>
  TAppleRandomProvider = class sealed(TInterfacedObject, IRandomSourceProvider)

  strict private
{$IFDEF CRYPTOLIB_UNIX}
  const
    EINTR = {$IFDEF FPC}ESysEINTR {$ELSE}Posix.Errno.EINTR{$ENDIF};

    function ErrorNo: Int32;
    function DevRandomDeviceRead(ALen: Int32; AData: PByte): Int32;
{$ENDIF}
    function GenRandomBytesApple(ALen: Int32; AData: PByte): Int32;

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

{ TAppleRandomProvider }

constructor TAppleRandomProvider.Create;
begin
  inherited Create();
end;

{$IFDEF CRYPTOLIB_UNIX}

function TAppleRandomProvider.ErrorNo: Int32;
begin
  result := Errno;
end;

function TAppleRandomProvider.DevRandomDeviceRead(ALen: Int32;
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

function TAppleRandomProvider.GenRandomBytesApple(ALen: Int32;
  AData: PByte): Int32;
{$IFDEF CRYPTOLIB_APPLE}
  function kSecRandomDefault: SecRandomRef;
  begin
{$IFDEF FPC}
    result := nil;
{$ELSE}
    result := CocoaPointerConst(libSecurity, 'kSecRandomDefault');
{$ENDIF}
  end;
{$ENDIF}

begin
{$IFDEF CRYPTOLIB_APPLE}
{$IF DEFINED(CRYPTOLIB_MACOS)}
  // >= (Mac OS X 10.7+)
  if NSAppKitVersionNumber >= 1138 then // NSAppKitVersionNumber10_7
  begin
    result := SecRandomCopyBytes(kSecRandomDefault, LongWord(ALen), AData);
  end
  else
  begin
    // fallback for when SecRandomCopyBytes API is not available
    result := DevRandomDeviceRead(ALen, AData);
  end;
{$ELSE}
  result := SecRandomCopyBytes(kSecRandomDefault, LongWord(ALen), AData);
{$IFEND}
{$ELSE}
  result := -1;
{$ENDIF}
end;

procedure TAppleRandomProvider.GetBytes(const AData: TCryptoLibByteArray);
var
  LCount: Int32;
begin
  LCount := System.Length(AData);

  if LCount <= 0 then
  begin
    Exit;
  end;

{$IFDEF CRYPTOLIB_APPLE}
  if GenRandomBytesApple(LCount, PByte(AData)) <> 0 then
  begin
    raise EOSRandomCryptoLibException.CreateRes
      (@SAppleSecRandomCopyBytesGenerationError);
  end;
{$ELSE}
  raise EOSRandomCryptoLibException.Create('AppleRandomProvider is only available on Apple platforms');
{$ENDIF}
end;

procedure TAppleRandomProvider.GetNonZeroBytes(const AData: TCryptoLibByteArray);
begin
  repeat
    GetBytes(AData);
  until (TArrayUtilities.NoZeroes(AData));
end;

function TAppleRandomProvider.GetIsAvailable: Boolean;
begin
{$IFDEF CRYPTOLIB_APPLE}
  result := True;
{$ELSE}
  result := False;
{$ENDIF}
end;

function TAppleRandomProvider.GetName: String;
begin
  result := 'Apple';
end;

end.
