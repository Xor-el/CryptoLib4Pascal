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

{$IFDEF CRYPTOLIB_APPLE}
uses
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
  SysUtils,
  ClpCryptoLibTypes,
  ClpBaseRandomProvider;

resourcestring
  SAppleSecRandomError =
    'An Error Occurred while generating random data using SecRandomCopyBytes API.';

type
{$IFDEF FPC}
  SecRandomRef = OpaquePointer;

function SecRandomCopyBytes(ARnd: SecRandomRef; ACount: NativeUInt;
  ABytes: PByte): Int32; cdecl; external;

{$ELSE}

type
  SecRandomRef = Pointer;

const
  libSecurity = '/System/Library/Frameworks/Security.framework/Security';

function SecRandomCopyBytes(ARnd: SecRandomRef; ACount: NativeUInt;
  ABytes: PByte): Int32; cdecl;
  external libSecurity Name _PU + 'SecRandomCopyBytes';

{$ENDIF}

  /// <summary>
  /// Apple OS random source provider.
  /// Implements Apple SecRandomCopyBytes and /dev/urandom fallback
  /// </summary>
  TAppleRandomProvider = class sealed(TBaseRandomProvider)

  strict private
  const
    NSAppKitVersionNumber10_7 = 1138;

    function GenRandomBytesApple(ALen: Int32; AData: PByte): Int32;

  public
    constructor Create();

    procedure GetBytes(const AData: TCryptoLibByteArray); override;
    function GetIsAvailable: Boolean; override;
    function GetName: String; override;

  end;

{$ENDIF}

implementation

{$IFDEF CRYPTOLIB_APPLE}
uses
  ClpDevRandomReader;

{ TAppleRandomProvider }

constructor TAppleRandomProvider.Create;
begin
  inherited Create();
end;

function TAppleRandomProvider.GenRandomBytesApple(ALen: Int32;
  AData: PByte): Int32;

  function kSecRandomDefault: SecRandomRef;
  begin
{$IFDEF FPC}
    Result := nil;
{$ELSE}
    Result := CocoaPointerConst(libSecurity, 'kSecRandomDefault');
{$ENDIF}
  end;

begin
{$IF DEFINED(CRYPTOLIB_MACOS)}
  // >= (Mac OS X 10.7+)
  if NSAppKitVersionNumber >= NSAppKitVersionNumber10_7 then
  begin
    Result := SecRandomCopyBytes(kSecRandomDefault, NativeUInt(ALen), AData);
  end
  else
  begin
    // fallback for when SecRandomCopyBytes API is not available
    Result := TDevRandomReader.Read(ALen, AData, ALen);
  end;
{$ELSE}
  Result := SecRandomCopyBytes(kSecRandomDefault, NativeUInt(ALen), AData);
{$IFEND}
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

  if GenRandomBytesApple(LCount, PByte(AData)) <> 0 then
  begin
    raise EOSRandomCryptoLibException.CreateRes(@SAppleSecRandomError);
  end;
end;

function TAppleRandomProvider.GetIsAvailable: Boolean;
begin
  Result := True;
end;

function TAppleRandomProvider.GetName: String;
begin
  Result := 'Apple';
end;

{$ENDIF}

end.
