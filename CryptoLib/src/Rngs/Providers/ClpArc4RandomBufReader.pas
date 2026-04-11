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

unit ClpArc4RandomBufReader;

{$I ..\..\Include\CryptoLib.inc}

interface

{$IFDEF CRYPTOLIB_HAS_ARC4RANDOM_BUF}
uses
{$IFDEF FPC}
  dl;
{$ELSE}
  Posix.Dlfcn;
{$ENDIF}

type
  TArc4RandomBufProc = procedure(ABuffer: PByte; ABufferLength: NativeUInt); cdecl;

  /// <summary>
  /// Resolves libc arc4random_buf from the already-loaded program (dlopen(nil)+dlsym),
  /// avoiding tying callers to a specific libc link name. Used by BSD random providers
  /// when CRYPTOLIB_HAS_ARC4RANDOM_BUF is defined (see arc4random(3)).
  /// </summary>
  TArc4RandomBufReader = class sealed
  public
    /// <summary>
    /// Resolves arc4random_buf; returns True and sets AFn when the symbol is found.
    /// Does not dlclose the handle from dlopen(nil).
    /// </summary>
    class function TryResolve(out AFn: TArc4RandomBufProc): Boolean; static;

    /// <summary>
    /// Fills ALength bytes at AData using AFn. ALength &lt; 0 returns -1; ALength = 0
    /// succeeds without calling AFn. Returns 0 on success, -1 if AFn is nil.
    /// </summary>
    class function Read(const AFn: TArc4RandomBufProc; ALength: Int32;
      AData: PByte): Int32; static;
  end;

{$ENDIF}

implementation

{$IFDEF CRYPTOLIB_HAS_ARC4RANDOM_BUF}

{ TArc4RandomBufReader }

class function TArc4RandomBufReader.TryResolve(out AFn: TArc4RandomBufProc): Boolean;
var
  H: Pointer;
  P: Pointer;
begin
  AFn := nil;
{$IFDEF FPC}
  H := dlopen(PChar(nil), RTLD_NOW);
  P := dlsym(H, 'arc4random_buf');
{$ELSE}
  H := dlopen(nil, RTLD_NOW);
  P := dlsym(H, PAnsiChar('arc4random_buf'));
{$ENDIF}
  if P = nil then
  begin
    Result := False;
    Exit;
  end;
  AFn := TArc4RandomBufProc(P);
  Result := True;
end;

class function TArc4RandomBufReader.Read(const AFn: TArc4RandomBufProc;
  ALength: Int32; AData: PByte): Int32;
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
  AFn(AData, NativeUInt(ALength));
  Result := 0;
end;

{$ENDIF}

end.
