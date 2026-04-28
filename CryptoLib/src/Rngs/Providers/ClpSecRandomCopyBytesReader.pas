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

unit ClpSecRandomCopyBytesReader;

{$I ..\..\Include\CryptoLib.inc}

interface

{$IFDEF CRYPTOLIB_HAS_SECRANDOMCOPYBYTES}
uses
{$IFDEF FPC}
{$LINKFRAMEWORK Security}
  dl;
{$ELSE}
  Posix.Dlfcn;
{$ENDIF}

{$IFDEF FPC}
type
  SecRandomRef = OpaquePointer;
{$ELSE}
type
  SecRandomRef = Pointer;
{$ENDIF}

type
  TSecRandomCopyBytesFunc = function(ARnd: SecRandomRef; ACount: NativeUInt;
    ABytes: PByte): Int32; cdecl;

  /// <summary>
  /// Resolves Security.framework SecRandomCopyBytes and kSecRandomDefault via
  /// dlopen(nil)+dlsym (try/finally dlclose), avoiding external declarations on
  /// callers. Used when CRYPTOLIB_HAS_SECRANDOMCOPYBYTES is defined (macOS / iOS).
  /// </summary>
  TSecRandomCopyBytesReader = class sealed
  public
    /// <summary>
    /// Resolves symbols; returns True when SecRandomCopyBytes is found.
    /// kSecRandomDefault is read from the framework when present, else nil.
    /// </summary>
    class function TryResolve(out AFn: TSecRandomCopyBytesFunc;
      out ARandomDefault: SecRandomRef): Boolean; static;

    /// <summary>
    /// Calls AFn(ARandomDefault, ...). ALength &lt; 0 returns -1; ALength = 0 succeeds
    /// without calling AFn. OSStatus 0 (errSecSuccess) maps to 0; else -1.
    /// </summary>
    class function Read(const AFn: TSecRandomCopyBytesFunc;
      ARandomDefault: SecRandomRef; ALength: Int32; AData: PByte): Int32; static;
  end;

{$ENDIF}

implementation

{$IFDEF CRYPTOLIB_HAS_SECRANDOMCOPYBYTES}

{ TSecRandomCopyBytesReader }

class function TSecRandomCopyBytesReader.TryResolve(
  out AFn: TSecRandomCopyBytesFunc; out ARandomDefault: SecRandomRef): Boolean;
var
  LHandle: Pointer;
  LSymbol: Pointer;
  LDefaultPtr: PPointer;
begin
  AFn := nil;
  ARandomDefault := nil;
  LHandle := dlopen(nil, RTLD_NOW);

  if LHandle = nil then
  begin
    Result := False;
    Exit;
  end;
  try
    LSymbol := dlsym(LHandle, 'SecRandomCopyBytes');

    if LSymbol = nil then
    begin
      Result := False;
      Exit;
    end;
    AFn := TSecRandomCopyBytesFunc(LSymbol);

    LSymbol := dlsym(LHandle, 'kSecRandomDefault');
    if LSymbol <> nil then
    begin
      LDefaultPtr := PPointer(LSymbol);
      ARandomDefault := SecRandomRef(LDefaultPtr^);
    end;

    Result := True;
  finally
    dlclose(LHandle);
  end;
end;

class function TSecRandomCopyBytesReader.Read(const AFn: TSecRandomCopyBytesFunc;
  ARandomDefault: SecRandomRef; ALength: Int32; AData: PByte): Int32;
var
  LStatus: Int32;
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
  LStatus := AFn(ARandomDefault, NativeUInt(ALength), AData);
  if LStatus = 0 then
  begin
    Result := 0;
  end
  else
  begin
    Result := -1;
  end;
end;

{$ENDIF}

end.
