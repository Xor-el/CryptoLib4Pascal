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

unit ClpWeakRef;

{$I ..\Include\CryptoLib.inc}

interface

type
  TWeakRef<T: IInterface> = record
  private
    FTarget: Pointer;
    function GetTarget: T; inline;
  public
    procedure Assign(const AValue: T); inline;
    procedure Clear; inline;
    function TryGetTarget(out target: T): Boolean; inline;
    function IsAlive: Boolean; inline;

    property Target: T read GetTarget;

    class operator Implicit(const AValue: T): TWeakRef<T>;
    class operator Implicit(const A: TWeakRef<T>): T;
  end;

implementation

{ TWeakRef<T> }

procedure TWeakRef<T>.Clear;
begin
  FTarget := nil;
end;

procedure TWeakRef<T>.Assign(const AValue: T);
begin
  FTarget := Pointer(IInterface(AValue));
end;

function TWeakRef<T>.GetTarget: T;
begin
  Result := T(IInterface(FTarget));
end;

function TWeakRef<T>.TryGetTarget(out target: T): Boolean;
begin
  Result := FTarget <> nil;
  if Result then
    target := T(IInterface(FTarget))
  else
    target := Default(T);
end;

function TWeakRef<T>.IsAlive: Boolean;
begin
  Result := FTarget <> nil;
end;

class operator TWeakRef<T>.Implicit(const AValue: T): TWeakRef<T>;
begin
  Result.FTarget := Pointer(IInterface(AValue));
end;

class operator TWeakRef<T>.Implicit(const A: TWeakRef<T>): T;
begin
  Result := A.GetTarget;
end;

end.
