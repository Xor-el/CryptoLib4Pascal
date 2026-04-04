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

unit ClpValueHelper;

{$I ..\Include\CryptoLib.inc}

interface

uses
  Rtti,
  SysUtils,
  TypInfo;

type
  TValueHelper = record helper for TValue
{$IFDEF FPC}
  strict private
    const
      EmptyGuid: TGUID = (D1: 0; D2: 0; D3: 0; D4: (0, 0, 0, 0, 0, 0, 0, 0));
    /// <summary>
    /// FPC-specific implementation of TValue.TryAsType (empty, exact match, interface/class casting).
    /// Stopgap in FPC 3.2.x until the minimum supported FPC version provides TValue.TryAsType out of the box;
    /// this helper can then be removed and call sites can use the RTL method.
    /// </summary>
    // TODO: Remove this stopgap when upgrading minimum supported FPC to a version that provides TValue.TryAsType in RTL.
    function TryGetAsTypeFpcImpl<T>(out AResult: T; const AEmptyAsAnyType: Boolean): Boolean;
{$ENDIF}
  public
    function TryGetAsType<T>(out AResult: T; const AEmptyAsAnyType: Boolean = True): Boolean;
    function GetAsType<T>(const AEmptyAsAnyType: Boolean = True): T;
  end;

implementation

{ TValueHelper }

function TValueHelper.GetAsType<T>(const AEmptyAsAnyType: Boolean): T;
var
  LResult: T;
begin
{$IFDEF FPC}
  if not (TryGetAsType<T>(LResult, AEmptyAsAnyType)) then
    raise EInvalidCast.Create('Invalid cast');
  Result := LResult;
{$ELSE}
  Result := Self.AsType<T>(AEmptyAsAnyType);
{$ENDIF}
end;

{$IFDEF FPC}
function TValueHelper.TryGetAsTypeFpcImpl<T>(out AResult: T; const AEmptyAsAnyType: Boolean): Boolean;
var
  LTargetInfo: PTypeInfo;
  LContext: TRttiContext;
  LType: TRttiType;
  LObj: TObject;
  LClass: TClass;
  LGuid: TGuid;
  LIntf: IInterface;
  LPtr: Pointer;
  LVal: TValue;
begin
  Result := False;
  LTargetInfo := System.TypeInfo(T);

  if AEmptyAsAnyType and Self.IsEmpty then
  begin
    AResult := Default(T);
    Exit(True);
  end;

  if Self.TypeInfo = nil then
    Exit;

  if LTargetInfo = nil then
    Exit;

  if Self.TypeInfo = LTargetInfo then
  begin
    if Self.TypeInfo <> nil then
      Self.ExtractRawData(@AResult)
    else
      AResult := Default(T);
    Exit(True);
  end;

  case Self.Kind of
    tkInterface:
      begin
        if (LTargetInfo^.Kind = tkInterface) or (LTargetInfo^.Kind = tkInterfaceRaw) then
        begin
          LContext := TRttiContext.Create;
          try
            LType := LContext.GetType(LTargetInfo);
            if (LType <> nil) and (LType is TRttiInterfaceType) then
            begin
              LGuid := (LType as TRttiInterfaceType).GUID;
              LIntf := Self.AsInterface;
              Result := Supports(LIntf, LGuid, AResult);
            end;
          finally
            LContext.Free;
          end;
        end;
      end;
    tkInterfaceRaw:
      begin
        if (LTargetInfo^.Kind = tkInterface) or (LTargetInfo^.Kind = tkInterfaceRaw) then
        begin
          LContext := TRttiContext.Create;
          try
            LType := LContext.GetType(LTargetInfo);
            if (LType <> nil) and (LType is TRttiInterfaceType) then
            begin
              LGuid := (LType as TRttiInterfaceType).GUID;
              LPtr := PPointer(Self.GetReferenceToRawData)^;
              if LPtr <> nil then
                Result := Supports(IUnknown(LPtr), LGuid, AResult);
            end;
          finally
            LContext.Free;
          end;
        end;
      end;
    tkClass:
      begin
        LObj := Self.AsObject;
        if LTargetInfo^.Kind = tkClass then
        begin
          LClass := GetTypeData(LTargetInfo)^.ClassType;
          if (LObj <> nil) and (LClass <> nil) and LObj.InheritsFrom(LClass) then
          begin
            PPointer(@AResult)^ := LObj;
            Result := True;
          end;
        end
        else
        if (LTargetInfo^.Kind = tkInterface) or (LTargetInfo^.Kind = tkInterfaceRaw) then
        begin
          LContext := TRttiContext.Create;
          try
            LType := LContext.GetType(LTargetInfo);
            if (LType <> nil) and (LType is TRttiInterfaceType) then
            begin
              LGuid := (LType as TRttiInterfaceType).GUID;
              if not IsEqualGUID(LGuid, EmptyGuid) then
              begin
                if (LObj <> nil) and LObj.GetInterface(LGuid, LPtr) then
                begin
                  TValue.Make(@LPtr, LTargetInfo, LVal);
                  try
                    LVal.ExtractRawData(@AResult);
                  finally
                    if LPtr <> nil then
                      IUnknown(LPtr)._Release;
                  end;
                  Result := True;
                end;
              end;
            end;
          finally
            LContext.Free;
          end;
        end;
      end;
  end;
end;
{$ENDIF}

function TValueHelper.TryGetAsType<T>(out AResult: T; const AEmptyAsAnyType: Boolean): Boolean;
begin
{$IFDEF FPC}
  Result := TryGetAsTypeFpcImpl<T>(AResult, AEmptyAsAnyType);
{$ELSE}
  Result := Self.TryAsType<T>(AResult, AEmptyAsAnyType);
{$ENDIF}
end;

end.
