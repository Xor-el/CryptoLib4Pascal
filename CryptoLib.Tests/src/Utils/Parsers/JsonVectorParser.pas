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

unit JsonVectorParser;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  SysUtils,
{$IFDEF FPC}
  fpjson,
  jsonparser,
{$ELSE}
  System.JSON,
{$ENDIF FPC}
  ClpCryptoLibTypes,
  CryptoLibTestResourceLoader;

type
  {$IFDEF FPC}
  TJsonNode = TJSONData;
  {$ELSE}
  TJsonNode = TJSONValue;
  {$ENDIF FPC}

  TJsonVectorObject = class;

  TJsonVectorDocument = class(TObject)
  private
    FRootOwner: TJsonNode;
    FRoot: TJsonVectorObject;
  public
    constructor Create(const AContent: string);
    destructor Destroy; override;
    property Root: TJsonVectorObject read FRoot;
    class function LoadFile(const ARelativePath: string): TJsonVectorDocument;
  end;

  TJsonVectorObject = class(TObject)
  private
    FObj: TJSONObject;
    function GetField(const AName: string): TJsonNode;
    class function NodeIsNull(const ANode: TJsonNode): Boolean; static;
    class function NodeAsString(const ANode: TJsonNode): string; static;
    class function NodeAsInteger(const ANode: TJsonNode): Integer; static;
    class function NodeAsBoolean(const ANode: TJsonNode): Boolean; static;
    function GetArray(const AName: string): TJSONArray;
  public
    constructor Create(AObj: TJSONObject);
    function HasField(const AName: string): Boolean;
    function IsNullField(const AName: string): Boolean;
    function GetString(const AName: string): string;
    function GetInt(const AName: string; ADefault: Integer = 0): Integer;
    function GetBool(const AName: string; ADefault: Boolean = False): Boolean;
    function GetStringArray(const AName: string): TCryptoLibStringArray;
    function GetIntArray(const AName: string): TCryptoLibGenericArray<Int32>;
    function GetBoolArray(const AName: string): TCryptoLibBooleanArray;
    /// Caller must free each element returned by GetObjectArray / GetNestedObject.
    function GetObjectArray(const AName: string): TCryptoLibGenericArray<TJsonVectorObject>;
    function GetNestedObject(const AName: string): TJsonVectorObject;
    function GetErrorSignerIndex(const AName: string = 'signer'): Int32;
    class procedure FreeOwnedArray(var AObjects: TCryptoLibGenericArray<TJsonVectorObject>);
  end;

implementation

{ TJsonVectorDocument }

constructor TJsonVectorDocument.Create(const AContent: string);
begin
  inherited Create;
  {$IFDEF FPC}
  FRootOwner := GetJSON(AContent);
  {$ELSE}
  FRootOwner := TJSONObject.ParseJSONValue(AContent);
  {$ENDIF FPC}
  if not (FRootOwner is TJSONObject) then
  begin
    FRootOwner.Free;
    raise EConvertError.Create('JSON root must be an object');
  end;
  FRoot := TJsonVectorObject.Create(TJSONObject(FRootOwner));
end;

destructor TJsonVectorDocument.Destroy;
begin
  FRoot.Free;
  FRootOwner.Free;
  inherited;
end;

class function TJsonVectorDocument.LoadFile(const ARelativePath: string)
  : TJsonVectorDocument;
begin
  Result := TJsonVectorDocument.Create(
    TCryptoLibTestResourceLoader.Instance.LoadAsString(ARelativePath));
end;

{ TJsonVectorObject }

constructor TJsonVectorObject.Create(AObj: TJSONObject);
begin
  inherited Create;
  FObj := AObj;
end;

function TJsonVectorObject.GetField(const AName: string): TJsonNode;
begin
  if FObj = nil then
    Exit(nil);
  {$IFDEF FPC}
  Result := FObj.Find(AName);
  {$ELSE}
  Result := FObj.GetValue(AName);
  {$ENDIF FPC}
end;

class function TJsonVectorObject.NodeIsNull(const ANode: TJsonNode): Boolean;
begin
  {$IFDEF FPC}
  Result := (ANode = nil) or (ANode.JSONType = TJSONType.jtNull);
  {$ELSE}
  Result := (ANode = nil) or (ANode is TJSONNull);
  {$ENDIF FPC}
end;

class function TJsonVectorObject.NodeAsString(const ANode: TJsonNode): string;
begin
  {$IFDEF FPC}
  Result := ANode.AsString;
  {$ELSE}
  Result := ANode.Value;
  {$ENDIF FPC}
end;

class function TJsonVectorObject.NodeAsInteger(const ANode: TJsonNode): Integer;
begin
  {$IFDEF FPC}
  Result := ANode.AsInteger;
  {$ELSE}
  Result := StrToIntDef(ANode.Value, 0);
  {$ENDIF FPC}
end;

class function TJsonVectorObject.NodeAsBoolean(const ANode: TJsonNode): Boolean;
begin
  {$IFDEF FPC}
  Result := ANode.AsBoolean;
  {$ELSE}
  Result := SameText(ANode.Value, 'true');
  {$ENDIF FPC}
end;

function TJsonVectorObject.GetArray(const AName: string): TJSONArray;
var
  LNode: TJsonNode;
begin
  Result := nil;
  if FObj = nil then
    Exit;
  LNode := GetField(AName);
  if (LNode <> nil) and (LNode is TJSONArray) then
    Result := TJSONArray(LNode);
end;

function TJsonVectorObject.HasField(const AName: string): Boolean;
begin
  Result := GetField(AName) <> nil;
end;

function TJsonVectorObject.IsNullField(const AName: string): Boolean;
var
  LNode: TJsonNode;
begin
  LNode := GetField(AName);
  if LNode = nil then
    Exit(False);
  Result := NodeIsNull(LNode);
end;

function TJsonVectorObject.GetString(const AName: string): string;
var
  LNode: TJsonNode;
begin
  LNode := GetField(AName);
  if (LNode = nil) or NodeIsNull(LNode) then
    Exit('');
  Result := NodeAsString(LNode);
end;

function TJsonVectorObject.GetInt(const AName: string; ADefault: Integer): Integer;
begin
  if not HasField(AName) or IsNullField(AName) then
    Exit(ADefault);
  Result := StrToIntDef(GetString(AName), ADefault);
end;

function TJsonVectorObject.GetBool(const AName: string; ADefault: Boolean): Boolean;
var
  LNode: TJsonNode;
begin
  LNode := GetField(AName);
  if (LNode = nil) or NodeIsNull(LNode) then
    Exit(ADefault);
  Result := NodeAsBoolean(LNode);
end;

function TJsonVectorObject.GetStringArray(const AName: string): TCryptoLibStringArray;
var
  LArr: TJSONArray;
  LI: Integer;
  LItem: TJsonNode;
begin
  Result := nil;
  LArr := GetArray(AName);
  if LArr = nil then
    Exit;
  SetLength(Result, LArr.Count);
  for LI := 0 to LArr.Count - 1 do
  begin
    LItem := LArr.Items[LI];
    if NodeIsNull(LItem) then
      Result[LI] := ''
    else
      Result[LI] := NodeAsString(LItem);
  end;
end;

function TJsonVectorObject.GetIntArray(const AName: string)
  : TCryptoLibGenericArray<Int32>;
var
  LArr: TJSONArray;
  LI: Integer;
begin
  Result := nil;
  LArr := GetArray(AName);
  if LArr = nil then
    Exit;
  SetLength(Result, LArr.Count);
  for LI := 0 to LArr.Count - 1 do
    Result[LI] := NodeAsInteger(LArr.Items[LI]);
end;

function TJsonVectorObject.GetBoolArray(const AName: string): TCryptoLibBooleanArray;
var
  LArr: TJSONArray;
  LI: Integer;
begin
  Result := nil;
  LArr := GetArray(AName);
  if LArr = nil then
    Exit;
  SetLength(Result, LArr.Count);
  for LI := 0 to LArr.Count - 1 do
    Result[LI] := NodeAsBoolean(LArr.Items[LI]);
end;

function TJsonVectorObject.GetObjectArray(const AName: string): TCryptoLibGenericArray<TJsonVectorObject>;
var
  LArr: TJSONArray;
  LI: Integer;
  LItem: TJsonNode;
begin
  Result := nil;
  LArr := GetArray(AName);
  if LArr = nil then
    Exit;
  SetLength(Result, LArr.Count);
  for LI := 0 to LArr.Count - 1 do
  begin
    LItem := LArr.Items[LI];
    if not (LItem is TJSONObject) then
      raise EConvertError.CreateFmt('Expected object at %s[%d]', [AName, LI]);
    Result[LI] := TJsonVectorObject.Create(TJSONObject(LItem));
  end;
end;

function TJsonVectorObject.GetNestedObject(const AName: string): TJsonVectorObject;
var
  LNode: TJsonNode;
begin
  LNode := GetField(AName);
  if (LNode = nil) or not (LNode is TJSONObject) then
    raise EConvertError.CreateFmt('Expected object field %s', [AName]);
  Result := TJsonVectorObject.Create(TJSONObject(LNode));
end;

function TJsonVectorObject.GetErrorSignerIndex(const AName: string): Int32;
begin
  if IsNullField(AName) then
    Exit(-1);
  Result := GetInt(AName, -1);
end;

class procedure TJsonVectorObject.FreeOwnedArray(
  var AObjects: TCryptoLibGenericArray<TJsonVectorObject>);
var
  LI: Integer;
begin
  for LI := 0 to High(AObjects) do
    AObjects[LI].Free;
  AObjects := nil;
end;

end.
