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

unit ClpPemObjects;

{$I ..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  Classes,
  Generics.Collections,
  ClpAsn1Core,
  ClpIAsn1Core,
  ClpIPemObjects,
  ClpCryptoLibTypes,
  ClpEncoders,
  ClpStringUtilities,
  ClpAsn1Objects,
  ClpIAsn1Objects,
  ClpCollectionUtilities;

type
  /// <summary>
  /// PEM header implementation.
  /// </summary>
  TPemHeader = class sealed(TInterfacedObject, IPemHeader)
  strict private
    FName: String;
    FValue: String;

    function GetName: String;
    function GetValue: String;
    function GetHashCodeInternal(const AStr: String): Int32;

  public
    constructor Create(const AName, AValue: String);

    function GetHashCode(): {$IFDEF DELPHI}Int32; {$ELSE}PtrInt; {$ENDIF DELPHI} override;
    function Equals(const AObj: IPemHeader): Boolean; reintroduce;
    function ToString(): String; override;

    property Name: String read GetName;
    property Value: String read GetValue;
  end;

  /// <summary>
  /// PEM object implementation.
  /// </summary>
  TPemObject = class sealed(TInterfacedObject, IPemObject, IPemObjectGenerator)
  strict private
    FType: String;
    FHeaders: TCryptoLibGenericArray<IPemHeader>;
    FContent: TCryptoLibByteArray;

    function GetType: String;
    function GetHeaders: TCryptoLibGenericArray<IPemHeader>;
    function GetContent: TCryptoLibByteArray;

  public
    constructor Create(const AType: String; const AContent: TCryptoLibByteArray); overload;
    constructor Create(const AType: String;
      const AHeaders: TCryptoLibGenericArray<IPemHeader>;
      const AContent: TCryptoLibByteArray); overload;

    function Generate(): IPemObject;

    property &Type: String read GetType;
    property Headers: TCryptoLibGenericArray<IPemHeader> read GetHeaders;
    property Content: TCryptoLibByteArray read GetContent;
  end;

implementation

{ TPemHeader }

constructor TPemHeader.Create(const AName, AValue: String);
begin
  Inherited Create();
  FName := AName;
  FValue := AValue;
end;

function TPemHeader.GetName: String;
begin
  Result := FName;
end;

function TPemHeader.GetValue: String;
begin
  Result := FValue;
end;

function TPemHeader.GetHashCodeInternal(const AStr: String): Int32;
begin
  if AStr = '' then
    Result := 1
  else
    Result := TStringUtilities.GetStringHashCode(AStr);
end;

function TPemHeader.GetHashCode(): {$IFDEF DELPHI}Int32; {$ELSE}PtrInt; {$ENDIF DELPHI}
begin
  Result := GetHashCodeInternal(FName) + 31 * GetHashCodeInternal(FValue);
end;

function TPemHeader.Equals(const AObj: IPemHeader): Boolean;
begin
  if AObj = Self as IPemHeader then
  begin
    Result := True;
    Exit;
  end;

  if AObj = nil then
  begin
    Result := False;
    Exit;
  end;

  Result := (FName = AObj.Name) and (FValue = AObj.Value);
end;

function TPemHeader.ToString(): String;
begin
  Result := FName + ':' + FValue;
end;

{ TPemObject }

constructor TPemObject.Create(const AType: String; const AContent: TCryptoLibByteArray);
var
  LEmptyHeaders: TCryptoLibGenericArray<IPemHeader>;
begin
  System.SetLength(LEmptyHeaders, 0);
  Create(AType, LEmptyHeaders, AContent);
end;

constructor TPemObject.Create(const AType: String;
  const AHeaders: TCryptoLibGenericArray<IPemHeader>;
  const AContent: TCryptoLibByteArray);
var
  I: Int32;
begin
  Inherited Create();
  FType := AType;
  System.SetLength(FHeaders, System.Length(AHeaders));
  for I := 0 to System.Length(AHeaders) - 1 do
  begin
    FHeaders[I] := AHeaders[I];
  end;
  FContent := AContent;
end;

function TPemObject.GetType: String;
begin
  Result := FType;
end;

function TPemObject.GetHeaders: TCryptoLibGenericArray<IPemHeader>;
begin
  Result := FHeaders;
end;

function TPemObject.GetContent: TCryptoLibByteArray;
begin
  Result := FContent;
end;

function TPemObject.Generate(): IPemObject;
begin
  Result := Self as IPemObject;
end;

end.
