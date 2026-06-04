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

unit CsvVectorLoaderBase;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  SysUtils,
  ClpCryptoLibTypes,
  CryptoLibTestResourceLoader,
  CsvVectorParser;

type
  /// <summary>
  /// Shared helpers for CSV-backed vector loaders and manifest file loading.
  /// </summary>
  TCsvVectorLoaderBase = class sealed
  public
    class procedure LoadCachedTable(var ATable: TCsvVectorTable;
      const ARelativePath: string); static;
    class function LoadTable(const ARelativePath: string): TCsvVectorTable; static;
    class function GetField(const ATable: TCsvVectorTable; const ARow: TCsvRow;
      const AName: string): string; static;
    class function GetFieldTrimmed(const ATable: TCsvVectorTable; const ARow: TCsvRow;
      const AName: string): string; static;
    class function GetFieldUpperCase(const ATable: TCsvVectorTable; const ARow: TCsvRow;
      const AName: string): string; static;
    class function FindRowIndex(const ATable: TCsvVectorTable; const AIdField,
      AId: string; const AErrorFormat: string): Integer; static;
    class function GetPassword(const ATable: TCsvVectorTable; const ARow: TCsvRow;
      const APasswordField: string = 'Password'): string; static;
    class function LoadBytes(const ATable: TCsvVectorTable; const ARow: TCsvRow;
      const AFileField: string = 'File'): TCryptoLibByteArray; static;
    class function LoadBytesById(const ATable: TCsvVectorTable; const AIdField,
      AId, AFileField: string; const AErrorFormat: string): TCryptoLibByteArray; static;
    class function GetPasswordById(const ATable: TCsvVectorTable; const AIdField,
      AId, APasswordField: string; const AErrorFormat: string): string; static;
  end;

implementation

{ TCsvVectorLoaderBase }

class procedure TCsvVectorLoaderBase.LoadCachedTable(var ATable: TCsvVectorTable;
  const ARelativePath: string);
begin
  ATable := LoadTable(ARelativePath);
end;

class function TCsvVectorLoaderBase.LoadTable(const ARelativePath: string): TCsvVectorTable;
begin
  Result := TCsvVectorParser.LoadTable(ARelativePath);
end;

class function TCsvVectorLoaderBase.GetField(const ATable: TCsvVectorTable;
  const ARow: TCsvRow; const AName: string): string;
begin
  Result := TCsvVectorParser.GetField(ARow, ATable.Header, AName);
end;

class function TCsvVectorLoaderBase.GetFieldTrimmed(const ATable: TCsvVectorTable;
  const ARow: TCsvRow; const AName: string): string;
begin
  Result := Trim(GetField(ATable, ARow, AName));
end;

class function TCsvVectorLoaderBase.GetFieldUpperCase(const ATable: TCsvVectorTable;
  const ARow: TCsvRow; const AName: string): string;
begin
  Result := TCsvVectorParser.GetFieldUpperCase(ATable, ARow, AName);
end;

class function TCsvVectorLoaderBase.FindRowIndex(const ATable: TCsvVectorTable;
  const AIdField, AId, AErrorFormat: string): Integer;
var
  LI: Integer;
begin
  for LI := 0 to High(ATable.Rows) do
  begin
    if SameText(GetFieldTrimmed(ATable, ATable.Rows[LI], AIdField), AId) then
      Exit(LI);
  end;
  raise Exception.CreateFmt(AErrorFormat, [AId]);
end;

class function TCsvVectorLoaderBase.GetPassword(const ATable: TCsvVectorTable;
  const ARow: TCsvRow; const APasswordField: string): string;
begin
  Result := GetFieldTrimmed(ATable, ARow, APasswordField);
end;

class function TCsvVectorLoaderBase.LoadBytes(const ATable: TCsvVectorTable;
  const ARow: TCsvRow; const AFileField: string): TCryptoLibByteArray;
var
  LPath: string;
begin
  LPath := GetFieldTrimmed(ATable, ARow, AFileField);
  Result := TCryptoLibTestResourceLoader.Instance.LoadAsBytes(LPath);
end;

class function TCsvVectorLoaderBase.LoadBytesById(const ATable: TCsvVectorTable;
  const AIdField, AId, AFileField, AErrorFormat: string): TCryptoLibByteArray;
var
  LIndex: Integer;
begin
  LIndex := FindRowIndex(ATable, AIdField, AId, AErrorFormat);
  Result := LoadBytes(ATable, ATable.Rows[LIndex], AFileField);
end;

class function TCsvVectorLoaderBase.GetPasswordById(const ATable: TCsvVectorTable;
  const AIdField, AId, APasswordField, AErrorFormat: string): string;
var
  LIndex: Integer;
begin
  LIndex := FindRowIndex(ATable, AIdField, AId, AErrorFormat);
  Result := GetPassword(ATable, ATable.Rows[LIndex], APasswordField);
end;

end.
