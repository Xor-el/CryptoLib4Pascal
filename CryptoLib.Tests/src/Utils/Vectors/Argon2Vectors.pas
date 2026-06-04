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

unit Argon2Vectors;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  SysUtils,
  ClpCryptoLibTypes,
  CsvVectorParser,
  CsvVectorLoaderBase;

type
  TArgon2VectorRow = record
    Argon2Type: string;
    Version: string;
    Iterations, Memory, Parallelism: Integer;
    Password, Salt, Secret, Additional: string;
    OutputLenBytes: Integer;
    ExpectedHex: string;
    Source: string;
    MemoryCostType: string;
  end;

  /// <summary>
  /// Argon2 test vectors loaded from external CSV.
  /// </summary>
  TArgon2Vectors = class sealed
  strict private
    class var
      FTable: TCsvVectorTable;

    class function RowFromCsv(const ARow: TCsvRow): TArgon2VectorRow; static;
    class function RowsFromCsv(const ACsvRows: TCryptoLibGenericArray<TCsvRow>)
      : TCryptoLibGenericArray<TArgon2VectorRow>; static;
    class function FilterBySource(const ASource: string)
      : TCryptoLibGenericArray<TArgon2VectorRow>; static;
  public
    class function GetDraftRows: TCryptoLibGenericArray<TArgon2VectorRow>; static;
    class function GetOthersRows: TCryptoLibGenericArray<TArgon2VectorRow>; static;
    class constructor Create;
  end;

implementation

{ TArgon2Vectors }

class function TArgon2Vectors.RowFromCsv(const ARow: TCsvRow): TArgon2VectorRow;
begin
  Result.Argon2Type := TCsvVectorParser.GetField(ARow, FTable.Header, 'Type');
  Result.Version := TCsvVectorParser.GetField(ARow, FTable.Header, 'Version');
  Result.Iterations := StrToIntDef(
    TCsvVectorParser.GetField(ARow, FTable.Header, 'Iterations'), 0);
  Result.Memory := StrToIntDef(
    TCsvVectorParser.GetField(ARow, FTable.Header, 'Memory'), 0);
  Result.Parallelism := StrToIntDef(
    TCsvVectorParser.GetField(ARow, FTable.Header, 'Parallelism'), 0);
  Result.Password := TCsvVectorParser.GetField(ARow, FTable.Header, 'Password');
  Result.Salt := TCsvVectorParser.GetField(ARow, FTable.Header, 'Salt');
  Result.Secret := TCsvVectorParser.GetField(ARow, FTable.Header, 'Secret');
  Result.Additional := TCsvVectorParser.GetField(ARow, FTable.Header, 'Additional');
  Result.OutputLenBytes := StrToIntDef(
    TCsvVectorParser.GetField(ARow, FTable.Header, 'OutputLenBytes'), 32);
  Result.ExpectedHex := TCsvVectorParser.GetFieldUpperCase(FTable, ARow, 'ExpectedHex');
  Result.Source := TCsvVectorParser.GetField(ARow, FTable.Header, 'Source');
  Result.MemoryCostType := TCsvVectorParser.GetField(ARow, FTable.Header, 'MemoryCostType');
end;

class function TArgon2Vectors.RowsFromCsv(const ACsvRows: TCryptoLibGenericArray<TCsvRow>)
  : TCryptoLibGenericArray<TArgon2VectorRow>;
var
  LI: Integer;
begin
  SetLength(Result, Length(ACsvRows));
  for LI := 0 to High(ACsvRows) do
    Result[LI] := RowFromCsv(ACsvRows[LI]);
end;

class function TArgon2Vectors.FilterBySource(const ASource: string)
  : TCryptoLibGenericArray<TArgon2VectorRow>;
begin
  Result := RowsFromCsv(TCsvVectorParser.FilterRows(FTable, 'Source', ASource));
end;

class function TArgon2Vectors.GetDraftRows: TCryptoLibGenericArray<TArgon2VectorRow>;
begin
  Result := FilterBySource('draft');
end;

class function TArgon2Vectors.GetOthersRows: TCryptoLibGenericArray<TArgon2VectorRow>;
begin
  Result := FilterBySource('others');
end;

class constructor TArgon2Vectors.Create;
begin
  TCsvVectorLoaderBase.LoadCachedTable(FTable, 'Crypto/Argon2/TestVectors.csv');
end;

end.
