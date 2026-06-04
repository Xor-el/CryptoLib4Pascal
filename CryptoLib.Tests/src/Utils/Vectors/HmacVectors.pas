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

unit HmacVectors;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  SysUtils,
  ClpCryptoLibTypes,
  ClpConverters,
  ClpEncoders,
  CsvVectorParser,
  CsvVectorLoaderBase;

type
  THmacRfc2202Row = record
    Algorithm: string;
    CaseIndex: Integer;
    Key, Message, ExpectedHex: string;
  end;

  THmacCrossAlgorithmRow = record
    Algorithm: string;
    KeyHex: string;
    Message: string;
    ExpectedHex: string;
    DefaultKeySizeBits: Integer;
  end;

  /// <summary>
  /// HMAC test vectors: RFC 2202 per-algorithm cases and cross-algorithm smoke vectors.
  /// </summary>
  THmacVectors = class sealed
  strict private
    class var
      FRfc2202Rows: TCryptoLibGenericArray<THmacRfc2202Row>;
      FRfc2202Table: TCsvVectorTable;
      FCrossAlgorithmRows: TCryptoLibGenericArray<THmacCrossAlgorithmRow>;
      FCrossAlgorithmTable: TCsvVectorTable;
      FCrossAlgorithmKeyBytes: TBytes;
      FCrossAlgorithmMessage: TBytes;

    class function Rfc2202RowFromCsv(const ARow: TCsvRow): THmacRfc2202Row; static;
    class function CrossAlgorithmRowFromCsv(const ARow: TCsvRow): THmacCrossAlgorithmRow; static;
    class function FindCrossAlgorithmRow(const AAlgorithm: string): THmacCrossAlgorithmRow; static;
    class procedure LoadRfc2202Rows; static;
    class procedure LoadCrossAlgorithmRows; static;
  public
    class function GetRfc2202Rows(const AAlgorithm: string)
      : TCryptoLibGenericArray<THmacRfc2202Row>; static;
    class function GetCrossAlgorithmKeyBytes: TBytes; static;
    class function GetCrossAlgorithmMessage: TBytes; static;
    class function GetCrossAlgorithmExpectedHex(const AAlgorithm: string): string; static;
    class function GetCrossAlgorithmDefaultKeySizeBits(const AAlgorithm: string): Integer; static;
    class constructor Create;
  end;

implementation

{ THmacVectors }

class function THmacVectors.Rfc2202RowFromCsv(const ARow: TCsvRow): THmacRfc2202Row;
begin
  Result.Algorithm := TCsvVectorParser.GetField(ARow, FRfc2202Table.Header, 'Algorithm');
  Result.CaseIndex := StrToIntDef(
    TCsvVectorParser.GetField(ARow, FRfc2202Table.Header, 'CaseIndex'), 0);
  Result.Key := TCsvVectorParser.GetField(ARow, FRfc2202Table.Header, 'Key');
  Result.Message := TCsvVectorParser.GetField(ARow, FRfc2202Table.Header, 'Message');
  Result.ExpectedHex := TCsvVectorParser.GetField(ARow, FRfc2202Table.Header, 'ExpectedHex');
end;

class function THmacVectors.CrossAlgorithmRowFromCsv(const ARow: TCsvRow)
  : THmacCrossAlgorithmRow;
var
  LKeySizeText: string;
begin
  Result.Algorithm := TCsvVectorParser.GetField(ARow, FCrossAlgorithmTable.Header, 'Algorithm');
  Result.KeyHex := TCsvVectorParser.GetField(ARow, FCrossAlgorithmTable.Header, 'KeyHex');
  Result.Message := TCsvVectorParser.GetField(ARow, FCrossAlgorithmTable.Header, 'Message');
  Result.ExpectedHex := TCsvVectorParser.GetField(ARow, FCrossAlgorithmTable.Header, 'ExpectedHex');
  LKeySizeText := TCsvVectorParser.GetField(
    ARow, FCrossAlgorithmTable.Header, 'DefaultKeySizeBits');
  if LKeySizeText = '' then
    Result.DefaultKeySizeBits := -1
  else
    Result.DefaultKeySizeBits := StrToIntDef(LKeySizeText, -1);
end;

class function THmacVectors.FindCrossAlgorithmRow(const AAlgorithm: string)
  : THmacCrossAlgorithmRow;
var
  LI: Integer;
begin
  for LI := 0 to High(FCrossAlgorithmRows) do
  begin
    if SameText(FCrossAlgorithmRows[LI].Algorithm, AAlgorithm) then
      Exit(FCrossAlgorithmRows[LI]);
  end;
  raise Exception.CreateFmt('Unknown cross-algorithm HMAC vector: %s', [AAlgorithm]);
end;

class procedure THmacVectors.LoadRfc2202Rows;
var
  LI: Integer;
begin
  FRfc2202Table := TCsvVectorLoaderBase.LoadTable('Crypto/Hmac/Rfc2202.csv');
  SetLength(FRfc2202Rows, Length(FRfc2202Table.Rows));
  for LI := 0 to High(FRfc2202Table.Rows) do
    FRfc2202Rows[LI] := Rfc2202RowFromCsv(FRfc2202Table.Rows[LI]);
end;

class procedure THmacVectors.LoadCrossAlgorithmRows;
var
  LI: Integer;
begin
  FCrossAlgorithmTable := TCsvVectorLoaderBase.LoadTable('Crypto/Hmac/CrossAlgorithm.csv');
  SetLength(FCrossAlgorithmRows, Length(FCrossAlgorithmTable.Rows));
  for LI := 0 to High(FCrossAlgorithmTable.Rows) do
    FCrossAlgorithmRows[LI] := CrossAlgorithmRowFromCsv(FCrossAlgorithmTable.Rows[LI]);

  if Length(FCrossAlgorithmRows) = 0 then
    raise Exception.Create('CrossAlgorithm.csv contains no rows');

  FCrossAlgorithmKeyBytes := THexEncoder.Decode(FCrossAlgorithmRows[0].KeyHex);
  FCrossAlgorithmMessage := TConverters.ConvertStringToBytes(
    FCrossAlgorithmRows[0].Message, TEncoding.ASCII);
end;

class function THmacVectors.GetRfc2202Rows(const AAlgorithm: string)
  : TCryptoLibGenericArray<THmacRfc2202Row>;
var
  LI, LCount: Integer;
begin
  LCount := 0;
  Result := nil;
  for LI := 0 to High(FRfc2202Rows) do
  begin
    if SameText(FRfc2202Rows[LI].Algorithm, AAlgorithm) then
    begin
      SetLength(Result, LCount + 1);
      Result[LCount] := FRfc2202Rows[LI];
      Inc(LCount);
    end;
  end;
end;

class function THmacVectors.GetCrossAlgorithmKeyBytes: TBytes;
begin
  Result := FCrossAlgorithmKeyBytes;
end;

class function THmacVectors.GetCrossAlgorithmMessage: TBytes;
begin
  Result := FCrossAlgorithmMessage;
end;

class function THmacVectors.GetCrossAlgorithmExpectedHex(const AAlgorithm: string): string;
begin
  Result := FindCrossAlgorithmRow(AAlgorithm).ExpectedHex;
end;

class function THmacVectors.GetCrossAlgorithmDefaultKeySizeBits(const AAlgorithm: string): Integer;
begin
  Result := FindCrossAlgorithmRow(AAlgorithm).DefaultKeySizeBits;
end;

class constructor THmacVectors.Create;
begin
  LoadRfc2202Rows;
  LoadCrossAlgorithmRows;
end;

end.
