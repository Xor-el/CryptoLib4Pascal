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

unit Bip340Vectors;

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
  TBip340VectorRow = record
    SecretKey, PublicKey, AuxRand, Message, Signature: string;
    VerifyResult: Boolean;
    Comment: string;
  end;

  /// <summary>
  /// BIP-340 Schnorr test vectors from external CSV.
  /// </summary>
  TBip340Vectors = class sealed
  strict private
    class var
      FRows: TCryptoLibGenericArray<TBip340VectorRow>;
      FTable: TCsvVectorTable;

    class function RowFromCsv(const ARow: TCsvRow): TBip340VectorRow; static;
  public
    class function GetRows: TCryptoLibGenericArray<TBip340VectorRow>; static;
    class constructor Create;
  end;

implementation

{ TBip340Vectors }

class function TBip340Vectors.RowFromCsv(const ARow: TCsvRow): TBip340VectorRow;
begin
  Result.SecretKey := TCsvVectorParser.GetField(ARow, FTable.Header, 'secret key');
  Result.PublicKey := TCsvVectorParser.GetField(ARow, FTable.Header, 'public key');
  Result.AuxRand := TCsvVectorParser.GetField(ARow, FTable.Header, 'aux_rand');
  Result.Message := TCsvVectorParser.GetField(ARow, FTable.Header, 'message');
  Result.Signature := TCsvVectorParser.GetField(ARow, FTable.Header, 'signature');
  Result.VerifyResult := SameText(
    TCsvVectorParser.GetField(ARow, FTable.Header, 'verification result'), 'TRUE');
  Result.Comment := TCsvVectorParser.GetField(ARow, FTable.Header, 'comment');
end;

class function TBip340Vectors.GetRows: TCryptoLibGenericArray<TBip340VectorRow>;
begin
  Result := FRows;
end;

class constructor TBip340Vectors.Create;
var
  LI: Integer;
begin
  FTable := TCsvVectorLoaderBase.LoadTable('Crypto/Bip340/TestVectors.csv');
  SetLength(FRows, Length(FTable.Rows));
  for LI := 0 to High(FTable.Rows) do
    FRows[LI] := RowFromCsv(FTable.Rows[LI]);
end;

end.
