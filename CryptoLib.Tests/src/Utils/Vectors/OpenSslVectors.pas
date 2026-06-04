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

unit OpenSslVectors;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  SysUtils,
  ClpCryptoLibTypes,
  CsvVectorParser,
  CsvVectorLoaderBase,
  PemDerCodec;

type
  TOpenSslVectors = class sealed
  strict private
    class var
      FReaderTable: TCsvVectorTable;
  public
    class function LoadPemBytes(const AVectorId: string): TCryptoLibByteArray; static;
    class function LoadPemString(const AVectorId: string): string; static;
    class function GetPassword(const AVectorId: string): string; static;
    class constructor Create;
  end;

implementation

{ TOpenSslVectors }

class function TOpenSslVectors.LoadPemBytes(const AVectorId: string): TCryptoLibByteArray;
begin
  Result := TCsvVectorLoaderBase.LoadBytesById(FReaderTable, 'VectorId', AVectorId, 'File',
    'Unknown OpenSSL reader vector: %s');
end;

class function TOpenSslVectors.LoadPemString(const AVectorId: string): string;
begin
  Result := TPemDerCodec.BytesToPemString(LoadPemBytes(AVectorId));
end;

class function TOpenSslVectors.GetPassword(const AVectorId: string): string;
begin
  Result := TCsvVectorLoaderBase.GetPasswordById(FReaderTable, 'VectorId', AVectorId, 'Password',
    'Unknown OpenSSL reader vector: %s');
end;

class constructor TOpenSslVectors.Create;
begin
  TCsvVectorLoaderBase.LoadCachedTable(FReaderTable, 'OpenSsl/Reader/Manifest.csv');
end;

end.
