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

unit PemReaderVectors;

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
  TPemReaderVectors = class sealed
  strict private
    class var
      FReaderTable: TCsvVectorTable;
  public
    class function LoadFixtureBytes(const AVectorId: string): TCryptoLibByteArray; static;
    class function LoadFixtureText(const AVectorId: string): string; static;
    class constructor Create;
  end;

implementation

{ TPemReaderVectors }

class function TPemReaderVectors.LoadFixtureBytes(const AVectorId: string): TCryptoLibByteArray;
begin
  Result := TCsvVectorLoaderBase.LoadBytesById(FReaderTable, 'VectorId', AVectorId, 'File',
    'Unknown PEM reader fixture: %s');
end;

class function TPemReaderVectors.LoadFixtureText(const AVectorId: string): string;
begin
  Result := TPemDerCodec.BytesToPemString(LoadFixtureBytes(AVectorId));
end;

class constructor TPemReaderVectors.Create;
begin
  TCsvVectorLoaderBase.LoadCachedTable(FReaderTable, 'Pem/Reader/Manifest.csv');
end;

end.
