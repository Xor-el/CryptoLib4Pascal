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

unit HpkeVectors;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  SysUtils,
  Classes,
  Generics.Collections,
  ClpEncoders,
  ClpCryptoLibTypes,
  CryptoLibTestResourceLoader;

type
  THpkeEncryptionVector = record
    Aad, Ct, Nonce, Pt: TBytes;
  end;

  THpkeExportVector = record
    ExporterContext: TBytes;
    L: Int32;
    ExportedValue: TBytes;
  end;

  THpkeVectorRecord = record
    Mode, KemId, KdfId, AeadId: Int32;
    Info, IkmR, IkmE, SkRm, SkEm, PkRm, PkEm, Enc, SharedSecret, Key,
      BaseNonce: TBytes;
    IkmS, SkSm, PkSm, Psk, PskId: TBytes;
    Encryptions: TCryptoLibGenericArray<THpkeEncryptionVector>;
    ExportVectors: TCryptoLibGenericArray<THpkeExportVector>;
  end;

  /// <summary>
  /// Loader for the RFC 9180 HPKE test vectors (crypto/hpke.txt). The file is a
  /// flat "key = value" block format (blocks separated by blank lines) with
  /// nested encryptions and exports lists.
  /// </summary>
  THpkeVectors = class sealed
  strict private
  const
    ResourcePath = 'Crypto/Hpke/hpke.txt';

  class var
    FRecords: TCryptoLibGenericArray<THpkeVectorRecord>;

    class function BuildRecord(const ABuf: TDictionary<string, string>;
      const AEncryptions: TList<THpkeEncryptionVector>;
      const AExports: TList<THpkeExportVector>): THpkeVectorRecord; static;
    class procedure Load(); static;

  public
    class function GetRecords(): TCryptoLibGenericArray<THpkeVectorRecord>;
      static;
  end;

implementation

{ THpkeVectors }

class function THpkeVectors.BuildRecord(const ABuf: TDictionary<string, string>;
  const AEncryptions: TList<THpkeEncryptionVector>;
  const AExports: TList<THpkeExportVector>): THpkeVectorRecord;
begin
  Result.Mode := StrToInt(ABuf['mode']);
  Result.KemId := StrToInt(ABuf['kem_id']);
  Result.KdfId := StrToInt(ABuf['kdf_id']);
  Result.AeadId := StrToInt(ABuf['aead_id']);

  Result.Info := THexEncoder.Decode(ABuf['info']);
  Result.IkmR := THexEncoder.Decode(ABuf['ikmR']);
  Result.IkmE := THexEncoder.Decode(ABuf['ikmE']);
  Result.SkRm := THexEncoder.Decode(ABuf['skRm']);
  Result.SkEm := THexEncoder.Decode(ABuf['skEm']);
  Result.PkRm := THexEncoder.Decode(ABuf['pkRm']);
  Result.PkEm := THexEncoder.Decode(ABuf['pkEm']);
  Result.Enc := THexEncoder.Decode(ABuf['enc']);
  Result.SharedSecret := THexEncoder.Decode(ABuf['shared_secret']);
  Result.Key := THexEncoder.Decode(ABuf['key']);
  Result.BaseNonce := THexEncoder.Decode(ABuf['base_nonce']);

  Result.IkmS := nil;
  Result.SkSm := nil;
  Result.PkSm := nil;
  Result.Psk := nil;
  Result.PskId := nil;

  // mode 2 (auth) and 3 (auth_psk) carry the sender's static key
  if (Result.Mode = 2) or (Result.Mode = 3) then
  begin
    Result.IkmS := THexEncoder.Decode(ABuf['ikmS']);
    Result.SkSm := THexEncoder.Decode(ABuf['skSm']);
    Result.PkSm := THexEncoder.Decode(ABuf['pkSm']);
  end;
  // mode 1 (psk) and 3 (auth_psk) carry the pre-shared key
  if (Result.Mode = 1) or (Result.Mode = 3) then
  begin
    Result.Psk := THexEncoder.Decode(ABuf['psk']);
    Result.PskId := THexEncoder.Decode(ABuf['psk_id']);
  end;

  Result.Encryptions := AEncryptions.ToArray;
  Result.ExportVectors := AExports.ToArray;
end;

class procedure THpkeVectors.Load;
var
  LText: string;
  LLines: TStringList;
  LBuf, LEncBuf, LExpBuf: TDictionary<string, string>;
  LEncryptions: TList<THpkeEncryptionVector>;
  LExports: TList<THpkeExportVector>;
  LRecords: TList<THpkeVectorRecord>;
  LIdx, LEq: Int32;
  LLine: string;
  LEnc: THpkeEncryptionVector;
  LExp: THpkeExportVector;
begin
  LText := TCryptoLibTestResourceLoader.Instance.LoadAsString(ResourcePath);
  LLines := TStringList.Create;
  LBuf := TDictionary<string, string>.Create;
  LEncBuf := TDictionary<string, string>.Create;
  LExpBuf := TDictionary<string, string>.Create;
  LEncryptions := TList<THpkeEncryptionVector>.Create;
  LExports := TList<THpkeExportVector>.Create;
  LRecords := TList<THpkeVectorRecord>.Create;
  try
    LLines.Text := LText;
    LIdx := 0;
    while LIdx < LLines.Count do
    begin
      LLine := Trim(LLines[LIdx]);
      Inc(LIdx);

      if LLine = '' then
      begin
        if LBuf.Count > 0 then
        begin
          LRecords.Add(BuildRecord(LBuf, LEncryptions, LExports));
        end;
        LBuf.Clear;
        LEncryptions.Clear;
        LExports.Clear;
        Continue;
      end;

      LEq := Pos('=', LLine);
      if LEq > 0 then
      begin
        LBuf.AddOrSetValue(Trim(Copy(LLine, 1, LEq - 1)),
          Trim(Copy(LLine, LEq + 1, System.Length(LLine))));
      end;

      if LLine = 'encryptionsSTART' then
      begin
        LEncBuf.Clear;
        while LIdx < LLines.Count do
        begin
          LLine := Trim(LLines[LIdx]);
          Inc(LIdx);
          if LLine = 'encryptionsSTOP' then
            Break;
          if LLine = '<' then
          begin
            LEnc.Aad := THexEncoder.Decode(LEncBuf['aad']);
            LEnc.Ct := THexEncoder.Decode(LEncBuf['ct']);
            LEnc.Nonce := THexEncoder.Decode(LEncBuf['nonce']);
            LEnc.Pt := THexEncoder.Decode(LEncBuf['pt']);
            LEncryptions.Add(LEnc);
            LEncBuf.Clear;
          end
          else
          begin
            LEq := Pos('=', LLine);
            if LEq > 0 then
              LEncBuf.AddOrSetValue(Trim(Copy(LLine, 1, LEq - 1)),
                Trim(Copy(LLine, LEq + 1, System.Length(LLine))));
          end;
        end;
      end;

      if LLine = 'exportsSTART' then
      begin
        LExpBuf.Clear;
        while LIdx < LLines.Count do
        begin
          LLine := Trim(LLines[LIdx]);
          Inc(LIdx);
          if LLine = 'exportsSTOP' then
            Break;
          if LLine = '<' then
          begin
            LExp.ExporterContext := THexEncoder.Decode
              (LExpBuf['exporter_context']);
            LExp.L := StrToInt(LExpBuf['L']);
            LExp.ExportedValue := THexEncoder.Decode(LExpBuf['exported_value']);
            LExports.Add(LExp);
            LExpBuf.Clear;
          end
          else
          begin
            LEq := Pos('=', LLine);
            if LEq > 0 then
              LExpBuf.AddOrSetValue(Trim(Copy(LLine, 1, LEq - 1)),
                Trim(Copy(LLine, LEq + 1, System.Length(LLine))));
          end;
        end;
      end;
    end;

    // final record if the file did not end with a blank line
    if LBuf.Count > 0 then
    begin
      LRecords.Add(BuildRecord(LBuf, LEncryptions, LExports));
    end;

    FRecords := LRecords.ToArray;
  finally
    LLines.Free;
    LBuf.Free;
    LEncBuf.Free;
    LExpBuf.Free;
    LEncryptions.Free;
    LExports.Free;
    LRecords.Free;
  end;
end;

class function THpkeVectors.GetRecords: TCryptoLibGenericArray<THpkeVectorRecord>;
begin
  if FRecords = nil then
  begin
    Load();
  end;
  Result := FRecords;
end;

end.
