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

unit RspTxtVectorParser;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  SysUtils,
  Classes,
  Generics.Collections,
  CryptoLibTestResourceLoader;

type
  TRspTxtRecord = TDictionary<string, string>;

  TRspTxtVectorCallback = class abstract(TObject)
  public
    procedure OnVector(const AName: string; const AData: TRspTxtRecord); virtual;
      abstract;
  end;

  /// <summary>
  /// Per-vector handler as a method pointer, so a suite can pass one of its own
  /// methods directly instead of a hand-written TRspTxtVectorCallback subclass.
  /// </summary>
  TRspTxtVectorHandler = procedure(const AName: string;
    const AData: TRspTxtRecord) of object;

  TRspTxtVectorParser = class sealed(TObject)
  public
    class procedure RunVectors(const ARelativePath1, ARelativePath2: string;
      ACallback: TRspTxtVectorCallback); overload; static;
    class procedure RunVectors(const ARelativePath: string;
      ACallback: TRspTxtVectorCallback); overload; static;
    class procedure RunVectors(const ARelativePath: string;
      const AHandler: TRspTxtVectorHandler); overload; static;
  end;

implementation

type
  // Adapts a method-pointer handler to the abstract-callback contract.
  TRspTxtVectorHandlerAdapter = class(TRspTxtVectorCallback)
  strict private
    FHandler: TRspTxtVectorHandler;
  public
    constructor Create(const AHandler: TRspTxtVectorHandler);
    procedure OnVector(const AName: string; const AData: TRspTxtRecord); override;
  end;

constructor TRspTxtVectorHandlerAdapter.Create(const AHandler: TRspTxtVectorHandler);
begin
  inherited Create();
  FHandler := AHandler;
end;

procedure TRspTxtVectorHandlerAdapter.OnVector(const AName: string;
  const AData: TRspTxtRecord);
begin
  if Assigned(FHandler) then
    FHandler(AName, AData);
end;

{ TRspTxtVectorParser }

class procedure TRspTxtVectorParser.RunVectors(const ARelativePath1,
  ARelativePath2: string; ACallback: TRspTxtVectorCallback);
var
  LPath: string;
begin
  if ARelativePath2 = '' then
    LPath := ARelativePath1
  else
    LPath := IncludeTrailingPathDelimiter(ARelativePath1) + ARelativePath2;
  RunVectors(LPath, ACallback);
end;

class procedure TRspTxtVectorParser.RunVectors(const ARelativePath: string;
  ACallback: TRspTxtVectorCallback);
var
  LContent: string;
  LReader: TStringList;
  LLine: string;
  LData, LCopy: TRspTxtRecord;
  LEq: Int32;
  LKey, LValue: string;
  LI: Int32;
  LPair: TPair<string, string>;
begin
  if not Assigned(ACallback) then
    Exit;

  LContent := TCryptoLibTestResourceLoader.Instance.LoadAsString(ARelativePath);
  LReader := TStringList.Create;
  LData := TRspTxtRecord.Create;
  try
    LReader.Text := LContent;
    for LI := 0 to LReader.Count - 1 do
    begin
      LLine := Trim(LReader[LI]);
      if (LLine <> '') and (LLine[1] = '#') then
        Continue;

      if LLine <> '' then
      begin
        LEq := Pos('=', LLine);
        if LEq > 0 then
        begin
          LKey := Trim(Copy(LLine, 1, LEq - 1));
          LValue := Trim(Copy(LLine, LEq + 1, MaxInt));
          LData.AddOrSetValue(LKey, LValue);
        end;
        Continue;
      end;

      if LData.Count > 0 then
      begin
        LCopy := TRspTxtRecord.Create;
        try
          for LPair in LData do
            LCopy.Add(LPair.Key, LPair.Value);
          ACallback.OnVector(ARelativePath, LCopy);
        finally
          LCopy.Free;
        end;
        LData.Clear;
      end;
    end;

    if LData.Count > 0 then
    begin
      LCopy := TRspTxtRecord.Create;
      try
        for LPair in LData do
          LCopy.Add(LPair.Key, LPair.Value);
        ACallback.OnVector(ARelativePath, LCopy);
      finally
        LCopy.Free;
      end;
    end;
  finally
    LData.Free;
    LReader.Free;
  end;
end;

class procedure TRspTxtVectorParser.RunVectors(const ARelativePath: string;
  const AHandler: TRspTxtVectorHandler);
var
  LAdapter: TRspTxtVectorHandlerAdapter;
begin
  LAdapter := TRspTxtVectorHandlerAdapter.Create(AHandler);
  try
    RunVectors(ARelativePath, LAdapter as TRspTxtVectorCallback);
  finally
    LAdapter.Free;
  end;
end;

end.
