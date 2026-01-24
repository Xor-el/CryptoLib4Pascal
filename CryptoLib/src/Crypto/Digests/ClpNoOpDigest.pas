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

unit ClpNoOpDigest;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  Classes,
  SysUtils,
  HlpHash,
  HlpIHash,
  HlpIHashInfo,
  HlpHashResult,
  HlpIHashResult,
  ClpCryptoLibTypes;

type
  TNoOpDigest = class sealed(THash, ITransformBlock)
  strict private
  var
    FOut: TMemoryStream;

  strict protected
    function GetBlockSize: Int32; override;
    function GetHashSize: Int32; override;
    function GetName: String; override;

  public
    constructor Create();
    destructor Destroy(); override;
    procedure Initialize(); override;
    procedure TransformBytes(const AData: TCryptoLibByteArray;
      AIndex, ALength: Int32); override;
    function TransformFinal(): IHashResult; override;
    function Clone(): IHash; override;
  end;

implementation

{ TNoOpDigest }

function TNoOpDigest.GetBlockSize: Int32;
begin
  Result := 0;;
end;

function TNoOpDigest.GetHashSize: Int32;
begin
  Result := Int32(FOut.Size);
end;

function TNoOpDigest.GetName: String;
begin
  Result := 'NoOpDigest';
end;

function TNoOpDigest.Clone(): IHash;
var
  LHashInstance: TNoOpDigest;
begin
  LHashInstance := TNoOpDigest.Create();
  FOut.Position := 0;
  LHashInstance.FOut.CopyFrom(FOut, FOut.Size);
  result := LHashInstance as IHash;
  result.BufferSize := BufferSize;
end;

constructor TNoOpDigest.Create;
begin
  Inherited Create(-1, -1); // Dummy State
  FOut := TMemoryStream.Create();
end;

destructor TNoOpDigest.Destroy;
begin
  FOut.Free;
  inherited Destroy;
end;

procedure TNoOpDigest.Initialize;
begin
  FOut.Clear;
end;

procedure TNoOpDigest.TransformBytes(const AData: TCryptoLibByteArray;
  AIndex, ALength: Int32);
begin
  if AData <> Nil then
  begin
    FOut.Write(AData[AIndex], ALength);
  end;
end;

function TNoOpDigest.TransformFinal: IHashResult;
var
  LResult: TCryptoLibByteArray;
begin
  try
    if FOut.Size > 0 then
    begin
      FOut.Position := 0;
      System.SetLength(LResult, FOut.Size);
      FOut.Read(LResult[0], FOut.Size);
    end;
    result := THashResult.Create(LResult);
  finally
    Initialize();
  end;
end;

end.

