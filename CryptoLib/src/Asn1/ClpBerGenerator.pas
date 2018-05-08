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

unit ClpBerGenerator;

{$I ..\Include\CryptoLib.inc}

interface

uses
  Classes,
  ClpStreams,
  ClpStreamHelper,
  ClpIProxiedInterface,
  ClpAsn1Tags,
  ClpAsn1Generator,
  ClpBerOutputStream,
  ClpIBerGenerator;

type
  TBerGenerator = class abstract(TAsn1Generator, IBerGenerator)

  strict private
  var
    F_tagged, F_isExplicit: Boolean;
    F_tagNo: Int32;

    procedure WriteHdr(tag: Int32);

  strict protected
    constructor Create(outStream: TStream); overload;
    constructor Create(outStream: TStream; tagNo: Int32;
      isExplicit: Boolean); overload;

    procedure WriteBerHeader(tag: Int32);
    procedure WriteBerBody(contentStream: TStream);
    procedure WriteBerEnd();

  public
    procedure AddObject(const obj: IAsn1Encodable); override;
    function GetRawOutputStream(): TStream; override;
    procedure Close(); override;

  end;

implementation

{ TBerGenerator }

constructor TBerGenerator.Create(outStream: TStream);
begin
  Inherited Create(outStream);
end;

procedure TBerGenerator.AddObject(const obj: IAsn1Encodable);
var
  temp: TBerOutputStream;
begin
  temp := TBerOutputStream.Create(&Out);
  try
    temp.WriteObject(obj);
  finally
    temp.Free;
  end;
end;

procedure TBerGenerator.Close;
begin
  WriteBerEnd();
end;

constructor TBerGenerator.Create(outStream: TStream; tagNo: Int32;
  isExplicit: Boolean);
begin
  Inherited Create(outStream);
  F_tagged := true;
  F_isExplicit := isExplicit;
  F_tagNo := tagNo;
end;

function TBerGenerator.GetRawOutputStream: TStream;
begin
  result := &Out;
end;

procedure TBerGenerator.WriteBerBody(contentStream: TStream);
begin
  TStreams.PipeAll(contentStream, &Out);
end;

procedure TBerGenerator.WriteBerEnd;
begin
  &Out.WriteByte($00);
  &Out.WriteByte($00);

  if (F_tagged and F_isExplicit) then // write extra end for tag header
  begin
    &Out.WriteByte($00);
    &Out.WriteByte($00);
  end;
end;

procedure TBerGenerator.WriteBerHeader(tag: Int32);
var
  tagNum: Int32;
begin
  if (F_tagged) then
  begin
    tagNum := F_tagNo or TAsn1Tags.Tagged;

    if (F_isExplicit) then
    begin
      WriteHdr(tagNum or TAsn1Tags.Constructed);
      WriteHdr(tag);
    end
    else
    begin
      if ((tag and TAsn1Tags.Constructed) <> 0) then
      begin
        WriteHdr(tagNum or TAsn1Tags.Constructed);
      end
      else
      begin
        WriteHdr(tagNum);
      end;
    end
  end
  else
  begin
    WriteHdr(tag);
  end;
end;

procedure TBerGenerator.WriteHdr(tag: Int32);
begin
  &Out.WriteByte(Byte(tag));
  &Out.WriteByte($80);
end;

end.
