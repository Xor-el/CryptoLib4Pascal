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

unit ClpDerSequenceGenerator;

{$I ..\Include\CryptoLib.inc}

interface

uses
  Classes,
  ClpCryptoLibTypes,
  ClpAsn1Tags,
  ClpDerOutputStream,
  ClpDerGenerator,
  ClpIProxiedInterface,
  ClpIDerSequenceGenerator;

type
  TDerSequenceGenerator = class(TDerGenerator, IDerSequenceGenerator)

  strict private
  var
    F_bOut: TMemoryStream;

  public
    constructor Create(outStream: TStream); overload;
    constructor Create(outStream: TStream; tagNo: Int32;
      isExplicit: Boolean); overload;
    destructor Destroy(); override;
    procedure AddObject(const obj: IAsn1Encodable); override;
    function GetRawOutputStream(): TStream; override;
    procedure Close(); override;
  end;

implementation

{ TDerSequenceGenerator }

procedure TDerSequenceGenerator.AddObject(const obj: IAsn1Encodable);
var
  temp: TDerOutputStream;
begin
  temp := TDerOutputStream.Create(F_bOut);
  try
    temp.WriteObject(obj);
  finally
    temp.Free;
  end;
end;

procedure TDerSequenceGenerator.Close;
var
  temp: TCryptoLibByteArray;
begin
  F_bOut.Position := 0;
  System.SetLength(temp, F_bOut.Size);
  F_bOut.Read(temp[0], F_bOut.Size);
  WriteDerEncoded(TAsn1Tags.Constructed or TAsn1Tags.Sequence, temp);
end;

constructor TDerSequenceGenerator.Create(outStream: TStream);
begin
  Inherited Create(outStream);
  F_bOut := TMemoryStream.Create();
end;

constructor TDerSequenceGenerator.Create(outStream: TStream; tagNo: Int32;
  isExplicit: Boolean);
begin
  Inherited Create(outStream, tagNo, isExplicit);
  F_bOut := TMemoryStream.Create();
end;

destructor TDerSequenceGenerator.Destroy;
begin
  F_bOut.Free;
  inherited Destroy;
end;

function TDerSequenceGenerator.GetRawOutputStream: TStream;
begin
  result := F_bOut;
end;

end.
