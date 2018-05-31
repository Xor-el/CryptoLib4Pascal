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

unit ClpAsn1Encodable;

{$I ..\Include\CryptoLib.inc}

interface

uses
  Classes,
  ClpAsn1OutputStream,
  ClpDerOutputStream,
  ClpIProxiedInterface,
  ClpCryptoLibTypes;

type

  TAsn1Encodable = class abstract(TInterfacedObject, IAsn1Encodable,
    IAsn1Convertible)

  public

    const
    Der: String = 'DER';
    Ber: String = 'BER';

    function GetEncoded(): TCryptoLibByteArray; overload;
    function GetEncoded(const encoding: String): TCryptoLibByteArray; overload;

    /// <summary>
    /// Return the DER encoding of the object, null if the DER encoding can
    /// not be made.
    /// </summary>
    /// <returns>
    /// return a DER byte array, null otherwise.
    /// </returns>
    function GetDerEncoded(): TCryptoLibByteArray;

    function Equals(const other: IAsn1Convertible): Boolean; reintroduce;
    function GetHashCode(): {$IFDEF DELPHI}Int32; {$ELSE}PtrInt;
{$ENDIF DELPHI}override;

    function ToAsn1Object(): IAsn1Object; virtual; abstract;

  end;

implementation

{ TAsn1Encodable }

function TAsn1Encodable.Equals(const other: IAsn1Convertible): Boolean;
var
  o1, o2: IAsn1Object;
begin

  if (other = Self as IAsn1Convertible) then
  begin
    Result := true;
    Exit;
  end;

  if (other = Nil) then
  begin
    Result := false;
    Exit;
  end;
  o1 := ToAsn1Object();
  o2 := other.ToAsn1Object();

  Result := ((o1 = o2) or o1.CallAsn1Equals(o2));
end;

function TAsn1Encodable.GetDerEncoded: TCryptoLibByteArray;
begin

  try
    Result := GetEncoded(Der);
  except
    on e: EIOCryptoLibException do
    begin
      Result := Nil;
    end;
  end;
end;

function TAsn1Encodable.GetEncoded: TCryptoLibByteArray;
var
  bOut: TMemoryStream;
  aOut: TAsn1OutputStream;
begin

  bOut := TMemoryStream.Create();
  aOut := TAsn1OutputStream.Create(bOut);
  try
    aOut.WriteObject(Self as IAsn1Encodable);
    System.SetLength(Result, bOut.Size);
    bOut.Position := 0;
    bOut.Read(Result[0], System.Length(Result));

  finally
    bOut.Free;
    aOut.Free;
  end;

end;

function TAsn1Encodable.GetEncoded(const encoding: String): TCryptoLibByteArray;
var
  bOut: TMemoryStream;
  dOut: TDerOutputStream;
begin
  if (encoding = Der) then
  begin
    bOut := TMemoryStream.Create();
    dOut := TDerOutputStream.Create(bOut);
    try
      dOut.WriteObject(Self as IAsn1Encodable);
      System.SetLength(Result, bOut.Size);
      bOut.Position := 0;
      bOut.Read(Result[0], System.Length(Result));

    finally
      bOut.Free;
      dOut.Free;
    end;
    Exit;
  end;

  Result := GetEncoded();
end;

function TAsn1Encodable.GetHashCode: {$IFDEF DELPHI}Int32; {$ELSE}PtrInt;
{$ENDIF DELPHI}
begin
  Result := ToAsn1Object().CallAsn1GetHashCode();
end;

end.
