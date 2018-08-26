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

unit ClpAsn1Object;

{$I ..\Include\CryptoLib.inc}

interface

uses
  Classes,
  SysUtils,
  ClpCryptoLibTypes,
  ClpIProxiedInterface,
  ClpAsn1Encodable;

resourcestring
  SExtraData = 'Extra Data Found After Object';
  SUnRecognizedObjectStream = 'Cannot Recognise Object in Stream';
  SUnRecognizedObjectByteArray = 'Cannot Recognise Object in ByteArray';

type

  TAsn1Object = class abstract(TAsn1Encodable, IAsn1Object)

  strict protected

    function Asn1Equals(const asn1Object: IAsn1Object): Boolean;
      virtual; abstract;

    function Asn1GetHashCode(): Int32; virtual; abstract;

  public
    /// <summary>Create a base ASN.1 object from a byte array.</summary>
    /// <param name="data">The byte array to parse.</param>
    /// <returns>The base ASN.1 object represented by the byte array.</returns>
    /// <exception cref="IOException">
    /// If there is a problem parsing the data, or parsing an object did not exhaust the available data.
    /// </exception>
    class function FromByteArray(const data: TCryptoLibByteArray)
      : IAsn1Object; static;

    /// <summary>Read a base ASN.1 object from a stream.</summary>
    /// <param name="inStr">The stream to parse.</param>
    /// <returns>The base ASN.1 object represented by the byte array.</returns>
    /// <exception cref="IOException">If there is a problem parsing the data.</exception>
    class function FromStream(inStr: TStream): IAsn1Object; static;

    function ToAsn1Object(): IAsn1Object; override;

    procedure Encode(const derOut: IDerOutputStream); virtual; abstract;

    function CallAsn1Equals(const obj: IAsn1Object): Boolean;

    function CallAsn1GetHashCode(): Int32;

  end;

implementation

uses
  // included here to avoid circular dependency :)
  ClpAsn1InputStream;

{ TAsn1Object }

function TAsn1Object.CallAsn1Equals(const obj: IAsn1Object): Boolean;
begin
  result := Asn1Equals(obj);
end;

function TAsn1Object.CallAsn1GetHashCode: Int32;
begin
  result := Asn1GetHashCode();
end;

class function TAsn1Object.FromByteArray(const data: TCryptoLibByteArray)
  : IAsn1Object;
var
  asn1: TAsn1InputStream;
  input: TBytesStream;
begin
  try
    // used TBytesStream here for one pass creation and population with byte array :)
    input := TBytesStream.Create(data);
    try

      asn1 := TAsn1InputStream.Create(input, System.Length(data));

      try
        result := asn1.ReadObject();
      finally
        asn1.Free;
      end;
      if (input.Position <> input.Size) then
      begin
        raise EIOCryptoLibException.CreateRes(@SExtraData);
      end;
    finally
      input.Free;
    end;
  except
    on e: EInvalidCastCryptoLibException do
    begin
      raise EIOCryptoLibException.CreateRes(@SUnRecognizedObjectByteArray);
    end;
  end;
end;

class function TAsn1Object.FromStream(inStr: TStream): IAsn1Object;
var
  asn1Stream: TAsn1InputStream;
begin
  asn1Stream := TAsn1InputStream.Create(inStr);
  try
    try
      result := asn1Stream.ReadObject();
    except
      on e: EInvalidCastCryptoLibException do
      begin
        raise EIOCryptoLibException.CreateRes(@SUnRecognizedObjectStream);
      end;
    end;
  finally
    asn1Stream.Free;
  end;
end;

function TAsn1Object.ToAsn1Object: IAsn1Object;
begin
  result := Self as IAsn1Object;
end;

end.
