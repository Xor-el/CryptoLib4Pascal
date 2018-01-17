{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                    Copyright (c) 2018 Ugochukwu Mmaduekwe                       * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }

{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }

{ *                              Acknowledgements:                                  * }
{ *                                                                                 * }
{ *        Thanks to Sphere 10 Software (http://sphere10.com) for sponsoring        * }
{ *                        the development of this library                          * }

{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit ClpDerOctetString;

{$I ..\Include\CryptoLib.inc}

interface

uses
  ClpCryptoLibTypes,
  ClpAsn1Tags,
  ClpIProxiedInterface,
  ClpAsn1OctetString,
  ClpIDerOctetString;

type
  TDerOctetString = class(TAsn1OctetString, IDerOctetString)

  public
    /// <param name="str">The octets making up the octet string.</param>
    constructor Create(str: TCryptoLibByteArray); overload;
    constructor Create(obj: IAsn1Encodable); overload;

    destructor Destroy(); override;

    procedure Encode(derOut: IDerOutputStream); overload; override;
    class procedure Encode(derOut: IDerOutputStream; bytes: TCryptoLibByteArray;
      offset, length: Int32); reintroduce; overload; static; inline;

  end;

implementation

{ TDerOctetString }

constructor TDerOctetString.Create(str: TCryptoLibByteArray);
begin
  Inherited Create(str);
end;

constructor TDerOctetString.Create(obj: IAsn1Encodable);
begin
  Inherited Create(obj);
end;

destructor TDerOctetString.Destroy;
begin
  inherited Destroy;
end;

procedure TDerOctetString.Encode(derOut: IDerOutputStream);
begin
  derOut.WriteEncoded(TAsn1Tags.OctetString, str);
end;

class procedure TDerOctetString.Encode(derOut: IDerOutputStream;
  bytes: TCryptoLibByteArray; offset, length: Int32);
begin
  derOut.WriteEncoded(TAsn1Tags.OctetString, bytes, offset, length);
end;

end.
