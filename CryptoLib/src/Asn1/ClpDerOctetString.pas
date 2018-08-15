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

unit ClpDerOctetString;

{$I ..\Include\CryptoLib.inc}

interface

uses
  ClpCryptoLibTypes,
  ClpAsn1Tags,
  ClpDerOutputStream,
  ClpIProxiedInterface,
  ClpAsn1OctetString,
  ClpIDerOctetString;

type
  TDerOctetString = class(TAsn1OctetString, IDerOctetString)

  public
    /// <param name="str">The octets making up the octet string.</param>
    constructor Create(const str: TCryptoLibByteArray); overload;
    constructor Create(const obj: IAsn1Encodable); overload;

    destructor Destroy(); override;

    procedure Encode(const derOut: IDerOutputStream); overload; override;
    class procedure Encode(const derOut: TDerOutputStream;
      const bytes: TCryptoLibByteArray; offset, length: Int32); reintroduce;
      overload; static; inline;

  end;

implementation

{ TDerOctetString }

constructor TDerOctetString.Create(const str: TCryptoLibByteArray);
begin
  Inherited Create(str);
end;

constructor TDerOctetString.Create(const obj: IAsn1Encodable);
begin
  Inherited Create(obj);
end;

destructor TDerOctetString.Destroy;
begin
  inherited Destroy;
end;

procedure TDerOctetString.Encode(const derOut: IDerOutputStream);
begin
  derOut.WriteEncoded(TAsn1Tags.OctetString, str);
end;

class procedure TDerOctetString.Encode(const derOut: TDerOutputStream;
  const bytes: TCryptoLibByteArray; offset, length: Int32);
begin
  derOut.WriteEncoded(TAsn1Tags.OctetString, bytes, offset, length);
end;

end.
