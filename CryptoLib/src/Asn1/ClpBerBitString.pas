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

unit ClpBerBitString;

{$I ..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpCryptoLibTypes,
  ClpAsn1OutputStream,
  ClpBerOutputStream,
  ClpIProxiedInterface,
  ClpDerBitString,
  ClpIBerBitString,
  ClpAsn1Tags;

type
  TBerBitString = class(TDerBitString, IBerBitString)

  public
    constructor Create(const data: TCryptoLibByteArray;
      padBits: Int32); overload;
    constructor Create(const data: TCryptoLibByteArray); overload;
    constructor Create(namedBits: Int32); overload;
    constructor Create(const obj: IAsn1Encodable); overload;

    procedure Encode(const derOut: IDerOutputStream); override;

  end;

implementation

{ TBerBitString }

constructor TBerBitString.Create(const data: TCryptoLibByteArray);
begin
  Inherited Create(data);
end;

constructor TBerBitString.Create(const data: TCryptoLibByteArray;
  padBits: Int32);
begin
  Inherited Create(data, padBits);
end;

constructor TBerBitString.Create(const obj: IAsn1Encodable);
begin
  Inherited Create(obj);
end;

constructor TBerBitString.Create(namedBits: Int32);
begin
  Inherited Create(namedBits);
end;

procedure TBerBitString.Encode(const derOut: IDerOutputStream);
begin
  if ((derOut is TAsn1OutputStream) or (derOut is TBerOutputStream)) then
  begin
    derOut.WriteEncoded(TAsn1Tags.BitString, Byte(mPadBits), mData);
  end
  else
  begin
    Inherited Encode(derOut);
  end;
end;

end.
