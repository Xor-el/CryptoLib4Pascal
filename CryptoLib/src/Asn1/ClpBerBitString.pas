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

unit ClpBerBitString;

{$I ..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpCryptoLibTypes,
  ClpIProxiedInterface,
  ClpDerBitString,
  ClpIBerBitString,
  ClpIAsn1OutputStream,
  ClpIBerOutputStream,
  ClpAsn1Tags;

type
  TBerBitString = class(TDerBitString, IBerBitString)

  public
    constructor Create(data: TCryptoLibByteArray; padBits: Int32); overload;
    constructor Create(data: TCryptoLibByteArray); overload;
    constructor Create(namedBits: Int32); overload;
    constructor Create(obj: IAsn1Encodable); overload;

    procedure Encode(derOut: IDerOutputStream); override;

  end;

implementation

{ TBerBitString }

constructor TBerBitString.Create(data: TCryptoLibByteArray);
begin
  Inherited Create(data);
end;

constructor TBerBitString.Create(data: TCryptoLibByteArray; padBits: Int32);
begin
  Inherited Create(data, padBits);
end;

constructor TBerBitString.Create(obj: IAsn1Encodable);
begin
  Inherited Create(obj);
end;

constructor TBerBitString.Create(namedBits: Int32);
begin
  Inherited Create(namedBits);
end;

procedure TBerBitString.Encode(derOut: IDerOutputStream);
begin
  if ((Supports(derOut, IAsn1OutputStream)) or
    (Supports(derOut, IBerOutputStream))) then
  begin
    derOut.WriteEncoded(TAsn1Tags.BitString, Byte(mPadBits), mData);
  end
  else
  begin
    Inherited Encode(derOut);
  end;
end;

end.
