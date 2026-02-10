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

unit ClpEncoders;

{$I ..\Include\CryptoLib.inc}

interface

uses
  SbpBase16,
  SbpBase58,
  SbpBase64,
  ClpCryptoLibTypes;

type
  TBase58Encoder = class sealed(TObject)

  public
    class function Encode(const AInput: TCryptoLibByteArray): String; static;
    class function Decode(const AInput: String): TCryptoLibByteArray; static;
  end;

type
  TBase64Encoder = class sealed(TObject)

  public
    class function Encode(const AInput: TCryptoLibByteArray): String; static;
    class function Decode(const AInput: String): TCryptoLibByteArray; static;
  end;

type
  THexEncoder = class sealed(TObject)

  public
    class function Decode(const AInput: String): TCryptoLibByteArray; static;
    class function Encode(const AInput: TCryptoLibByteArray; AUpperCase: Boolean = True): String; static;
  end;

implementation

{ TBase58 }

class function TBase58Encoder.Decode(const AInput: String): TCryptoLibByteArray;
begin
  Result := TBase58.BitCoin.Decode(AInput);
end;

class function TBase58Encoder.Encode(const AInput: TCryptoLibByteArray): String;
begin
  Result := TBase58.BitCoin.Encode(AInput);
end;

{ TBase64 }

class function TBase64Encoder.Decode(const AInput: String): TCryptoLibByteArray;
begin
  Result := TBase64.Default.Decode(AInput);
end;

class function TBase64Encoder.Encode(const AInput: TCryptoLibByteArray): String;
begin
  Result := TBase64.Default.Encode(AInput);
end;

{ THex }

class function THexEncoder.Decode(const AInput: String): TCryptoLibByteArray;
begin
  Result := TBase16.Decode(AInput);
end;

class function THexEncoder.Encode(const AInput: TCryptoLibByteArray; AUpperCase: Boolean): String;
begin
  case AUpperCase of
    True:
      Result := TBase16.EncodeUpper(AInput);
    False:
      Result := TBase16.EncodeLower(AInput);
  end;
end;

end.
