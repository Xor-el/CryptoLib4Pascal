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

unit ClpX9IntegerConverter;

interface

uses
  ClpIECInterface,
  ClpIECFieldElement,
  ClpCryptoLibTypes,
  ClpBigInteger;

type
  TX9IntegerConverter = class sealed(TObject)

  public

    class function GetByteLength(const fe: IECFieldElement): Int32; overload;
      static; inline;
    class function GetByteLength(const c: IECCurve): Int32; overload;
      static; inline;

    class function IntegerToBytes(const s: TBigInteger; qLength: Int32)
      : TCryptoLibByteArray; static;

  end;

implementation

{ TX9IntegerConverter }

class function TX9IntegerConverter.GetByteLength
  (const fe: IECFieldElement): Int32;
begin
  result := (fe.FieldSize + 7) div 8;
end;

class function TX9IntegerConverter.GetByteLength(const c: IECCurve): Int32;
begin
  result := (c.FieldSize + 7) div 8;
end;

class function TX9IntegerConverter.IntegerToBytes(const s: TBigInteger;
  qLength: Int32): TCryptoLibByteArray;
var
  bytes, tmp: TCryptoLibByteArray;
begin
  bytes := s.ToByteArrayUnsigned();

  if (qLength < System.Length(bytes)) then
  begin
    System.SetLength(tmp, qLength);
    System.Move(bytes[System.Length(bytes) - System.Length(tmp)], tmp[0],
      System.Length(tmp) * System.SizeOf(Byte));
    result := tmp;
    Exit;
  end;
  if (qLength > System.Length(bytes)) then
  begin
    System.SetLength(tmp, qLength);
    System.Move(bytes[0], tmp[System.Length(tmp) - System.Length(bytes)],
      System.Length(bytes) * System.SizeOf(Byte));
    result := tmp;
    Exit;
  end;

  result := bytes;
end;

end.
