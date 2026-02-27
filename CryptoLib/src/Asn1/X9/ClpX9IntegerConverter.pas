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

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpBigInteger,
  ClpIECCommon,
  ClpIECFieldElement,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// Integer converter for X9.62 encoding.
  /// </summary>
  TX9IntegerConverter = class sealed(TObject)

  public
    /// <summary>
    /// Get the byte length for a field element.
    /// </summary>
    class function GetByteLength(const AFe: IECFieldElement): Int32; overload; static;
    /// <summary>
    /// Get the byte length for a curve.
    /// </summary>
    class function GetByteLength(const AC: IECCurve): Int32; overload; static;
    /// <summary>
    /// Convert an integer to bytes of the specified length.
    /// </summary>
    class function IntegerToBytes(const &AS: TBigInteger; AQLength: Int32): TCryptoLibByteArray; static;

  end;

implementation

{ TX9IntegerConverter }

class function TX9IntegerConverter.GetByteLength(const AFe: IECFieldElement): Int32;
begin
  Result := AFe.GetEncodedLength();
end;

class function TX9IntegerConverter.GetByteLength(const AC: IECCurve): Int32;
begin
  Result := AC.GetFieldElementEncodingLength();
end;

class function TX9IntegerConverter.IntegerToBytes(const &AS: TBigInteger; AQLength: Int32): TCryptoLibByteArray;
var
  LBytes, LTmp: TCryptoLibByteArray;
begin
  LBytes := &AS.ToByteArrayUnsigned();

  if AQLength < System.Length(LBytes) then
  begin
    System.SetLength(LTmp, AQLength);
    System.Move(LBytes[System.Length(LBytes) - System.Length(LTmp)], LTmp[0],
      System.Length(LTmp) * System.SizeOf(Byte));
    Result := LTmp;
    Exit;
  end;

  if AQLength > System.Length(LBytes) then
  begin
    System.SetLength(LTmp, AQLength);
    System.Move(LBytes[0], LTmp[System.Length(LTmp) - System.Length(LBytes)],
      System.Length(LBytes) * System.SizeOf(Byte));
    Result := LTmp;
    Exit;
  end;

  Result := LBytes;
end;

end.
