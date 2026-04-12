{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                           Author - Ugochukwu Mmaduekwe                          * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ *                                                                                 * }
{ *                              Acknowledgements:                                  * }
{ *                                                                                 * }
{ *      Thanks to Sphere 10 Software (http://www.sphere10.com/) for sponsoring     * }
{ *                         the development of this library                         * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit ClpInt16Utilities;

{$I ..\Include\CryptoLib.inc}

interface

uses
  ClpBitOperations;

type
  TInt16Utilities = class sealed(TObject)
  public
    const
      NumBits: Int32 = 16;
      NumBytes: Int32 = 2;

    class function ReverseBytes(AValue: Int16): Int16; overload; static;
    class function ReverseBytes(AValue: UInt16): UInt16; overload; static;

    class function RotateLeft(AValue: Int16; ADistance: Int32): Int16; overload; static;
    class function RotateLeft(AValue: UInt16; ADistance: Int32): UInt16; overload; static;

    class function RotateRight(AValue: Int16; ADistance: Int32): Int16; overload; static;
    class function RotateRight(AValue: UInt16; ADistance: Int32): UInt16; overload; static;
  end;

implementation

{ TInt16Utilities }

class function TInt16Utilities.ReverseBytes(AValue: Int16): Int16;
begin
  Result := Int16(TBitOperations.ReverseBytesUInt16(UInt16(AValue)));
end;

class function TInt16Utilities.ReverseBytes(AValue: UInt16): UInt16;
begin
  Result := TBitOperations.ReverseBytesUInt16(AValue);
end;

class function TInt16Utilities.RotateLeft(AValue: Int16; ADistance: Int32): Int16;
begin
  Result := Int16(RotateLeft(UInt16(AValue), ADistance));
end;

class function TInt16Utilities.RotateLeft(AValue: UInt16; ADistance: Int32): UInt16;
begin
  Result := TBitOperations.RotateLeft16(AValue, ADistance);
end;

class function TInt16Utilities.RotateRight(AValue: Int16; ADistance: Int32): Int16;
begin
  Result := Int16(RotateRight(UInt16(AValue), ADistance));
end;

class function TInt16Utilities.RotateRight(AValue: UInt16; ADistance: Int32): UInt16;
begin
  Result := TBitOperations.RotateRight16(AValue, ADistance);
end;

end.
