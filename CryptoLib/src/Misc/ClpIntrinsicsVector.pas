{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                           Author - Ugochukwu Mmaduekwe                          * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }

{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }

{ *                              Acknowledgements:                                  * }
{ *                                                                                 * }
{ *      Thanks to Sphere 10 Software (http://www.sphere10.com/) for sponsoring     * }
{ *                           development of this library                           * }

{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit ClpIntrinsicsVector;

{$I ..\Include\CryptoLib.inc}

interface

type
  /// Vector64/128/256 byte sizes.
  TIntrinsicsVector64Bytes = packed array[0..7] of Byte;
  TIntrinsicsVector128Bytes = packed array[0..15] of Byte;
  TIntrinsicsVector256Bytes = packed array[0..31] of Byte;

  TIntrinsicsVector = class sealed(TObject)
  public
    class function IsPacked: Boolean; static;
  end;

implementation

{ TIntrinsicsVector }

class function TIntrinsicsVector.IsPacked: Boolean;
begin
  Result := (SizeOf(TIntrinsicsVector64Bytes) = 8) and
    (SizeOf(TIntrinsicsVector128Bytes) = 16) and
    (SizeOf(TIntrinsicsVector256Bytes) = 32);
end;

end.
