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

unit ClpCheck;

{$I ..\Include\CryptoLib.inc}

interface

uses
  ClpCryptoLibTypes;

type
  TCheck = class sealed(TObject)

  public
    class procedure DataLength(ACondition: Boolean; const AMsg: String);
      overload; inline;
    class procedure DataLength(const ABuf: TCryptoLibByteArray; AOff, ALen: Int32;
      const AMsg: String); overload; inline;
    class procedure OutputLength(const ABuf: TCryptoLibByteArray;
      AOff, ALen: Int32; const AMsg: String); overload; inline;

  end;

implementation

{ TCheck }

class procedure TCheck.DataLength(ACondition: Boolean; const AMsg: String);
begin
  if ACondition then
  begin
    raise EDataLengthCryptoLibException.Create(AMsg);
  end;
end;

class procedure TCheck.DataLength(const ABuf: TCryptoLibByteArray;
  AOff, ALen: Int32; const AMsg: String);
begin
  if ((AOff + ALen) > System.Length(ABuf)) then
  begin
    raise EDataLengthCryptoLibException.Create(AMsg);
  end;
end;

class procedure TCheck.OutputLength(const ABuf: TCryptoLibByteArray;
  AOff, ALen: Int32; const AMsg: String);
begin
  if ((AOff + ALen) > System.Length(ABuf)) then
  begin
    raise EOutputLengthCryptoLibException.Create(AMsg);
  end;
end;

end.
