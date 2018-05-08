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

unit ClpPCGRandomNumberGenerator;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpCryptoLibTypes,
  ClpPcgRandomMinimal,
  ClpIPCGRandomNumberGenerator,
  ClpRandomNumberGenerator;

type
  TPCGRandomNumberGenerator = class sealed(TRandomNumberGenerator,
    IPCGRandomNumberGenerator)

  public
    constructor Create();

    procedure GetBytes(data: TCryptoLibByteArray); override;

    procedure GetNonZeroBytes(data: TCryptoLibByteArray); override;

  end;

implementation

{ TPCGRandomNumberGenerator }

constructor TPCGRandomNumberGenerator.Create;
begin
  inherited Create();
end;

procedure TPCGRandomNumberGenerator.GetBytes(data: TCryptoLibByteArray);
var
  i: Int64;
begin
  i := System.Length(data);
  while i > 0 do
  begin
    data[i - 1] := Byte(TPcg.NextInt(System.Low(Int32), System.High(Int32)));
    System.Dec(i);
  end;

end;

procedure TPCGRandomNumberGenerator.GetNonZeroBytes(data: TCryptoLibByteArray);
var
  i: Int64;
  val: Byte;
begin
  i := System.Length(data);
  while i > 0 do
  begin
    repeat
      val := Byte(TPcg.NextUInt32(System.Low(UInt32), System.High(UInt32)));
    until (not(val = 0));

    data[i - 1] := val;
    System.Dec(i);
  end;

end;

end.
