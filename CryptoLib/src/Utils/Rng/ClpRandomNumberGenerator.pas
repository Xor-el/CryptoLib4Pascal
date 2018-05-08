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

unit ClpRandomNumberGenerator;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpCryptoLibTypes,
  ClpIRandomNumberGenerator;

resourcestring
  SUnknownAlgorithm = 'Unknown Random Generation Algorithm Requested';

type
  TRandomNumberGenerator = class abstract(TInterfacedObject,
    IRandomNumberGenerator)

  public
    class function CreateRNG(): IRandomNumberGenerator; overload; static;

    class function CreateRNG(const rngName: String): IRandomNumberGenerator;
      overload; static;

    procedure GetBytes(data: TCryptoLibByteArray); virtual; abstract;

    procedure GetNonZeroBytes(data: TCryptoLibByteArray); virtual; abstract;

  end;

implementation

uses
  // included here to avoid circular dependency :)
  ClpPCGRandomNumberGenerator,
  ClpOSRandomNumberGenerator;

{ TRandomNumberGenerator }

class function TRandomNumberGenerator.CreateRNG: IRandomNumberGenerator;
begin
  result := TOSRandomNumberGenerator.Create();
end;

class function TRandomNumberGenerator.CreateRNG(const rngName: String)
  : IRandomNumberGenerator;
begin
  if CompareText(rngName, 'OSRandomNumberGenerator') = 0 then
  begin
    result := TOSRandomNumberGenerator.Create();
  end
  else if CompareText(rngName, 'PCGRandomNumberGenerator') = 0 then
  begin
    result := TPCGRandomNumberGenerator.Create();
  end
  else
  begin
    raise EArgumentCryptoLibException.CreateRes(@SUnknownAlgorithm);
  end;

end;

end.
