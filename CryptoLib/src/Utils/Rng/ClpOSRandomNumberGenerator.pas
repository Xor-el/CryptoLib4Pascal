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

unit ClpOSRandomNumberGenerator;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpCryptoLibTypes,
  ClpOSRandom,
  ClpIOSRandomNumberGenerator,
  ClpRandomNumberGenerator;

type
  TOSRandomNumberGenerator = class sealed(TRandomNumberGenerator,
    IOSRandomNumberGenerator)

  public
    constructor Create();

    procedure GetBytes(data: TCryptoLibByteArray); override;

    procedure GetNonZeroBytes(data: TCryptoLibByteArray); override;

  end;

implementation

{ TOSRandomNumberGenerator }

constructor TOSRandomNumberGenerator.Create;
begin
  inherited Create();
end;

procedure TOSRandomNumberGenerator.GetBytes(data: TCryptoLibByteArray);
begin
  TOSRandom.GetBytes(data);
end;

procedure TOSRandomNumberGenerator.GetNonZeroBytes(data: TCryptoLibByteArray);
begin
  TOSRandom.GetNonZeroBytes(data);
end;

end.
