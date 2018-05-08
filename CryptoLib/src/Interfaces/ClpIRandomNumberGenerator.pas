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

unit ClpIRandomNumberGenerator;

{$I ..\Include\CryptoLib.inc}

interface

uses
  ClpCryptoLibTypes;

type
  IRandomNumberGenerator = interface(IInterface)
    ['{48F39DBB-8BE4-4167-8CE9-265F9B3B785E}']

    procedure GetBytes(data: TCryptoLibByteArray);

    procedure GetNonZeroBytes(data: TCryptoLibByteArray);

  end;

implementation

end.
