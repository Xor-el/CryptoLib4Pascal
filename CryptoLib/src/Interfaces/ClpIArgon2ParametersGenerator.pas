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

unit ClpIArgon2ParametersGenerator;

{$I ..\Include\CryptoLib.inc}

interface

uses
  HlpArgon2TypeAndVersion,
  ClpIPbeParametersGenerator,
  ClpCryptoLibTypes;

type
{$SCOPEDENUMS ON}
  TArgon2Type = HlpArgon2TypeAndVersion.TArgon2Type;
  TArgon2Version = HlpArgon2TypeAndVersion.TArgon2Version;
  TArgon2MemoryCostType = (a2mctMemoryAsKB, a2mctMemoryPowOfTwo);
{$SCOPEDENUMS OFF}

type
  IArgon2ParametersGenerator = interface(IPbeParametersGenerator)

    ['{0AC3D3A8-9422-405F-B0EE-6B7AE0F64F74}']

    procedure Init(argon2Type: TArgon2Type; argon2Version: TArgon2Version;
      const password, salt, secret, additional: TCryptoLibByteArray;
      iterations, memory, parallelism: Int32;
      memoryCostType: TArgon2MemoryCostType);

  end;

implementation

end.
