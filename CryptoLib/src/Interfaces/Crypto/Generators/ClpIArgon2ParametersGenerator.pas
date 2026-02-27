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

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpIPbeParametersGenerator,
  ClpCryptoLibTypes;

type
{$SCOPEDENUMS ON}
  TCryptoLibArgon2Type = (Argon2D = $00, Argon2I = $01, Argon2ID = $02);
  TCryptoLibArgon2Version = (Argon2Version10 = $10, Argon2Version13 = $13);
  TCryptoLibArgon2MemoryCostType = (MemoryAsKB, MemoryPowOfTwo);
{$SCOPEDENUMS OFF}

type
  IArgon2ParametersGenerator = interface(IPbeParametersGenerator)

    ['{0AC3D3A8-9422-405F-B0EE-6B7AE0F64F74}']

    procedure Init(AArgon2Type: TCryptoLibArgon2Type;
      AArgon2Version: TCryptoLibArgon2Version; const APassword, ASalt, ASecret,
      AAdditional: TCryptoLibByteArray; AIterations, AMemory, AParallelism: Int32;
      AMemoryCostType: TCryptoLibArgon2MemoryCostType);

  end;

implementation

end.
