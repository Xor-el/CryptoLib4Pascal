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

unit AESTestVectors;

interface

uses
  ClpCryptoLibTypes;

type

  TAESTestVectors = class sealed(TObject)

  public
    class var

      FBlockCipherVectorKeys, FBlockCipherVectorInputs,
      FBlockCipherVectorOutputs, FOfficialVectorKeys__AES256_CBC,
      FOfficialVectorIVs_AES256_CBC, FOfficialVectorInputs_AES256_CBC,
      FOfficialVectorOutputs_AES256_CBC: TCryptoLibStringArray;

    class constructor AESTestVectors();

  end;

implementation

{ TAESTestVectors }

class constructor TAESTestVectors.AESTestVectors;
begin

  // Test vectors from the NIST standard tests and Brian Gladman's
  // vector set
  // http://fp.gladman.plus.com/cryptography_technology/rijndael
  FBlockCipherVectorKeys := TCryptoLibStringArray.Create

    (
    // keylength 128 bits
    '80000000000000000000000000000000', '00000000000000000000000000000080',
    // keylength 192 bits
    '000000000000000000000000000000000000000000000000',
    // keylength 256 bits
    '0000000000000000000000000000000000000000000000000000000000000000');

  FBlockCipherVectorInputs := TCryptoLibStringArray.Create
    ('00000000000000000000000000000000', '00000000000000000000000000000000',

    '80000000000000000000000000000000',

    '80000000000000000000000000000000');

  FBlockCipherVectorOutputs := TCryptoLibStringArray.Create
    ('0EDD33D3C621E546455BD8BA1418BEC8', '172AEAB3D507678ECAF455C12587ADB7',

    '6CD02513E8D4DC986B4AFE087A60BD0C',

    'DDC6BF790C15760D8D9AEB6F9A75FD4E');

  // http://csrc.nist.gov/groups/STM/cavp/documents/aes/KAT_AES.zip
  FOfficialVectorKeys__AES256_CBC := TCryptoLibStringArray.Create
    ('C47B0294DBBBEE0FEC4757F22FFEEE3587CA4730C3D33B691DF38BAB076BC558',
    '28D46CFFA158533194214A91E712FC2B45B518076675AFFD910EDECA5F41AC64');

  FOfficialVectorIVs_AES256_CBC := TCryptoLibStringArray.Create
    ('00000000000000000000000000000000', '00000000000000000000000000000000');

  FOfficialVectorInputs_AES256_CBC := TCryptoLibStringArray.Create
    ('00000000000000000000000000000000', '00000000000000000000000000000000');

  FOfficialVectorOutputs_AES256_CBC := TCryptoLibStringArray.Create
    ('46F2FB342D6F0AB477476FC501242C5F', '4BF3B0A69AEB6657794F2901B1440AD4');
end;

end.
