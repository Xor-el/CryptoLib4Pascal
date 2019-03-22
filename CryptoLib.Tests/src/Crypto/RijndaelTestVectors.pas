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

unit RijndaelTestVectors;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  ClpCryptoLibTypes;

type

  TRijndaelTestVectors = class sealed(TObject)

  public
    class var

      FBlockCipherVectorBlockSizes, FBlockCipherVectorKeys,
      FBlockCipherVectorInputs, FBlockCipherVectorOutputs,
      FBlockCipherMonteCarloBlockSizes, FBlockCipherMonteCarloIterations,
      FBlockCipherMonteCarloKeys, FBlockCipherMonteCarloInputs,
      FBlockCipherMonteCarloOutputs: TCryptoLibStringArray;

    class constructor RijndaelTestVectors();

  end;

implementation

{ TAESTestVectors }

class constructor TRijndaelTestVectors.RijndaelTestVectors;
begin

  // Test vectors from the NIST standard tests and Brian Gladman's
  // vector set
  // http://fp.gladman.plus.com/cryptography_technology/rijndael

  FBlockCipherVectorBlockSizes := TCryptoLibStringArray.Create('128', '128',
    '160', '160', '192', '192', '224', '224', '256', '256');

  FBlockCipherVectorKeys := TCryptoLibStringArray.Create

    ('80000000000000000000000000000000', '00000000000000000000000000000080',
    '2B7E151628AED2A6ABF7158809CF4F3C',
    '2B7E151628AED2A6ABF7158809CF4F3C762E7160',
    '2B7E151628AED2A6ABF7158809CF4F3C',
    '2B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA5',
    '2B7E151628AED2A6ABF7158809CF4F3C',
    '2B7E151628AED2A6ABF7158809CF4F3C762E7160',
    '2B7E151628AED2A6ABF7158809CF4F3C',
    '2B7E151628AED2A6ABF7158809CF4F3C762E7160');

  FBlockCipherVectorInputs := TCryptoLibStringArray.Create
    ('00000000000000000000000000000000', '00000000000000000000000000000000',
    '3243F6A8885A308D313198A2E03707344A409382',
    '3243F6A8885A308D313198A2E03707344A409382',
    '3243F6A8885A308D313198A2E03707344A4093822299F31D',
    '3243F6A8885A308D313198A2E03707344A4093822299F31D',
    '3243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA9',
    '3243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA9',
    '3243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C8',
    '3243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C8');

  FBlockCipherVectorOutputs := TCryptoLibStringArray.Create
    ('0EDD33D3C621E546455BD8BA1418BEC8', '172AEAB3D507678ECAF455C12587ADB7',
    '16E73AEC921314C29DF905432BC8968AB64B1F51',
    '0553EB691670DD8A5A5B5ADDF1AA7450F7A0E587',
    'B24D275489E82BB8F7375E0D5FCDB1F481757C538B65148A',
    '725AE43B5F3161DE806A7C93E0BCA93C967EC1AE1B71E1CF',
    'B0A8F78F6B3C66213F792FFD2A61631F79331407A5E5C8D3793ACEB1',
    '08B99944EDFCE33A2ACB131183AB0168446B2D15E958480010F545E3',
    '7D15479076B69A46FFB3B3BEAE97AD8313F622F67FEDB487DE9F06B9ED9C8F19',
    '514F93FB296B5AD16AA7DF8B577ABCBD484DECACCCC7FB1F18DC567309CEEFFD');

  FBlockCipherMonteCarloBlockSizes := TCryptoLibStringArray.Create('128', '128',
    '128', '128');

  FBlockCipherMonteCarloIterations := TCryptoLibStringArray.Create('10000',
    '10000', '10000', '10000');

  FBlockCipherMonteCarloKeys := TCryptoLibStringArray.Create
    ('00000000000000000000000000000000', '5F060D3716B345C253F6749ABAC10917',
    'AAFE47EE82411A2BF3F6752AE8D7831138F041560631B114',
    '28E79E2AFC5F7745FCCABE2F6257C2EF4C4EDFB37324814ED4137C288711A386');

  FBlockCipherMonteCarloInputs := TCryptoLibStringArray.Create
    ('00000000000000000000000000000000', '355F697E8B868B65B25A04E18D782AFA',
    'F3F6752AE8D7831138F041560631B114', 'C737317FE0846F132B23C8C2A672CE22');

  FBlockCipherMonteCarloOutputs := TCryptoLibStringArray.Create
    ('C34C052CC0DA8D73451AFE5F03BE297F', 'ACC863637868E3E068D2FD6E3508454A',
    '77BA00ED5412DFF27C8ED91F3C376172', 'E58B82BFBA53C0040DC610C642121168');

end;

end.
