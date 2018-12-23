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

unit BlowfishTestVectors;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  ClpCryptoLibTypes;

type
  /// <remarks>Blowfish tester - vectors from http://www.counterpane.com/vectors.txt</remarks>
  TBlowfishTestVectors = class sealed(TObject)

  public
    class var

      FBlockCipherVectorKeys, FBlockCipherVectorInputs,
      FBlockCipherVectorOutputs: TCryptoLibStringArray;

    class constructor BlowfishTestVectors();

  end;

implementation

{ TBlowfishTestVectors }

class constructor TBlowfishTestVectors.BlowfishTestVectors;
begin

  /// <remarks>Blowfish tester - vectors from http://www.counterpane.com/vectors.txt</remarks>
  FBlockCipherVectorKeys := TCryptoLibStringArray.Create

    (

    '0000000000000000', 'FFFFFFFFFFFFFFFF',

    '3000000000000000',

    '1111111111111111', '0123456789ABCDEF', 'FEDCBA9876543210',
    '7CA110454A1A6E57', '0131D9619DC1376E');

  FBlockCipherVectorInputs := TCryptoLibStringArray.Create('0000000000000000',
    'FFFFFFFFFFFFFFFF',

    '1000000000000001',

    '1111111111111111', '1111111111111111', '0123456789ABCDEF',
    '01A1D6D039776742', '5CD54CA83DEF57DA');

  FBlockCipherVectorOutputs := TCryptoLibStringArray.Create('4EF997456198DD78',
    '51866FD5B85ECB8A',

    '7D856F9A613063F2',

    '2466DD878B963C9D', '61F9C3802281B096', '0ACEAB0FC6A0A28D',
    '59C68245EB05282B', 'B1B8CC0B250F09A0');

end;

end.
