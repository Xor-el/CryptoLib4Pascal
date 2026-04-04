{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                           Author - Ugochukwu Mmaduekwe                          * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }

{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }

{ *                              Acknowledgements:                                  * }
{ *                                                                                 * }
{ *      Thanks to Sphere 10 Software (http://www.sphere10.com/) for sponsoring     * }
{ *                           development of this library                           * }

{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit ClpICipherKeyGenerator;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpIKeyGenerationParameters,
  ClpIKeyParameter,
  ClpCryptoLibTypes;

type

  ICipherKeyGenerator = interface(IInterface)
    ['{084FE16F-7AEA-42C0-92BB-6CEC7923DE6F}']

    /// <summary>
    /// initialise the key generator.
    /// </summary>
    /// <param name="AParameters">
    /// the parameters to be used for key generation
    /// </param>
    procedure Init(const AParameters: IKeyGenerationParameters);

    /// <summary>
    /// Generate a secret key.
    /// </summary>
    /// <returns>
    /// a byte array containing the key value.
    /// </returns>
    function GenerateKey: TCryptoLibByteArray;

    /// <summary>
    /// Generate a secret key as a KeyParameter.
    /// </summary>
    function GenerateKeyParameter: IKeyParameter;

    function GetDefaultStrength: Int32;

    property DefaultStrength: Int32 read GetDefaultStrength;

  end;

implementation

end.
