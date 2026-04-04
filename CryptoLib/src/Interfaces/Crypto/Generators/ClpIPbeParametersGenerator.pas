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

unit ClpIPbeParametersGenerator;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpICipherParameters,
  ClpCryptoLibTypes;

type
  IPbeParametersGenerator = interface(IInterface)

    ['{8C530FB2-6B8F-4E22-8EA0-D538665471EF}']

    procedure Clear();

    procedure Init(const APassword, ASalt: TCryptoLibByteArray; AIterationCount: Int32);

    function GetPassword: TCryptoLibByteArray;
    function GetSalt: TCryptoLibByteArray;
    function GetIterationCount: Int32;

    property Password: TCryptoLibByteArray read GetPassword;
    property Salt: TCryptoLibByteArray read GetSalt;
    property IterationCount: Int32 read GetIterationCount;

    /// <summary>
    /// Generate derived parameters for a key of length keySize.
    /// </summary>
    /// <param name="AAlgorithm">
    /// a parameters object representing a key.
    /// </param>
    /// <param name="AKeySize">
    /// the length, in bits, of the key required.
    /// </param>
    /// <returns>
    /// a parameters object representing a key.
    /// </returns>
    function GenerateDerivedParameters(const AAlgorithm: String; AKeySize: Int32)
      : ICipherParameters; overload;

    /// <summary>
    /// Generate derived parameters for a key of length keySize and iv
    /// of length ivSize.
    /// </summary>
    /// <param name="AAlgorithm">
    /// a parameters object representing a key.
    /// </param>
    /// <param name="AKeySize">
    /// the length, in bits, of the key required.
    /// </param>
    /// <param name="AIvSize">
    /// the length, in bits, of the iv required.
    /// </param>
    /// <returns>
    /// a parameters object representing a key and an iv.
    /// </returns>
    function GenerateDerivedParameters(const AAlgorithm: String;
      AKeySize, AIvSize: Int32): ICipherParameters; overload;

    /// <summary>
    /// Generate derived parameters for a key of length keySize,
    /// specifically <br />for use with a MAC.
    /// </summary>
    /// <param name="AKeySize">
    /// the length, in bits, of the key required.
    /// </param>
    /// <returns>
    /// a parameters object representing a key.
    /// </returns>
    function GenerateDerivedMacParameters(AKeySize: Int32): ICipherParameters;

  end;

implementation

end.
