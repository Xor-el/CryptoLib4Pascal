{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                    Copyright (c) 2018 Ugochukwu Mmaduekwe                       * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }

{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }

{ *                              Acknowledgements:                                  * }
{ *                                                                                 * }
{ *        Thanks to Sphere 10 Software (http://sphere10.com) for sponsoring        * }
{ *                        the development of this library                          * }

{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit ClpIECSchnorrSigner;

{$I ..\Include\CryptoLib.inc}

interface

uses
  ClpICipherParameters,
  ClpIECPrivateKeyParameters,
  ClpBigInteger,
  ClpCryptoLibTypes;

type
  IECSchnorrSigner = interface(IInterface)
    ['{A941F9C5-81BE-4F0D-9294-2488C21035E3}']

    function GetAlgorithmName: String;
    property AlgorithmName: String read GetAlgorithmName;

    procedure Init(forSigning: Boolean; const parameters: ICipherParameters);

    /// <summary>
    /// update the internal digest with the byte b
    /// </summary>
    procedure Update(input: Byte);

    /// <summary>
    /// update the internal digest with the byte array in
    /// </summary>
    procedure BlockUpdate(input: TCryptoLibByteArray; inOff, length: Int32);

    /// <summary>
    /// Generate a signature for the message we've been loaded with using the
    /// key we were initialised with.
    /// </summary>
    function GenerateSignature(): TCryptoLibByteArray;

    /// <returns>
    /// true if the internal state represents the signature described in the
    /// passed in array.
    /// </returns>
    function VerifySignature(signature: TCryptoLibByteArray): Boolean;

    /// <summary>
    /// Reset the internal state
    /// </summary>
    procedure Reset();

    /// <summary>
    /// <para>
    /// Warning...
    /// </para>
    /// <para>
    /// do not use this method, it was exposed solely for testing
    /// purposes.
    /// </para>
    /// </summary>
    /// <param name="pv_key">
    /// private key
    /// </param>
    /// <param name="k">
    /// known random number
    /// </param>
    function Sign_K(const pv_key: IECPrivateKeyParameters;  const k: TBigInteger)
      : TCryptoLibByteArray;

  end;

implementation

end.
