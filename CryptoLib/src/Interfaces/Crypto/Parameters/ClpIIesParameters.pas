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

unit ClpIIesParameters;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpICipherParameters,
  ClpCryptoLibTypes;

type

  IIesParameters = interface(ICipherParameters)
    ['{F95232BB-594C-492E-AF63-C5A6822C96FD}']

    function GetDerivationV: TCryptoLibByteArray;

    /// <summary>
    /// Return the derivation vector.
    /// </summary>
    /// <value>
    /// the derivation vector.
    /// </value>
    property DerivationV: TCryptoLibByteArray read GetDerivationV;

    function GetEncodingV: TCryptoLibByteArray;

    /// <summary>
    /// Return the encoding vector.
    /// </summary>
    /// <value>
    /// the encoding vector.
    /// </value>
    property EncodingV: TCryptoLibByteArray read GetEncodingV;

    function GetMacKeySize: Int32;

    /// <summary>
    /// Return the key size in bits for the MAC used with the message
    /// </summary>
    /// <value>
    /// the key size in bits for the MAC used with the message
    /// </value>
    property MacKeySize: Int32 read GetMacKeySize;

  end;

  /// <summary>
  /// Parameters for BufferedIesCipher Init: bundles private key, public key,
  /// and IES parameters for engine.Init(forEncryption, priv, pub, iesParams).
  /// </summary>
  IIesCipherParameters = interface(ICipherParameters)
    ['{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}']

    function GetPrivateKey: ICipherParameters;
    function GetPublicKey: ICipherParameters;
    function GetIesParameters: IIesParameters;

    property PrivateKey: ICipherParameters read GetPrivateKey;
    property PublicKey: ICipherParameters read GetPublicKey;
    property IesParameters: IIesParameters read GetIesParameters;
  end;

  IIesWithCipherParameters = interface(IIesParameters)
    ['{77F38EA8-08F2-4D0D-A8E9-F3796DCCCA54}']

    function GetCipherKeySize: Int32;

    /// <summary>
    /// Return the key size in bits for the block cipher used with the message
    /// </summary>
    property CipherKeySize: Int32 read GetCipherKeySize;
  end;

implementation

end.
