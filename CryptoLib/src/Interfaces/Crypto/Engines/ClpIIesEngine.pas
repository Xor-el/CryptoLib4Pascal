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

unit ClpIIesEngine;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpIMac,
  ClpIBufferedBlockCipher,
  ClpICipherParameters,
  ClpIAsymmetricKeyParameter,
  ClpIEphemeralKeyPairGenerator,
  ClpIKeyParser,
  ClpCryptoLibTypes;

type

  IIesEngine = interface(IInterface)
    ['{9FA0E287-9988-467D-9E00-3BECEE4A78C6}']

    function GetCipher: IBufferedBlockCipher;
    function GetMac: IMac;

    /// <summary>
    /// Initialise the encryptor/decryptor.
    /// </summary>
    /// <param name="AForEncryption">
    /// whether or not this is encryption/decryption.
    /// </param>
    /// <param name="APrivParam">
    /// our private key parameters
    /// </param>
    /// <param name="APubParam">
    /// the recipient's/sender's public key parameters
    /// </param>
    /// <param name="AParams">
    /// encoding and derivation parameters, may be wrapped to include an IV
    /// for an underlying block cipher.
    /// </param>
    procedure Init(AForEncryption: Boolean; const APrivParam, APubParam,
      AParams: ICipherParameters); overload;

    /// <summary>
    /// Initialise the encryptor.
    /// </summary>
    /// <param name="APublicKey">
    /// the recipient's/sender's public key parameters
    /// </param>
    /// <param name="AParams">
    /// encoding and derivation parameters, may be wrapped to include an IV
    /// for an underlying block cipher.
    /// </param>
    /// <param name="AEphemeralKeyPairGenerator">
    /// the ephemeral key pair generator to use.
    /// </param>
    procedure Init(const APublicKey: IAsymmetricKeyParameter;
      const AParams: ICipherParameters;
      const AEphemeralKeyPairGenerator: IEphemeralKeyPairGenerator); overload;

    /// <summary>
    /// Initialise the decryptor.
    /// </summary>
    /// <param name="APrivateKey">
    /// the recipient's private key.
    /// </param>
    /// <param name="AParams">
    /// encoding and derivation parameters, may be wrapped to include an IV
    /// for an underlying block cipher.
    /// </param>
    /// <param name="APublicKeyParser">
    /// the parser for reading the ephemeral public key.
    /// </param>
    procedure Init(const APrivateKey: IAsymmetricKeyParameter;
      const AParams: ICipherParameters;
      const APublicKeyParser: IKeyParser); overload;

    function ProcessBlock(const AIn: TCryptoLibByteArray; AInOff, AInLen: Int32)
      : TCryptoLibByteArray;

    property Cipher: IBufferedBlockCipher read GetCipher;
    property Mac: IMac read GetMac;
  end;

implementation

end.
