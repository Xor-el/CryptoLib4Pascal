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

unit ClpIIesCipherParameters;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpICipherParameters,
  ClpIIESParameters;

type
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

implementation

end.
