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

unit ClpISecAsn1Objects;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpBigInteger,
  ClpIAsn1Core,
  ClpIAsn1Objects;

type
  /// <summary>
  /// Interface for the elliptic curve private key object from SEC 1
  /// </summary>
  IECPrivateKeyStructure = interface(IAsn1Encodable)
    ['{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}']

    function GetVersion: IDerInteger;
    function GetPrivateKey: IAsn1OctetString;
    function GetParameters: IAsn1Encodable;
    function GetPublicKey: IDerBitString;
    function GetKey: TBigInteger;

    property Version: IDerInteger read GetVersion;
    property PrivateKey: IAsn1OctetString read GetPrivateKey;
    property Parameters: IAsn1Encodable read GetParameters;
    property PublicKey: IDerBitString read GetPublicKey;
  end;

implementation

end.
