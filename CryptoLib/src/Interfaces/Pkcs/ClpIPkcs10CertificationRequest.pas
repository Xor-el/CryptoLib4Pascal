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

unit ClpIPkcs10CertificationRequest;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpIPkcsAsn1Objects,
  ClpIX509Asn1Objects,
  ClpIAsymmetricKeyParameter,
  ClpIVerifierFactoryProvider,
  ClpIVerifierFactory;

type
  /// <summary>
  /// Interface for Pkcs10CertificationRequest (PKCS#10 CSR with verify/get public key/extensions).
  /// </summary>
  IPkcs10CertificationRequest = interface(ICertificationRequest)
    ['{D4E5F6A7-B8C9-0123-DEF0-123456789ABC}']

    function GetPublicKey: IAsymmetricKeyParameter;
    function GetRequestedExtensions: IX509Extensions;
    function Verify: Boolean; overload;
    function Verify(const APublicKey: IAsymmetricKeyParameter): Boolean; overload;
    function Verify(const AVerifierProvider: IVerifierFactoryProvider): Boolean; overload;
    function Verify(const AVerifier: IVerifierFactory): Boolean; overload;

    property RequestedExtensions: IX509Extensions read GetRequestedExtensions;
  end;

implementation

end.
