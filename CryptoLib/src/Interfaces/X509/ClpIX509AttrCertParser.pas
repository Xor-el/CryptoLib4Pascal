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

unit ClpIX509AttrCertParser;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  Classes,
  ClpCryptoLibTypes,
  ClpIX509V2AttributeCertificate;

type
  /// <summary>
  /// Interface for X.509 Attribute Certificate parser.
  /// </summary>
  IX509AttrCertParser = interface(IInterface)
    ['{F5A6B7C8-D9E0-1234-5678-9ABCDEF01234}']

    function ReadAttrCert(const AInput: TCryptoLibByteArray): IX509V2AttributeCertificate; overload;
    function ReadAttrCerts(const AInput: TCryptoLibByteArray): TCryptoLibGenericArray<IX509V2AttributeCertificate>; overload;
    function ReadAttrCert(const AInStream: TStream): IX509V2AttributeCertificate; overload;
    function ReadAttrCerts(const AInStream: TStream): TCryptoLibGenericArray<IX509V2AttributeCertificate>; overload;
    function ParseAttrCerts(const AInStream: TStream): TCryptoLibGenericArray<IX509V2AttributeCertificate>;
  end;

implementation

end.
