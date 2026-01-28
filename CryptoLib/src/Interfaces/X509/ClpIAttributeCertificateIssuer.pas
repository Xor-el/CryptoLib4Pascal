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

unit ClpIAttributeCertificateIssuer;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpIAsn1Core,
  ClpIAsn1Objects,
  ClpIX509Asn1Objects,
  ClpIX509Certificate,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// Carrying class for an attribute certificate issuer.
  /// </summary>
  IAttributeCertificateIssuer = interface
    ['{D3E4F5A6-B7C8-9012-DEF0-3456789ABCDE}']

    function GetForm: IAsn1Encodable;
    function GetAttCertIssuer: IAttCertIssuer;
    function GetPrincipals: TCryptoLibGenericArray<IX509Name>;
    function Clone: IAttributeCertificateIssuer;
    function Match(const AX509Cert: IX509Certificate): Boolean;
    function Equals(const AOther: IAttributeCertificateIssuer): Boolean;

    property Form: IAsn1Encodable read GetForm;
  end;

implementation

end.

