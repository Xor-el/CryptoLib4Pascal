{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                           Author - Ugochukwu Mmaduekwe                          * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ *                                                                                 * }
{ *                              Acknowledgements:                                  * }
{ *                                                                                 * }
{ *      Thanks to Sphere 10 Software (http://www.sphere10.com/) for sponsoring     * }
{ *                         the development of this library                         * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit ClpIX509CertificateEntry;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpIPkcs12Entry,
  ClpIX509Certificate;

type
  /// <summary>
  /// Interface for X509CertificateEntry (PKCS#12 certificate bag entry).
  /// </summary>
  IX509CertificateEntry = interface(IPkcs12Entry)
    ['{4B5C6D7E-8F9A-0B1C-2D3E-4F5A6B7C8D9E}']

    function GetCertificate: IX509Certificate;
    function Equals(const AOther: IX509CertificateEntry): Boolean;
    function GetHashCode: {$IFDEF DELPHI}Int32; {$ELSE}PtrInt; {$ENDIF DELPHI}

    property Certificate: IX509Certificate read GetCertificate;
  end;

implementation

end.
