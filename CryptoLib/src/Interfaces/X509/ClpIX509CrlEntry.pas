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

unit ClpIX509CrlEntry;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpIAsn1Objects,
  ClpIX509Asn1Objects,
  ClpCryptoLibTypes,
  ClpBigInteger;

type
  /// <summary>
  /// Interface for X.509 CRL entry (revoked certificate entry).
  /// </summary>
  IX509CrlEntry = interface(IInterface)
    ['{C2D3E4F5-A6B7-8901-CDEF-234567890123}']

    function GetCrlEntry: ICrlEntry;
    function GetCertificateIssuer: IX509Name;
    function GetEncoded: TCryptoLibByteArray;
    function GetSerialNumber: TBigInteger;
    function GetRevocationDate: TDateTime;
    function GetHasExtensions: Boolean;
    function GetExtensionValue(const AOid: IDerObjectIdentifier): IAsn1OctetString;
    function Equals(const AOther: IX509CrlEntry): Boolean;
    function GetHashCode: {$IFDEF DELPHI}Int32; {$ELSE}PtrInt; {$ENDIF DELPHI}
    function ToString: String;

    property CrlEntry: ICrlEntry read GetCrlEntry;
    property SerialNumber: TBigInteger read GetSerialNumber;
    property RevocationDate: TDateTime read GetRevocationDate;
    property HasExtensions: Boolean read GetHasExtensions;
  end;

implementation

end.
