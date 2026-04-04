{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                           Author - Ugochukwu Mmaduekwe                          * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }

{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }

{ *                              Acknowledgements:                                  * }
{ *                                                                                 * }
{ *      Thanks to Sphere 10 Software (http://www.sphere10.com/) for sponsoring     * }
{ *                           development of this library                           * }

{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit ClpIX509CertificatePair;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpIX509Certificate,
  ClpIX509Asn1Objects,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// Interface for X509CertificatePair (cross certificate pair, RFC 2587).
  /// Forward = certificate from the other CA to this CA; Reverse = certificate from this CA to the other CA.
  /// </summary>
  IX509CertificatePair = interface(IInterface)
    ['{A7B8C9D0-E1F2-4356-7890-ABCDEF123456}']

    function GetForward: IX509Certificate;
    function GetReverse: IX509Certificate;
    function GetCertificatePair: ICertificatePair;
    function GetEncoded: TCryptoLibByteArray;

    function Equals(const AOther: IX509CertificatePair): Boolean;
    function GetHashCode: {$IFDEF DELPHI}Int32; {$ELSE}PtrInt; {$ENDIF DELPHI}

    property Forward: IX509Certificate read GetForward;
    property Reverse: IX509Certificate read GetReverse;
  end;

implementation

end.
