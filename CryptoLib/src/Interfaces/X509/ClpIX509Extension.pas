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

unit ClpIX509Extension;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpIAsn1Objects;

type
  /// <summary>
  /// Interface for X509Extension (helper class, not ASN1Encodable).
  /// </summary>
  IX509Extension = interface
    ['{E6F7A8B9-C0D1-E2F3-A4B5-C6D7E8F9A0B1}']

    function GetIsCritical: Boolean;
    function GetValue: IAsn1OctetString;
    function GetParsedValue: IAsn1Object;

    property IsCritical: Boolean read GetIsCritical;
    property Value: IAsn1OctetString read GetValue;
  end;

implementation

end.
