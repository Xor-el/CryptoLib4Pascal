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
  ClpIAsn1Core,
  ClpIAsn1Objects;

type
  /// <summary>
  /// Interface for X509Extension (helper class, not ASN1Encodable).
  /// </summary>
  IX509Extension = interface
    ['{3C3A86D2-15E7-4692-8386-01708589F045}']

    function GetIsCritical: Boolean;
    function GetValue: IAsn1OctetString;
    function GetParsedValue: IAsn1Object;

    property IsCritical: Boolean read GetIsCritical;
    property Value: IAsn1OctetString read GetValue;
  end;

implementation

end.
