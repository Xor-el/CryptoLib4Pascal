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

unit ClpIProxiedInterface;

{$I ..\Include\CryptoLib.inc}

interface

uses
  Classes,
  ClpCryptoLibTypes;

type
  IAsn1Object = interface;

  IAsn1Convertible = interface(IInterface)
    ['{13104D9E-9DF1-4CCE-B48C-1ACC2AC362B1}']

    function ToAsn1Object(): IAsn1Object;
  end;

  IAsn1Encodable = interface(IAsn1Convertible)

    ['{1B2D1F84-4E8F-442E-86F8-B75C9942F1AB}']

    function GetEncoded(): TCryptoLibByteArray; overload;
    function GetEncoded(const encoding: String): TCryptoLibByteArray; overload;

    function GetDerEncoded(): TCryptoLibByteArray;

    function Equals(const obj: IAsn1Convertible): Boolean;
    function GetHashCode(): {$IFDEF DELPHI}Int32; {$ELSE}PtrInt;
{$ENDIF DELPHI}
  end;

  IAsn1Object = interface(IAsn1Encodable)

    ['{83A52A0F-570B-43BB-9B98-8E5351FDA996}']

    function Asn1Equals(const asn1Object: IAsn1Object): Boolean;

    function Asn1GetHashCode(): Int32;

    procedure Encode(const derOut: TStream);

    function CallAsn1Equals(const obj: IAsn1Object): Boolean;

    function CallAsn1GetHashCode(): Int32;

  end;

implementation

end.
