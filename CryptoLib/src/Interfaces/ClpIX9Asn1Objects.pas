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

unit ClpIX9Asn1Objects;

{$I ..\Include\CryptoLib.inc}

interface

uses
  ClpIAsn1Objects,
  ClpBigInteger;

type
  /// <summary>
  /// Interface for X962Parameters.
  /// </summary>
  IX962Parameters = interface(IAsn1Encodable)
    ['{D1E2F3A4-B5C6-7890-DEF1-23456789ABCD}']

    function GetParameters: IAsn1Object;
    function GetNamedCurve: IDerObjectIdentifier;
    function IsImplicitlyCA: Boolean;
    function IsNamedCurve: Boolean;

    property Parameters: IAsn1Object read GetParameters;
    property NamedCurve: IDerObjectIdentifier read GetNamedCurve;
  end;

implementation

end.
