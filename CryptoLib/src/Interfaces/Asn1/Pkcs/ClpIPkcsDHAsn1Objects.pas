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

unit ClpIPkcsDHAsn1Objects;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpIAsn1Objects,
  ClpIAsn1Core,
  ClpBigInteger,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// Interface for DHParameter (PKCS#3: P, G, optional L).
  /// </summary>
  IDHParameter = interface(IAsn1Encodable)
    ['{7E8F9A0B-1C2D-4E5F-A6B7-8C9D0E1F2A3B}']

    function GetP: TBigInteger;
    function GetG: TBigInteger;
    /// <summary>Optional L; nil when not present in sequence.</summary>
    function GetL: IDerInteger;

    property P: TBigInteger read GetP;
    property G: TBigInteger read GetG;
    property L: IDerInteger read GetL;
  end;

implementation

end.
