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

unit ClpIX9DHAsn1Objects;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpIAsn1Core,
  ClpIAsn1Objects;

type
  /// <summary>
  /// Interface for DHValidationParms.
  /// </summary>
  IDHValidationParms = interface(IAsn1Encodable)
    ['{A75D3486-080A-43F5-9296-9C74B7DEE7DC}']

    function GetSeed: IDerBitString;
    function GetPGenCounter: IDerInteger;

    property Seed: IDerBitString read GetSeed;
    property PGenCounter: IDerInteger read GetPGenCounter;
  end;

  /// <summary>
  /// Interface for DHDomainParameters.
  /// </summary>
  IDHDomainParameters = interface(IAsn1Encodable)
    ['{18288135-B71F-48B4-8595-57AAB9092FC8}']

    function GetP: IDerInteger;
    function GetG: IDerInteger;
    function GetQ: IDerInteger;
    function GetJ: IDerInteger;
    function GetValidationParms: IDHValidationParms;

    property P: IDerInteger read GetP;
    property G: IDerInteger read GetG;
    property Q: IDerInteger read GetQ;
    property J: IDerInteger read GetJ;
    property ValidationParms: IDHValidationParms read GetValidationParms;
  end;

implementation

end.
