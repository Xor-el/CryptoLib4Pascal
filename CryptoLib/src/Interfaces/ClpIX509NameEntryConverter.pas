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

unit ClpIX509NameEntryConverter;

{$I ..\Include\CryptoLib.inc}

interface

uses
  ClpIAsn1Objects;

type
  /// <summary>
  /// Interface for X509NameEntryConverter (abstract base class).
  /// </summary>
  IX509NameEntryConverter = interface
    ['{F1A2B3C4-D5E6-7890-EFAB-0123456789CD}']

    function GetConvertedValue(const AOid: IDerObjectIdentifier;
      const AValue: String): IAsn1Object;
  end;

implementation

end.
