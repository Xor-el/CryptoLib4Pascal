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

unit ClpIAsn1StreamParser;

{$I ..\Include\CryptoLib.inc}

interface

uses
  ClpIProxiedInterface,
  ClpIAsn1EncodableVector;

type
  IAsn1StreamParser = interface(IInterface)
    ['{D6FF970C-F5B0-4B62-8585-F5F499A18597}']

    procedure Set00Check(enabled: Boolean);

    function ReadIndef(tagValue: Int32): IAsn1Convertible;
    function ReadImplicit(constructed: Boolean; tag: Int32): IAsn1Convertible;

    function ReadTaggedObject(constructed: Boolean; tag: Int32): IAsn1Object;

    function ReadObject(): IAsn1Convertible;

    function ReadVector(): IAsn1EncodableVector;

  end;

implementation

end.
