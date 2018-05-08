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

unit ClpIAsn1TaggedObject;

{$I ..\Include\CryptoLib.inc}

interface

uses
  ClpIProxiedInterface;

type
  IAsn1TaggedObject = interface(IAsn1Object)
    ['{2EBA68BE-CEC6-4030-BB9C-E8310C9B7D5F}']

    function GetTagNo: Int32;
    function Getexplicitly: Boolean;
    function Getobj: IAsn1Encodable;

    property tagNo: Int32 read GetTagNo;
    property explicitly: Boolean read Getexplicitly;
    property obj: IAsn1Encodable read Getobj;

    function isExplicit(): Boolean;

    function IsEmpty(): Boolean;

    function GetObject(): IAsn1Object;

    function GetObjectParser(tag: Int32; isExplicit: Boolean): IAsn1Convertible;

    function ToString(): String;

  end;

implementation

end.
