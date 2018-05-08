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

unit ClpIDerBoolean;

{$I ..\Include\CryptoLib.inc}

interface

uses
  ClpIProxiedInterface;

type
  IDerBoolean = interface(IAsn1Object)
    ['{1AD2B466-E3D6-4CD4-A66B-660FB63F2FFE}']

    function GetIsTrue: Boolean;

    function ToString(): String;

    property IsTrue: Boolean read GetIsTrue;

  end;

implementation

end.
