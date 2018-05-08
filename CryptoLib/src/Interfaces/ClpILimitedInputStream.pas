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

unit ClpILimitedInputStream;

{$I ..\Include\CryptoLib.inc}

interface

uses
  ClpIBaseInputStream;

type
  ILimitedInputStream = interface(IBaseInputStream)

    ['{04A7A641-74B5-418A-935B-3B6EE5C8340C}']

    procedure SetParentEofDetect(&on: Boolean);
    function GetRemaining(): Int32;

  end;

implementation

end.
