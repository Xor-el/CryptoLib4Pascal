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

unit ClpIPreCompCallback;

{$I ..\..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpIPreCompInfo;

type
  IPreCompCallback = interface(IInterface)
    ['{C3D4E5F6-A7B8-9012-C3D4-E5F6A7B89013}']

    function Precompute(const AExisting: IPreCompInfo): IPreCompInfo;
  end;

implementation

end.
