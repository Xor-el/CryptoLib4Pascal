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

unit ClpIZTauElement;

{$I ..\..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpBigInteger;

type
  /// <summary>
  /// Interface for an element of Z[tau], where lambda = u + v*tau.
  /// </summary>
  IZTauElement = interface(IInterface)
    ['{F6E791EA-EBF1-4224-9210-43099D52F317}']

    function GetU: TBigInteger;
    function GetV: TBigInteger;

    property U: TBigInteger read GetU;
    property V: TBigInteger read GetV;
  end;

implementation

end.
