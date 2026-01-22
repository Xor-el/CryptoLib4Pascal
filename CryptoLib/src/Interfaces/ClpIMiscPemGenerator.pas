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

unit ClpIMiscPemGenerator;

{$I ..\Include\CryptoLib.inc}

interface

uses
  ClpIPemObjects;

type
  /// <summary>
  /// Interface for miscellaneous PEM generator.
  /// </summary>
  IMiscPemGenerator = interface(IPemObjectGenerator)
    ['{F6A7B8C9-D0E1-2345-EF01-23456789ABCD}']

  end;

implementation

end.
