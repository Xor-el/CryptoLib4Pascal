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

unit ClpIX509NameTokenizer;

{$I ..\..\..\Include\CryptoLib.inc}

interface

type
  /// <summary>
  /// Interface for breaking up an X500 Name into its component tokens.
  /// </summary>
  IX509NameTokenizer = interface
    ['{A1B2C3D4-E5F6-7890-ABCD-EF0123456789}']

    function HasMoreTokens: Boolean;
    function NextToken: String;
  end;

implementation

end.
