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
    ['{E3DBDADD-8F1F-4472-AED5-E617920024A0}']

    function HasMoreTokens: Boolean;
    function NextToken: String;
  end;

implementation

end.
