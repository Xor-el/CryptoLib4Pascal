{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                           Author - Ugochukwu Mmaduekwe                          * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }

{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }

{ *                              Acknowledgements:                                  * }
{ *                                                                                 * }
{ *      Thanks to Sphere 10 Software (http://www.sphere10.com/) for sponsoring     * }
{ *                           development of this library                           * }

{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit ClpICipherBuilderWithKey;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpICipherBuilder,
  ClpICipherParameters;

type
  /// <summary>
  /// A cipher builder that can also return the key it was initialized with.
  /// </summary>
  ICipherBuilderWithKey = interface(ICipherBuilder)
    ['{B38400C7-E330-465A-BDDF-BD06946F5E4A}']

    /// <summary>
    /// Return the key we were initialized with.
    /// </summary>
    function GetKey: ICipherParameters;

    property Key: ICipherParameters read GetKey;
  end;

implementation

end.
