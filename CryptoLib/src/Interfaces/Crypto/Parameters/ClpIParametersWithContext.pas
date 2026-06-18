{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                           Author - Ugochukwu Mmaduekwe                          * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ *                                                                                 * }
{ *                              Acknowledgements:                                  * }
{ *                                                                                 * }
{ *      Thanks to Sphere 10 Software (http://www.sphere10.com/) for sponsoring     * }
{ *                         the development of this library                         * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit ClpIParametersWithContext;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpICipherParameters,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// Optional signing/KEM context envelope (FIPS 204/205), wrapping inner <see cref="ICipherParameters"/>.
  /// </summary>
  IParametersWithContext = interface(ICipherParameters)

    ['{A3B8C4D1-2E5F-4A6B-9C0D-1E2F3A4B5C6D}']

    function GetContextLength: Int32;
    procedure CopyContextTo(const ABuf: TCryptoLibByteArray; AOff, ALen: Int32);
    function GetContext: TCryptoLibByteArray;
    function GetParameters: ICipherParameters;

    property ContextLength: Int32 read GetContextLength;
    property Parameters: ICipherParameters read GetParameters;

  end;

implementation

end.
