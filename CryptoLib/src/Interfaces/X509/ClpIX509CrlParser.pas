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

unit ClpIX509CrlParser;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  Classes,
  ClpCryptoLibTypes,
  ClpIX509Crl;

type
  /// <summary>
  /// Interface for X.509 CRL parser.
  /// </summary>
  IX509CrlParser = interface(IInterface)
    ['{E4F5A6B7-C8D9-0123-EF01-456789012345}']

    function ReadCrl(const AInput: TCryptoLibByteArray): IX509Crl; overload;
    function ReadCrls(const AInput: TCryptoLibByteArray): TCryptoLibGenericArray<IX509Crl>; overload;
    function ReadCrl(const AInStream: TStream): IX509Crl; overload;
    function ReadCrls(const AInStream: TStream): TCryptoLibGenericArray<IX509Crl>; overload;
    function ParseCrls(const AInStream: TStream): TCryptoLibGenericArray<IX509Crl>;
  end;

implementation

end.
