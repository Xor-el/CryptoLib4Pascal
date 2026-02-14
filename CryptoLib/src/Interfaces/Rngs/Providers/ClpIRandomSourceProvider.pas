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

unit ClpIRandomSourceProvider;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpCryptoLibTypes;

type
  /// <summary>
  /// Interface for random source providers.
  /// </summary>
  IRandomSourceProvider = interface(IInterface)
    ['{36D4B411-F510-418F-9ADB-DB8136DCFCA5}']

    /// <summary>Fill byte array with random bytes from implementing source.</summary>
    procedure GetBytes(const AData: TCryptoLibByteArray);

    /// <summary>Fill byte array with non-zero random bytes from implementing source.</summary>
    procedure GetNonZeroBytes(const AData: TCryptoLibByteArray);

    /// <summary>Returns true if this implementing random implementation is available.</summary>
    function GetIsAvailable: Boolean;

    /// <summary>Returns the name of this random source provider.</summary>
    function GetName: String;

    property IsAvailable: Boolean read GetIsAvailable;
    property Name: String read GetName;
  end;

implementation

end.
