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

unit ClpIVerifier;

{$I ..\Include\CryptoLib.inc}

interface

uses
  ClpCryptoLibTypes;

type
  /// <summary>
  /// Interface for operators that reduce their input to the validation of a signature.
  /// </summary>
  IVerifier = interface
    ['{B2C3D4E5-F6A7-8901-BCDE-F0123456789A}']

    /// <summary>
    /// Return true if the passed in data matches what is expected by the verification result.
    /// </summary>
    function IsVerified(const AData: TCryptoLibByteArray): Boolean; overload;
    /// <summary>
    /// Return true if the length bytes from off in the source array match the signature expected.
    /// </summary>
    function IsVerified(const ASource: TCryptoLibByteArray; AOff, ALength: Int32): Boolean; overload;
  end;

implementation

end.
