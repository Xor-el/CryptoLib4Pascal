{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                    Copyright (c) 2018 Ugochukwu Mmaduekwe                       * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }

{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }

{ *                              Acknowledgements:                                  * }
{ *                                                                                 * }
{ *        Thanks to Sphere 10 Software (http://sphere10.com) for sponsoring        * }
{ *                        the development of this library                          * }

{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit ClpIDefiniteLengthInputStream;

{$I ..\Include\CryptoLib.inc}

interface

uses
  ClpCryptoLibTypes,
  ClpILimitedInputStream;

type
  IDefiniteLengthInputStream = interface(ILimitedInputStream)

    ['{3828572B-FB58-47A3-826B-6A6AEEBF59E4}']

    function GetRemaining: Int32;

    function ReadByte(): Int32;

    function Read(buf: TCryptoLibByteArray; off, len: Int32): Int32;

    procedure ReadAllIntoByteArray(buf: TCryptoLibByteArray);

    function ToArray: TCryptoLibByteArray;

    property Remaining: Int32 read GetRemaining;

  end;

implementation

end.
