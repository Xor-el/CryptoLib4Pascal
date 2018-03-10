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

unit ClpIIndefiniteLengthInputStream;

{$I ..\Include\CryptoLib.inc}

interface

uses
  ClpILimitedInputStream;

type
  IIndefiniteLengthInputStream = interface(ILimitedInputStream)

    ['{2B9245D6-E5E8-48C2-8BB1-36E44F43F1D5}']

    function CheckForEof(): Boolean;
    function RequireByte(): Int32;

    procedure SetEofOn00(eofOn00: Boolean);

    function ReadByte(): Int32;

  end;

implementation

end.
