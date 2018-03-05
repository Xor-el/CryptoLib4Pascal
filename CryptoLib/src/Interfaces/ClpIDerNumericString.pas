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

unit ClpIDerNumericString;

{$I ..\Include\CryptoLib.inc}

interface

uses
  ClpCryptoLibTypes,
  ClpIDerStringBase;

type
  IDerNumericString = interface(IDerStringBase)

    ['{58BB62CA-16C5-4696-AC0B-E83628182740}']

    function GetStr: String;

    property Str: String read GetStr;

    function GetOctets(): TCryptoLibByteArray;

  end;

implementation

end.
