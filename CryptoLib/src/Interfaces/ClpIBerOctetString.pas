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

unit ClpIBerOctetString;

{$I ..\Include\CryptoLib.inc}

interface

uses
  Generics.Collections,
  ClpIDerOctetString;

type
  IBerOctetString = interface(IDerOctetString)

    ['{B9D96DA7-623C-491C-9304-7B67A6DBCFA6}']

    function GenerateOcts(): TList<IDerOctetString>;

    /// <summary>
    /// return the DER octets that make up this string.
    /// </summary>

    function GetEnumerator: TEnumerator<IDerOctetString>;

  end;

implementation

end.
