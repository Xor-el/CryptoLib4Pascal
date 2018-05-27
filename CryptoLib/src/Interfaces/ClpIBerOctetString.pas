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

unit ClpIBerOctetString;

{$I ..\Include\CryptoLib.inc}

interface

uses
  Generics.Collections,
  ClpIDerOctetString,
  ClpCryptoLibTypes;

type
  IBerOctetString = interface(IDerOctetString)

    ['{B9D96DA7-623C-491C-9304-7B67A6DBCFA6}']

    function GenerateOcts(): TList<IDerOctetString>;

    /// <summary>
    /// return the DER octets that make up this string.
    /// </summary>

    function GetEnumerable: TCryptoLibGenericArray<IDerOctetString>;

  end;

implementation

end.
