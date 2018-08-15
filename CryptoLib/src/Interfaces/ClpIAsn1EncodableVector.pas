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

unit ClpIAsn1EncodableVector;

{$I ..\Include\CryptoLib.inc}

interface

uses
  ClpIProxiedInterface,
  ClpCryptoLibTypes;

type
  IAsn1EncodableVector = interface(IInterface)
    ['{A78E22EB-DB67-472E-A55F-CD710BCBDBFA}']

    function GetCount: Int32;
    function GetSelf(Index: Int32): IAsn1Encodable;

    procedure Add(const objs: array of IAsn1Encodable);

    procedure AddOptional(const objs: array of IAsn1Encodable);

    property Self[Index: Int32]: IAsn1Encodable read GetSelf; default;

    property Count: Int32 read GetCount;

    function GetEnumerable: TCryptoLibGenericArray<IAsn1Encodable>;

  end;

implementation

end.
