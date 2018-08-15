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

unit ClpIDerObjectIdentifier;

{$I ..\Include\CryptoLib.inc}

interface

uses
  Classes,
  ClpBigInteger,
  ClpIProxiedInterface,
  ClpCryptoLibTypes;

type
  IDerObjectIdentifier = interface(IAsn1Object)

    ['{8626051F-828D-419B-94E8-65CC0752CCA1}']

    function GetID: String;
    property ID: String read GetID;

    procedure WriteField(const outputStream: TStream;
      fieldValue: Int64); overload;
    procedure WriteField(const outputStream: TStream;
      const fieldValue: TBigInteger); overload;
    procedure DoOutput(const bOut: TMemoryStream); overload;
    function GetBody(): TCryptoLibByteArray;

    function Branch(const branchID: String): IDerObjectIdentifier;

    function &On(const stem: IDerObjectIdentifier): Boolean;

    function ToString(): String;

  end;

implementation

end.
