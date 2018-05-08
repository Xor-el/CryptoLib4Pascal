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

unit ClpAsn1Generator;

{$I ..\Include\CryptoLib.inc}

interface

uses
  Classes,
  ClpIProxiedInterface,
  ClpIAsn1Generator;

type
  TAsn1Generator = class abstract(TInterfacedObject, IAsn1Generator)

  strict private
  var
    F_out: TStream;

    function GetOut: TStream; inline;

  strict protected
    constructor Create(outStream: TStream);
    property &Out: TStream read GetOut;

  public
    procedure AddObject(const obj: IAsn1Encodable); virtual; abstract;

    function GetRawOutputStream(): TStream; virtual; abstract;

    procedure Close(); virtual; abstract;
  end;

implementation

{ TAsn1Generator }

constructor TAsn1Generator.Create(outStream: TStream);
begin
  F_out := outStream;
end;

function TAsn1Generator.GetOut: TStream;
begin
  result := F_out;
end;

end.
