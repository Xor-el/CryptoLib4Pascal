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

unit ClpBerApplicationSpecific;

{$I ..\Include\CryptoLib.inc}

interface

uses
  ClpIAsn1EncodableVector,
  ClpIBerApplicationSpecific,
  ClpDerApplicationSpecific;

type
  TBerApplicationSpecific = class(TDerApplicationSpecific,
    IBerApplicationSpecific)

  public
    constructor Create(tagNo: Int32; const vec: IAsn1EncodableVector);

  end;

implementation

{ TBerApplicationSpecific }

constructor TBerApplicationSpecific.Create(tagNo: Int32;
  const vec: IAsn1EncodableVector);
begin
  inherited Create(tagNo, vec);
end;

end.
