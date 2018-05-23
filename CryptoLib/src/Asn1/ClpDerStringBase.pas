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

unit ClpDerStringBase;

{$I ..\Include\CryptoLib.inc}

interface

uses
  ClpIAsn1String,
  ClpAsn1Object,
  ClpStringUtils,
  ClpIDerStringBase;

type
  TDerStringBase = class abstract(TAsn1Object, IAsn1String, IDerStringBase)

  strict protected
    constructor Create();
    function Asn1GetHashCode(): Int32; override;
  public
    function GetString(): String; virtual; abstract;
    function ToString(): String; override;
  end;

implementation

{ TDerStringBase }

function TDerStringBase.Asn1GetHashCode: Int32;
begin
  Result := TStringUtils.GetStringHashCode(GetString());
end;

constructor TDerStringBase.Create;
begin
  Inherited Create();
end;

function TDerStringBase.ToString: String;
begin
  Result := GetString();
end;

end.
