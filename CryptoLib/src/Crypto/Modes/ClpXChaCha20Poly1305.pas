{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                           Author - Ugochukwu Mmaduekwe                          * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ *                                                                                 * }
{ *                              Acknowledgements:                                  * }
{ *                                                                                 * }
{ *      Thanks to Sphere 10 Software (http://www.sphere10.com/) for sponsoring     * }
{ *                         the development of this library                         * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit ClpXChaCha20Poly1305;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpIXChaCha20Poly1305,
  ClpIAeadCipher,
  ClpIXChaCha20Engine,
  ClpChaCha20Poly1305,
  ClpIMac,
  ClpPoly1305,
  ClpXChaCha20Engine;

type
  TXChaCha20Poly1305 = class(TChaCha20Poly1305, IXChaCha20Poly1305, IAeadCipher)

  strict protected
    function GetAlgorithmName: String; override;

  public
    constructor Create(); overload;
    constructor Create(const APoly1305: IMac); overload;
  end;

implementation

{ TXChaCha20Poly1305 }

constructor TXChaCha20Poly1305.Create;
begin
  Create(TPoly1305.Create() as IMac);
end;

constructor TXChaCha20Poly1305.Create(const APoly1305: IMac);
begin
  inherited Create(APoly1305, TXChaCha20Engine.Create() as IXChaCha20Engine, 24);
end;

function TXChaCha20Poly1305.GetAlgorithmName: String;
begin
  Result := 'XChaCha20Poly1305';
end;

end.
