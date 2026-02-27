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

unit ClpZTauElement;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpBigInteger,
  ClpIZTauElement;

type
  /// <summary>
  /// Class representing an element of Z[tau]. Let lambda be an element of
  /// Z[tau]. Then lambda is given as lambda = u + v*tau. The components
  /// u and v may be used directly via properties.
  /// Immutable class.
  /// </summary>
  TZTauElement = class sealed(TInterfacedObject, IZTauElement)
  strict private
    FU, FV: TBigInteger;
    function GetU: TBigInteger;
    function GetV: TBigInteger;
  public
    constructor Create(const AU, AV: TBigInteger);
    property U: TBigInteger read GetU;
    property V: TBigInteger read GetV;
  end;

implementation

{ TZTauElement }

constructor TZTauElement.Create(const AU, AV: TBigInteger);
begin
  inherited Create;
  FU := AU;
  FV := AV;
end;

function TZTauElement.GetU: TBigInteger;
begin
  Result := FU;
end;

function TZTauElement.GetV: TBigInteger;
begin
  Result := FV;
end;

end.
