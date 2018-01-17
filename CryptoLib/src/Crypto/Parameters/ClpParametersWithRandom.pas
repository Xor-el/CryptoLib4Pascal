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

unit ClpParametersWithRandom;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpCryptoLibTypes,
  ClpIParametersWithRandom,
  ClpISecureRandom,
  ClpSecureRandom,
  ClpICipherParameters;

resourcestring
  SParameters = 'Parameters';
  SRandom = 'Random';

type
  TParametersWithRandom = class(TInterfacedObject, ICipherParameters,
    IParametersWithRandom)

  strict private
  var
    Fparameters: ICipherParameters;
    Frandom: ISecureRandom;
    function GetRandom: ISecureRandom; inline;
    function GetParameters: ICipherParameters; inline;

  public

    constructor Create(parameters: ICipherParameters); overload;

    constructor Create(parameters: ICipherParameters;
      random: ISecureRandom); overload;

    property random: ISecureRandom read GetRandom;

    property parameters: ICipherParameters read GetParameters;

  end;

implementation

{ TParametersWithRandom }

constructor TParametersWithRandom.Create(parameters: ICipherParameters);
begin
  Create(parameters, TSecureRandom.Create());
end;

constructor TParametersWithRandom.Create(parameters: ICipherParameters;
  random: ISecureRandom);
begin
  inherited Create();
  if (parameters = Nil) then
  begin
    raise EArgumentNilCryptoLibException.CreateRes(@SParameters);
  end;

  if (random = Nil) then
  begin
    raise EArgumentNilCryptoLibException.CreateRes(@SRandom);
  end;

  Fparameters := parameters;
  Frandom := random;
end;

function TParametersWithRandom.GetParameters: ICipherParameters;
begin
  Result := Fparameters;
end;

function TParametersWithRandom.GetRandom: ISecureRandom;
begin
  Result := Frandom;
end;

end.
