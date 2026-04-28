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

unit ClpDHKdfParameters;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpIAsn1Objects,
  ClpIDHKdfParameters,
  ClpIDerivationParameters,
  ClpCryptoLibTypes;

type
  TDHKdfParameters = class(TInterfacedObject, IDHKdfParameters,
    IDerivationParameters)

  strict private
  var
    FAlgorithm: IDerObjectIdentifier;
    FKeySize: Int32;
    FZ: TCryptoLibByteArray;
    FExtraInfo: TCryptoLibByteArray;

  strict protected
    function GetAlgorithm(): IDerObjectIdentifier;
    function GetKeySize(): Int32;
    function GetZ(): TCryptoLibByteArray;
    function GetExtraInfo(): TCryptoLibByteArray;

  public
    constructor Create(const AAlgorithm: IDerObjectIdentifier;
      AKeySize: Int32; const AZ: TCryptoLibByteArray); overload;
    constructor Create(const AAlgorithm: IDerObjectIdentifier;
      AKeySize: Int32; const AZ, AExtraInfo: TCryptoLibByteArray); overload;

    property Algorithm: IDerObjectIdentifier read GetAlgorithm;
    property KeySize: Int32 read GetKeySize;
    property Z: TCryptoLibByteArray read GetZ;
    property ExtraInfo: TCryptoLibByteArray read GetExtraInfo;
  end;

implementation

{ TDHKdfParameters }

constructor TDHKdfParameters.Create(const AAlgorithm: IDerObjectIdentifier;
  AKeySize: Int32; const AZ: TCryptoLibByteArray);
begin
  Create(AAlgorithm, AKeySize, AZ, nil);
end;

constructor TDHKdfParameters.Create(const AAlgorithm: IDerObjectIdentifier;
  AKeySize: Int32; const AZ, AExtraInfo: TCryptoLibByteArray);
begin
  inherited Create();
  FAlgorithm := AAlgorithm;
  FKeySize := AKeySize;
  if AZ <> nil then
    FZ := System.Copy(AZ)
  else
    FZ := nil;
  if AExtraInfo <> nil then
    FExtraInfo := System.Copy(AExtraInfo)
  else
    FExtraInfo := nil;
end;

function TDHKdfParameters.GetAlgorithm: IDerObjectIdentifier;
begin
  Result := FAlgorithm;
end;

function TDHKdfParameters.GetKeySize: Int32;
begin
  Result := FKeySize;
end;

function TDHKdfParameters.GetZ: TCryptoLibByteArray;
begin
  if FZ <> nil then
    Result := System.Copy(FZ)
  else
    Result := nil;
end;

function TDHKdfParameters.GetExtraInfo: TCryptoLibByteArray;
begin
  if FExtraInfo <> nil then
    Result := System.Copy(FExtraInfo)
  else
    Result := nil;
end;

end.
