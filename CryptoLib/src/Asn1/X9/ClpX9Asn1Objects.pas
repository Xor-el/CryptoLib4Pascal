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

unit ClpX9Asn1Objects;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpAsn1Objects,
  ClpIAsn1Objects,
  ClpAsn1Core,
  ClpIAsn1Core,
  ClpIX9Asn1Objects,
  ClpIX9ECParameters,
  ClpX9ECParameters,
  ClpCryptoLibTypes,
  ClpAsn1Utilities;

resourcestring
  SInvalidParameters = 'Invalid parameters';
  SBadSequenceSize = 'Bad sequence size: %d';
  SUnexpectedElementsInSequence = 'Unexpected elements in sequence';

type
  /// <summary>
  /// The X962Parameters object.
  /// </summary>
  TX962Parameters = class(TAsn1Encodable, IX962Parameters)

  strict private
  var
    FParameters: IAsn1Object;

  strict protected
    function GetParameters: IAsn1Object;
    function GetNamedCurve: IDerObjectIdentifier;
    function IsImplicitlyCA: Boolean;
    function IsNamedCurve: Boolean;

  public
    class function GetInstance(AObj: TObject): IX962Parameters; overload; static;
    class function GetInstance(const AObj: IAsn1Object): IX962Parameters; overload; static;
    class function GetInstance(const AElement: IAsn1Encodable): IX962Parameters; overload; static;
    class function GetInstance(const AEncoded: TCryptoLibByteArray): IX962Parameters; overload; static;
    class function GetInstance(const AObj: IAsn1TaggedObject;
      AExplicitly: Boolean): IX962Parameters; overload; static;
    class function GetOptional(const AElement: IAsn1Encodable): IX962Parameters; static;

    constructor Create(const AParameters: IAsn1Object); overload;
    constructor Create(const AParameters: IAsn1Encodable); overload;

    function ToAsn1Object: IAsn1Object; override;

    property Parameters: IAsn1Object read GetParameters;

  end;

implementation

{ TX962Parameters }

class function TX962Parameters.GetInstance(AObj: TObject): IX962Parameters;
begin
  Result := TAsn1Utilities.GetInstanceChoice<IX962Parameters>(AObj,
    function(AElement: IAsn1Encodable): IX962Parameters
    begin
      Result := GetOptional(AElement);
    end);
end;

class function TX962Parameters.GetOptional(const AElement: IAsn1Encodable): IX962Parameters;
var
  LECParams: IX9ECParameters;
  LNamedCurve: IDerObjectIdentifier;
  LNull: IAsn1Null;
begin
  if AElement = nil then
    raise EArgumentNilCryptoLibException.Create('element');

  if Supports(AElement, IX962Parameters, Result) then
    Exit;

  LECParams := TX9ECParameters.GetOptional(AElement);
  if LECParams <> nil then
  begin
    Result := TX962Parameters.Create(LECParams.ToAsn1Object());
    Exit;
  end;

  LNamedCurve := TDerObjectIdentifier.GetOptional(AElement);
  if LNamedCurve <> nil then
  begin
    Result := TX962Parameters.Create(LNamedCurve);
    Exit;
  end;

  LNull := TAsn1Null.GetOptional(AElement);
  if LNull <> nil then
  begin
    Result := TX962Parameters.Create(LNull);
    Exit;
  end;

  Result := nil;
end;

class function TX962Parameters.GetInstance(const AObj: IAsn1Object): IX962Parameters;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IX962Parameters, Result) then
    Exit;

  Result := GetOptional(AObj as IAsn1Encodable);
end;

class function TX962Parameters.GetInstance(const AElement: IAsn1Encodable): IX962Parameters;
begin
  if AElement = nil then
  begin
    Result := nil;
    Exit;
  end;

  Result := GetOptional(AElement);
  if Result = nil then
    raise EArgumentCryptoLibException.Create('unable to parse X962Parameters');
end;

class function TX962Parameters.GetInstance(const AEncoded: TCryptoLibByteArray): IX962Parameters;
var
  LAsn1Obj: IAsn1Object;
begin
  if AEncoded = nil then
  begin
    Result := nil;
    Exit;
  end;

  try
    LAsn1Obj := TAsn1Object.FromByteArray(AEncoded);
    Result := GetInstance(LAsn1Obj);
  except
    on E: EIOCryptoLibException do
      raise EArgumentCryptoLibException.Create('failed to construct X962Parameters from byte[]: ' + E.Message);
  end;
end;

class function TX962Parameters.GetInstance(const AObj: IAsn1TaggedObject;
  AExplicitly: Boolean): IX962Parameters;
begin
  Result := TAsn1Utilities.GetInstanceChoice<IX962Parameters>(AObj, AExplicitly,
    function(AElement: IAsn1Encodable): IX962Parameters
    begin
      Result := GetInstance(AElement.ToAsn1Object());
    end);
end;

constructor TX962Parameters.Create(const AParameters: IAsn1Object);
begin
  inherited Create();
  FParameters := AParameters;
end;

constructor TX962Parameters.Create(const AParameters: IAsn1Encodable);
begin
  Create(AParameters.ToAsn1Object());
end;

function TX962Parameters.GetParameters: IAsn1Object;
begin
  Result := FParameters;
end;

function TX962Parameters.IsImplicitlyCA: Boolean;
var
  LNull: IAsn1Null;
begin
  // IsImplicitlyCA => m_params is Asn1Null
  // Check if FParameters is an Asn1Null instance (not nil check)
  Result := Supports(FParameters, IAsn1Null, LNull);
end;

function TX962Parameters.GetNamedCurve: IDerObjectIdentifier;
begin
  if not Supports(FParameters, IDerObjectIdentifier, Result) then
    Result := nil;
end;

function TX962Parameters.IsNamedCurve: Boolean;
begin
  Result := GetNamedCurve <> nil;
end;

function TX962Parameters.ToAsn1Object: IAsn1Object;
begin
  Result := FParameters;
end;

end.
