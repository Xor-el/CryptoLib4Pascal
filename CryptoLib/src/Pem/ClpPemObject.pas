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

unit ClpPemObject;

{$I ..\Include\CryptoLib.inc}

interface

uses
  ClpIPemHeader,
  ClpIPemObject,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// PEM object implementation.
  /// </summary>
  TPemObject = class sealed(TInterfacedObject, IPemObject, IPemObjectGenerator)
  strict private
    FType: String;
    FHeaders: TCryptoLibGenericArray<IPemHeader>;
    FContent: TCryptoLibByteArray;

    function GetType: String;
    function GetHeaders: TCryptoLibGenericArray<IPemHeader>;
    function GetContent: TCryptoLibByteArray;

  public
    constructor Create(const AType: String; const AContent: TCryptoLibByteArray); overload;
    constructor Create(const AType: String;
      const AHeaders: TCryptoLibGenericArray<IPemHeader>;
      const AContent: TCryptoLibByteArray); overload;

    function Generate(): IPemObject;

    property &Type: String read GetType;
    property Headers: TCryptoLibGenericArray<IPemHeader> read GetHeaders;
    property Content: TCryptoLibByteArray read GetContent;
  end;

implementation

{ TPemObject }

constructor TPemObject.Create(const AType: String; const AContent: TCryptoLibByteArray);
var
  LEmptyHeaders: TCryptoLibGenericArray<IPemHeader>;
begin
  System.SetLength(LEmptyHeaders, 0);
  Create(AType, LEmptyHeaders, AContent);
end;

constructor TPemObject.Create(const AType: String;
  const AHeaders: TCryptoLibGenericArray<IPemHeader>;
  const AContent: TCryptoLibByteArray);
var
  I: Int32;
begin
  Inherited Create();
  FType := AType;
  System.SetLength(FHeaders, System.Length(AHeaders));
  for I := 0 to System.Length(AHeaders) - 1 do
  begin
    FHeaders[I] := AHeaders[I];
  end;
  FContent := AContent;
end;

function TPemObject.GetType: String;
begin
  Result := FType;
end;

function TPemObject.GetHeaders: TCryptoLibGenericArray<IPemHeader>;
begin
  Result := FHeaders;
end;

function TPemObject.GetContent: TCryptoLibByteArray;
begin
  Result := FContent;
end;

function TPemObject.Generate(): IPemObject;
begin
  Result := Self as IPemObject;
end;

end.
