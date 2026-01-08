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

unit ClpAlgorithmIdentifier;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpAsn1Objects,
  ClpIAsn1Objects,
  ClpIAlgorithmIdentifier,
  ClpCryptoLibTypes;

resourcestring
  SInvalidAlgorithmIdentifier = 'Invalid AlgorithmIdentifier: %s';
  SBadSequenceSize = 'Bad Sequence Size: %d';

type
  /// <summary>
  /// AlgorithmIdentifier ::= SEQUENCE {
  ///   algorithm OBJECT IDENTIFIER,
  ///   parameters ANY DEFINED BY algorithm OPTIONAL
  /// }
  /// </summary>
  TAlgorithmIdentifier = class(TAsn1Encodable, IAlgorithmIdentifier)

  strict private
  var
    FAlgorithm: IDerObjectIdentifier;
    FParameters: IAsn1Encodable;

    function GetAlgorithm: IDerObjectIdentifier;
    function GetParameters: IAsn1Encodable;

    constructor Create(const seq: IAsn1Sequence); overload;

  public
    constructor Create(const algorithm: IDerObjectIdentifier); overload;
    constructor Create(const algorithm: IDerObjectIdentifier;
      const parameters: IAsn1Encodable); overload;

    function ToAsn1Object(): IAsn1Object; override;

    property Algorithm: IDerObjectIdentifier read GetAlgorithm;
    property Parameters: IAsn1Encodable read GetParameters;

    class function GetInstance(obj: TObject): IAlgorithmIdentifier; overload;
      static;
    class function GetInstance(const obj: IAsn1TaggedObject;
      explicitly: Boolean): IAlgorithmIdentifier; overload; static;
  end;

implementation

{ TAlgorithmIdentifier }

constructor TAlgorithmIdentifier.Create(const algorithm: IDerObjectIdentifier);
begin
  inherited Create();
  FAlgorithm := algorithm;
  FParameters := nil;
end;

constructor TAlgorithmIdentifier.Create(const algorithm: IDerObjectIdentifier;
  const parameters: IAsn1Encodable);
begin
  inherited Create();
  FAlgorithm := algorithm;
  FParameters := parameters;
end;

constructor TAlgorithmIdentifier.Create(const seq: IAsn1Sequence);
begin
  inherited Create();
  if (seq.Count < 1) or (seq.Count > 2) then
  begin
    raise EArgumentCryptoLibException.CreateResFmt(@SBadSequenceSize,
      [seq.Count]);
  end;

  FAlgorithm := TDerObjectIdentifier.GetInstance(seq[0] as TAsn1Encodable);

  if seq.Count = 2 then
  begin
    FParameters := seq[1] as IAsn1Encodable;
  end
  else
  begin
    FParameters := nil;
  end;
end;

function TAlgorithmIdentifier.GetAlgorithm: IDerObjectIdentifier;
begin
  Result := FAlgorithm;
end;

function TAlgorithmIdentifier.GetParameters: IAsn1Encodable;
begin
  Result := FParameters;
end;

class function TAlgorithmIdentifier.GetInstance(obj: TObject): IAlgorithmIdentifier;
begin
  if (obj = nil) or (obj is TAlgorithmIdentifier) then
  begin
    Result := obj as TAlgorithmIdentifier;
    Exit;
  end;

  if obj is TAsn1Sequence then
  begin
    Result := TAlgorithmIdentifier.Create(obj as TAsn1Sequence);
    Exit;
  end;

  raise EArgumentCryptoLibException.CreateResFmt(@SInvalidAlgorithmIdentifier,
    [obj.ToString]);
end;

class function TAlgorithmIdentifier.GetInstance(const obj: IAsn1TaggedObject;
  explicitly: Boolean): IAlgorithmIdentifier;
begin
  Result := GetInstance(TAsn1Sequence.GetInstance(obj, explicitly) as TAsn1Sequence);
end;

function TAlgorithmIdentifier.ToAsn1Object: IAsn1Object;
var
  v: IAsn1EncodableVector;
begin
  v := TAsn1EncodableVector.Create();
  v.Add(FAlgorithm);

  if FParameters <> nil then
    v.Add(FParameters);

  Result := TDerSequence.FromVector(v);
end;

end.
