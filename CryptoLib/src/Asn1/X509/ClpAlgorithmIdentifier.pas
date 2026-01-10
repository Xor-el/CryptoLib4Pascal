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
  SysUtils,
  ClpAsn1Objects,
  ClpIAsn1Objects,
  ClpIAlgorithmIdentifier,
  ClpCryptoLibTypes;

resourcestring
  SBadSequenceSize = 'Bad sequence size: %d';
  SAlgorithmNil = 'algorithm';

type
  /// <summary>
  /// The AlgorithmIdentifier object.
  /// <code>
  /// AlgorithmIdentifier ::= SEQUENCE {
  ///   algorithm OBJECT IDENTIFIER,
  ///   parameters ANY DEFINED BY algorithm OPTIONAL
  /// }
  /// </code>
  /// </summary>
  TAlgorithmIdentifier = class(TAsn1Encodable, IAlgorithmIdentifier)

  strict private
  var
    FAlgorithm: IDerObjectIdentifier;
    FParameters: IAsn1Encodable;

  strict protected
    function GetAlgorithm: IDerObjectIdentifier;
    function GetParameters: IAsn1Encodable;

  public
    /// <summary>
    /// Parse an AlgorithmIdentifier from an object.
    /// </summary>
    class function GetInstance(obj: TObject): IAlgorithmIdentifier; overload; static;

    /// <summary>
    /// Parse an AlgorithmIdentifier from a tagged object.
    /// </summary>
    class function GetInstance(const obj: IAsn1TaggedObject;
      explicitly: Boolean): IAlgorithmIdentifier; overload; static;

    constructor Create(const seq: IAsn1Sequence); overload;
    constructor Create(const algorithm: IDerObjectIdentifier); overload;
    constructor Create(const algorithm: IDerObjectIdentifier;
      const parameters: IAsn1Encodable); overload;

    function ToAsn1Object: IAsn1Object; override;

    property Algorithm: IDerObjectIdentifier read GetAlgorithm;
    property Parameters: IAsn1Encodable read GetParameters;

  end;

implementation

{ TAlgorithmIdentifier }

class function TAlgorithmIdentifier.GetInstance(obj: TObject): IAlgorithmIdentifier;
begin
  if obj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(obj, IAlgorithmIdentifier, Result) then
    Exit;

  Result := TAlgorithmIdentifier.Create(TAsn1Sequence.GetInstance(obj));
end;

class function TAlgorithmIdentifier.GetInstance(const obj: IAsn1TaggedObject;
  explicitly: Boolean): IAlgorithmIdentifier;
begin
  Result := TAlgorithmIdentifier.Create(TAsn1Sequence.GetInstance(obj, explicitly));
end;

constructor TAlgorithmIdentifier.Create(const seq: IAsn1Sequence);
var
  count: Int32;
begin
  inherited Create();

  count := seq.Count;
  if (count < 1) or (count > 2) then
  begin
    raise EArgumentCryptoLibException.CreateResFmt(@SBadSequenceSize, [count]);
  end;

  //FAlgorithm := TDerObjectIdentifier.GetInstance(seq[0].ToAsn1Object as TObject);
  FAlgorithm := TDerObjectIdentifier.GetInstance(seq[0] as TAsn1Encodable);
  if count < 2 then
    FParameters := nil
  else
    FParameters := seq[1] as IAsn1Encodable;
end;

constructor TAlgorithmIdentifier.Create(const algorithm: IDerObjectIdentifier);
begin
  Create(algorithm, nil);
end;

constructor TAlgorithmIdentifier.Create(const algorithm: IDerObjectIdentifier;
  const parameters: IAsn1Encodable);
begin
  inherited Create();

  if algorithm = nil then
  begin
    raise EArgumentNilCryptoLibException.Create(SAlgorithmNil);
  end;

  FAlgorithm := algorithm;
  FParameters := parameters;
end;

function TAlgorithmIdentifier.GetAlgorithm: IDerObjectIdentifier;
begin
  Result := FAlgorithm;
end;

function TAlgorithmIdentifier.GetParameters: IAsn1Encodable;
begin
  Result := FParameters;
end;

function TAlgorithmIdentifier.ToAsn1Object: IAsn1Object;
begin
  if FParameters = nil then
    Result := TDerSequence.Create([FAlgorithm as IAsn1Encodable])
  else
    Result := TDerSequence.Create([FAlgorithm as IAsn1Encodable, FParameters]);
end;

end.
