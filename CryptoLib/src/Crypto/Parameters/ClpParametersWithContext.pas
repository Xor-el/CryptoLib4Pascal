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

unit ClpParametersWithContext;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpIParametersWithContext,
  ClpICipherParameters,
  ClpArrayUtilities,
  ClpCryptoLibTypes;

resourcestring
  SContextNilWithLength = 'context cannot be nil when length is non-zero';

type
  /// <summary>
  /// Wrapper carrying an optional protocol context byte string with nested cipher parameters.
  /// </summary>
  TParametersWithContext = class sealed(TInterfacedObject, IParametersWithContext,
    ICipherParameters)

  strict private
  var
    FParameters: ICipherParameters;
    FContext: TCryptoLibByteArray;

    function GetParameters: ICipherParameters; inline;
    function GetContextLength: Int32; inline;

  public
    constructor Create(const AParameters: ICipherParameters;
      const AContext: TCryptoLibByteArray); overload;
    constructor Create(const AParameters: ICipherParameters;
      const AContext: TCryptoLibByteArray; AContextOff, AContextLen: Int32); overload;
    destructor Destroy; override;

    procedure CopyContextTo(const ABuf: TCryptoLibByteArray; AOff, ALen: Int32);
    function GetContext: TCryptoLibByteArray;

    property Parameters: ICipherParameters read GetParameters;
    property ContextLength: Int32 read GetContextLength;

  end;

implementation

{ TParametersWithContext }

constructor TParametersWithContext.Create(const AParameters: ICipherParameters;
  const AContext: TCryptoLibByteArray);
begin
  inherited Create();
  Create(AParameters, AContext, 0, System.Length(AContext));
end;

constructor TParametersWithContext.Create(const AParameters: ICipherParameters;
  const AContext: TCryptoLibByteArray; AContextOff, AContextLen: Int32);
begin
  inherited Create();
  // NOTE: 'parameters' may be nil to imply key re-use
  if (AContext = nil) and (AContextLen <> 0) then
    raise EArgumentNilCryptoLibException.CreateRes(@SContextNilWithLength);

  FParameters := AParameters;
  if (AContext = nil) then
    FContext := nil
  else
    FContext := TArrayUtilities.CopyOfRange<Byte>(AContext, AContextOff,
      AContextOff + AContextLen);
end;

destructor TParametersWithContext.Destroy;
begin
  TArrayUtilities.Fill<Byte>(FContext, 0, System.Length(FContext), Byte(0));
  inherited;
end;

procedure TParametersWithContext.CopyContextTo(const ABuf: TCryptoLibByteArray;
  AOff, ALen: Int32);
begin
  if (ALen > 0) then
    System.Move(FContext[0], ABuf[AOff], ALen);
end;

function TParametersWithContext.GetContext: TCryptoLibByteArray;
begin
  Result := TArrayUtilities.CopyOfRange<Byte>(FContext, 0, System.Length(FContext));
end;

function TParametersWithContext.GetContextLength: Int32;
begin
  Result := System.Length(FContext);
end;

function TParametersWithContext.GetParameters: ICipherParameters;
begin
  Result := FParameters;
end;

end.
