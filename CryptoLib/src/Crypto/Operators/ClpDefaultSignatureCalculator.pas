{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                Copyright (c) 2018 - 20XX Ugochukwu Mmaduekwe                    * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }

{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }

{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit ClpDefaultSignatureCalculator;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  Classes,
  ClpIStreamCalculator,
  ClpIBlockResult,
  ClpISigner,
  ClpSignerSink,
  ClpDefaultSignatureResult;

type
  /// <summary>
  /// Default implementation of IStreamCalculator for signature operations.
  /// </summary>
  TDefaultSignatureCalculator = class sealed(TInterfacedObject, IStreamCalculator<IBlockResult>)

  strict private
  var
    FSignerSink: TSignerSink;

  public
    constructor Create(const ASigner: ISigner);
    destructor Destroy; override;

    function GetStream: TStream;
    function GetResult: IBlockResult;

    property Stream: TStream read GetStream;
  end;

implementation

{ TDefaultSignatureCalculator }

constructor TDefaultSignatureCalculator.Create(const ASigner: ISigner);
begin
  inherited Create();
  FSignerSink := TSignerSink.Create(ASigner);
end;

destructor TDefaultSignatureCalculator.Destroy;
begin
  FSignerSink.Free;
  inherited Destroy;
end;

function TDefaultSignatureCalculator.GetStream: TStream;
begin
  Result := FSignerSink;
end;

function TDefaultSignatureCalculator.GetResult: IBlockResult;
begin
  Result := TDefaultSignatureResult.Create(FSignerSink.Signer);
end;

end.
