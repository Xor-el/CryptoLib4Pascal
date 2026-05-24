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

unit ClpDefaultMacCalculator;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  Classes,
  ClpIStreamCalculator,
  ClpIBlockResult,
  ClpIMac,
  ClpMacSink,
  ClpDefaultMacResult;

type
  /// <summary>
  /// Default implementation of IStreamCalculator for MAC operations.
  /// </summary>
  TDefaultMacCalculator = class sealed(TInterfacedObject, IStreamCalculator<IBlockResult>)

  strict private
  var
    FMacSink: TMacSink;

  public
    constructor Create(const AMac: IMac);
    destructor Destroy; override;

    function GetStream: TStream;
    function GetResult: IBlockResult;

    property Stream: TStream read GetStream;
  end;

implementation

{ TDefaultMacCalculator }

constructor TDefaultMacCalculator.Create(const AMac: IMac);
begin
  inherited Create();
  FMacSink := TMacSink.Create(AMac);
end;

destructor TDefaultMacCalculator.Destroy;
begin
  FMacSink.Free;
  inherited Destroy;
end;

function TDefaultMacCalculator.GetStream: TStream;
begin
  Result := FMacSink;
end;

function TDefaultMacCalculator.GetResult: IBlockResult;
begin
  Result := TDefaultMacResult.Create(FMacSink.Mac);
end;

end.
