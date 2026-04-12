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

unit ClpMac;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpIMac,
  ClpICipherParameters,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// Abstract base class for implementations of message authentication codes (MACs).
  /// </summary>
  TMac = class abstract(TInterfacedObject, IMac)

  strict protected
    function GetAlgorithmName: String; virtual; abstract;

  public
    constructor Create();

    function GetMacSize: Int32; virtual; abstract;
    procedure Update(AInput: Byte); virtual; abstract;
    procedure BlockUpdate(const AInput: TCryptoLibByteArray;
      AInOff, ALen: Int32); virtual; abstract;
    procedure Init(const AParameters: ICipherParameters); virtual; abstract;
    function DoFinal(const AOutput: TCryptoLibByteArray; AOutOff: Int32)
      : Int32; overload; virtual; abstract;
    procedure Reset(); virtual; abstract;
    procedure Clear(); virtual;
    function DoFinal(): TCryptoLibByteArray; overload; virtual;

    property AlgorithmName: String read GetAlgorithmName;
  end;

implementation

{ TMac }

constructor TMac.Create;
begin
  inherited Create();
end;

procedure TMac.Clear;
begin
  // Default empty implementation - subclasses can override if needed
end;

function TMac.DoFinal(): TCryptoLibByteArray;
begin
  System.SetLength(Result, GetMacSize);
  DoFinal(Result, 0);
end;

end.
