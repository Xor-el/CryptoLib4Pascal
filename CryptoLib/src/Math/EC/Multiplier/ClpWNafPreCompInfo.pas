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

unit ClpWNafPreCompInfo;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpCryptoLibTypes,
  ClpIECC,
  ClpIWNafPreCompInfo,
  ClpIPreCompInfo;

type

  /// <summary>
  /// Class holding precomputation data for the WNAF (Window Non-Adjacent
  /// Form) algorithm.
  /// </summary>
  TWNafPreCompInfo = class(TInterfacedObject, IPreCompInfo, IWNafPreCompInfo)

  strict private
    function GetPreComp: TCryptoLibGenericArray<IECPoint>; virtual;
    procedure SetPreComp(const Value
      : TCryptoLibGenericArray<IECPoint>); virtual;
    function GetPreCompNeg: TCryptoLibGenericArray<IECPoint>; virtual;
    procedure SetPreCompNeg(const Value
      : TCryptoLibGenericArray<IECPoint>); virtual;
    function GetTwice: IECPoint; virtual;
    procedure SetTwice(const Value: IECPoint); virtual;

    function GetConfWidth: Int32; virtual;
    procedure SetConfWidth(Value: Int32); virtual;

    function GetWidth: Int32; virtual;
    procedure SetWidth(Value: Int32); virtual;
  strict protected
  var
    /// <summary>
    /// Array holding the precomputed <c>ECPoint</c>s used for a Window NAF
    /// multiplication.
    /// </summary>
    FPreComp: TCryptoLibGenericArray<IECPoint>;

    /// <summary>
    /// Array holding the negations of the precomputed <c>ECPoint</c>s used
    /// for a Window NAF multiplication.
    /// </summary>
    FPreCompNeg: TCryptoLibGenericArray<IECPoint>;

    /// <summary>
    /// Holds an <c>ECPoint</c> representing Twice(this). Used for the Window
    /// NAF multiplication to create or extend the precomputed values.
    /// </summary>
    FTwice: IECPoint;

    FConfWidth, FWidth: Int32;

  public

    constructor Create();
    destructor Destroy; override;
    property PreComp: TCryptoLibGenericArray<IECPoint> read GetPreComp
      write SetPreComp;
    property PreCompNeg: TCryptoLibGenericArray<IECPoint> read GetPreCompNeg
      write SetPreCompNeg;
    property Twice: IECPoint read GetTwice write SetTwice;

    property ConfWidth: Int32 read GetConfWidth write SetConfWidth;
    property Width: Int32 read GetWidth write SetWidth;

  end;

implementation

{ TWNafPreCompInfo }

constructor TWNafPreCompInfo.Create;
begin
  inherited Create();
  FConfWidth := -1;
  FWidth := -1;
end;

destructor TWNafPreCompInfo.Destroy;
begin
  inherited Destroy;
end;

function TWNafPreCompInfo.GetConfWidth: Int32;
begin
  result := FConfWidth;
end;

function TWNafPreCompInfo.GetPreComp: TCryptoLibGenericArray<IECPoint>;
begin
  result := FPreComp;
end;

function TWNafPreCompInfo.GetPreCompNeg: TCryptoLibGenericArray<IECPoint>;
begin
  result := FPreCompNeg;
end;

function TWNafPreCompInfo.GetTwice: IECPoint;
begin
  result := FTwice;
end;

function TWNafPreCompInfo.GetWidth: Int32;
begin
  result := FWidth;
end;

procedure TWNafPreCompInfo.SetConfWidth(Value: Int32);
begin
  FConfWidth := Value;
end;

procedure TWNafPreCompInfo.SetPreComp(const Value
  : TCryptoLibGenericArray<IECPoint>);
begin
  FPreComp := Value;
end;

procedure TWNafPreCompInfo.SetPreCompNeg(const Value
  : TCryptoLibGenericArray<IECPoint>);
begin
  FPreCompNeg := Value;
end;

procedure TWNafPreCompInfo.SetTwice(const Value: IECPoint);
begin
  FTwice := Value;
end;

procedure TWNafPreCompInfo.SetWidth(Value: Int32);
begin
  FWidth := Value;
end;

end.
