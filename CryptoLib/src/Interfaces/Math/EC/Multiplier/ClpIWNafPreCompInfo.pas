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

unit ClpIWNafPreCompInfo;

{$I ..\..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpIECCore,
  ClpIPreCompInfo,
  ClpCryptoLibTypes;

type
  IWNafPreCompInfo = interface(IPreCompInfo)
    ['{E6F7A8B9-C0D1-2345-E6F7-A8B9C0D12346}']

    function DecrementPromotionCountdown: Int32;
    function GetConfWidth: Int32;
    procedure SetConfWidth(AValue: Int32);
    function GetPreComp: TCryptoLibGenericArray<IECPoint>;
    procedure SetPreComp(const AValue: TCryptoLibGenericArray<IECPoint>);
    function GetPreCompNeg: TCryptoLibGenericArray<IECPoint>;
    procedure SetPreCompNeg(const AValue: TCryptoLibGenericArray<IECPoint>);
    function GetTwice: IECPoint;
    procedure SetTwice(const AValue: IECPoint);
    function GetWidth: Int32;
    procedure SetWidth(AValue: Int32);
    function GetIsPromoted: Boolean;
    function GetPromotionCountdown: Int32;
    procedure SetPromotionCountdown(AValue: Int32);

    property ConfWidth: Int32 read GetConfWidth write SetConfWidth;
    property PreComp: TCryptoLibGenericArray<IECPoint> read GetPreComp write SetPreComp;
    property PreCompNeg: TCryptoLibGenericArray<IECPoint> read GetPreCompNeg write SetPreCompNeg;
    property Twice: IECPoint read GetTwice write SetTwice;
    property Width: Int32 read GetWidth write SetWidth;
    property IsPromoted: Boolean read GetIsPromoted;
    property PromotionCountdown: Int32 read GetPromotionCountdown write SetPromotionCountdown;
  end;

implementation

end.
