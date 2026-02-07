{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                Copyright (c) 2018 - 20XX Ugochukwu Mmaduekwe                    * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }

{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }

{ * ******************************************************************************* * }

unit ClpIWTauNafPreCompInfo;

{$I ..\..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpIECCore,
  ClpIPreCompInfo,
  ClpCryptoLibTypes;

type
  IWTauNafPreCompInfo = interface(IPreCompInfo)
    ['{F7A8B9C0-D1E2-3456-F7A8-B9C0D1E23457}']

    function GetPreComp: TCryptoLibGenericArray<IAbstractF2mPoint>;
    procedure SetPreComp(const AValue: TCryptoLibGenericArray<IAbstractF2mPoint>);

    property PreComp: TCryptoLibGenericArray<IAbstractF2mPoint> read GetPreComp write SetPreComp;
  end;

implementation

end.
