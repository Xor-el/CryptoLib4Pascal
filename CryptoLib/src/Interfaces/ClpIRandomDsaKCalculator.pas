{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                    Copyright (c) 2018 Ugochukwu Mmaduekwe                       * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }

{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }

{ *                              Acknowledgements:                                  * }
{ *                                                                                 * }
{ *        Thanks to Sphere 10 Software (http://sphere10.com) for sponsoring        * }
{ *                        the development of this library                          * }

{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit ClpIRandomDsaKCalculator;

{$I ..\Include\CryptoLib.inc}

interface

uses
  ClpBigInteger,
  ClpCryptoLibTypes,
  ClpISecureRandom,
  ClpIDsaKCalculator;

type
  IRandomDsaKCalculator = interface(IDsaKCalculator)

    ['{79C48638-0015-4D65-901B-638D9F4154E4}']

    function GetIsDeterministic: Boolean;

    property IsDeterministic: Boolean read GetIsDeterministic;
    procedure Init(n: TBigInteger; random: ISecureRandom); overload;
    procedure Init(n, d: TBigInteger; &message: TCryptoLibByteArray); overload;
    function NextK(): TBigInteger;

  end;

implementation

end.
