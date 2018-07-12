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

unit ClpIFixedSecureRandom;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  ClpISecureRandom,
  ClpCryptoLibTypes;

type
  IFixedSecureRandom = interface(ISecureRandom)
    ['{8D3C436D-1E93-487F-9C03-5E0EEFBCBBB4}']

    function GetIsExhausted: Boolean;

    property IsExhausted: Boolean read GetIsExhausted;

  end;

  IRandomChecker = interface(ISecureRandom)
    ['{EFC0D597-00E4-4DAE-8529-E14C9FE50B41}']
  end;

  ISource = interface(IInterface)
    ['{D4391E69-BA80-4245-BB94-52715BC6D043}']
    function GetData: TCryptoLibByteArray;

    property Data: TCryptoLibByteArray read GetData;
  end;

  IData = interface(ISource)
    ['{CF4AB8B8-724D-4EEA-93F5-0732C81774F0}']
  end;

  IBigIntegerSource = interface(ISource)
    ['{202BF4D8-D872-4757-8C0F-D76228CEDB92}']
  end;

implementation

end.
